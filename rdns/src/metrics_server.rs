//! A scrape endpoint for [`crate::metrics::DnsMetrics`], hand-rolled over
//! `tokio`'s `TcpListener`, plus the two probes an orchestrator asks for:
//! `/healthz` (alive) and `/readyz` (finished starting). [`crate::readiness`]
//! has the distinction.
//!
//! Hand-rolled because Prometheus needs a `GET` returning text, and an HTTP
//! stack for one method on one path costs `hyper` and everything under it.
//!
//! No TLS, no auth, no keep-alive, no chunked encoding, no compression. Bind it
//! on a management address or on loopback: the counters say how much traffic a
//! server takes and which zones are failing.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::metrics::DnsMetrics;
use crate::readiness::Readiness;
use crate::shutdown::{Busy, Stop};

/// A connection that has said nothing is a stalled scraper or a port scanner.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Only the first line is read, and a request line with headers is well under
/// this.
const MAX_REQUEST: usize = 8 * 1024;

/// Concurrent scrape connections. Smaller than the DNS loops' 128: a scrape is
/// one request from a handful of collectors, and more is a queue nobody waits
/// on.
const MAX_SCRAPES: usize = 16;

/// Serve `GET /metrics`, `GET /healthz` and `GET /readyz` until told to stop.
///
/// Returns when [`Stop`] fires, holding a [`Busy`] for each connection so a
/// scrape in flight is finished rather than cut.
pub async fn serve(
    listener: TcpListener,
    metrics: Arc<DnsMetrics>,
    readiness: Readiness,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_SCRAPES));
    loop {
        let (stream, _peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = stop.wait() => return Ok(()),
        };
        // `try_acquire`, not `acquire`: a queued scrape is stale by the time it
        // is served. Dropping closes the socket, which the collector reads as a
        // failed scrape.
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let metrics = metrics.clone();
        let readiness = readiness.clone();
        let busy = busy.clone();
        tokio::spawn(async move {
            let _busy = busy;
            let _permit = permit;
            // A misbehaving scraper cannot affect an answer, so it is not worth
            // a log line on a DNS server's stderr.
            let _ = respond(stream, &metrics, &readiness).await;
        });
    }
}

async fn respond(
    mut stream: TcpStream,
    metrics: &DnsMetrics,
    readiness: &Readiness,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST];
    let mut filled = 0;

    // Only the request line. Waiting for the blank line ending the headers
    // would hang on a client that pipelines badly.
    let line_end = loop {
        if let Some(at) = buf[..filled].iter().position(|b| *b == b'\n') {
            break at;
        }
        if filled == buf.len() {
            // No request line in 8 KB: not a scraper.
            return write_all(
                &mut stream,
                &response(431, "text/plain", "request too long"),
            )
            .await;
        }
        let read = match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf[filled..])).await {
            Ok(Ok(0)) | Err(_) => return Ok(()),
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
        };
        filled += read;
    };

    let line = String::from_utf8_lossy(&buf[..line_end]);
    let mut parts = line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    // Strip a query string: `GET /metrics?foo=1` is a scrape.
    let path = path.split('?').next().unwrap_or(path);

    let reply = match (method, path) {
        ("GET", "/metrics") => response(
            200,
            "text/plain; version=0.0.4",
            &metrics.to_prometheus_format(),
        ),
        // The process is running and its runtime is scheduling tasks, which is
        // all a liveness probe can honestly claim.
        ("GET", "/healthz") => response(200, "text/plain", "ok\n"),
        // 503 rather than 200-with-a-body: an orchestrator's probe reads the
        // status code, and one that always passes is not a gate. The names go
        // in the body for whoever curls it.
        ("GET", "/readyz") => match readiness.pending() {
            pending if pending.is_empty() => response(200, "text/plain", "ready\n"),
            pending => response(
                503,
                "text/plain",
                &format!(
                    "not ready: waiting for {} zone(s) to transfer: {}\n",
                    pending.len(),
                    pending.join(" ")
                ),
            ),
        },
        ("GET", "/") => response(
            200,
            "text/plain",
            "rdns metrics\n\n  /metrics   Prometheus text\n  /healthz   liveness\n  \
             /readyz    readiness\n",
        ),
        ("GET", _) => response(404, "text/plain", "not found\n"),
        _ => response(405, "text/plain", "method not allowed\n"),
    };
    write_all(&mut stream, &reply).await
}

async fn write_all(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(bytes).await?;
    stream.flush().await
}

fn response(status: u16, content_type: &str, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    };
    // No keep-alive: one request, one response, one socket, no state machine.
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown::Shutdown;
    use std::net::SocketAddr;

    async fn scrape(addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("send the request");
        let mut out = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut out)
            .await
            .expect("read the response");
        out
    }

    async fn start() -> (SocketAddr, Shutdown, Arc<DnsMetrics>) {
        let (addr, shutdown, metrics, _) = start_with(Readiness::ready()).await;
        (addr, shutdown, metrics)
    }

    async fn start_with(
        readiness: Readiness,
    ) -> (SocketAddr, Shutdown, Arc<DnsMetrics>, Readiness) {
        let shutdown = Shutdown::new();
        let metrics = Arc::new(DnsMetrics::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(serve(
            listener,
            metrics.clone(),
            readiness.clone(),
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
        (addr, shutdown, metrics, readiness)
    }

    #[tokio::test]
    async fn a_scrape_returns_the_counters() {
        let (addr, _shutdown, metrics) = start().await;
        metrics.count(&metrics.queries_received);
        metrics.count(&metrics.responses_refused);
        metrics.observe_latency_us(200);

        let body = scrape(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
        assert!(body.contains("dns_queries_received_total 1"), "{body}");
        assert!(body.contains("dns_responses_refused_total 1"), "{body}");
        // A 200 µs answer is at or below the 500 µs bucket, above the 50 µs one.
        // Both bounds moved when the buckets were rescaled to where an answer
        // actually lands (`TODO.md` #25c); the shape asserted here did not.
        assert!(
            body.contains("dns_answer_latency_seconds_bucket{le=\"0.0005\"} 1"),
            "{body}"
        );
        assert!(
            body.contains("dns_answer_latency_seconds_bucket{le=\"0.00005\"} 0"),
            "{body}"
        );
        assert!(
            body.contains("dns_answer_latency_seconds_count 1"),
            "{body}"
        );
    }

    /// A query string is ordinary scrape configuration, not a 404.
    #[tokio::test]
    async fn a_query_string_is_still_a_scrape() {
        let (addr, _shutdown, _metrics) = start().await;
        let body = scrape(addr, "GET /metrics?x=1 HTTP/1.1\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
    }

    #[tokio::test]
    async fn healthz_answers_and_other_paths_do_not() {
        let (addr, _shutdown, _metrics) = start().await;
        assert!(scrape(addr, "GET /healthz HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 200 OK"));
        assert!(scrape(addr, "GET /admin HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 404"));
        assert!(scrape(addr, "POST /metrics HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 405"));
    }

    /// The point of the split: a secondary that has bound its sockets but
    /// transferred nothing is alive and not ready.
    #[tokio::test]
    async fn a_server_can_be_alive_and_not_ready() {
        let (addr, _shutdown, _metrics, readiness) =
            start_with(Readiness::waiting_for(["example.com.", "example.net."])).await;

        assert!(
            scrape(addr, "GET /healthz HTTP/1.1\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 200 OK"),
            "liveness does not wait on the zones"
        );
        let body = scrape(addr, "GET /readyz HTTP/1.1\r\n\r\n").await;
        assert!(
            body.starts_with("HTTP/1.1 503 Service Unavailable"),
            "{body}"
        );
        assert!(body.contains("example.com."), "{body}");
        assert!(body.contains("example.net."), "{body}");

        readiness.arrived("example.com.");
        let body = scrape(addr, "GET /readyz HTTP/1.1\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 503"), "one of two: {body}");
        assert!(!body.contains("example.com."), "it arrived: {body}");

        readiness.arrived("example.net.");
        let body = scrape(addr, "GET /readyz HTTP/1.1\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
        assert!(body.ends_with("ready\n"), "{body}");
    }

    /// A primary loads every zone before anything binds: no window to report.
    #[tokio::test]
    async fn a_server_with_nothing_to_wait_for_is_ready_at_once() {
        let (addr, _shutdown, _metrics) = start().await;
        assert!(scrape(addr, "GET /readyz HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 200 OK"));
    }

    /// The endpoint watches the stop; it does not claim the drain.
    #[tokio::test]
    async fn the_endpoint_stops_with_the_server() {
        let (addr, shutdown, _metrics) = start().await;
        assert!(scrape(addr, "GET /healthz HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 200 OK"));

        shutdown.begin();
        assert!(
            shutdown.drain(Duration::from_secs(3)).await,
            "the metrics listener held the drain open"
        );
    }
}
