//! A scrape endpoint for [`crate::metrics::DnsMetrics`], hand-rolled over
//! `tokio`'s `TcpListener`.
//!
//! **Why not a web framework.** This replaced an OpenTelemetry OTLP exporter
//! that dragged `tonic`, `prost`, `hyper` and `h2` — a gRPC *server* — into a
//! DNS daemon, and never initialised. Pulling a second HTTP stack back in to
//! serve one endpoint that answers one method on one path would be the same
//! mistake with better manners. What Prometheus actually needs is a `GET` that
//! returns text; that is ninety lines, and they are all here where they can be
//! read.
//!
//! **What it deliberately does not do**: no TLS, no auth, no keep-alive, no
//! chunked encoding, no compression. Bind it on a management address or on
//! loopback behind whatever already terminates TLS — the counters say how much
//! traffic a server is taking and which zones are failing, which is not secret
//! but is not public either.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::metrics::DnsMetrics;
use crate::shutdown::{Busy, Stop};

/// How long a scraper gets to send its request line before we give up on it.
///
/// Short on purpose: a connection that has connected and said nothing is either
/// a stalled scraper or a port scanner, and neither is worth a socket.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Most bytes we will read from a request. We only ever look at the first line,
/// and a `GET /metrics HTTP/1.1` with headers is well under this.
const MAX_REQUEST: usize = 8 * 1024;

/// Serve `GET /metrics` until told to stop.
///
/// Returns when [`Stop`] fires, holding a [`Busy`] for each connection so a
/// scrape in flight is finished rather than cut.
pub async fn serve(
    listener: TcpListener,
    metrics: Arc<DnsMetrics>,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    loop {
        let (stream, _peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = stop.wait() => return Ok(()),
        };
        let metrics = metrics.clone();
        let busy = busy.clone();
        tokio::spawn(async move {
            let _busy = busy;
            // A scraper that misbehaves is not worth a log line on a DNS
            // server's stderr — it cannot affect an answer, and the flood item
            // in TODO.md #9d is about exactly this shape of noise.
            let _ = respond(stream, &metrics).await;
        });
    }
}

async fn respond(mut stream: TcpStream, metrics: &DnsMetrics) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST];
    let mut filled = 0;

    // Read until the end of the request line. We need nothing after it, and
    // waiting for the blank line that ends the headers would hang on a client
    // that pipelines badly.
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
        // A liveness probe that costs nothing to answer. It says the process is
        // running and its runtime is scheduling tasks, which is all a `/healthz`
        // can honestly claim — readiness (are the zones loaded?) is a different
        // question and does not have an answer here yet.
        ("GET", "/healthz") => response(200, "text/plain", "ok\n"),
        ("GET", "/") => response(
            200,
            "text/plain",
            "rdns metrics\n\n  /metrics   Prometheus text\n  /healthz   liveness\n",
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
        _ => "Error",
    };
    // `Connection: close` because there is no keep-alive here: one request, one
    // response, one socket. Prometheus is perfectly happy with that, and it
    // means no state machine to get wrong.
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
        let shutdown = Shutdown::new();
        let metrics = Arc::new(DnsMetrics::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(serve(
            listener,
            metrics.clone(),
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
        (addr, shutdown, metrics)
    }

    #[tokio::test]
    async fn a_scrape_returns_the_counters() {
        let (addr, _shutdown, metrics) = start().await;
        metrics.count(&metrics.queries_received);
        metrics.count(&metrics.responses_refused);
        metrics.observe_latency_ms(0.2);

        let body = scrape(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
        assert!(body.contains("dns_queries_received_total 1"), "{body}");
        assert!(body.contains("dns_responses_refused_total 1"), "{body}");
        // The histogram, in the shape `histogram_quantile()` needs: a 0.2 ms
        // answer is at or below the 0.25 ms bucket and above the 0.1 ms one.
        assert!(
            body.contains("dns_answer_latency_seconds_bucket{le=\"0.00025\"} 1"),
            "{body}"
        );
        assert!(
            body.contains("dns_answer_latency_seconds_bucket{le=\"0.0001\"} 0"),
            "{body}"
        );
        assert!(
            body.contains("dns_answer_latency_seconds_count 1"),
            "{body}"
        );
    }

    /// A query string is part of ordinary scrape configuration and must not turn
    /// the scrape into a 404.
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

    /// The endpoint stops with everything else, and does not hold the drain open
    /// (`CLAUDE.md` §9): it watches the stop, it does not claim it.
    #[tokio::test]
    async fn the_endpoint_stops_with_the_server() {
        let (addr, shutdown, _metrics) = start().await;
        // It is up.
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
