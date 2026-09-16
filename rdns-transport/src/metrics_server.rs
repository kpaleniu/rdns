//! A scrape endpoint for [`rdns::metrics::DnsMetrics`], plus the two probes an
//! orchestrator asks for: `/healthz` (alive) and `/readyz` (finished starting).
//! [`rdns::readiness`] has the distinction.
//!
//! **This was hand-rolled, and its own header said why**: "Prometheus needs a
//! `GET` returning text, and an HTTP stack for one method on one path costs
//! `hyper` and everything under it." That was a cost comparison, and #42c
//! retired its premise — DoH makes `hyper` unconditional, so the stack is
//! already linked and the comparison is now between using it and keeping a
//! second HTTP implementation next to it.
//!
//! **What the fold actually removed**, since the filing estimated it and an
//! estimate is worth checking: the request-line parser and its 8 KB read loop,
//! `write_all`, and `response`'s status-line and header formatting. What stayed
//! is everything that is not HTTP — the accept loop, the `Stop`/`Busy` shutdown
//! integration, the `try_acquire` that drops a scrape rather than queueing it,
//! and the `match (method, path)`, which is a `service_fn` with the same arms
//! and the same bodies.
//!
//! ~~**Two behaviours changed, both toward the RFC.** An HTTP/1.1 request with
//! no `Host` header now gets 400 — RFC 9112 §3.2 requires that. And a request
//! line longer than 8 KB is now hyper's 431.~~ **Neither was true**, and the
//! tests in this file had disproved half of it on the day it was written:
//! `a_query_string_is_still_a_scrape` sends no `Host` and asserts 200. Measured
//! (`hyper_serves_what_the_header_used_to_claim_it_refused`): no `Host` is
//! **200**, hyper does not look; an over-long request line is **414** past
//! ~64 KB, hyper's read buffer, not 431 at 8 KB. Both numbers were estimates of
//! somebody else's code — `CLAUDE.md` §4's "never state what a function does
//! without opening it", about a dependency. §3.2's MUST is unenforced and
//! that is now a decision to take rather than a claim (`TODO.md` #70).
//!
//! **Keep-alive is off on purpose**, which is the one thing hyper offers here
//! that is not taken. The permit below is held for a connection's life, so a
//! handful of idle keep-alive connections would hold every scrape slot; the
//! hand-rolled version closed after one response and this keeps that.
//!
//! No TLS and no auth. Bind it on a management address or on loopback: the
//! counters say how much traffic a server takes and which zones are failing.

use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use rdns::metrics::DnsMetrics;
use rdns::readiness::Readiness;
use rdns::shutdown::{Busy, Stop};

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
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                // Not `?`: descriptor exhaustion clears on its own, and this
                // loop's death is the whole process's (`survive_accept_error`).
                Err(e) => {
                    crate::survive_accept_error(e, "metrics").await?;
                    continue;
                }
            },
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
            let service = service_fn(move |request| {
                let metrics = metrics.clone();
                let readiness = readiness.clone();
                async move { Ok::<_, std::convert::Infallible>(answer(request, &metrics, &readiness)) }
            });
            // A misbehaving scraper cannot affect an answer, so it is not worth
            // a log line on a DNS server's stderr.
            let _ = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

fn answer(
    request: Request<hyper::body::Incoming>,
    metrics: &DnsMetrics,
    readiness: &Readiness,
) -> Response<Full<Bytes>> {
    // hyper has already stripped the query string, which `GET /metrics?x=1`
    // needs: a query string is ordinary scrape configuration, not a 404.
    match (request.method(), request.uri().path()) {
        (&Method::GET, "/metrics") => text(
            StatusCode::OK,
            "text/plain; version=0.0.4",
            metrics.to_prometheus_format(),
        ),
        // The process is running and its runtime is scheduling tasks, which is
        // all a liveness probe can honestly claim.
        (&Method::GET, "/healthz") => text(StatusCode::OK, "text/plain", "ok\n".into()),
        // 503 rather than 200-with-a-body: an orchestrator's probe reads the
        // status code, and one that always passes is not a gate. The names go
        // in the body for whoever curls it.
        (&Method::GET, "/readyz") => match readiness.pending() {
            pending if pending.is_empty() => text(StatusCode::OK, "text/plain", "ready\n".into()),
            pending => text(
                StatusCode::SERVICE_UNAVAILABLE,
                "text/plain",
                format!(
                    "not ready: waiting for {} zone(s) to transfer: {}\n",
                    pending.len(),
                    pending.join(" ")
                ),
            ),
        },
        (&Method::GET, "/") => text(
            StatusCode::OK,
            "text/plain",
            "rdns metrics\n\n  /metrics   Prometheus text\n  /healthz   liveness\n  \
             /readyz    readiness\n"
                .into(),
        ),
        (&Method::GET, _) => text(StatusCode::NOT_FOUND, "text/plain", "not found\n".into()),
        _ => text(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain",
            "method not allowed\n".into(),
        ),
    }
}

fn text(status: StatusCode, content_type: &str, body: String) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    if let Ok(value) = content_type.parse() {
        response.headers_mut().insert(CONTENT_TYPE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdns::shutdown::Shutdown;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    /// Every failure names the socket call and the address. #68 was one run of
    /// this that failed and could not be diagnosed, because the assertion it
    /// failed printed neither the body nor which of the three steps went wrong.
    async fn scrape(addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("connect to {addr}: {e}"));
        stream
            .write_all(request.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("send to {addr}: {e}"));
        let mut out = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stream, &mut out)
            .await
            .unwrap_or_else(|e| panic!("read from {addr}: {e}"));
        out
    }

    /// [`scrape`] for a request hyper refuses part-read: it stops at its buffer
    /// limit, answers and closes with the rest of the request still in flight,
    /// which is an RST rather than a FIN. A reset here ends the response; in
    /// [`scrape`] it stays a panic, because there it is the finding.
    async fn scrape_tolerating_reset(addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("connect to {addr}: {e}"));
        let _ = stream.write_all(request.as_bytes()).await;
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        String::from_utf8_lossy(&out).into_owned()
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
        let body = scrape(addr, "GET /healthz HTTP/1.1\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
        let body = scrape(addr, "GET /admin HTTP/1.1\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 404"), "{body}");
        let body = scrape(addr, "POST /metrics HTTP/1.1\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 405"), "{body}");
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
        let body = scrape(addr, "GET /readyz HTTP/1.1\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
    }

    /// Both halves of a claim this module's header made about hyper and nobody
    /// ran. Pinned rather than described: the header's numbers were 400 and
    /// 431, and a dependency's defaults are exactly the kind of claim that
    /// changes under you (`TODO.md` #68).
    #[tokio::test]
    async fn hyper_serves_what_the_header_used_to_claim_it_refused() {
        let (addr, _shutdown, _metrics) = start().await;

        // RFC 9112 §3.2 says 400. hyper does not look, and the four tests above
        // that send no `Host` are the evidence it never did (`TODO.md` #70).
        let body = scrape(addr, "GET /metrics HTTP/1.1\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");

        // Past hyper's 64 KiB read buffer, not past 8 KB, and 414 not 431:
        // 60 000 is served as an ordinary 404.
        let body = scrape(
            addr,
            &format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "x".repeat(60_000)),
        )
        .await;
        assert!(
            body.starts_with("HTTP/1.1 404"),
            "{}",
            &body[..60.min(body.len())]
        );
        let body = scrape_tolerating_reset(
            addr,
            &format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "x".repeat(100_000)),
        )
        .await;
        assert!(
            body.starts_with("HTTP/1.1 414"),
            "{}",
            &body[..60.min(body.len())]
        );
    }

    /// The endpoint watches the stop; it does not claim the drain.
    #[tokio::test]
    async fn the_endpoint_stops_with_the_server() {
        let (addr, shutdown, _metrics) = start().await;
        let body = scrape(addr, "GET /healthz HTTP/1.1\r\n\r\n").await;
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");

        shutdown.begin();
        assert!(
            shutdown.drain(Duration::from_secs(3)).await,
            "the metrics listener held the drain open"
        );
    }
}
