//! DNS over HTTPS (RFC 8484): a DNS message as an HTTP body.
//!
//! The odd one of the three. DoT and DoQ carry the wire format unchanged — the
//! 2-octet prefix RFC 1035 §4.2.2 defines — and this does not: RFC 8484 §4.1
//! sends the bare message as an entity body, with the length in
//! `Content-Length` in place of the prefix. So [`crate::tcp::send_framed`]
//! produces the reply and this module takes the prefix back off, which is the
//! one place in the tree where framing is removed rather than added.
//!
//! **Two forms**, and both are required of a server:
//!
//! - `POST <path>` with `content-type: application/dns-message`, the body being
//!   the message.
//! - `GET <path>?dns=<base64url>`, unpadded — the form a cache can store,
//!   which is why the response carries `Cache-Control` (§5.1).
//!
//! **HTTP/2, and HTTP/1.1 as well.** §5.2 makes HTTP/2 the minimum recommended
//! version and clients negotiate `h2` by ALPN, so `h2` is offered first; a
//! client that asks for `http/1.1` is still served, because `curl` and every
//! ad-hoc probe speak it and refusing them buys nothing.
//!
//! **What this deliberately does not carry.** A zone transfer. The handler is a
//! sink because an AXFR is a sequence of messages (RFC 5936 §2.2), and one HTTP
//! response is one message. RFC 8484 defines no framing that would carry the
//! rest, and inventing one would be a protocol this tree made up; RFC 9103
//! §7.1 leaves DoH outside zone transfer as well.
//!
//! The refusal is the *dispatcher's*, on
//! [`rdns::validation::Arrival::carries_a_sequence`], because only it can
//! refuse before the zone is looked up: found out here, by draining what had
//! been built, a zone small enough to fit one envelope transfers, so whether
//! DoH carries a transfer depends on zone size. The drain is here as a
//! backstop: the `Handler` trait permits a sequence because `tcp` and `quic`
//! need it.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;

use rdns::shutdown::{Busy, Stop};
use rdns::validation::{Arrival, TlsVersion, Transport};

use crate::slots::Slots;
use crate::tcp::{Handler, RateLimit, Reply};
use crate::tls::CertificateStore;
use crate::TransportLimits;
use rdns::metrics::StreamListener;
use rdns::peer::Peer;

/// The port RFC 8484 uses, which is HTTPS's: DoH is meant to be
/// indistinguishable from other HTTPS traffic, and a port of its own would
/// undo that.
pub const DOH_PORT: u16 = 443;

/// The path RFC 8484 §4.1.1 uses in its examples and every deployment uses in
/// practice. Configurable, because the RFC makes it a template rather than a
/// constant.
pub const DEFAULT_PATH: &str = "/dns-query";

/// RFC 8484 §6 registers this media type for both directions.
const DNS_MESSAGE: &str = "application/dns-message";

const ALPN_H2: &[u8] = b"h2";
const ALPN_HTTP11: &[u8] = b"http/1.1";

/// What a DoH listener needs that the other two do not: a path as well as a
/// certificate.
///
/// One struct rather than two arguments, because `serve` reached eight and
/// clippy says so at seven — `CLAUDE.md` §14, and the same reason `ServePolicy`
/// exists. The two belong together anyway: the path is as much a part of the
/// endpoint's identity as the port.
#[derive(Clone)]
pub struct Endpoint {
    tls: Arc<ServerConfig>,
    path: Arc<str>,
}

/// The configuration a DoH listener serves under.
///
/// `h2` first: ALPN offers are ordered by the server's preference, and §5.2
/// makes HTTP/2 the minimum recommended version.
pub fn endpoint(
    store: Arc<CertificateStore>,
    path: &str,
    clients: Option<rdns::tls_identity::TrustAnchors>,
) -> anyhow::Result<Endpoint> {
    let mut config = crate::tls::config_with_alpn(store, ALPN_H2, clients)?;
    config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
    Ok(Endpoint {
        tls: Arc::new(config),
        path: Arc::from(path),
    })
}

/// Accept HTTPS connections and answer DNS queries on them, until told to stop.
pub async fn serve<H: Handler>(
    listener: TcpListener,
    endpoint: Endpoint,
    handler: Arc<H>,
    limits: TransportLimits,
    rate: RateLimit,
    stop: Stop,
    busy: Busy,
) -> Result<(), io::Error> {
    let Endpoint { tls, path } = endpoint;
    let acceptor = TlsAcceptor::from(tls);
    let slots = Slots::new(
        limits.max_connections,
        &handler.context().metrics,
        StreamListener::Doh,
        handler.context().per_source.clone(),
    );
    loop {
        // Before `accept`, as `tcp::serve` does and for its reason.
        let mut slot = tokio::select! {
            slot = slots.take() => slot,
            _ = stop.wait() => return Ok(()),
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                // Not `?`: descriptor exhaustion clears on its own, and this
                // loop's death is the whole process's (`survive_accept_error`).
                Err(e) => {
                    crate::survive_accept_error(e, "doh").await?;
                    continue;
                }
            },
            _ = stop.wait() => return Ok(()),
        };
        // Canonical before anything sees it, as in `tcp::serve`.
        let peer = rdns::peer::canonical(peer);
        // The query ACL first: a peer it refuses is closed before the rate
        // limiter or the per-source table hears of it (`TODO.md` #171).
        if !handler
            .context()
            .admits_connection(Peer::from(peer), StreamListener::Doh)
        {
            continue;
        }
        if !rate.admits_connection(handler.context(), Peer::from(peer)) {
            continue;
        }
        // Closed unserved: dropping the stream closes it and dropping the
        // slot releases it.
        if !slot.open(Peer::from(peer)) {
            continue;
        }
        let acceptor = acceptor.clone();
        let handler = handler.clone();
        let path = path.clone();
        let stop = stop.clone();
        let busy = busy.clone();
        tokio::spawn(async move {
            // In the connection's task, as for DoT and DoQ: two round trips
            // with a stranger do not belong in an accept loop.
            let Some(stream) =
                crate::tls::handshake(&acceptor, stream, peer, handler.context(), limits, &stop)
                    .await
            else {
                drop(slot);
                drop(busy);
                return;
            };
            handler
                .context()
                .metrics
                .count(&handler.context().metrics.tls_handshakes);

            let negotiated_h2 = stream.get_ref().1.alpn_protocol() == Some(ALPN_H2);
            // From the finished handshake, as DoT does it: this build offers
            // 1.2 as well, and a transfer wants 1.3 (RFC 9103 §7.2).
            let arrival = Arrival::Doh(
                match stream.get_ref().1.protocol_version() {
                    Some(rustls::ProtocolVersion::TLSv1_3) => TlsVersion::Tls13,
                    _ => TlsVersion::Older,
                },
                crate::tls::presented_certificate(stream.get_ref().1),
            );
            let started = Arc::new(Notify::new());
            let service = service_fn({
                let started = started.clone();
                move |request| {
                    started.notify_one();
                    let handler = handler.clone();
                    let path = path.clone();
                    let arrival = arrival.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            answer(request, peer, handler, path, arrival, rate).await,
                        )
                    }
                }
            });
            let io = TokioIo::new(stream);
            // From ALPN, which the handshake settled, rather than sniffing the
            // preface as hyper's `auto` does.
            let idle = limits.idle_timeout;
            let served = if negotiated_h2 {
                // TCP's and DoQ's in-flight cap, not hyper's 200; past it,
                // REFUSED_STREAM (RFC 9113 §8.7, safe to retry).
                let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .max_concurrent_streams(limits.max_inflight_per_connection as u32)
                    .serve_connection(io, service);
                until_idle(conn, |c| c.graceful_shutdown(), &started, idle, &stop).await
            } else {
                let conn = hyper::server::conn::http1::Builder::new().serve_connection(io, service);
                until_idle(conn, |c| c.graceful_shutdown(), &started, idle, &stop).await
            };
            match served {
                Some(Ok(())) => {}
                Some(Err(e)) => {
                    tracing::debug!(peer = %peer.ip(), "HTTPS connection ended: {e}");
                }
                None => {
                    tracing::debug!(peer = %peer.ip(), "HTTPS connection dropped: no close after GOAWAY");
                }
            }
            drop(slot);
            drop(busy);
        });
    }
}

/// Drive `conn` until it ends, closing it gracefully once no request has
/// started for `idle` or shutdown begins, and dropping it `idle` after that.
///
/// Idle is no new request, whatever is in flight, as on TCP (`TODO.md` #161).
/// hyper's HTTP/2 server has no idle close of its own, and its HTTP/1
/// `header_read_timeout` starts after a response rather than at a request.
/// The second deadline is for a peer that stops reading, which stalls HTTP/2
/// flow control, or that never finishes an HTTP/1 header: `graceful_shutdown`
/// waits for either without a limit. `None` is a connection dropped there.
#[expect(clippy::disallowed_methods, reason = "the idle timeout is the event")]
async fn until_idle<C, E>(
    conn: C,
    graceful_shutdown: impl FnOnce(Pin<&mut C>),
    started: &Notify,
    idle: Duration,
    stop: &Stop,
) -> Option<Result<(), E>>
where
    C: Future<Output = Result<(), E>>,
{
    let mut conn = std::pin::pin!(conn);
    loop {
        tokio::select! {
            served = conn.as_mut() => return Some(served),
            // `notify_one` keeps a permit when nobody is waiting, so a request
            // that starts between two turns of this loop is not missed.
            () = started.notified() => {}
            () = tokio::time::sleep(idle) => break,
            () = stop.wait() => break,
        }
    }
    graceful_shutdown(conn.as_mut());
    tokio::time::timeout(idle, conn).await.ok()
}

/// One HTTP request: find the DNS message in it, answer it, wrap the answer.
async fn answer<H: Handler>(
    request: Request<Incoming>,
    peer: SocketAddr,
    handler: Arc<H>,
    path: Arc<str>,
    arrival: Arrival,
    rate: RateLimit,
) -> Response<Full<Bytes>> {
    if request.uri().path() != &*path {
        return status(StatusCode::NOT_FOUND);
    }
    let query = match extract(request).await {
        Ok(query) => query,
        Err(code) => return status(code),
    };

    let now = handler.context().clock.now();
    // Through `rate` like the other adapters: `allow_source` outright charges a
    // `PerConnection` client twice for a connection's first request.
    if !rate.admits_message(handler.context(), Peer::from(peer), now) {
        // 429 rather than silence: after TCP and TLS handshakes there is nobody
        // to reflect an answer at.
        return status(StatusCode::TOO_MANY_REQUESTS);
    }
    // The TCP cap, not the UDP one: a body is not a datagram.
    if !handler
        .context()
        .accept_packet(Peer::from(peer), &query, Transport::Tcp)
    {
        return status(StatusCode::BAD_REQUEST);
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Reply>(4);
    let answering = tokio::spawn(async move {
        handler.handle(query, peer, now, arrival, tx).await;
    });

    let mut answer = None;
    let mut extra = 0usize;
    while let Some(reply) = rx.recv().await {
        match reply {
            // `send_framed` prefixed two length octets; RFC 8484 §4.1 uses
            // `Content-Length`, so they come off.
            Reply::Frame(framed) if answer.is_none() => {
                answer = Some(framed[2.min(framed.len())..].to_vec());
            }
            Reply::Frame(_) => extra += 1,
            Reply::Abort => {
                let _ = answering.await;
                return status(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }
    let _ = answering.await;

    if extra > 0 {
        // A transfer: RFC 8484 has no framing for a sequence, and a client must
        // not take the first envelope for the zone.
        tracing::warn!(
            peer = %peer.ip(),
            "a DoH request produced {} further messages, which one response cannot carry; \
             answered with the first only",
            extra
        );
    }

    match answer {
        Some(message) => {
            let max_age = min_ttl(&message);
            let mut response = Response::new(Full::new(Bytes::from(message)));
            response
                .headers_mut()
                .insert(CONTENT_TYPE, DNS_MESSAGE.parse().expect("a static type"));
            // RFC 8484 §5.1: freshness follows the smallest TTL, so an HTTP
            // cache cannot hold a record past its lifetime.
            if let Ok(value) = format!("max-age={max_age}").parse() {
                response.headers_mut().insert(CACHE_CONTROL, value);
            }
            response
        }
        // The handler answered nothing at all, which for DNS means the request
        // was one it drops rather than refuses.
        None => status(StatusCode::BAD_REQUEST),
    }
}

/// The DNS message a request carries, or the status that says why not.
async fn extract(request: Request<Incoming>) -> Result<Vec<u8>, StatusCode> {
    match *request.method() {
        Method::GET => {
            // `?dns=<base64url>`, unpadded (RFC 8484 §4.1); padding is
            // tolerated, since some clients send it.
            let Some(query) = request.uri().query() else {
                return Err(StatusCode::BAD_REQUEST);
            };
            let Some(value) = query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(key, _)| *key == "dns")
                .map(|(_, value)| value)
            else {
                return Err(StatusCode::BAD_REQUEST);
            };
            base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(value.trim_end_matches('='))
                .map_err(|_| StatusCode::BAD_REQUEST)
        }
        Method::POST => {
            let content_type = request
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            // The media type alone: a client may append parameters, and `;
            // charset=utf-8` is wrong but the same type.
            if !content_type
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case(DNS_MESSAGE)
            {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            // Bounded before it is read, not after: `Content-Length` is the
            // client's claim and the body is what arrives.
            let limited = http_body_util::Limited::new(request.into_body(), u16::MAX as usize);
            limited
                .collect()
                .await
                .map(|body| body.to_bytes().to_vec())
                .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)
        }
        _ => Err(StatusCode::METHOD_NOT_ALLOWED),
    }
}

/// The smallest TTL in an answer, which is how long an HTTP cache may hold it.
///
/// Zero when the message will not parse or holds no records: a response nothing
/// may cache is the safe reading, and a negative answer's own SOA TTL is
/// already the smallest record in it.
fn min_ttl(message: &[u8]) -> u32 {
    let Ok(parsed) = rdns::DnsMessage::try_from_bytes(message) else {
        return 0;
    };
    parsed
        .answers
        .iter()
        .chain(parsed.authorities.iter())
        .chain(parsed.additionals.iter())
        // No OPT filter: an OPT's TTL is flags, but `DnsMessage::edns` holds
        // it, not the records. `Ttl` is clamped at parse (RFC 2181 §8).
        .map(|record| record.ttl.as_secs())
        .min()
        .unwrap_or(0)
}

fn status(code: StatusCode) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = code;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{context, query};
    use crate::tls::testing::write_pem;
    use crate::ServeContext;
    use rdns::clock::Clock;
    use rdns::shutdown::Shutdown;
    use rustls::pki_types::CertificateDer;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Echoes the message back, after `.1`.
    struct Echo(ServeContext, Duration);

    impl Handler for Echo {
        fn context(&self) -> &ServeContext {
            &self.0
        }

        async fn handle(
            &self,
            packet: Vec<u8>,
            _peer: SocketAddr,
            _now: u64,
            _arrival: Arrival,
            out: tokio::sync::mpsc::Sender<Reply>,
        ) {
            #[expect(
                clippy::disallowed_methods,
                reason = "a slow peer, the subject of the test"
            )]
            tokio::time::sleep(self.1).await;
            crate::tcp::send_framed(&out, &packet).await;
        }
    }

    /// A server on a fresh port, and the client config that trusts it.
    async fn started() -> (SocketAddr, Vec<u8>, Shutdown, tokio::task::JoinHandle<()>) {
        started_with(context(0), RateLimit::PerMessage).await
    }

    /// The same, for a test that is about the admission policy.
    async fn started_with(
        ctx: ServeContext,
        rate: RateLimit,
    ) -> (SocketAddr, Vec<u8>, Shutdown, tokio::task::JoinHandle<()>) {
        started_limited(ctx, rate, TransportLimits::default(), Duration::ZERO).await
    }

    /// The same, for a test that is about a connection limit, with a handler
    /// that takes `delay` over each answer.
    async fn started_limited(
        ctx: ServeContext,
        rate: RateLimit,
        limits: TransportLimits,
        delay: Duration,
    ) -> (SocketAddr, Vec<u8>, Shutdown, tokio::task::JoinHandle<()>) {
        let pem = write_pem("doh", "localhost");
        let store = CertificateStore::load(&pem.cert, &pem.key).expect("loads");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let shutdown = Shutdown::new();
        let task = tokio::spawn({
            let stop = shutdown.stop_handle();
            let busy = shutdown.busy();
            async move {
                let _ = serve(
                    listener,
                    endpoint(store, DEFAULT_PATH, None).expect("a DoH endpoint"),
                    Arc::new(Echo(ctx, delay)),
                    limits,
                    rate,
                    stop,
                    busy,
                )
                .await;
            }
        });
        (addr, pem.der.clone(), shutdown, task)
    }

    /// One HTTP/1.1 request over TLS, written by hand so the test is about the
    /// bytes RFC 8484 §4.1 specifies rather than about a client library.
    async fn request(addr: SocketAddr, der: &[u8], head: &str, body: &[u8]) -> Vec<u8> {
        try_request(addr, der, head, body)
            .await
            .expect("the connection was served")
    }

    /// The same, for a test where the server may refuse before the handshake.
    ///
    /// `None` is a connection the accept loop dropped — which is what a
    /// `PerConnection` refusal looks like from outside, there being no HTTP
    /// yet to carry a 429.
    async fn try_request(addr: SocketAddr, der: &[u8], head: &str, body: &[u8]) -> Option<Vec<u8>> {
        // http/1.1, so the request can be written as text.
        let mut tls = connect(addr, der, ALPN_HTTP11).await?;

        let mut wire = head.as_bytes().to_vec();
        wire.extend_from_slice(body);
        tls.write_all(&wire).await.ok()?;
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        (!out.is_empty()).then_some(out)
    }

    /// A TLS connection to `addr` offering only `alpn`, or `None` when the
    /// handshake failed.
    async fn connect(
        addr: SocketAddr,
        der: &[u8],
        alpn: &[u8],
    ) -> Option<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(der.to_vec()))
            .expect("a root");
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("a name");
        connector.connect(name, tcp).await.ok()
    }

    /// A POST head for `body`, keeping the connection open afterwards.
    fn keep_alive_post(body: &[u8]) -> String {
        format!(
            "POST {DEFAULT_PATH} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
    }

    /// Read until the server closes, or `None` if it has not within five
    /// seconds: the bound that makes an unclosed connection a failure rather
    /// than a hang.
    async fn read_until_closed(stream: &mut (impl AsyncReadExt + Unpin)) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
            .await
            .ok()
            .map(|_| out)
    }

    /// One slot and a 200 ms idle timeout, so a test can show both the close
    /// and that the slot came back.
    fn one_short_slot() -> TransportLimits {
        TransportLimits {
            idle_timeout: Duration::from_millis(200),
            max_connections: 1,
            ..TransportLimits::default()
        }
    }

    /// The listener answers: with one slot, only once the last connection let
    /// go of it.
    async fn answers(addr: SocketAddr, der: &[u8]) {
        let question = query(0x1610);
        let head = format!(
            "POST {DEFAULT_PATH} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/dns-message\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            question.len()
        );
        let response =
            tokio::time::timeout(Duration::from_secs(5), request(addr, der, &head, &question))
                .await
                .expect("the slot was released");
        assert!(split(&response).0.starts_with("HTTP/1.1 200"));
    }

    fn split(response: &[u8]) -> (String, Vec<u8>) {
        let at = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a header/body boundary");
        (
            String::from_utf8_lossy(&response[..at]).to_string(),
            response[at + 4..].to_vec(),
        )
    }

    /// A peer that connects and never sends a ClientHello is closed at the idle
    /// timeout, and its slot goes to the next client. One slot, so the request
    /// after it is answered only if it was released.
    #[tokio::test]
    async fn a_peer_that_never_says_hello_is_closed_and_its_slot_freed() {
        let ctx = context(0);
        let metrics = ctx.metrics.clone();
        let limits = TransportLimits {
            idle_timeout: Duration::from_millis(200),
            max_connections: 1,
            ..TransportLimits::default()
        };
        let (addr, der, shutdown, task) =
            started_limited(ctx, RateLimit::PerMessage, limits, Duration::ZERO).await;

        let mut silent = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut byte = [0u8; 1];
        let closed = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut byte)).await;
        assert!(
            matches!(closed, Ok(Ok(0) | Err(_))),
            "the server closes a handshake that never starts, got {closed:?}"
        );
        assert_eq!(
            metrics
                .tls_handshake_failures
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "and counts it with the other handshake failures"
        );

        let question = query(0x1620);
        let head = format!(
            "POST {DEFAULT_PATH} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/dns-message\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            question.len()
        );
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            request(addr, &der, &head, &question),
        )
        .await
        .expect("the slot was released");
        assert!(split(&response).0.starts_with("HTTP/1.1 200"));

        shutdown.begin();
        task.abort();
    }

    /// One HTTP/2 frame: RFC 9113 §4.1's nine-octet header, then `payload`.
    fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut frame = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        frame.extend_from_slice(&[kind, flags]);
        frame.extend_from_slice(&stream.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// A DoH GET as a HEADERS frame with END_STREAM and END_HEADERS. HPACK by
    /// hand (RFC 7541): indexed `:method GET` and `:scheme https`, then
    /// `:path` and `:authority` as literals with indexed names, not indexed.
    fn h2_get(stream: u32, path: &str) -> Vec<u8> {
        let mut block = vec![0x82, 0x87, 0x04, path.len() as u8];
        block.extend_from_slice(path.as_bytes());
        block.extend_from_slice(&[0x01, 9]);
        block.extend_from_slice(b"localhost");
        h2_frame(0x1, 0x5, stream, &block)
    }

    /// Fails unless a seventeenth stream, opened while sixteen are answered, is
    /// refused; hyper's default of 200 admits it.
    ///
    /// Frames by hand: a conforming client would queue the seventeenth itself.
    #[tokio::test]
    async fn a_seventeenth_http2_stream_is_refused() {
        let (addr, der, shutdown, task) = started_limited(
            context(0),
            RateLimit::PerMessage,
            TransportLimits::default(),
            Duration::from_secs(2),
        )
        .await;
        let mut h2 = connect(addr, &der, ALPN_H2).await.expect("the handshake");
        h2.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .expect("preface");
        h2.write_all(&h2_frame(0x4, 0, 0, &[]))
            .await
            .expect("SETTINGS");

        // h2 applies its SETTINGS once they are acknowledged, so the ACK goes
        // first and the streams after.
        let mut head = [0u8; 9];
        loop {
            h2.read_exact(&mut head).await.expect("a frame");
            let mut payload =
                vec![0u8; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
            h2.read_exact(&mut payload).await.expect("its payload");
            if head[3] == 0x4 && head[4] & 0x1 == 0 {
                break;
            }
        }
        h2.write_all(&h2_frame(0x4, 0x1, 0, &[]))
            .await
            .expect("ACK");

        let path = format!(
            "{DEFAULT_PATH}?dns={}",
            base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(query(0x1700))
        );
        let streams: Vec<u32> = (0..17).map(|i| 1 + 2 * i).collect();
        for &stream in &streams {
            h2.write_all(&h2_get(stream, &path)).await.expect("HEADERS");
        }

        // Inside the handler's two seconds: a refusal is immediate, an answer
        // is not.
        let refused = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                h2.read_exact(&mut head).await.expect("a frame");
                let mut payload =
                    vec![0u8; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
                h2.read_exact(&mut payload).await.expect("its payload");
                let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
                // RST_STREAM, REFUSED_STREAM (RFC 9113 §6.4, §7).
                if head[3] == 0x3 && payload == [0, 0, 0, 0x7] {
                    return stream;
                }
            }
        })
        .await
        .expect("a stream was refused");
        assert_eq!(refused, streams[16], "the seventeenth");

        shutdown.begin();
        task.abort();
    }

    /// An HTTP/2 connection that opens and asks nothing is closed at the idle
    /// timeout, and its slot goes to the next client (`TODO.md` #161).
    #[tokio::test]
    async fn an_http2_connection_with_no_request_is_closed_when_idle() {
        let (addr, der, shutdown, task) = started_limited(
            context(0),
            RateLimit::PerMessage,
            one_short_slot(),
            Duration::ZERO,
        )
        .await;
        let mut h2 = connect(addr, &der, ALPN_H2).await.expect("the handshake");
        // The client preface and an empty SETTINGS frame (RFC 9113 §3.4,
        // §6.5), and then nothing.
        h2.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            .await
            .expect("preface");
        assert!(
            read_until_closed(&mut h2).await.is_some(),
            "an idle HTTP/2 connection is closed"
        );
        answers(addr, &der).await;
        shutdown.begin();
        task.abort();
    }

    /// An HTTP/1.1 keep-alive connection is answered, then closed once no
    /// further request starts.
    #[tokio::test]
    async fn an_http1_connection_is_closed_when_idle_after_an_answer() {
        let (addr, der, shutdown, task) = started_limited(
            context(0),
            RateLimit::PerMessage,
            one_short_slot(),
            Duration::ZERO,
        )
        .await;
        let mut h1 = connect(addr, &der, ALPN_HTTP11)
            .await
            .expect("the handshake");
        let question = query(0x1611);
        h1.write_all(keep_alive_post(&question).as_bytes())
            .await
            .expect("head");
        h1.write_all(&question).await.expect("body");
        let response = read_until_closed(&mut h1)
            .await
            .expect("an idle keep-alive connection is closed");
        let (head, body) = split(&response);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(body, question, "after the answer, not instead of it");
        answers(addr, &der).await;
        shutdown.begin();
        task.abort();
    }

    /// The clock is about requests started, not answers finished: a request
    /// still in flight when it runs out is answered, then the connection
    /// closes. Half again the idle timeout, inside the one more timeout a
    /// graceful close is given.
    #[tokio::test]
    async fn a_request_in_flight_at_the_idle_timeout_is_still_answered() {
        let limits = one_short_slot();
        let (addr, der, shutdown, task) = started_limited(
            context(0),
            RateLimit::PerMessage,
            limits,
            limits.idle_timeout * 3 / 2,
        )
        .await;
        let mut h1 = connect(addr, &der, ALPN_HTTP11)
            .await
            .expect("the handshake");
        let question = query(0x1612);
        h1.write_all(keep_alive_post(&question).as_bytes())
            .await
            .expect("head");
        h1.write_all(&question).await.expect("body");
        let response = read_until_closed(&mut h1).await.expect("closed afterwards");
        let (head, body) = split(&response);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(body, question);
        shutdown.begin();
        task.abort();
    }

    /// A header that never finishes is not a request, so it does not hold the
    /// connection open.
    #[tokio::test]
    async fn a_header_that_never_finishes_is_dropped() {
        let (addr, der, shutdown, task) = started_limited(
            context(0),
            RateLimit::PerMessage,
            one_short_slot(),
            Duration::ZERO,
        )
        .await;
        let mut h1 = connect(addr, &der, ALPN_HTTP11)
            .await
            .expect("the handshake");
        h1.write_all(b"POST /dns-query HTTP/1.1\r\nHost: loc")
            .await
            .expect("half a head");
        assert!(read_until_closed(&mut h1).await.is_some(), "dropped");
        answers(addr, &der).await;
        shutdown.begin();
        task.abort();
    }

    /// Shutdown closes an idle keep-alive connection rather than waiting on
    /// the client, as the TCP loop stops reading at shutdown. The idle timeout
    /// is the default ten seconds, so a close inside the five-second bound is
    /// the shutdown's.
    #[tokio::test]
    async fn shutdown_closes_an_idle_keep_alive_connection() {
        let (addr, der, shutdown, task) = started().await;
        let mut h1 = connect(addr, &der, ALPN_HTTP11)
            .await
            .expect("the handshake");
        let question = query(0x1613);
        h1.write_all(keep_alive_post(&question).as_bytes())
            .await
            .expect("head");
        h1.write_all(&question).await.expect("body");
        let mut status = [0u8; 12];
        h1.read_exact(&mut status).await.expect("the answer starts");
        assert_eq!(&status, b"HTTP/1.1 200");
        shutdown.begin();
        assert!(
            read_until_closed(&mut h1).await.is_some(),
            "shutdown closes the connection"
        );
        task.abort();
    }

    /// A DoH client is charged one token for its connection, not two.
    ///
    /// Fails if `answer` charges again after `serve` charged at accept under
    /// `PerConnection`. A burst of one makes the double charge the difference
    /// between 200 and 429; the clock is the test's, as the limiter refills by
    /// whole seconds.
    #[tokio::test]
    async fn a_doh_connection_is_charged_once_and_not_once_per_request() {
        let clock = Clock::fixed(1_000_000_000);
        let mut ctx = context(1);
        ctx.clock = clock.clone();
        let (addr, der, shutdown, task) = started_with(ctx, RateLimit::PerConnection).await;

        let question = query(0x1111);
        let head = |body: &[u8]| {
            format!(
                "POST /dns-query HTTP/1.1\r\nHost: localhost\r\n\
                 Content-Type: application/dns-message\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            )
        };
        let (headers, body) = split(&request(addr, &der, &head(&question), &question).await);
        assert!(
            headers.starts_with("HTTP/1.1 200 OK"),
            "the connection's own token paid for its first request: {headers}"
        );
        assert_eq!(body, question);

        // The token was spent at accept: the next connection is refused before
        // TLS, so the tell is a dropped connection, not a 429.
        assert!(
            try_request(addr, &der, &head(&question), &question)
                .await
                .is_none(),
            "a second connection is over the burst of one"
        );

        // One second buys one token back, which is what says the first
        // connection was charged rather than never admitted.
        clock.advance(1);
        let (headers, _) = split(&request(addr, &der, &head(&question), &question).await);
        assert!(
            headers.starts_with("HTTP/1.1 200 OK"),
            "the refill admits one: {headers}"
        );

        shutdown.begin();
        task.abort();
    }

    /// POST, which is the form RFC 8484 §4.1 requires of every implementation.
    #[tokio::test]
    async fn a_post_carries_the_message_as_the_body() {
        let (addr, der, shutdown, task) = started().await;
        let question = query(0x7777);
        let head = format!(
            "POST /dns-query HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/dns-message\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            question.len()
        );
        let (headers, body) = split(&request(addr, &der, &head, &question).await);
        assert!(headers.starts_with("HTTP/1.1 200 OK"), "{headers}");
        assert!(
            headers.contains("content-type: application/dns-message"),
            "{headers}"
        );
        assert_eq!(
            body, question,
            "the body is the bare message, with no 2-octet prefix"
        );
        shutdown.begin();
        task.abort();
    }

    /// GET with `?dns=<base64url>`, the cacheable form — and the `Cache-Control`
    /// §5.1 asks for, taken from the smallest TTL in the answer.
    #[tokio::test]
    async fn a_get_takes_base64url_and_the_answer_carries_its_ttl() {
        let (addr, der, shutdown, task) = started().await;
        // One A record at TTL 60; the handler echoes, so its TTL is what
        // `max-age` reflects.
        let wire = crate::testutil::answer_with_ttl(0x2222, 60);

        let encoded = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(&wire);
        let head = format!(
            "GET /dns-query?dns={encoded} HTTP/1.1\r\nHost: localhost\r\n\
             Connection: close\r\n\r\n"
        );
        let (headers, body) = split(&request(addr, &der, &head, b"").await);
        assert!(headers.starts_with("HTTP/1.1 200 OK"), "{headers}");
        assert_eq!(body, wire, "base64url decoded to the message that was sent");
        assert!(
            headers.contains("cache-control: max-age=60"),
            "the smallest TTL in the answer is the HTTP freshness (RFC 8484 §5.1): {headers}"
        );
        shutdown.begin();
        task.abort();
    }

    /// The three ways a request can be wrong, and the status each gets. A server
    /// that answered 200 to all of them would pass the two tests above.
    #[tokio::test]
    async fn a_request_that_is_not_a_dns_query_is_refused_by_kind() {
        let (addr, der, shutdown, task) = started().await;
        for (head, expected) in [
            (
                "GET /nope HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                "404",
            ),
            (
                "GET /dns-query HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                "400",
            ),
            (
                "POST /dns-query HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n",
                "415",
            ),
            (
                "DELETE /dns-query HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                "405",
            ),
        ] {
            let (headers, _) = split(&request(addr, &der, head, b"").await);
            assert!(
                headers.starts_with(&format!("HTTP/1.1 {expected}")),
                "wanted {expected} for {:?}, got {headers}",
                head.lines().next().unwrap_or_default()
            );
        }
        shutdown.begin();
        task.abort();
    }
}
