//! DNS over HTTPS (RFC 8484): a DNS message as an HTTP body.
//!
//! The odd one of the three. DoT and DoQ carry the wire format unchanged — the
//! 2-octet prefix RFC 1035 §4.2.2 defines — and this does not: RFC 8484 §4.1
//! sends the bare message as an entity body, with the length in
//! `Content-Length` where the prefix used to be. So [`crate::tcp::send_framed`]
//! still produces the reply and this module takes the prefix back off, which is
//! the one place in the tree where framing is removed rather than added.
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
//! response is one message — so a handler that emits several has its first
//! answer sent and the rest dropped, with a warning. RFC 8484 defines no
//! framing that would carry the rest, and inventing one would be a protocol
//! this tree made up.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use rdns::shutdown::{Busy, Stop};
use rdns::validation::{Privacy, Transport};

use crate::tcp::{Handler, RateLimit, Reply};
use crate::tls::CertificateStore;
use crate::TransportLimits;

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
pub fn endpoint(store: Arc<CertificateStore>, path: &str) -> Endpoint {
    let mut config = crate::tls::config_with_alpn(store, ALPN_H2);
    config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()];
    Endpoint {
        tls: Arc::new(config),
        path: Arc::from(path),
    }
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
    let permits = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = stop.wait() => return Ok(()),
        };
        if rate == RateLimit::PerConnection
            && !handler
                .context()
                .allow_source(peer.ip(), rdns::clock::current_unix_timestamp())
        {
            continue;
        }
        let Ok(permit) = permits.clone().acquire_owned().await else {
            continue;
        };
        let acceptor = acceptor.clone();
        let handler = handler.clone();
        let path = path.clone();
        let stop = stop.clone();
        let busy = busy.clone();
        tokio::spawn(async move {
            // The handshake is in the connection's own task, as it is for DoT
            // and DoQ: two round trips with a stranger do not belong in an
            // accept loop.
            let stream = tokio::select! {
                accepted = acceptor.accept(stream) => accepted,
                _ = stop.wait() => {
                    drop(permit);
                    drop(busy);
                    return;
                }
            };
            let stream = match stream {
                Ok(stream) => stream,
                Err(e) => {
                    handler
                        .context()
                        .metrics
                        .count(&handler.context().metrics.tls_handshake_failures);
                    tracing::debug!(peer = %peer.ip(), "HTTPS handshake failed: {e}");
                    drop(permit);
                    drop(busy);
                    return;
                }
            };
            handler
                .context()
                .metrics
                .count(&handler.context().metrics.tls_handshakes);

            let negotiated_h2 = stream.get_ref().1.alpn_protocol() == Some(ALPN_H2);
            // From the finished handshake, as DoT does it: this build offers
            // 1.2 as well, and a transfer wants 1.3 (RFC 9103 §7.2).
            let privacy = match stream.get_ref().1.protocol_version() {
                Some(rustls::ProtocolVersion::TLSv1_3) => Privacy::Tls13,
                _ => Privacy::TlsOlder,
            };
            let service = service_fn(move |request| {
                let handler = handler.clone();
                let path = path.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        answer(request, peer, handler, path, privacy).await,
                    )
                }
            });
            let io = TokioIo::new(stream);
            // Chosen from ALPN rather than sniffed: hyper's `auto` builder would
            // do the same by reading the preface, and the handshake has already
            // told us.
            let served = if negotiated_h2 {
                hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
            } else {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
            };
            if let Err(e) = served {
                tracing::debug!(peer = %peer.ip(), "HTTPS connection ended: {e}");
            }
            drop(permit);
            drop(busy);
        });
    }
}

/// One HTTP request: find the DNS message in it, answer it, wrap the answer.
async fn answer<H: Handler>(
    request: Request<Incoming>,
    peer: SocketAddr,
    handler: Arc<H>,
    path: Arc<str>,
    privacy: Privacy,
) -> Response<Full<Bytes>> {
    if request.uri().path() != &*path {
        return status(StatusCode::NOT_FOUND);
    }
    let query = match extract(request).await {
        Ok(query) => query,
        Err(code) => return status(code),
    };

    let now = rdns::clock::current_unix_timestamp();
    if !handler.context().allow_source(peer.ip(), now) {
        // 429 rather than a silent drop, and the difference from UDP is the
        // point: this peer completed a TCP and a TLS handshake, so there is
        // nobody to reflect an answer at and nothing to gain by staying quiet.
        return status(StatusCode::TOO_MANY_REQUESTS);
    }
    // The TCP cap, not the UDP one: a body is not a datagram.
    if !handler
        .context()
        .accept_packet(peer.ip(), &query, Transport::Tcp)
    {
        return status(StatusCode::BAD_REQUEST);
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Reply>(4);
    let answering = tokio::spawn(async move {
        handler.handle(query, peer, now, privacy, tx).await;
    });

    let mut answer = None;
    let mut extra = 0usize;
    while let Some(reply) = rx.recv().await {
        match reply {
            // `send_framed` put a 2-octet length prefix on it, because that is
            // what every other transport wants. RFC 8484 §4.1 puts the length in
            // `Content-Length` instead, so it comes back off here.
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
        // A transfer. One HTTP response is one DNS message and RFC 8484 defines
        // no framing for a sequence, so the rest cannot be sent — and a client
        // receiving only the first envelope of an AXFR must not mistake it for
        // the zone.
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
            // RFC 8484 §5.1: the freshness of the HTTP response should follow
            // the smallest TTL in the answer, so an HTTP cache between client
            // and server cannot hold a record past its own lifetime.
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
            // `?dns=<base64url>`, unpadded (RFC 8484 §4.1). Padding is not
            // rejected outright — some clients send it — but the unpadded
            // alphabet is what the RFC specifies.
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
            // Compared on the media type alone: a client may append parameters,
            // and `application/dns-message; charset=utf-8` is wrong but is not
            // a different type.
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
        // No OPT filter, and that is worth a sentence rather than silence: an
        // OPT's TTL field is a flags word rather than a lifetime, so one in the
        // additional section would make every answer with DO clear `max-age=0`
        // and quietly disable HTTP caching for the whole endpoint. It cannot
        // happen here because #13d took the pseudo-record out of the resource
        // list — `DnsMessage::edns` holds it — which is `CLAUDE.md` §17's
        // "make it unrepresentable" paying out in a module written years later.
        //
        // No clamp either: `Ttl` is unsigned by construction, clamped once at
        // the parse boundary per RFC 2181 §8.
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
    use rdns::shutdown::Shutdown;
    use rustls::pki_types::CertificateDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Echo(ServeContext);

    impl Handler for Echo {
        fn context(&self) -> &ServeContext {
            &self.0
        }

        async fn handle(
            &self,
            packet: Vec<u8>,
            _peer: SocketAddr,
            _now: u64,
            _privacy: Privacy,
            out: tokio::sync::mpsc::Sender<Reply>,
        ) {
            crate::tcp::send_framed(&out, &packet).await;
        }
    }

    /// A server on a fresh port, and the client config that trusts it.
    async fn started() -> (SocketAddr, Vec<u8>, Shutdown, tokio::task::JoinHandle<()>) {
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
                    endpoint(store, DEFAULT_PATH),
                    Arc::new(Echo(context(0))),
                    TransportLimits::default(),
                    RateLimit::PerMessage,
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
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(der.to_vec()))
            .expect("a root");
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // http/1.1, so the request can be written as text.
        config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("a name");
        let mut tls = connector.connect(name, tcp).await.expect("handshake");

        let mut wire = head.as_bytes().to_vec();
        wire.extend_from_slice(body);
        tls.write_all(&wire).await.expect("write");
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        out
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
        // One A record at TTL 60, so `max-age` has something to be. The handler
        // echoes, so what is sent is what comes back and is what gets parsed
        // for its TTL.
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
