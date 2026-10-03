//! DNS over QUIC (RFC 9250): one query per stream, framed as on TCP.
//!
//! Architecturally the cheapest of the three encrypted transports, despite
//! being the largest dependency, and the reason is in the mapping: RFC 9250
//! keeps the 2-octet length prefix RFC 1035 §4.2.2 defines, so
//! [`crate::tcp::send_framed`] already produces what goes on a QUIC stream and
//! [`crate::tcp::Handler`] already answers into the sink that feeds it. There is
//! no HTTP anywhere — the RFC calls this a lightweight direct mapping, and what
//! that buys here is that quinn supplies streams and nothing else has to change.
//!
//! **The shape.** A client opens one client-initiated bidirectional stream per
//! query, writes the framed message, and closes its half. The server writes the
//! framed response (or several, for a transfer) and closes its half. The stream
//! is the request/response pairing, which is why the DNS Message ID is
//! redundant and RFC 9250 has a client set it to zero.
//!
//! **The ID is echoed, never checked.** A reply repeats the ID the request
//! carried, which is right whatever the client put there — and refusing a
//! non-zero one would break a client for no gain, since the stream has already
//! done the pairing. The RFC's own reason for the rule is linkability, which is
//! the client's to protect and not something a server can enforce on its behalf.
//!
//! **The certificate is [`crate::tls`]'s**, the same store and the same reload:
//! a renewal that reached DoT and not DoQ would be a certificate expiring on one
//! port of one server (`TODO.md` #42a, #42b).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{Endpoint, ServerConfig};

use rdns::shutdown::{Busy, Stop};
use rdns::validation::{Arrival, PeerCertificate, Transport};

use crate::slots::Slots;
use crate::tcp::{Handler, RateLimit, Reply};
use crate::tls::CertificateStore;
use crate::TransportLimits;
use rdns::metrics::StreamListener;
use rdns::peer::Peer;

/// The port RFC 9250 assigns, which is DoT's.
///
/// The same number on UDP rather than TCP, so the two listeners do not collide
/// and an operator configuring both writes 853 twice.
pub const DOQ_PORT: u16 = 853;

/// The ALPN token RFC 9250 registers. Required, not advertised: unlike DoT this
/// protocol has no pre-ALPN deployment to be gentle with, and QUIC gives no way
/// to tell DNS from anything else without it.
const ALPN_DOQ: &[u8] = b"doq";

/// RFC 9250 §4.3's application error codes.
///
/// Only the three this server can produce are named. The others describe a
/// client's conduct or a condition that cannot arise here, and a constant
/// nothing sends is a claim nothing checks.
///
/// No code is named for closing an idle connection. `DOQ_NO_ERROR` fits: "used
/// when the connection or stream needs to be closed, but there is no error to
/// signal". `DOQ_EXCESSIVE_LOAD` would claim a load nothing here measures.
const DOQ_NO_ERROR: u32 = 0x0;
const DOQ_PROTOCOL_ERROR: u32 = 0x2;
/// "In the absence of a more specific error code": a reply the client starved
/// of credit. Not `DOQ_NO_ERROR`, because the client did starve it.
const DOQ_UNSPECIFIED_ERROR: u32 = 0x5;

/// The quinn configuration a DoQ listener serves under.
pub fn server_config(
    store: Arc<CertificateStore>,
    limits: TransportLimits,
    clients: Option<rdns::tls_identity::TrustAnchors>,
) -> Result<ServerConfig> {
    let crypto = crate::tls::config_with_alpn(store, ALPN_DOQ, clients)?;
    // QUIC is TLS 1.3 only, and this is where a configuration that cannot do
    // 1.3 is refused rather than failing every handshake later.
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .context("the TLS configuration cannot carry QUIC (it needs TLS 1.3)")?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));

    let transport =
        Arc::get_mut(&mut config.transport).expect("the transport config is not shared yet");
    // The same two ceilings the TCP loop applies, expressed where QUIC enforces
    // them for us: a stream is a query, so the in-flight cap is a stream cap.
    // QUIC's idle timer is only the floor for a silent client: RFC 9000 §10.1
    // restarts it on every packet, PINGs included, so `serve_connection` keeps
    // its own (`TODO.md` #164).
    transport.max_concurrent_bidi_streams((limits.max_inflight_per_connection as u32).into());
    // A client has no reason to open one of these, so allowing any is allowing
    // an unanswerable stream to sit there holding memory.
    transport.max_concurrent_uni_streams(0u32.into());
    transport.max_idle_timeout(Some(
        limits
            .idle_timeout
            .try_into()
            .context("the idle timeout does not fit a QUIC transport parameter")?,
    ));
    Ok(config)
}

/// Accept QUIC connections and serve each one's streams, until told to stop.
pub async fn serve<H: Handler>(
    endpoint: Endpoint,
    handler: Arc<H>,
    limits: TransportLimits,
    rate: RateLimit,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    let slots = Slots::new(
        limits.max_connections,
        &handler.context().metrics,
        StreamListener::Doq,
        handler.context().per_source.clone(),
    );
    loop {
        // Before `accept`, as `tcp::serve` does: a full listener leaves the
        // next attempt with quinn rather than taking it on here.
        let mut slot = tokio::select! {
            slot = slots.take() => slot,
            _ = stop.wait() => {
                shut_down(&endpoint, limits.idle_timeout).await;
                return Ok(());
            }
        };
        let incoming = tokio::select! {
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                // The endpoint is closed and will accept nothing further.
                None => return Ok(()),
            },
            _ = stop.wait() => {
                shut_down(&endpoint, limits.idle_timeout).await;
                return Ok(());
            }
        };
        // Canonical before anything sees it, as in `tcp::serve`; quinn keeps
        // the address it replies to itself.
        let peer = rdns::peer::canonical(incoming.remote_address());
        if !rate.admits_connection(handler.context(), Peer::from(peer)) {
            // Refuse before the handshake: a retry-able refusal costs the
            // source a round trip and costs us no crypto at all.
            incoming.refuse();
            continue;
        }
        if !slot.open(Peer::from(peer)) {
            // Before the handshake, like the rate refusal above.
            incoming.refuse();
            continue;
        }
        let handler = handler.clone();
        let stop = stop.clone();
        let busy = busy.clone();
        tokio::spawn(async move {
            // The handshake is here rather than in the accept loop, for the
            // reason `tls::serve` gives: it is a round trip with a stranger.
            match incoming.await {
                Ok(connection) => {
                    handler
                        .context()
                        .metrics
                        .count(&handler.context().metrics.quic_handshakes);
                    serve_connection(connection, peer, handler, limits, rate, stop).await;
                }
                Err(e) => {
                    handler
                        .context()
                        .metrics
                        .count(&handler.context().metrics.quic_handshake_failures);
                    tracing::debug!(peer = %peer.ip(), "QUIC handshake failed: {e}");
                }
            }
            drop(slot);
            drop(busy);
        });
    }
}

/// Stop taking connections and wait for those open to close themselves.
///
/// Not `Endpoint::close` first: a CONNECTION_CLOSE ends every stream at once
/// (RFC 9000 §10.2), so it would cut off the answers `serve_connection` lets
/// finish. Each connection closes within `idle` of the stop; the close here is
/// for one that has not, such as a handshake still running. Waiting for the
/// endpoint to go idle is what gives every peer its CONNECTION_CLOSE.
async fn shut_down(endpoint: &Endpoint, idle: std::time::Duration) {
    // A new Initial now gets a stateless reset.
    endpoint.set_server_config(None);
    if tokio::time::timeout(idle * 2, endpoint.wait_idle())
        .await
        .is_err()
    {
        endpoint.close(DOQ_NO_ERROR.into(), b"shutting down");
        endpoint.wait_idle().await;
    }
}

/// One connection: a query per bidirectional stream, answered concurrently.
///
/// Closed once no stream has started for `idle_timeout`, whatever is in flight
/// (`CONTEXT.md`'s idle, as on TCP and DoH), or at shutdown. Either way no
/// further stream is accepted, those in flight get one more `idle_timeout` to
/// finish, and the close carries `DOQ_NO_ERROR`. RFC 9250 has no graceful
/// drain, so the wait is ours; a stream the client opens meanwhile is reset by
/// the close, abandoned as §4.4 has it.
async fn serve_connection<H: Handler>(
    connection: quinn::Connection,
    peer: SocketAddr,
    handler: Arc<H>,
    limits: TransportLimits,
    rate: RateLimit,
    stop: Stop,
) {
    // Read once per connection, not per stream: the handshake is the only place
    // a certificate is presented, and a transfer over DoQ is authorized from it
    // exactly as one over DoT is (`TODO.md` #59). `peer_identity` is quinn's
    // `Box<dyn Any>` because the crypto layer is generic; under rustls it is the
    // chain, leaf first.
    let presented = match connection
        .peer_identity()
        .and_then(|identity| {
            identity
                .downcast::<Vec<rustls::pki_types::CertificateDer>>()
                .ok()
        })
        .and_then(|chain| chain.first().map(|leaf| leaf.as_ref().to_vec()))
    {
        Some(der) => PeerCertificate::presented(der),
        None => PeerCertificate::none(),
    };
    let idle = limits.idle_timeout;
    let mut idle_at = tokio::time::Instant::now() + idle;
    let mut streams = tokio::task::JoinSet::new();
    let why: &[u8] = loop {
        // `accept_bi` is the shutdown check's home for the same reason the TCP
        // loop checks between messages: between streams the peer has committed
        // to nothing.
        let stream = tokio::select! {
            stream = connection.accept_bi() => stream,
            () = tokio::time::sleep_until(idle_at) => break b"idle",
            () = stop.wait() => break b"shutting down",
        };
        let (send, recv) = match stream {
            Ok(pair) => pair,
            // Ordinary: the client is done and closed the connection.
            Err(_) => return,
        };
        idle_at = tokio::time::Instant::now() + idle;
        while streams.try_join_next().is_some() {}

        let now = handler.context().clock.now();
        if !rate.admits_message(handler.context(), Peer::from(peer), now) {
            continue;
        }
        let client = Client {
            connection: connection.clone(),
            peer,
            presented: presented.clone(),
        };
        streams.spawn(serve_stream(
            send,
            recv,
            client,
            handler.clone(),
            limits,
            now,
        ));
    };
    let _ =
        tokio::time::timeout(idle, async { while streams.join_next().await.is_some() {} }).await;
    connection.close(DOQ_NO_ERROR.into(), why);
}

/// What a stream knows of the connection it arrived on.
struct Client {
    /// To close, for a fault RFC 9250 answers on the connection.
    connection: quinn::Connection,
    peer: SocketAddr,
    presented: PeerCertificate,
}

/// One stream: read the framed query, answer it, close.
async fn serve_stream<H: Handler>(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    client: Client,
    handler: Arc<H>,
    limits: TransportLimits,
    now: u64,
) {
    let Client {
        connection,
        peer,
        presented,
    } = client;
    // The client closes its half after one query, so reading to the end is the
    // whole message and needs no length prefix to bound it — but the prefix is
    // there (RFC 9250 keeps RFC 1035 §4.2.2's framing) and is what says how much
    // of what arrived is the message.
    //
    // Bounded by what the prefix can describe, which is the same bound the TCP
    // loop works under: it reads a u16 length and no more. The daemon's
    // configured cap is applied below by `accept_packet`, on the message rather
    // than on the stream, exactly as on TCP -- one place decides how big a
    // request may be and it is not per transport.
    //
    // A query with no FIN after `read_timeout` is a "dangling" stream
    // (RFC 9250 §4.2), and a missing FIN is on §4.3.3's list: "SHOULD forcibly
    // abort the connection ... and SHOULD use the DoQ error code
    // DOQ_PROTOCOL_ERROR" -- as a stalled message ends a TCP connection.
    let raw =
        match tokio::time::timeout(limits.read_timeout, recv.read_to_end(u16::MAX as usize + 2))
            .await
        {
            Ok(Ok(raw)) => raw,
            Ok(Err(e)) => {
                handler.context().logger.count_error(Peer::from(peer));
                tracing::debug!(peer = %peer.ip(), "QUIC stream read error: {e}");
                let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
                return;
            }
            Err(_) => {
                handler.context().logger.count_error(Peer::from(peer));
                tracing::debug!(peer = %peer.ip(), "QUIC query stream sent no FIN");
                connection.close(DOQ_PROTOCOL_ERROR.into(), b"no STREAM FIN");
                return;
            }
        };
    if raw.len() < 2 {
        handler.context().logger.count_error(Peer::from(peer));
        tracing::debug!(peer = %peer.ip(), "QUIC stream too short to hold a length prefix");
        let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
        return;
    }
    let len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
    if len == 0 || raw.len() < 2 + len {
        handler.context().logger.count_error(Peer::from(peer));
        tracing::debug!(
            peer = %peer.ip(),
            "QUIC stream says {len} octets and carries {}",
            raw.len().saturating_sub(2)
        );
        let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
        return;
    }
    let packet = raw[2..2 + len].to_vec();

    if !handler
        .context()
        .accept_packet(Peer::from(peer), &packet, Transport::Tcp)
    {
        // Same cap as TCP and for the same reason: a stream is not a datagram,
        // so the UDP ceiling is the wrong one to judge it by.
        let _ = send.finish();
        return;
    }

    // A channel per stream, so the handler is the one it already is. A transfer
    // answers with several framed messages and they all belong on this stream
    // (RFC 9250 permits that, and it is what makes XFR-over-DoQ the same code).
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Reply>(limits.max_inflight_per_connection);
    let logger = handler.context().logger.clone();
    let answering = tokio::spawn(async move {
        // Unconditionally 1.3: RFC 9001 §4.2 gives QUIC no other option
        // ("QUIC ... MUST use TLS 1.3 or greater"), so there is no handshake to
        // interrogate the way `tls.rs` has to.
        handler
            .handle(packet, peer, now, Arrival::Doq(presented), tx)
            .await;
    });

    while let Some(reply) = rx.recv().await {
        let Reply::Frame(framed) = reply else {
            // `Reply::Abort`: a transfer that cannot be finished. Resetting says
            // so, where finishing cleanly would read as a complete answer.
            let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
            let _ = answering.await;
            return;
        };
        // The RFC leaves a reply never read to flow control (§5.8). Reset per
        // stream: QUIC credit is per stream, so one starved stream says nothing
        // of the others. quinn reports a lost connection as `NotConnected`, so
        // `TimedOut` is the stall.
        if let Err(e) = crate::write_progressing(&mut send, &framed, limits.read_timeout).await {
            if e.kind() == std::io::ErrorKind::TimedOut {
                logger.count_error(Peer::from(peer));
                tracing::debug!(peer = %peer.ip(), "QUIC reply stalled: {e}");
                let _ = send.reset(DOQ_UNSPECIFIED_ERROR.into());
            }
            // Before the await: a transfer still answering would otherwise
            // block on a full channel nobody drains.
            drop(rx);
            let _ = answering.await;
            return;
        }
    }
    // Closing our half is how the client knows the answer is complete.
    let _ = send.finish();
    let _ = answering.await;
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::testutil::{context, id_of, query};
    use crate::tls::testing::{write_pem, Pem};
    use crate::ServeContext;
    use rdns::metrics::DnsMetrics;
    use rdns::shutdown::Shutdown;

    /// The id answered as a transfer is: more envelopes than the reply channel
    /// holds, each 60 KB, so one connection can carry a reply that outgrows a
    /// small receive window beside one that fits.
    const BULK: u16 = 0xb0b0;

    struct Echo {
        ctx: ServeContext,
        /// How long `handle` waits before answering, for a stream that must
        /// still be in flight when something else happens.
        pause: Duration,
        /// Signalled as `handle` starts. A sleep standing in for it lost the
        /// race under load in `tcp.rs` (`TODO.md` #120a).
        started: Arc<tokio::sync::Notify>,
        /// Signalled as a `BULK` transfer returns.
        finished: Arc<tokio::sync::Notify>,
    }

    impl Handler for Echo {
        fn context(&self) -> &ServeContext {
            &self.ctx
        }

        async fn handle(
            &self,
            packet: Vec<u8>,
            _peer: SocketAddr,
            _now: u64,
            _arrival: Arrival,
            out: tokio::sync::mpsc::Sender<Reply>,
        ) {
            self.started.notify_one();
            tokio::time::sleep(self.pause).await;
            if id_of(&packet) == BULK {
                let mut reply = vec![0u8; 60_000];
                reply[..2].copy_from_slice(&packet[..2]);
                for _ in 0..TransportLimits::default().max_inflight_per_connection + 4 {
                    if !crate::tcp::send_framed(&out, &reply).await {
                        break;
                    }
                }
                self.finished.notify_one();
            } else {
                crate::tcp::send_framed(&out, &packet).await;
            }
        }
    }

    /// A DoQ listener on loopback, served by `serve` as the daemons run it.
    struct Server {
        addr: SocketAddr,
        pem: Pem,
        shutdown: Shutdown,
        metrics: Arc<DnsMetrics>,
        started: Arc<tokio::sync::Notify>,
        finished: Arc<tokio::sync::Notify>,
        task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    }

    impl Server {
        async fn start(limits: TransportLimits, pause: Duration) -> Server {
            let pem = write_pem("doq", "localhost");
            let store = CertificateStore::load(&pem.cert, &pem.key).expect("loads");
            let endpoint = Endpoint::server(
                server_config(store, limits, None).expect("a quinn config"),
                "127.0.0.1:0".parse().expect("an address"),
            )
            .expect("bind");
            let addr = endpoint.local_addr().expect("addr");
            let shutdown = Shutdown::new();
            let handler = Arc::new(Echo {
                ctx: context(0),
                pause,
                started: Arc::new(tokio::sync::Notify::new()),
                finished: Arc::new(tokio::sync::Notify::new()),
            });
            let metrics = handler.ctx.metrics.clone();
            let started = handler.started.clone();
            let finished = handler.finished.clone();
            let task = tokio::spawn(serve(
                endpoint,
                handler,
                limits,
                RateLimit::PerMessage,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));
            Server {
                addr,
                pem,
                shutdown,
                metrics,
                started,
                finished,
                task,
            }
        }

        /// A connection from a client configured by `transport`, trusting
        /// exactly this server's certificate and offering DoQ's ALPN token.
        async fn connect(&self, transport: quinn::TransportConfig) -> quinn::Connection {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(rustls::pki_types::CertificateDer::from(
                    self.pem.der.clone(),
                ))
                .expect("a root");
            let mut crypto = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            crypto.alpn_protocols = vec![ALPN_DOQ.to_vec()];
            let mut config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("TLS 1.3"),
            ));
            config.transport_config(Arc::new(transport));
            let mut endpoint =
                Endpoint::client("127.0.0.1:0".parse().expect("an address")).expect("client bind");
            endpoint.set_default_client_config(config);
            endpoint
                .connect(self.addr, "localhost")
                .expect("connect")
                .await
                .expect("the handshake")
        }

        /// Until the listener holds no connection, or a failure after five
        /// seconds rather than a hang.
        async fn slots_free(&self) {
            let doq = self.metrics.listener(StreamListener::Doq);
            tokio::time::timeout(Duration::from_secs(5), async {
                while doq.open() > 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the slot was released");
        }
    }

    /// A client that PINGs every 100 ms, which is what keeps QUIC's own idle
    /// timer from ever firing.
    fn pinging() -> quinn::TransportConfig {
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_millis(100)));
        transport
    }

    /// A short idle timeout, so a test sees the close in a fraction of a
    /// second.
    fn idle_300ms() -> TransportLimits {
        TransportLimits {
            idle_timeout: Duration::from_millis(300),
            ..TransportLimits::default()
        }
    }

    /// One framed query on a fresh stream, FIN sent, and what came back.
    async fn ask(
        connection: &quinn::Connection,
        id: u16,
    ) -> Result<Vec<u8>, quinn::ReadToEndError> {
        let (mut send, mut recv) = connection.open_bi().await.expect("a stream");
        send.write_all(&rdns::framed(&query(id)).expect("frames"))
            .await
            .expect("write");
        send.finish().expect("finish");
        recv.read_to_end(64 * 1024).await
    }

    /// How the connection ended, or a failure once `bound` has passed with it
    /// still open.
    async fn closed_within(
        connection: &quinn::Connection,
        bound: Duration,
    ) -> quinn::ConnectionError {
        tokio::time::timeout(bound, connection.closed())
            .await
            .expect("the server closed the connection")
    }

    fn application_code(closed: &quinn::ConnectionError) -> Option<u64> {
        match closed {
            quinn::ConnectionError::ApplicationClosed(close) => Some(close.error_code.into()),
            _ => None,
        }
    }

    /// The whole of 42b: a real QUIC handshake, one query on one bidirectional
    /// stream, framed exactly as on TCP, answered and the stream closed.
    #[tokio::test]
    async fn a_doq_client_gets_an_answer_on_its_own_stream() {
        let server = Server::start(TransportLimits::default(), Duration::ZERO).await;
        let connection = server.connect(quinn::TransportConfig::default()).await;

        // Two queries on two streams, because "one query per stream" is the
        // mapping and a second one on the same connection is what proves the
        // loop keeps accepting rather than answering once.
        for id in [0x0000u16, 0x1234] {
            let question = query(id);
            let answered = ask(&connection, id).await.expect("read");
            assert!(answered.len() > 2, "a length prefix and a message");
            let len = u16::from_be_bytes([answered[0], answered[1]]) as usize;
            assert_eq!(len, question.len(), "the prefix describes the message");
            assert_eq!(
                &answered[2..2 + len],
                &question[..],
                "and the message came back unchanged, id {id:#06x} included"
            );
        }

        assert_eq!(
            server
                .metrics
                .quic_handshakes
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one connection, two streams"
        );

        server.shutdown.begin();
        server.task.abort();
    }

    /// A stream whose length prefix does not describe what it carries is a
    /// protocol error, not an answer. Reset rather than closed, because a clean
    /// close is how this server says "that is the whole answer".
    #[tokio::test]
    async fn a_stream_that_is_framed_wrongly_is_reset() {
        let server = Server::start(TransportLimits::default(), Duration::ZERO).await;
        let connection = server.connect(quinn::TransportConfig::default()).await;

        // Says 300 octets and carries four.
        let (mut send, mut recv) = connection.open_bi().await.expect("a stream");
        send.write_all(&[0x01, 0x2c, 0xde, 0xad])
            .await
            .expect("write");
        send.finish().expect("finish");

        match recv.read_to_end(64 * 1024).await {
            Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) => {
                assert_eq!(u64::from(code), u64::from(DOQ_PROTOCOL_ERROR));
            }
            other => panic!("expected a reset carrying DOQ_PROTOCOL_ERROR, got {other:?}"),
        }

        server.shutdown.begin();
        server.task.abort();
    }

    /// PINGs restart QUIC's idle timer (RFC 9000 §10.1) and are not a query,
    /// so they must not hold a connection and its slot (`TODO.md` #164).
    ///
    /// Watched failing without `serve_connection`'s idle deadline: the
    /// connection was still open at the bound.
    #[tokio::test]
    async fn a_client_sending_only_pings_is_closed_when_idle() {
        let server = Server::start(idle_300ms(), Duration::ZERO).await;
        let connection = server.connect(pinging()).await;

        let closed = closed_within(&connection, Duration::from_secs(3)).await;
        assert_eq!(
            application_code(&closed),
            Some(u64::from(DOQ_NO_ERROR)),
            "{closed:?}"
        );
        server.slots_free().await;

        server.shutdown.begin();
        let _ = server.task.await;
    }

    /// Idle is no new stream, whatever is in flight, so the clock runs while
    /// this one is answered; the close waits for it.
    ///
    /// Watched failing with the close made as soon as the deadline passed:
    /// the stream was cut off by the CONNECTION_CLOSE.
    #[tokio::test]
    async fn a_stream_in_flight_at_the_idle_timeout_is_answered() {
        // Half again the idle timeout, inside the one more the drain allows.
        let server = Server::start(idle_300ms(), Duration::from_millis(450)).await;
        let connection = server.connect(pinging()).await;

        let answered = ask(&connection, 0x0101).await.expect("answered");
        assert_eq!(id_of(&answered[2..]), 0x0101);
        let closed = closed_within(&connection, Duration::from_secs(3)).await;
        assert_eq!(
            application_code(&closed),
            Some(u64::from(DOQ_NO_ERROR)),
            "{closed:?}"
        );

        server.shutdown.begin();
        let _ = server.task.await;
    }

    /// A reply the client never reads, with or without PINGs, does not hold
    /// the connection past about twice the idle timeout: one for no new
    /// stream, one for the drain. `read_timeout` is left at its 5 s so the
    /// stall reset is not what ends it.
    ///
    /// Watched failing without the idle deadline: with PINGs the connection
    /// was open at the bound. Without PINGs it passed before, closed by QUIC's
    /// own timer, as triage measured.
    #[tokio::test]
    async fn a_reply_never_read_does_not_hold_the_connection() {
        for pings in [false, true] {
            let server = Server::start(idle_300ms(), Duration::ZERO).await;
            let mut transport = if pings {
                pinging()
            } else {
                quinn::TransportConfig::default()
            };
            transport.stream_receive_window(8u32.into());
            let connection = server.connect(transport).await;

            let (mut send, _unread) = connection.open_bi().await.expect("a stream");
            send.write_all(&rdns::framed(&query(0x0202)).expect("frames"))
                .await
                .expect("write");
            send.finish().expect("finish");

            let began = std::time::Instant::now();
            closed_within(&connection, Duration::from_secs(3)).await;
            // A ceiling of five timeouts, not a measurement (`CLAUDE.md`
            // §10): the outcomes are "about two" and "never".
            assert!(
                began.elapsed() < Duration::from_millis(1500),
                "closed after {:?}, pings {pings}",
                began.elapsed()
            );
            server.slots_free().await;

            server.shutdown.begin();
            let _ = server.task.await;
        }
    }

    /// Shutdown closes a connection that is open and idle, with
    /// `DOQ_NO_ERROR`, and the listener returns.
    ///
    /// Not a regression test: the old `Endpoint::close` at the stop did this
    /// too. The next one is what that close got wrong.
    #[tokio::test]
    async fn shutdown_closes_an_idle_connection() {
        let server = Server::start(TransportLimits::default(), Duration::ZERO).await;
        let connection = server.connect(pinging()).await;
        assert!(ask(&connection, 0x0303).await.is_ok());

        server.shutdown.begin();
        let closed = closed_within(&connection, Duration::from_secs(3)).await;
        assert_eq!(
            application_code(&closed),
            Some(u64::from(DOQ_NO_ERROR)),
            "{closed:?}"
        );
        tokio::time::timeout(Duration::from_secs(5), server.task)
            .await
            .expect("the listener returned")
            .expect("and did not panic")
            .expect("cleanly");
    }

    /// Shutdown answers a stream already in flight before closing, as on TCP:
    /// a CONNECTION_CLOSE ends every stream at once (RFC 9000 §10.2).
    ///
    /// Watched failing against the old stop, which closed the endpoint at
    /// once: the stream ended with the connection.
    #[tokio::test]
    async fn shutdown_answers_a_stream_already_in_flight() {
        let server = Server::start(TransportLimits::default(), Duration::from_millis(300)).await;
        let connection = server.connect(quinn::TransportConfig::default()).await;

        let asking = {
            let connection = connection.clone();
            tokio::spawn(async move { ask(&connection, 0x0404).await })
        };
        tokio::time::timeout(Duration::from_secs(5), server.started.notified())
            .await
            .expect("the handler was given the query");
        server.shutdown.begin();

        let answered = asking.await.expect("the task").expect("answered");
        assert_eq!(id_of(&answered[2..]), 0x0404);
        closed_within(&connection, Duration::from_secs(3)).await;
        let _ = server.task.await;
    }

    /// A query stream with no FIN is "dangling" (RFC 9250 §4.2), and a missing
    /// FIN is a protocol error that "SHOULD forcibly abort the connection"
    /// with `DOQ_PROTOCOL_ERROR` (§4.3.3).
    ///
    /// Watched failing without the read deadline: the connection was still
    /// open at the bound.
    #[tokio::test]
    async fn a_query_stream_with_no_fin_closes_the_connection() {
        let limits = TransportLimits {
            read_timeout: Duration::from_millis(200),
            ..TransportLimits::default()
        };
        let server = Server::start(limits, Duration::ZERO).await;
        let connection = server.connect(quinn::TransportConfig::default()).await;

        let (mut send, _recv) = connection.open_bi().await.expect("a stream");
        send.write_all(&rdns::framed(&query(0x0505)).expect("frames"))
            .await
            .expect("write");

        let closed = closed_within(&connection, Duration::from_secs(3)).await;
        assert_eq!(
            application_code(&closed),
            Some(u64::from(DOQ_PROTOCOL_ERROR)),
            "{closed:?}"
        );

        server.shutdown.begin();
        let _ = server.task.await;
    }

    /// A reply starved of stream credit is reset with `DOQ_UNSPECIFIED_ERROR`
    /// after `read_timeout` without progress, and only that stream: credit is
    /// per stream, so another on the same connection is still answered.
    ///
    /// And the transfer answering it stops, rather than blocking on a reply
    /// channel nobody drains.
    ///
    /// Watched failing without the progress deadline: the starved stream was
    /// never reset. Without dropping the channel before awaiting the handler,
    /// the handler never returned.
    #[tokio::test]
    async fn a_reply_starved_of_credit_resets_only_its_stream() {
        let limits = TransportLimits {
            read_timeout: Duration::from_millis(200),
            ..TransportLimits::default()
        };
        let server = Server::start(limits, Duration::ZERO).await;
        let mut transport = quinn::TransportConfig::default();
        // Room for an echo, not for `BULK`'s 60 KB.
        transport.stream_receive_window(1024u32.into());
        let connection = server.connect(transport).await;

        let (mut send, mut starved) = connection.open_bi().await.expect("a stream");
        send.write_all(&rdns::framed(&query(BULK)).expect("frames"))
            .await
            .expect("write");
        send.finish().expect("finish");
        // Unread until the deadline has passed, so no credit is granted.
        tokio::time::sleep(Duration::from_millis(600)).await;

        let answered = ask(&connection, 0x0606).await.expect("the other stream");
        assert_eq!(id_of(&answered[2..]), 0x0606);
        match tokio::time::timeout(Duration::from_secs(3), starved.read_to_end(64 * 1024)).await {
            Ok(Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)))) => {
                assert_eq!(u64::from(code), u64::from(DOQ_UNSPECIFIED_ERROR));
            }
            other => panic!("expected a reset carrying DOQ_UNSPECIFIED_ERROR, got {other:?}"),
        }
        tokio::time::timeout(Duration::from_secs(3), server.finished.notified())
            .await
            .expect("the transfer stopped");

        server.shutdown.begin();
        let _ = server.task.await;
    }
}
