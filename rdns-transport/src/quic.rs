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
use rdns::validation::Transport;

use crate::tcp::{Handler, RateLimit, Reply};
use crate::tls::CertificateStore;
use crate::TransportLimits;

/// The port RFC 9250 assigns, which is DoT's.
///
/// The same number on UDP rather than TCP, so the two listeners do not collide
/// and an operator configuring both writes 853 twice.
pub const DOQ_PORT: u16 = 853;

/// The ALPN token RFC 9250 registers. Required, not advertised: unlike DoT this
/// protocol has no pre-ALPN deployment to be gentle with, and QUIC gives no way
/// to tell DNS from anything else without it.
const ALPN_DOQ: &[u8] = b"doq";

/// RFC 9250's application error code for a stream the peer framed wrongly.
///
/// Only the two this server can produce are named. The others describe a
/// client's conduct or a condition that cannot arise here, and a constant
/// nothing sends is a claim nothing checks.
const DOQ_NO_ERROR: u32 = 0x0;
const DOQ_PROTOCOL_ERROR: u32 = 0x2;

/// The quinn configuration a DoQ listener serves under.
pub fn server_config(
    store: Arc<CertificateStore>,
    limits: TransportLimits,
) -> Result<ServerConfig> {
    let crypto = crate::tls::config_with_alpn(store, ALPN_DOQ);
    // QUIC is TLS 1.3 only, and this is where a configuration that cannot do
    // 1.3 is refused rather than failing every handshake later.
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .context("the TLS configuration cannot carry QUIC (it needs TLS 1.3)")?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));

    let transport =
        Arc::get_mut(&mut config.transport).expect("the transport config is not shared yet");
    // The same two ceilings the TCP loop applies, expressed where QUIC enforces
    // them for us: a stream is a query, so the in-flight cap is a stream cap,
    // and an idle connection is closed on the same timer.
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
    let permits = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                // The endpoint is closed and will accept nothing further.
                None => return Ok(()),
            },
            _ = stop.wait() => {
                // Tell every open connection rather than dropping the endpoint
                // under them: a peer that is told gets to stop waiting.
                endpoint.close(DOQ_NO_ERROR.into(), b"shutting down");
                endpoint.wait_idle().await;
                return Ok(());
            }
        };
        let peer = incoming.remote_address();
        if rate == RateLimit::PerConnection
            && !handler
                .context()
                .allow_source(peer.ip(), rdns::clock::current_unix_timestamp())
        {
            // Refuse before the handshake: a retry-able refusal costs the
            // source a round trip and costs us no crypto at all.
            incoming.refuse();
            continue;
        }
        let Ok(permit) = permits.clone().acquire_owned().await else {
            continue;
        };
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
            drop(permit);
            drop(busy);
        });
    }
}

/// One connection: a query per bidirectional stream, answered concurrently.
async fn serve_connection<H: Handler>(
    connection: quinn::Connection,
    peer: SocketAddr,
    handler: Arc<H>,
    limits: TransportLimits,
    rate: RateLimit,
    stop: Stop,
) {
    loop {
        // `accept_bi` is the shutdown check's home for the same reason the TCP
        // loop checks between messages: between streams the peer has committed
        // to nothing, and a stream already accepted below finishes.
        let stream = tokio::select! {
            stream = connection.accept_bi() => stream,
            _ = stop.wait() => {
                connection.close(DOQ_NO_ERROR.into(), b"shutting down");
                return;
            }
        };
        let (send, recv) = match stream {
            Ok(pair) => pair,
            // Ordinary: the client is done and closed the connection.
            Err(_) => return,
        };

        let now = rdns::clock::current_unix_timestamp();
        if rate == RateLimit::PerMessage && !handler.context().allow_source(peer.ip(), now) {
            continue;
        }
        let handler = handler.clone();
        tokio::spawn(async move {
            serve_stream(send, recv, peer, handler, limits, now).await;
        });
    }
}

/// One stream: read the framed query, answer it, close.
async fn serve_stream<H: Handler>(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    handler: Arc<H>,
    limits: TransportLimits,
    now: u64,
) {
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
    let raw = match recv.read_to_end(u16::MAX as usize + 2).await {
        Ok(raw) => raw,
        Err(e) => {
            handler.context().logger.count_error(peer.ip());
            tracing::debug!(peer = %peer.ip(), "QUIC stream read error: {e}");
            let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
            return;
        }
    };
    if raw.len() < 2 {
        handler.context().logger.count_error(peer.ip());
        tracing::debug!(peer = %peer.ip(), "QUIC stream too short to hold a length prefix");
        let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
        return;
    }
    let len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
    if len == 0 || raw.len() < 2 + len {
        handler.context().logger.count_error(peer.ip());
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
        .accept_packet(peer.ip(), &packet, Transport::Tcp)
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
    let answering = tokio::spawn(async move {
        handler.handle(packet, peer, now, tx).await;
    });

    while let Some(reply) = rx.recv().await {
        let Reply::Frame(framed) = reply else {
            // `Reply::Abort`: a transfer that cannot be finished. Resetting says
            // so, where finishing cleanly would read as a complete answer.
            let _ = send.reset(DOQ_PROTOCOL_ERROR.into());
            let _ = answering.await;
            return;
        };
        if send.write_all(&framed).await.is_err() {
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
    use super::*;
    use crate::testutil::{context, query};
    use crate::tls::testing::write_pem;
    use crate::ServeContext;
    use rdns::shutdown::Shutdown;

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
            out: tokio::sync::mpsc::Sender<Reply>,
        ) {
            crate::tcp::send_framed(&out, &packet).await;
        }
    }

    /// A quinn client that trusts exactly the certificate the server holds, and
    /// offers the ALPN token DoQ requires.
    fn client(server_der: &[u8]) -> quinn::ClientConfig {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(server_der.to_vec()))
            .expect("a root");
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![ALPN_DOQ.to_vec()];
        quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("TLS 1.3"),
        ))
    }

    /// The whole of 42b: a real QUIC handshake, one query on one bidirectional
    /// stream, framed exactly as on TCP, answered and the stream closed.
    #[tokio::test]
    async fn a_doq_client_gets_an_answer_on_its_own_stream() {
        let pem = write_pem("doq", "localhost");
        let store = CertificateStore::load(&pem.cert, &pem.key).expect("loads");
        let limits = TransportLimits::default();
        let endpoint = Endpoint::server(
            server_config(store, limits).expect("a quinn config"),
            "127.0.0.1:0".parse().expect("an address"),
        )
        .expect("bind");
        let addr = endpoint.local_addr().expect("addr");

        let shutdown = Shutdown::new();
        let handler = Arc::new(Echo(context(0)));
        let metrics = handler.0.metrics.clone();
        let server = tokio::spawn(serve(
            endpoint,
            handler,
            limits,
            RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let mut client_endpoint =
            Endpoint::client("127.0.0.1:0".parse().expect("an address")).expect("client bind");
        client_endpoint.set_default_client_config(client(&pem.der));
        let connection = client_endpoint
            .connect(addr, "localhost")
            .expect("connect")
            .await
            .expect("the handshake");

        // Two queries on two streams, because "one query per stream" is the
        // mapping and a second one on the same connection is what proves the
        // loop keeps accepting rather than answering once.
        for id in [0x0000u16, 0x1234] {
            let (mut send, mut recv) = connection.open_bi().await.expect("a stream");
            let question = query(id);
            send.write_all(&rdns::framed(&question).expect("frames"))
                .await
                .expect("write");
            // Closing our half is what tells the server the query is complete.
            send.finish().expect("finish");

            let answered = recv.read_to_end(64 * 1024).await.expect("read");
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
            metrics
                .quic_handshakes
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one connection, two streams"
        );

        shutdown.begin();
        server.abort();
    }

    /// A stream whose length prefix does not describe what it carries is a
    /// protocol error, not an answer. Reset rather than closed, because a clean
    /// close is how this server says "that is the whole answer".
    #[tokio::test]
    async fn a_stream_that_is_framed_wrongly_is_reset() {
        let pem = write_pem("doq-bad", "localhost");
        let store = CertificateStore::load(&pem.cert, &pem.key).expect("loads");
        let limits = TransportLimits::default();
        let endpoint = Endpoint::server(
            server_config(store, limits).expect("a quinn config"),
            "127.0.0.1:0".parse().expect("an address"),
        )
        .expect("bind");
        let addr = endpoint.local_addr().expect("addr");

        let shutdown = Shutdown::new();
        let handler = Arc::new(Echo(context(0)));
        let server = tokio::spawn(serve(
            endpoint,
            handler,
            limits,
            RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let mut client_endpoint =
            Endpoint::client("127.0.0.1:0".parse().expect("an address")).expect("client bind");
        client_endpoint.set_default_client_config(client(&pem.der));
        let connection = client_endpoint
            .connect(addr, "localhost")
            .expect("connect")
            .await
            .expect("the handshake");

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

        shutdown.begin();
        server.abort();
    }
}
