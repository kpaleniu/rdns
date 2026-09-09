//! The two socket loops, and what they hand a query to.
//!
//! Both transports answer through [`crate::answer::handle_query`]; what differs
//! is what surrounds it. UDP owns its loop because the shedding, the response
//! budget and the TC=1 refusal are all properties of answering an address that
//! has proved nothing; TCP is `rdns-transport`'s loop with [`Resolving`] as the
//! handler, because a connection proved the peer at the handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use rdns::resolver::Resolver;
use rdns::security::ResponseVerdict;
use rdns::shutdown::{Busy, Stop};
use rdns::utils::current_unix_timestamp;
use rdns::utils::{recv_error_is_transient, UDP_RECEIVE_BUFFER};
use rdns_transport::{tcp, ServeContext, Transport};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Semaphore};

use crate::answer::{handle_query, truncate_reply, Caches};

/// Receive datagrams and resolve each in its own task, up to `max_inflight`.
///
/// The permit is taken *before* the packet is copied and the task created — see
/// [`crate::MAX_INFLIGHT_UDP`] for why a resolver spawns per datagram at all.
/// `try_acquire`, not `acquire`: waiting would move the queue from the kernel's
/// receive buffer into a pile of tasks holding copies. For UDP, shedding is the
/// back-pressure.
pub(crate) async fn udp_main(
    socket: Arc<UdpSocket>,
    resolver: Arc<Resolver>,
    caches: Arc<Caches>,
    ctx: Arc<ServeContext>,
    max_inflight: usize,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    // Floored, not refused: nobody means "answer nothing".
    let in_flight = Arc::new(Semaphore::new(max_inflight.max(1)));
    // Sized for any datagram a client may send, not the payload size we
    // advertise: on Windows an oversized one fails the receive rather than
    // truncating, and a failed receive ends this loop.
    let mut buf = vec![0u8; UDP_RECEIVE_BUFFER];
    loop {
        // Stop receiving on shutdown. `recv_from` is cancel-safe, so a datagram
        // is either fully received or not received at all.
        let received = tokio::select! {
            r = socket.recv_from(&mut buf) => r,
            _ = stop.wait() => return Ok(()),
        };
        let (n, peer) = match received {
            Ok(received) => received,
            // An ICMP report about a datagram already sent, or one that did
            // not fit: neither says anything about this socket. Shared with
            // `rdnsd` — see `recv_error_is_transient`.
            Err(e) if recv_error_is_transient(&e) => continue,
            Err(e) => return Err(e),
        };
        // First, because it is the cheapest rejection and the one a flood
        // should hit: a hash lookup and a token, before the packet is looked
        // at. Dropping is silent, which is why the policy is printed at startup
        // and counted here.
        //
        // One read for the limiter and the query log, which happen within
        // microseconds of each other; the response budget reads its own, since a
        // recursion sits in between (`TODO.md` #28a).
        let now = current_unix_timestamp();
        if !ctx.allow_source(peer.ip(), now) {
            continue;
        }
        // Then the structural checks, on bytes nothing has trusted yet.
        if !ctx.accept_packet(peer.ip(), &buf[..n], Transport::Udp) {
            continue;
        }
        // Before the copy, the clones and the task: at the ceiling a datagram
        // costs one comparison. The semaphore is never closed, so the only
        // failure is "full".
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "dropped: {max_inflight} UDP queries already in flight");
            ctx.metrics.count(&ctx.metrics.queries_dropped);
            continue;
        };
        let data = buf[..n].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        let caches = caches.clone();
        // A recursion takes seconds and the client is already waiting, so it
        // is worth the drain.
        let busy = busy.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _busy = busy;
            let _permit = permit;
            if let Some(reply) = handle_query(
                data,
                peer.ip(),
                now,
                &resolver,
                &caches,
                &ctx,
                Transport::Udp,
            )
            .await
            {
                // Charge the response, not the query. Over budget, TC=1 is
                // the useful refusal: no records to amplify, and a real client
                // retries over TCP where the handshake proves who it is.
                // Its own clock read, not the one the limiter used above: a
                // recursive resolution sits in between and can take seconds, so
                // sharing that instant would deny the bucket the refill the wait
                // earned it.
                match ctx.admit_response(peer.ip(), reply.len(), current_unix_timestamp()) {
                    ResponseVerdict::Send => {
                        let _ = socket.send_to(&reply, peer).await;
                    }
                    ResponseVerdict::Truncate => {
                        if let Some(short) = truncate_reply(&reply) {
                            let _ = socket.send_to(&short, peer).await;
                        }
                    }
                    ResponseVerdict::Drop => {}
                }
            }
        });
    }
}

/// What answers a query on this resolver, for the shared TCP transport.
///
/// The three handles `handle_query` needs, in one place so the transport can
/// hold them: it is generic over the handler and knows nothing about resolving.
pub(crate) struct Resolving {
    pub(crate) resolver: Arc<Resolver>,
    pub(crate) caches: Arc<Caches>,
    pub(crate) ctx: Arc<ServeContext>,
}

impl tcp::Handler for Resolving {
    fn context(&self) -> &ServeContext {
        &self.ctx
    }

    /// One reply or none, into a sink that can carry several — a resolver never
    /// sends more than one, and the shape is `rdnsd`'s AXFR's (`TODO.md` #30a).
    async fn handle(
        &self,
        packet: Vec<u8>,
        peer: SocketAddr,
        now: u64,
        out: mpsc::Sender<tcp::Reply>,
    ) {
        if let Some(reply) = handle_query(
            packet,
            peer.ip(),
            now,
            &self.resolver,
            &self.caches,
            &self.ctx,
            Transport::Tcp,
        )
        .await
        {
            tcp::send_framed(&out, &reply).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rdns::logging::QueryLogger;
    use rdns::metrics::DnsMetrics;
    use rdns::resolver::{ResolverConfig, ResolverMode};
    use rdns::security::{RateLimitConfig, RateLimiter, ResponseLimiter, TransferAcl};
    use rdns::shutdown::Shutdown;
    use rdns::validation::AdmissionCheck;
    use rdns::{DnsMessage, OpCode, ResourceRecord, ResponseCode};
    use rdns_transport::TransportLimits;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::testutil::*;

    /// A source over its query rate is dropped, and the drop is counted. Both
    /// halves: silence is right, because a reply to a spoofed source is what an
    /// amplifier sends, which is exactly why the counter has to exist.
    ///
    /// Watched failing without the limiter check: all four datagrams answered,
    /// `rate_limited` at 0.
    #[tokio::test]
    async fn a_source_over_its_query_rate_is_dropped_and_counted() {
        let (resolver, caches) = context();

        // One per second, burst of one: the second datagram in a burst is over
        // the limit whatever the clock does.
        let ctx = Arc::new(ServeContext {
            limiter: Arc::new(RateLimiter::new(RateLimitConfig::per_second(1, 1))),
            responses: Arc::new(ResponseLimiter::disabled()),
            metrics: Arc::new(DnsMetrics::new()),
            logger: Arc::new(QueryLogger::new()),
            validator: Arc::new(AdmissionCheck::with_defaults()),
        });
        let metrics = ctx.metrics.clone();

        let shutdown = Shutdown::new();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let addr = socket.local_addr().expect("addr");
        let server = tokio::spawn(udp_main(
            socket,
            resolver,
            caches,
            ctx,
            16,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
        for _ in 0..4 {
            client
                .send_to(&message(OpCode::Query, false), addr)
                .await
                .expect("send");
        }
        // Long enough for the loop to have taken all four off the socket.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            metrics.rate_limited.load(std::sync::atomic::Ordering::Relaxed) >= 3,
            "three of four datagrams are over a burst of one, and each drop is              counted: {}",
            metrics.rate_limited.load(std::sync::atomic::Ordering::Relaxed)
        );

        shutdown.begin();
        let _ = server.await;
    }

    /// The escape hatch, for a monitoring probe whose job is to query more
    /// often than a client would.
    #[test]
    fn an_exempt_source_is_not_rate_limited() {
        let limiter = RateLimiter::new(
            RateLimitConfig::per_second(1, 1)
                .exempting(TransferAcl::parse_named(&["127.0.0.1".to_string()], "--test").unwrap()),
        );
        let exempt: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let other: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..10 {
            assert!(
                limiter.should_allow(exempt, current_unix_timestamp()),
                "an exempt source never trips"
            );
        }
        assert!(limiter.should_allow(other, current_unix_timestamp()));
        assert!(
            !limiter.should_allow(other, current_unix_timestamp()),
            "and a source that is not exempt still does"
        );
    }

    /// An UPDATE carrying `additionals` additional records, which
    /// `handle_query` answers NOTIMP out of the message alone. Five is one over
    /// `AdmissionCheck`'s cap for a request.
    fn update_with_additionals(id: u16, additionals: usize) -> Vec<u8> {
        let mut msg = DnsMessage::try_from_bytes(&message(OpCode::Update, false)).expect("parses");
        msg.id = id;
        msg.additionals = vec![
            ResourceRecord {
                name: nm("example.com."),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(60),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                    "192.0.2.1".parse().unwrap(),
                ))
                .unwrap(),
            };
            additionals
        ];
        let mut buf = vec![0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("serialize");
        buf.truncate(n);
        buf
    }

    /// The admission check runs on TCP as well. It ran on one of the two
    /// transports (`TODO.md` #30q), so the 16 KiB ceiling, the QDCOUNT cap and
    /// the per-section counts all stopped at the UDP loop.
    ///
    /// Provoked with the additional-count cap because it is the cheapest of
    /// those rules to build; the check is one call, so any rule of it firing is
    /// the whole check running. Both messages are UPDATEs, answered from the
    /// message alone — no cache, no upstream — so a missing reply is a drop
    /// rather than a timeout somewhere else, and the second one is what says
    /// the connection survived the first.
    ///
    /// Watched failing with the check removed: the reply carried 0xBAD1.
    #[tokio::test]
    async fn a_tcp_message_over_the_admission_caps_is_dropped_and_the_connection_kept() {
        let (resolver, caches) = context();
        let ctx = test_shell();
        let metrics = ctx.metrics.clone();

        let shutdown = Shutdown::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(tcp::serve(
            listener,
            Arc::new(Resolving {
                resolver,
                caches,
                ctx,
            }),
            TransportLimits::default(),
            tcp::RateLimit::PerConnection,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let mut client = TcpStream::connect(addr).await.expect("connect");
        for message in [
            update_with_additionals(0xBAD1, 5),
            update_with_additionals(0x600D, 1),
        ] {
            client
                .write_all(&rdns::framed(&message).expect("frames"))
                .await
                .expect("send");
        }

        let mut prefix = [0u8; 2];
        client.read_exact(&mut prefix).await.expect("one reply");
        let mut reply = vec![0u8; u16::from_be_bytes(prefix) as usize];
        client.read_exact(&mut reply).await.expect("its body");
        let reply = DnsMessage::try_from_bytes(&reply).expect("a well-formed reply");
        assert_eq!(
            reply.id, 0x600D,
            "0xBAD1 is over the cap and must not be answered"
        );
        assert_eq!(reply.rcode, ResponseCode::NotImplemented);
        assert_eq!(
            metrics
                .validation_errors
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "and the drop is counted, since it is silent on the wire"
        );

        shutdown.begin();
        let _ = server.await;
    }

    /// A datagram arriving with the in-flight ceiling already reached is
    /// dropped, and dropped *before* it is copied and given a task.
    ///
    /// Neither half is a race. Forwarding to an upstream that never answers
    /// holds the only permit for the whole test, and the black hole *receiving*
    /// that query is the proof it does. The second datagram is an UPDATE, which
    /// `handle_query` answers with NOTIMP out of the message alone — no cache,
    /// no network — so "no reply" means dropped at the door.
    ///
    /// Watched failing with the `try_acquire_owned` removed: the NOTIMP came
    /// straight back.
    #[tokio::test]
    async fn a_datagram_over_the_in_flight_ceiling_is_dropped() {
        let black_hole = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let upstream = black_hole.local_addr().expect("addr");
        let resolver = Arc::new(Resolver::new(ResolverConfig {
            mode: ResolverMode::Forward,
            upstream_servers: vec![upstream],
            // Long enough that the first query is still outstanding at the
            // end of the test.
            timeout_ms: 30_000,
            ..Default::default()
        }));
        let (_, caches) = context();

        let shutdown = Shutdown::new();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let addr = socket.local_addr().expect("addr");
        let server = tokio::spawn(udp_main(
            socket,
            resolver,
            caches,
            test_shell(),
            1,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
        client
            .send_to(&message(OpCode::Query, false), addr)
            .await
            .expect("send the query that takes the permit");
        // The forwarded query landing here is what makes the permit
        // definitely held rather than probably held.
        let mut buf = vec![0u8; 512];
        black_hole
            .recv_from(&mut buf)
            .await
            .expect("the query was forwarded, so the permit is taken");

        client
            .send_to(&message(OpCode::Update, false), addr)
            .await
            .expect("send the query that must be dropped");
        let waited = tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
            .await
            .is_ok();
        assert!(
            !waited,
            "a NOTIMP came back, so the datagram was answered rather than shed — \
             it costs microseconds to build, and half a second is a thousand times that"
        );

        shutdown.begin();
        // The worker is parked in `recv_from`, which the stop cancels. The
        // resolving task is what the drain is for; this test does not wait out
        // its thirty seconds.
        let _ = server.await;
    }
}
