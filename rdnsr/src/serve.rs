//! The two socket loops, and what they hand a query to.
//!
//! Both transports answer through [`crate::answer::handle_query`]; what differs
//! is what surrounds it. UDP owns its loop because the shedding, the response
//! budget and the TC=1 refusal are all properties of answering an address that
//! has proved nothing; TCP is `rdns-transport`'s loop with [`Resolving`] as the
//! handler, because a connection proved the peer at the handshake.

use std::net::SocketAddr;
use std::sync::Arc;

use rdns::peer::Peer;
use rdns::response::ClientEdns;
use rdns::security::ResponseVerdict;
use rdns::shutdown::{Busy, Stop};
use rdns::validation::{Arrival, Transport};
use rdns::DnsMessage;
use rdns_transport::{recv_error_is_transient, tcp, ServeContext, UDP_RECEIVE_BUFFER};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::answer::{handle_query, refused_by_acl, truncate_reply, Resolving};
use crate::inflight::{Admission, InFlight};

/// Receive datagrams and resolve each in its own task, up to `max_inflight`.
///
/// The place is taken *before* the packet is copied and the task created — see
/// [`crate::MAX_INFLIGHT_UDP`] for why a resolver spawns per datagram at all.
/// Never waited for: waiting would move the queue from the kernel's receive
/// buffer into a pile of tasks holding copies. For UDP, shedding is the
/// back-pressure; who is shed is [`InFlight`]'s.
pub(crate) async fn udp_main(
    socket: Arc<UdpSocket>,
    serving: Arc<Resolving>,
    max_inflight: usize,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    let ctx = &serving.ctx;
    // Floored, not refused: nobody means "answer nothing".
    let in_flight = InFlight::new(max_inflight.max(1));
    // Any datagram a client may send: on Windows an oversized one fails the
    // receive, ending this loop.
    let mut buf = vec![0u8; UDP_RECEIVE_BUFFER];
    loop {
        // Stop receiving on shutdown. `recv_from` is cancel-safe, so a datagram
        // is either fully received or not received at all.
        let received = tokio::select! {
            r = socket.recv_from(&mut buf) => r,
            _ = stop.wait() => return Ok(()),
        };
        let (n, from) = match received {
            Ok(received) => received,
            // ICMP about a datagram sent, or one too big: nothing about this
            // socket (`recv_error_is_transient`).
            Err(e) if recv_error_is_transient(&e) => continue,
            Err(e) => return Err(e),
        };
        // Canonical for every check and record; the reply goes to `from`, the
        // form a dual-stack socket sends to.
        let peer = Peer::from(from);
        // The ACL before the rate limiter, so a refused peer gets no bucket
        // (`CLAUDE.md` §5); REFUSED only for a question within the budget.
        if !ctx.acl.admits(peer) {
            ctx.metrics.count(&ctx.metrics.acl_refused);
            if !ctx.accept_packet(peer, &buf[..n], Transport::Udp) {
                continue;
            }
            if let Some(reply) = refused_by_acl(&buf[..n], ctx) {
                send_within_budget(&socket, ctx, peer, from, &reply).await;
            }
            continue;
        }
        // First: the cheapest rejection. Silent, so printed at startup and
        // counted; one clock read serves the limiter and the log.
        let now = ctx.clock.now();
        if !ctx.allow_source(peer, now) {
            continue;
        }
        // Then the structural checks, on bytes nothing has trusted yet.
        if !ctx.accept_packet(peer, &buf[..n], Transport::Udp) {
            continue;
        }
        // Before the copy, the clones and the task: at the ceiling a datagram
        // costs a lock and a comparison.
        let place = match in_flight.admit() {
            Admission::Free(place) => place,
            Admission::Evicted(place) => {
                ctx.metrics.count(&ctx.metrics.inflight_evicted);
                place
            }
            Admission::Full => {
                tracing::debug!(%peer, "dropped: {max_inflight} UDP queries already in flight");
                ctx.metrics.count(&ctx.metrics.queries_dropped);
                continue;
            }
        };
        let id = place.id();
        let data = buf[..n].to_vec();
        // Only when somebody is reading: the copy and the clock read are the
        // stream's cost (`TODO.md` #191).
        let tapped = serving
            .dnstap
            .as_ref()
            .map(|_| (data.clone(), rdns::dnstap::Timestamp::now()));
        let socket = socket.clone();
        // A recursion takes seconds and the client is already waiting, so it
        // is worth the drain.
        let busy = busy.clone();
        let serving = serving.clone();
        let task = tokio::spawn(async move {
            let _busy = busy;
            let _place = place;
            let ctx = &serving.ctx;
            let reply = handle_query(data, peer, now, &serving, Transport::Udp).await;
            if let (Some(sink), Some((query, arrived))) = (&serving.dnstap, &tapped) {
                crate::tap::record_client(
                    sink,
                    rdns::dnstap::SocketProtocol::Udp,
                    from,
                    *arrived,
                    query,
                    reply.as_deref(),
                );
            }
            if let Some(reply) = reply {
                send_within_budget(&socket, ctx, peer, from, &reply).await;
            }
        });
        in_flight.hold(id, task.abort_handle());
    }
}

/// Send `reply` as far as the response budget allows.
///
/// Charge the response, not the query. Over budget, TC=1 is the useful
/// refusal: no records to amplify, and a real client retries over TCP where the
/// handshake proves who it is. Its own clock read, not the one the limiter
/// used: a recursive resolution sits in between and can take seconds, so
/// sharing that instant would deny the bucket the refill the wait earned it.
async fn send_within_budget(
    socket: &UdpSocket,
    ctx: &ServeContext,
    peer: Peer,
    to: SocketAddr,
    reply: &[u8],
) {
    match ctx.admit_response(peer, reply.len(), ctx.clock.now()) {
        ResponseVerdict::Send => {
            let _ = socket.send_to(reply, to).await;
        }
        ResponseVerdict::Truncate => {
            if let Some(short) = truncate_reply(reply) {
                let _ = socket.send_to(&short, to).await;
            }
        }
        ResponseVerdict::Drop => {}
    }
}

impl tcp::Handler for Resolving {
    fn context(&self) -> &ServeContext {
        &self.ctx
    }

    /// One reply or none, into a sink that can carry several — a resolver never
    /// sends more than one, and the shape is `rdnsd`'s AXFR's.
    async fn handle(
        &self,
        packet: Vec<u8>,
        peer: SocketAddr,
        now: u64,
        // The arrival decides only whether the reply may be padded (RFC 7830
        // §6).
        arrival: Arrival,
        out: mpsc::Sender<tcp::Reply>,
    ) {
        // Read before `handle_query` takes the packet. Only on an encrypted
        // transport, so plain TCP pays no second parse (`TODO.md` #187).
        let tapped = self
            .dnstap
            .as_ref()
            .map(|_| (packet.clone(), rdns::dnstap::Timestamp::now()));
        let padding = arrival
            .may_pad()
            .then(|| DnsMessage::try_from_bytes(&packet).ok())
            .flatten()
            .filter(|request| ClientEdns::of(request).padding())
            .map(|request| request.udp_payload_size() as usize);
        if let Some(mut reply) =
            handle_query(packet, Peer::from(peer), now, self, Transport::Tcp).await
        {
            if let Some(payload) = padding {
                rdns::response::pad_reply(&mut reply, payload, u16::MAX as usize);
            }
            if let (Some(sink), Some((query, arrived))) = (&self.dnstap, &tapped) {
                crate::tap::record_client(
                    sink,
                    (&arrival).into(),
                    peer,
                    *arrived,
                    query,
                    Some(&reply),
                );
            }
            tcp::send_framed(&out, &reply).await;
        } else if let (Some(sink), Some((query, arrived))) = (&self.dnstap, &tapped) {
            crate::tap::record_client(sink, (&arrival).into(), peer, *arrived, query, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rdns::logging::QueryLogger;
    use rdns::metrics::DnsMetrics;
    use rdns::resolver::{Resolver, ResolverConfig};
    use rdns::rpz::PolicyZones;
    use rdns::security::{RateLimitConfig, RateLimiter, ResponseLimiter, TransferAcl};
    use rdns::shutdown::Shutdown;
    use rdns::validation::AdmissionCheck;
    use rdns::{DnsMessage, OpCode, ResourceRecord, ResponseCode};
    use rdns_transport::TransportLimits;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::testutil::*;

    /// A source over its query rate is dropped silently, and the drop counted.
    /// Fails without the limiter check: all four answered, `rate_limited` at 0.
    #[tokio::test]
    async fn a_source_over_its_query_rate_is_dropped_and_counted() {
        // One per second, burst of one, on a clock nothing moves, so no second
        // boundary refills the bucket mid-test.
        let ctx = Arc::new(ServeContext {
            limiter: Arc::new(RateLimiter::new(RateLimitConfig::per_second(1, 1))),
            responses: Arc::new(ResponseLimiter::disabled()),
            metrics: Arc::new(DnsMetrics::new()),
            logger: Arc::new(QueryLogger::new()),
            admission: Arc::new(AdmissionCheck::with_defaults()),
            udp: rdns::UdpSizes::default(),
            per_source: Default::default(),
            acl: rdns_transport::QueryAcl::Open,
            nsid: None,
            clock: rdns::clock::Clock::fixed(1_000_000_000),
        });
        let metrics = ctx.metrics.clone();
        let serving = serving(test_resolver(), ctx, PolicyZones::default());

        let shutdown = Shutdown::new();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let addr = socket.local_addr().expect("addr");
        let server = tokio::spawn(udp_main(
            socket,
            serving,
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
        // Sixteen workers on one socket keep no order, so there is no reply to
        // await: the count is polled.
        let dropped = || {
            metrics
                .rate_limited
                .load(std::sync::atomic::Ordering::Relaxed)
        };
        assert!(
            rdns::test_util::eventually(Duration::from_secs(5), || {
                std::future::ready(dropped() >= 3)
            })
            .await,
            "three of four datagrams are over a burst of one, and each drop \
             is counted: {}",
            dropped()
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
        let exempt = Peer::from("127.0.0.1".parse::<std::net::IpAddr>().unwrap());
        let other = Peer::from("192.0.2.1".parse::<std::net::IpAddr>().unwrap());
        // One instant for the whole test: the bucket refills by whole seconds.
        let now = rdns::clock::current_unix_timestamp();
        for _ in 0..10 {
            assert!(
                limiter.should_allow(exempt, now),
                "an exempt source never trips"
            );
        }
        assert!(limiter.should_allow(other, now));
        assert!(
            !limiter.should_allow(other, now),
            "and a source that is not exempt still does"
        );
    }

    /// A UDP loop on `bind` for a resolver whose query ACL lists `allow`, and
    /// whose limiter admits one query a second with a burst of one.
    async fn acl_server(
        bind: &str,
        allow: &[&str],
    ) -> (
        SocketAddr,
        Arc<DnsMetrics>,
        Shutdown,
        tokio::task::JoinHandle<Result<(), std::io::Error>>,
    ) {
        let specs: Vec<String> = allow.iter().map(|s| s.to_string()).collect();
        let ctx = Arc::new(ServeContext {
            limiter: Arc::new(RateLimiter::new(RateLimitConfig::per_second(1, 1))),
            acl: rdns_transport::QueryAcl::Only(Arc::new(TransferAcl::parse(&specs).expect("acl"))),
            clock: rdns::clock::Clock::fixed(1_000_000_000),
            ..(*test_shell()).clone()
        });
        let metrics = ctx.metrics.clone();
        let shutdown = Shutdown::new();
        let socket = rdns_transport::bind::udp(bind).await.expect("bind");
        let addr = socket.local;
        let server = tokio::spawn(udp_main(
            Arc::new(socket.socket),
            serving(test_resolver(), ctx, PolicyZones::default()),
            16,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
        (addr, metrics, shutdown, server)
    }

    async fn reply_to(client: &UdpSocket, addr: SocketAddr, query: &[u8]) -> Option<DnsMessage> {
        client.send_to(query, addr).await.expect("send");
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_millis(500), client.recv(&mut buf))
            .await
            .ok()?
            .expect("recv");
        Some(DnsMessage::try_from_bytes(&buf[..n]).expect("a well-formed reply"))
    }

    /// An unlisted peer is REFUSED with RFC 8914's Prohibited and never reaches
    /// the rate limiter: three queries against a burst of one are all answered.
    /// A QR=1 datagram gets nothing. Fails with the ACL check removed from
    /// `udp_main`: the last two are rate-limited.
    #[tokio::test]
    async fn an_unlisted_peer_is_refused_and_never_rate_limited() {
        let (addr, metrics, shutdown, server) = acl_server("127.0.0.1:0", &["192.0.2.0/24"]).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");

        let mut with_opt =
            DnsMessage::try_from_bytes(&message(OpCode::Query, false)).expect("parses");
        with_opt.set_edns(rdns::Edns::with_payload_size(1232));
        let with_opt = with_opt.to_bytes_within(512).expect("serialize");
        for _ in 0..3 {
            let reply = reply_to(&client, addr, &with_opt).await.expect("a reply");
            assert_eq!(reply.rcode, ResponseCode::Refused);
            assert_eq!(
                reply.queries[0].qname,
                nm("example.com."),
                "the question echoed"
            );
            let edns = reply.edns.as_ref().expect("the OPT is mirrored");
            let errors = rdns::ExtendedError::all_in(edns).expect("a well-formed option list");
            assert_eq!(
                errors.iter().map(|(code, _)| *code).collect::<Vec<_>>(),
                vec![rdns::ede::InfoCode::PROHIBITED]
            );
        }
        let plain = reply_to(&client, addr, &message(OpCode::Query, false))
            .await
            .expect("a reply");
        assert_eq!(plain.rcode, ResponseCode::Refused);
        assert!(plain.edns.is_none(), "no OPT asked, none sent");

        assert!(
            reply_to(&client, addr, &message(OpCode::Query, true))
                .await
                .is_none(),
            "a response is not a question, from anybody"
        );
        let count = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(count(&metrics.rate_limited), 0);
        assert_eq!(count(&metrics.acl_refused), 5);

        shutdown.begin();
        let _ = server.await;
    }

    /// A listed peer is answered as it was, and an IPv4 client of `::` is
    /// matched by an IPv4 rule (`docs/adr/0006`). The UPDATE is NOTIMP out of
    /// the message alone, so the reply is the answer path's and not the ACL's.
    #[tokio::test]
    async fn a_listed_peer_is_answered_on_a_dual_stack_socket() {
        let (addr, _metrics, shutdown, server) = acl_server("[::]:0", &["127.0.0.0/8"]).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
        let to = SocketAddr::from(([127, 0, 0, 1], addr.port()));

        let reply = reply_to(&client, to, &message(OpCode::Update, false))
            .await
            .expect("a reply");
        assert_eq!(reply.rcode, ResponseCode::NotImplemented);

        shutdown.begin();
        let _ = server.await;
    }

    /// RFC 7830 §4 over DoT, and never over plain TCP (§6), for this daemon's
    /// handler (`TODO.md` #187). The UPDATE is NOTIMP out of the message alone,
    /// so nothing is resolved. Fails with the handler's padding removed.
    #[tokio::test]
    async fn a_padded_query_over_dot_gets_a_padded_reply() {
        let mut msg = DnsMessage::try_from_bytes(&message(OpCode::Update, false)).expect("parses");
        msg.set_edns(
            rdns::Edns::with_options(
                1232,
                0,
                false,
                &[rdns::EdnsOption {
                    code: 12,
                    data: Vec::new(),
                }],
            )
            .expect("options"),
        );
        let query = msg.to_bytes_within(512).expect("serialize");

        for (arrival, padded) in [
            (
                Arrival::Dot(
                    rdns::validation::TlsVersion::Tls13,
                    rdns::validation::PeerCertificate::none(),
                ),
                true,
            ),
            (Arrival::Tcp, false),
        ] {
            let shutdown = Shutdown::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let serving = context();
            let server = tokio::spawn(async move {
                let (stream, peer) = listener.accept().await.expect("accept");
                tcp::serve_one(
                    stream,
                    peer,
                    serving,
                    TransportLimits::default(),
                    tcp::RateLimit::PerConnection,
                    arrival,
                    shutdown.stop_handle(),
                )
                .await;
            });
            let mut client = TcpStream::connect(addr).await.expect("connect");
            client
                .write_all(&rdns::framed(&query).expect("frames"))
                .await
                .expect("send");
            let mut prefix = [0u8; 2];
            client.read_exact(&mut prefix).await.expect("a reply");
            let mut reply = vec![0u8; u16::from_be_bytes(prefix) as usize];
            client.read_exact(&mut reply).await.expect("its body");
            let parsed = DnsMessage::try_from_bytes(&reply).expect("well formed");
            assert_eq!(parsed.rcode, ResponseCode::NotImplemented);
            let has_padding = parsed
                .edns
                .expect("the OPT is mirrored")
                .options()
                .expect("options")
                .iter()
                .any(|o| o.code == 12);
            assert_eq!(has_padding, padded);
            assert_eq!(
                reply.len().is_multiple_of(rdns::response::PADDING_BLOCK),
                padded
            );
            drop(client);
            let _ = server.await;
        }
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
                class: rdns::Class::IN,
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

    /// The admission check runs on TCP as well, not only on the UDP loop.
    ///
    /// The additional-count cap is the cheapest rule to provoke. UPDATEs are
    /// answered from the message alone, so silence is a drop, and the second
    /// reply shows the connection survived. Fails without the check: 0xBAD1.
    #[tokio::test]
    async fn a_tcp_message_over_the_admission_caps_is_dropped_and_the_connection_kept() {
        let serving = context();
        let metrics = serving.ctx.metrics.clone();

        let shutdown = Shutdown::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(tcp::serve(
            listener,
            serving,
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
                .packets_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "and the drop is counted, since it is silent on the wire"
        );

        shutdown.begin();
        let _ = server.await;
    }

    /// A datagram arriving with the in-flight ceiling reached is dropped before
    /// it is copied and given a task.
    ///
    /// A black-hole upstream holds the only permit, and its receiving the query
    /// proves it. The UPDATE would get NOTIMP from the message alone, so
    /// silence is the drop. Fails without `try_acquire_owned`.
    #[tokio::test]
    async fn a_datagram_over_the_in_flight_ceiling_is_dropped() {
        let black_hole = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let upstream = black_hole.local_addr().expect("addr");
        let resolver = Arc::new(Resolver::new(ResolverConfig {
            routes: vec![rdns::resolver::Route::forward(
                rdns::Name::root(),
                vec![upstream],
            )],
            // Long enough that the first query is still outstanding at the
            // end of the test.
            timeout_ms: 30_000,
            ..Default::default()
        }));
        let shutdown = Shutdown::new();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let addr = socket.local_addr().expect("addr");
        let server = tokio::spawn(udp_main(
            socket,
            serving(resolver, test_shell(), PolicyZones::default()),
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
        // The stop cancels the worker's `recv_from`; the resolution the drain
        // waits for is not waited out here.
        let _ = server.await;
    }
}
