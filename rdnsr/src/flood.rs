//! What a legitimate UDP client keeps while an attacker floods names under
//! zones that never answer (`TODO.md` #169). Real sockets and real time: what
//! is measured is `udp_main`'s admission under load, which a paused clock
//! would turn into a different schedule.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rdns::resolver::{Resolver, ResolverConfig, Upstream};
use rdns::rpz::PolicyZones;
use rdns::shutdown::Shutdown;
use rdns::{Class, DnsMessage, ParsedRecord, Qtype, RecordData, ResourceRecord, ResponseCode, Ttl};
use tokio::net::UdpSocket;

use crate::serve::udp_main;
use crate::testutil::*;

const ROOT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 53);
const GOOD_NS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

fn record(owner: &str, rdata: ParsedRecord) -> ResourceRecord {
    ResourceRecord {
        name: nm(owner),
        class: Class::IN,
        ttl: Ttl::from_secs(3600),
        rdata: RecordData::from_parsed(&rdata).expect("encodes"),
    }
}

fn referral(query: &DnsMessage, zone: &str, servers: &[Ipv4Addr]) -> DnsMessage {
    let mut reply = query.clone();
    reply.response = true;
    let names: Vec<_> = (0..servers.len())
        .map(|i| format!("ns{i}.{zone}"))
        .collect();
    reply.authorities = names
        .iter()
        .map(|ns| record(zone, ParsedRecord::NS(nm(ns))))
        .collect();
    reply.additionals = names
        .iter()
        .zip(servers)
        .map(|(ns, addr)| record(ns, ParsedRecord::A(*addr)))
        .collect();
    reply
}

/// The root delegates `good.test.` to one server answering in 50 ms, and each
/// `q<n>.evil.test.` to four addresses of its own that never answer: a fresh
/// zone and fresh servers per query, so nothing keyed on either can help.
fn internet() -> Upstream {
    Upstream::answering_later(move |server, _, query| {
        let query = DnsMessage::try_from_bytes(query).expect("a query");
        let qname = query.queries[0].qname.to_string().to_ascii_lowercase();
        let reply = if server == ROOT {
            if qname.ends_with("good.test.") {
                Some(referral(&query, "good.test.", &[GOOD_NS]))
            } else {
                qname.strip_suffix(".evil.test.").map(|label| {
                    let n: u32 = label.trim_start_matches('q').parse().expect("q<n>");
                    let silent: Vec<_> = (0..4)
                        .map(|i| Ipv4Addr::from(0x0a00_0000 + n * 4 + i))
                        .collect();
                    referral(&query, &qname, &silent)
                })
            }
        } else if server.ip() == IpAddr::V4(GOOD_NS) {
            let mut reply = query.clone();
            reply.response = true;
            reply.authoritive = true;
            reply.answers = vec![record(&qname, ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1)))];
            Some(reply)
        } else {
            None
        };
        async move {
            let reply = match reply {
                Some(reply) => reply,
                None => std::future::pending().await,
            };
            #[expect(
                clippy::disallowed_methods,
                reason = "an upstream's latency, part of the load modelled"
            )]
            tokio::time::sleep(Duration::from_millis(50)).await;
            reply.to_bytes_within(u16::MAX as usize).ok()
        }
    })
}

fn question(id: u16, name: &str) -> Vec<u8> {
    rdns::DnsMessageBuilder::new()
        .with_id(id)
        .with_query(nm(name), Qtype::of(rdns::record_types::A))
        .with_recursion(true)
        .build()
        .to_bytes_within(512)
        .expect("serialize")
}

/// 128 places fill at 12.8 queries a second against a tenfold attack; full, the
/// client response timer frees 71 a second, about half for the client at best.
/// Fails with a plain semaphore: none of 40 answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_of_silent_zones_leaves_room_for_a_client_that_is_waiting() {
    const PLACES: usize = 128;
    const ATTACK_PER_SECOND: u64 = 128;

    let resolver = Arc::new(
        Resolver::new(ResolverConfig {
            root_hints: vec![ROOT],
            qname_minimization: false,
            ..Default::default()
        })
        .with_upstream(internet()),
    );
    let shutdown = Shutdown::new();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
    let addr = socket.local_addr().expect("addr");
    let server = tokio::spawn(udp_main(
        socket,
        serving(resolver, test_shell(), PolicyZones::default()),
        PLACES,
        shutdown.stop_handle(),
        shutdown.busy(),
    ));

    let attack = tokio::spawn(async move {
        let attacker = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        let began = tokio::time::Instant::now();
        let mut sent = 0u64;
        loop {
            tick.tick().await;
            while sent < ATTACK_PER_SECOND * began.elapsed().as_millis() as u64 / 1000 {
                let name = format!("q{sent}.evil.test.");
                let _ = attacker.send_to(&question(sent as u16, &name), addr).await;
                sent += 1;
            }
        }
    });
    // Long enough for every place to be held and the first to pass 1.8 s.
    #[expect(
        clippy::disallowed_methods,
        reason = "real-time load: the places fill at the attack's rate"
    )]
    tokio::time::sleep(Duration::from_secs(3)).await;

    let client = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
    let answered = Arc::new(Mutex::new(HashSet::new()));
    let reader = {
        let (client, answered) = (client.clone(), answered.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while let Ok((n, _)) = client.recv_from(&mut buf).await {
                if let Ok(reply) = DnsMessage::try_from_bytes(&buf[..n]) {
                    if reply.rcode == ResponseCode::Ok && !reply.answers.is_empty() {
                        answered.lock().unwrap().insert(reply.id);
                    }
                }
            }
        })
    };
    const ASKED: u16 = 40;
    for id in 0..ASKED {
        client
            .send_to(&question(id, &format!("l{id}.good.test.")), addr)
            .await
            .expect("send");
        #[expect(
            clippy::disallowed_methods,
            reason = "real-time load: the client's own query rate"
        )]
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Stragglers get the second they always had; enough answers end it sooner.
    rdns::test_util::eventually(Duration::from_secs(1), || {
        std::future::ready(answered.lock().unwrap().len() * 100 >= usize::from(ASKED) * 20)
    })
    .await;
    attack.abort();
    reader.abort();
    shutdown.begin();
    server.abort();

    let got = answered.lock().unwrap().len();
    // Half what was measured (`CLAUDE.md` §10).
    assert!(
        got * 100 >= usize::from(ASKED) * 20,
        "{got} of {ASKED} answered"
    );
}
