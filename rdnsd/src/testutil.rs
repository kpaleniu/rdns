//! Fixtures shared by more than one module's tests: message builders, a
//! scratch directory, a `Server` to call, and primaries on loopback ports.
//!
//! Here rather than in the crate root's test module, where they were until
//! `TODO.md` #116: a fixture there is reachable from the root's tests alone,
//! which is what kept a module's tests out of that module.
//!
//! Builders only. A helper that asserts, or that knows what a correct answer
//! looks like, belongs beside the tests that care — that knowledge is what a
//! reader is checking.

use crate::answer::write_response;
use crate::dispatch::{Server, Wire};
use crate::zones::{zone_key, ZoneContext, Zones};
use crate::Scratch;
use rdns::clock::Clock;
use rdns::ixfr::DeltaLog;
use rdns::logging::QueryLogger;
use rdns::metrics::DnsMetrics;
use rdns::security::{RateLimiter, ResponseLimiter, TransferAcl, TransferCertificates};
use rdns::shutdown::Shutdown;
use rdns::tsig::{self, TsigAlgorithm, TsigKey, TsigKeyring};
use rdns::validation::{AdmissionCheck, Arrival};
use rdns::zone::Zone;
use rdns::{
    record_types, DnsMessage, DnsMessageBuilder, OpCode, Qtype, QueryClass, ResourceRecord,
    ResponseCode, UdpSizes,
};
use rdns_transport::tcp::{self, Reply};
use rdns_transport::{ServeContext, TransportLimits};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};

/// The answer to `msg`, read back off the wire.
///
/// `write_response` writes bytes, so a test that wants to look at sections has
/// to parse them — which is the right way round: our serializer agreeing with
/// our own record structs proves nothing, and this puts the reader between the
/// two (`CLAUDE.md` §1). `u16::MAX` because nothing here is about truncation;
/// the tests that are pass their own limit.
pub(crate) fn make_response(msg: &DnsMessage, zones: &Zones, metrics: &DnsMetrics) -> DnsMessage {
    let mut scratch = Scratch::default();
    write_response(
        msg,
        zones,
        metrics,
        u16::MAX as usize,
        rdns::UdpSizes::default().advertised(),
        &mut scratch,
    )
    .expect("the response serializes");
    DnsMessage::try_from_bytes(&scratch.out).expect("and parses back")
}

/// A name from a literal, for tests only: `Name` is fallible to build and a
/// test that writes a bad one should fail loudly at that line.
pub(crate) fn nm(text: &str) -> rdns::Name {
    text.parse().expect("a test name parses")
}

/// The key the served-zone maps use: the folded wire form of the origin, which
/// is what `zones::zone_key` builds.
pub(crate) fn zkey(text: &str) -> Vec<u8> {
    nm(text).as_ref().folded().into_owned()
}

/// A query for `qname`/`qtype`, with DO set when `dnssec_ok`.
///
/// The OPT record is always attached; only the DO bit moves. Attaching it only
/// for DO would look neater and would stop every caller from exercising
/// `make_response`'s OPT mirroring (RFC 6891 §6.1.1).
pub(crate) fn query(qname: &str, qtype: Qtype, dnssec_ok: bool) -> DnsMessage {
    DnsMessageBuilder::new()
        .with_id(1)
        .with_query(nm(qname), qtype)
        .with_recursion(false)
        .with_edns(4096, dnssec_ok)
        .build()
}

/// `rdns-core`'s, re-exported so a test here writes one name.
///
/// Not a copy: that module is `pub` rather than `#[cfg(test)]` for exactly
/// this reason, and a second copy is what it exists to have stopped
/// (`CLAUDE.md` §7, `TODO.md` #38e, #66c).
pub(crate) use rdns::testutil::ScratchDir;

/// `Server::answer` collected, for tests wanting the whole reply in hand.
/// It sends rather than returns so a transfer need not exist all at once;
/// nothing in a test fills the channel before it is drained here.
pub(crate) async fn answered(server: &Server, packet: &[u8], peer: SocketAddr) -> Vec<Vec<u8>> {
    let (tx, mut rx) = mpsc::channel::<Reply>(1024);
    server
        .answer(
            packet,
            peer,
            tsig::now(),
            &Wire::Framed(&tx, Arrival::Tcp),
            &mut Scratch::default(),
        )
        .await;
    drop(tx);
    let mut replies = Vec::new();
    while let Some(Reply::Frame(framed)) = rx.recv().await {
        replies.push(framed);
    }
    replies
}

/// A [`ZoneContext`] over the given map and log, with throwaway gauges — for
/// tests about installing and withdrawing zones rather than about metrics.
pub(crate) fn served(zone_map: &Arc<RwLock<Zones>>, deltas: &Arc<RwLock<DeltaLog>>) -> ZoneContext {
    ZoneContext {
        zone_map: zone_map.clone(),
        deltas: deltas.clone(),
        metrics: Arc::new(DnsMetrics::new()),
        journal: None,
    }
}

/// A `Shutdown` that is never triggered and never dropped, for tests that
/// need the handles but not the behaviour.
///
/// Leaked on purpose. Dropping the `Shutdown` closes the `watch` channel,
/// which makes every `Stop::wait` resolve *immediately* — so a test holding
/// only a `Stop` would find its connections closing the moment they opened,
/// and would be testing shutdown rather than whatever it meant to test.
pub(crate) fn test_shutdown() -> &'static Shutdown {
    use std::sync::OnceLock;
    static SHUTDOWN: OnceLock<Shutdown> = OnceLock::new();
    SHUTDOWN.get_or_init(Shutdown::new)
}

/// Every limit off and throwaway counters: a test about answering must not
/// also be a test of the rate limiter.
pub(crate) fn test_context() -> ServeContext {
    context_at(Clock::system())
}

fn context_at(clock: Clock) -> ServeContext {
    ServeContext {
        limiter: Arc::new(RateLimiter::with_defaults()),
        responses: Arc::new(ResponseLimiter::disabled()),
        validator: Arc::new(AdmissionCheck::with_defaults()),
        logger: Arc::new(QueryLogger::new()),
        metrics: Arc::new(DnsMetrics::new()),
        udp: UdpSizes::default(),
        clock,
    }
}

/// A `Server` holding one zone and nothing else surprising: no rate limit
/// worth hitting, no response budget, no keys.
///
/// One for the UDP, shutdown and dispatch tests alike: a second copy is how
/// two of them come to disagree about what a default server is
/// (`CLAUDE.md` §7).
pub(crate) fn server_with(zone: Zone) -> Arc<Server> {
    server_with_keys(zone, Vec::new())
}

pub(crate) fn server_with_keys(zone: Zone, keys: Vec<TsigKey>) -> Arc<Server> {
    server_with_keys_at(zone, keys, Clock::system())
}

pub(crate) fn server_with_keys_at(zone: Zone, keys: Vec<TsigKey>, clock: Clock) -> Arc<Server> {
    let mut zones = HashMap::new();
    zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
    Arc::new(
        Server::new(Arc::new(RwLock::new(Zones::new(zones))), context_at(clock))
            .with_transfers(
                TransferAcl::parse(&["127.0.0.1".to_string()]).expect("acl"),
                TransferCertificates::default(),
                false,
            )
            .with_tsig_keys(TsigKeyring::new(keys)),
    )
}

/// A primary on a loopback port, answering with `rdnsd`'s own AXFR path.
///
/// Deliberately the real thing rather than a stub: `tcp::serve_one` over a
/// `Server` is what a live `rdnsd` answers a transfer with, ACL and all, so
/// what this exercises is the two halves of this codebase against each other
/// rather than the secondary against a convenient fiction.
pub(crate) async fn spawn_primary(zone_text: &str) -> SocketAddr {
    spawn_primary_with_acl(zone_text, &["127.0.0.1".to_string()]).await
}

/// A primary serving `new_text` that remembers the step from `old_text` —
/// what a real one holds after a reload, and what lets it answer an IXFR.
pub(crate) async fn spawn_primary_with_history(old_text: &str, new_text: &str) -> SocketAddr {
    let old = rdns::zone::parse_zone_file(old_text, "example.com.").expect("parse the old zone");
    let new = rdns::zone::parse_zone_file(new_text, "example.com.").expect("parse the new zone");
    let mut log = DeltaLog::new();
    log.note_change(Some(&old), &new);
    spawn_primary_inner(new, &["127.0.0.1".to_string()], log).await
}

pub(crate) async fn spawn_primary_with_acl(zone_text: &str, acl: &[String]) -> SocketAddr {
    let zone = rdns::zone::parse_zone_file(zone_text, "example.com.").expect("parse the zone");
    spawn_primary_inner(zone, acl, DeltaLog::new()).await
}

async fn spawn_primary_inner(zone: Zone, acl: &[String], log: DeltaLog) -> SocketAddr {
    spawn_primary_with_keys(zone, acl, log, TsigKeyring::new(Vec::new())).await
}

/// A primary that knows some TSIG keys, for the authorization tests. The ACL
/// is deliberately empty in those, so the key is the *only* thing that can
/// grant a transfer.
pub(crate) async fn spawn_primary_with_keys(
    zone: Zone,
    acl: &[String],
    log: DeltaLog,
    keys: TsigKeyring,
) -> SocketAddr {
    spawn_primary_full(zone, acl, log, keys, false, Arrival::Tcp).await
}

/// A primary with the two XoT knobs exposed: whether it requires an
/// encrypted transfer, and what the connection claims to be.
///
/// The privacy is asserted rather than negotiated, which is the point of
/// the split: `rdns_transport::tls` reads it off a real handshake and has
/// its own test for that, and this one is about what `answer_transfer`
/// does with the answer.
pub(crate) async fn spawn_primary_full(
    zone: Zone,
    acl: &[String],
    log: DeltaLog,
    keys: TsigKeyring,
    transfer_tls_only: bool,
    arrival: Arrival,
) -> SocketAddr {
    let mut zones = HashMap::new();
    zones.insert(zone_key(&zone), std::sync::Arc::new(zone));

    let server = Arc::new(
        Server::new(Arc::new(RwLock::new(Zones::new(zones))), test_context())
            .with_transfers(
                TransferAcl::parse(acl).expect("acl"),
                TransferCertificates::default(),
                transfer_tls_only,
            )
            .with_tsig_keys(keys)
            .with_history(Arc::new(RwLock::new(log)), None),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            tokio::spawn(tcp::serve_one(
                stream,
                peer,
                server.clone(),
                TransportLimits::default(),
                tcp::RateLimit::PerMessage,
                arrival.clone(),
                test_shutdown().stop_handle(),
            ));
        }
    });
    addr
}

pub(crate) fn update_key(zones: rdns::tsig::UpdatePolicy) -> TsigKey {
    TsigKey::new("dhcp.key.", TsigAlgorithm::HmacSha256, vec![7u8; 32]).for_updates(zones)
}

/// An UPDATE message adding `name` with one A record, or whatever `changes`
/// says.
pub(crate) fn update_message(zone: &str, changes: Vec<ResourceRecord>) -> DnsMessage {
    DnsMessage {
        id: 0x2136,
        response: false,
        opcode: OpCode::Update,
        authoritive: false,
        truncation: false,
        recursion: false,
        recursion_ok: false,
        ad: false,
        cd: false,
        rcode: ResponseCode::Ok,
        queries: vec![rdns::QuerySection {
            qname: nm(zone),
            qtype: Qtype::of(record_types::SOA),
            qclass: QueryClass::IN,
        }],
        answers: Vec::new(),
        authorities: changes,
        additionals: Vec::new(),
        edns: None,
    }
}

pub(crate) fn zone_at_serial(serial: u32) -> String {
    format!(
        "$TTL 3600\n\
         @    IN SOA ns1.example.com. admin.example.com. {serial} 3600 1800 604800 86400\n\
         @    IN NS  ns1.example.com.\n\
         ns1  IN A   192.0.2.1\n\
         www  IN A   192.0.2.2\n"
    )
}
