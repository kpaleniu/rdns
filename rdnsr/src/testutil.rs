//! Fixtures shared by more than one module's tests.
//!
//! Builders only, the way `rdnsd/src/testutil.rs` is: what a correct answer
//! looks like belongs beside the test that asserts it.

use std::net::IpAddr;
use std::sync::Arc;

use rdns::logging::QueryLogger;
use rdns::metrics::DnsMetrics;
use rdns::record_types;
use rdns::resolver::{Resolver, ResolverConfig, ResolverMode};
use rdns::security::{RateLimitConfig, RateLimiter, ResponseLimiter, TransferAcl};
use rdns::validation::AdmissionCheck;
use rdns::{DnsMessage, OpCode, Qtype, QuerySection, ResponseCode};
use rdns_transport::ServeContext;

use rdns::cache::StalePolicy;
use rdns::rpz::{PolicyStore, PolicyZones};

use crate::answer::{Caches, NotifyAcl, Resolving};
use crate::reload::PolicyReload;

/// A name from a literal, for tests only: `Name` is fallible to build and a
/// test that writes a bad one should fail loudly at that line.
pub(crate) fn nm(text: &str) -> rdns::Name {
    text.parse().expect("a test name parses")
}

/// Whose queries these are, where the test does not care.
pub(crate) const TEST_PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7));

/// A ctx with every limit off, so a test measures the thing it names and
/// not the rate limiter.
pub(crate) fn test_shell() -> Arc<ServeContext> {
    Arc::new(ServeContext {
        limiter: Arc::new(RateLimiter::new(RateLimitConfig::per_second(0, 0))),
        responses: Arc::new(ResponseLimiter::disabled()),
        metrics: Arc::new(DnsMetrics::new()),
        logger: Arc::new(QueryLogger::new()),
        validator: Arc::new(AdmissionCheck::with_defaults()),
        udp: rdns::UdpSizes::default(),
        clock: rdns::clock::Clock::system(),
    })
}

/// A resolver that is never reached — every test using it is about a packet
/// refused before any resolution is attempted.
pub(crate) fn test_resolver() -> Arc<Resolver> {
    let config = ResolverConfig {
        mode: ResolverMode::Forward,
        // Nothing here reaches an upstream.
        upstream_servers: vec!["127.0.0.1:1".parse().unwrap()],
        ..Default::default()
    };
    Arc::new(Resolver::new(config))
}

/// The handle `handle_query` takes: an unreachable resolver, caches small
/// enough to see into, no policy, and every limit off.
pub(crate) fn context() -> Arc<Resolving> {
    serving(test_resolver(), test_shell(), PolicyZones::default())
}

/// The same, for a test that brings its own resolver, shell or policy.
pub(crate) fn serving(
    resolver: Arc<Resolver>,
    ctx: Arc<ServeContext>,
    policy: PolicyZones,
) -> Arc<Resolving> {
    let caches = Caches::new(16, 4, StalePolicy::OFF, ctx.clock.clone());
    Arc::new(Resolving {
        resolver,
        caches,
        policy: PolicyStore::in_memory(policy),
        prefetch: false,
        dns64: None,
        rpz_notify: None,
        feed_wakes: Vec::new(),
        ctx,
    })
}

/// The same, for a test that brings a policy it will rewrite under the
/// resolver.
pub(crate) fn serving_policy(policy: Arc<PolicyStore>) -> Arc<Resolving> {
    let ctx = test_shell();
    let caches = Caches::new(16, 4, StalePolicy::OFF, ctx.clock.clone());
    Arc::new(Resolving {
        resolver: test_resolver(),
        caches,
        policy,
        prefetch: false,
        dns64: None,
        rpz_notify: None,
        feed_wakes: Vec::new(),
        ctx,
    })
}

/// A resolver that will take a NOTIFY from `from`, and the handle a queued
/// reload lands on so a test can see whether one did.
pub(crate) fn serving_notified(
    policy: Arc<PolicyStore>,
    from: &[&str],
) -> (Arc<Resolving>, PolicyReload) {
    let reload = PolicyReload::default();
    let ctx = test_shell();
    let caches = Caches::new(16, 4, StalePolicy::OFF, ctx.clock.clone());
    let specs: Vec<String> = from.iter().map(|s| s.to_string()).collect();
    let serving = Arc::new(Resolving {
        resolver: test_resolver(),
        caches,
        policy,
        prefetch: false,
        dns64: None,
        rpz_notify: Some(NotifyAcl {
            from: TransferAcl::parse_named(&specs, "--rpz-notify-from").expect("the list parses"),
            reload: reload.clone(),
        }),
        feed_wakes: Vec::new(),
        ctx,
    });
    (serving, reload)
}

/// `rdns-core`'s, re-exported so a test here writes one name.
///
/// Not a third copy: that module is `pub` rather than `#[cfg(test)]` for
/// exactly this reason (`CLAUDE.md` §7, `TODO.md` #38e, #66c).
pub(crate) use rdns::testutil::ScratchDir;

/// A NOTIFY for `zone`, shaped the way `rdnsd` sends one: QTYPE SOA, no answer
/// section. The serial is deliberately absent, because nothing here reads it.
pub(crate) fn notify_message(zone: &str) -> Vec<u8> {
    let msg = DnsMessage {
        id: 0x1234,
        response: false,
        opcode: OpCode::Notify,
        authoritive: false,
        truncation: false,
        recursion: false,
        recursion_ok: false,
        ad: false,
        cd: false,
        rcode: ResponseCode::Ok,
        queries: vec![QuerySection {
            qname: nm(zone),
            qtype: Qtype::of(record_types::SOA),
            qclass: rdns::QueryClass::IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        edns: None,
    };
    let mut buf = vec![0u8; 512];
    let n = msg.to_bytes(&mut buf).expect("serialize");
    buf.truncate(n);
    buf
}

pub(crate) fn message(opcode: OpCode, response: bool) -> Vec<u8> {
    let msg = DnsMessage {
        id: 0x1234,
        response,
        opcode,
        authoritive: false,
        truncation: false,
        recursion: true,
        recursion_ok: false,
        ad: false,
        cd: false,
        rcode: ResponseCode::Ok,
        queries: vec![QuerySection {
            qname: nm("example.com."),
            qtype: Qtype::of(record_types::A),
            qclass: rdns::QueryClass::IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        edns: None,
    };
    let mut buf = vec![0u8; 512];
    let n = msg.to_bytes(&mut buf).expect("serialize");
    buf.truncate(n);
    buf
}
