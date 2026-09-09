//! Fixtures shared by more than one module's tests.
//!
//! Builders only, the way `rdnsd/src/testutil.rs` is: what a correct answer
//! looks like belongs beside the test that asserts it.

use std::net::IpAddr;
use std::sync::Arc;

use rdns::logging::QueryLogger;
use rdns::metrics::DnsMetrics;
use rdns::resolver::{Resolver, ResolverConfig, ResolverMode};
use rdns::security::{RateLimitConfig, RateLimiter, ResponseLimiter};
use rdns::utils::record_types;
use rdns::validation::AdmissionCheck;
use rdns::{DnsMessage, OpCode, Qtype, QuerySection, ResponseCode};
use rdns_transport::ServeContext;

use crate::answer::Caches;

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
    })
}

/// A resolver that is never reached — every test using it is about a packet
/// refused before any resolution is attempted — and caches small enough to see
/// into.
pub(crate) fn context() -> (Arc<Resolver>, Arc<Caches>) {
    let config = ResolverConfig {
        mode: ResolverMode::Forward,
        // Nothing here reaches an upstream.
        upstream_servers: vec!["127.0.0.1:1".parse().unwrap()],
        ..Default::default()
    };
    (
        Arc::new(Resolver::new(config)),
        Arc::new(Caches::new(16, 4)),
    )
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
