//! Fixtures shared by more than one module's tests.
//!
//! Builders only, the way `rdnsd/src/testutil.rs` is: what a correct answer
//! looks like belongs beside the test that asserts it.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rdns::dnssec::{Ds, DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE};
use rdns::dnssec_chain::TrustAnchors;
use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::logging::QueryLogger;
use rdns::metrics::DnsMetrics;
use rdns::record_types;
use rdns::resolver::{Resolver, ResolverConfig, ResolverMode};
use rdns::security::{RateLimitConfig, RateLimiter, ResponseLimiter, TransferAcl};
use rdns::validation::AdmissionCheck;
use rdns::zone_signer::{sign_zone, SigningPolicy};
use rdns::{DnsMessage, OpCode, Qtype, QuerySection, ResourceRecord, ResponseCode, Rtype};
use rdns_transport::ServeContext;

use rdns::cache::StalePolicy;
use rdns::rpz::{PolicyStore, PolicyZones};

use crate::answer::{NotifyAcl, Resolving};
use crate::caches::Caches;
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
        refreshes: None,
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
        refreshes: None,
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
        refreshes: None,
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

/// `example.test.`, signed by the signer `rdnsd` uses, and the answers an
/// upstream gives about it.
///
/// The NSEC chain is apex → `ns` → `*.w` → apex, so the apex NSEC denies every
/// name between the apex and `ns` together with `*.example.test.`, and the
/// `*.w` NSEC covers every name the wildcard reaches.
pub(crate) struct SignedZone {
    records: Vec<ResourceRecord>,
    anchor: Ds,
}

impl SignedZone {
    pub(crate) fn new() -> SignedZone {
        const TEXT: &str = "$TTL 300\n\
            @ IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 86400 300\n\
            @ IN NS ns.example.test.\n\
            ns IN A 192.0.2.1\n\
            *.w IN A 192.0.2.7\n";
        let zone = rdns::zone::parse_zone_file(TEXT, "example.test.").expect("parses");
        let key = |flags| {
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, "example.test.", flags)
                .expect("a key")
        };
        let ksk = key(DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP);
        let anchor = ksk.ds(2).expect("a DS");
        let keys = [ksk, key(DNSKEY_FLAG_ZONE)];
        let policy = SigningPolicy::valid_for(rdns::clock::current_unix_timestamp(), 86_400);
        let signed = sign_zone(&zone, &keys, &policy).expect("signs");
        let records = signed
            .records()
            .iter()
            .map(|r| {
                let r = r.to_owned();
                ResourceRecord {
                    name: r.name,
                    class: r.class,
                    ttl: r.ttl,
                    rdata: r.rdata,
                }
            })
            .collect();
        SignedZone { records, anchor }
    }

    /// The RRset at `owner`, with the signatures over it.
    fn at(&self, owner: &str, rtype: Rtype) -> Vec<ResourceRecord> {
        let owner = nm(owner);
        self.records
            .iter()
            .filter(|r| r.name == owner)
            .filter(|r| r.rdata.rtype() == rtype || r.rdata.rrsig_type_covered() == Some(rtype))
            .cloned()
            .collect()
    }

    /// What the upstream says to `query`. Only the names the fixture is built
    /// for: the DNSKEY RRset, a name the wildcard reaches, and otherwise
    /// NXDOMAIN proved by the apex NSEC — true for the gap before `ns` only.
    pub(crate) fn reply(&self, query: &DnsMessage) -> DnsMessage {
        let mut reply = query.clone();
        reply.response = true;
        reply.recursion_ok = true;
        let question = &query.queries[0];
        let w = nm("w.example.test.");
        if question.qtype.is(record_types::DNSKEY) {
            reply.answers = self.at("example.test.", record_types::DNSKEY);
        } else if question.qname.as_ref().is_at_or_under(w.as_ref()) {
            // Expanded: re-owned onto the name asked for, the RRSIG's label
            // count left saying a wildcard signed it (RFC 4035 §5.3.2).
            reply.answers = self.at("*.w.example.test.", record_types::A);
            for record in &mut reply.answers {
                record.name = question.qname.clone();
            }
            reply.authorities = self.at("*.w.example.test.", record_types::NSEC);
        } else {
            reply.rcode = ResponseCode::NoSuchDomain;
            reply.authorities = self.at("example.test.", record_types::SOA);
            reply
                .authorities
                .extend(self.at("example.test.", record_types::NSEC));
        }
        reply
    }

    /// A forwarder anchored on this zone's KSK, pointed at an upstream that
    /// answers with [`SignedZone::reply`], and the count of what it was asked
    /// other than the DNSKEY RRset.
    pub(crate) async fn upstream(self) -> (Arc<Resolver>, Arc<AtomicUsize>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = socket.local_addr().expect("bound");
        let asked = Arc::new(AtomicUsize::new(0));
        let config = ResolverConfig {
            mode: ResolverMode::Forward,
            upstream_servers: vec![addr],
            dnssec: Some(TrustAnchors::new(vec![self.anchor.clone()]).into()),
            ..Default::default()
        };
        let counter = asked.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let Ok(query) = DnsMessage::try_from_bytes(&buf[..n]) else {
                    continue;
                };
                if !query.queries[0].qtype.is(record_types::DNSKEY) {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                let reply = self.reply(&query).to_bytes_within(4096).expect("serialize");
                let _ = socket.send_to(&reply, peer).await;
            }
        });
        (Arc::new(Resolver::new(config)), asked)
    }
}

/// A resolver forwarding to a socket that reads nothing, so every resolution
/// runs to its timeout. Keep the socket alive for as long as the resolver.
pub(crate) fn silent_resolver() -> (Arc<Resolver>, std::net::UdpSocket) {
    let upstream = std::net::UdpSocket::bind("127.0.0.1:0").expect("a loopback port");
    let config = ResolverConfig {
        mode: ResolverMode::Forward,
        upstream_servers: vec![upstream.local_addr().expect("bound")],
        timeout_ms: 10_000,
        ..Default::default()
    };
    (Arc::new(Resolver::new(config)), upstream)
}
