//! Input: a flags byte (bit 0: validate against the ICANN root anchor), then
//! the reply every upstream sends to every query.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rdns::dnssec_chain::TrustAnchors;
use rdns::resolver::{Resolver, ResolverConfig, SharedAnchors, Upstream};
use rdns::{record_types, Qtype, QueryClass, QuerySection};

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let Some((&flags, reply)) = data.split_first() else {
        return;
    };
    let reply = reply.to_vec();
    let root = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 53);

    // Case randomization and minimization off, so the question in a mutated
    // seed can still match the one asked and the reply gets past the id check.
    let mut config = ResolverConfig {
        root_hints: vec![root],
        timeout_ms: 100,
        query_budget: 8,
        qname_minimization: false,
        zero_x20: false,
        ..ResolverConfig::default()
    };
    if flags & 1 != 0 {
        config.dnssec = Some(SharedAnchors::new(TrustAnchors::icann_root()));
    }

    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime")
    });
    runtime.block_on(async move {
        let upstream = Upstream::answering(move |_, _, query| {
            let mut reply = reply.clone();
            if reply.len() >= 2 && query.len() >= 2 {
                reply[..2].copy_from_slice(&query[..2]);
            }
            Some(reply)
        });
        let resolver = Resolver::new(config).with_upstream(upstream);
        let _ = resolver
            .resolve(&QuerySection {
                qname: "www.example.com.".parse().expect("a name"),
                qtype: Qtype::of(record_types::A),
                qclass: QueryClass::IN,
            })
            .await;
    });
});
