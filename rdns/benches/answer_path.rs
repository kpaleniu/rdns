//! What one query costs, measured on optimized code.
//!
//! **Why this exists.** `src/bench.rs` timed the same sort of thing from inside
//! `#[cfg(test)]`, which means every number it printed was a *debug* number —
//! useless for deciding whether an optimization worked, and unable to see the
//! defects #9e was about (`TODO.md` #9e's last item). Criterion runs benches
//! under the release profile, samples until the confidence interval is narrow,
//! and can compare a run against a saved baseline, which is what an optimization
//! actually needs. What is left in `src/bench.rs` are two wall-clock *floors*
//! that guard a complexity class; they are not benchmarks and say so.
//!
//! **Read every number here against the cost of the datagram it sits in.**
//! Measured on the development machine, 2026-08-01: one `sendto` + one
//! `recvfrom` on loopback is **3.6 µs on Linux and 4.1 µs on Windows**, and the
//! whole library-side answer to a plain A query — parse, look up, build,
//! serialize — is **231 ns on Linux, 455 ns on Windows**. So the entire contents
//! of this file is around 6% of what a query costs a server, and a 20%
//! improvement in any of it is worth about 1% end to end. That is not an
//! argument against measuring; it is the number that stops a 20% win being
//! reported as one. Anything that claims a *query* got faster has to be measured
//! against a query, syscalls included.
//!
//! **Running it.**
//!
//! ```sh
//! cargo bench -p rdns                        # everything
//! cargo bench -p rdns -- answer              # one group
//! cargo bench -p rdns -- --save-baseline before
//! cargo bench -p rdns -- --baseline before   # after a change
//! ```
//!
//! The baseline pair is the point for `TODO.md` #11 and #13, both of which are
//! single-digit-percent questions that no allocation count can answer.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};

use rdns::cache::DnsCache;
use rdns::dnssec::{dnskeys_in, rrsigs_in, verify_rrset, Rrset};
use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::logging::QueryLogger;
use rdns::security::RateLimiter;
use rdns::utils::{current_unix_timestamp, record_types};
use rdns::validation::RequestValidator;
use rdns::zone::{parse_zone_file, Zone, ZoneRecord};
use rdns::zone_signer::{sign_zone, SigningPolicy};
use rdns::{
    DnsMessage, OpCode, ParsedRecord, QueryClass, QuerySection, RecordData, ResourceRecord,
    ResponseCode,
};

const ZONE: &str = "$ORIGIN example.com.
$TTL 3600
@    IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@    IN NS  ns1.example.com.
ns1  IN A   192.0.2.1
www  IN A   192.0.2.10
www  IN AAAA 2001:db8::10
mail IN MX  10 mx.example.com.
mx   IN A   192.0.2.20
";

fn query_message(qname: &str, qtype: u16) -> DnsMessage {
    DnsMessage {
        id: 0x1234,
        response: false,
        opcode: OpCode::Query,
        authoritive: false,
        truncation: false,
        recursion: false,
        recursion_ok: false,
        ad: false,
        cd: false,
        rcode: ResponseCode::Ok,
        queries: vec![QuerySection {
            qname: qname.to_string(),
            qtype,
            qclass: QueryClass::IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

fn owned(zone: &Zone, name: &str, qtype: u16) -> Vec<ResourceRecord> {
    zone.query(name, qtype)
        .into_iter()
        .map(|r| ResourceRecord {
            name: name.to_string(),
            class: r.class,
            ttl: r.ttl,
            rdata: r.rdata.clone(),
        })
        .collect()
}

/// The four steps between a datagram arriving and one leaving, separately and
/// together.
///
/// Separately because the whole is what an operator cares about and the parts
/// are what a change moves: the allocation work under #9e took the *together*
/// number from 25.7 allocations per query to 13.7 without any single part
/// obviously dominating.
fn answer(c: &mut Criterion) {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse the zone");
    let wire = query_message("www.example.com.", record_types::A)
        .to_bytes_within(512)
        .expect("serialize the query");

    let mut group = c.benchmark_group("answer");

    group.bench_function("parse a query", |b| {
        b.iter(|| DnsMessage::try_from_bytes(black_box(&wire)).expect("parse"))
    });

    group.bench_function("look up one A record", |b| {
        b.iter(|| zone.query(black_box("www.example.com."), record_types::A))
    });

    // Into a warm buffer, because that is what the UDP workers do — one scratch
    // buffer each, reused for the life of the process.
    let mut response = DnsMessage::try_from_bytes(&wire).expect("parse");
    response.response = true;
    response.authoritive = true;
    response.answers = owned(&zone, "www.example.com.", record_types::A);
    let mut scratch = Vec::with_capacity(4096);
    response
        .to_bytes_within_buf(4096, &mut scratch)
        .expect("warm the buffer");
    group.bench_function("serialize a one-record response", |b| {
        b.iter(|| {
            response
                .to_bytes_within_buf(4096, black_box(&mut scratch))
                .expect("serialize")
        })
    });

    // A full-size answer is a different shape: 4 KB of records sharing a suffix,
    // where name compression and the answer vector are doing real work rather
    // than being one record's worth of overhead.
    let mut big = query_message("example.com.", record_types::A);
    big.response = true;
    big.authoritive = true;
    for i in 0..60 {
        big.answers.push(ResourceRecord {
            name: format!("host{i}.example.com."),
            class: 1,
            ttl: 3600,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(
                192,
                0,
                2,
                (i % 254) as u8 + 1,
            )))
            .expect("build the rdata"),
        });
    }
    let mut big_scratch = Vec::with_capacity(65_535);
    big.to_bytes_within_buf(4096, &mut big_scratch)
        .expect("warm the buffer");
    group.bench_function("serialize a full-size response", |b| {
        b.iter(|| {
            big.to_bytes_within_buf(4096, black_box(&mut big_scratch))
                .expect("serialize")
        })
    });

    // Parse, look up, build, serialize: the library's share of one query, and
    // the number the #9e work moved.
    group.bench_function("one whole answer", |b| {
        b.iter(|| {
            let parsed = DnsMessage::try_from_bytes(black_box(&wire)).expect("parse");
            let answers = owned(&zone, &parsed.queries[0].qname, record_types::A);
            let mut out = parsed.clone();
            out.response = true;
            out.authoritive = true;
            out.answers = answers;
            out.to_bytes_within_buf(4096, &mut scratch).expect("write");
            scratch.len()
        })
    });

    group.finish();
}

/// The index, on a zone big enough for the shape of the lookup to show.
///
/// The miss is the one to watch: it is what a random-name flood produces, and
/// what the linear scan this replaced paid the most for. It is also the case
/// `TODO.md` #11 (data layout) would move, if anything does.
fn zone_index(c: &mut Criterion) {
    let mut zone = Zone::new("example.com.".to_string());
    for i in 0..10_000u32 {
        zone.add_record(ZoneRecord {
            name: format!("host{i}"),
            ttl: 3600,
            class: 1,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(
                192,
                0,
                2,
                (i % 254) as u8 + 1,
            )))
            .expect("build the rdata"),
        });
    }

    let mut group = c.benchmark_group("zone");
    group.bench_function("hit in a 10k-record zone", |b| {
        b.iter(|| zone.query(black_box("host9000.example.com."), record_types::A))
    });
    group.bench_function("miss in a 10k-record zone", |b| {
        b.iter(|| zone.query(black_box("nothing-here.example.com."), record_types::A))
    });
    group.finish();
}

/// What every datagram pays before anything looks at the question.
///
/// Both of these are per-packet and neither is on anyone's list of costs, which
/// is exactly why they are worth a number: they run before the rate limiter has
/// decided the packet is worth answering.
fn admission(c: &mut Criterion) {
    let limiter = RateLimiter::with_defaults();
    let validator = RequestValidator::with_defaults();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let packet = query_message("www.example.com.", record_types::A)
        .to_bytes_within(512)
        .expect("serialize");

    let mut group = c.benchmark_group("admission");
    group.bench_function("rate limiter", |b| {
        b.iter(|| limiter.should_allow(black_box(ip)))
    });
    group.bench_function("request validator", |b| {
        b.iter(|| validator.validate_packet(black_box(&packet), false))
    });
    group.finish();
}

/// The two pieces of shared state a query touches, at the depth that hurts.
///
/// Both are here because the old bench measured them where they cost nothing:
/// `bench_cache_throughput` only ever called `get` on an *empty* cache, so it
/// never reached `evict_oldest` and could not have seen the O(n²) eviction it
/// was meant to be watching. A cache is interesting when it is full and a
/// logger is interesting when it is tracking a lot of sources.
fn shared_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("state");

    // Amortized over 100 inserts, because eviction is not per-insert: the cache
    // halves itself when it goes over, so one insert in thousands pays for the
    // rest and a per-insert timing would report the median instead of the cost.
    let cache = DnsCache::new(20_000);
    let record = |name: &str| ResourceRecord {
        name: name.to_string(),
        class: 1,
        ttl: 300,
        rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1)))
            .expect("build the rdata"),
    };
    for i in 0..20_000 {
        let name = format!("fill{i}.example.com.");
        cache.put(&name, 1, vec![record(&name)]);
    }
    let mut n = 0u64;
    group.bench_function("100 puts into a full cache", |b| {
        b.iter(|| {
            for _ in 0..100 {
                n += 1;
                let name = format!("new{n}.example.com.");
                cache.put(black_box(&name), 1, vec![record(&name)]);
            }
        })
    });

    // A thousand distinct sources tracked, which is the depth the per-window
    // scan used to be quadratic in (`CLAUDE.md` §10).
    let logger = QueryLogger::new();
    for i in 0..1_000u32 {
        logger.log_query(IpAddr::V4(Ipv4Addr::from(i.to_be_bytes())), Some(1));
    }
    group.bench_function("log a query with 1k sources tracked", |b| {
        b.iter(|| logger.log_query(black_box(ip_of(12_345)), Some(1)))
    });

    group.finish();
}

fn ip_of(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(n.to_be_bytes()))
}

/// The item this harness exists for: `TODO.md` #9e's DNSSEC canonicalization.
///
/// `verify_rrset` rebuilds the canonical form of the whole RRset for each
/// candidate RRSIG, and the DHAT pass said in as many words that this is a
/// *time* problem rather than a count one — so a benchmark is the only thing
/// that can say whether fixing it is worth anything.
///
/// **Two shapes, because one of them cannot show the cost.** The DNSKEY RRset
/// signed by a KSK and a ZSK is the case the allocation test measures, and it is
/// the wrong case for this question: `verify_rrset` **returns on the first
/// signature that verifies**, so the second candidate is never canonicalized at
/// all and what the number contains is one canonicalization and one ECDSA
/// verify. The rebuild only happens when a candidate is *rejected*, which is a
/// key rollover or an attack, not the ordinary path.
///
/// So the second pair is the decomposition: the same verification over an RRset
/// of 1 record and of 20. Canonicalization scales with the record count and the
/// crypto does not, so the difference between them is the canonicalization, and
/// the ratio to the whole is what says whether #13 is worth doing.
fn dnssec(c: &mut Criterion) {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse the zone");
    let keys = vec![
        SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            rdns::dnssec::DNSKEY_FLAG_ZONE | rdns::dnssec::DNSKEY_FLAG_SEP,
        )
        .expect("ksk"),
        SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            rdns::dnssec::DNSKEY_FLAG_ZONE,
        )
        .expect("zsk"),
    ];
    let signed = sign_zone(
        &zone,
        &keys,
        &SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400),
    )
    .expect("sign the zone");

    let dnskeys = dnskeys_in(&owned(&signed, "example.com.", record_types::DNSKEY));
    let rrsigs = rrsigs_in(&owned(&signed, "example.com.", record_types::RRSIG));
    let rdatas: Vec<_> = owned(&signed, "example.com.", record_types::DNSKEY)
        .into_iter()
        .map(|r| r.rdata)
        .collect();
    let rrset = Rrset::new("example.com.", record_types::DNSKEY, 1, &rdatas);
    let now = current_unix_timestamp();

    let mut group = c.benchmark_group("dnssec");
    group.bench_function("verify an RRset against two candidate signatures", |b| {
        b.iter(|| {
            verify_rrset(
                black_box(&rrset),
                &rrsigs,
                &dnskeys,
                "example.com.",
                black_box(now),
            )
        })
    });

    // The decomposition: one RRset of 1 A record and one of 20, each signed
    // once. Everything but the canonicalization is identical between them.
    for count in [1usize, 20] {
        let mut text = String::from(ZONE);
        for i in 0..count {
            text.push_str(&format!("many IN A 192.0.2.{}\n", i + 1));
        }
        let zone = parse_zone_file(&text, "example.com.").expect("parse the zone");
        let signed = sign_zone(&zone, &keys, &SigningPolicy::valid_for(now, 30 * 86_400))
            .expect("sign the zone");

        let records = owned(&signed, "many.example.com.", record_types::A);
        assert_eq!(records.len(), count, "the RRset is the size claimed");
        let rrsigs = rrsigs_in(&owned(&signed, "many.example.com.", record_types::RRSIG));
        let rdatas: Vec<_> = records.into_iter().map(|r| r.rdata).collect();
        let rrset = Rrset::new("many.example.com.", record_types::A, 1, &rdatas);

        let plural = if count == 1 { "record" } else { "records" };
        group.bench_function(format!("verify an RRset of {count} {plural}"), |b| {
            b.iter(|| {
                verify_rrset(
                    black_box(&rrset),
                    &rrsigs,
                    &dnskeys,
                    "example.com.",
                    black_box(now),
                )
            })
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    // Three seconds of samples after one of warm-up. The default is five and
    // three, which is more than these need — every one of them is sub-microsecond
    // except the cache batch — and the whole file should stay runnable in under a
    // minute or nobody will run it before a change.
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = answer, zone_index, admission, shared_state, dnssec
}
criterion_main!(benches);
