//! What one query costs, measured on optimized code.
//!
//! Everything here is about 6% of what a query costs a server — one `sendto`
//! plus one `recvfrom` on loopback is ~3.6 µs against ~231 ns of library work —
//! so a claim that a *query* got faster has to be measured against a query,
//! syscalls included.
//!
//! ```sh
//! cargo bench -p rdns                        # everything
//! cargo bench -p rdns -- answer              # one group
//! cargo bench -p rdns -- --save-baseline before
//! cargo bench -p rdns -- --baseline before   # after a change
//! ```

use rdns::Class;
use rdns::Ttl;
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
use rdns::validation::AdmissionCheck;
use rdns::zone::{parse_zone_file, Zone, ZoneRecord};
use rdns::zone_signer::{sign_zone, SigningPolicy};
use rdns::{
    DnsMessage, OpCode, ParsedRecord, Qtype, QueryClass, QuerySection, RecordData, ResourceRecord,
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

fn query_message(qname: &str, qtype: Qtype) -> DnsMessage {
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
        edns: None,
    }
}

fn owned(zone: &Zone, name: &str, qtype: Qtype) -> Vec<ResourceRecord> {
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

/// The steps between a datagram arriving and one leaving, separately and
/// together: the whole is what an operator cares about, the parts are what a
/// change moves.
fn answer(c: &mut Criterion) {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse the zone");
    let wire = query_message("www.example.com.", Qtype::of(record_types::A))
        .to_bytes_within(512)
        .expect("serialize the query");

    let mut group = c.benchmark_group("answer");

    group.bench_function("parse a query", |b| {
        b.iter(|| DnsMessage::try_from_bytes(black_box(&wire)).expect("parse"))
    });

    group.bench_function("look up one A record", |b| {
        b.iter(|| zone.query(black_box("www.example.com."), Qtype::of(record_types::A)))
    });

    // Into a warm buffer: the UDP workers keep one scratch buffer each for the
    // life of the process.
    let mut response = DnsMessage::try_from_bytes(&wire).expect("parse");
    response.response = true;
    response.authoritive = true;
    response.answers = owned(&zone, "www.example.com.", Qtype::of(record_types::A));
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

    // 4 KB of records sharing a suffix: name compression and the answer vector
    // doing real work rather than one record's worth of overhead.
    let mut big = query_message("example.com.", Qtype::of(record_types::A));
    big.response = true;
    big.authoritive = true;
    for i in 0..60 {
        big.answers.push(ResourceRecord {
            name: format!("host{i}.example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
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

    // A transfer envelope: 300-500 records, nearly all distinct owner names, so
    // the compressor's table is hundreds of entries rather than a handful — the
    // one shape "a scan beats a hash for a few names" is false of. Names are
    // short so the message stays inside the 14-bit pointer range.
    let mut envelope = query_message("example.com.", Qtype::AXFR);
    envelope.response = true;
    envelope.authoritive = true;
    for i in 0..400 {
        envelope.answers.push(ResourceRecord {
            name: format!("h{i}.e.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(
                192,
                0,
                2,
                (i % 254) as u8 + 1,
            )))
            .expect("build the rdata"),
        });
    }
    let mut envelope_scratch = Vec::with_capacity(65_535);
    envelope
        .to_bytes_within_buf(65_535, &mut envelope_scratch)
        .expect("warm the buffer");
    group.bench_function("serialize a 400-record transfer envelope", |b| {
        b.iter(|| {
            envelope
                .to_bytes_within_buf(65_535, black_box(&mut envelope_scratch))
                .expect("serialize")
        })
    });

    // Parse, look up, build, serialize: the library's share of one query.
    group.bench_function("one whole answer", |b| {
        b.iter(|| {
            let parsed = DnsMessage::try_from_bytes(black_box(&wire)).expect("parse");
            let answers = owned(&zone, &parsed.queries[0].qname, Qtype::of(record_types::A));
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
/// The miss is the one to watch: what a random-name flood produces, and what the
/// linear scan this replaced paid the most for.
fn zone_index(c: &mut Criterion) {
    let mut zone = Zone::new("example.com.".to_string());
    for i in 0..10_000u32 {
        zone.add_record(ZoneRecord {
            name: format!("host{i}"),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
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
        b.iter(|| {
            zone.query(
                black_box("host9000.example.com."),
                Qtype::of(record_types::A),
            )
        })
    });
    group.bench_function("miss in a 10k-record zone", |b| {
        b.iter(|| {
            zone.query(
                black_box("nothing-here.example.com."),
                Qtype::of(record_types::A),
            )
        })
    });
    group.finish();
}

/// What every datagram pays before anything looks at the question — including
/// before the rate limiter has decided the packet is worth answering.
fn admission(c: &mut Criterion) {
    let limiter = RateLimiter::with_defaults();
    let validator = AdmissionCheck::with_defaults();
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let packet = query_message("www.example.com.", Qtype::of(record_types::A))
        .to_bytes_within(512)
        .expect("serialize");

    let mut group = c.benchmark_group("admission");
    group.bench_function("rate limiter", |b| {
        b.iter(|| limiter.should_allow(black_box(ip), current_unix_timestamp()))
    });
    group.bench_function("request validator", |b| {
        b.iter(|| validator.validate_packet(black_box(&packet), false))
    });
    group.finish();
}

/// The two pieces of shared state a query touches, at the depth that hurts: a
/// cache is interesting when it is full and a logger when it tracks many
/// sources.
fn shared_state(c: &mut Criterion) {
    let mut group = c.benchmark_group("state");

    // Amortized over 100 inserts: the cache halves itself when it goes over, so
    // one insert in thousands pays for the rest and a per-insert timing would
    // report the median instead of the cost.
    let cache = DnsCache::new(20_000);
    let record = |name: &str| ResourceRecord {
        name: name.to_string(),
        class: Class::new(1),
        ttl: Ttl::from_secs(300),
        rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1)))
            .expect("build the rdata"),
    };
    for i in 0..20_000 {
        let name = format!("fill{i}.example.com.");
        cache.put(&name, Qtype::of(record_types::A), vec![record(&name)]);
    }
    let mut n = 0u64;
    group.bench_function("100 puts into a full cache", |b| {
        b.iter(|| {
            for _ in 0..100 {
                n += 1;
                let name = format!("new{n}.example.com.");
                cache.put(
                    black_box(&name),
                    Qtype::of(record_types::A),
                    vec![record(&name)],
                );
            }
        })
    });

    // A thousand distinct sources tracked: the depth `log_query` was quadratic
    // in.
    let logger = QueryLogger::new();
    for i in 0..1_000u32 {
        logger.log_query(
            IpAddr::V4(Ipv4Addr::from(i.to_be_bytes())),
            Some(Qtype::of(record_types::A)),
            current_unix_timestamp(),
        );
    }
    group.bench_function("log a query with 1k sources tracked", |b| {
        // The clock read stays inside the closure: a caller makes one per
        // datagram, so this is still what answering one query pays (#28a).
        b.iter(|| {
            logger.log_query(
                black_box(ip_of(12_345)),
                Some(Qtype::of(record_types::A)),
                current_unix_timestamp(),
            )
        })
    });

    group.finish();
}

fn ip_of(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(n.to_be_bytes()))
}

/// DNSSEC canonicalization, which `verify_rrset` rebuilds per candidate RRSIG.
///
/// Two shapes, because the two-signature one cannot show the cost:
/// `verify_rrset` returns on the first signature that verifies, so the second
/// candidate is never canonicalized unless one is *rejected* — a rollover or an
/// attack, not the ordinary path. The 1-record and 20-record pair is the
/// decomposition: canonicalization scales with the record count and the crypto
/// does not, so the difference between them is the canonicalization.
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

    let dnskeys = dnskeys_in(&owned(
        &signed,
        "example.com.",
        Qtype::of(record_types::DNSKEY),
    ));
    let rrsigs = rrsigs_in(&owned(
        &signed,
        "example.com.",
        Qtype::of(record_types::RRSIG),
    ));
    let rdatas: Vec<_> = owned(&signed, "example.com.", Qtype::of(record_types::DNSKEY))
        .into_iter()
        .map(|r| r.rdata)
        .collect();
    let rrset = Rrset::new("example.com.", record_types::DNSKEY, Class::new(1), &rdatas);
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

    // One RRset of 1 A record and one of 20, each signed once: everything but
    // the canonicalization is identical between them.
    for count in [1usize, 20] {
        let mut text = String::from(ZONE);
        for i in 0..count {
            text.push_str(&format!("many IN A 192.0.2.{}\n", i + 1));
        }
        let zone = parse_zone_file(&text, "example.com.").expect("parse the zone");
        let signed = sign_zone(&zone, &keys, &SigningPolicy::valid_for(now, 30 * 86_400))
            .expect("sign the zone");

        let records = owned(&signed, "many.example.com.", Qtype::of(record_types::A));
        assert_eq!(records.len(), count, "the RRset is the size claimed");
        let rrsigs = rrsigs_in(&owned(
            &signed,
            "many.example.com.",
            Qtype::of(record_types::RRSIG),
        ));
        let rdatas: Vec<_> = records.into_iter().map(|r| r.rdata).collect();
        let rrset = Rrset::new("many.example.com.", record_types::A, Class::new(1), &rdatas);

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
    // Below criterion's five-and-three default: everything here is
    // sub-microsecond except the cache batch, and a file that takes over a
    // minute does not get run before a change.
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = answer, zone_index, admission, shared_state, dnssec
}
criterion_main!(benches);
