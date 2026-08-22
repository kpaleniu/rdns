//! What one denial-cache lookup costs when nothing in the cache bears on it.
//!
//! The worst case for the scan this replaced, and the case a flood of random
//! names produces: 256 cached NSEC3 records, every span one hash wide, so every
//! lookup misses after looking at all of them. Two things the client picks are
//! the arguments — the zone's iteration count and the QNAME's label count —
//! because both were multipliers.
//!
//! ```sh
//! cargo run --release -p rdns --example nsec3_cache_probe -- 150 115
//! ```
//!
//! # Measured 2026-08-04
//!
//! Release, per `synthesize`, on the development machine. Both columns run from
//! this file, the "before" one against the commit before the fix.
//!
//! | iterations | QNAME | before | after |
//! |---|---|---|---|
//! | 0 (RFC 9276's recommendation) | 117 labels, 243 octets | 102 ms | 237 µs |
//! | 10 | 117 labels | 171 ms | 307 µs |
//! | 150 (`MAX_NSEC3_ITERATIONS`) | 10 labels, 29 octets | 84 ms | 95 µs |
//! | 150 | 117 labels | 1 124 ms | 1.28 ms |
//!
//! What is left is not the hash: at iterations 0 the walk still costs 2.1 µs per
//! label, which is `suffix_labels` rebuilding the name — a `canonical_name`
//! copy, a `Vec<&str>` of the labels, a join and a `format!` per ancestor. The
//! 150-iteration column adds ~7.6 µs per label on top, which is the 150 extra
//! SHA-1 rounds over 22 bytes and is the part RFC 9276 §3.1 asks zones not to
//! ask for. Removing the first wants a name type that can yield a suffix
//! without allocating.

use rdns::dnssec_denial::{base32hex_encode, build_type_bitmap, nsec3_hash};
use rdns::nsec_cache::NsecCache;
use rdns::utils::record_types as rt;
use rdns::{
    Class, DnsMessage, OpCode, ParsedRecord, Qtype, QueryClass, QuerySection, RecordData,
    ResourceRecord, ResponseCode, Serial, Ttl,
};
use std::hint::black_box;
use std::time::Instant;

const RECORDS: usize = 256; // nsec_cache::MAX_PROOFS_PER_ZONE

fn main() {
    let arg = |n: usize, default: usize| -> usize {
        std::env::args()
            .nth(n)
            .and_then(|s| s.parse().ok())
            .unwrap_or(default)
    };
    let iterations = arg(1, 150) as u16;
    let labels = arg(2, 115);

    let cache = NsecCache::new(4);
    cache.insert_validated(&filled(iterations));

    let qname = format!("{}example.com.", "a.".repeat(labels));
    // A name in presentation form with a trailing dot is one octet shorter than
    // its wire form, which ends in a zero-length root label.
    let octets = qname.len() + 1;
    assert!(
        cache.synthesize(&qname, Qtype::of(rt::A)).is_none(),
        "the probe measures the miss; something in the cache answered"
    );

    let n = 100;
    let start = Instant::now();
    for _ in 0..n {
        black_box(cache.synthesize(&qname, Qtype::of(rt::A)));
    }
    let each = start.elapsed() / n;
    println!(
        "{RECORDS} records, iterations {iterations}, qname {} labels / {octets} octets: \
         {each:?} per synthesize",
        labels + 2
    );
}

/// One zone's worth of NSEC3 that proves nothing about anything: each span runs
/// from the owner hash to the same hash with its last octet at 0xff, so nothing
/// falls inside one and only the `fill` names match.
fn filled(iterations: u16) -> DnsMessage {
    let salt = vec![0xaa, 0xbb];
    let mut authorities = vec![ResourceRecord {
        name: "example.com.".to_string(),
        class: Class::new(1),
        ttl: Ttl::from_secs(3600),
        rdata: RecordData::from_parsed(&ParsedRecord::SOA {
            mname: "ns1.example.com.".into(),
            rname: "admin.example.com.".into(),
            serial: Serial::new(1),
            refresh: 10800,
            retry: 3600,
            expire: 604800,
            minimum: 3600,
        })
        .unwrap(),
    }];
    let mut i = 0;
    while authorities.len() <= RECORDS {
        let hash = nsec3_hash(&format!("fill{i}.example.com."), &salt, iterations).unwrap();
        i += 1;
        // A hash already ending in 0xff would make the span empty *and* wrapped,
        // which covers everything rather than nothing.
        if *hash.last().unwrap() == 0xff {
            continue;
        }
        let mut next = hash.clone();
        *next.last_mut().unwrap() = 0xff;
        authorities.push(ResourceRecord {
            name: format!("{}.example.com.", base32hex_encode(&hash).to_lowercase()),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC3 {
                hash_algorithm: 1,
                flags: 0,
                iterations,
                salt: salt.clone(),
                next_hashed_owner: next,
                type_bitmap: build_type_bitmap(&[rt::A]),
            })
            .unwrap(),
        });
    }

    DnsMessage {
        id: 1,
        response: true,
        opcode: OpCode::Query,
        authoritive: true,
        truncation: false,
        recursion: true,
        recursion_ok: true,
        ad: true,
        cd: false,
        rcode: ResponseCode::NoSuchDomain,
        queries: vec![QuerySection {
            qname: "nope.example.com.".into(),
            qtype: Qtype::of(rt::A),
            qclass: QueryClass::IN,
        }],
        answers: Vec::new(),
        authorities,
        additionals: Vec::new(),
        edns: None,
    }
}
