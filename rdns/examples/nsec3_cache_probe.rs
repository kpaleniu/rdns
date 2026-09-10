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
//! # Measured 2026-08-04, and again 2026-09-04
//!
//! Release, per `synthesize`, on the development machine. Every column runs from
//! this file; "before" is the commit before #23's fix, "walk" the one before
//! #29b's.
//!
//! | iterations | QNAME | before | after | walk | now |
//! |---|---|---|---|---|---|
//! | 0 (RFC 9276's recommendation) | 117 labels, 243 octets | 102 ms | 237 µs | 240 µs | 102 µs |
//! | 10 | 117 labels | 171 ms | 307 µs | 287 µs | 151 µs |
//! | 150 (`MAX_NSEC3_ITERATIONS`) | 10 labels, 29 octets | 84 ms | 95 µs | 61 µs | 60 µs |
//! | 150 | 117 labels | 1 124 ms | 1.28 ms | 867 µs | 743 µs |
//!
//! The 2026-08-04 note said what was left was not the hash: at iterations 0 the
//! walk cost ~2.1 µs per label, `suffix_labels` rebuilding the name — a
//! `canonical_name` copy, a `Vec<&str>` of the labels, a join and a `format!`
//! per ancestor — and removing it wanted a name that can yield a suffix without
//! allocating. An absolute name's ancestor *is* a suffix of it, so that turned
//! out to be a slice rather than a type: `utils::suffix_labels`, and the "now"
//! column is what it bought. **Over half of the zero-iteration case was the
//! naming, not the hashing.**
//!
//! The 150-iteration rows barely move, which is the other half of the same
//! reading: they are ~7.6 µs per label of SHA-1 over 22 bytes, the part
//! RFC 9276 §3.1 asks zones not to ask for.

use rdns::denial_wire::{base32hex_encode, build_type_bitmap};
use rdns::dnssec_denial::nsec3_hash;
use rdns::nsec_cache::NsecCache;
use rdns::record_types as rt;
use rdns::{
    Class, DnsMessage, Name, OpCode, ParsedRecord, Qtype, QueryClass, QuerySection, RecordData,
    ResourceRecord, ResponseCode, Serial, Ttl,
};
use std::hint::black_box;
use std::time::Instant;

/// A name from a literal, for a probe only: `Name` is fallible to build and a
/// probe that writes a bad one should fail loudly at that line.
fn nm(text: &str) -> Name {
    text.parse().expect("a probe name parses")
}

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

    let qname: rdns::Name = format!("{}example.com.", "a.".repeat(labels))
        .parse()
        .expect("the probe's own name parses");
    // A name in presentation form with a trailing dot is one octet shorter than
    // its wire form, which ends in a zero-length root label.
    let octets = qname.as_ref().as_wire().len();
    assert!(
        cache.synthesize(qname.as_ref(), Qtype::of(rt::A)).is_none(),
        "the probe measures the miss; something in the cache answered"
    );

    let n = 100;
    let start = Instant::now();
    for _ in 0..n {
        black_box(cache.synthesize(qname.as_ref(), Qtype::of(rt::A)));
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
        name: nm("example.com."),
        class: Class::new(1),
        ttl: Ttl::from_secs(3600),
        rdata: RecordData::from_parsed(&ParsedRecord::SOA {
            mname: nm("ns1.example.com."),
            rname: nm("admin.example.com."),
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
            name: nm(&format!(
                "{}.example.com.",
                base32hex_encode(&hash).to_lowercase()
            )),
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
            qname: nm("nope.example.com."),
            qtype: Qtype::of(rt::A),
            qclass: QueryClass::IN,
        }],
        answers: Vec::new(),
        authorities,
        additionals: Vec::new(),
        edns: None,
    }
}
