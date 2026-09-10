//! Plain record fixtures, shared because six test modules were building the
//! same ones.
//!
//! Nothing cryptographic lives here — keys and signatures are
//! [`crate::dnssec_test_util`]. What a fixture is *for* stays with the test;
//! what a record *is* belongs in one place, because a second copy is where the
//! next bug goes (`CLAUDE.md` §7).

use crate::denial_wire::build_type_bitmap;
use crate::dnssec_denial::{nsec3_hash_name, nsec3_owner_name_at, Nsec3, Nsec3Hash};
use crate::zone::{parse_zone_file, Zone};
use crate::{Class, Name, ParsedRecord, RecordData, ResourceRecord, Rtype, Serial, Ttl};
use std::net::Ipv4Addr;

/// A name from a literal, for tests only: `Name` is fallible to build and a test
/// that writes a bad one should fail loudly at that line, rather than threading
/// a `Result` through a fixture.
///
/// One per crate, not one per module — and `rdns-core` has the same three lines
/// in `name.rs`. The copies left are in the standalone binaries, `tests/`,
/// `benches/` and `examples/`, which cannot see a `#[cfg(test)]` item in the
/// library; making it public API to spare them would be the worse trade.
pub fn nm(text: &str) -> Name {
    text.parse().expect("a test name parses")
}

/// The NSEC3 parameters every fixture here hashes under. One salt and one
/// iteration count, because two records in one proof that disagree about
/// either are a chain with a hole in it rather than a test.
pub const NSEC3_SALT: [u8; 2] = [0xaa, 0xbb];
pub const NSEC3_ITERATIONS: u16 = 3;

/// An A record at 300s, the TTL every caller was already using.
pub fn a_record(name: &str, addr: impl Into<Ipv4Addr>) -> ResourceRecord {
    ResourceRecord {
        name: nm(name),
        class: Class::new(1),
        ttl: Ttl::from_secs(300),
        rdata: a_rdata(addr),
    }
}

pub fn a_rdata(addr: impl Into<Ipv4Addr>) -> RecordData {
    RecordData::from_parsed(&ParsedRecord::A(addr.into())).expect("encode A")
}

/// An apex SOA whose MNAME and RNAME are derived from the zone, so a test that
/// names two zones cannot accidentally give them the same SOA.
pub fn soa_record(zone: &str, minimum: u32, ttl: Ttl) -> ResourceRecord {
    ResourceRecord {
        name: nm(zone),
        class: Class::new(1),
        ttl,
        rdata: RecordData::from_parsed(&ParsedRecord::SOA {
            mname: nm(&format!("ns1.{zone}")),
            rname: nm(&format!("admin.{zone}")),
            serial: Serial::new(1),
            refresh: 10800,
            retry: 3600,
            expire: 604800,
            minimum,
        })
        .expect("encode SOA"),
    }
}

pub fn nsec_record(owner: &str, next: &str, types: &[Rtype], ttl: Ttl) -> ResourceRecord {
    ResourceRecord {
        name: nm(owner),
        class: Class::new(1),
        ttl,
        rdata: RecordData::from_parsed(&ParsedRecord::NSEC {
            next_domain_name: nm(next),
            type_bitmap: build_type_bitmap(types),
        })
        .expect("encode NSEC"),
    }
}

/// The NSEC3 denying `name`, parsed — the owner hash is `name`'s under
/// [`NSEC3_SALT`], and `next` is given outright because a fixture wants to
/// choose what the span contains.
pub fn nsec3(zone: &str, name: &str, next: &[u8], flags: u8, types: &[Rtype]) -> Nsec3 {
    let hash = nsec3_hash_name(nm(name).as_ref(), &NSEC3_SALT, NSEC3_ITERATIONS)
        .expect("hash the owner name");
    Nsec3 {
        owner: nsec3_owner_name_at(hash, nm(zone).as_ref()).expect("an NSEC3 owner name"),
        owner_hash: hash,
        zone: nm(zone),
        hash_algorithm: 1,
        flags,
        iterations: NSEC3_ITERATIONS,
        salt: NSEC3_SALT.to_vec(),
        next_hashed_owner: Nsec3Hash::from_wire(next).expect("a 20-octet next hash"),
        type_bitmap: build_type_bitmap(types),
    }
}

/// The same record on the wire.
pub fn nsec3_record(
    zone: &str,
    name: &str,
    next: &[u8],
    flags: u8,
    types: &[Rtype],
    ttl: Ttl,
) -> ResourceRecord {
    nsec3_as_record(&nsec3(zone, name, next, flags, types), ttl)
}

/// An NSEC3 with both hashes given outright, for a chain laid out by hand
/// rather than by finding names that hash where they are wanted.
pub fn nsec3_span(
    zone: &str,
    owner_hash: &[u8],
    next: &[u8],
    types: &[Rtype],
    ttl: Ttl,
) -> ResourceRecord {
    ResourceRecord {
        name: nsec3_owner_name_at(
            Nsec3Hash::from_wire(owner_hash).expect("a 20-octet owner hash"),
            nm(zone).as_ref(),
        )
        .expect("an NSEC3 owner name"),
        class: Class::new(1),
        ttl,
        rdata: RecordData::from_parsed(&ParsedRecord::NSEC3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: NSEC3_ITERATIONS,
            salt: NSEC3_SALT.to_vec(),
            next_hashed_owner: next.to_vec(),
            type_bitmap: build_type_bitmap(types),
        })
        .expect("encode NSEC3"),
    }
}

fn nsec3_as_record(n: &Nsec3, ttl: Ttl) -> ResourceRecord {
    ResourceRecord {
        name: n.owner.clone(),
        class: Class::new(1),
        ttl,
        rdata: RecordData::from_parsed(&ParsedRecord::NSEC3 {
            hash_algorithm: n.hash_algorithm,
            flags: n.flags,
            iterations: n.iterations,
            salt: n.salt.clone(),
            next_hashed_owner: n.next_hashed_owner.as_bytes().to_vec(),
            type_bitmap: n.type_bitmap.clone(),
        })
        .expect("encode NSEC3"),
    }
}

/// A zone at `serial`, with `body` appended to an apex that never changes.
///
/// `ixfr` and `journal` had this identical: both are about the *steps between*
/// two versions, so both want a zone that differs only where they say it does.
pub fn zone_at(serial: u32, body: &str) -> Zone {
    parse_zone_file(
        &format!(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. {serial} 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             {body}"
        ),
        "example.com.",
    )
    .expect("zone should parse")
}
