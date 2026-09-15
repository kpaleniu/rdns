//! Plain record fixtures, shared because six test modules were building the
//! same ones.
//!
//! Nothing cryptographic lives here — keys, signatures and the NSEC3 fixtures,
//! which hash a name, are [`crate::dnssec_test_util`]. The sentence was not
//! true until `TODO.md` #67f moved the last three out: `nsec3` called
//! `nsec3_hash_name` fifty lines below it. What a fixture is *for* stays with the test;
//! what a record *is* belongs in one place, because a second copy is where the
//! next bug goes (`CLAUDE.md` §7).

use crate::denial_wire::build_type_bitmap;
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
