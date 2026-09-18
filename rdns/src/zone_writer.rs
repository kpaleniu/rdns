//! Writing a [`Zone`] back out as a zone file, in the presentation format the
//! parser already reads.
//!
//! What is written must read back as the same bytes: a signature covers RDATA
//! octet for octet, so a re-spelling that re-encodes differently turns a valid
//! RRset bogus. A record is rendered type-specifically only where that provably
//! round-trips, otherwise in RFC 3597 §5's `\# <len> <hex>` form.
//!
//! An owner name has no such fallback — it is the first field of the line, and
//! this parser has no escape syntax — so an unspellable one is refused rather
//! than written as a different name.
//!
//! Every line stands on its own: owner names absolute, TTL and class stated.

use crate::error::ZoneError;
use crate::record_text::record_line;
use crate::Qtype;
use crate::Ttl;
use std::path::Path;

use crate::record_types;
use crate::zone::{Zone, ZoneRecord};
use crate::ParsedRecord;

/// Serialize a zone to the text presentation format.
///
/// Fails only on a record this format cannot express — see the module docs; in
/// practice that is an owner name needing escapes.
pub fn zone_to_string(zone: &Zone) -> Result<String, ZoneError> {
    // A zone file runs to tens of megabytes and this grew from empty, so a
    // million-record zone was ~25 reallocations copying up to the whole file
    // each time. The estimate need not be right — being wrong costs one
    // `realloc` (`TODO.md` #64c).
    let mut out = String::with_capacity(zone.records().len() * 64 + 256);

    out.push_str("; ");
    out.push_str(&zone.origin().to_presentation());
    out.push_str(" — written by rdns. Owner names are absolute and every record\n");
    out.push_str("; states its own TTL, so no line here depends on any other.\n");
    out.push_str(&format!("$ORIGIN {}\n", zone.origin().to_presentation()));
    out.push_str(&format!("$TTL {}\n\n", default_ttl(zone)));

    // The SOA first, as a transfer sends it. The rest keep load order, so
    // rewriting an unchanged zone produces an unchanged file.
    //
    // Through `Zone::is_apex_soa` rather than comparing `record.name`, which is
    // the same question five other places ask (`TODO.md` #33f). A `Name` is
    // absolute and compares case-insensitively, so the two now agree — which is
    // the point of asking one of them.
    for record in zone.records().iter().filter(|r| zone.is_apex_soa(r)) {
        record_into(&mut out, record)?;
    }
    for record in zone.records().iter().filter(|r| !zone.is_apex_soa(r)) {
        record_into(&mut out, record)?;
    }

    Ok(out)
}

/// Serialize a zone and replace `path` with it, atomically.
///
/// The rename ([`crate::persist::write_atomically`]) makes a reload safe against
/// a zone being rewritten, and a record that cannot be expressed leaves the
/// previous file untouched.
pub fn write_zone_file(zone: &Zone, path: &Path) -> Result<(), ZoneError> {
    write_zone_text(&zone_to_string(zone)?, path)
}

/// The same, for a caller that needs the text as well as the file.
///
/// A digest of what was written is how the next reader knows it need not parse
/// the file back (`TODO.md` #71f, `rdns::rpz::PolicyStore::offer`), and
/// serializing a million-record zone twice to get it is 249 ms
/// (`rdns/tests/record_storage.rs`).
pub fn write_zone_text(text: &str, path: &Path) -> Result<(), ZoneError> {
    crate::persist::write_atomically_str(path, text).map_err(|source| ZoneError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// One record and its newline, appended to a zone being written.
fn record_into(out: &mut String, record: &ZoneRecord) -> Result<(), ZoneError> {
    crate::record_text::record_line_into(
        out,
        record.name.as_ref(),
        record.ttl,
        record.class,
        &record.rdata,
    )?;
    out.push('\n');
    Ok(())
}

/// One record as a zone-file line.
pub fn record_to_string(record: &ZoneRecord) -> Result<String, ZoneError> {
    record_line(
        record.name.as_ref(),
        record.ttl,
        record.class,
        &record.rdata,
    )
}

/// What to put in `$TTL`. Every record written states its own, so this exists
/// only because other tools insist on seeing the directive; the SOA's minimum is
/// the conventional choice.
fn default_ttl(zone: &Zone) -> Ttl {
    let soa = zone
        .query(zone.origin(), Qtype::of(record_types::SOA))
        .first()
        .and_then(|r| r.rdata.parse().ok());
    if let Some(ParsedRecord::SOA { minimum, .. }) = soa {
        return Ttl::from_secs(minimum);
    }
    zone.records()
        .first()
        .map(|r| r.ttl)
        .unwrap_or(Ttl::from_secs(3600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record_types as rt;
    use crate::test_records::nm;
    use crate::testutil::ScratchDir;
    use crate::zone::parse_zone_file;
    use crate::Name;
    use crate::Rtype;
    use crate::Serial;
    use crate::{Class, ParsedRecord, RecordData};

    /// Load, write, load again: the two zones must match record for record and
    /// RDATA byte for byte.
    fn round_trip(text: &str, origin: &str) -> (Zone, Zone, String) {
        let first = parse_zone_file(text, origin).expect("parse the input");
        let written = zone_to_string(&first).expect("write");
        let second = parse_zone_file(&written, origin)
            .unwrap_or_else(|e| panic!("re-parse what we wrote: {e}\n---\n{written}\n---"));

        let mut before: Vec<_> = first
            .records()
            .iter()
            .map(|r| (r.name.clone(), r.ttl, r.class, r.rdata.clone()))
            .collect();
        let mut after: Vec<_> = second
            .records()
            .iter()
            .map(|r| (r.name.clone(), r.ttl, r.class, r.rdata.clone()))
            .collect();
        // Sorted only to make the comparison order-independent; `Name` has no
        // `Ord` because canonical DNS order is not byte order (RFC 4034 §6.1).
        before.sort_by_key(|r| (r.0.to_string(), r.3.rtype()));
        after.sort_by_key(|r| (r.0.to_string(), r.3.rtype()));
        assert_eq!(
            before, after,
            "round trip changed the zone\n---\n{written}\n---"
        );

        (first, second, written)
    }

    #[test]
    fn test_ordinary_zone_round_trips() {
        let (_, second, written) = round_trip(
            "$ORIGIN example.com.\n\
             $TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 2021010101 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             @    IN MX  10 mail.example.com.\n\
             www  IN A   192.0.2.1\n\
             www  IN AAAA 2001:db8::1\n\
             ptr  IN PTR host.example.com.\n\
             old  300 IN CNAME www.example.com.\n\
             *    IN A   192.0.2.9\n",
            "example.com.",
        );

        assert!(written.contains("$ORIGIN example.com."));
        assert!(written.contains("; serial"), "the SOA is written readably");
        assert_eq!(
            second
                .query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
        assert_eq!(
            second
                .query(nm("anything.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "wildcard"
        );
        assert_eq!(second.serial(), Some(Serial::new(2021010101)));
    }

    /// A per-record TTL makes each line independent, including one differing
    /// from the zone's default.
    #[test]
    fn test_ttls_are_written_per_record() {
        let (_, second, _) = round_trip(
            "$TTL 3600\n@ IN SOA ns1. admin. 1 2 3 4 5\nshort 60 IN A 192.0.2.1\n",
            "example.com.",
        );
        let record = second.query(nm("short.example.com.").as_ref(), Qtype::of(rt::A))[0];
        assert_eq!(record.ttl, Ttl::from_secs(60));
    }

    /// The SOA leads the file whatever order it was loaded in.
    #[test]
    fn test_soa_is_written_first() {
        let (_, _, written) = round_trip(
            "www IN A 192.0.2.1\n@ IN SOA ns1. admin. 1 2 3 4 5\n",
            "example.com.",
        );
        let soa = written.find(" SOA ").expect("an SOA line");
        let a = written.find(" A ").expect("an A line");
        assert!(soa < a, "SOA should lead:\n{written}");
    }

    #[test]
    fn test_txt_strings_survive_as_a_sequence() {
        let (_, second, written) = round_trip(
            "txt IN TXT \"v=spf1 -all\" \"second string\"\n\
             one IN TXT \"a b\"\n\
             two IN TXT a b\n\
             quo IN TXT \"say \\\"hi\\\"; and a backslash \\\\\"\n",
            "example.com.",
        );

        let two = second.query(nm("two.example.com.").as_ref(), Qtype::of(rt::TXT))[0];
        assert!(
            matches!(two.rdata.parse(), Ok(ParsedRecord::TXT(s)) if s.len() == 2),
            "unquoted words stay two strings"
        );
        assert!(
            written.contains(r#""say \"hi\"; and a backslash \\""#),
            "{written}"
        );
    }

    /// A TXT record is arbitrary octets, and every one of them now has a
    /// spelling: RFC 1035 §5.1's `\DDD`.
    ///
    /// ~~"this format has no decimal escape, so the generic form carries
    /// it"~~ — true until `codecs::char_string_decode` was written for
    /// RFC 9460's SvcParamValues, which needed the same escape. This test
    /// asserted the limitation, so it had to change when the limitation went
    /// (`CLAUDE.md` §1). What it asserts now is the round trip, which is what
    /// it was for.
    #[test]
    fn test_binary_txt_round_trips_through_decimal_escapes() {
        let mut zone = Zone::new(nm("example.com."));
        let rdata = RecordData::from_parsed(&ParsedRecord::TXT(vec![vec![0x00, 0xff, 0x1f]]))
            .expect("encode");
        zone.add_record(ZoneRecord {
            name: nm("bin.example.com."),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: rdata.clone(),
        });

        let written = zone_to_string(&zone).expect("write");
        assert!(
            written.contains(r#"TXT     "\000\255\031""#),
            "every octet has a spelling now: {written}"
        );

        let reread = parse_zone_file(&written, "example.com.").expect("re-parse");
        assert_eq!(
            reread.query(nm("bin.example.com.").as_ref(), Qtype::of(rt::TXT))[0].rdata,
            rdata
        );
    }

    /// A type with no parser here must survive persistence, or a secondary drops
    /// records when it writes a fetched zone down.
    #[test]
    fn test_unknown_types_survive_as_generic_records() {
        let mut zone = Zone::new(nm("example.com."));
        let rdata = RecordData::new(Rtype::new(1234), vec![0xde, 0xad, 0xbe, 0xef])
            .expect("a type with no decoder is stored verbatim");
        zone.add_record(ZoneRecord {
            name: nm("odd.example.com."),
            ttl: Ttl::from_secs(300),
            class: Class::new(1),
            rdata: rdata.clone(),
        });

        let written = zone_to_string(&zone).expect("write");
        assert!(written.contains("TYPE1234 \\# 4 DEADBEEF"), "{written}");

        let reread = parse_zone_file(&written, "example.com.").expect("re-parse");
        assert_eq!(
            reread.query(nm("odd.example.com.").as_ref(), Qtype::of(Rtype::new(1234)))[0].rdata,
            rdata
        );
    }

    /// Empty RDATA is legal and has to be written as `\# 0`, with no hex at all.
    #[test]
    fn test_empty_generic_rdata() {
        let mut zone = Zone::new(nm("example.com."));
        zone.add_record(ZoneRecord {
            name: nm("empty.example.com."),
            ttl: Ttl::from_secs(300),
            class: Class::new(1),
            rdata: RecordData::new(Rtype::new(4321), Vec::new()).expect("zero-length rdata"),
        });

        let written = zone_to_string(&zone).expect("write");
        assert!(written.contains("TYPE4321 \\# 0"), "{written}");
        let reread = parse_zone_file(&written, "example.com.").expect("re-parse");
        assert!(reread.query(
            nm("empty.example.com.").as_ref(),
            Qtype::of(Rtype::new(4321))
        )[0]
        .rdata
        .bytes()
        .is_empty());
    }

    /// A signature covers the RDATA it was made over, so anything that comes
    /// back different no longer verifies.
    #[test]
    fn test_dnssec_records_round_trip_byte_for_byte() {
        let (first, second, written) = round_trip(
            "@ IN SOA ns1. admin. 1 2 3 4 5\n\
             @ 3600 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3\n\
             @ 3600 IN DS 12345 8 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE1EE8F13B5F5D1D1D1D1D1D1D\n\
             @ 3600 IN RRSIG A 8 2 3600 20300101000000 20200101000000 12345 example.com. AwEAAaz/tAm8\n\
             @ 3600 IN NSEC www.example.com. A NS SOA MX RRSIG NSEC DNSKEY\n\
             @ 3600 IN NSEC3 1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A RRSIG\n\
             n3 3600 IN NSEC3 1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A\n",
            "example.com.",
        );

        // The round trip is the real check; these pin the spellings, and that
        // none of them took the generic escape hatch.
        assert!(
            written.contains("NSEC    www.example.com. A NS SOA MX RRSIG NSEC DNSKEY"),
            "{written}"
        );
        assert!(written.contains("NSEC3   1 1 12 AABBCCDD "), "{written}");
        assert!(
            written.contains("NSEC3   1 0 0 - "),
            "empty salt is `-`: {written}"
        );
        assert!(
            written.contains("RRSIG   A 8 2 3600 20300101000000 20200101000000 12345"),
            "{written}"
        );
        assert!(
            !written.contains("\\#"),
            "nothing needed the generic form: {written}"
        );

        assert_eq!(
            first.query(nm("example.com.").as_ref(), Qtype::of(rt::NSEC3))[0].rdata,
            second.query(nm("example.com.").as_ref(), Qtype::of(rt::NSEC3))[0].rdata
        );
    }

    /// CDS and CDNSKEY read and write under their own names, not as
    /// `TYPE59`/`TYPE60`.
    ///
    /// They share DS's and DNSKEY's formats (RFC 7344 §3.1, §3.2) and one
    /// `ParsedRecord` arm each, so what could go wrong is the *name*: a record
    /// that parses into the DS arm and prints as `DS` is a different record,
    /// and a signature over it covers a different type code. Until `TODO.md`
    /// #55 neither name parsed at all — the row said an operator could write
    /// them by hand, and `record_type_name_to_code` said `unsupported record
    /// type "CDS"`.
    #[test]
    fn cds_and_cdnskey_round_trip_under_their_own_names() {
        // Unindented, because a leading space makes a line a continuation of
        // the record above it — a zone file's own syntax, not this file's
        // formatting.
        const TEXT: &str = "\
@ IN SOA ns1. admin. 1 2 3 4 5
@ 3600 IN CDS 12345 8 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE1EE8F13B5F5D1D1D1D1D1D1D
@ 3600 IN CDNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3
@ 3600 IN CDS 0 0 0 00
";
        let (first, second, written) = round_trip(TEXT, "example.com.");
        assert!(written.contains("CDS     12345 8 2 49FD46E6"), "{written}");
        assert!(written.contains("CDNSKEY 257 3 8 "), "{written}");
        // RFC 8078 §4's "withdraw the DS": an operator is allowed to mean it,
        // and nothing here generates it.
        assert!(written.contains("CDS     0 0 0 00"), "{written}");
        assert!(
            !written.contains("TYPE59") && !written.contains("TYPE60"),
            "neither took RFC 3597's generic escape hatch: {written}"
        );

        let cds = |z: &Zone| {
            z.query(nm("example.com.").as_ref(), Qtype::of(rt::CDS))
                .len()
        };
        assert_eq!(cds(&first), 2);
        assert_eq!(cds(&second), 2);
        // And neither is a DS: the arm is shared, the type code is not.
        assert_eq!(
            first
                .query(nm("example.com.").as_ref(), Qtype::of(rt::DS))
                .len(),
            0
        );
    }

    /// Re-spelling a non-canonical bitmap by type name would re-encode it
    /// canonically and change the bytes a signature covers.
    #[test]
    fn test_a_non_canonical_bitmap_is_written_generically() {
        let mut zone = Zone::new(nm("example.com."));
        // Four bytes of bits where one would do: legal to read, not what
        // `build_type_bitmap` produces.
        let padded = RecordData::from_parsed(&ParsedRecord::NSEC {
            next_domain_name: nm("www.example.com."),
            type_bitmap: vec![0x00, 0x04, 0x40, 0x00, 0x00, 0x00],
        })
        .expect("encode");
        zone.add_record(ZoneRecord {
            name: nm("example.com."),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: padded.clone(),
        });

        let written = zone_to_string(&zone).expect("write");
        assert!(written.contains("NSEC    \\# "), "{written}");
        let reread = parse_zone_file(&written, "example.com.").expect("re-parse");
        assert_eq!(
            reread.query(nm("example.com.").as_ref(), Qtype::of(rt::NSEC))[0].rdata,
            padded,
            "the bytes are preserved exactly, padding and all"
        );
    }

    /// An owner name carrying an octet the syntax reserves. It used to stop the
    /// write, because presentation storage had no spelling for it; RFC 1035 §5.1
    /// escapes do, and the file reads back as the same zone (`TODO.md` D-1).
    #[test]
    fn an_owner_name_needing_escapes_round_trips() {
        for label in [b"has space".as_slice(), b"a.b", b"semi;colon", b"quo\"te"] {
            let name = Name::prefixed(label, nm("example.com.").as_ref()).expect("a name");
            let mut zone = Zone::new(nm("example.com."));
            zone.add_record(ZoneRecord {
                name: name.clone(),
                ttl: Ttl::from_secs(300),
                class: Class::new(1),
                rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.1".parse().unwrap()))
                    .expect("encode"),
            });

            let written = zone_to_string(&zone).expect("write");
            let reread = parse_zone_file(&written, "example.com.").expect("re-parse");
            assert_eq!(
                reread.query(name.as_ref(), Qtype::of(rt::A)).len(),
                1,
                "{name}: {written}"
            );
            assert_eq!(reread.records()[0].name, name);
        }
    }

    /// The same for a name inside RDATA, which used to fall back to the generic
    /// `\\#` form. It is spelled out now, and still means the same octets.
    #[test]
    fn an_rdata_name_needing_escapes_round_trips() {
        let target = Name::prefixed(b"has space", nm("example.com.").as_ref()).expect("a name");
        let ns = RecordData::from_parsed(&ParsedRecord::NS(target)).expect("encode");
        let mut zone = Zone::new(nm("example.com."));
        zone.add_record(ZoneRecord {
            name: nm("example.com."),
            ttl: Ttl::from_secs(300),
            class: Class::new(1),
            rdata: ns.clone(),
        });

        let written = zone_to_string(&zone).expect("write");
        assert!(
            !written.contains("\\# "),
            "spelled out, not generic: {written}"
        );
        let reread = parse_zone_file(&written, "example.com.").expect("re-parse");
        assert_eq!(
            reread.query(nm("example.com.").as_ref(), Qtype::of(rt::NS))[0].rdata,
            ns
        );
    }

    #[test]
    fn test_classes_other_than_in() {
        let mut zone = Zone::new(nm("example.com."));
        zone.add_record(ZoneRecord {
            name: nm("ch.example.com."),
            ttl: Ttl::from_secs(300),
            class: Class::new(3),
            rdata: RecordData::from_parsed(&ParsedRecord::TXT(vec![b"chaos".to_vec()]))
                .expect("encode"),
        });
        assert!(zone_to_string(&zone).expect("write").contains(" CH  "));

        let mut unknown = Zone::new(nm("example.com."));
        unknown.add_record(ZoneRecord {
            name: nm("x.example.com."),
            ttl: Ttl::from_secs(300),
            class: Class::new(42),
            rdata: RecordData::from_parsed(&ParsedRecord::TXT(vec![b"x".to_vec()]))
                .expect("encode"),
        });
        let err = zone_to_string(&unknown).unwrap_err();
        assert!(err.to_string().contains("unknown class 42"), "got: {err}");
    }

    #[test]
    fn test_written_zone_reaches_disk_whole() {
        let dir = ScratchDir::new("zone-writer");
        let path = dir.join("example.com.zone");

        let zone = parse_zone_file(
            "@ IN SOA ns1.example.com. admin.example.com. 7 3600 1800 604800 86400\nwww IN A 192.0.2.1\n",
            "example.com.",
        )
        .expect("parse");

        write_zone_file(&zone, &path).expect("write");
        let reloaded = crate::zone::parse_zone_file_at(&path, "example.com.").expect("reload");
        assert_eq!(reloaded.serial(), Some(Serial::new(7)));
        assert_eq!(
            reloaded
                .query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
    }
}
