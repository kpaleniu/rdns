//! The RR-type and QTYPE registry: the codes, and the names a zone file and a
//! query spell them with.
//!
//! Split out of `utils`, which is where a thing went when nobody decided where
//! it belonged (`TODO.md` #38c). The membership rule here is exact: a type or
//! class *code*, or a conversion between one and its presentation name.
//!
//! Not `codes`, which holds the newtypes themselves and seals their fields to
//! that one file (`CLAUDE.md` §17). This module is a caller of those, through
//! the same public constructors as anybody else.

use crate::{Qtype, Rtype};
use std::borrow::Cow;

pub const A: Rtype = Rtype::new(1);
pub const NS: Rtype = Rtype::new(2);
pub const CNAME: Rtype = Rtype::new(5);
pub const SOA: Rtype = Rtype::new(6);
pub const PTR: Rtype = Rtype::new(12);
pub const MX: Rtype = Rtype::new(15);
pub const TXT: Rtype = Rtype::new(16);
pub const AAAA: Rtype = Rtype::new(28);
/// Redirection for a whole subtree (RFC 6672 §2.1). Unlike a CNAME it
/// redirects names *below* its owner and not the owner itself.
pub const DNAME: Rtype = Rtype::new(39);
pub const DS: Rtype = Rtype::new(43);
/// Service binding: how to reach a service, not just where the name points
/// (RFC 9460 §2). [`HTTPS`] is the same format under another number.
pub const SVCB: Rtype = Rtype::new(64);
/// SVCB with HTTP semantics and no underscore-prefixed owner name
/// (RFC 9460 §9.1). "The same encoding, format, and high-level
/// semantics" (§6), so one parser serves both.
pub const HTTPS: Rtype = Rtype::new(65);
pub const RRSIG: Rtype = Rtype::new(46);
pub const NSEC: Rtype = Rtype::new(47);
pub const DNSKEY: Rtype = Rtype::new(48);
pub const NSEC3: Rtype = Rtype::new(50);
/// The salt and iteration count of a zone's NSEC3 chain (RFC 5155 §4). Held
/// as opaque RDATA, so there is no `ParsedRecord` arm for it.
pub const NSEC3PARAM: Rtype = Rtype::new(51);
/// A QTYPE only, and over TCP alone (RFC 5936).
pub const AXFR: Rtype = Rtype::new(252);
/// The raw codes, so `Rtype::is_meta` and `Qtype`'s constants can be `const`
/// without a second registry of numbers.
pub const AXFR_CODE: u16 = 252;
/// A QTYPE only (RFC 1995), and the one request carrying a record of its
/// own: the client's SOA, saying which version it already holds.
pub const IXFR: Rtype = Rtype::new(251);
pub const IXFR_CODE: u16 = 251;
/// A QTYPE only.
pub const ANY: Rtype = Rtype::new(255);
pub const ANY_CODE: u16 = 255;

/// A record type name as its numeric code. `TYPEnnn` is accepted for any type
/// at all (RFC 3597 §5).
///
/// # Examples
/// ```ignore
/// assert_eq!(record_type_name_to_code("A"), Some(1));
/// assert_eq!(record_type_name_to_code("MX"), Some(15));
/// assert_eq!(record_type_name_to_code("TYPE1234"), Some(Rtype::new(1234)));
/// assert_eq!(record_type_name_to_code("UNKNOWN"), None);
/// ```
pub fn record_type_name_to_code(kind: &str) -> Option<Rtype> {
    match kind {
        "A" => Some(A),
        "NS" => Some(NS),
        "CNAME" => Some(CNAME),
        "SOA" => Some(SOA),
        "PTR" => Some(PTR),
        "MX" => Some(MX),
        "TXT" => Some(TXT),
        "AAAA" => Some(AAAA),
        "DNAME" => Some(DNAME),
        "DS" => Some(DS),
        "SVCB" => Some(SVCB),
        "HTTPS" => Some(HTTPS),
        "DNSKEY" => Some(DNSKEY),
        "RRSIG" => Some(RRSIG),
        "NSEC" => Some(NSEC),
        "NSEC3" => Some(NSEC3),
        other => other
            .strip_prefix("TYPE")
            .or_else(|| other.strip_prefix("type"))
            .and_then(|n| n.parse::<u16>().ok())
            .map(Rtype::new),
    }
}

/// The QTYPE a presentation name asks for — the *question* space, which holds
/// values no record can have: ANY (`*` is the same question, RFC 1035 §3.2.3),
/// AXFR (RFC 5936) and IXFR (RFC 1995).
///
/// Separate from [`record_type_name_to_code`] rather than folded into it,
/// because that one answers with an `Rtype` and these three are not types any
/// record is. MAILB and MAILA are absent for the opposite reason to obscurity —
/// they are obsolete (RFC 1035 §3.2.3) — and `TYPE253` still reaches them.
pub fn qtype_name_to_code(name: &str) -> Option<Qtype> {
    match name {
        "ANY" | "*" => Some(Qtype::ANY),
        "AXFR" => Some(Qtype::AXFR),
        "IXFR" => Some(Qtype::IXFR),
        other => record_type_name_to_code(other).map(Qtype::of),
    }
}

/// The mnemonic for a QTYPE, or its `TYPEnnn` form. Always a name
/// [`qtype_name_to_code`] reads back.
///
/// [`record_type_name`] cannot answer this: it takes an `Rtype`, and printing
/// QTYPE 255 through it gives `TYPE255` for the question everyone writes `ANY`.
pub fn qtype_name(qtype: Qtype) -> Cow<'static, str> {
    match qtype {
        Qtype::ANY => Cow::Borrowed("ANY"),
        Qtype::AXFR => Cow::Borrowed("AXFR"),
        Qtype::IXFR => Cow::Borrowed("IXFR"),
        other => record_type_name(Rtype::new(other.to_u16())),
    }
}

/// The mnemonic for a type code, or its `TYPEnnn` form (RFC 3597 §5) when this
/// library has none. Always a name [`record_type_name_to_code`] reads back.
///
/// `Cow`, because sixteen of the answers are constants and only the last one
/// has to be built: writing a zone allocated a `String` per record to print a
/// name that was in the binary already (`TODO.md` #26h).
pub fn record_type_name(code: Rtype) -> Cow<'static, str> {
    let known = match code {
        A => "A",
        NS => "NS",
        CNAME => "CNAME",
        SOA => "SOA",
        PTR => "PTR",
        MX => "MX",
        TXT => "TXT",
        AAAA => "AAAA",
        DNAME => "DNAME",
        DS => "DS",
        SVCB => "SVCB",
        HTTPS => "HTTPS",
        DNSKEY => "DNSKEY",
        RRSIG => "RRSIG",
        NSEC => "NSEC",
        NSEC3 => "NSEC3",
        other => return Cow::Owned(format!("TYPE{}", other.to_u16())),
    };
    Cow::Borrowed(known)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rtype;

    /// A QTYPE is not an RTYPE: these three are questions no record answers to,
    /// so the record-type table says `None` for all of them (#33b).
    #[test]
    fn the_question_only_types_have_names_both_ways() {
        for (name, qtype) in [
            ("ANY", Qtype::ANY),
            ("AXFR", Qtype::AXFR),
            ("IXFR", Qtype::IXFR),
        ] {
            assert_eq!(qtype_name_to_code(name), Some(qtype));
            assert_eq!(qtype_name(qtype), name, "and prints back as it was asked");
            assert_eq!(
                record_type_name_to_code(name),
                None,
                "no record is of type {name}"
            );
        }
        assert_eq!(qtype_name_to_code("*"), Some(Qtype::ANY), "RFC 1035 §3.2.3");

        // Everything else is the record-type table, TYPEnnn included.
        assert_eq!(qtype_name_to_code("MX"), Some(Qtype::of(MX)));
        assert_eq!(qtype_name_to_code("TYPE1234"), Some(Qtype::from_u16(1234)));
        assert_eq!(qtype_name(Qtype::from_u16(1234)), "TYPE1234");
        assert_eq!(qtype_name_to_code("NOPE"), None);
    }

    #[test]
    fn test_record_type_name_to_code() {
        assert_eq!(record_type_name_to_code("A"), Some(A));
        assert_eq!(record_type_name_to_code("AAAA"), Some(AAAA));
        assert_eq!(record_type_name_to_code("MX"), Some(MX));
        assert_eq!(record_type_name_to_code("DNSKEY"), Some(DNSKEY));
        assert_eq!(record_type_name_to_code("UNKNOWN"), None);
    }

    /// RFC 3597 §5: any type at all can be named.
    #[test]
    fn test_generic_type_names_round_trip() {
        assert_eq!(record_type_name_to_code("TYPE1234"), Some(Rtype::new(1234)));
        assert_eq!(record_type_name_to_code("TYPE1"), Some(A));
        assert_eq!(record_type_name(Rtype::new(1234)), "TYPE1234");
        assert_eq!(record_type_name(A), "A");

        for code in [1u16, 15, 39, 50, 64, 65, 99, 257, 65535] {
            let name = record_type_name(Rtype::new(code));
            assert_eq!(
                record_type_name_to_code(&name),
                Some(Rtype::new(code)),
                "{name} should read back as {code}"
            );
        }
    }

    #[test]
    fn test_out_of_range_generic_type_name_is_rejected() {
        assert_eq!(record_type_name_to_code("TYPE65536"), None);
        assert_eq!(record_type_name_to_code("TYPE"), None);
        assert_eq!(record_type_name_to_code("TYPEA"), None);
    }

    /// The thirteen mnemonics are in the binary already; only `TYPEnnn` has to
    /// be built. Asserted on the `Cow` rather than on the text, because the
    /// text was right before and the allocation is what changed
    /// (`TODO.md` #26h).
    #[test]
    fn a_known_type_name_is_not_built() {
        for known in [A, NS, SOA, RRSIG, NSEC3] {
            assert!(
                matches!(record_type_name(known), Cow::Borrowed(_)),
                "{known} is a constant"
            );
        }
        assert!(matches!(record_type_name(Rtype::new(1234)), Cow::Owned(_)));
        assert_eq!(record_type_name(Rtype::new(1234)), "TYPE1234");
    }
}
