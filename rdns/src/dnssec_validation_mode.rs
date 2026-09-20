//! Validate an RRset before it goes out, and set AD when it verifies
//! (RFC 4035 §3.2.3).
//!
//! The serving side, narrower than [`crate::dnssec_chain`]: a zone loaded from
//! disk has no chain to walk, only the question of whether the records match the
//! signatures beside them in the same file.

use crate::clock::current_unix_timestamp;
use crate::dnssec::{verify_rrset, Dnskey, Rrset, RrsetProof, Rrsig};
use crate::record_types;
use crate::zone::{Zone, ZoneRecordRef};
use crate::{Qtype, RecordDataRef, ResourceRecord};

/// The keys every RRset in one zone is checked against, collected once.
///
/// A type because collecting them is O(the zone) and checking one RRset is not,
/// and the check used to do both on every call —
/// which made verifying a zone at load quadratic in the zone
/// (`TODO.md` #50: 20,006 RRsets took 112 s where 5,006 took 7). A parameter
/// makes the zone-wide cost visible at the call site, where it can be hoisted;
/// as a hidden step inside the check it could only be paid again
/// (`CLAUDE.md` §17).
pub struct ZoneKeys {
    /// Whether the zone holds a DNSKEY record at all, which is what "is this
    /// zone signed" means. Separate from `keys` being non-empty: a zone whose
    /// only DNSKEY does not parse is signed *and* broken, and answering
    /// "unsigned" for it would let `require_signed` pass it.
    signed: bool,
    keys: Vec<Dnskey>,
}

impl ZoneKeys {
    /// Every DNSKEY in `zone`, parsed.
    ///
    /// One pass over the records, which is the cost this type exists to charge
    /// once.
    pub fn of(zone: &Zone) -> Self {
        let mut signed = false;
        let keys = zone
            .records()
            .iter()
            .filter(|r| r.rdata.rtype() == record_types::DNSKEY)
            .inspect(|_| signed = true)
            .filter_map(|r| {
                Dnskey::from_record(&ResourceRecord {
                    name: r.name.to_owned(),
                    class: r.class,
                    ttl: r.ttl,
                    rdata: r.rdata.to_owned(),
                })
            })
            .collect();
        ZoneKeys { signed, keys }
    }

    /// Whether the zone carries DNSKEY records.
    pub fn is_signed(&self) -> bool {
        self.signed
    }
}

/// What checking one RRset concluded.
///
/// Three variants where there were two bools. `(is_valid, is_signed)` was
/// documented in prose and nowhere in the type, all four call sites discarded
/// the second element, and the file held seven bare tuple literals
/// (`TODO.md` #80). The signedness was redundant by construction: a caller
/// holds the [`ZoneKeys`] that answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing was checked: validation is off, or the zone carries no DNSKEY
    /// and unsigned zones are allowed.
    Unchecked,
    /// It verifies against the zone's own keys — or the zone is signed and
    /// there was no RRset to check.
    Valid,
    /// Why, in the sentence an operator reads. Typed as the category and prose
    /// as the reason (`CLAUDE.md` §3): the caller branches on the variant, and
    /// "does not verify" is an expiry, a missing signature, an unreadable
    /// algorithm or a zone with no usable key — four different mornings.
    Invalid(String),
}

impl Verdict {
    /// Whether the RRset may be served. `Unchecked` may: it is the answer for
    /// a validator that is off and for an unsigned zone that is allowed to be.
    pub fn is_valid(&self) -> bool {
        !matches!(self, Verdict::Invalid(_))
    }
}

pub struct DnssecValidator {
    enabled: bool,
    /// Whether an *unsigned* zone counts as a failure.
    ///
    /// Off by default: a server may hold a mix, so "not signed" must not read as
    /// "not valid". On, it is the operator asserting every zone here is meant to
    /// be signed — a zone that loses its signatures otherwise keeps answering as
    /// though nothing happened.
    require_signed: bool,
}

impl DnssecValidator {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            require_signed: false,
        }
    }

    /// Treat an unsigned zone as a validation failure. See `Self::require_signed`.
    pub fn set_require_signed(&mut self, require: bool) {
        self.require_signed = require;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// One RRset, against keys already collected.
    ///
    /// The signatures come from the zone's own owner index rather than from a
    /// scan: an RRSIG is stored at the name it covers, so "which signatures
    /// could cover this" is a lookup. It was a walk of every record in the
    /// zone, per RRset, which is the other half of #50 — and the half a hoist
    /// alone would not have fixed, because `verify_rrset` filters whatever
    /// slice it is handed.
    pub fn validate_rrset(
        &self,
        zone: &Zone,
        keys: &ZoneKeys,
        records: &[ZoneRecordRef<'_>],
    ) -> Verdict {
        if !self.enabled {
            return Verdict::Unchecked;
        }

        if !keys.is_signed() {
            return if self.require_signed {
                Verdict::Invalid("the zone carries no DNSKEY".to_string())
            } else {
                Verdict::Unchecked
            };
        }

        // An empty answer carries no RRset, but the zone is still signed.
        let Some(first) = records.first() else {
            return Verdict::Valid;
        };

        if keys.keys.is_empty() {
            return Verdict::Invalid(
                "the zone has DNSKEY records and not one of them parses".to_string(),
            );
        }

        // `verify_rrset` picks the ones covering this RRset by owner and type,
        // and rejects a signer outside the zone.
        let owner = first.name;
        let rrsigs: Vec<Rrsig> = zone
            .query(owner, Qtype::of(record_types::RRSIG))
            .into_iter()
            .filter_map(|r| {
                Rrsig::from_record(&ResourceRecord {
                    name: r.name.to_owned(),
                    class: r.class,
                    ttl: r.ttl,
                    rdata: r.rdata.to_owned(),
                })
            })
            .collect();

        // Borrowed, not copied: the RRset is the zone's own arena (`TODO.md`
        // #71e), and `Rrset` is generic over what holds one record's RDATA.
        let rdatas: Vec<RecordDataRef<'_>> = records.iter().map(|r| r.rdata).collect();
        let proof = verify_rrset(
            &Rrset::new(owner, first.rdata.rtype(), first.class, &rdatas),
            &rrsigs,
            &keys.keys,
            zone.origin(),
            current_unix_timestamp(),
        );

        match proof {
            RrsetProof::Verified { .. } => Verdict::Valid,
            // An unsigned RRset in a signed zone is a broken zone; AD would be
            // a lie either way. The three say different things to an operator,
            // which is the whole reason the verdict carries one.
            RrsetProof::Unsigned => {
                Verdict::Invalid("no signature covers it, in a signed zone".to_string())
            }
            RrsetProof::Bogus(why) => Verdict::Invalid(why.why),
            RrsetProof::Unsupported(what) => Verdict::Invalid(format!(
                "every signature over it uses something we cannot read: {what}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_records::nm;
    use crate::zone::ZoneRecord;
    use crate::Class;
    use crate::ParsedRecord;
    use crate::RecordData;
    use crate::Ttl;
    use std::net::Ipv4Addr;

    /// An unsigned zone is nothing to check, and may be served.
    ///
    /// Lived in `lib.rs`'s tests until the crate split, where it was the one
    /// case in the codec's own suite that needed a zone and a validator
    /// (`TODO.md` #31).
    #[test]
    fn an_unsigned_zone_is_unchecked_rather_than_invalid() {
        let validator = DnssecValidator::new(true);
        let zone = crate::zone::Zone::new(nm(&nm("example.com.").to_string()));

        let verdict = validator.validate_rrset(&zone, &ZoneKeys::of(&zone), &[]);

        assert_eq!(verdict, Verdict::Unchecked);
        assert!(verdict.is_valid());
    }

    /// The same zone under `--require-signd`: the operator asserted every zone
    /// here is signed, so one that is not is a failure with a reason.
    #[test]
    fn an_unsigned_zone_is_invalid_when_signing_is_required() {
        let mut validator = DnssecValidator::new(true);
        validator.set_require_signed(true);
        let zone = crate::zone::Zone::new(nm(&nm("example.com.").to_string()));

        let verdict = validator.validate_rrset(&zone, &ZoneKeys::of(&zone), &[]);

        assert!(!verdict.is_valid());
        assert_eq!(
            verdict,
            Verdict::Invalid("the zone carries no DNSKEY".to_string())
        );
    }

    #[test]
    fn test_validator_new() {
        let validator = DnssecValidator::new(true);
        assert!(validator.is_enabled());

        let validator = DnssecValidator::new(false);
        assert!(!validator.is_enabled());
    }

    #[test]
    fn a_disabled_validator_checks_nothing() {
        let validator = DnssecValidator::new(false);
        let zone = Zone::new(nm(&nm("example.com.").to_string()));

        assert_eq!(
            validator.validate_rrset(&zone, &ZoneKeys::of(&zone), &[]),
            Verdict::Unchecked
        );
    }

    /// `ZoneKeys` is what answers "is this zone signed", and it is the answer
    /// the bool used to duplicate.
    #[test]
    fn zone_keys_reads_the_dnskeys_a_zone_has() {
        let mut zone = Zone::new(nm(&nm("example.com.").to_string()));
        zone.add_record(ZoneRecord {
            name: nm(&nm("example.com.").to_string()),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });
        assert!(!ZoneKeys::of(&zone).is_signed());

        zone.add_record(ZoneRecord {
            name: nm(&nm("example.com.").to_string()),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::DNSKEY {
                rtype: rdns_core::record_types::DNSKEY,
                flags: 256,
                protocol: 3,
                algorithm: 8,
                public_key: vec![1, 2, 3, 4],
            })
            .unwrap(),
        });
        assert!(ZoneKeys::of(&zone).is_signed());
    }

    /// A signed zone with an RRset nothing signed is invalid, and the verdict
    /// says which of the three ways it failed.
    ///
    /// This is what `--require-signd` and `verify_zones` exist to catch: a
    /// zone that lost its signatures answers exactly as it did before.
    #[test]
    fn an_unsigned_rrset_in_a_signed_zone_says_so() {
        let validator = DnssecValidator::new(true);
        let mut zone = Zone::new(nm(&nm("example.com.").to_string()));
        zone.add_record(ZoneRecord {
            name: nm(&nm("example.com.").to_string()),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::DNSKEY {
                rtype: rdns_core::record_types::DNSKEY,
                flags: 256,
                protocol: 3,
                algorithm: 8,
                public_key: vec![1, 2, 3, 4],
            })
            .unwrap(),
        });
        zone.add_record(ZoneRecord {
            name: nm(&nm("www.example.com.").to_string()),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });
        let keys = ZoneKeys::of(&zone);
        let records = zone.query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A));

        let verdict = validator.validate_rrset(&zone, &keys, &records);

        assert_eq!(
            verdict,
            Verdict::Invalid("no signature covers it, in a signed zone".to_string()),
            "the reason is the point, not the failure"
        );
    }
}
