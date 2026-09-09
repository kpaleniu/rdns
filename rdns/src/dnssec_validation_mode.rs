//! Validate an RRset before it goes out, and set AD when it verifies
//! (RFC 4035 §3.2.3).
//!
//! The serving side, narrower than [`crate::dnssec_chain`]: a zone loaded from
//! disk has no chain to walk, only the question of whether the records match the
//! signatures beside them in the same file.

use crate::dnssec::{verify_rrset, Dnskey, Rrset, RrsetProof, Rrsig};
use crate::utils::{current_unix_timestamp, record_types};
use crate::zone::Zone;
use crate::{RecordData, ResourceRecord};

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

    /// Whether the zone has DNSKEY records.
    pub fn is_zone_signed(zone: &Zone) -> bool {
        zone.records()
            .iter()
            .any(|r| r.rdata.rtype() == record_types::DNSKEY)
    }

    /// Returns `(is_valid, is_signed)`: disabled is `(true, false)`, an unsigned
    /// zone `(!require_signed, false)`, a signed one `(verified, true)`.
    pub fn validate_response(
        &self,
        zone: &Zone,
        records: &[&crate::zone::ZoneRecord],
        _query_name: &str,
    ) -> (bool, bool) {
        if !self.enabled {
            return (true, false);
        }

        if !Self::is_zone_signed(zone) {
            return (!self.require_signed, false);
        }

        // An empty answer carries no RRset, but the zone is still signed.
        let Some(first) = records.first() else {
            return (true, true);
        };

        let keys: Vec<Dnskey> = zone
            .records()
            .iter()
            .filter(|r| r.rdata.rtype() == record_types::DNSKEY)
            .filter_map(|r| {
                Dnskey::from_record(&ResourceRecord {
                    name: r.name.clone(),
                    class: r.class,
                    ttl: r.ttl,
                    rdata: r.rdata.clone(),
                })
            })
            .collect();
        if keys.is_empty() {
            return (false, true); // A signed zone must have DNSKEYs.
        }

        // `verify_rrset` picks the ones covering this RRset by owner and type,
        // and rejects a signer outside the zone.
        let rrsigs: Vec<Rrsig> = zone
            .records()
            .iter()
            .filter(|r| r.rdata.rtype() == record_types::RRSIG)
            .filter_map(|r| {
                Rrsig::from_record(&ResourceRecord {
                    name: r.name.clone(),
                    class: r.class,
                    ttl: r.ttl,
                    rdata: r.rdata.clone(),
                })
            })
            .collect();

        let rdatas: Vec<RecordData> = records.iter().map(|r| r.rdata.clone()).collect();
        let proof = verify_rrset(
            &Rrset::new(
                first.name.as_ref(),
                first.rdata.rtype(),
                first.class,
                &rdatas,
            ),
            &rrsigs,
            &keys,
            zone.origin(),
            current_unix_timestamp(),
        );

        match proof {
            RrsetProof::Verified { .. } => (true, true),
            // An unsigned RRset in a signed zone is a broken zone; AD would be
            // a lie either way.
            RrsetProof::Unsigned | RrsetProof::Bogus(_) | RrsetProof::Unsupported(_) => {
                (false, true)
            }
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
    use crate::Ttl;
    use std::net::Ipv4Addr;

    /// An unsigned zone is valid and unsigned, and the AD bit says so.
    ///
    /// Lived in `lib.rs`'s tests until the crate split, where it was the one
    /// case in the codec's own suite that needed a zone and a validator
    /// (`TODO.md` #31).
    #[test]
    fn test_dnssec_validator_integration() {
        let validator = DnssecValidator::new(true);
        let zone = crate::zone::Zone::new(nm(&nm("example.com.").to_string()));
        let records = vec![];

        let (is_valid, is_signed) = validator.validate_response(&zone, &records, "example.com.");

        assert!(is_valid);
        assert!(!is_signed);
    }

    #[test]
    fn test_validator_new() {
        let validator = DnssecValidator::new(true);
        assert!(validator.is_enabled());

        let validator = DnssecValidator::new(false);
        assert!(!validator.is_enabled());
    }

    #[test]
    fn test_validator_disabled_returns_not_signed() {
        let validator = DnssecValidator::new(false);
        let zone = Zone::new(nm(&nm("example.com.").to_string()));
        let records = vec![];

        let (is_valid, is_signed) = validator.validate_response(&zone, &records, "example.com.");

        assert!(is_valid);
        assert!(!is_signed);
    }

    #[test]
    fn test_validator_unsigned_zone() {
        let validator = DnssecValidator::new(true);
        let zone = Zone::new(nm(&nm("example.com.").to_string()));
        let records = vec![];

        let (is_valid, is_signed) = validator.validate_response(&zone, &records, "example.com.");

        assert!(is_valid);
        assert!(!is_signed);
    }

    #[test]
    fn test_is_zone_signed_false() {
        let mut zone = Zone::new(nm(&nm("example.com.").to_string()));
        zone.add_record(ZoneRecord {
            name: nm(&nm("example.com.").to_string()),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });

        assert!(!DnssecValidator::is_zone_signed(&zone));
    }

    #[test]
    fn test_is_zone_signed_true() {
        let mut zone = Zone::new(nm(&nm("example.com.").to_string()));
        zone.add_record(ZoneRecord {
            name: nm(&nm("example.com.").to_string()),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::DNSKEY {
                flags: 256,
                protocol: 3,
                algorithm: 8,
                public_key: vec![1, 2, 3, 4],
            })
            .unwrap(),
        });

        assert!(DnssecValidator::is_zone_signed(&zone));
    }
}
