//! DNSSEC Validation for Query-Response Mode
//!
//! This module provides query-response level DNSSEC validation integration,
//! allowing authoritative-only DNS servers to validate RRsets before responding
//! and set the Authenticated Data (AD) bit when validation succeeds.
//!
//! Architecture:
//! - Authoritative-only (not recursive validation)
//! - When enabled, validates RRsets before responding
//! - Sets AD bit in DNS message header if validation succeeds
//! - Follows RFC 4035 § 3.2.3 guidance for recursive servers
//!
//! This is the *serving* side and is deliberately narrower than
//! [`crate::dnssec_chain`], which is what a resolver uses: there is no chain to
//! walk when the zone is loaded from disk, only the question of whether the
//! records about to go out match the signatures sitting beside them in the same
//! file.

use crate::dnssec::{verify_rrset, Dnskey, Rrset, RrsetProof, Rrsig};
use crate::utils::{current_unix_timestamp, record_types};
use crate::zone::Zone;
use crate::{RecordData, ResourceRecord};

/// DNSSEC validator for query-response mode
///
/// Validates RRsets in responses before sending, setting the AD bit
/// when validation succeeds.
pub struct DnssecValidator {
    /// Whether DNSSEC validation is enabled
    enabled: bool,
    /// Whether an *unsigned* zone counts as a failure.
    ///
    /// Off by default, which is the only sane default for a server that may
    /// hold a mix of signed and unsigned zones: most zones are unsigned and
    /// serving them is the normal case, so "not signed" must not read as "not
    /// valid". Turning it on means "every zone I serve is meant to be signed" —
    /// an operator assertion, and a useful one, because a zone that silently
    /// loses its signatures (an expired resigning cron, a bad reload) otherwise
    /// keeps answering as though nothing happened.
    require_signed: bool,
}

impl DnssecValidator {
    /// Create a new DNSSEC validator
    ///
    /// # Arguments
    /// * `enabled` - Whether to enable DNSSEC validation
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            require_signed: false,
        }
    }

    /// Treat an unsigned zone as a validation failure. See [`Self::require_signed`].
    pub fn set_require_signed(&mut self, require: bool) {
        self.require_signed = require;
    }

    /// Check if DNSSEC validation is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Check if a zone is signed (has DNSKEY records)
    pub fn is_zone_signed(zone: &Zone) -> bool {
        zone.records()
            .iter()
            .any(|r| r.rdata.rtype == record_types::DNSKEY)
    }

    /// Validate records in a response before sending
    ///
    /// This checks if the zone has valid DNSSEC signatures for the records
    /// being returned.
    ///
    /// # Returns
    /// A tuple (is_valid, is_signed):
    /// - If validation disabled: (true, false)
    /// - If the zone is unsigned: (!require_signed, false)
    /// - If the zone is signed: (validation_result, true)
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
            // Unsigned. Normal unless the operator has said every zone here is
            // meant to be signed, in which case the absence of signatures is
            // itself the finding.
            return (!self.require_signed, false);
        }

        // Nothing to check — an empty answer carries no RRset. The zone is
        // still signed, so say so.
        let Some(first) = records.first() else {
            return (true, true);
        };

        let keys: Vec<Dnskey> = zone
            .records()
            .iter()
            .filter(|r| r.rdata.rtype == record_types::DNSKEY)
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

        // Every RRSIG in the zone; `verify_rrset` picks the ones that cover
        // this RRset by owner and type, and rejects a signer outside the zone.
        let rrsigs: Vec<Rrsig> = zone
            .records()
            .iter()
            .filter(|r| r.rdata.rtype == record_types::RRSIG)
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
            &Rrset::new(&first.name, first.rdata.rtype, first.class, &rdatas),
            &rrsigs,
            &keys,
            zone.origin(),
            current_unix_timestamp(),
        );

        match proof {
            RrsetProof::Verified { .. } => (true, true),
            // A signed zone with an unsigned RRset in it is a broken zone, and
            // the AD bit would be a lie either way.
            RrsetProof::Unsigned | RrsetProof::Bogus(_) | RrsetProof::Unsupported(_) => {
                (false, true)
            }
        }
    }

    /// Check if response should have AD bit set
    ///
    /// The AD bit should be set if:
    /// 1. Validation is enabled
    /// 2. The records are signed (is_signed = true)
    /// 3. Validation succeeded (is_valid = true)
    pub fn should_set_ad_bit(&self, is_valid: bool, is_signed: bool) -> bool {
        is_valid && is_signed && self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::ZoneRecord;
    use crate::Class;
    use crate::ParsedRecord;
    use crate::Ttl;
    use std::net::Ipv4Addr;

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
        let zone = Zone::new("example.com.".to_string());
        let records = vec![];

        let (is_valid, is_signed) = validator.validate_response(&zone, &records, "example.com.");

        assert!(is_valid);
        assert!(!is_signed);
    }

    #[test]
    fn test_validator_unsigned_zone() {
        let validator = DnssecValidator::new(true);
        let zone = Zone::new("example.com.".to_string());
        let records = vec![];

        let (is_valid, is_signed) = validator.validate_response(&zone, &records, "example.com.");

        assert!(is_valid);
        assert!(!is_signed);
    }

    #[test]
    fn test_is_zone_signed_false() {
        let mut zone = Zone::new("example.com.".to_string());
        zone.add_record(ZoneRecord {
            name: "example.com.".to_string(),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });

        assert!(!DnssecValidator::is_zone_signed(&zone));
    }

    #[test]
    fn test_is_zone_signed_true() {
        let mut zone = Zone::new("example.com.".to_string());
        zone.add_record(ZoneRecord {
            name: "example.com.".to_string(),
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

    #[test]
    fn test_should_set_ad_bit_all_conditions_met() {
        let validator = DnssecValidator::new(true);
        assert!(validator.should_set_ad_bit(true, true));
    }

    #[test]
    fn test_should_set_ad_bit_validation_failed() {
        let validator = DnssecValidator::new(true);
        assert!(!validator.should_set_ad_bit(false, true));
    }

    #[test]
    fn test_should_set_ad_bit_not_signed() {
        let validator = DnssecValidator::new(true);
        assert!(!validator.should_set_ad_bit(true, false));
    }

    #[test]
    fn test_should_set_ad_bit_validation_disabled() {
        let validator = DnssecValidator::new(false);
        assert!(!validator.should_set_ad_bit(true, true));
    }
}
