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
//! - Silently skips validation if it fails (doesn't reject) or zone is unsigned
//! - Follows RFC 4035 § 3.2.3 guidance for recursive servers

use crate::zone::Zone;
use crate::{ParsedRecord, RecordData};
use crate::utils::record_types;

/// DNSSEC validator for query-response mode
///
/// Validates RRsets in responses before sending, setting the AD bit
/// when validation succeeds.
pub struct DnssecValidator {
    /// Whether DNSSEC validation is enabled
    enabled: bool,
    /// Whether to validate unsigned zones (if false, unsigned = valid)
    validate_unsigned: bool,
}

impl DnssecValidator {
    /// Create a new DNSSEC validator
    ///
    /// # Arguments
    /// * `enabled` - Whether to enable DNSSEC validation
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            validate_unsigned: false,
        }
    }

    /// Enable or disable validation of unsigned zones
    pub fn set_validate_unsigned(&mut self, validate: bool) {
        self.validate_unsigned = validate;
    }

    /// Check if DNSSEC validation is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Check if a zone is signed (has DNSKEY records)
    pub fn is_zone_signed(zone: &Zone) -> bool {
        zone.records.iter().any(|r| r.rdata.rtype == record_types::DNSKEY)
    }

    /// Validate records in a response before sending
    ///
    /// This checks if the zone has valid DNSSEC signatures for the records
    /// being returned.
    ///
    /// # Returns
    /// A tuple (is_valid, is_signed):
    /// - If validation disabled: (true, false)
    /// - If zone is unsigned: (true, false)
    /// - If zone is signed: (validation_result, true)
    pub fn validate_response(
        &self,
        zone: &Zone,
        records: &[&crate::zone::ZoneRecord],
        query_name: &str,
    ) -> (bool, bool) {
        // If validation is disabled, return success but not signed
        if !self.enabled {
            return (true, false);
        }

        // Check if zone is signed
        let is_signed = Self::is_zone_signed(zone);

        if !is_signed {
            // Unsigned zone: return success, not signed
            if self.validate_unsigned {
                (true, false)
            } else {
                (true, false)
            }
        } else {
            // If records is empty, we can't validate signatures on them
            if records.is_empty() {
                return (true, true);
            }

            // Get the type and class of the records (they should all be the same)
            let rtype = crate::utils::record_type_code(&records[0].rdata);
            let class = records[0].class;
            let ttl = records[0].ttl as u32;

            // Find DNSKEY records in the zone to use as trusted keys
            let dnskeys: Vec<ParsedRecord> = zone.records.iter()
                .filter(|r| r.rdata.rtype == record_types::DNSKEY)
                .filter_map(|r| r.rdata.parse().ok())
                .collect();

            if dnskeys.is_empty() {
                return (false, true); // Signed zone must have DNSKEYs
            }

            // Find RRSIG records in the zone that cover this rtype and query_name
            let rrsigs: Vec<ParsedRecord> = zone.records.iter()
                .filter(|r| {
                    r.rdata.rtype == record_types::RRSIG
                        && zone.matches_query(&r.name, query_name)
                })
                .filter_map(|r| r.rdata.parse().ok())
                .filter(|sig| {
                    matches!(sig, ParsedRecord::RRSIG { type_covered, .. } if *type_covered == rtype)
                })
                .collect();

            if rrsigs.is_empty() {
                return (false, true); // Signed zone must have RRSIG for the RRset
            }

            // Construct DnssecValidator from dnssec.rs
            let crypto_validator = crate::dnssec::DnssecValidator::new(dnskeys);

            // Serialize the RRset in canonical form
            let records_data: Vec<RecordData> = records.iter().map(|r| r.rdata.clone()).collect();
            let serialized_rrset = match crate::dnssec::serialize_rrset_from_record_data(
                &records[0].name,
                rtype,
                class,
                ttl,
                &records_data,
            ) {
                Ok(bytes) => bytes,
                Err(_) => return (false, true),
            };

            // Validate each RRSIG signature
            for rrsig in &rrsigs {
                // Also validate wildcard expansion if applicable
                if let Ok(false) = crate::dnssec::validate_wildcard(query_name, &records[0].name, rrsig) {
                    continue;
                }
                
                if let Ok(true) = crypto_validator.validate_signature(&serialized_rrset, rrsig) {
                    // Valid signature found!
                    return (true, true);
                }
            }

            // No valid signature found
            (false, true)
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
            ttl: 3600,
            class: 1,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });

        assert!(!DnssecValidator::is_zone_signed(&zone));
    }

    #[test]
    fn test_is_zone_signed_true() {
        let mut zone = Zone::new("example.com.".to_string());
        zone.add_record(ZoneRecord {
            name: "example.com.".to_string(),
            ttl: 3600,
            class: 1,
            rdata: RecordData::from_parsed(&ParsedRecord::DNSKEY {
                flags: 256,
                protocol: 3,
                algorithm: 8,
                public_key: vec![1, 2, 3, 4],
            }).unwrap(),
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
