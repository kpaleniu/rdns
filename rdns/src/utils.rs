//! Shared utility functions for RDNSC
//! 
//! This module contains common functions that are used across multiple modules
//! to eliminate code duplication and provide a consistent interface for:
//! - Domain name normalization
//! - Unix timestamp retrieval
//! - Expiration checking
//! - Record type constants and conversion

use crate::{ParsedRecord, RecordData};
use std::time::{SystemTime, UNIX_EPOCH};

/// DNS record type constants
pub mod record_types {
    /// A record (IPv4 address)
    pub const A: u16 = 1;
    /// NS record (nameserver)
    pub const NS: u16 = 2;
    /// CNAME record (canonical name)
    pub const CNAME: u16 = 5;
    /// SOA record (start of authority)
    pub const SOA: u16 = 6;
    /// PTR record (pointer)
    pub const PTR: u16 = 12;
    /// MX record (mail exchange)
    pub const MX: u16 = 15;
    /// TXT record (text)
    pub const TXT: u16 = 16;
    /// AAAA record (IPv6 address)
    pub const AAAA: u16 = 28;
    /// DS record (delegation signer)
    pub const DS: u16 = 43;
    /// RRSIG record (DNSSEC signature)
    pub const RRSIG: u16 = 46;
    /// NSEC record (next secure)
    pub const NSEC: u16 = 47;
    /// DNSKEY record (DNSSEC key)
    pub const DNSKEY: u16 = 48;
    /// NSEC3 record (next secure v3)
    pub const NSEC3: u16 = 50;
}

/// Normalize a domain name to lowercase and remove trailing dot
///
/// # Examples
/// ```ignore
/// assert_eq!(normalize_domain_name("EXAMPLE.COM."), "example.com");
/// assert_eq!(normalize_domain_name("Example.com"), "example.com");
/// ```
pub fn normalize_domain_name(name: &str) -> String {
    name.to_lowercase().trim_end_matches('.').to_string()
}

/// Compare two domain names for equality after normalization
///
/// # Examples
/// ```ignore
/// assert!(normalize_domain_name_for_comparison("EXAMPLE.COM.", "example.com"));
/// assert!(normalize_domain_name_for_comparison("Example.Com", "EXAMPLE.COM."));
/// ```
pub fn normalize_domain_name_for_comparison(a: &str, b: &str) -> bool {
    normalize_domain_name(a) == normalize_domain_name(b)
}

/// Get the current Unix timestamp in seconds
///
/// Returns 0 if the system time is before UNIX_EPOCH (unlikely in practice)
///
/// # Examples
/// ```ignore
/// let now = current_unix_timestamp();
/// assert!(now > 0);
/// ```
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Check if a time range (inception to expiration) has expired
///
/// Returns true if the current time is outside the valid range:
/// - Current time < inception (not yet valid)
/// - Current time > expiration (expired)
///
/// # Examples
/// ```ignore
/// let now = current_unix_timestamp() as u32;
/// assert!(is_time_expired(now + 3600, now)); // Future inception
/// assert!(is_time_expired(now - 7200, now - 3600)); // Expired
/// ```
pub fn is_time_expired(inception: u32, expiration: u32) -> bool {
    let now = current_unix_timestamp();
    now < (inception as u64) || now > (expiration as u64)
}

/// Check if a cache entry has expired
///
/// # Examples
/// ```ignore
/// let now = current_unix_timestamp();
/// assert!(!is_cache_expired(now + 3600)); // Valid for 1 hour
/// assert!(is_cache_expired(now - 1)); // Already expired
/// ```
pub fn is_cache_expired(expires_at: u64) -> bool {
    current_unix_timestamp() >= expires_at
}

/// Extract fields from a DNSKEY record
///
/// Returns a tuple of (algorithm, public_key, flags, protocol)
///
/// # Errors
/// Returns an error if the record is not a DNSKEY record
pub fn extract_dnskey_fields(
    key: &ParsedRecord,
) -> Result<(u8, Vec<u8>, u16, u8), anyhow::Error> {
    match key {
        ParsedRecord::DNSKEY {
            algorithm,
            public_key,
            flags,
            protocol,
        } => Ok((*algorithm, public_key.clone(), *flags, *protocol)),
        _ => Err(anyhow::anyhow!("Not a DNSKEY record")),
    }
}

/// Get the record type code from a stored record.
///
/// The type code is carried directly on [`RecordData`], so this is just an
/// accessor kept for call-site compatibility.
pub fn record_type_code(rdata: &RecordData) -> u16 {
    rdata.rtype
}

/// Convert record type name to its numeric code
///
/// # Examples
/// ```ignore
/// assert_eq!(record_type_name_to_code("A"), Some(1));
/// assert_eq!(record_type_name_to_code("MX"), Some(15));
/// assert_eq!(record_type_name_to_code("UNKNOWN"), None);
/// ```
pub fn record_type_name_to_code(kind: &str) -> Option<u16> {
    match kind {
        "A" => Some(record_types::A),
        "NS" => Some(record_types::NS),
        "CNAME" => Some(record_types::CNAME),
        "SOA" => Some(record_types::SOA),
        "PTR" => Some(record_types::PTR),
        "MX" => Some(record_types::MX),
        "TXT" => Some(record_types::TXT),
        "AAAA" => Some(record_types::AAAA),
        "DS" => Some(record_types::DS),
        "DNSKEY" => Some(record_types::DNSKEY),
        "RRSIG" => Some(record_types::RRSIG),
        "NSEC" => Some(record_types::NSEC),
        "NSEC3" => Some(record_types::NSEC3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain_name_lowercase() {
        assert_eq!(normalize_domain_name("EXAMPLE.COM."), "example.com");
        assert_eq!(normalize_domain_name("Example.Com"), "example.com");
    }

    #[test]
    fn test_normalize_domain_name_trailing_dot() {
        assert_eq!(normalize_domain_name("example.com."), "example.com");
        assert_eq!(normalize_domain_name("example.com"), "example.com");
    }

    #[test]
    fn test_normalize_domain_name_for_comparison() {
        assert!(normalize_domain_name_for_comparison(
            "EXAMPLE.COM.",
            "example.com"
        ));
        assert!(normalize_domain_name_for_comparison(
            "Example.Com",
            "EXAMPLE.COM."
        ));
        assert!(!normalize_domain_name_for_comparison(
            "example.com.",
            "other.com."
        ));
    }

    #[test]
    fn test_current_unix_timestamp() {
        let ts = current_unix_timestamp();
        assert!(ts > 0);
        
        let ts2 = current_unix_timestamp();
        assert!(ts2 >= ts);
    }

    #[test]
    fn test_is_time_expired_not_yet_valid() {
        let now = current_unix_timestamp() as u32;
        let inception = now + 3600; // 1 hour in future
        let expiration = now + 7200; // 2 hours in future
        
        assert!(is_time_expired(inception, expiration));
    }

    #[test]
    fn test_is_time_expired_already_expired() {
        let now = current_unix_timestamp() as u32;
        let inception = now - 7200; // 2 hours ago
        let expiration = now - 3600; // 1 hour ago
        
        assert!(is_time_expired(inception, expiration));
    }

    #[test]
    fn test_is_time_not_expired() {
        let now = current_unix_timestamp() as u32;
        let inception = now - 3600; // 1 hour ago
        let expiration = now + 3600; // 1 hour in future
        
        assert!(!is_time_expired(inception, expiration));
    }

    #[test]
    fn test_is_cache_expired_valid() {
        let now = current_unix_timestamp();
        let expires_at = now + 3600; // 1 hour from now
        
        assert!(!is_cache_expired(expires_at));
    }

    #[test]
    fn test_is_cache_expired_expired() {
        let now = current_unix_timestamp();
        let expires_at = now - 1; // Already expired
        
        assert!(is_cache_expired(expires_at));
    }

    #[test]
    fn test_extract_dnskey_fields() {
        let key = ParsedRecord::DNSKEY {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3, 4],
        };

        let result = extract_dnskey_fields(&key).expect("extract failed");
        assert_eq!(result.0, 8); // algorithm
        assert_eq!(result.1, vec![1, 2, 3, 4]); // public_key
        assert_eq!(result.2, 0x0100); // flags
        assert_eq!(result.3, 3); // protocol
    }

    #[test]
    fn test_extract_dnskey_fields_not_dnskey() {
        let record = ParsedRecord::DS {
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: vec![1, 2, 3],
        };

        let result = extract_dnskey_fields(&record);
        assert!(result.is_err());
    }

    #[test]
    fn test_record_type_code_standard() {
        use std::net::Ipv4Addr;
        
        let a_record = RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap();
        assert_eq!(record_type_code(&a_record), record_types::A);

        let aaaa_record = RecordData::from_parsed(&ParsedRecord::AAAA("::1".parse().unwrap())).unwrap();
        assert_eq!(record_type_code(&aaaa_record), record_types::AAAA);
    }

    #[test]
    fn test_record_type_code_dnssec() {
        let dnskey = RecordData::from_parsed(&ParsedRecord::DNSKEY {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3],
        }).unwrap();
        assert_eq!(record_type_code(&dnskey), record_types::DNSKEY);

        let ds = RecordData::from_parsed(&ParsedRecord::DS {
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: vec![1, 2, 3],
        }).unwrap();
        assert_eq!(record_type_code(&ds), record_types::DS);
    }

    #[test]
    fn test_record_type_code_unknown() {
        let unknown = RecordData::from_parsed(&ParsedRecord::Unknown(99)).unwrap();
        assert_eq!(record_type_code(&unknown), 99);
    }

    #[test]
    fn test_record_type_name_to_code() {
        assert_eq!(record_type_name_to_code("A"), Some(record_types::A));
        assert_eq!(record_type_name_to_code("AAAA"), Some(record_types::AAAA));
        assert_eq!(record_type_name_to_code("MX"), Some(record_types::MX));
        assert_eq!(record_type_name_to_code("DNSKEY"), Some(record_types::DNSKEY));
        assert_eq!(record_type_name_to_code("UNKNOWN"), None);
    }

    #[test]
    fn test_record_types_constants() {
        assert_eq!(record_types::A, 1);
        assert_eq!(record_types::NS, 2);
        assert_eq!(record_types::CNAME, 5);
        assert_eq!(record_types::SOA, 6);
        assert_eq!(record_types::PTR, 12);
        assert_eq!(record_types::MX, 15);
        assert_eq!(record_types::TXT, 16);
        assert_eq!(record_types::AAAA, 28);
        assert_eq!(record_types::DS, 43);
        assert_eq!(record_types::RRSIG, 46);
        assert_eq!(record_types::NSEC, 47);
        assert_eq!(record_types::DNSKEY, 48);
        assert_eq!(record_types::NSEC3, 50);
    }
}
