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
    /// NSEC3PARAM — the salt and iteration count a zone's NSEC3 chain was built
    /// with, published at the apex so an authoritative server can find the chain
    /// it is meant to answer from (RFC 5155 §4). It carries no names and is
    /// stored as opaque RDATA rather than parsed, which is why there is no
    /// `ParsedRecord` arm for it.
    pub const NSEC3PARAM: u16 = 51;
    /// AXFR — a whole-zone transfer. A QTYPE only: no record ever has this type,
    /// and it is defined over TCP alone (RFC 5936).
    pub const AXFR: u16 = 252;
    /// IXFR — an incremental transfer (RFC 1995). A QTYPE only, and the one
    /// request that carries a record of its own: the client's SOA, in the
    /// authority section, saying which version it already holds.
    pub const IXFR: u16 = 251;
    /// ANY (`*`) — also a QTYPE only.
    pub const ANY: u16 = 255;
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

/// WSAEMSGSIZE: the datagram was larger than the buffer offered for it.
///
/// Windows fails the receive rather than truncating, and Rust has no
/// [`std::io::ErrorKind`] for it — it arrives as `Uncategorized`, which no
/// `matches!` on kinds can catch, so the raw code is the only way to recognize
/// it.
const WSAEMSGSIZE: i32 = 10040;

/// Whether a UDP receive error is about a *previous* datagram, or about the one
/// just dropped, rather than about the health of the socket.
///
/// Both servers end their receive loop — and with it the process — when
/// `recv_from` returns `Err`. So anything a remote party can provoke has to be
/// recognized here, or it is a remote kill switch. This lives in the library
/// because it was written twice, in `rdnsd` and in `rdnsr`, and the second
/// oversight below was found in one copy only.
///
/// **A stray ICMP report.** A server that replies to a client which has already
/// gone away gets an ICMP port-unreachable back, and Windows reports it on the
/// socket's **next** `recv_from` (WSAECONNRESET; `WSAENETRESET` for a TTL
/// expiry). Unix only does this on a connected socket, which is why the shape is
/// invisible there and fatal here — any client that closed its socket before our
/// reply landed could stop the server.
///
/// **An oversized datagram.** On Windows a datagram larger than the buffer makes
/// `recv_from` fail with WSAEMSGSIZE instead of truncating, so one large packet
/// from anywhere — before authentication, before the rate limiter, before any
/// zone is consulted — exited the process. Same class as the ICMP bug, and missed
/// because the original fix was a list of `ErrorKind`s and this error has no kind
/// of its own. On Unix the packet is truncated instead and then fails to parse,
/// so a receive buffer large enough for any datagram is the other half of the
/// fix.
///
/// Errors that are neither are still fatal, because a server that cannot receive
/// is not serving.
pub fn recv_error_is_transient(e: &std::io::Error) -> bool {
    if e.raw_os_error() == Some(WSAEMSGSIZE) {
        return true;
    }
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            // The portable spelling of "that datagram did not fit", which is
            // what some platforms report and what a future Rust may map
            // WSAEMSGSIZE onto.
            | std::io::ErrorKind::InvalidInput
    )
}

/// The receive buffer one datagram needs.
///
/// Not the EDNS payload size either server advertises: that is a statement about
/// *responses*, and a request is not bound by it. A client may send anything a
/// UDP length field can express.
pub const UDP_RECEIVE_BUFFER: usize = 65_535;

/// A name in the form DNS compares names by: ASCII case folded, and nothing
/// else.
///
/// The "and nothing else" is the point. DNS case-insensitivity is defined over
/// ASCII only (RFC 4343): the octets 0x41–0x5A match 0x61–0x7A and every other
/// octet matches only itself, because a label is a byte string and the protocol
/// has no idea what encoding is in it. `str::to_lowercase` applies the full
/// Unicode mapping instead, which folds codepoints *into* ASCII — U+212A KELVIN
/// SIGN becomes `k` — so two names that differ on the wire come out equal. Any
/// table keyed on the result then merges them, which for a cache means one
/// entry answering for two owners.
///
/// This lives here because it was independently written, correctly, in `zone`
/// and incorrectly in `cache`, with the comment explaining why only in the
/// former. Every keyed-by-name structure should reach for this one.
pub fn ascii_lowered(name: &str) -> String {
    let mut owned = name.to_string();
    owned.make_ascii_lowercase();
    owned
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
/// `TYPEnnn` is accepted for any type at all (RFC 3597 §5), which is what makes
/// a type this library has no mnemonic for still expressible in a zone file — an
/// NSEC bitmap listing one, or a record carried in the generic `\#` form.
///
/// # Examples
/// ```ignore
/// assert_eq!(record_type_name_to_code("A"), Some(1));
/// assert_eq!(record_type_name_to_code("MX"), Some(15));
/// assert_eq!(record_type_name_to_code("TYPE1234"), Some(1234));
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
        other => other
            .strip_prefix("TYPE")
            .or_else(|| other.strip_prefix("type"))
            .and_then(|n| n.parse::<u16>().ok()),
    }
}

/// The mnemonic for a type code, or its `TYPEnnn` form (RFC 3597 §5) when this
/// library has none. Always a name the parser reads back, which is what the zone
/// writer relies on.
pub fn record_type_name(code: u16) -> String {
    match code {
        record_types::A => "A".to_string(),
        record_types::NS => "NS".to_string(),
        record_types::CNAME => "CNAME".to_string(),
        record_types::SOA => "SOA".to_string(),
        record_types::PTR => "PTR".to_string(),
        record_types::MX => "MX".to_string(),
        record_types::TXT => "TXT".to_string(),
        record_types::AAAA => "AAAA".to_string(),
        record_types::DS => "DS".to_string(),
        record_types::DNSKEY => "DNSKEY".to_string(),
        record_types::RRSIG => "RRSIG".to_string(),
        record_types::NSEC => "NSEC".to_string(),
        record_types::NSEC3 => "NSEC3".to_string(),
        other => format!("TYPE{other}"),
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

    /// RFC 3597 §5: any type at all can be named, which is what keeps a type we
    /// have no mnemonic for from being unwritable.
    #[test]
    fn test_generic_type_names_round_trip() {
        assert_eq!(record_type_name_to_code("TYPE1234"), Some(1234));
        assert_eq!(record_type_name_to_code("TYPE1"), Some(record_types::A));
        assert_eq!(record_type_name(1234), "TYPE1234");
        assert_eq!(record_type_name(record_types::A), "A");

        for code in [1u16, 15, 50, 99, 257, 65535] {
            let name = record_type_name(code);
            assert_eq!(
                record_type_name_to_code(&name),
                Some(code),
                "{name} should read back as {code}"
            );
        }
    }

    /// A number that does not fit a TYPE code is not a type name.
    #[test]
    fn test_out_of_range_generic_type_name_is_rejected() {
        assert_eq!(record_type_name_to_code("TYPE65536"), None);
        assert_eq!(record_type_name_to_code("TYPE"), None);
        assert_eq!(record_type_name_to_code("TYPEA"), None);
    }

    /// The oversized-datagram case, which the `ErrorKind` list could not express.
    ///
    /// Windows reports WSAEMSGSIZE for a datagram bigger than the buffer, Rust
    /// maps it to `kind = Uncategorized`, and an `Uncategorized` error matched
    /// none of the arms — so the receive loop treated it as fatal and one
    /// oversized packet from any source exited the process, before
    /// authentication and before the rate limiter. The predicate has to be
    /// tested through the raw code because the kind carries no information.
    #[test]
    fn an_oversized_datagram_is_not_a_reason_to_stop_serving() {
        let too_big = std::io::Error::from_raw_os_error(WSAEMSGSIZE);
        assert!(
            recv_error_is_transient(&too_big),
            "WSAEMSGSIZE arrives as {:?}, which is why matching on the kind alone missed it",
            too_big.kind()
        );
    }

    #[test]
    fn a_stray_icmp_report_is_not_a_reason_to_stop_serving() {
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::NetworkUnreachable,
            std::io::ErrorKind::HostUnreachable,
        ] {
            assert!(recv_error_is_transient(&std::io::Error::from(kind)), "{kind:?}");
        }
    }

    /// And a socket that has genuinely failed still stops the loop — the point of
    /// the predicate is to be narrow. A server that cannot receive is not
    /// serving, and pretending otherwise is a process that looks healthy and
    /// answers nothing.
    #[test]
    fn a_broken_socket_is_still_fatal() {
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::AddrNotAvailable,
            std::io::ErrorKind::OutOfMemory,
        ] {
            assert!(!recv_error_is_transient(&std::io::Error::from(kind)), "{kind:?}");
        }
    }

    /// ASCII case folding, and nothing else (RFC 4343).
    #[test]
    fn ascii_lowering_does_not_fold_unicode_into_ascii() {
        assert_eq!(ascii_lowered("WWW.Example.COM."), "www.example.com.");
        // U+212A KELVIN SIGN lowercases to `k` under Unicode rules. Two names
        // that are different bytes on the wire must not come out equal.
        assert_ne!(ascii_lowered("\u{212A}.example.com."), "k.example.com.");
        assert_eq!("\u{212A}".to_lowercase(), "k", "which is what to_lowercase does");
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
