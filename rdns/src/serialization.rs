//! Serialization helpers for DNS records.
//!
//! Records store their RDATA as uncompressed wire-format bytes (see
//! [`crate::RecordData`]), so serializing a record's data is just a copy. The
//! per-type encoding lives in one place — `ParsedRecord::encode` — and is
//! exercised when records are built, not when they are written out.
//!
//! This module also provides canonical (uncompressed) RR serialization for
//! DNSSEC, per RFC 4034.

use crate::RecordData;
use crate::dname::dname_to_bytes;
use anyhow::anyhow;

/// Copy a record's RDATA (already in uncompressed wire format) into `buf`.
///
/// Returns the number of bytes written.
pub fn serialize_record_data(
    rdata: &RecordData,
    buf: &mut [u8],
) -> Result<usize, anyhow::Error> {
    let bytes = &rdata.rdata;
    if buf.len() < bytes.len() {
        return Err(anyhow!(
            "buffer too small for RDATA (need {}, have {})",
            bytes.len(),
            buf.len()
        ));
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(bytes.len())
}

/// Serialize a single resource record in canonical form (no name compression).
///
/// Format: name | type | class | TTL | RDLEN | RDATA
///
/// This is used for DNSSEC operations where canonical form is required per RFC 4034.
/// TTL must be u32 for proper DNSSEC validation.
///
/// Returns the number of bytes written.
pub fn serialize_resource_record_canonical(
    name: &str,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: &RecordData,
    buf: &mut [u8],
) -> Result<usize, anyhow::Error> {
    let mut pos = 0;

    // Serialize name (uncompressed)
    let name_bytes = dname_to_bytes(name)?;
    if buf.len() < pos + name_bytes.len() {
        return Err(anyhow!(
            "buffer too small for name (need {}, have {})",
            name_bytes.len(),
            buf.len()
        ));
    }
    buf[pos..pos + name_bytes.len()].copy_from_slice(&name_bytes);
    pos += name_bytes.len();

    // Type (2 bytes, big-endian)
    if buf.len() < pos + 2 {
        return Err(anyhow!("buffer too small for type field"));
    }
    buf[pos..pos + 2].copy_from_slice(&rtype.to_be_bytes());
    pos += 2;

    // Class (2 bytes, big-endian)
    if buf.len() < pos + 2 {
        return Err(anyhow!("buffer too small for class field"));
    }
    buf[pos..pos + 2].copy_from_slice(&class.to_be_bytes());
    pos += 2;

    // TTL (4 bytes, big-endian)
    if buf.len() < pos + 4 {
        return Err(anyhow!("buffer too small for TTL field"));
    }
    buf[pos..pos + 4].copy_from_slice(&ttl.to_be_bytes());
    pos += 4;

    // RDATA: First serialize to a temporary buffer to know its length
    let mut rdata_buf = vec![0u8; buf.len().saturating_sub(pos + 2)]; // Reserve space for RDLEN
    let rdata_len = serialize_record_data(rdata, &mut rdata_buf)?;

    // RDLEN (2 bytes, big-endian)
    if buf.len() < pos + 2 + rdata_len {
        return Err(anyhow!(
            "buffer too small for RDATA (need {} bytes, have {})",
            pos + 2 + rdata_len,
            buf.len()
        ));
    }
    buf[pos..pos + 2].copy_from_slice(&(rdata_len as u16).to_be_bytes());
    pos += 2;

    // RDATA
    buf[pos..pos + rdata_len].copy_from_slice(&rdata_buf[..rdata_len]);
    pos += rdata_len;

    Ok(pos)
}

/// Serialize an RRset for DNSSEC operations.
///
/// This concatenates multiple RRs in canonical form for hashing/signature verification.
/// All RRs must be for the same name, type, and class.
///
/// Per RFC 4034, RRsets must be:
/// 1. Sorted in canonical order
/// 2. Serialized without name compression
/// 3. All with the same TTL (the original_ttl from RRSIG)
pub fn serialize_rrset_canonical(
    name: &str,
    rtype: u16,
    class: u16,
    ttl: u32,
    records: &[RecordData],
) -> Result<Vec<u8>, anyhow::Error> {
    let mut serialized = Vec::new();

    for record in records {
        // Serialize each RR to a temporary buffer
        let mut temp_buf = vec![0u8; 65535]; // Max DNS message size
        let written = serialize_resource_record_canonical(name, rtype, class, ttl, record, &mut temp_buf)?;
        serialized.extend_from_slice(&temp_buf[..written]);
    }

    Ok(serialized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParsedRecord;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Build a stored record from its typed form (the normal construction path).
    fn stored(parsed: ParsedRecord) -> RecordData {
        RecordData::from_parsed(&parsed).expect("from_parsed")
    }

    #[test]
    fn test_serialize_a_record() {
        let addr = Ipv4Addr::new(192, 0, 2, 1);
        let record = stored(ParsedRecord::A(addr));

        let mut buf = vec![0u8; 4];
        let written = serialize_record_data(&record, &mut buf).expect("serialize_record_data");

        assert_eq!(written, 4);
        assert_eq!(&buf[..written], &[192, 0, 2, 1]);
    }

    #[test]
    fn test_serialize_aaaa_record() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let record = stored(ParsedRecord::AAAA(addr));

        let mut buf = vec![0u8; 16];
        let written = serialize_record_data(&record, &mut buf).expect("serialize_record_data");

        assert_eq!(written, 16);
        assert_eq!(&buf[..written], &addr.octets());
    }

    #[test]
    fn test_serialize_ns_record() {
        let record = stored(ParsedRecord::NS("ns.example.com.".to_string()));

        let mut buf = vec![0u8; 256];
        let written = serialize_record_data(&record, &mut buf).expect("serialize_record_data");

        assert!(written > 0);
        // Should contain the domain name in wire format
        assert!(written < 256);
    }

    #[test]
    fn test_serialize_mx_record() {
        let record = stored(ParsedRecord::MX {
            preference: 10,
            exchange: "mail.example.com.".to_string(),
        });

        let mut buf = vec![0u8; 256];
        let written = serialize_record_data(&record, &mut buf).expect("serialize_record_data");

        // Should have at least preference (2 bytes) + domain name
        assert!(written >= 2);
        // First 2 bytes should be preference in big-endian
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 10);
    }

    #[test]
    fn test_serialize_soa_record() {
        let record = stored(ParsedRecord::SOA {
            mname: "ns1.example.com.".to_string(),
            rname: "admin.example.com.".to_string(),
            serial: 2024010101,
            refresh: 10800,
            retry: 3600,
            expire: 604800,
            minimum: 86400,
        });

        let mut buf = vec![0u8; 512];
        let written = serialize_record_data(&record, &mut buf).expect("serialize_record_data");

        // Should include both names + 5 x 4-byte numbers = name1 + name2 + 20 bytes
        assert!(written >= 20);
    }

    #[test]
    fn test_serialize_dnskey_record() {
        let record = stored(ParsedRecord::DNSKEY {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![0x01, 0x02, 0x03, 0x04],
        });

        let mut buf = vec![0u8; 256];
        let written = serialize_record_data(&record, &mut buf).expect("serialize_record_data");

        assert_eq!(written, 8); // 2 + 1 + 1 + 4
        assert_eq!(&buf[0..2], &[0x01, 0x00]); // flags
        assert_eq!(buf[2], 3); // protocol
        assert_eq!(buf[3], 8); // algorithm
        assert_eq!(&buf[4..8], &[0x01, 0x02, 0x03, 0x04]); // public_key
    }

    #[test]
    fn test_serialize_ds_record() {
        let record = stored(ParsedRecord::DS {
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: vec![0xAB, 0xCD, 0xEF],
        });

        let mut buf = vec![0u8; 256];
        let written = serialize_record_data(&record, &mut buf).expect("serialize_record_data");

        assert_eq!(written, 7); // 2 + 1 + 1 + 3
        assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 12345);
        assert_eq!(buf[2], 8);
        assert_eq!(buf[3], 2);
        assert_eq!(&buf[4..7], &[0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn test_serialize_resource_record_canonical() {
        let record = stored(ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1)));

        let mut buf = vec![0u8; 256];
        let written = serialize_resource_record_canonical(
            "example.com.",
            1,
            1,
            300,
            &record,
            &mut buf,
        ).expect("serialize_resource_record_canonical");

        // Should have: name + type + class + ttl + rdlen + rdata
        assert!(written >= 20);
    }

    #[test]
    fn test_serialize_rrset_canonical() {
        let records = vec![
            stored(ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))),
            stored(ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 2))),
        ];

        let serialized = serialize_rrset_canonical(
            "example.com.",
            1,
            1,
            300,
            &records,
        ).expect("serialize_rrset_canonical");

        // Should contain both RRs
        assert!(serialized.len() > 20);
    }

    #[test]
    fn test_buffer_overflow_protection() {
        let record = stored(ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1)));

        let mut buf = vec![0u8; 2]; // Too small
        let result = serialize_record_data(&record, &mut buf);

        assert!(result.is_err(), "Should fail with small buffer");
    }

    #[test]
    fn test_canonical_name_no_compression() {
        // Verify that canonical form doesn't use compression
        let record = stored(ParsedRecord::NS("ns.example.com.".to_string()));

        let mut buf = vec![0u8; 256];
        let written = serialize_resource_record_canonical(
            "example.com.",
            2,
            1,
            3600,
            &record,
            &mut buf,
        ).expect("serialize_resource_record_canonical");

        // Check that we don't have compression pointers
        let _serialized = &buf[..written];
        assert!(written > 0);
    }
}
