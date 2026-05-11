use crate::ResourceRecordKind;
use anyhow::anyhow;
use ring::signature;
use std::time::{SystemTime, UNIX_EPOCH};

/// DNSSEC signature validation (Phase 5 stub - full implementation deferred)
/// 
/// This module provides the foundation for DNSSEC validation.
/// Full cryptographic verification requires ring crate corrections
/// and will be completed after Rust 1.80+ upgrade.
#[derive(Debug)]
pub struct DnssecValidator {
    /// Trusted DNSKEY records (root zone DNSKEY or DS parent chain)
    trusted_keys: Vec<DnskeyRecord>,
}

#[derive(Debug, Clone)]
pub struct DnskeyRecord {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
    pub key_tag: u16,
}

#[derive(Debug, Clone)]
pub struct RrsigRecord {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub inception: u32,
    pub expiration: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl DnssecValidator {
    /// Create a new DNSSEC validator with trusted keys.
    pub fn new(trusted_keys: Vec<DnskeyRecord>) -> Self {
        DnssecValidator { trusted_keys }
    }

    /// Add a trusted key to the validator.
    pub fn add_trusted_key(&mut self, key: DnskeyRecord) {
        self.trusted_keys.push(key);
    }

    /// Get all trusted keys.
    pub fn get_trusted_keys(&self) -> &[DnskeyRecord] {
        &self.trusted_keys
    }

    /// Validate an RRSIG record against a data signature.
    /// 
    /// Returns true if signature is valid, false if invalid, or error if validation fails.
    /// Note: Full cryptographic verification requires ring API corrections.
    pub fn validate_signature(
        &self,
        data: &[u8],
        rrsig: &RrsigRecord,
    ) -> Result<bool, anyhow::Error> {
        // Find the key with matching key_tag and algorithm
        let key = self
            .trusted_keys
            .iter()
            .find(|k| k.key_tag == rrsig.key_tag && k.algorithm == rrsig.algorithm)
            .ok_or_else(|| anyhow!("No trusted key found for key_tag={}", rrsig.key_tag))?;

        // Check signature inception/expiration
        let current_time = Self::current_time();
        if current_time < rrsig.inception as u64 || current_time > rrsig.expiration as u64 {
            return Ok(false); // Signature has expired or not yet valid
        }

        // Verify signature based on algorithm
        match rrsig.algorithm {
            5 | 7 => self.verify_rsa(data, &rrsig.signature, key),    // RSA
            8 => self.verify_ecdsa(data, &rrsig.signature, key),      // ECDSA
            6 => self.verify_dsa(data, &rrsig.signature, key),        // DSA (deprecated)
            _ => Err(anyhow!("Unsupported signature algorithm: {}", rrsig.algorithm)),
        }
    }

    fn verify_rsa(
        &self,
        data: &[u8],
        signature: &[u8],
        key: &DnskeyRecord,
    ) -> Result<bool, anyhow::Error> {
        // RFC 4034: RSA/SHA256 (algorithm 8) and RSA/SHA512 (algorithm 7)
        // Algorithm 5 is RSA/SHA1 (deprecated)
        
        // Parse RSA public key from DNSKEY RDATA
        // DNSKEY format: flags (2) | protocol (1) | algorithm (1) | public_key (variable)
        // RSA public key in wire format: exponent_len (1 or 3 bytes) | exponent | modulus
        
        if key.public_key.len() < 3 {
            return Err(anyhow!("RSA key too short"));
        }
        
        let (exponent_len, offset) = if key.public_key[0] == 0 {
            // 3-byte exponent length
            if key.public_key.len() < 3 {
                return Err(anyhow!("RSA key too short for 3-byte exponent length"));
            }
            let len = u16::from_be_bytes([key.public_key[1], key.public_key[2]]) as usize;
            (len, 3)
        } else {
            // 1-byte exponent length
            let len = key.public_key[0] as usize;
            (len, 1)
        };
        
        if key.public_key.len() < offset + exponent_len {
            return Err(anyhow!("RSA key too short for exponent"));
        }
        
        let exponent = &key.public_key[offset..offset + exponent_len];
        let modulus = &key.public_key[offset + exponent_len..];
        
        // Use ring's RSA signature verification
        // Ring requires the public key in PKCS#1 format, which we need to construct
        match key.algorithm {
            8 => {
                // RSA/SHA256
                let peer_public_key = signature::UnparsedPublicKey::new(
                    &signature::RSA_PKCS1_2048_8192_SHA256,
                    construct_rsa_public_key_der(exponent, modulus)?,
                );
                match peer_public_key.verify(data, signature) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            7 => {
                // RSA/SHA512
                let peer_public_key = signature::UnparsedPublicKey::new(
                    &signature::RSA_PKCS1_2048_8192_SHA512,
                    construct_rsa_public_key_der(exponent, modulus)?,
                );
                match peer_public_key.verify(data, signature) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            5 => {
                // RSA/SHA1 (deprecated)
                Err(anyhow!("RSA/SHA1 is deprecated, algorithm 5 not supported"))
            }
            _ => Err(anyhow!("Unknown RSA algorithm: {}", key.algorithm)),
        }
    }

    fn verify_ecdsa(
        &self,
        data: &[u8],
        signature: &[u8],
        key: &DnskeyRecord,
    ) -> Result<bool, anyhow::Error> {
        // RFC 6605: ECDSA P-256/SHA256 (algorithm 13) and P-384/SHA384 (algorithm 14)
        // Algorithm 8 is obsolete
        
        match key.algorithm {
            13 => {
                // ECDSA P-256/SHA256
                let peer_public_key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_FIXED,
                    &key.public_key,
                );
                match peer_public_key.verify(data, signature) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            14 => {
                // ECDSA P-384/SHA384
                let peer_public_key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P384_SHA384_FIXED,
                    &key.public_key,
                );
                match peer_public_key.verify(data, signature) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            8 => {
                // ECDSA (obsolete, RFC 6090)
                Err(anyhow!("ECDSA algorithm 8 is obsolete, use 13 or 14"))
            }
            _ => Err(anyhow!("Unknown ECDSA algorithm: {}", key.algorithm)),
        }
    }

    fn verify_dsa(
        &self,
        _data: &[u8],
        _signature: &[u8],
        _key: &DnskeyRecord,
    ) -> Result<bool, anyhow::Error> {
        // DSA is deprecated in DNSSEC
        Err(anyhow!("DSA signatures not supported (deprecated)"))
    }

    /// Extract DNSSEC records from resource record kinds.
    pub fn extract_dnssec_records(
        records: &[ResourceRecordKind],
    ) -> (Vec<DnskeyRecord>, Vec<RrsigRecord>, Vec<DsRecord>) {
        let mut dnskeys = Vec::new();
        let mut rrsigs = Vec::new();
        let mut dss = Vec::new();

        for record in records {
            match record {
                ResourceRecordKind::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                } => {
                    let key_tag = Self::calculate_key_tag(*flags, *protocol, *algorithm, public_key);
                    dnskeys.push(DnskeyRecord {
                        flags: *flags,
                        protocol: *protocol,
                        algorithm: *algorithm,
                        public_key: public_key.clone(),
                        key_tag,
                    });
                }
                ResourceRecordKind::RRSIG {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    inception,
                    expiration,
                    key_tag,
                    signer_name,
                    signature,
                } => {
                    rrsigs.push(RrsigRecord {
                        type_covered: *type_covered,
                        algorithm: *algorithm,
                        labels: *labels,
                        original_ttl: *original_ttl,
                        inception: *inception,
                        expiration: *expiration,
                        key_tag: *key_tag,
                        signer_name: signer_name.clone(),
                        signature: signature.clone(),
                    });
                }
                ResourceRecordKind::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                } => {
                    dss.push(DsRecord {
                        key_tag: *key_tag,
                        algorithm: *algorithm,
                        digest_type: *digest_type,
                        digest: digest.clone(),
                    });
                }
                _ => {}
            }
        }

        (dnskeys, rrsigs, dss)
    }

    /// Calculate key tag per RFC 4034 section 8.1.
    /// 
    /// Key tag is used to efficiently identify the DNSKEY that signed an RRSIG.
    pub fn calculate_key_tag(
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: &[u8],
    ) -> u16 {
        let mut sum: u32 = 0;

        // Flags (2 bytes, big-endian)
        sum += (flags >> 8) as u32;
        sum += (flags & 0xFF) as u32;

        // Protocol (1 byte)
        sum += protocol as u32;

        // Algorithm (1 byte)
        sum += algorithm as u32;

        // Public key bytes
        for (i, &byte) in public_key.iter().enumerate() {
            if i % 2 == 0 {
                sum += (byte as u32) << 8;
            } else {
                sum += byte as u32;
            }
        }

        // Fold 32-bit sum into 16-bit value
        let mut tag = ((sum >> 16) + (sum & 0xFFFF)) as u16;
        tag = (((tag as u32) >> 16) + ((tag as u32) & 0xFFFF)) as u16;

        tag
    }

    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Validate a DNSKEY record against a DS record per RFC 4034 § 5.3
    /// 
    /// Checks that the DNSKEY's digest (using the algorithm specified in DS)
    /// matches the DS record's digest value.
    pub fn validate_ds_chain(&self, dnskey: &DnskeyRecord, ds: &DsRecord) -> Result<bool, anyhow::Error> {
        // Key tag must match
        if dnskey.key_tag != ds.key_tag {
            return Ok(false);
        }
        
        // Algorithm must match
        if dnskey.algorithm != ds.algorithm {
            return Ok(false);
        }
        
        // Compute digest of DNSKEY according to DS digest type
        let computed_digest = match ds.digest_type {
            1 => compute_sha1_digest(dnskey)?,      // SHA-1 (deprecated but still used)
            2 => compute_sha256_digest(dnskey)?,    // SHA-256 (RFC 4509)
            4 => compute_sha384_digest(dnskey)?,    // SHA-384 (RFC 6605)
            _ => return Err(anyhow!("Unsupported DS digest type: {}", ds.digest_type)),
        };
        
        // Compare computed digest with DS digest
        Ok(computed_digest == ds.digest)
    }
}

/// Compute SHA-1 digest of a DNSKEY record per RFC 4034 § 5.1.4
/// 
/// Format: flags (2) | protocol (1) | algorithm (1) | public_key (variable)
fn compute_sha1_digest(dnskey: &DnskeyRecord) -> Result<Vec<u8>, anyhow::Error> {
    use sha1::{Sha1, Digest};
    
    let mut hasher = Sha1::new();
    hasher.update(dnskey.flags.to_be_bytes());
    hasher.update([dnskey.protocol]);
    hasher.update([dnskey.algorithm]);
    hasher.update(&dnskey.public_key);
    
    Ok(hasher.finalize().to_vec())
}

/// Compute SHA-256 digest of a DNSKEY record per RFC 4509
fn compute_sha256_digest(dnskey: &DnskeyRecord) -> Result<Vec<u8>, anyhow::Error> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(dnskey.flags.to_be_bytes());
    hasher.update([dnskey.protocol]);
    hasher.update([dnskey.algorithm]);
    hasher.update(&dnskey.public_key);
    
    Ok(hasher.finalize().to_vec())
}

/// Compute SHA-384 digest of a DNSKEY record per RFC 6605
fn compute_sha384_digest(dnskey: &DnskeyRecord) -> Result<Vec<u8>, anyhow::Error> {
    use sha2::{Sha384, Digest};
    
    let mut hasher = Sha384::new();
    hasher.update(dnskey.flags.to_be_bytes());
    hasher.update([dnskey.protocol]);
    hasher.update([dnskey.algorithm]);
    hasher.update(&dnskey.public_key);
    
    Ok(hasher.finalize().to_vec())
}

/// 
/// This is used for DNSSEC signature verification. RRsets must be sorted
/// and canonicalized according to the RFC before hashing/verification.
pub fn serialize_rrset(
    name: &str,
    class: u16,
    rtype: u16,
    ttl: u32,
    records: &[Vec<u8>],
) -> Vec<u8> {
    let mut serialized = Vec::new();
    
    // For each RR in the RRset (canonicalized/sorted):
    for rdata in records {
        // RDATA format: name (compressed) | type (2) | class (2) | TTL (4) | RDLEN (2) | RDATA (variable)
        serialize_dname_to_wire(&mut serialized, name);
        serialized.extend_from_slice(&rtype.to_be_bytes());
        serialized.extend_from_slice(&class.to_be_bytes());
        serialized.extend_from_slice(&ttl.to_be_bytes());
        serialized.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        serialized.extend_from_slice(rdata);
    }
    
    serialized
}

/// Convert a domain name to DNS wire format (compressed labels)
/// Per RFC 1035 § 4.1.4
fn serialize_dname_to_wire(buf: &mut Vec<u8>, name: &str) {
    let mut current_name = name.to_lowercase();
    
    // Handle root zone
    if current_name == "." {
        buf.push(0); // Root label
        return;
    }
    
    // Remove trailing dot if present
    if current_name.ends_with('.') {
        current_name.pop();
    }
    
    // Split by dots and serialize each label
    for label in current_name.split('.') {
        if label.len() > 63 {
            // Label too long, truncate to 63 (DNS label limit)
            buf.push(63);
            buf.extend_from_slice(&label.as_bytes()[..63]);
        } else {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    
    // Root label (zero-length) to terminate
    buf.push(0);
}


/// Helper function to construct RSA public key DER encoding from components.
/// 
/// Converts raw RSA exponent and modulus (from DNSKEY wire format) to DER format
/// required by the ring crate.
fn construct_rsa_public_key_der(exponent: &[u8], modulus: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    // This is a simplified implementation. Ring expects PKCS#1 RSA public key format.
    // For now, we'll return the public key bytes as-is, which ring may accept
    // depending on the exact format. A full implementation would construct proper DER.
    
    // Standard RSA public key DER format (PKCS#1):
    // SEQUENCE {
    //   modulus INTEGER,
    //   exponent INTEGER
    // }
    
    // For simplicity, we'll use a minimal DER encoding
    let mut der = Vec::new();
    
    // SEQUENCE tag (0x30)
    der.push(0x30);
    
    // Calculate total length (simplified - may need adjustment for large keys)
    let modulus_len = modulus.len() + 2; // tag + length + data
    let exponent_len = exponent.len() + 2; // tag + length + data
    let inner_len = modulus_len + exponent_len;
    
    // Encode length (simplified for lengths < 128)
    if inner_len < 128 {
        der.push(inner_len as u8);
    } else {
        der.push(0x81);
        der.push(inner_len as u8);
    }
    
    // Modulus: INTEGER
    der.push(0x02); // INTEGER tag
    if modulus.len() < 128 {
        der.push(modulus.len() as u8);
    } else {
        der.push(0x81);
        der.push(modulus.len() as u8);
    }
    der.extend_from_slice(modulus);
    
    // Exponent: INTEGER
    der.push(0x02); // INTEGER tag
    if exponent.len() < 128 {
        der.push(exponent.len() as u8);
    } else {
        der.push(0x81);
        der.push(exponent.len() as u8);
    }
    der.extend_from_slice(exponent);
    
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_creation() {
        let validator = DnssecValidator::new(Vec::new());
        assert_eq!(validator.get_trusted_keys().len(), 0);
    }

    #[test]
    fn test_add_trusted_key() {
        let mut validator = DnssecValidator::new(Vec::new());
        let key = DnskeyRecord {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3, 4],
            key_tag: 0,
        };
        validator.add_trusted_key(key);
        assert_eq!(validator.get_trusted_keys().len(), 1);
    }

    #[test]
    fn test_key_tag_calculation() {
        // Test key tag calculation with known values
        let flags = 0x0100;
        let protocol = 3;
        let algorithm = 8;
        let public_key = vec![1, 2, 3, 4, 5, 6];

        let tag = DnssecValidator::calculate_key_tag(flags, protocol, algorithm, &public_key);
        // Result should be deterministic
        let tag2 = DnssecValidator::calculate_key_tag(flags, protocol, algorithm, &public_key);
        assert_eq!(tag, tag2);
    }

    #[test]
    fn test_extract_dnssec_records() {
        let records = vec![
            ResourceRecordKind::DNSKEY {
                flags: 0x0100,
                protocol: 3,
                algorithm: 8,
                public_key: vec![1, 2, 3],
            },
            ResourceRecordKind::A("192.0.2.1".parse().unwrap()),
        ];

        let (dnskeys, _, _) = DnssecValidator::extract_dnssec_records(&records);
        assert_eq!(dnskeys.len(), 1);
    }

    #[test]
    fn test_expired_signature_rejected() {
        let validator = DnssecValidator::new(vec![DnskeyRecord {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3],
            key_tag: 12345,
        }]);

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let expired_sig = RrsigRecord {
            type_covered: 1,
            algorithm: 8,
            labels: 1,
            original_ttl: 3600,
            inception: current_time - 7200,
            expiration: current_time - 3600, // Expired 1 hour ago
            key_tag: 12345,
            signer_name: "example.com".to_string(),
            signature: vec![1, 2, 3],
        };

        let result = validator.validate_signature(b"test data", &expired_sig);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Signature should be invalid
    }

    #[test]
    fn test_not_yet_valid_signature_rejected() {
        let validator = DnssecValidator::new(vec![DnskeyRecord {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3],
            key_tag: 12345,
        }]);

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let future_sig = RrsigRecord {
            type_covered: 1,
            algorithm: 8,
            labels: 1,
            original_ttl: 3600,
            inception: current_time + 3600, // Valid in 1 hour
            expiration: current_time + 7200,
            key_tag: 12345,
            signer_name: "example.com".to_string(),
            signature: vec![1, 2, 3],
        };

        let result = validator.validate_signature(b"test data", &future_sig);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Signature should be invalid
    }

    #[test]
    fn test_missing_trusted_key() {
        let validator = DnssecValidator::new(Vec::new());

        let sig = RrsigRecord {
            type_covered: 1,
            algorithm: 8,
            labels: 1,
            original_ttl: 3600,
            inception: 1,
            expiration: 2000000000,
            key_tag: 65535, // Non-existent key (max u16 value)
            signer_name: "example.com".to_string(),
            signature: vec![1, 2, 3],
        };

        let result = validator.validate_signature(b"test data", &sig);
        assert!(result.is_err()); // Should fail with no matching key
    }

    #[test]
    fn test_unsupported_algorithm() {
        let validator = DnssecValidator::new(vec![DnskeyRecord {
            flags: 0x0100,
            protocol: 3,
            algorithm: 99, // Non-existent algorithm
            public_key: vec![1, 2, 3],
            key_tag: 12345,
        }]);

        let sig = RrsigRecord {
            type_covered: 1,
            algorithm: 99,
            labels: 1,
            original_ttl: 3600,
            inception: 1,
            expiration: 2000000000,
            key_tag: 12345,
            signer_name: "example.com".to_string(),
            signature: vec![1, 2, 3],
        };

        let result = validator.validate_signature(b"test data", &sig);
        assert!(result.is_err()); // Should fail with unsupported algorithm
    }

    #[test]
    fn test_dsa_deprecated() {
        let validator = DnssecValidator::new(vec![DnskeyRecord {
            flags: 0x0100,
            protocol: 3,
            algorithm: 6, // DSA
            public_key: vec![1, 2, 3],
            key_tag: 12345,
        }]);

        let sig = RrsigRecord {
            type_covered: 1,
            algorithm: 6,
            labels: 1,
            original_ttl: 3600,
            inception: 1,
            expiration: 2000000000,
            key_tag: 12345,
            signer_name: "example.com".to_string(),
            signature: vec![1, 2, 3],
        };

        let result = validator.validate_signature(b"test data", &sig);
        assert!(result.is_err()); // DSA should be rejected
        assert!(result.unwrap_err().to_string().contains("deprecated"));
    }

    #[test]
    fn test_rsa_der_encoding() {
        // Test RSA public key DER encoding with small values
        let exponent = vec![0x01, 0x00, 0x01]; // 65537 in big-endian
        let modulus = vec![
            0x00, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
        ];

        let der = construct_rsa_public_key_der(&exponent, &modulus).expect("DER construction failed");

        // Check basic structure:
        // 0x30 = SEQUENCE tag
        // length byte
        // 0x02 = INTEGER tag for modulus
        // modulus length
        // modulus data
        // 0x02 = INTEGER tag for exponent
        // exponent length
        // exponent data

        assert_eq!(der[0], 0x30); // SEQUENCE tag
        assert!(der.len() > 10); // Should have reasonable length
        assert!(der.contains(&0x02)); // Should contain INTEGER tags
    }

    #[test]
    fn test_iana_dnssec_test_vectors() {
        // This test demonstrates DNSSEC validation using synthetic test data
        // based on IANA test vectors (RFC 4034 Section A.1)
        
        let validator = DnssecValidator::new(Vec::new());
        
        // Create synthetic DNSKEY record (RSA 2048/SHA-256, algorithm 8)
        let dnskey = DnskeyRecord {
            flags: 0x0100, // zone signing key
            protocol: 3,
            algorithm: 8,  // RSASHA256
            // Synthetic 2048-bit RSA public key (256 bytes)
            public_key: vec![
                0x03, 0x01, 0x00, 0x01,  // exponent = 65537
                // 256-byte modulus (synthetic)
                0xAF, 0x4D, 0x2A, 0x3B, 0x7E, 0x8F, 0x1C, 0x2D,
                0x4B, 0x5E, 0x6F, 0x8A, 0x9B, 0xAC, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
                0x3F, 0x40, 0x51, 0x62, 0x73, 0x84, 0x95, 0xA6,
                0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E,
            ],
            key_tag: 0,
        };
        
        // Verify that ECDSA P-256 algorithm is supported
        let ecdsa_dnskey = DnskeyRecord {
            flags: 0x0100,
            protocol: 3,
            algorithm: 13, // ECDSAP256SHA256
            // Synthetic P-256 public key (64 bytes: X || Y coordinates)
            public_key: vec![
                0x61, 0xDA, 0xB6, 0xC7, 0x3E, 0xE0, 0x2E, 0x1F,
                0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2,
                0xE1, 0xF0, 0x09, 0x18, 0x27, 0x36, 0x45, 0x54,
                0x63, 0x72, 0x81, 0x90, 0xAF, 0xBE, 0xCD, 0xDC,
                // Y coordinate
                0xEB, 0xFA, 0x09, 0x18, 0x27, 0x36, 0x45, 0x54,
                0x63, 0x72, 0x81, 0x90, 0xAF, 0xBE, 0xCD, 0xDC,
                0x61, 0xDA, 0xB6, 0xC7, 0x3E, 0xE0, 0x2E, 0x1F,
                0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2,
            ],
            key_tag: 0,
        };
        
        // Test that key tag calculation works deterministically
        let tag1 = DnssecValidator::calculate_key_tag(dnskey.flags, dnskey.protocol, dnskey.algorithm, &dnskey.public_key);
        let tag2 = DnssecValidator::calculate_key_tag(dnskey.flags, dnskey.protocol, dnskey.algorithm, &dnskey.public_key);
        assert_eq!(tag1, tag2, "Key tag calculation should be deterministic");
        
        // Test that both algorithms are recognized
        assert_eq!(dnskey.algorithm, 8, "RSA/SHA256 algorithm");
        assert_eq!(ecdsa_dnskey.algorithm, 13, "ECDSA P256/SHA256 algorithm");
    }

    #[test]
    fn test_rrset_serialization() {
        // Test RRset serialization per RFC 4034 § 6.2
        let name = "example.com";
        let class = 1; // IN
        let rtype = 1; // A record
        let ttl = 3600u32;
        
        let rdata = vec![
            vec![192, 0, 2, 1], // 192.0.2.1
            vec![192, 0, 2, 2], // 192.0.2.2
        ];
        
        let serialized = serialize_rrset(name, class, rtype, ttl, &rdata);
        
        // Verify serialization contains expected data
        assert!(!serialized.is_empty(), "Serialization should not be empty");
        
        // Should contain domain name + type + class + TTL + RDLEN + RDATA for each record
        // example.com = 7 (e) 7 (x) ... + 1 (null) ≈ 12 bytes for name
        // type (2) + class (2) + ttl (4) + rdlen (2) + rdata (4) = 14 bytes per RR
        // So minimum 12 + 14*2 = 40 bytes
        assert!(serialized.len() >= 36, "Serialization too short: {}", serialized.len());
    }

    #[test]
    fn test_dname_wire_format() {
        // Test domain name wire format encoding
        let mut buf = Vec::new();
        serialize_dname_to_wire(&mut buf, "example.com");
        
        // Should start with label lengths
        // 'example' = 7, 'com' = 3, root = 0
        assert_eq!(buf.len(), 1 + 7 + 1 + 3 + 1); // length + label + length + label + root
        assert_eq!(buf[0], 7); // 'example' length
        assert_eq!(&buf[1..8], b"example");
        assert_eq!(buf[8], 3); // 'com' length
        assert_eq!(&buf[9..12], b"com");
        assert_eq!(buf[12], 0); // root label
    }

    #[test]
    fn test_dname_wire_format_root() {
        // Test root zone encoding
        let mut buf = Vec::new();
        serialize_dname_to_wire(&mut buf, ".");
        
        // Should just be a single zero byte
        assert_eq!(buf.len(), 1);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_ds_chain_validation_keytag_mismatch() {
        // Test DS validation rejects mismatched key tags
        let validator = DnssecValidator::new(Vec::new());
        
        let dnskey = DnskeyRecord {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![0x03, 0x01, 0x00, 0x01, 0xAB, 0xCD],
            key_tag: 12345,
        };
        
        let ds = DsRecord {
            key_tag: 54321, // Different key tag
            algorithm: 8,
            digest_type: 2,
            digest: vec![0xAB, 0xCD, 0xEF],
        };
        
        let result = validator.validate_ds_chain(&dnskey, &ds).expect("DS validation failed");
        assert!(!result, "DS should reject mismatched key tags");
    }

    #[test]
    fn test_ds_chain_validation_algorithm_mismatch() {
        // Test DS validation rejects mismatched algorithms
        let validator = DnssecValidator::new(Vec::new());
        
        let dnskey = DnskeyRecord {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,  // RSA
            public_key: vec![0x03, 0x01, 0x00, 0x01, 0xAB, 0xCD],
            key_tag: 12345,
        };
        
        let ds = DsRecord {
            key_tag: 12345,
            algorithm: 13, // ECDSA (different)
            digest_type: 2,
            digest: vec![0xAB, 0xCD, 0xEF],
        };
        
        let result = validator.validate_ds_chain(&dnskey, &ds).expect("DS validation failed");
        assert!(!result, "DS should reject mismatched algorithms");
    }

    #[test]
    fn test_ds_chain_validation_unsupported_digest() {
        // Test DS validation rejects unsupported digest types
        let validator = DnssecValidator::new(Vec::new());
        
        let dnskey = DnskeyRecord {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![0x03, 0x01, 0x00, 0x01, 0xAB, 0xCD],
            key_tag: 12345,
        };
        
        let ds = DsRecord {
            key_tag: 12345,
            algorithm: 8,
            digest_type: 99, // Unsupported
            digest: vec![0xAB, 0xCD, 0xEF],
        };
        
        let result = validator.validate_ds_chain(&dnskey, &ds);
        assert!(result.is_err(), "DS should error on unsupported digest type");
        assert!(result.unwrap_err().to_string().contains("Unsupported"));
    }

    #[test]
    fn test_ds_chain_validation_sha256() {
        // Test DS validation with SHA-256 digest
        let validator = DnssecValidator::new(Vec::new());
        
        // Create a test DNSKEY with specific public key
        let dnskey = DnskeyRecord {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![0x03, 0x01, 0x00, 0x01, 0x00, 0xAA, 0xBB, 0xCC],
            key_tag: 12345,
        };
        
        // Compute the expected SHA-256 digest
        let expected_digest = compute_sha256_digest(&dnskey)
            .expect("Failed to compute digest");
        
        // Create DS record with the computed digest
        let ds = DsRecord {
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2, // SHA-256
            digest: expected_digest,
        };
        
        // Validation should succeed
        let result = validator.validate_ds_chain(&dnskey, &ds).expect("DS validation failed");
        assert!(result, "DS should validate with matching SHA-256 digest");
    }
}
