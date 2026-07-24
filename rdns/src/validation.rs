use anyhow::anyhow;

/// Upper bound on additional records in a request. A legitimate request carries
/// at most an OPT plus a TSIG/SIG(0); the slack is for forward compatibility.
const MAX_REQUEST_ADDITIONALS: usize = 4;

/// Configuration for request validation
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Maximum UDP packet size (RFC 512)
    pub max_udp_size: usize,
    /// Maximum TCP packet size
    pub max_tcp_size: usize,
    /// Maximum labels in a domain name
    pub max_labels: usize,
    /// Maximum bytes in a single label
    pub max_label_size: usize,
    /// Maximum total domain name size
    pub max_name_size: usize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        ValidationConfig {
            max_udp_size: 512,         // RFC 1035 standard
            max_tcp_size: 16 * 1024,   // 16KB for TCP
            max_labels: 127,           // RFC 1035 limit
            max_label_size: 63,        // RFC 1035 limit
            max_name_size: 255,        // RFC 1035 limit
        }
    }
}

/// Result of validation
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Valid,
    Invalid(String),
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            ValidationResult::Valid => None,
            ValidationResult::Invalid(msg) => Some(msg),
        }
    }
}

/// DNS request validator
pub struct RequestValidator {
    config: ValidationConfig,
}

impl RequestValidator {
    pub fn new(config: ValidationConfig) -> Self {
        RequestValidator { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(ValidationConfig::default())
    }

    /// Validate a DNS request packet
    pub fn validate_packet(&self, data: &[u8], is_tcp: bool) -> ValidationResult {
        // Check size
        let max_size = if is_tcp {
            self.config.max_tcp_size
        } else {
            self.config.max_udp_size
        };

        if data.len() > max_size {
            return ValidationResult::Invalid(format!(
                "packet size {} exceeds maximum {}",
                data.len(),
                max_size
            ));
        }

        // Minimum DNS header size
        if data.len() < 12 {
            return ValidationResult::Invalid("packet too small for DNS header".to_string());
        }

        // Validate header structure
        if let Err(e) = self.validate_header(data) {
            return ValidationResult::Invalid(e.to_string());
        }

        // Parse and validate domain names in queries
        if let Err(e) = self.validate_domain_names(data) {
            return ValidationResult::Invalid(e.to_string());
        }

        ValidationResult::Valid
    }

    /// Validate DNS header format
    fn validate_header(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        if data.len() < 12 {
            return Err(anyhow!("header too short"));
        }

        // Parse counts from header
        let query_count = u16::from_be_bytes([data[4], data[5]]) as usize;
        let answer_count = u16::from_be_bytes([data[6], data[7]]) as usize;
        let auth_count = u16::from_be_bytes([data[8], data[9]]) as usize;
        let add_count = u16::from_be_bytes([data[10], data[11]]) as usize;

        // Sanity checks
        if query_count > 10 {
            return Err(anyhow!("too many queries: {}", query_count));
        }

        // Answers and authority records belong in responses, not requests.
        // The additional section is different: it is where a request carries its
        // OPT (EDNS0, RFC 6891 §6.1.1) and TSIG/SIG(0) records, so rejecting a
        // non-empty additional section would reject every EDNS query. Cap it
        // instead — a request has no legitimate reason to carry many records.
        let qr_flag = data[2] & 0x80 != 0;
        if !qr_flag {
            if answer_count > 0 || auth_count > 0 {
                return Err(anyhow!(
                    "request query should not have answer/authority sections"
                ));
            }
            if add_count > MAX_REQUEST_ADDITIONALS {
                return Err(anyhow!(
                    "too many additional records in request: {}",
                    add_count
                ));
            }
        }

        Ok(())
    }

    /// Validate domain names in the packet
    fn validate_domain_names(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        let mut offset = 12; // Start after header

        // Parse query names (basic validation without full parsing)
        if offset < data.len() {
            // Attempt to validate first query domain name
            self.validate_domain_name_at(data, &mut offset, 0)?;
        }

        Ok(())
    }

    /// Validate a domain name at offset, following pointers
    fn validate_domain_name_at(
        &self,
        data: &[u8],
        offset: &mut usize,
        depth: usize,
    ) -> Result<(), anyhow::Error> {
        const MAX_DEPTH: usize = 10;
        
        if depth > MAX_DEPTH {
            return Err(anyhow!("domain name pointer depth exceeded"));
        }

        let mut label_count = 0;
        let mut total_size = 0;

        loop {
            if *offset >= data.len() {
                return Err(anyhow!("domain name goes beyond packet boundary"));
            }

            let len_byte = data[*offset];
            *offset += 1;

            // Check for pointer (top 2 bits = 11)
            if len_byte & 0xc0 == 0xc0 {
                if *offset >= data.len() {
                    return Err(anyhow!("pointer incomplete"));
                }
                // Skip pointer offset byte (pointer is 2 bytes total, we already consumed first)
                *offset += 1;
                return Ok(()); // Pointers end the name
            }

            // Normal label
            let label_len = len_byte as usize;

            // Root label
            if label_len == 0 {
                return Ok(());
            }

            // Validate label length
            if label_len > self.config.max_label_size {
                return Err(anyhow!(
                    "label length {} exceeds maximum {}",
                    label_len,
                    self.config.max_label_size
                ));
            }

            // Check bounds
            if *offset + label_len > data.len() {
                return Err(anyhow!("label goes beyond packet boundary"));
            }

            *offset += label_len;
            label_count += 1;
            total_size += label_len + 1;

            // Validate counts
            if label_count > self.config.max_labels {
                return Err(anyhow!(
                    "label count {} exceeds maximum {}",
                    label_count,
                    self.config.max_labels
                ));
            }

            if total_size > self.config.max_name_size {
                return Err(anyhow!(
                    "domain name size {} exceeds maximum {}",
                    total_size,
                    self.config.max_name_size
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_small_packet() {
        let validator = RequestValidator::with_defaults();
        
        // Minimal valid DNS query header (12 bytes) + minimal query (www.com.)
        let packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags (query)
            0x00, 0x01, // 1 query
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authorities
            0x00, 0x00, // 0 additionals
            0x03, 0x77, 0x77, 0x77, // "www"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00,       // root
            0x00, 0x01, // A record
            0x00, 0x01, // IN class
        ];
        
        let result = validator.validate_packet(&packet, false);
        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn test_packet_too_large_udp() {
        let validator = RequestValidator::with_defaults();
        let packet = vec![0u8; 513]; // Over 512 byte limit for UDP
        
        let result = validator.validate_packet(&packet, false);
        assert!(!result.is_valid());
        assert!(result
            .error_message()
            .unwrap()
            .contains("exceeds maximum"));
    }

    #[test]
    fn test_packet_size_ok_tcp() {
        let validator = RequestValidator::with_defaults();
        let packet = vec![0u8; 600]; // Valid for TCP
        
        // But invalid because it's malformed DNS
        let result = validator.validate_packet(&packet, true);
        // May fail due to format, but not size
        assert!(result.error_message().is_none() || 
                !result.error_message().unwrap().contains("exceeds maximum"));
    }

    #[test]
    fn test_packet_too_small() {
        let validator = RequestValidator::with_defaults();
        let packet = vec![0u8; 11]; // Less than 12-byte header
        
        let result = validator.validate_packet(&packet, false);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_request_with_answer_section() {
        let validator = RequestValidator::with_defaults();
        
        // Query with QR=0 (request) but answer_count > 0 (invalid)
        let packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags (query, QR=0)
            0x00, 0x00, // 0 queries
            0x00, 0x01, // 1 answer (invalid for request!)
            0x00, 0x00, // 0 authorities
            0x00, 0x00, // 0 additionals
        ];
        
        let result = validator.validate_packet(&packet, false);
        assert!(!result.is_valid());
        assert!(result
            .error_message()
            .unwrap()
            .contains("should not have answer"));
    }

    #[test]
    fn test_request_with_opt_record_is_allowed() {
        let validator = RequestValidator::with_defaults();

        // An EDNS0 query: one question plus an OPT record in the additional
        // section. Rejecting this would reject every EDNS-capable client.
        let packet = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // flags (query, RD)
            0x00, 0x01, // 1 query
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authorities
            0x00, 0x01, // 1 additional (the OPT record)
            0x03, 0x77, 0x77, 0x77, // "www"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // root
            0x00, 0x01, // A
            0x00, 0x01, // IN
            0x00, // OPT name: root
            0x00, 0x29, // type 41 (OPT)
            0x10, 0x00, // class: 4096 payload size
            0x00, 0x00, 0x00, 0x00, // TTL: version 0, no flags
            0x00, 0x00, // RDLENGTH: no options
        ];

        assert!(validator.validate_packet(&packet, false).is_valid());
    }

    #[test]
    fn test_request_with_too_many_additionals() {
        let validator = RequestValidator::with_defaults();

        let packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags (query, QR=0)
            0x00, 0x01, // 1 query
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authorities
            0x00, 0x64, // 100 additionals (over the limit)
        ];

        let result = validator.validate_packet(&packet, false);
        assert!(!result.is_valid());
        assert!(result
            .error_message()
            .unwrap()
            .contains("too many additional"));
    }

    #[test]
    fn test_too_many_queries() {
        let validator = RequestValidator::with_defaults();
        
        let packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags (query)
            0x00, 0x0b, // 11 queries (over limit of 10)
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authorities
            0x00, 0x00, // 0 additionals
        ];
        
        let result = validator.validate_packet(&packet, false);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_response_packet_allowed() {
        let validator = RequestValidator::with_defaults();
        
        // Response (QR=1) with answers is valid
        let packet = vec![
            0x00, 0x01, // ID
            0x80, 0x00, // flags (response, QR=1)
            0x00, 0x00, // 0 queries
            0x00, 0x01, // 1 answer (OK for response)
            0x00, 0x00, // 0 authorities
            0x00, 0x00, // 0 additionals
        ];
        
        let result = validator.validate_packet(&packet, false);
        // Should not fail due to answer count (responses can have answers)
        assert!(result.error_message().is_none() || 
                !result.error_message().unwrap().contains("should not have answer"));
    }

    #[test]
    fn test_oversized_label() {
        let validator = RequestValidator::with_defaults();
        
        // Create packet with a label longer than 63 bytes
        let mut packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags (query)
            0x00, 0x01, // 1 query
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authorities
            0x00, 0x00, // 0 additionals
            0x41,       // Label length: 65 (exceeds 63 max)
        ];
        
        // Add 65 bytes of data
        packet.extend_from_slice(&[0x61; 65]);
        
        let result = validator.validate_packet(&packet, false);
        assert!(!result.is_valid());
        assert!(result
            .error_message()
            .unwrap()
            .contains("label length") || result
            .error_message()
            .unwrap()
            .contains("boundary"));
    }

    #[test]
    fn test_max_tcp_size_accepted() {
        let validator = RequestValidator::with_defaults();
        
        // 16KB should be accepted for TCP
        let packet = vec![0u8; 16 * 1024];
        let result = validator.validate_packet(&packet, true);
        // May fail due to format, but not size
        assert!(result.error_message().is_none() || 
                !result.error_message().unwrap().contains("exceeds maximum"));
    }

    #[test]
    fn test_exceeds_tcp_size() {
        let validator = RequestValidator::with_defaults();
        
        // Exceed 16KB for TCP
        let packet = vec![0u8; 16 * 1024 + 1];
        let result = validator.validate_packet(&packet, true);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_pointer_with_incomplete_offset() {
        let validator = RequestValidator::with_defaults();
        
        let packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags
            0x00, 0x01, // 1 query
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authorities
            0x00, 0x00, // 0 additionals
            0xc0,       // Pointer marker (incomplete)
        ];
        
        let result = validator.validate_packet(&packet, false);
        assert!(!result.is_valid());
    }
}

