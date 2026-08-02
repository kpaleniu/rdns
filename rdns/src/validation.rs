use crate::error::{RequestError, RequestResult, WireError};
use crate::DnsMessage;

/// A message that arrived at a listening socket **and is a question**.
///
/// The only way to build one is [`Request::from_bytes`], which refuses QR=1. So
/// a path holding a `Request` has made the check, and "did this one remember?"
/// is answered by its type rather than by reading fifty lines of it.
///
/// **What that is and is not worth, stated plainly, because a doc comment
/// asserting an invariant is a claim to verify (`CLAUDE.md` §4).** This does
/// *not* make the omission impossible: [`DnsMessage::try_from_bytes`] is still
/// public and still the right call for the resolver, for `xfr`, and for a test.
/// A new answering path could call it and skip the check exactly as
/// `answer_datagram` did. What changed is that there is now one named door with
/// the reason attached to it, that both of `rdnsd`'s answering paths and
/// `rdnsr`'s go through it, and that the drop decision is written once instead
/// of once per path — so the next path is *copied from* something that checks,
/// rather than from something that happened not to. Real teeth would mean
/// `make_response` and its siblings taking `&Request`, which is a larger change
/// than `TODO.md` #14b scopes and would push every unit test of them through a
/// serialize-and-reparse round trip.
///
/// **The bug this is the fix for is in the log.** `CLAUDE.md` §8 has said "test
/// QR before doing anything with a packet that arrived at a listening socket, on
/// both daemons" since before either of `rdnsd`'s two answering paths was last
/// touched. `fn answer` (TCP) had the check; `answer_datagram` (UDP) never did,
/// and UDP is the transport it matters on — nothing makes the peer prove its
/// address first, so a spoofed datagram naming another server as its source was
/// a packet loop neither end could see. `rdnsr` has one `handle_query` shared by
/// both of its transports and so could not drift. Two answering paths, one
/// check: §7's shape, and §17's answer to it — a rule written down is a rule
/// somebody has to remember, and a type is not.
///
/// **A wrapper at the door, not a split of [`DnsMessage`].** The resolver sends
/// queries and reads responses, `tsig` verifies both directions of the wire, and
/// `xfr` reads a stream of replies; all of those need a message that may have
/// QR=1, and none of them is a socket a stranger can talk to. So `DnsMessage`
/// keeps its `response` field and this type is the narrow thing that guards the
/// one place where the answer is fixed.
///
/// `Deref` gives read access to every field, and there is deliberately **no
/// `DerefMut` and no `&mut` accessor**: `request.response = true` would put the
/// value back in the state the type exists to exclude.
///
/// **What it does not do**, so nothing reads more into it than is there: it does
/// not run [`RequestValidator`] (which is configured per server and, on UDP,
/// runs before admission so a datagram is rejected before it is copied), it does
/// not check the opcode (that is each daemon's policy, and the answer is NOTIMP
/// rather than silence), and it does not verify a TSIG. It answers one question,
/// and it answers it every time.
#[derive(Debug, Clone)]
pub struct Request(DnsMessage);

impl Request {
    /// Parse a packet that arrived at a socket this server is listening on.
    ///
    /// `Err(RequestError::NotAQuestion)` for QR=1, and the caller's only correct
    /// response to that is **silence**: there is no reply to send, because the
    /// sender did not ask anything, and sending one is what closes the loop.
    pub fn from_bytes(packet: &[u8]) -> RequestResult<Request> {
        let msg = DnsMessage::try_from_bytes(packet)?;
        if msg.response {
            return Err(RequestError::NotAQuestion);
        }
        Ok(Request(msg))
    }

    /// The message, for the code that builds a reply to it.
    pub fn message(&self) -> &DnsMessage {
        &self.0
    }
}

impl std::ops::Deref for Request {
    type Target = DnsMessage;

    fn deref(&self) -> &DnsMessage {
        &self.0
    }
}

/// Upper bound on additional records in a request. A legitimate request carries
/// at most an OPT plus a TSIG/SIG(0); the slack is for forward compatibility.
const MAX_REQUEST_ADDITIONALS: usize = 4;

/// The QUERY opcode, which is the only one whose requests carry no records of
/// their own — see the section checks in [`RequestValidator::validate_header`].
const OPCODE_QUERY: u8 = 0;

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
            max_udp_size: 512,       // RFC 1035 standard
            max_tcp_size: 16 * 1024, // 16KB for TCP
            max_labels: 127,         // RFC 1035 limit
            max_label_size: 63,      // RFC 1035 limit
            max_name_size: 255,      // RFC 1035 limit
        }
    }
}

/// Result of validation
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Valid,
    Invalid(WireError),
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }

    /// Why the packet was rejected, as something a caller can branch on.
    ///
    /// Typed rather than a message, because the decision this feeds is a
    /// *response code*: [`WireError::Unsupported`] is NOTIMP and the rest are
    /// FORMERR. Stringifying it here threw that away and forced every caller to
    /// grep the wording.
    pub fn error(&self) -> Option<&WireError> {
        match self {
            ValidationResult::Valid => None,
            ValidationResult::Invalid(why) => Some(why),
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
            return ValidationResult::Invalid(WireError::TooLong {
                what: "the packet",
                limit: max_size,
                actual: data.len(),
            });
        }

        // Minimum DNS header size
        if data.len() < 12 {
            return ValidationResult::Invalid(WireError::Truncated {
                what: "the DNS header",
                need: 12,
                have: data.len(),
            });
        }

        // Validate header structure
        if let Err(e) = self.validate_header(data) {
            return ValidationResult::Invalid(e);
        }

        // Parse and validate domain names in queries
        if let Err(e) = self.validate_domain_names(data) {
            return ValidationResult::Invalid(e);
        }

        ValidationResult::Valid
    }

    /// Validate DNS header format
    fn validate_header(&self, data: &[u8]) -> Result<(), WireError> {
        if data.len() < 12 {
            return Err(WireError::Truncated {
                what: "the DNS header",
                need: 12,
                have: data.len(),
            });
        }

        // Parse counts from header
        let query_count = u16::from_be_bytes([data[4], data[5]]) as usize;
        let answer_count = u16::from_be_bytes([data[6], data[7]]) as usize;
        let auth_count = u16::from_be_bytes([data[8], data[9]]) as usize;
        let add_count = u16::from_be_bytes([data[10], data[11]]) as usize;

        // Sanity checks
        if query_count > 10 {
            return Err(WireError::TooLong {
                what: "the question count",
                limit: 10,
                actual: query_count,
            });
        }

        // Which sections a *request* may carry is a question per section, not one
        // blanket rule — and the blanket version of it has now silently killed a
        // feature three times, because the symptom is always the same: the
        // message is dropped before anything reads the opcode, so the feature
        // simply never happens and nothing says why.
        //
        // - **The answer section** is empty in a QUERY: no query type carries
        //   answers to a question it is still asking. A **NOTIFY** does carry
        //   one — the zone's SOA (RFC 1996 §3.7), which is how a secondary learns
        //   the new serial without asking a second question. Forbidden for QUERY,
        //   capped otherwise.
        // - **The authority section** cannot be forbidden at all: an **IXFR**
        //   request is a QUERY that carries the client's current SOA there
        //   (RFC 1995 §3), and that record is the whole of what makes it
        //   incremental rather than an AXFR. Capped.
        // - **The additional section** is where a request carries its OPT (EDNS0,
        //   RFC 6891 §6.1.1) and its TSIG/SIG(0), so rejecting a non-empty one
        //   rejects every signed or EDNS query — which is precisely what it used
        //   to do, leaving EDNS dead on arrival. Capped.
        //
        // A cap rather than a prohibition is the shape this check wants: a
        // request has no legitimate reason to carry many records, and that is a
        // statement about resources rather than a guess about which protocol
        // extensions exist.
        let qr_flag = data[2] & 0x80 != 0;
        let opcode = (data[2] >> 3) & 0x0f;
        if !qr_flag {
            if opcode == OPCODE_QUERY && answer_count > 0 {
                return Err(WireError::malformed(
                    "a request",
                    "a QUERY carries no answer records",
                ));
            }
            if answer_count > MAX_REQUEST_ADDITIONALS || auth_count > MAX_REQUEST_ADDITIONALS {
                return Err(WireError::TooLong {
                    what: "the answer and authority counts of a request",
                    limit: MAX_REQUEST_ADDITIONALS,
                    actual: answer_count.max(auth_count),
                });
            }
            if add_count > MAX_REQUEST_ADDITIONALS {
                return Err(WireError::TooLong {
                    what: "the additional count of a request",
                    limit: MAX_REQUEST_ADDITIONALS,
                    actual: add_count,
                });
            }
        }

        Ok(())
    }

    /// Validate domain names in the packet
    fn validate_domain_names(&self, data: &[u8]) -> Result<(), WireError> {
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
    ) -> Result<(), WireError> {
        const MAX_DEPTH: usize = 10;

        if depth > MAX_DEPTH {
            return Err(WireError::TooLong {
                what: "compression pointer nesting",
                limit: MAX_DEPTH,
                actual: depth,
            });
        }

        let mut label_count = 0;
        let mut total_size = 0;

        loop {
            if *offset >= data.len() {
                return Err(WireError::Truncated {
                    what: "a domain name",
                    need: *offset + 1,
                    have: data.len(),
                });
            }

            let len_byte = data[*offset];
            *offset += 1;

            // Check for pointer (top 2 bits = 11)
            if len_byte & 0xc0 == 0xc0 {
                if *offset >= data.len() {
                    return Err(WireError::Truncated {
                        what: "a compression pointer",
                        need: 2,
                        // Cannot underflow, and the proof is four lines up: the
                        // loop head returns unless `*offset < data.len()`, and
                        // only one byte has been consumed since, so reaching
                        // here means `*offset == data.len()` exactly. Written
                        // down because this is a subtraction of two
                        // wire-derived lengths on the pre-authentication path
                        // (`TODO.md` #12) — the class of thing that is safe
                        // until somebody adds a second `+= 1` above it.
                        have: data.len() - *offset,
                    });
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
                return Err(WireError::TooLong {
                    what: "a label",
                    limit: self.config.max_label_size,
                    actual: label_len,
                });
            }

            // Check bounds
            if *offset + label_len > data.len() {
                return Err(WireError::Truncated {
                    what: "a label",
                    need: *offset + label_len,
                    have: data.len(),
                });
            }

            *offset += label_len;
            label_count += 1;
            total_size += label_len + 1;

            // Validate counts
            if label_count > self.config.max_labels {
                return Err(WireError::TooLong {
                    what: "the label count of a domain name",
                    limit: self.config.max_labels,
                    actual: label_count,
                });
            }

            if total_size > self.config.max_name_size {
                return Err(WireError::TooLong {
                    what: "a domain name",
                    limit: self.config.max_name_size,
                    actual: total_size,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same 25-byte query as `test_valid_small_packet`, with the QR bit the
    /// only thing that moves between the two calls below.
    fn query_packet(response: bool) -> Vec<u8> {
        let mut packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags: QR=0, opcode QUERY
            0x00, 0x01, // 1 query
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no other sections
            0x03, 0x77, 0x77, 0x77, // "www"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // root
            0x00, 0x01, // A
            0x00, 0x01, // IN
        ];
        if response {
            packet[2] |= 0x80;
        }
        packet
    }

    /// A response arriving at a listening socket is not a question, and the
    /// answer is silence (`CLAUDE.md` §8).
    ///
    /// **Not a failing-first regression test, and it should not be read as
    /// one.** The defect this type exists for — `rdnsd` answering a response on
    /// its UDP port — was fixed at the call site in an earlier commit, so there
    /// is nothing left here to watch fail (`CLAUDE.md` §1). What this asserts is
    /// that the constructor refuses; what actually stops the defect coming back
    /// is that there is no other constructor, and that is a compile-time fact no
    /// test can express.
    #[test]
    fn a_response_is_not_a_request() {
        assert!(matches!(
            Request::from_bytes(&query_packet(true)),
            Err(RequestError::NotAQuestion)
        ));

        let request = Request::from_bytes(&query_packet(false)).expect("a question parses");
        assert!(!request.response, "and it is still a question afterwards");
        assert_eq!(request.queries[0].qname, "www.com.");
    }

    /// The two failure modes stay apart, because they are different operational
    /// signals: garbage or a parser probe, against a traffic loop.
    #[test]
    fn a_malformed_packet_is_not_reported_as_a_response() {
        assert!(matches!(
            Request::from_bytes(&[0x00, 0x01, 0x00]),
            Err(RequestError::Wire(_))
        ));
    }

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
            0x00, // root
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
        assert!(
            matches!(
                result.error(),
                Some(WireError::TooLong {
                    what: "the packet",
                    ..
                })
            ),
            "got {result:?}"
        );
    }

    #[test]
    fn test_packet_size_ok_tcp() {
        let validator = RequestValidator::with_defaults();
        let packet = vec![0u8; 600]; // Valid for TCP

        // But invalid because it's malformed DNS
        let result = validator.validate_packet(&packet, true);
        // May fail due to format, but not size
        assert!(
            !matches!(
                result.error(),
                Some(WireError::TooLong {
                    what: "the packet",
                    ..
                })
            ),
            "600 bytes is under the TCP limit, so any failure here is not about size"
        );
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
        assert!(
            matches!(
                result.error(),
                Some(WireError::Malformed {
                    what: "a request",
                    ..
                })
            ),
            "got {result:?}"
        );
    }

    /// A NOTIFY carries the zone's SOA in its answer section (RFC 1996 §3.7),
    /// and an IXFR request carries the client's SOA in its authority section
    /// (RFC 1995 §3). Rejecting either here is invisible — the message is
    /// dropped before anything reads the opcode — and it made NOTIFY silently
    /// undeliverable to this server's own secondary role until a live test
    /// caught it.
    #[test]
    fn test_a_notify_may_carry_its_soa_and_an_ixfr_may_carry_its_own() {
        let validator = RequestValidator::with_defaults();
        let header = |opcode: u8, answers: u8, authorities: u8| {
            vec![
                0x00,
                0x01,        // ID
                opcode << 3, // flags: QR=0, this opcode
                0x00,        //
                0x00,
                0x01, // 1 query
                0x00,
                answers, //
                0x00,
                authorities, //
                0x00,
                0x00, // 0 additionals
                0x07,
                0x65,
                0x78,
                0x61,
                0x6d,
                0x70,
                0x6c,
                0x65, // "example"
                0x03,
                0x63,
                0x6f,
                0x6d,
                0x00, // "com."
                0x00,
                0x06, // SOA
                0x00,
                0x01, // IN
            ]
        };

        assert!(
            validator
                .validate_packet(&header(4, 1, 0), false)
                .is_valid(),
            "a NOTIFY carrying the new SOA must reach the server"
        );
        assert!(
            validator
                .validate_packet(&header(0, 0, 1), false)
                .is_valid(),
            "an IXFR request is a QUERY carrying its SOA in the authority section"
        );
        assert!(
            !validator
                .validate_packet(&header(4, 40, 0), false)
                .is_valid(),
            "the sections are capped rather than unbounded"
        );
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
        assert!(
            matches!(
                result.error(),
                Some(WireError::TooLong {
                    what: "the additional count of a request",
                    ..
                })
            ),
            "got {result:?}"
        );
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
        assert!(
            !matches!(
                result.error(),
                Some(WireError::Malformed {
                    what: "a request",
                    ..
                })
            ),
            "a response may carry answers, got {result:?}"
        );
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
            0x41, // Label length: 65 (exceeds 63 max)
        ];

        // Add 65 bytes of data
        packet.extend_from_slice(&[0x61; 65]);

        let result = validator.validate_packet(&packet, false);
        assert!(!result.is_valid());
        assert!(
            matches!(
                result.error(),
                Some(WireError::TooLong {
                    what: "a label",
                    ..
                }) | Some(WireError::Truncated {
                    what: "a label",
                    ..
                })
            ),
            "got {result:?}"
        );
    }

    #[test]
    fn test_max_tcp_size_accepted() {
        let validator = RequestValidator::with_defaults();

        // 16KB should be accepted for TCP
        let packet = vec![0u8; 16 * 1024];
        let result = validator.validate_packet(&packet, true);
        // May fail due to format, but not size
        assert!(
            !matches!(
                result.error(),
                Some(WireError::TooLong {
                    what: "the packet",
                    ..
                })
            ),
            "600 bytes is under the TCP limit, so any failure here is not about size"
        );
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
            0xc0, // Pointer marker (incomplete)
        ];

        let result = validator.validate_packet(&packet, false);
        assert!(!result.is_valid());
    }
}
