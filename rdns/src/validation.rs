use crate::error::{RequestError, RequestResult, WireError};
use crate::{DnsMessage, OpCode};

/// A message that arrived at a listening socket **and is a question**.
///
/// The only way to build one is [`Request::from_bytes`], which refuses QR=1, so
/// a path holding a `Request` has made the check.
///
/// It does not make the omission impossible: [`DnsMessage::try_from_bytes`] is
/// still public and still right for the resolver, for `xfr`, and for tests. What
/// it buys is one named door that all three answering paths go through, so the
/// next one is copied from something that checks. Real teeth would mean
/// `make_response` and its siblings taking `&Request`, which is larger than
/// `TODO.md` #14b scopes.
///
/// The bug: `fn answer` (TCP) tested QR and `answer_datagram` (UDP) never did,
/// and UDP is where it matters — a spoofed datagram naming another server as its
/// source was a packet loop neither end could see.
///
/// A wrapper at the door rather than a split of [`DnsMessage`], because the
/// resolver, `tsig` and `xfr` all need messages that may have QR=1.
///
/// `Deref` gives read access to every field. No `DerefMut` and no `&mut`
/// accessor: `request.response = true` would restore the excluded state.
///
/// It does not run [`AdmissionCheck`], check the opcode, or verify a TSIG.
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

/// Configuration for request validation
#[derive(Debug, Clone)]
pub struct AdmissionLimits {
    /// Largest UDP request accepted (RFC 1035 §4.2.1's 512).
    ///
    /// The doc comment here used to cite "RFC 512", which is not a document.
    pub max_udp_size: usize,
    /// Largest TCP request accepted. Not a protocol limit — the length prefix
    /// allows 65,535 — but a request has no legitimate reason to be larger.
    pub max_tcp_size: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        AdmissionLimits {
            max_udp_size: 512,       // RFC 1035 §4.2.1
            max_tcp_size: 16 * 1024, // not a protocol limit; see the field
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

/// Whether a datagram is worth parsing at all.
///
/// **Named for what it does, which is not validation** (`TODO.md` #19e). It was
/// `RequestValidator`, and the name was a claim it could not keep: two of the
/// three things it did were cheap header arithmetic with no equivalent in the
/// parser, and the third was a second, weaker copy of the parser's own name
/// rules that ran *first*. The copy is gone; what is left is an admission
/// check — size caps and per-section count caps, on bytes nothing has trusted
/// yet, before anything is allocated.
///
/// The distinction matters at the call site. A caller reaching for a
/// "validator" reasonably assumes a packet that passes is well formed, and it is
/// not: `DnsMessage::try_from_bytes` is the thing that decides that, and it runs
/// afterwards.
pub struct AdmissionCheck {
    config: AdmissionLimits,
}

impl AdmissionCheck {
    pub fn new(config: AdmissionLimits) -> Self {
        AdmissionCheck { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(AdmissionLimits::default())
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

        // **No name walk here.** There used to be one, and it was a second,
        // weaker implementation of what `dname.rs` does immediately afterwards:
        // its own label-length check, its own 255-octet check and its own
        // pointer handling. The two already disagreed in four ways
        // (`TODO.md` #19e) — `MAX_DEPTH` 10 against 50, no requirement that a
        // pointer point backwards (which is the whole of `dname.rs`'s cycle
        // prevention), only the *first* question validated, and a `total_size`
        // omitting the terminating root octet, so it admitted a name one octet
        // over the limit.
        //
        // All four erred safe, because the real parser ran afterwards. That is
        // the argument for deleting them rather than for keeping them: they were
        // two implementations of one rule where the weaker one ran first, and
        // the safe direction was a property of the call order rather than of the
        // code. What is left is the part with no equivalent in the parser.
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

        // Which sections a request may carry is a question per section. A blanket
        // rule has silently killed a feature three times: the message is dropped
        // before anything reads the opcode, so nothing says why.
        //
        // - Answer: empty in a QUERY, but a NOTIFY carries the zone's SOA
        //   (RFC 1996 §3.7). Forbidden for QUERY, capped otherwise.
        // - Authority: cannot be forbidden — an IXFR request is a QUERY carrying
        //   the client's current SOA there (RFC 1995 §3). Capped.
        // - Additional: where a request carries its OPT (RFC 6891 §6.1.1) and its
        //   TSIG/SIG(0), so forbidding it kills every signed or EDNS query, which
        //   it used to. Capped.
        //
        // A cap rather than a prohibition: a statement about resources rather
        // than a guess about which protocol extensions exist.
        // Read through the types rather than by shifting bits here: `OpCode`
        // and the QR flag both have one definition already, and a second
        // hand-rolled one is how the two come to disagree (`TODO.md` #19e).
        let qr_flag = data[2] & 0x80 != 0;
        let opcode = OpCode::from_u8((data[2] >> 3) & 0x0f);
        if !qr_flag {
            if opcode == OpCode::Query && answer_count > 0 {
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
        let validator = AdmissionCheck::with_defaults();

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
        let validator = AdmissionCheck::with_defaults();
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
        let validator = AdmissionCheck::with_defaults();
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
        let validator = AdmissionCheck::with_defaults();
        let packet = vec![0u8; 11]; // Less than 12-byte header

        let result = validator.validate_packet(&packet, false);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_request_with_answer_section() {
        let validator = AdmissionCheck::with_defaults();

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
        let validator = AdmissionCheck::with_defaults();
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
        let validator = AdmissionCheck::with_defaults();

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
        let validator = AdmissionCheck::with_defaults();

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
        let validator = AdmissionCheck::with_defaults();

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
        let validator = AdmissionCheck::with_defaults();

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

    /// **A fifth way the two name checks disagreed, found by re-pointing this
    /// test rather than by reading either of them.**
    ///
    /// `TODO.md` #19e listed four disagreements between the admission check's
    /// name walk and `dname.rs`. Here is the fifth: this test was called
    /// `test_oversized_label` and its packet carries `0x41`, described in its
    /// own comment as "Label length: 65 (exceeds 63 max)". It is not a length at
    /// all. The top two bits of a length octet are a *type* (RFC 1035 §4.1.4),
    /// and `01` is RFC 2673's binary label — so `dname.rs` calls it
    /// `Unsupported { what: "a binary label" }`, which is right, while the
    /// deleted copy read the low six bits as a length and called it `TooLong`,
    /// which is not.
    ///
    /// A label longer than 63 octets cannot be spelled on the wire in the first
    /// place: `00` is the only type that means "a length", and six bits hold 63.
    /// So the check that was deleted was rejecting an impossible case with the
    /// wrong reason, and the test agreed with it because both were written from
    /// the same misreading — `CLAUDE.md` §1, exactly.
    #[test]
    fn an_extended_label_type_is_refused_by_the_parser() {
        let mut packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags (query)
            0x00, 0x01, // 1 query
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authorities
            0x00, 0x00, // 0 additionals
            0x41, // *not* a length: top bits `01` is RFC 2673's binary label
        ];
        packet.extend_from_slice(&[0x61; 65]);

        // Admitted: it is small, and its counts are sane. That is all this check
        // now claims to know.
        assert!(AdmissionCheck::with_defaults()
            .validate_packet(&packet, false)
            .is_valid());

        // And refused a moment later, by the one implementation of the rule,
        // with the reason that is actually true of these bytes.
        let err = DnsMessage::try_from_bytes(&packet).expect_err("an extended label type");
        assert!(
            matches!(
                err,
                WireError::Unsupported {
                    what: "a binary label"
                }
            ),
            "asserting on the variant, not the message (`CLAUDE.md` §3): {err:?}"
        );
    }

    #[test]
    fn test_max_tcp_size_accepted() {
        let validator = AdmissionCheck::with_defaults();

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
        let validator = AdmissionCheck::with_defaults();

        // Exceed 16KB for TCP
        let packet = vec![0u8; 16 * 1024 + 1];
        let result = validator.validate_packet(&packet, true);
        assert!(!result.is_valid());
    }

    /// A truncated compression pointer is refused by the parser, for the same
    /// reason as the test above. `dname.rs` is also the only one of the two that
    /// ever required a pointer to point *backwards*, which is the whole of its
    /// cycle prevention.
    #[test]
    fn a_truncated_pointer_is_refused_by_the_parser() {
        let packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags
            0x00, 0x01, // 1 query
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authorities
            0x00, 0x00, // 0 additionals
            0xc0, // a pointer marker with no second octet
        ];

        assert!(AdmissionCheck::with_defaults()
            .validate_packet(&packet, false)
            .is_valid());
        assert!(DnsMessage::try_from_bytes(&packet).is_err());
    }
}
