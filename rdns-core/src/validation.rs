use crate::error::{AnswerMismatch, RequestError, RequestResult, WireError};
use crate::{DnsMessage, NameRef, OpCode, Qtype, QueryClass};

/// A message that arrived at a listening socket and is a question.
///
/// The only constructor is [`Request::from_bytes`], which refuses QR=1: a
/// response answered at a listening socket is a packet loop neither end can see.
/// A wrapper rather than a split of [`DnsMessage`], because the resolver, `tsig`
/// and `xfr` all need messages that may have QR=1.
///
/// `Deref` only — `request.response = true` would restore the excluded state.
///
/// It does not run [`AdmissionCheck`], check the opcode, or verify a TSIG.
#[derive(Debug, Clone)]
pub struct Request(DnsMessage);

impl Request {
    /// Parse a packet that arrived at a socket this server is listening on.
    ///
    /// `Err(RequestError::NotAQuestion)` for QR=1; the only correct reply to
    /// that is silence, since replying is what closes the loop.
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

/// The query a reply has to answer, as it went on the wire.
///
/// The mirror of [`Request`]: that one is the door for what arrives at a
/// listening socket, this is the check on what comes back to a client one.
/// Borrowed, because the caller still holds the message it built.
#[derive(Debug, Clone, Copy)]
pub struct SentQuery<'a> {
    pub id: u16,
    /// The QNAME as it was sent — scrambled case included.
    pub qname: NameRef<'a>,
    pub qtype: Qtype,
    pub qclass: QueryClass,
    /// Compare the name byte for byte rather than folding ASCII case. DNS-0x20
    /// puts entropy in the casing, and entropy nobody compares is none; without
    /// it the compare must fold, because a server may echo the question in any
    /// case (RFC 4343).
    pub case_sensitive: bool,
}

/// Whether `reply` answers `sent` (RFC 5452 §9.1).
///
/// §9.1 lists five attributes a resolver MUST match: both addresses, the source
/// port, the id, the name, and the class and type. A `connect`ed socket leaves
/// the kernel to enforce the first three, so this is the rest of the list — and
/// the type and class half of it is what the resolver's own copy of this check
/// did not have (`TODO.md` #30o).
pub fn answers_query(reply: &DnsMessage, sent: &SentQuery) -> Result<(), AnswerMismatch> {
    if !reply.response {
        return Err(AnswerMismatch::NotAResponse);
    }
    if reply.id != sent.id {
        return Err(AnswerMismatch::Id {
            got: reply.id,
            want: sent.id,
        });
    }
    let Some(echoed) = reply.queries.first() else {
        return Err(AnswerMismatch::NoQuestion);
    };
    // 0x20 compares the echo octet for octet; otherwise `Name`'s own `Eq`,
    // which folds ASCII and nothing else (RFC 4343).
    let name_matches = if sent.case_sensitive {
        echoed.qname.as_ref().as_wire() == sent.qname.as_wire()
    } else {
        echoed.qname == sent.qname
    };
    if !name_matches || echoed.qtype != sent.qtype || echoed.qclass != sent.qclass {
        return Err(AnswerMismatch::Question {
            got: format!("{} {} {:?}", echoed.qname, echoed.qtype, echoed.qclass),
            want: format!("{} {} {:?}", sent.qname, sent.qtype, sent.qclass),
        });
    }
    Ok(())
}

/// Which transport a message arrived on.
///
/// Not a bool: it decides the admission size cap below (RFC 1035 §4.2.1's 512
/// against a ceiling we chose), whether a reply may be truncated, and whether
/// the peer completed a handshake — three questions one `is_tcp` was answering.
///
/// Here rather than in `rdns_transport`, where it was until `TODO.md` #40c,
/// because this is the module that reads it: an enum one crate above the
/// decision it makes has to be converted back to the bool it replaced at the
/// call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// Upper bound on additional records in a request. A legitimate request carries
/// at most an OPT plus a TSIG/SIG(0); the slack is for forward compatibility.
const MAX_REQUEST_ADDITIONALS: usize = 4;

/// The two size caps admission applies, one per transport.
///
/// `pub(crate)`: nothing outside builds one, and [`AdmissionCheck::with_defaults`]
/// is the only constructor anything reaches for. So the caps are not
/// configurable at all today, which is `TODO.md` #40f's question — a `pub` type
/// nobody constructs was not an answer to it (`CLAUDE.md` §14).
#[derive(Debug, Clone)]
pub(crate) struct AdmissionLimits {
    /// Largest UDP request accepted (RFC 1035 §4.2.1's 512).
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

/// Whether a packet is worth parsing, and if not, the typed reason.
///
/// `pub` because [`AdmissionCheck::validate_packet`] returns it and
/// `rdns_transport` calls that; narrowing it is a private-in-public error
/// (`TODO.md` #40e).
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Valid,
    Invalid(WireError),
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }

    /// Why the packet was rejected. Typed because it decides a response code:
    /// [`WireError::Unsupported`] is NOTIMP, the rest FORMERR.
    pub fn error(&self) -> Option<&WireError> {
        match self {
            ValidationResult::Valid => None,
            ValidationResult::Invalid(why) => Some(why),
        }
    }
}

/// Whether a datagram is worth parsing at all: size caps and per-section count
/// caps, applied before anything is allocated.
///
/// Not validation. A packet that passes is not known to be well formed;
/// [`DnsMessage::try_from_bytes`] decides that, afterwards.
pub struct AdmissionCheck {
    config: AdmissionLimits,
}

impl AdmissionCheck {
    pub(crate) fn new(config: AdmissionLimits) -> Self {
        AdmissionCheck { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(AdmissionLimits::default())
    }

    /// Whether `data` is worth parsing, at the cap its transport sets.
    pub fn validate_packet(&self, data: &[u8], transport: Transport) -> ValidationResult {
        let max_size = match transport {
            Transport::Tcp => self.config.max_tcp_size,
            Transport::Udp => self.config.max_udp_size,
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

        // No name walk here: `dname.rs` owns the label, length and pointer
        // rules, and a second implementation only drifts from it.
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

        // Per section, and capped rather than forbidden — a cap is a statement
        // about resources, not a guess about which extensions exist:
        //
        // - Answer: empty in a QUERY, but a NOTIFY carries the zone's SOA
        //   (RFC 1996 §3.7).
        // - Authority: an IXFR request is a QUERY carrying the client's SOA
        //   there (RFC 1995 §3).
        // - Additional: the OPT (RFC 6891 §6.1.1) and the TSIG/SIG(0).
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
    use crate::name::nm;

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

    /// RFC 5452 §9.1's list, minus what the socket enforces: the id, the name,
    /// and "Query class and type" — which the resolver's own copy of this check
    /// did not have, so an upstream (or a spoofer past the id) could answer an A
    /// query with an MX question echoed and be believed (`TODO.md` #30o).
    #[test]
    fn an_answer_matches_the_question_type_and_class_too() {
        let asked = DnsMessage::try_from_bytes(&query_packet(false)).expect("a question");
        let sent = SentQuery {
            id: asked.id,
            qname: asked.queries[0].qname.as_ref(),
            qtype: asked.queries[0].qtype,
            qclass: asked.queries[0].qclass,
            case_sensitive: false,
        };

        let mut reply = DnsMessage::reply_to(&asked);
        assert_eq!(answers_query(&reply, &sent), Ok(()));

        reply.queries[0].qtype = Qtype::of(crate::record_types::MX);
        assert!(matches!(
            answers_query(&reply, &sent),
            Err(AnswerMismatch::Question { .. })
        ));

        let mut reply = DnsMessage::reply_to(&asked);
        reply.queries[0].qclass = QueryClass::CH;
        assert!(matches!(
            answers_query(&reply, &sent),
            Err(AnswerMismatch::Question { .. })
        ));

        // The name folds ASCII case without DNS-0x20 (RFC 4343) and is compared
        // byte for byte with it, since that is where the entropy is.
        let mut reply = DnsMessage::reply_to(&asked);
        reply.queries[0].qname = nm(&reply.queries[0]
            .qname
            .as_ref()
            .to_presentation()
            .to_uppercase());
        assert_eq!(answers_query(&reply, &sent), Ok(()));
        let strict = SentQuery {
            case_sensitive: true,
            ..sent
        };
        assert!(matches!(
            answers_query(&reply, &strict),
            Err(AnswerMismatch::Question { .. })
        ));

        // And the two that are not about the question at all.
        let mut wrong_id = DnsMessage::reply_to(&asked);
        wrong_id.id = asked.id.wrapping_add(1);
        assert!(matches!(
            answers_query(&wrong_id, &sent),
            Err(AnswerMismatch::Id { .. })
        ));

        let mut query = DnsMessage::reply_to(&asked);
        query.response = false;
        assert_eq!(
            answers_query(&query, &sent),
            Err(AnswerMismatch::NotAResponse)
        );

        let mut silent = DnsMessage::reply_to(&asked);
        silent.queries.clear();
        assert_eq!(
            answers_query(&silent, &sent),
            Err(AnswerMismatch::NoQuestion)
        );
    }

    /// A response arriving at a listening socket is not a question, and the
    /// answer is silence.
    ///
    /// Asserts only that the constructor refuses; what stops the defect
    /// recurring is that there is no other constructor.
    #[test]
    fn a_response_is_not_a_request() {
        assert!(matches!(
            Request::from_bytes(&query_packet(true)),
            Err(RequestError::NotAQuestion)
        ));

        let request = Request::from_bytes(&query_packet(false)).expect("a question parses");
        assert!(!request.response, "and it is still a question afterwards");
        assert_eq!(request.queries[0].qname, nm("www.com."));
    }

    /// Garbage and a traffic loop are different operational signals.
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

        let result = validator.validate_packet(&packet, Transport::Udp);
        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn test_packet_too_large_udp() {
        let validator = AdmissionCheck::with_defaults();
        let packet = vec![0u8; 513]; // Over 512 byte limit for UDP

        let result = validator.validate_packet(&packet, Transport::Udp);
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
        let result = validator.validate_packet(&packet, Transport::Tcp);
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

        let result = validator.validate_packet(&packet, Transport::Udp);
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

        let result = validator.validate_packet(&packet, Transport::Udp);
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
    /// dropped before anything reads the opcode.
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
                .validate_packet(&header(4, 1, 0), Transport::Udp)
                .is_valid(),
            "a NOTIFY carrying the new SOA must reach the server"
        );
        assert!(
            validator
                .validate_packet(&header(0, 0, 1), Transport::Udp)
                .is_valid(),
            "an IXFR request is a QUERY carrying its SOA in the authority section"
        );
        assert!(
            !validator
                .validate_packet(&header(4, 40, 0), Transport::Udp)
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

        assert!(validator
            .validate_packet(&packet, Transport::Udp)
            .is_valid());
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

        let result = validator.validate_packet(&packet, Transport::Udp);
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

        let result = validator.validate_packet(&packet, Transport::Udp);
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

        let result = validator.validate_packet(&packet, Transport::Udp);
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

    /// The top two bits of a length octet are a type (RFC 1035 §4.1.4), and `01`
    /// is RFC 2673's binary label — not an oversized length. A label longer than
    /// 63 octets cannot be spelled on the wire at all.
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

        // Admitted: small, sane counts. That is all this check claims to know.
        assert!(AdmissionCheck::with_defaults()
            .validate_packet(&packet, Transport::Udp)
            .is_valid());

        // And refused by the one implementation of the rule.
        let err = DnsMessage::try_from_bytes(&packet).expect_err("an extended label type");
        assert!(
            matches!(
                err,
                WireError::Unsupported {
                    what: "a binary label"
                }
            ),
            "asserting on the variant, not the message: {err:?}"
        );
    }

    #[test]
    fn test_max_tcp_size_accepted() {
        let validator = AdmissionCheck::with_defaults();

        // 16KB should be accepted for TCP
        let packet = vec![0u8; 16 * 1024];
        let result = validator.validate_packet(&packet, Transport::Tcp);
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
        let result = validator.validate_packet(&packet, Transport::Tcp);
        assert!(!result.is_valid());
    }

    /// A truncated compression pointer is the parser's business, not this
    /// check's.
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
            .validate_packet(&packet, Transport::Udp)
            .is_valid());
        assert!(DnsMessage::try_from_bytes(&packet).is_err());
    }
}
