//! What has to be true of a packet before anything acts on it, on either side
//! of the wire.
//!
//! Three questions, in the order they are asked, and the membership rule is that
//! all three are answerable from the packet alone:
//!
//! - **Is it worth parsing?** [`AdmissionCheck`] — size and section-count caps
//!   applied before a byte is allocated, at the cap the [`Transport`] sets.
//! - **Is it a question for us?** [`Request`], the one door anything a stranger
//!   can reach goes through, and the only thing that refuses QR=1.
//! - **Does this reply answer what we asked?** [`answers_query`] against a
//!   [`SentQuery`], which is RFC 5452 §9.1's list minus the three a `connect`ed
//!   socket enforces.
//!
//! What is deliberately not here: whether the packet is *well formed*, which is
//! [`DnsMessage::try_from_bytes`] and happens after admission; who the sender is
//! (`rdns::tsig`, a different question, and `CLAUDE.md` §16 is why it must stay
//! one); and what the sender may *do*, which is policy and needs a
//! configuration this module never sees.

use std::sync::Arc;

use crate::edns::CLASSIC_UDP_SIZE;
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

/// What the connection a message arrived on hid from the path it crossed.
///
/// Separate from [`Transport`] rather than two more variants of it, because
/// they answer different questions and the same message can want both: DoT is
/// framed like TCP and private like nothing else, and every size and
/// truncation rule keyed on `Transport` would have had to learn the new
/// variants to keep saying the same thing.
///
/// The version matters, which is why this is not a bool. RFC 9103 §7.2: "All
/// implementations of this specification MUST use only TLS 1.3 \[RFC8446\] or
/// later" — so a zone transfer over a 1.2 connection is not XFR-over-TLS, while
/// a *query* over one is ordinary DoT (RFC 7858 §4.1 asks only for 1.2 or
/// later).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privacy {
    /// Plain UDP or TCP: everyone on the path read it.
    Clear,
    /// TLS 1.3 or later. DoQ is always this — RFC 9001 §4.2, "QUIC ... MUST use
    /// TLS 1.3 or greater" — and DoT and DoH are when they negotiate it.
    Tls13,
    /// TLS older than 1.3. Good enough for a query, not for a transfer.
    TlsOlder,
}

impl Privacy {
    /// Whether a zone transfer may be answered over this, when the operator
    /// has asked that transfers be encrypted (RFC 9103 §7.2, §11).
    pub fn is_xot(&self) -> bool {
        matches!(self, Privacy::Tls13)
    }
}

/// Which protocol carried a message, and what it negotiated.
///
/// Three questions, three types, and this one answers the other two.
/// [`Transport`] is "what size may this answer be"; [`Privacy`] is "what did
/// the connection hide"; this is "what was it called", which dnstap's
/// `SocketProtocol` wants and neither of the others can give — DoT, DoH and DoQ
/// are one [`Privacy`] and one [`Transport`] between them (`TODO.md` #54).
///
/// An enum with the TLS version inside rather than a `{ protocol, privacy }`
/// pair, because the pair can be written down wrong: `Tcp` with `Tls13`, or
/// `Doq` with `TlsOlder`, are states no connection can be in and every one of
/// the five construction sites would have to keep saying so. Here `Doq` carries
/// RFC 9001 §4.2 — "QUIC ... MUST use TLS 1.3 or greater" — in the type, and
/// `Tcp` cannot claim to have hidden anything (`CLAUDE.md` §17).
///
/// No `Udp` variant, on purpose: this reaches a consumer by way of a
/// *connection* handler, and a datagram takes a different path in both daemons.
///
/// `Clone` rather than `Copy` since `TODO.md` #59: an encrypted connection
/// carries what the client proved about itself, which is a certificate, and a
/// plain one cannot. The clone is one `Arc` bump per message on a connection
/// that already spends a round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arrival {
    /// Plain TCP (RFC 1035 §4.2.2).
    Tcp,
    /// DNS over TLS (RFC 7858). 1.2 is allowed for a query (§4.1), so the
    /// version is carried.
    Dot(TlsVersion, PeerCertificate),
    /// DNS over HTTPS (RFC 8484), same.
    Doh(TlsVersion, PeerCertificate),
    /// DNS over QUIC (RFC 9250). No version: RFC 9001 §4.2 makes it 1.3.
    Doq(PeerCertificate),
}

/// What the client proved about itself in the handshake: the end-entity
/// certificate it presented, or nothing.
///
/// The DER as rustls verified it, not a name read out of it. Which name counts
/// is the *authorizing* end's question — RFC 9103 §7.5's mTLS says a transfer
/// client may be recognised by its certificate and says nothing about how the
/// two are matched — and a transport that answered it would be deciding policy
/// (`CLAUDE.md` §16).
///
/// `None` is the ordinary case: a DoT stub resolver asking a question offers no
/// certificate and must not be made to (RFC 8310 §8.2's mTLS is a different
/// relationship from RFC 9103's).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerCertificate(Option<Arc<Vec<u8>>>);

impl PeerCertificate {
    /// The one a plain connection has, borrowable because there is nothing in
    /// it to own.
    const NONE: &'static PeerCertificate = &PeerCertificate(None);

    /// Nothing was presented — every plain connection, and every encrypted one
    /// whose client was not asked or did not answer.
    pub fn none() -> PeerCertificate {
        PeerCertificate(None)
    }

    /// The end-entity certificate, in DER, as it arrived.
    pub fn presented(der: impl Into<Vec<u8>>) -> PeerCertificate {
        PeerCertificate(Some(Arc::new(der.into())))
    }

    /// The DER, for a caller that knows what it wants to match it against.
    pub fn der(&self) -> Option<&[u8]> {
        self.0.as_deref().map(Vec::as_slice)
    }

    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }
}

/// Which TLS version an encrypted connection negotiated.
///
/// Two values, because that is how many there are once a connection exists:
/// "no TLS" is a different variant of [`Arrival`] rather than a third value
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// 1.3 or later, which is what RFC 9103 §7.2 requires of a transfer.
    Tls13,
    /// Older than 1.3. Good enough for a query (RFC 7858 §4.1), not a transfer.
    Older,
}

impl Arrival {
    /// What the client proved about itself, if the connection let it prove
    /// anything.
    pub fn peer_certificate(&self) -> &PeerCertificate {
        match self {
            Arrival::Tcp => PeerCertificate::NONE,
            Arrival::Dot(_, cert) | Arrival::Doh(_, cert) | Arrival::Doq(cert) => cert,
        }
    }

    /// Whether this transport can carry a *sequence* of messages in answer to
    /// one request, which a zone transfer is (RFC 5936 §2.2).
    ///
    /// The fourth question, and the one the dispatcher used to answer by
    /// asking whether the reply channel was framed at all. DoH is framed and
    /// carries one message: RFC 8484 §4.2 makes one HTTP response one
    /// `application/dns-message`, defines no framing that would carry the
    /// rest, and RFC 9103 §7.1 leaves DoH outside zone transfer altogether.
    /// So a transfer over DoH used to be built in full, drained by the adapter
    /// and thrown away — except for a zone small enough to fit one envelope,
    /// which succeeded (`TODO.md` #106).
    ///
    /// Here rather than on the dispatcher's own wrapper, for the reason the
    /// other two answers are here: this is a fact about the protocol, and
    /// every adapter that builds an [`Arrival`] has already decided it.
    pub fn carries_a_sequence(&self) -> bool {
        match self {
            Arrival::Tcp | Arrival::Dot(..) | Arrival::Doq(_) => true,
            Arrival::Doh(..) => false,
        }
    }

    /// What this connection hid from the path it crossed.
    pub fn privacy(&self) -> Privacy {
        match self {
            Arrival::Tcp => Privacy::Clear,
            Arrival::Doq(_) => Privacy::Tls13,
            Arrival::Dot(TlsVersion::Tls13, _) | Arrival::Doh(TlsVersion::Tls13, _) => {
                Privacy::Tls13
            }
            Arrival::Dot(TlsVersion::Older, _) | Arrival::Doh(TlsVersion::Older, _) => {
                Privacy::TlsOlder
            }
        }
    }
}

/// Upper bound on additional records in a request. A legitimate request carries
/// at most an OPT plus a TSIG/SIG(0); the slack is for forward compatibility.
const MAX_REQUEST_ADDITIONALS: usize = 4;

/// The two size caps admission applies, one per transport.
///
/// A resource bound — how much of a stranger's datagram we are willing to parse
/// — and not a protocol rule. The distinction is `TODO.md` #40f, where the UDP
/// cap was RFC 1035 §4.2.1's 512 applied to the wrong direction: §4.2.1 limits
/// what a server may *send* without EDNS, and a requestor's own limit is the
/// payload size it advertises (RFC 6891 §4.3). Both daemons advertise 4,096 and
/// refused over 512, so a client that believed the advertisement got silence —
/// measured at `rdns/examples/request_size_probe.rs`, where a 2,048-bit DKIM key
/// rotation weighs 566 octets signed and the TSIG the server *requires* is what
/// pushes it over.
#[derive(Debug, Clone)]
pub struct AdmissionLimits {
    max_udp_size: usize,
    max_tcp_size: usize,
}

impl AdmissionLimits {
    /// The largest request accepted on each transport, in octets.
    ///
    /// Both are floored at [`CLASSIC_UDP_SIZE`], because a cap below it refuses
    /// the plainest query RFC 1035 allows: a mistyped flag should be wrong, not
    /// fatal (`CLAUDE.md` §14). Both are ceilinged at 65,535, which is every
    /// message there can be — TCP's length prefix is 16 bits and a UDP payload
    /// cannot exceed 65,507 — so there is no "off", only "as large as a message
    /// gets".
    pub fn new(max_udp_size: usize, max_tcp_size: usize) -> AdmissionLimits {
        let clamp = |n: usize| n.clamp(CLASSIC_UDP_SIZE as usize, u16::MAX as usize);
        AdmissionLimits {
            max_udp_size: clamp(max_udp_size),
            max_tcp_size: clamp(max_tcp_size),
        }
    }

    /// The cap for each transport, for an operator-facing line at startup: a
    /// limit nobody can read is a limit nobody has reviewed (`CLAUDE.md` §14).
    pub fn caps(&self) -> (usize, usize) {
        (self.max_udp_size, self.max_tcp_size)
    }
}

impl Default for AdmissionLimits {
    /// 4,096 on UDP, which is what both daemons advertise they can reassemble,
    /// and 16 KiB on TCP.
    ///
    /// Neither is a protocol number. The UDP one has to match the advertisement
    /// or the advertisement is a lie, and a daemon that advertises something else
    /// passes its own figure to [`AdmissionLimits::new`]; the TCP one is this
    /// codebase's judgement about a request that has no legitimate reason to be
    /// larger, and is now a flag because that judgement is the operator's to
    /// review.
    fn default() -> Self {
        AdmissionLimits::new(4096, 16 * 1024)
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
    pub fn new(config: AdmissionLimits) -> Self {
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

    /// The UDP cap is the payload size a daemon advertises, not RFC 1035
    /// §4.2.1's 512.
    ///
    /// This test asserted the opposite until `TODO.md` #40f, which is a test
    /// encoding the bug (`CLAUDE.md` §1): both daemons advertise 4,096 octets of
    /// receive capability in every OPT (RFC 6891 §6.2.4) and admission refused
    /// over 512 in silence, so a 566-octet DKIM rotation — a legitimate signed
    /// UPDATE, measured in `rdns/examples/request_size_probe.rs` — was dropped
    /// with nothing on the wire to say why.
    #[test]
    fn the_udp_cap_is_the_advertised_payload_size() {
        let validator = AdmissionCheck::with_defaults();
        let too_long = |packet: &[u8]| {
            matches!(
                validator.validate_packet(packet, Transport::Udp).error(),
                Some(WireError::TooLong {
                    what: "the packet",
                    ..
                })
            )
        };

        assert!(
            !too_long(&vec![0u8; 513]),
            "513 octets is what the advertisement promises to accept"
        );
        assert!(
            !too_long(&vec![0u8; 4096]),
            "and so is the advertised size itself"
        );
        assert!(too_long(&vec![0u8; 4097]), "one octet past it is refused");
    }

    /// A configured cap is the cap, and a cap that would turn the server off is
    /// floored rather than obeyed (`CLAUDE.md` §14).
    #[test]
    fn a_configured_cap_applies_and_cannot_refuse_a_plain_query() {
        let validator = AdmissionCheck::new(AdmissionLimits::new(1232, 1232));
        assert!(validator
            .validate_packet(&vec![0u8; 1232], Transport::Udp)
            .error()
            .is_none());
        assert!(matches!(
            validator
                .validate_packet(&vec![0u8; 1233], Transport::Udp)
                .error(),
            Some(WireError::TooLong { .. })
        ));

        // Zero is the flag an operator mistypes, and it must not be a way to
        // refuse every query: a 512-octet request is the plainest there is.
        let floored = AdmissionCheck::new(AdmissionLimits::new(0, 0));
        assert_eq!(
            AdmissionLimits::new(0, 0).caps(),
            (CLASSIC_UDP_SIZE as usize, CLASSIC_UDP_SIZE as usize)
        );
        assert!(floored
            .validate_packet(&vec![0u8; CLASSIC_UDP_SIZE as usize], Transport::Udp)
            .error()
            .is_none());

        // And past a message's own maximum is that maximum, not a wider cap
        // nothing can reach.
        assert_eq!(
            AdmissionLimits::new(usize::MAX, usize::MAX).caps(),
            (u16::MAX as usize, u16::MAX as usize)
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

    /// What each arrival hid, which is the half of it RFC 9103 §11 turns on.
    ///
    /// A table because the derivation is the whole content of the type
    /// (`TODO.md` #54): the alternative shape carried a `Privacy` beside a
    /// protocol, and the two could be written down disagreeing —
    /// `{ protocol: Tcp, privacy: Tls13 }` compiles, and was printed by the
    /// probe that decided against it. Here `Tcp` cannot claim to have hidden
    /// anything and `Doq` cannot claim not to.
    #[test]
    fn what_each_arrival_hid() {
        assert_eq!(Arrival::Tcp.privacy(), Privacy::Clear);
        assert_eq!(
            Arrival::Dot(TlsVersion::Tls13, PeerCertificate::none()).privacy(),
            Privacy::Tls13
        );
        assert_eq!(
            Arrival::Dot(TlsVersion::Older, PeerCertificate::none()).privacy(),
            Privacy::TlsOlder
        );
        assert_eq!(
            Arrival::Doh(TlsVersion::Tls13, PeerCertificate::none()).privacy(),
            Privacy::Tls13
        );
        assert_eq!(
            Arrival::Doh(TlsVersion::Older, PeerCertificate::none()).privacy(),
            Privacy::TlsOlder
        );
        // RFC 9001 §4.2: "QUIC ... MUST use TLS 1.3 or greater", so there is no
        // older DoQ to carry a version for.
        assert_eq!(
            Arrival::Doq(PeerCertificate::none()).privacy(),
            Privacy::Tls13
        );

        // Only 1.3 may carry a transfer (RFC 9103 §7.2), whichever protocol it
        // is under.
        assert!(Arrival::Doq(PeerCertificate::none()).privacy().is_xot());
        assert!(Arrival::Dot(TlsVersion::Tls13, PeerCertificate::none())
            .privacy()
            .is_xot());
        assert!(!Arrival::Dot(TlsVersion::Older, PeerCertificate::none())
            .privacy()
            .is_xot());
        assert!(!Arrival::Tcp.privacy().is_xot());
    }

    /// ~~Two octets, the same as the `Privacy` it replaces plus a
    /// discriminant.~~ **Sixteen since `TODO.md` #59**, and upward, so the
    /// reason is here (§17): a connection carries the certificate its client
    /// presented, which is an `Option<Arc<Vec<u8>>>` — one pointer, `None`
    /// costing nothing extra by the niche, and the version and discriminant
    /// padded out beside it. `Arc<[u8]>` would be worse, being a fat pointer.
    ///
    /// Pinned because this rides on the answer path, once per message
    /// (`CLAUDE.md` §17's rule about measuring rather than assuming a newtype
    /// is free). The `{ protocol, privacy }` pair measured the same 2, which is
    /// why size was not what decided between them.
    #[test]
    fn an_arrival_costs_sixteen_octets() {
        assert_eq!(std::mem::size_of::<Arrival>(), 16);
        assert_eq!(std::mem::size_of::<PeerCertificate>(), 8);
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
