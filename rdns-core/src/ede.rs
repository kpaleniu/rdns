//! Extended DNS Errors (RFC 8914): the reason beside the RCODE.
//!
//! A bare SERVFAIL says a lookup failed and nothing about why. The same
//! SERVFAIL carrying INFO-CODE 7 says the zone's signatures have expired,
//! which is a fixed problem rather than a support ticket (`TODO.md` #44b).
//!
//! The option rides in the OPT record, so it reaches only a client that sent
//! one — RFC 8914 §2 puts it in "any response (SERVFAIL, NXDOMAIN, REFUSED,
//! even NOERROR, etc.) to a query that includes an OPT pseudo-RR". That rule
//! needs no check here: [`ClientEdns::mirror`](crate::response::ClientEdns::mirror)
//! is the only way to a reply's OPT and hands back `None` without one, so an
//! EDE with no OPT to ride in is not expressible (`CLAUDE.md` §17).

use crate::error::WireError;
use crate::{Edns, EdnsOption};

/// The EDNS option code IANA assigned to Extended DNS Error (RFC 8914 §5.1).
pub const EDNS_OPTION_EXTENDED_ERROR: u16 = 15;

/// The longest EXTRA-TEXT this codebase will send.
///
/// Not a protocol limit — the field is bounded by OPTION-LENGTH alone. It is
/// here because [`ResponseWriter::finish`](crate::response::ResponseWriter::finish)
/// writes the OPT of an over-long reply without re-checking the caller's
/// ceiling, leaning on the 512-octet floor
/// [`ResponseWriter::start`](crate::response::ResponseWriter::start) sizes the
/// buffer to. The arithmetic that floor has to cover is 12 octets of header,
/// 259 of the longest possible question, 11 of OPT and 6 of option header plus
/// INFO-CODE, which leaves 224; 128 keeps the claim true with room to spare.
pub const MAX_EXTRA_TEXT: usize = 128;

/// An INFO-CODE: an index into IANA's "Extended DNS Error Codes" registry
/// (RFC 8914 §2).
///
/// A newtype over the whole 16-bit space rather than an enum. §5.2 gives
/// 0-49151 to First Come First Served and 49152-65535 to Private Use, so a code
/// we have no name for is ordinary and has to relay as itself; there is no
/// value free to be a sentinel (`CLAUDE.md` §2).
///
/// Only the codes this tree emits are named. An option code that exists and
/// that nothing reads or writes is the shape `TODO.md` #45e filed as a finding,
/// so the registry is cited rather than transcribed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct InfoCode(u16);

impl InfoCode {
    /// 0, Other Error: "the error in question falls into a category that does
    /// not match known extended error codes".
    pub const OTHER: InfoCode = InfoCode(0);
    /// 3, Stale Answer: "the resolver was unable to resolve the answer within
    /// its time limits and decided to answer with stale data" (RFC 8767).
    pub const STALE_ANSWER: InfoCode = InfoCode(3);
    /// 4, Forged Answer: "For policy reasons (legal obligation or malware
    /// filtering, for instance), an answer was forged. Note that this should be
    /// used when an answer is still provided, not when failure codes are
    /// returned instead" — which is the line between this and `BLOCKED`.
    pub const FORGED_ANSWER: InfoCode = InfoCode(4);
    /// 6, DNSSEC Bogus: "validation ended in the Bogus state".
    pub const DNSSEC_BOGUS: InfoCode = InfoCode(6);
    /// 7, Signature Expired: "no signatures are presently valid and some
    /// (often all) are expired".
    pub const SIGNATURE_EXPIRED: InfoCode = InfoCode(7);
    /// 8, Signature Not Yet Valid: "no signatures are presently valid and at
    /// least some are not yet valid".
    pub const SIGNATURE_NOT_YET_VALID: InfoCode = InfoCode(8);
    /// 9, DNSKEY Missing: "a DS record existed at a parent, but no supported
    /// matching DNSKEY record could be found".
    pub const DNSKEY_MISSING: InfoCode = InfoCode(9);
    /// 10, RRSIGs Missing: "no RRSIGs could be found for at least one RRset
    /// where RRSIGs were expected".
    pub const RRSIGS_MISSING: InfoCode = InfoCode(10);
    /// 12, NSEC Missing: "the requested data was missing and a covering NSEC
    /// or NSEC3 was not provided".
    pub const NSEC_MISSING: InfoCode = InfoCode(12);
    /// 15, Blocked: "the server is blocking the query due to a policy defined
    /// by the operator" — a Response Policy Zone rewrite (`rdns::rpz`).
    ///
    /// Not 16 (Censored, "an external requirement") or 17 (Filtered, "a policy
    /// defined by the end user"): which of the three an RPZ feed is depends on
    /// where the feed came from, and only the operator knows that.
    pub const BLOCKED: InfoCode = InfoCode(15);
    /// 18, Prohibited: "an authoritative server or recursive resolver that
    /// receives a query from an 'unauthorized' client can annotate its REFUSED
    /// message with this code".
    pub const PROHIBITED: InfoCode = InfoCode(18);
    /// 19, Stale NXDOMAIN Answer: the same for a cached "no", which is a
    /// different claim and so a different code.
    pub const STALE_NXDOMAIN: InfoCode = InfoCode(19);
    /// 20, Not Authoritative: an authoritative server refusing a name it holds
    /// no zone for.
    pub const NOT_AUTHORITATIVE: InfoCode = InfoCode(20);
    /// 21, Not Supported: "the requested operation or query is not supported".
    pub const NOT_SUPPORTED: InfoCode = InfoCode(21);
    /// 23, Network Error: "an unrecoverable error occurred while communicating
    /// with another server".
    pub const NETWORK_ERROR: InfoCode = InfoCode(23);
    /// 22, No Reachable Authority: "the resolver could not reach any of the
    /// authoritative name servers (or they potentially refused to reply)".
    pub const NO_REACHABLE_AUTHORITY: InfoCode = InfoCode(22);

    /// Total: every 16-bit value indexes the registry.
    pub const fn new(value: u16) -> InfoCode {
        InfoCode(value)
    }

    pub const fn to_u16(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for InfoCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One Extended DNS Error: an INFO-CODE and the text beside it (RFC 8914 §2).
///
/// EXTRA-TEXT is `&'static str` on purpose. A refusal is the one reply a
/// stranger can ask for in a flood, so the text may not cost an allocation per
/// query; and §2's "care should be taken to not leak private information" is
/// easiest to hold when nothing the client sent, and nothing about this
/// server's state, can reach it. The INFO-CODE carries the diagnosis; the text
/// only says which of the sites sharing that code this was.
///
/// The fields are private because [`ExtendedError::new`] checks one — a `pub`
/// field beside a checking constructor is a value nothing objects to until
/// something reads it (`CLAUDE.md` §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtendedError {
    info_code: InfoCode,
    extra_text: &'static str,
}

impl ExtendedError {
    /// Panics if `extra_text` is longer than [`MAX_EXTRA_TEXT`].
    ///
    /// `const fn`, so that panic is a *compile* error at every call site that
    /// is a `const` — which is every one of them, since an EDE is a fixed code
    /// and a fixed sentence chosen when the branch is written. Truncating
    /// instead would silently shorten a message somebody meant to send, and
    /// cutting UTF-8 without `str::is_char_boundary` (which is not const) is
    /// how a receiver gets a byte sequence §2 says is text.
    pub const fn new(info_code: InfoCode, extra_text: &'static str) -> ExtendedError {
        assert!(
            extra_text.len() <= MAX_EXTRA_TEXT,
            "an EDE's EXTRA-TEXT must leave room for the reply that carries it"
        );
        ExtendedError {
            info_code,
            extra_text,
        }
    }

    pub fn info_code(self) -> InfoCode {
        self.info_code
    }

    pub fn extra_text(self) -> &'static str {
        self.extra_text
    }

    /// The option as it goes in the OPT RDATA: INFO-CODE then EXTRA-TEXT, with
    /// no terminator — §2's length "MUST be derived from the OPTION-LENGTH
    /// field".
    pub fn to_option(self) -> EdnsOption {
        let mut data = Vec::with_capacity(2 + self.extra_text.len());
        data.extend_from_slice(&self.info_code.to_u16().to_be_bytes());
        data.extend_from_slice(self.extra_text.as_bytes());
        EdnsOption {
            code: EDNS_OPTION_EXTENDED_ERROR,
            data,
        }
    }

    /// The INFO-CODE of an option's data, for a client reading one off the
    /// wire.
    ///
    /// The reading half borrows rather than owning: a received EDE is printed
    /// and dropped, and its text is somebody else's bytes rather than the
    /// `&'static str` this type sends.
    pub(crate) fn info_code_of(data: &[u8]) -> Result<InfoCode, WireError> {
        let head: [u8; 2] =
            data.get(..2)
                .and_then(|b| b.try_into().ok())
                .ok_or(WireError::Truncated {
                    what: "an EDE INFO-CODE",
                    need: 2,
                    have: data.len(),
                })?;
        Ok(InfoCode::new(u16::from_be_bytes(head)))
    }

    /// The EXTRA-TEXT beside that code, as it arrived. Lossy, because a remote
    /// party's text is not ours to trust as UTF-8 however §2 describes it.
    pub(crate) fn extra_text_of(data: &[u8]) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(data.get(2..).unwrap_or(&[]))
    }

    /// Every Extended DNS Error `edns` carries, in the order they appear.
    ///
    /// A list rather than a lookup: §2 says "Senders MAY include more than one
    /// EDE option and receivers MUST be able to accept (but not necessarily
    /// process or act on) multiple EDE options in a DNS message".
    ///
    /// `Err` is a malformed *option list*, which is FORMERR for the message as
    /// a whole. An individual EDE too short to hold its INFO-CODE is skipped
    /// instead â §3 is explicit that an EDE changes nothing about how the
    /// RCODE beside it is processed, so discarding an unreadable annotation
    /// discards no answer.
    pub fn all_in(edns: &Edns) -> Result<Vec<(InfoCode, String)>, WireError> {
        Ok(edns
            .options()?
            .iter()
            .filter(|option| option.code == EDNS_OPTION_EXTENDED_ERROR)
            .filter_map(|option| {
                let code = Self::info_code_of(&option.data).ok()?;
                Some((code, Self::extra_text_of(&option.data).into_owned()))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CLASSIC_UDP_SIZE;

    /// RFC 8914 §2's fields, in order, with no terminator after the text.
    #[test]
    fn the_option_is_a_16_bit_code_then_the_text() {
        let option = ExtendedError::new(InfoCode::SIGNATURE_EXPIRED, "expired").to_option();
        assert_eq!(option.code, EDNS_OPTION_EXTENDED_ERROR);
        assert_eq!(option.data, b"\x00\x07expired");
        assert_eq!(
            ExtendedError::info_code_of(&option.data).expect("a code"),
            InfoCode::SIGNATURE_EXPIRED
        );
        assert_eq!(ExtendedError::extra_text_of(&option.data), "expired");
    }

    /// "may be zero octets in length" (§2), which is the whole option for a
    /// code that needs no annotation. 65535 is also the round trip an unnamed
    /// code has to survive.
    #[test]
    fn the_text_may_be_empty() {
        let option = ExtendedError::new(InfoCode::new(65535), "").to_option();
        assert_eq!(option.data, b"\xff\xff");
        assert_eq!(
            ExtendedError::info_code_of(&option.data).expect("a code"),
            InfoCode::new(65535)
        );
        assert_eq!(ExtendedError::extra_text_of(&option.data), "");
    }

    /// A one-octet option carries no INFO-CODE, so it is not an EDE.
    #[test]
    fn an_option_shorter_than_the_code_is_truncated() {
        assert!(matches!(
            ExtendedError::info_code_of(&[0x00]),
            Err(WireError::Truncated {
                what: "an EDE INFO-CODE",
                ..
            })
        ));
    }

    /// The bound is a compile-time check at a `const` call site, which is what
    /// every caller in this tree is; here it is only that the limit is the one
    /// the reply budget was computed against.
    #[test]
    fn the_longest_text_still_leaves_the_reply_room() {
        const EDE: ExtendedError = ExtendedError::new(InfoCode::OTHER, "x");
        assert_eq!(EDE.to_option().data.len(), 3);
        // 12 octets of header, 259 of the longest question, 11 of OPT and 4 of
        // option header, plus the option itself, inside the 512 the writer
        // floors its buffer at.
        assert!(12 + 259 + 11 + 4 + 2 + MAX_EXTRA_TEXT < CLASSIC_UDP_SIZE as usize);
    }
}
