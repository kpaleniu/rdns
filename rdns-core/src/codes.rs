//! The numbers a DNS message is written in: opcodes, classes, types, TTLs,
//! serials and response codes.
//!
//! A module rather than the crate root so the five `#[repr(transparent)]`
//! newtypes here are sealed: their inner fields are private to *this file*, and
//! the conversions below are the only way in or out (`CLAUDE.md` §17).

use crate::record_types;

/// The four-bit OPCODE of RFC 1035 §4.1.1 — "set by the originator of a query
/// and copied into the response".
///
/// `Other` carries the value, because that copying rule leaves no room for a
/// sentinel: every four-bit value is a real opcode. The numbering lives in
/// [`OpCode::from_u8`] and [`OpCode::to_u8`], which are each other's inverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Query,
    IQuery, // RFC 3425: IQUERY obsolete
    Status,
    Notify,
    Update,
    /// An opcode this implementation has no name for, kept as it arrived.
    /// Always four bits: [`OpCode::from_u8`] masks.
    Other(u8),
}

impl OpCode {
    /// Total: every four-bit value is some opcode. The mask establishes that —
    /// a larger `u8` is not an opcode at all.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0f {
            0 => OpCode::Query,
            1 => OpCode::IQuery,
            2 => OpCode::Status,
            4 => OpCode::Notify,
            5 => OpCode::Update,
            other => OpCode::Other(other),
        }
    }

    /// Infallible, so echoing a request's opcode cannot silently change it.
    pub fn to_u8(self) -> u8 {
        match self {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Notify => 4,
            OpCode::Update => 5,
            OpCode::Other(value) => value,
        }
    }
}

/// The class a *question* asks for — QCLASS (RFC 6895 §3.2). Practically always
/// IN; CH and HS exist and are near-unused.
///
/// `Other` carries the value: a class we cannot name must be echoed back as
/// itself, since a client matches the response to its query on the question
/// section (RFC 5452 §9.1). There is no free sentinel — 254 is RFC 2136's real
/// NONE.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum QueryClass {
    IN,
    CH,
    HS,
    None,
    Any,
    /// A class this implementation has no name for, kept as it arrived.
    Other(u16),
}

impl QueryClass {
    /// Total, by construction: every 16-bit value is some class.
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => QueryClass::IN,
            3 => QueryClass::CH,
            4 => QueryClass::HS,
            254 => QueryClass::None,
            255 => QueryClass::Any,
            other => QueryClass::Other(other),
        }
    }

    /// Whether this question selects a record in `class`. The only comparison
    /// of a question's class against stored data; ANY matches every class
    /// (RFC 1035 §3.2.5).
    pub fn matches(self, class: Class) -> bool {
        self == QueryClass::Any || self.to_u16() == class.to_u16()
    }

    /// Whether the question is for exactly `class`, with no ANY handling.
    pub fn is(self, class: Class) -> bool {
        self.to_u16() == class.to_u16()
    }

    /// Infallible: what came off the wire goes back onto it unchanged.
    pub fn to_u16(self) -> u16 {
        match self {
            QueryClass::IN => 1,
            QueryClass::CH => 3,
            QueryClass::HS => 4,
            QueryClass::None => 254,
            QueryClass::Any => 255,
            QueryClass::Other(value) => value,
        }
    }
}

/// The class a *record* is in — CLASS, not QCLASS (RFC 1035 §3.2.4).
///
/// QCLASS is a superset (§3.2.5), so the conversion runs one way only:
/// [`Class`] into [`QueryClass`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Class(u16);

impl Class {
    /// The Internet class, and in practice the only one (RFC 1035 §3.2.4).
    pub const IN: Class = Class(1);
    /// CHAOS — used by `version.bind` and little else.
    pub const CH: Class = Class(3);
    /// Hesiod.
    pub const HS: Class = Class(4);

    /// Total: every 16-bit value names some class, known here or not.
    pub const fn new(value: u16) -> Class {
        Class(value)
    }

    /// Infallible, so a record round-trips unchanged.
    pub const fn to_u16(self) -> u16 {
        self.0
    }

    /// Whether this is a QCLASS-only value that no stored record can be in:
    /// ANY (255) and RFC 2136's NONE (254). Both arrive in a record's CLASS
    /// field in an UPDATE, where §2.4 and §2.5 repurpose it to say what to *do*
    /// with the record.
    pub const fn is_meta(self) -> bool {
        matches!(self.0, 254 | 255)
    }
}

impl Default for Class {
    /// IN, not `derive(Default)`'s `CLASS0`, which is not a class at all.
    fn default() -> Class {
        Class::IN
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Class::IN => write!(f, "IN"),
            Class::CH => write!(f, "CH"),
            Class::HS => write!(f, "HS"),
            Class(other) => write!(f, "CLASS{other}"),
        }
    }
}

impl From<Class> for QueryClass {
    /// Every CLASS is a legal QCLASS (RFC 1035 §3.2.5); there is no reverse.
    /// Also how `update.rs` reads RFC 2136's repurposed CLASS field.
    fn from(class: Class) -> QueryClass {
        QueryClass::from_u16(class.to_u16())
    }
}

/// The type a *record* has — TYPE, not QTYPE (RFC 1035 §3.2.1).
///
/// There is no conversion from [`Qtype`]; most QTYPEs are not record types.
/// `Rtype` can still hold the meta-types (RFC 6895 §3.1), because RFC 2136 §2.4
/// and §2.5 put TYPE=ANY in an UPDATE's record sections — see
/// [`Rtype::is_meta`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Rtype(u16);

impl Rtype {
    /// Total: every 16-bit value names some type, known here or not.
    pub const fn new(value: u16) -> Rtype {
        Rtype(value)
    }

    /// Infallible, so a record round-trips unchanged.
    pub const fn to_u16(self) -> u16 {
        self.0
    }

    /// Whether this is a meta-type — a value that may appear in a TYPE field but
    /// that no stored resource record can have (RFC 6895 §3.1). RFC 2136 §3.4.1's
    /// prescan refuses an UPDATE that tries to add one.
    pub const fn is_meta(self) -> bool {
        matches!(
            self.0,
            record_types::ANY_CODE | record_types::AXFR_CODE | record_types::IXFR_CODE
        )
    }
}

impl std::fmt::Display for Rtype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", record_types::record_type_name(*self))
    }
}

impl From<Rtype> for Qtype {
    /// Every TYPE is a legal QTYPE (RFC 1035 §3.2.3); there is no reverse.
    fn from(rtype: Rtype) -> Qtype {
        Qtype(rtype.0)
    }
}

/// The type a *question* asks for — QTYPE, not TYPE (RFC 1035 §3.2.3).
///
/// A superset of TYPE: it holds values no resource record can ever have — ANY
/// (255), AXFR (252), IXFR (251), MAILB (253), MAILA (254) — so
/// `record.rtype == question.qtype` is false for every record in a perfectly
/// good ANY answer. A newtype so that comparison does not compile: the two
/// spaces meet only at [`Qtype::matches`], which knows what ANY means, and
/// [`Qtype::is`], which asks the narrower question out loud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Qtype(u16);

impl Qtype {
    /// `*` — every type at the name (RFC 1035 §3.2.3).
    pub const ANY: Qtype = Qtype(record_types::ANY_CODE);
    /// A whole-zone transfer (RFC 5936). TCP only.
    pub const AXFR: Qtype = Qtype(record_types::AXFR_CODE);
    /// An incremental transfer (RFC 1995).
    pub const IXFR: Qtype = Qtype(record_types::IXFR_CODE);

    /// The question that asks for exactly this record type. `const`, so
    /// `record_types` stays the one registry of numbers.
    pub const fn of(rtype: Rtype) -> Qtype {
        Qtype(rtype.to_u16())
    }

    /// Total: every 16-bit value is some QTYPE.
    pub const fn from_u16(value: u16) -> Qtype {
        Qtype(value)
    }

    /// Infallible, so a question round-trips unchanged.
    pub const fn to_u16(self) -> u16 {
        self.0
    }

    /// Whether this question selects a stored record of type `rtype` — the only
    /// comparison of a question's type against stored data.
    ///
    /// ANY means every type at the name (RFC 1035 §3.2.3) *except* RRSIG, NSEC
    /// and NSEC3, which are not answer-section data unless DO asked for them
    /// (RFC 4035 §3.1.1); `dnssec_answer::answer_signatures` attaches those.
    /// Including them would also make an empty non-terminal in an NSEC-signed
    /// zone look like a name with data.
    pub fn matches(self, rtype: Rtype) -> bool {
        use crate::record_types as rt;
        if self == Qtype::ANY {
            !matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3)
        } else {
            self.0 == rtype.to_u16()
        }
    }

    /// Whether the question is for exactly `rtype`, with no ANY handling — so
    /// the call site does not read like a [`Qtype::matches`] that forgot it.
    pub const fn is(self, rtype: Rtype) -> bool {
        self.0 == rtype.to_u16()
    }
}

impl std::fmt::Display for Qtype {
    /// Through [`record_types::qtype_name`], not `record_type_name`: the latter takes
    /// an `Rtype` and prints the question everyone writes `ANY` as `TYPE255`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", record_types::qtype_name(*self))
    }
}

/// How long a record may be cached, in seconds.
///
/// A `u32` clamped once, at the parse boundary: RFC 1035 §4.1.3 calls the field
/// signed, RFC 2181 §8 corrects it to unsigned with the top-bit-set case treated
/// as zero. [`Ttl::from_wire`] is where that happens, so no call site has to
/// widen a negative `i32` and get `u64::MAX` for the smallest TTL in an RRset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Ttl(u32);

impl Ttl {
    /// Zero seconds: do not cache (RFC 1035 §3.2.1).
    pub const ZERO: Ttl = Ttl(0);

    /// A TTL as it came off the wire, clamped per RFC 2181 §8 — the only place
    /// the sign of the wire field is considered.
    pub const fn from_wire(seconds: i32) -> Ttl {
        Ttl(if seconds < 0 { 0 } else { seconds as u32 })
    }

    /// A TTL from a value already known to be a count of seconds.
    pub const fn from_secs(seconds: u32) -> Ttl {
        Ttl(seconds)
    }

    /// The count of seconds.
    pub const fn as_secs(self) -> u32 {
        self.0
    }

    /// The count of seconds, widened for arithmetic against a timestamp. An
    /// accessor rather than `as u64` per site: the widening is only safe because
    /// the value is non-negative by construction.
    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }

    /// This TTL, or `ceiling` if it is larger — the cap every cache applies.
    pub fn capped_at(self, ceiling: u32) -> Ttl {
        Ttl(if self.0 > ceiling { ceiling } else { self.0 })
    }

    /// The wire encoding — the same 32 bits, since RFC 2181 §8 makes the field
    /// unsigned.
    pub const fn to_wire(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for Ttl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A zone's version number: the SOA's SERIAL field (RFC 1035 §3.3.13).
///
/// No `PartialOrd` and no `Ord`: RFC 1982 sequence space wraps, so `a > b` is
/// not "a is later". [`Serial::is_newer_than`] is the only comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Serial(u32);

impl Serial {
    /// Total: every 32-bit value is a serial. There is no invalid one.
    pub const fn new(value: u32) -> Serial {
        Serial(value)
    }

    /// The wire encoding, unchanged, so an SOA round-trips.
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    /// Whether this version is later than `other` (RFC 1982 §3.2): the forward
    /// distance is in the first half of the space. Equal serials are not newer,
    /// so a secondary does not re-transfer an unchanged zone.
    ///
    /// Not `PartialOrd`: §3.2 leaves the result undefined for serials exactly
    /// half the space apart, and an `Ord` would have to invent one.
    pub const fn is_newer_than(self, other: Serial) -> bool {
        let forward = self.0.wrapping_sub(other.0);
        forward != 0 && forward < 0x8000_0000
    }

    /// This serial advanced by `increment`, wrapping (RFC 1982 §3.1) — wrapping
    /// is the defined addition in the sequence space, not an overflow.
    pub const fn wrapping_add(self, increment: u32) -> Serial {
        Serial(self.0.wrapping_add(increment))
    }
}

impl std::fmt::Display for Serial {
    /// Forwards the whole formatter, so width and alignment survive: callers
    /// write `{serial:<12}` into a zone file and `{:>6}` into a status column.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::str::FromStr for Serial {
    type Err = std::num::ParseIntError;

    /// The presentation form is a decimal number and nothing else.
    fn from_str(text: &str) -> Result<Serial, Self::Err> {
        text.parse().map(Serial)
    }
}

/// A DNS response code: the 12-bit value of RFC 6891 §6.1.3, not the 4-bit
/// header field.
///
/// `Other` carries the value: an rcode we have no name for is relayed as
/// itself, never as NOERROR, and RFC 6895 §2.3 keeps the space open. The
/// numbering lives in [`ResponseCode::from_u16`] and [`ResponseCode::to_u16`],
/// which are each other's inverse over the whole 16-bit range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    // RFC 1035 - Basic codes
    Ok,
    FormatError,
    ServerFailure,
    NoSuchDomain,
    NotImplemented,
    Refused,
    // RFC 2136 - Domain update related codes
    DomainExistsForSomeReason,
    ResourceRecordSetExistsForSomeReason,
    NoSuchResourceRecordSet,
    NotAuthorized, // Or ServerNotAuthorativeForZone (RFC8945)
    NameNotInZone,

    // RFC 8490 - DNS Stateful Operations
    DsoTypeNotImplemented,

    BadOptVersion, // Or BadTsigSignature (RFC8945)
    BadKey,
    BadTime,

    // RFC 2930 - TKEY RR
    BadTkeyMode,
    BadName,
    BadAlgorithm,
    BadTruncation,
    BadCookie,

    /// A code with no name here, carried through as it arrived.
    Other(u16),
}

impl ResponseCode {
    /// Total: every 16-bit value is some response code.
    pub fn from_u16(value: u16) -> Self {
        match value {
            0 => ResponseCode::Ok,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NoSuchDomain,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            6 => ResponseCode::DomainExistsForSomeReason,
            7 => ResponseCode::ResourceRecordSetExistsForSomeReason,
            8 => ResponseCode::NoSuchResourceRecordSet,
            9 => ResponseCode::NotAuthorized,
            10 => ResponseCode::NameNotInZone,
            11 => ResponseCode::DsoTypeNotImplemented,
            16 => ResponseCode::BadOptVersion,
            17 => ResponseCode::BadKey,
            18 => ResponseCode::BadTime,
            19 => ResponseCode::BadTkeyMode,
            20 => ResponseCode::BadName,
            21 => ResponseCode::BadAlgorithm,
            22 => ResponseCode::BadTruncation,
            23 => ResponseCode::BadCookie,
            other => ResponseCode::Other(other),
        }
    }

    /// Infallible, so relaying a response cannot silently change its meaning.
    pub fn to_u16(self) -> u16 {
        match self {
            ResponseCode::Ok => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NoSuchDomain => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
            ResponseCode::DomainExistsForSomeReason => 6,
            ResponseCode::ResourceRecordSetExistsForSomeReason => 7,
            ResponseCode::NoSuchResourceRecordSet => 8,
            ResponseCode::NotAuthorized => 9,
            ResponseCode::NameNotInZone => 10,
            ResponseCode::DsoTypeNotImplemented => 11,
            ResponseCode::BadOptVersion => 16,
            ResponseCode::BadKey => 17,
            ResponseCode::BadTime => 18,
            ResponseCode::BadTkeyMode => 19,
            ResponseCode::BadName => 20,
            ResponseCode::BadAlgorithm => 21,
            ResponseCode::BadTruncation => 22,
            ResponseCode::BadCookie => 23,
            ResponseCode::Other(value) => value,
        }
    }
}
