use crate::error::WireError;
use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr};

use compression::NameCompressor;
use dname::{dname_from_bytes, dname_to_bytes, write_bytes, DNameUnpacker, TryUnpackFromBytes};

/// This build, as `<package version> (<git describe>)`.
///
/// Stamped by `build.rs`. Every binary passes it to clap's `version`, so
/// `--version` names a commit rather than three crates all saying `0.1.0` —
/// which is what an operator needs when asked which build is running.
pub const VERSION: &str = env!("RDNS_VERSION");

// The *file name* is kept on purpose — `TODO.md` §10 argues from
// `bench_logger_throughput` by name — but the module is entirely
// `#[cfg(test)]`, so a `pub mod` exported an empty public module from every
// release build (`TODO.md` #19h).
#[cfg(test)]
mod bench;
pub mod cache;
pub mod compression;
pub mod control;
pub mod dname;
pub mod dnssec;
pub mod dnssec_answer;
pub mod dnssec_chain;
pub mod dnssec_denial;
pub mod dnssec_key;
/// Real DNSSEC signing for tests only — see the module docs for why an
/// in-process signer is the only way to exercise this code here.
#[cfg(test)]
mod dnssec_test_util;
pub mod dnssec_validation_mode;
pub mod error;
pub mod ixfr;
pub mod journal;
pub mod logging;
pub mod metrics;
pub mod metrics_server;
pub mod negative_cache;
pub mod notify;
pub mod nsec_cache;
pub mod persist;
pub mod readiness;
mod record_data;
pub mod resolver;
pub mod rfc5011;
pub mod secondary;
pub mod security;
pub mod shutdown;
pub mod special_names;
pub mod transfer;
pub mod tsig;
pub mod update;
pub mod utils;
pub mod validation;
pub mod xfr;
pub mod zone;
pub mod zone_signer;
pub mod zone_writer;

// Re-export cache module for public use
pub use cache::{CacheStats, DnsCache};

/// [`RecordData`] lives in its own module so its fields can be private to it —
/// see that module's header for why a one-struct module is the point.
pub use record_data::RecordData;

#[macro_use]
mod macros {
    macro_rules! read_be {
        ($dt:ty, $data:expr) => {{
            let sz = std::mem::size_of::<$dt>();
            if $data.len() < sz {
                return Err($crate::error::WireError::Truncated {
                    what: stringify!($dt),
                    need: sz,
                    have: $data.len(),
                });
            }
            (
                <$dt>::from_be_bytes($data[..sz].try_into().unwrap()),
                &$data[sz..],
            )
        }};
    }
}

/// The four-bit OPCODE of RFC 1035 §4.1.1 — "set by the originator of a query
/// and copied into the response".
///
/// `Other` carries the value, and that copying rule is why. This used to be an
/// `Unknown = 15` sentinel parsed with
/// `OpCode::from_u8((hi >> 3) & 0x0f).unwrap_or(OpCode::Unknown)`, and 15 is a
/// real value in a four-bit field, so **eleven of the sixteen opcodes came back
/// off the wire as 15** — 3 and 7-15, which IANA lists as Unassigned, and
/// **6, which is DSO (RFC 8490) and assigned**. `rdnsd` answers an opcode it
/// does not implement with NOTIMP and echoes this field, so a DSO client was
/// handed a reply whose OPCODE was not the one it sent, which RFC 5452 §9.1 has
/// it discard.
///
/// The third variant of the same mistake, after `QueryClass::None` (which was
/// 254, a real class) and `ResponseCode::Unknown` (which serialized as
/// NOERROR). All three had the same cause — `num_derive`'s `FromPrimitive`
/// hands back an `Option` and invites the `unwrap_or` — and fixing this one
/// removed the last user of that crate from the workspace. See `CLAUDE.md` §2
/// and §17.
///
/// No explicit discriminants, because a variant with a payload forbids them;
/// the numbering lives in [`OpCode::from_u8`] and [`OpCode::to_u8`], which are
/// each other's inverse over the whole four-bit range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Query,
    IQuery, // RFC 3425: IQUERY obsolete
    Status,
    Notify,
    Update,
    /// An opcode this implementation has no name for, kept as it arrived.
    ///
    /// Always four bits: [`OpCode::from_u8`] masks, so the field cannot hold a
    /// value the wire has no room for and [`OpCode::to_u8`] cannot lose one.
    Other(u8),
}

impl OpCode {
    /// Total, by construction: every four-bit value is some opcode.
    ///
    /// The mask is the boundary this type's invariant is established at
    /// (`CLAUDE.md` §2) — OPCODE is four bits, so a larger `u8` is not an
    /// opcode that got truncated later, it is not an opcode at all.
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

// practically always IN (1), classes are supposed to be sort of
// dimension to the DNS database (see RFC6895 section 3.2). Only CH (3)
// and HS (4) are mentioned but practially never used outside of local tests
///
/// `Other` carries the value, which is the whole point of it. The parse used to
/// be `QueryClass::from_u16(qclass).unwrap_or(QueryClass::None)`, and `None` is
/// not a sentinel — it is 254, RFC 2136's real "no such class" used in UPDATE
/// prerequisites. So QCLASS 99 arrived as `None`, was re-serialized as **254**,
/// and the question echoed back in the response was not the question that was
/// asked. A client matching the response to its query on the question section,
/// as RFC 5452 §9.1 says to, sees a mismatch and discards a reply it waited for.
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

    /// Whether this question selects a record in `class`.
    ///
    /// The only comparison of a question's class against stored data. ANY
    /// matches every class (RFC 1035 §3.2.5), which is why matching it against
    /// the IN zone is right when IN is the only class this server holds.
    pub fn matches(self, class: Class) -> bool {
        self == QueryClass::Any || self.to_u16() == class.to_u16()
    }

    /// Whether the question is for exactly `class`, with no ANY handling.
    pub fn is(self, class: Class) -> bool {
        self.to_u16() == class.to_u16()
    }

    /// Infallible, so round-tripping a question is total: what came off the wire
    /// goes back onto it unchanged.
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
/// The third pair in this file, after [`Rtype`]/[`Qtype`] and beside
/// [`QueryClass`]. QCLASS is a superset of CLASS (§3.2.5): `*` (255) matches any
/// class and RFC 2136 §2.4 uses NONE (254) in an UPDATE, and no stored record is
/// in either. The conversion runs one way, [`Class`] into [`QueryClass`], and
/// there is no way back.
///
/// **This could not be a newtype until OPT stopped being parsed as a resource
/// record** (`TODO.md` #13d). An OPT record's CLASS field is the requestor's UDP
/// payload size, not a class at all — the same two-meanings-in-one-field problem
/// [`Ttl`] had, in the field next door, and fixed by the same change.
///
/// §8 of `CLAUDE.md` records what the untyped version cost: the class was parsed,
/// stored on every record, and then never compared, so a CH question was
/// answered out of the IN zone and the reply carried `CLASS=CH` in the echoed
/// question beside `CLASS=IN` records in the answer. That was fixed in `rdnsd`'s
/// query loop and in the zone parser, which refuses a non-IN record outright —
/// and it is the parser's refusal, not the type, that makes the class-blind zone
/// index correct. The type is what stops the *next* pseudo-record quietly
/// borrowing the field.
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
    /// ANY (255) and RFC 2136's NONE (254).
    ///
    /// Both arrive in a record's CLASS field in an UPDATE message, where §2.4
    /// and §2.5 repurpose it to say what to *do* with the record — which is why
    /// `Class` can hold them and why [`QueryClass::from`] exists.
    pub const fn is_meta(self) -> bool {
        matches!(self.0, 254 | 255)
    }
}

impl Default for Class {
    /// IN. Every zone this server holds is IN — `zone::parse_zone_file` refuses
    /// anything else — so a record built without saying its class is in the only
    /// one there is. A `derive(Default)` would have given `CLASS0`, which is not
    /// a class at all.
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
    /// Every CLASS is a legal QCLASS (RFC 1035 §3.2.5). The reverse does not
    /// exist, and that asymmetry is the point of the pair.
    ///
    /// This is also how RFC 2136's repurposed CLASS field is read: an UPDATE
    /// carries ANY or NONE there to mean "any type at this name" or "delete",
    /// and `update.rs` matches on the `QueryClass` this produces.
    fn from(class: Class) -> QueryClass {
        QueryClass::from_u16(class.to_u16())
    }
}

/// The type a *record* has — TYPE, not QTYPE (RFC 1035 §3.2.1).
///
/// The other half of the pair [`Qtype`] documents. There is no conversion from
/// `Qtype` to `Rtype`, because most QTYPEs are not record types; the conversion
/// that does exist runs the other way, since every TYPE is a legal QTYPE.
///
/// **A few values appear in a TYPE field and are still not record types.** ANY,
/// AXFR and IXFR are meta-types (RFC 6895 §3.1): they are legal in a question,
/// and RFC 2136 §2.4 and §2.5 also put TYPE=ANY in an UPDATE's prerequisite and
/// update sections to mean "any type at this name". So `Rtype` can hold them —
/// they arrive on the wire — and [`Rtype::is_meta`] is how code asks whether the
/// value in hand could ever be a stored record. §3.4.1's prescan is exactly that
/// question.
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
    /// that no stored resource record can have (RFC 6895 §3.1).
    ///
    /// RFC 2136 §3.4.1's prescan refuses an UPDATE that tries to *add* one, and
    /// that is the question this answers: not "is this ANY" but "could this ever
    /// be a record".
    pub const fn is_meta(self) -> bool {
        matches!(
            self.0,
            utils::record_types::ANY_CODE
                | utils::record_types::AXFR_CODE
                | utils::record_types::IXFR_CODE
        )
    }
}

impl std::fmt::Display for Rtype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", utils::record_type_name(*self))
    }
}

impl From<Rtype> for Qtype {
    /// Every TYPE is a legal QTYPE (RFC 1035 §3.2.3). The reverse does not
    /// exist, and that asymmetry is the whole point of the pair.
    fn from(rtype: Rtype) -> Qtype {
        Qtype(rtype.0)
    }
}

/// The type a *question* asks for — QTYPE, not TYPE (RFC 1035 §3.2.3).
///
/// A newtype because the two are different spaces and `u16` let them be
/// compared. QTYPE is "a superset of TYPE": it holds values **no resource
/// record can ever have** — ANY (255), AXFR (252), IXFR (251), MAILB (253) and
/// MAILA (254) — so `record.rtype == question.qtype` is false for every record
/// in a perfectly good answer whenever the question is one of those.
///
/// That has cost this codebase twice. `zone::of_type` returned nothing for
/// QTYPE=ANY, so an ANY query at a name with data came back as an empty NOERROR
/// plus the SOA — a NODATA for a name that has data, and none of the shapes
/// RFC 8482 §4 permits (`CLAUDE.md` §8). That was fixed at the call site, and
/// the same comparison was still written twice in `resolver.rs`: once to decide
/// whether a CNAME chase is finished, and once to decide whether an answer is
/// *negative* — which sent the DNSSEC validator looking for a denial proof that
/// a positive answer has no reason to carry, so an ANY answer that verified was
/// reported `Bogus("... was denied without an NSEC or NSEC3 proof")` and
/// `rdnsr --dnssec-validate` failed closed with SERVFAIL. Nothing on that path
/// rejects ANY, so a client only had to ask.
///
/// The fix is that there is no way to compare the two spaces except
/// [`Qtype::matches`], which knows what ANY means, and [`Qtype::is`], which asks
/// the narrower question out loud. See `TODO.md` #13c and `CLAUDE.md` §17.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Qtype(u16);

impl Qtype {
    /// `*` — every type at the name (RFC 1035 §3.2.3).
    pub const ANY: Qtype = Qtype(utils::record_types::ANY_CODE);
    /// A whole-zone transfer (RFC 5936). TCP only.
    pub const AXFR: Qtype = Qtype(utils::record_types::AXFR_CODE);
    /// An incremental transfer (RFC 1995).
    pub const IXFR: Qtype = Qtype(utils::record_types::IXFR_CODE);

    /// The question that asks for exactly this record type.
    ///
    /// `const`, so it can name a `Qtype` wherever `utils::record_types` names a
    /// TYPE — which is what keeps one registry of numbers rather than two that
    /// can drift (`CLAUDE.md` §7).
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

    /// Whether this question selects a stored record of type `rtype`.
    ///
    /// **The only comparison of a question's type against stored data**, and the
    /// reason this type exists. ANY means every type at the name (RFC 1035
    /// §3.2.3) — *except* the three DNSSEC meta types, which are not
    /// answer-section data unless the DO bit asked for them (RFC 4035 §3.1.1)
    /// and whose signatures are attached by `dnssec_answer::answer_signatures`,
    /// which knows which ones an answer actually owes. Returning them here would
    /// hand signatures to a client that cannot read them, duplicate them for one
    /// that can, and — the correctness bug rather than the noise — make an empty
    /// non-terminal in an NSEC-signed zone look like a name *with* data, because
    /// the chain puts an NSEC at it.
    pub fn matches(self, rtype: Rtype) -> bool {
        use utils::record_types as rt;
        if self == Qtype::ANY {
            !matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3)
        } else {
            self.0 == rtype.to_u16()
        }
    }

    /// Whether the question is for exactly `rtype` — the narrow question, with
    /// no ANY handling. Say this when "is the client asking for a DS?" is what
    /// is meant, so that the site does not read like a [`Qtype::matches`] that
    /// forgot about ANY.
    pub const fn is(self, rtype: Rtype) -> bool {
        self.0 == rtype.to_u16()
    }
}

impl std::fmt::Display for Qtype {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", utils::record_type_name(Rtype::new(self.0)))
    }
}

#[derive(Debug, Clone)]
pub struct QuerySection {
    // Contains the domain name for the question
    pub qname: String,
    /// The type asked for. See [`Qtype`] — a QTYPE is not a TYPE.
    pub qtype: Qtype,
    pub qclass: QueryClass,
}

/// Typed, fully-parsed view of a record's data.
///
/// This is produced on demand from [`RecordData`] via [`RecordData::parse`],
/// and consumed when building records via [`RecordData::from_parsed`]. It is
/// deliberately *not* what we store: keeping the parsed form (with its `String`s
/// and `Vec`s) resident for every cached record is what the raw-bytes storage
/// avoids. All domain names here are fully-qualified and uncompressed.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedRecord {
    A(Ipv4Addr),
    NS(String),
    CNAME(String),
    SOA {
        mname: String,
        rname: String,
        /// The zone's version. See [`Serial`] — the comparison is RFC 1982's,
        /// not `>`.
        serial: Serial,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
    PTR(String),
    MX {
        preference: u16,
        exchange: String,
    },
    /// One TXT record's `<character-string>`s (RFC 1035 §3.3.14).
    ///
    /// A sequence of byte strings, and both halves of that matter.
    ///
    /// **A sequence**, because the RDATA is a run of length-prefixed strings of
    /// at most 255 bytes each, and a record holding two of them is a different
    /// record from one holding the two joined together. Stored as a single
    /// unframed blob — which is what this was — the RDATA is something no
    /// correct client can read: the first byte of the text is taken for a length
    /// that nothing wrote.
    ///
    /// **Bytes**, because a character-string is arbitrary octets. As `String` it
    /// was worse than lossy: a TXT carrying non-UTF-8 data failed to decode, and
    /// since decoding happens while reading the message, one such record made
    /// the entire response unparseable.
    TXT(Vec<Vec<u8>>),
    AAAA(Ipv6Addr),
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    RRSIG {
        type_covered: Rtype,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        inception: u32,
        expiration: u32,
        key_tag: u16,
        signer_name: String,
        signature: Vec<u8>,
    },
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    NSEC {
        next_domain_name: String,
        type_bitmap: Vec<u8>,
    },
    NSEC3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed_owner: Vec<u8>,
        type_bitmap: Vec<u8>,
    },
    /// A record type we don't parse. `rtype` is carried by the enclosing
    /// [`RecordData`]; the raw bytes are preserved there too.
    Unknown(Rtype),
}

impl ParsedRecord {
    /// Decode wire-format RDATA into a typed record. `unpacker` resolves any
    /// compressed domain names against the message it was built over.
    pub(crate) fn decode<'a>(
        record_type: Rtype,
        rdata: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<Self, WireError> {
        // **RDLENGTH=0 is a record that names a type and carries no value**, and
        // it is legal: RFC 2136 §2.4.1 and §2.4.2 spell "an RRset of this type
        // exists / does not exist" as TYPE=t, CLASS=ANY or NONE, RDLENGTH=0, and
        // §2.5.2 and §2.5.3 spell "delete this RRset" the same way. The record
        // is a *specifier* there, not data, so there is nothing for a per-type
        // decoder to be given.
        //
        // Without this the arms below reject it — an A with no bytes is four
        // bytes short — and because `RecordData::from_wire` runs per record
        // while the message is being read, **the whole UPDATE became FORMERR at
        // the wire layer, before `update.rs` ever saw it**. So the half of
        // `TODO.md` #10 that exists could not receive the messages it
        // implements: every value-independent prerequisite and every RRset
        // deletion was unreadable. Nothing caught it because `update.rs`'s tests
        // build `DnsMessage` structs directly and never cross the wire, which is
        // `CLAUDE.md` §1 exactly — the tests were written from the same
        // understanding as the code, so the boundary the real message crosses
        // was the one thing never exercised.
        //
        // `Unknown` rather than a per-type empty variant, because "no value" is
        // the same fact whatever the type is, and because it is already what
        // happens for a type with no decoder: the bytes (none) are kept verbatim
        // and the TYPE is carried by the enclosing `RecordData`, so the record
        // goes back out as the zero-length RDATA it arrived as.
        //
        // The cost is that an *answer* holding, say, an A with RDLENGTH 0 now
        // parses rather than making the whole message FORMERR. That is the right
        // trade: one useless record relayed as it arrived, against refusing an
        // entire class of legal message — and RFC 3597 §5 already requires an
        // implementation to carry RDATA it cannot interpret.
        if rdata.is_empty() {
            return Ok(ParsedRecord::Unknown(record_type));
        }
        match record_type {
            utils::record_types::A => {
                let addr: [u8; 4] = rdata.try_into()?;
                Ok(ParsedRecord::A(Ipv4Addr::from(addr)))
            }
            utils::record_types::NS => {
                let (nsname, _) = dname_from_bytes(rdata, unpacker)?;
                Ok(ParsedRecord::NS(nsname))
            }
            utils::record_types::CNAME => {
                let (cname, _) = dname_from_bytes(rdata, unpacker)?;
                Ok(ParsedRecord::CNAME(cname))
            }
            utils::record_types::SOA => {
                let (mname, rest) = dname_from_bytes(rdata, unpacker)?;
                let (rname, rest) = dname_from_bytes(rest, unpacker)?;
                let (serial, rest) = read_be!(u32, rest);
                let serial = Serial::new(serial);
                let (refresh, rest) = read_be!(i32, rest);
                let (retry, rest) = read_be!(i32, rest);
                let (expire, rest) = read_be!(i32, rest);
                let (minimum, _) = read_be!(u32, rest);

                Ok(ParsedRecord::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
            }
            utils::record_types::PTR => {
                let (ptrdname, _) = dname_from_bytes(rdata, unpacker)?;
                Ok(ParsedRecord::PTR(ptrdname))
            }
            utils::record_types::MX => {
                let (preference, rest) = read_be!(u16, rdata);
                let (exchange, _) = dname_from_bytes(rest, unpacker)?;
                Ok(ParsedRecord::MX {
                    preference,
                    exchange,
                })
            }
            utils::record_types::TXT => {
                // A run of `<character-string>`s: one length byte, then that
                // many bytes, until the RDATA runs out.
                let mut strings = Vec::new();
                let mut rest = rdata;
                while let Some((&len, after_len)) = rest.split_first() {
                    let len = len as usize;
                    if after_len.len() < len {
                        return Err(WireError::Truncated {
                            what: "a TXT character-string",
                            need: len,
                            have: after_len.len(),
                        });
                    }
                    strings.push(after_len[..len].to_vec());
                    rest = &after_len[len..];
                }
                Ok(ParsedRecord::TXT(strings))
            }
            utils::record_types::AAAA => {
                let addr: [u8; 16] = rdata.try_into()?;
                Ok(ParsedRecord::AAAA(Ipv6Addr::from(addr)))
            }
            // DNSSEC types
            utils::record_types::DS => {
                // DS: key_tag(2) + algorithm(1) + digest_type(1) + digest(variable)
                let (key_tag, rest) = read_be!(u16, rdata);
                if rest.len() < 2 {
                    return Err(WireError::Truncated {
                        what: "DS RDATA",
                        need: 4,
                        have: rdata.len(),
                    });
                }
                let algorithm = rest[0];
                let digest_type = rest[1];
                let digest = rest[2..].to_vec();
                Ok(ParsedRecord::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                })
            }
            utils::record_types::RRSIG => {
                // RRSIG (RFC 4034 §3.1): type_covered(2) + algorithm(1) + labels(1)
                // + original_ttl(4) + expiration(4) + inception(4) + key_tag(2) +
                // signer_name + signature. Expiration precedes inception on the
                // wire — reading them the other way round makes an expired
                // signature look current, which is only invisible while both ends
                // of the round trip are ours.
                let (type_covered, rest) = read_be!(u16, rdata);
                if rest.len() < 2 {
                    return Err(WireError::Truncated {
                        what: "RRSIG RDATA",
                        need: 3,
                        have: rdata.len(),
                    });
                }
                let algorithm = rest[0];
                let labels = rest[1];
                let (original_ttl, rest) = read_be!(u32, &rest[2..]);
                let (expiration, rest) = read_be!(u32, rest);
                let (inception, rest) = read_be!(u32, rest);
                let (key_tag, rest) = read_be!(u16, rest);
                let (signer_name, rest) = dname_from_bytes(rest, unpacker)?;
                let signature = rest.to_vec();
                Ok(ParsedRecord::RRSIG {
                    type_covered: Rtype::new(type_covered),
                    algorithm,
                    labels,
                    original_ttl,
                    inception,
                    expiration,
                    key_tag,
                    signer_name,
                    signature,
                })
            }
            utils::record_types::NSEC => {
                // NSEC: next_domain_name + type_bitmap
                let (next_domain_name, rest) = dname_from_bytes(rdata, unpacker)?;
                let type_bitmap = rest.to_vec();
                Ok(ParsedRecord::NSEC {
                    next_domain_name,
                    type_bitmap,
                })
            }
            utils::record_types::DNSKEY => {
                // DNSKEY: flags(2) + protocol(1) + algorithm(1) + public_key(variable)
                let (flags, rest) = read_be!(u16, rdata);
                if rest.len() < 2 {
                    return Err(WireError::Truncated {
                        what: "DNSKEY RDATA",
                        need: 4,
                        have: rdata.len(),
                    });
                }
                let protocol = rest[0];
                let algorithm = rest[1];
                let public_key = rest[2..].to_vec();
                Ok(ParsedRecord::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                })
            }
            utils::record_types::NSEC3 => {
                // NSEC3: hash_algorithm(1) + flags(1) + iterations(2) + salt_len(1) + salt(variable) + next_hashed_owner + type_bitmap
                if rdata.len() < 5 {
                    return Err(WireError::Truncated {
                        what: "NSEC3 RDATA",
                        need: 5,
                        have: rdata.len(),
                    });
                }
                let hash_algorithm = rdata[0];
                let flags = rdata[1];
                let (iterations, rest) = read_be!(u16, &rdata[2..]);
                let salt_len = rest[0] as usize;
                if rest.len() < 1 + salt_len {
                    return Err(WireError::malformed(
                        "NSEC3 RDATA",
                        "the salt extends past the end of the record",
                    ));
                }
                let salt = rest[1..1 + salt_len].to_vec();
                let rest = &rest[1 + salt_len..];

                // next_hashed_owner is a raw byte string (not a domain name)
                if rest.is_empty() {
                    return Err(WireError::malformed(
                        "NSEC3 RDATA",
                        "there is no next-hashed-owner field",
                    ));
                }
                let next_owner_len = rest[0] as usize;
                if rest.len() < 1 + next_owner_len {
                    return Err(WireError::malformed(
                        "NSEC3 RDATA",
                        "the next-hashed-owner field extends past the end of the record",
                    ));
                }
                let next_hashed_owner = rest[1..1 + next_owner_len].to_vec();
                let type_bitmap = rest[1 + next_owner_len..].to_vec();

                Ok(ParsedRecord::NSEC3 {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                    next_hashed_owner,
                    type_bitmap,
                })
            }
            _ => Ok(ParsedRecord::Unknown(record_type)),
        }
    }

    /// Encode this record into `(rtype, uncompressed wire-format RDATA)`.
    ///
    /// The inverse of [`ParsedRecord::decode`] for the types we parse. Names
    /// are written uncompressed via [`dname_to_bytes`].
    pub(crate) fn encode(&self) -> Result<(Rtype, Vec<u8>), WireError> {
        let out = match self {
            ParsedRecord::A(addr) => (utils::record_types::A, addr.octets().to_vec()),
            ParsedRecord::AAAA(addr) => (utils::record_types::AAAA, addr.octets().to_vec()),
            ParsedRecord::NS(name) => (utils::record_types::NS, dname_to_bytes(name)?),
            ParsedRecord::CNAME(name) => (utils::record_types::CNAME, dname_to_bytes(name)?),
            ParsedRecord::PTR(name) => (utils::record_types::PTR, dname_to_bytes(name)?),
            ParsedRecord::MX {
                preference,
                exchange,
            } => {
                let mut v = preference.to_be_bytes().to_vec();
                v.extend_from_slice(&dname_to_bytes(exchange)?);
                (utils::record_types::MX, v)
            }
            ParsedRecord::TXT(strings) => {
                if strings.is_empty() {
                    return Err(WireError::malformed(
                        "a TXT record",
                        "it must carry at least one character-string",
                    ));
                }
                let mut v = Vec::new();
                for s in strings {
                    // The length is one byte, so 255 is the ceiling. Splitting a
                    // longer string across two character-strings would change
                    // what the record says, so this is the zone's mistake to fix.
                    let len = u8::try_from(s.len()).map_err(|_| WireError::TooLong {
                        what: "a TXT character-string",
                        limit: 255,
                        actual: s.len(),
                    })?;
                    v.push(len);
                    v.extend_from_slice(s);
                }
                (utils::record_types::TXT, v)
            }
            ParsedRecord::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let mut v = dname_to_bytes(mname)?;
                v.extend_from_slice(&dname_to_bytes(rname)?);
                v.extend_from_slice(&serial.to_u32().to_be_bytes());
                v.extend_from_slice(&refresh.to_be_bytes());
                v.extend_from_slice(&retry.to_be_bytes());
                v.extend_from_slice(&expire.to_be_bytes());
                v.extend_from_slice(&minimum.to_be_bytes());
                (utils::record_types::SOA, v)
            }
            ParsedRecord::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                let mut v = flags.to_be_bytes().to_vec();
                v.push(*protocol);
                v.push(*algorithm);
                v.extend_from_slice(public_key);
                (utils::record_types::DNSKEY, v)
            }
            ParsedRecord::RRSIG {
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
                let mut v = type_covered.to_u16().to_be_bytes().to_vec();
                v.push(*algorithm);
                v.push(*labels);
                v.extend_from_slice(&original_ttl.to_be_bytes());
                // Expiration first, then inception (RFC 4034 §3.1).
                v.extend_from_slice(&expiration.to_be_bytes());
                v.extend_from_slice(&inception.to_be_bytes());
                v.extend_from_slice(&key_tag.to_be_bytes());
                v.extend_from_slice(&dname_to_bytes(signer_name)?);
                v.extend_from_slice(signature);
                (utils::record_types::RRSIG, v)
            }
            ParsedRecord::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                let mut v = key_tag.to_be_bytes().to_vec();
                v.push(*algorithm);
                v.push(*digest_type);
                v.extend_from_slice(digest);
                (utils::record_types::DS, v)
            }
            ParsedRecord::NSEC {
                next_domain_name,
                type_bitmap,
            } => {
                let mut v = dname_to_bytes(next_domain_name)?;
                v.extend_from_slice(type_bitmap);
                (utils::record_types::NSEC, v)
            }
            ParsedRecord::NSEC3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmap,
            } => {
                let mut v = Vec::with_capacity(
                    6 + salt.len() + next_hashed_owner.len() + type_bitmap.len(),
                );
                v.push(*hash_algorithm);
                v.push(*flags);
                v.extend_from_slice(&iterations.to_be_bytes());
                v.push(salt.len() as u8);
                v.extend_from_slice(salt);
                v.push(next_hashed_owner.len() as u8);
                v.extend_from_slice(next_hashed_owner);
                v.extend_from_slice(type_bitmap);
                (utils::record_types::NSEC3, v)
            }
            // Opaque types are stored verbatim by `RecordData::from_wire`; there
            // is no typed payload to re-encode here.
            ParsedRecord::Unknown(rtype) => (*rtype, Vec::new()),
        };
        Ok(out)
    }
}

/// `PartialEq` is structural and includes the TTL, which is the right default
/// and not what every DNS comparison wants: RFC 2181 §5.2 says the TTLs within
/// one RRset must agree, so two records differing only in TTL are a malformed
/// RRset rather than two different records. Anywhere that distinction matters —
/// `ixfr`'s delta keys, `update`'s §2.5.4 deletion — compares the fields it
/// means rather than reaching for this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    /// The class this record is in. See [`Class`].
    pub class: Class,
    /// How long this record may be cached. See [`Ttl`].
    pub ttl: Ttl,
    pub rdata: RecordData,
}

/// How long a record may be cached, in seconds.
///
/// **A `u32`, and clamped at the parse boundary.** RFC 1035 §4.1.3 calls the
/// field "a 32 bit signed integer", and RFC 2181 §8 corrects it: the TTL is
/// unsigned, and "implementations should treat TTL values received with the most
/// significant bit set as if the entire value received was zero". That `.max(0)`
/// is what [`Ttl::from_wire`] does, once, where the bytes come off the wire.
///
/// It used to be an `i32` on [`ResourceRecord`], and the clamp was written out
/// by hand **fourteen times** — `cache`, `negative_cache`, five in `nsec_cache`,
/// four in `resolver`, `zone_signer`, two in test helpers — plus five
/// `.min(i32::MAX as u32) as i32` conversions going the other way. Every one of
/// them was correct. The one that was missing is the bug `CLAUDE.md` §2 records:
/// `ttl as u64` on a negative TTL is `u64::MAX`, which `min` then picked as the
/// smallest TTL in an RRset and pinned a cache entry for the life of the
/// process. §2's rule is that a clamp belongs at the boundary once rather than
/// at every use, and this is that rule applied to the value it was written for.
///
/// This could not be done before OPT left the additional section (`TODO.md`
/// #13d): an OPT record's TTL field is not a TTL at all — it packs the extended
/// RCODE, the EDNS version and the DO bit — so clamping every `ResourceRecord`
/// TTL at the parse boundary would have corrupted it. One field with two
/// meanings depending on a sibling field is exactly the conflation the section
/// is about, and the two halves had to land in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[repr(transparent)]
pub struct Ttl(u32);

impl Ttl {
    /// Zero seconds: do not cache (RFC 1035 §3.2.1).
    pub const ZERO: Ttl = Ttl(0);

    /// A TTL as it came off the wire, clamped per RFC 2181 §8.
    ///
    /// Total, and the only place the sign of the wire field is considered.
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

    /// The count of seconds, widened for arithmetic against a timestamp.
    ///
    /// A separate accessor rather than `as u64` at each site, because the
    /// widening is where the original bug lived: it is safe here only because
    /// the value is already non-negative by construction.
    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }

    /// This TTL, or `ceiling` if it is larger — the cap every cache applies.
    pub fn capped_at(self, ceiling: u32) -> Ttl {
        Ttl(if self.0 > ceiling { ceiling } else { self.0 })
    }

    /// The wire encoding: RFC 2181 §8 makes the field unsigned, so this is the
    /// same 32 bits, and a value with the top bit set can no longer be built.
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
/// **A newtype whose whole content is what it refuses to do.** It has no
/// `PartialOrd` and no `Ord`, so `a > b` does not compile and
/// [`Serial::is_newer_than`] is the only way to ask which of two versions is
/// later. That is the point: serials are RFC 1982 sequence-space numbers, not
/// integers. They wrap, and 32 bits at one bump a second is 136 years — but a
/// zone with a date-style serial that is edited past `4294967295`, or one
/// carried forward from another server, gets there sooner than that argument
/// suggests, and `signed_serial` adds hours-since-the-epoch to whatever the
/// operator wrote (`zone_signer::signed_serial`), which brings the ceiling
/// closer still.
///
/// **What a plain `>` costs is not a wrong answer once.** A secondary that reads
/// a wrapped increment as a rollback declines the transfer, and declines it
/// again on every refresh for the rest of the zone's life, because the
/// comparison that rejected it never changes its mind. The zone is frozen and
/// nothing is in a failed state to alert on.
///
/// This was already known here and already written down twice.
/// `secondary::is_newer` had it right and said why; `notify::changed_zones` then
/// wrote the same wrapping arithmetic out inline with its own copy of the
/// citation — `CLAUDE.md` §7's shape, in the one piece of arithmetic in DNS most
/// likely to be got wrong with a `>`. Both are gone; this is the copy.
///
/// **No live defect prompted this** (`TODO.md` #14a). Nothing in the tree
/// compared two serials with an operator, so there is no regression test that
/// fails against the old code — the compile error is the test, and it protects
/// the sites nobody has written yet. `CLAUDE.md` §17 is the argument: a fix that
/// lives in a type has not recurred here, and a fix that lives at a call site
/// always has.
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

    /// Whether this version is later than `other` (RFC 1982 §3.2).
    ///
    /// > s1 < s2 ... if s1 < s2 and (s2 - s1) < 2^(SERIAL_BITS - 1)
    ///
    /// Which in wrapping arithmetic is the whole of it: the forward distance is
    /// in the first half of the space. Equal serials are not newer — an
    /// unchanged zone is not news, and a secondary must not re-transfer one.
    ///
    /// **Not `PartialOrd`.** It cannot be: RFC 1982 §3.2 says so out loud for
    /// serials exactly half the space apart, where "the result ... is undefined"
    /// and neither is later. An `Ord` that has to pick one would be lying, and
    /// deriving one would give the plain `>` this type exists to forbid.
    pub const fn is_newer_than(self, other: Serial) -> bool {
        let forward = self.0.wrapping_sub(other.0);
        forward != 0 && forward < 0x8000_0000
    }

    /// This serial advanced by `increment`, wrapping (RFC 1982 §3.1).
    ///
    /// Wrapping is the defined addition in the sequence space, not an overflow
    /// to be avoided — which is why this is spelled out rather than left to
    /// `+`, whose debug panic would be the wrong answer at the one moment it
    /// mattered.
    pub const fn wrapping_add(self, increment: u32) -> Serial {
        Serial(self.0.wrapping_add(increment))
    }
}

impl std::fmt::Display for Serial {
    /// Forwards the whole formatter rather than `write!("{}", self.0)`, so that
    /// width and alignment survive: `zone_writer` writes `{serial:<12}` into a
    /// zone file's SOA block and `rdnsctl status` writes `{:>6}` into a column,
    /// and a `write!` that ignores the flags silently unaligns both.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::str::FromStr for Serial {
    type Err = std::num::ParseIntError;

    /// The presentation form is a decimal number and nothing else — the zone
    /// file's SOA field and the secondary state file's second column.
    fn from_str(text: &str) -> Result<Serial, Self::Err> {
        text.parse().map(Serial)
    }
}

/// A DNS response code: the 12-bit value of RFC 6891 §6.1.3, not the 4-bit
/// header field.
///
/// `Other` replaces what was an `Unknown = 65535` sentinel. The sentinel could
/// not carry the code it stood for, so [`DnsMessage::to_bytes`] mapped it to
/// **0** — and the resolver *does* relay upstream messages, so a response
/// carrying an rcode we have no name for was handed to the client as NOERROR.
/// An unrecognized failure became a successful empty answer, which is the one
/// direction this must never fail in. RFC 6895 §2.3 keeps the space open for
/// exactly this: codes get assigned after the code that relays them is written.
///
/// No explicit discriminants, because a variant with a payload forbids them.
/// The numbering lives in [`ResponseCode::from_u16`] and
/// [`ResponseCode::to_u16`] instead, which are each other's inverse over the
/// whole 16-bit range.
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

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,      // is the message response or query, QR
    pub opcode: OpCode,      // type of query, copied over to the response
    pub authoritive: bool,   // response: whether or not responding nameserver is the zone owner
    pub truncation: bool, // whether or not the message had to be truncated due to transmission channel
    pub recursion: bool,  // query: whether or not client wants server to do recursion
    pub recursion_ok: bool, // response: whether or not server support is available
    pub ad: bool,         // Authenticated Data bit (RFC 4035)
    pub cd: bool,         // Checking Disabled bit (RFC 4035)
    pub rcode: ResponseCode, // response status: whether or not response was succesful

    pub queries: Vec<QuerySection>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    /// The additional section **without** its OPT record — see [`DnsMessage::edns`].
    pub additionals: Vec<ResourceRecord>,
    /// The EDNS0 OPT pseudo-record, if the message carries one (RFC 6891).
    ///
    /// A field rather than a record in [`DnsMessage::additionals`], because OPT
    /// is not a resource record: it has no owner name that means anything, its
    /// CLASS is a payload size and its TTL is a flags word. Keeping it in the
    /// section cost eight linear scans of that `Vec` per message in this file
    /// alone, made every filter over the section responsible for remembering to
    /// spare it (`rdnsr`'s was `retain(|rr| rr.rdata.rtype() == OPT_RECORD_TYPE ||
    /// keep(rr))`), and left a malformed state representable: **two OPT records
    /// in one message**, which RFC 6891 §6.1.1 says MUST be FORMERR and which
    /// nothing here rejected — the first was read and both were re-serialized.
    /// `Option` makes two of them unspellable.
    pub edns: Option<Edns>,
}

/// The RR TYPE code of the EDNS0 OPT pseudo-record (RFC 6891).
pub const OPT_RECORD_TYPE: Rtype = Rtype::new(41);

/// The classic (pre-EDNS) UDP message size limit (RFC 1035 §4.2.1).
pub const CLASSIC_UDP_SIZE: u16 = 512;

/// The EDNS version we implement. A request at a higher version gets BADVERS
/// (RFC 6891 §6.1.3).
pub const EDNS_VERSION: u8 = 0;

/// A message with its RFC 1035 §4.2.2 two-octet length prefix, in one buffer so
/// a writer emits both in a single call.
///
/// **The check is the point.** This existed five times over as
/// `bytes.len() as u16`, once per binary and twice in the library, and a message
/// past 65,535 octets was therefore framed with a *wrapped* length. At exactly
/// 65,536 the prefix is **0**, which every read loop here treats as a broken
/// peer: the connection is dropped with no answer and nothing on either side
/// saying why. Larger overshoots give a small non-zero prefix instead, which
/// desynchronises the stream — the reader takes the next N octets of a message
/// body for a whole message.
///
/// `CLAUDE.md` §2 is about `as` on a value coming *off* the wire; this is the
/// same cast going the other way, and [`DnsMessage::to_bytes`] is the sibling
/// that shows the shape it should have — RDLENGTH, ARCOUNT and the OPT RDLENGTH
/// all go through `try_into` and a [`WireError::TooLong`], within twenty lines
/// of each other in this same file.
///
/// **How a message gets here over the limit at all**, since `to_bytes_within`
/// cannot return more than it was given: [`crate::tsig`] appends a TSIG record
/// to the *finished* bytes. That is the one path that can grow a message past
/// the size it was serialized to, and it now refuses rather than producing
/// something no framing can express.
pub fn framed(bytes: &[u8]) -> Result<Vec<u8>, WireError> {
    let len: u16 = bytes.len().try_into().map_err(|_| WireError::TooLong {
        what: "a TCP message",
        limit: u16::MAX as usize,
        actual: bytes.len(),
    })?;
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

// EDNS option codes from the IANA "DNS EDNS0 Option Codes" registry. We don't
// interpret any of these yet — options round-trip as opaque bytes — but naming
// the common ones keeps call sites readable.
/// Name Server Identifier (RFC 5001).
pub const EDNS_OPTION_NSID: u16 = 3;
/// Client Subnet (RFC 7871).
pub const EDNS_OPTION_CLIENT_SUBNET: u16 = 8;
/// DNS Cookie (RFC 7873).
pub const EDNS_OPTION_COOKIE: u16 = 10;
/// Padding (RFC 7830).
pub const EDNS_OPTION_PADDING: u16 = 12;

/// A single EDNS option carried in the OPT RDATA (RFC 6891 §6.1.2): a 16-bit
/// option code, a 16-bit length, then that many bytes of option data.
///
/// Option data is stored verbatim; we don't interpret any option's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

/// EDNS0 OPT pseudo-record (RFC 6891).
///
/// OPT is carried as a record in the additional section, but repurposes the
/// usual RR fields: NAME is root, CLASS is the requestor's UDP payload size, and
/// TTL packs the extended-RCODE / version / flags (including the DNSSEC-OK bit).
/// We interpret it on top of the generic [`ResourceRecord`] storage rather than
/// giving [`DnsMessage`] dedicated fields.
///
/// The extended RCODE is deliberately *not* a field here: it is a property of
/// the message, not of the OPT record, so it lives in [`DnsMessage::rcode`] as a
/// single 12-bit value and is split across the header and the OPT TTL only at
/// serialization time. See [`DnsMessage::to_bytes`].
/// The option list is held **unparsed**, and that is load-bearing rather than an
/// optimization.
///
/// The three fields above it come from the OPT record's CLASS and TTL, so a
/// parsed record always has them and nothing about them can be malformed —
/// [`EdnsHeader`] says so already. The option list is the only fallible part,
/// and if reading it were part of parsing the *message*, a bad list would make
/// `DnsMessage::try_from_bytes` fail. `rdnsd` returns `Vec::new()` on a parse
/// failure (`main.rs:1465` and `:2072`) and `error_bytes` needs a parsed message
/// to answer from, so that would turn today's diagnosable FORMERR into a client
/// timeout. Keeping the bytes and parsing on demand is what preserves the reply.
///
/// It also preserves the allocation profile: the answer path reads the payload
/// size, the version and the DO bit and never looks at an option, so nothing
/// builds a `Vec<EdnsOption>` unless something asks for the options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edns {
    /// Requestor's/responder's advertised UDP payload size (OPT CLASS field).
    pub udp_payload_size: u16,
    /// EDNS version (0 for EDNS0).
    pub version: u8,
    /// DNSSEC OK bit (DO) — the client is willing to receive DNSSEC records.
    pub do_bit: bool,
    /// The OPT RDATA: the option list in wire form. See the note above.
    rdata: Box<[u8]>,
}

/// The three EDNS parameters a server acts on, without the option list.
///
/// Everything on the answer path asks the same three questions of a request's
/// OPT record — how big a reply may be, is this a version we implement, does the
/// client want DNSSEC records — and none of them asks what the options were.
/// [`Edns`] carries those too, which means a `Vec` and a `Vec<u8>` per option
/// allocated and dropped again at every call site that only wanted a flag; the
/// two in `rdnsd`'s `make_response` are sixteen lines apart (`TODO.md` #9e).
///
/// `Copy`, so threading it through a function costs nothing and nobody is
/// tempted to re-derive it. The option list is still there for a caller that
/// wants it: [`DnsMessage::edns`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdnsHeader {
    /// Requestor's advertised UDP payload size (OPT CLASS field), as sent —
    /// **not** floored at 512. [`DnsMessage::udp_payload_size`] is the one that
    /// applies RFC 6891 §6.2.3's floor, because that is a question about what we
    /// may send rather than about what the client wrote.
    pub udp_payload_size: u16,
    /// EDNS version. Anything but 0 is BADVERS (RFC 6891 §6.1.3).
    pub version: u8,
    /// DNSSEC OK: the client can make sense of DNSSEC records (RFC 3225).
    pub do_bit: bool,
}

impl Edns {
    /// The parameters without the options — see [`EdnsHeader`].
    pub fn header(&self) -> EdnsHeader {
        EdnsHeader {
            udp_payload_size: self.udp_payload_size,
            version: self.version,
            do_bit: self.do_bit,
        }
    }

    /// A plain OPT advertising `size` bytes, EDNS version 0, DO clear, no options.
    pub fn with_payload_size(size: u16) -> Self {
        Edns {
            udp_payload_size: size,
            version: EDNS_VERSION,
            do_bit: false,
            rdata: Box::new([]),
        }
    }

    /// An OPT carrying `options`, encoded into RDATA once here rather than at
    /// serialization time.
    ///
    /// Errors only if an option's data exceeds the 16-bit length field.
    pub fn with_options(
        size: u16,
        version: u8,
        do_bit: bool,
        options: &[EdnsOption],
    ) -> Result<Self, WireError> {
        let mut rdata = Vec::new();
        for opt in options {
            let len: u16 = opt.data.len().try_into().map_err(|_| WireError::TooLong {
                what: "EDNS option data",
                limit: u16::MAX as usize,
                actual: opt.data.len(),
            })?;
            rdata.extend_from_slice(&opt.code.to_be_bytes());
            rdata.extend_from_slice(&len.to_be_bytes());
            rdata.extend_from_slice(&opt.data);
        }
        Ok(Edns {
            udp_payload_size: size,
            version,
            do_bit,
            rdata: rdata.into_boxed_slice(),
        })
    }

    /// The option list, parsed. A malformed list is an error rather than a
    /// partial read: a client that sends one deserves FORMERR, not a silently
    /// truncated view of what it asked for.
    pub fn options(&self) -> Result<Vec<EdnsOption>, WireError> {
        let mut options = Vec::new();
        Self::walk_options(&self.rdata, |code, data| {
            options.push(EdnsOption {
                code,
                data: data.to_vec(),
            })
        })?;
        Ok(options)
    }

    /// Whether the option list is well formed, without building it.
    ///
    /// This is the FORMERR question, and it is separate from [`Edns::options`]
    /// because the answer path asks it and never wants the options themselves.
    pub fn check_options(&self) -> Result<(), WireError> {
        Self::walk_options(&self.rdata, |_, _| {})
    }

    /// The data of the first option with `code`, if the list is well formed.
    pub fn option(&self, code: u16) -> Result<Option<Vec<u8>>, WireError> {
        let mut found = None;
        Self::walk_options(&self.rdata, |c, data| {
            if c == code && found.is_none() {
                found = Some(data.to_vec());
            }
        })?;
        Ok(found)
    }

    /// The OPT RDATA as it will go on the wire.
    fn rdata(&self) -> &[u8] {
        &self.rdata
    }

    /// Walk the option list, handing each option's code and data to `each`
    /// without copying either.
    ///
    /// The walk is here once and has three callers because it answers two
    /// different questions: [`Edns::options`] wants the options, and
    /// [`Edns::check_options`] only wants to know that they are well formed
    /// — the answer path reads the payload size, the version and the DO bit and
    /// never looks at an option. A second copy of the TLV arithmetic for the
    /// checking case is exactly the drift `CLAUDE.md` §7 is about, and this one
    /// decides whether a packet is FORMERR.
    fn walk_options(mut rdata: &[u8], mut each: impl FnMut(u16, &[u8])) -> Result<(), WireError> {
        while !rdata.is_empty() {
            if rdata.len() < 4 {
                return Err(WireError::Truncated {
                    what: "an EDNS option header",
                    need: 4,
                    have: rdata.len(),
                });
            }
            let code = u16::from_be_bytes([rdata[0], rdata[1]]);
            let len = u16::from_be_bytes([rdata[2], rdata[3]]) as usize;
            rdata = &rdata[4..];
            if rdata.len() < len {
                return Err(WireError::Truncated {
                    what: "EDNS option data",
                    need: len,
                    have: rdata.len(),
                });
            }
            each(code, &rdata[..len]);
            rdata = &rdata[len..];
        }
        Ok(())
    }
}

impl<'a> TryUnpackFromBytes<'a> for QuerySection {
    type Output = (QuerySection, &'a [u8]);
    type Error = WireError;
    fn try_from_bytes(
        data: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<
        <QuerySection as TryUnpackFromBytes<'a>>::Output,
        <QuerySection as TryUnpackFromBytes<'a>>::Error,
    > {
        let (qname, rest) = dname_from_bytes(data, unpacker)?;
        let (qtype, rest) = read_be!(u16, rest);
        let (qclass, rest) = read_be!(u16, rest);
        Ok((
            Self {
                qname,
                // Total: every 16-bit value is a QTYPE, including the ones no
                // record can hold. See [`Qtype`].
                qtype: Qtype::from_u16(qtype),
                // Total, and it has to be: a class we have no name for is
                // echoed back unchanged, not folded onto one we do.
                qclass: QueryClass::from_u16(qclass),
            },
            rest,
        ))
    }
}

/// The fields of one resource record, read straight off the wire.
///
/// Exists because the additional section has to know a record's TYPE *before* it
/// can decide whether the record is a resource record at all — an OPT is not —
/// and the first version answered that by parsing the owner name twice. That
/// cost an extra `String` per OPT-bearing message, which is every modern query:
/// `tests/allocations.rs` put it at **8 allocations to parse an EDNS query
/// against 7 before**, found while reviewing #13 rather than by the gate, since
/// nothing measured that path. Reading the fields once and branching afterwards
/// is both the fix and the removal of a second copy of this field arithmetic
/// (`CLAUDE.md` §7).
///
/// `ttl_bits` is deliberately raw. An OPT record's TTL field is not a TTL — it
/// packs the extended RCODE, the EDNS version and the DO bit — so the clamp of
/// RFC 2181 §8 belongs to whichever branch knows it is holding a real record.
struct RecordParts<'a> {
    name: String,
    rtype: Rtype,
    class: u16,
    ttl_bits: i32,
    rdata: &'a [u8],
}

fn read_record_parts<'a>(
    data: &'a [u8],
    unpacker: &DNameUnpacker<'a>,
) -> Result<(RecordParts<'a>, &'a [u8]), WireError> {
    let (name, rest) = dname_from_bytes(data, unpacker)?;
    let (rtype, rest) = read_be!(u16, rest);
    let (class, rest) = read_be!(u16, rest);
    let (ttl_bits, rest) = read_be!(i32, rest);
    let (rdatalen, rest) = read_be!(u16, rest);
    // RDLENGTH is attacker-chosen and every other length in this file is
    // checked before it is used — `read_be!` checks its own bytes,
    // `Label::try_from_bytes` checks before slicing, `walk_options` checks each
    // option. This one was not, and a record declaring more RDATA than the
    // message carries panicked the parser on a bare slice. That is reachable
    // before any authentication on both transports, in `rdnsr` where no
    // validator runs at all, and from a primary during a transfer — where it
    // kills a replication task that is never restarted, so the zone silently
    // stops refreshing until EXPIRE. `split_at` cannot be used until the length
    // is known good, which is the whole point.
    let rdatalen = rdatalen as usize;
    if rest.len() < rdatalen {
        return Err(WireError::Truncated {
            what: "RDATA",
            need: rdatalen,
            have: rest.len(),
        });
    }
    let (rdata, rest) = rest.split_at(rdatalen);
    Ok((
        RecordParts {
            name,
            rtype: Rtype::new(rtype),
            class,
            ttl_bits,
            rdata,
        },
        rest,
    ))
}

impl<'a> TryUnpackFromBytes<'a> for ResourceRecord {
    type Output = (ResourceRecord, &'a [u8]);
    type Error = WireError;
    fn try_from_bytes(
        data: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<<Self as TryUnpackFromBytes<'a>>::Output, Self::Error> {
        let (parts, rest) = read_record_parts(data, unpacker)?;
        Ok((ResourceRecord::from_parts(parts, unpacker)?, rest))
    }
}

impl ResourceRecord {
    /// Assemble a record from its wire fields. This is where a real record's
    /// TTL is clamped (RFC 2181 §8) — see [`RecordParts::ttl_bits`].
    fn from_parts(parts: RecordParts<'_>, unpacker: &DNameUnpacker<'_>) -> Result<Self, WireError> {
        Ok(ResourceRecord {
            name: parts.name,
            class: Class::new(parts.class),
            ttl: Ttl::from_wire(parts.ttl_bits),
            rdata: RecordData::from_wire(parts.rtype, parts.rdata, unpacker)?,
        })
    }
}

/// One record of the additional section: an ordinary record, or the OPT
/// pseudo-record it is not.
enum Additional {
    Record(ResourceRecord),
    /// The OPT record, and its raw 32-bit flags word — whose top byte is the
    /// extended RCODE's high bits and belongs to the *message*, not to the OPT
    /// record. [`Edns`] documents that split; this carries the value across it.
    Opt(Edns, u32),
}

impl Additional {
    /// Read one additional-section record.
    ///
    /// OPT is decoded from the wire fields directly rather than being built as a
    /// [`ResourceRecord`] and taken apart afterwards, and that is a correctness
    /// requirement rather than tidiness: an OPT record's TTL field is **not a
    /// TTL**. It packs the extended RCODE, the EDNS version and the DO bit
    /// (RFC 6891 §6.1.3), so putting it through [`Ttl::from_wire`] — which
    /// clamps a negative value to zero per RFC 2181 §8 — would erase all three
    /// whenever the extended RCODE's high byte has its top bit set. Nothing
    /// sends that today, and "nothing sends that today" is not a reason to
    /// build a parser that cannot represent it.
    fn try_from_bytes<'a>(
        data: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<(Additional, &'a [u8]), WireError> {
        let (parts, rest) = read_record_parts(data, unpacker)?;
        if parts.rtype != OPT_RECORD_TYPE {
            return Ok((
                Additional::Record(ResourceRecord::from_parts(parts, unpacker)?),
                rest,
            ));
        }
        // CLASS is the requestor's UDP payload size and TTL is a flags word
        // (RFC 6891 §6.1.3). Neither goes through `Class` or `Ttl`, because
        // neither is one.
        let flags = parts.ttl_bits as u32;
        Ok((
            Additional::Opt(
                Edns {
                    udp_payload_size: parts.class,
                    version: ((flags >> 16) & 0xff) as u8,
                    do_bit: (flags & 0x8000) != 0,
                    // The extended RCODE's high byte lives in the top of
                    // `flags` and is *not* kept here: it is a property of the
                    // message, so `DnsMessage` reassembles it into `rcode`.
                    rdata: parts.rdata.to_vec().into_boxed_slice(),
                },
                flags,
            ),
            rest,
        ))
    }
}

impl DnsMessage {
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, WireError> {
        if data.len() < 12 {
            return Err(WireError::Truncated {
                what: "the DNS header",
                need: 12,
                have: data.len(),
            });
        }

        let unpacker = DNameUnpacker::new(data);

        let (id, rest) = read_be!(u16, data);
        let (hi, rest) = read_be!(u8, rest);
        let (lo, rest) = read_be!(u8, rest);
        let (query_len, rest) = read_be!(u16, rest);
        let (answer_len, rest) = read_be!(u16, rest);
        let (auth_len, rest) = read_be!(u16, rest);
        let (add_len, mut rest) = read_be!(u16, rest);

        // The opcode is bits 3..6 of the flags' high byte, so it has to be
        // shifted down. Masking in place (`hi & 0x70`) read every opcode wrong:
        // it dropped the low bit, so IQUERY (1) came out as QUERY and NOTIFY (4),
        // UPDATE (5) and STATUS (2) all came out as `Unknown` — while the *write*
        // side shifted correctly, so the two disagreed. Nothing noticed because
        // every test used QUERY, whose value survives any mask.
        //
        // Total, and it has to be: an opcode we have no name for is echoed back
        // unchanged (RFC 1035 §4.1.1), not folded onto one we do. The
        // `.unwrap_or(OpCode::Unknown)` this replaced turned eleven of the
        // sixteen into 15 on the way out — see [`OpCode`].
        let opcode = OpCode::from_u8(hi >> 3);

        let mut queries: Vec<QuerySection> = Vec::new();
        for _ in 0..query_len {
            let (query, r) = QuerySection::try_from_bytes(rest, &unpacker)?;
            queries.push(query);
            rest = r;
        }

        let mut answers = Vec::new();
        for _ in 0..answer_len {
            let (query, r) = ResourceRecord::try_from_bytes(rest, &unpacker)?;
            answers.push(query);
            rest = r;
        }

        let mut authorities = Vec::new();
        for _ in 0..auth_len {
            let (query, r) = ResourceRecord::try_from_bytes(rest, &unpacker)?;
            authorities.push(query);
            rest = r;
        }

        // The additional section, with the OPT pseudo-record taken out as it is
        // read rather than fished back out of a list of resource records.
        let mut additionals = Vec::new();
        let mut edns: Option<Edns> = None;
        let mut ext_rcode: u16 = 0;
        for _ in 0..add_len {
            let (item, r) = Additional::try_from_bytes(rest, &unpacker)?;
            match item {
                Additional::Record(rr) => additionals.push(rr),
                Additional::Opt(opt, flags) => {
                    // RFC 6891 §6.1.1: "If a query message with more than one
                    // OPT RR is received, a FORMERR (RCODE=1) MUST be returned."
                    // Nothing checked this before OPT became a field — the first
                    // was read and every one of them was written back out.
                    if edns.is_some() {
                        return Err(WireError::malformed(
                            "the additional section",
                            "more than one OPT record; RFC 6891 §6.1.1 allows one",
                        ));
                    }
                    ext_rcode = (flags >> 24) as u16;
                    edns = Some(opt);
                }
            }
            rest = r;
        }

        // RCODE is 12 bits (RFC 6891 §6.1.3): the low 4 in the header, the high
        // 8 in the OPT record's TTL when the message carries one. Reassemble
        // them so `rcode` is the whole value; without OPT the high bits are 0
        // and this is the classic 4-bit code.
        // RCODE is 12 bits: the low 4 in the header, the high 8 in the OPT
        // record's flags word. The option list is *not* read here — a malformed
        // one must not fail the parse, or the FORMERR that answers it could not
        // be built (see [`Edns`]).
        let rcode = ResponseCode::from_u16((ext_rcode << 4) | (lo & 0x0f) as u16);

        Ok(Self {
            id,
            response: hi & 0x80 == 0x80,
            opcode,
            authoritive: hi & 0x04 == 0x04,
            truncation: hi & 0x02 == 0x02,
            recursion: hi & 0x01 == 0x01,
            recursion_ok: lo & 0x80 == 0x80,
            ad: lo & 0x20 == 0x20,
            cd: lo & 0x10 == 0x10,
            rcode,
            queries,
            answers,
            authorities,
            additionals,
            edns,
        })
    }

    /// Serialize the message into `output`, with domain-name compression
    /// (RFC 1035 §4.1.4). Returns the number of bytes written; errors if the
    /// message does not fit rather than writing a silently truncated one.
    pub fn to_bytes(&self, output: &mut [u8]) -> Result<usize, WireError> {
        let mut compressor = NameCompressor::new();
        let mut pos = 0;

        pos = write_bytes(output, pos, &self.id.to_be_bytes())?;

        let opcode = self.opcode.to_u8();

        // RCODE is a 12-bit value split across the header (low 4 bits) and the
        // OPT record's TTL (high 8). This used to read
        // `match self.rcode.to_u16() { Some(v) if v <= 0xfff => v, _ => 0 }`,
        // which turned the old `Unknown` sentinel — and any code above 0xfff —
        // into **NOERROR**. `to_u16` is infallible now, so the only thing left
        // to check is the 12-bit ceiling, and a value past it is a bug in the
        // caller rather than something to paper over with a success code.
        let rcode = self.rcode.to_u16();
        if rcode > 0xfff {
            return Err(WireError::malformed(
                "the header",
                format!("RCODE {rcode} does not fit the 12 bits RFC 6891 §6.1.3 gives it"),
            ));
        }
        if rcode > 0xf && self.edns.is_none() {
            return Err(WireError::malformed(
                "the header",
                format!(
                    "extended RCODE {rcode} needs an EDNS0 OPT record to carry                      its high bits (RFC 6891 §6.1.3)"
                ),
            ));
        }

        let hi: u8 = (self.response as u8) << 7
            | (opcode & 0xf_u8) << 3
            | (self.authoritive as u8) << 2
            | (self.truncation as u8) << 1
            | self.recursion as u8;
        let lo: u8 = (self.recursion_ok as u8) << 7
            | (self.ad as u8) << 5
            | (self.cd as u8) << 4
            | (rcode & 0xf) as u8;

        pos = write_bytes(output, pos, &[hi, lo])?;
        pos = write_bytes(output, pos, &(self.queries.len() as u16).to_be_bytes())?;
        pos = write_bytes(output, pos, &(self.answers.len() as u16).to_be_bytes())?;
        pos = write_bytes(output, pos, &(self.authorities.len() as u16).to_be_bytes())?;
        // ARCOUNT counts the OPT record, which is a field here rather than a
        // member of `additionals`. Getting this wrong is the arithmetic most
        // likely to break when OPT moved, so it is one expression and not two.
        let arcount = self.additionals.len() + usize::from(self.edns.is_some());
        let arcount: u16 = arcount.try_into().map_err(|_| WireError::TooLong {
            what: "the additional section",
            limit: u16::MAX as usize,
            actual: arcount,
        })?;
        pos = write_bytes(output, pos, &arcount.to_be_bytes())?;

        for q in &self.queries {
            pos = compressor.write_name(q.qname.as_str(), output, pos)?;
            pos = write_bytes(output, pos, &q.qtype.to_u16().to_be_bytes())?;
            pos = write_bytes(output, pos, &q.qclass.to_u16().to_be_bytes())?;
        }

        // Resource records. Owner names are compressed against everything
        // written so far; RDATA is stored uncompressed and wire-ready, so it is
        // a straight copy except for the record types whose embedded names may
        // legally be compressed (see [`NameCompressor::write_rdata`]).
        for section in [&self.answers, &self.authorities, &self.additionals] {
            for rr in section {
                pos = compressor.write_name(rr.name.as_str(), output, pos)?;
                pos = write_bytes(output, pos, &rr.rdata.rtype().to_u16().to_be_bytes())?;
                pos = write_bytes(output, pos, &rr.class.to_u16().to_be_bytes())?;
                pos = write_bytes(output, pos, &rr.ttl.to_wire().to_be_bytes())?;

                // RDLEN can only be known once the RDATA is written, since
                // compression changes its length. Leave a hole and fill it in.
                let rdlen_at = pos;
                pos = write_bytes(output, pos, &[0u8, 0u8])?;
                let rdata_at = pos;
                pos = compressor.write_rdata(rr.rdata.rtype(), rr.rdata.bytes(), output, pos)?;
                let rdlen: u16 = (pos - rdata_at)
                    .try_into()
                    .map_err(|_| WireError::TooLong {
                        what: "RDATA",
                        limit: u16::MAX as usize,
                        actual: pos - rdata_at,
                    })?;
                write_bytes(output, rdlen_at, &rdlen.to_be_bytes())?;
            }
        }

        // The OPT record, last in the additional section.
        //
        // Last on purpose: `tsig::append_tsig` appends its record to the
        // finished bytes and bumps ARCOUNT itself, so whatever this writes ends
        // up before the TSIG — which RFC 8945 §5.1 requires to be final. Writing
        // OPT before the other additionals would still satisfy that; writing it
        // here keeps the wire order a client sees closest to what it sent.
        if let Some(edns) = &self.edns {
            // NAME is root, TYPE is OPT, CLASS is the payload size and TTL packs
            // the extended RCODE, the version and the flags (RFC 6891 §6.1.3).
            pos = write_bytes(output, pos, &[0])?;
            pos = write_bytes(output, pos, &OPT_RECORD_TYPE.to_u16().to_be_bytes())?;
            pos = write_bytes(output, pos, &edns.udp_payload_size.to_be_bytes())?;
            let ttl = ((rcode as u32 >> 4) << 24)
                | ((edns.version as u32) << 16)
                | if edns.do_bit { 0x8000 } else { 0 };
            pos = write_bytes(output, pos, &ttl.to_be_bytes())?;
            let rdata = edns.rdata();
            let rdlen: u16 = rdata.len().try_into().map_err(|_| WireError::TooLong {
                what: "OPT RDATA",
                limit: u16::MAX as usize,
                actual: rdata.len(),
            })?;
            pos = write_bytes(output, pos, &rdlen.to_be_bytes())?;
            pos = write_bytes(output, pos, rdata)?;
        }
        Ok(pos)
    }

    /// The message's EDNS parameters, if it carries an OPT record.
    ///
    /// Infallible now, and that is the change: the OPT record is a field rather
    /// than something to be found in [`DnsMessage::additionals`], and its
    /// option list is carried unparsed (see [`Edns`]). "Does this message do
    /// EDNS" and "is its option list well formed" were one fallible question
    /// and are now two.
    pub fn edns(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    /// The EDNS parameters a server acts on, with the option list checked but
    /// not built — see [`EdnsHeader`]. `Err` on a malformed option list, which
    /// is the caller's cue to answer FORMERR.
    pub fn edns_header(&self) -> Result<Option<EdnsHeader>, WireError> {
        let Some(edns) = &self.edns else {
            return Ok(None);
        };
        edns.check_options()?;
        Ok(Some(edns.header()))
    }

    /// Whether the message carries an OPT record at all, regardless of whether
    /// its options parse. Use this to decide OPT mirroring (RFC 6891 §6.1.1).
    pub fn has_edns(&self) -> bool {
        self.edns.is_some()
    }

    /// The requestor's advertised UDP payload size: the EDNS value (floored at
    /// the classic 512 per RFC 6891 §6.2.3) if present, else the classic 512.
    ///
    /// The payload size lives in the OPT CLASS field, so it is readable even
    /// when the option list is malformed; a bad option list just falls back to
    /// the safe classic size.
    pub fn udp_payload_size(&self) -> u16 {
        self.edns
            .as_ref()
            .map(|e| e.udp_payload_size.max(CLASSIC_UDP_SIZE))
            .unwrap_or(CLASSIC_UDP_SIZE)
    }

    /// Set the message's OPT record, replacing any it already had.
    ///
    /// Infallible: encoding the option list is [`Edns::with_options`]' job now,
    /// so there is nothing left here that can fail. The `Result` it used to
    /// return is kept off deliberately — every caller was writing `let _ =`.
    pub fn set_edns(&mut self, edns: Edns) {
        self.edns = Some(edns);
    }

    /// Serialize, truncating to `max_len` bytes (RFC 1035 §4.2.1). If the full
    /// message doesn't fit, the answer/authority records are dropped (the OPT
    /// record and question are kept) and TC=1 is set so the client retries over
    /// TCP. Returns the wire bytes.
    pub fn to_bytes_within(&self, max_len: usize) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.to_bytes_within_buf(max_len, &mut out)?;
        Ok(out)
    }

    /// [`Self::to_bytes_within`] into a caller-owned buffer, which is left
    /// holding exactly the wire bytes.
    ///
    /// This exists so a hot send path can keep one scratch buffer and allocate
    /// nothing per response. `to_bytes_within` used to serialize into
    /// `vec![0u8; u16::MAX as usize]` — 64 KB, zeroed, per response — and
    /// `Vec::truncate` **does not release capacity**, so the `Vec` handed to
    /// `send_to` and held until the send completed was 64 KB whatever the answer
    /// was. Confirmed: a 60-byte response retained capacity 65535, and a DHAT
    /// probe of the same shape reported 65,560,600 bytes live in 1,002 blocks
    /// for a thousand of them. Measured cost on a 3-record response: 1043 ns vs
    /// 718 ns with a reused buffer — a third of serialization was allocator
    /// traffic, and not optimizer-erasable because the allocation escapes into
    /// the socket call.
    ///
    /// The buffer is sized to what the caller will actually send rather than to
    /// the protocol maximum. Only the TCP and transfer paths pass `u16::MAX`;
    /// a UDP caller passes its EDNS payload size, and now pays for that.
    pub fn to_bytes_within_buf(&self, max_len: usize, out: &mut Vec<u8>) -> Result<(), WireError> {
        out.clear();
        out.resize(max_len, 0);
        match self.to_bytes(out) {
            Ok(n) if n <= max_len => {
                out.truncate(n);
                return Ok(());
            }
            // Fits the buffer but not the limit — only reachable when a caller
            // passes a `max_len` above what it means to send, which none do.
            Ok(_) => {}
            // The message did not fit, which is the ordinary reason to truncate.
            // Sizing the scratch to `max_len` is what turns "too long" from a
            // comparison into an error, so it has to be caught rather than
            // propagated; every other `WireError` is a real failure to encode.
            Err(WireError::Truncated {
                what: "the output buffer",
                ..
            }) => {}
            Err(e) => return Err(e),
        }

        let mut truncated = self.clone();
        truncated.truncation = true;
        truncated.answers.clear();
        truncated.authorities.clear();
        // `truncated.edns` is carried over untouched: the DNS message size
        // limit is itself signalled via EDNS, so the OPT record must survive
        // truncation. It used to be a `retain` over the additional section that
        // had to remember to spare it.
        truncated.additionals.clear();

        // The floor is the classic 512: a header, a question and an OPT record
        // fit there, and a caller that asked for less than a minimal response
        // can hold still gets a well-formed TC=1 answer to retry on.
        out.clear();
        out.resize(max_len.max(CLASSIC_UDP_SIZE as usize), 0);
        let n = truncated.to_bytes(out)?;
        out.truncate(n);
        Ok(())
    }
}

#[derive(Default)]
pub struct DnsMessageBuilder {
    id: u16,
    queries: Vec<(String, Rtype)>,
    /// Whether to attach an OPT record, and with DO set.
    ///
    /// The shipped client could not ask for DNSSEC at all, which meant it could
    /// not exercise this library's most complex feature — and *that* is why
    /// every DNSSEC recipe in `TODO.md` reaches for dnspython (`TODO.md` #19h).
    dnssec: bool,
}

impl DnsMessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_url(mut self, url: &str, query_type: &str) -> Self {
        if let Some(q) = utils::record_type_name_to_code(query_type) {
            self.queries.push((url.to_owned(), q));
        }
        self
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    /// Ask for DNSSEC records: an EDNS0 OPT with DO set (RFC 4035 §3.2.1).
    ///
    /// Without DO a server is *required* not to send RRSIG, NSEC or NSEC3, so a
    /// client that cannot set it cannot see any of the signing this library
    /// does.
    pub fn with_dnssec(mut self, dnssec: bool) -> Self {
        self.dnssec = dnssec;
        self
    }

    pub fn build(&self) -> DnsMessage {
        let mut id = self.id;
        if id == 0 {
            let mut rng = rand::thread_rng();
            id = rng.gen::<u16>();
        }

        DnsMessage {
            id,
            response: false,
            opcode: OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: true,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: self
                .queries
                .iter()
                .map(|(url, qt)| QuerySection {
                    qname: url.to_owned(),
                    qtype: Qtype::of(*qt),
                    qclass: QueryClass::IN,
                })
                .collect(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: self.dnssec.then(|| {
                let mut edns = Edns::with_payload_size(4096);
                edns.do_bit = true;
                edns
            }),
        }
    }
}

#[cfg(test)]
mod builder_dnssec_tests {
    use super::*;

    /// `--dnssec` has to produce an OPT record with DO set, and survive the
    /// wire — a client that cannot ask for DNSSEC cannot see any of the signing
    /// this library does (`TODO.md` #19h).
    ///
    /// Round-tripped rather than inspected, because the flag only matters if a
    /// *server* reads it: `edns_header` is the same call `rdnsd` makes to decide
    /// whether to attach signatures.
    #[test]
    fn the_dnssec_flag_sets_do_and_survives_the_wire() {
        let plain = DnsMessageBuilder::new()
            .with_url("example.com", "A")
            .build();
        assert!(plain.edns.is_none(), "no OPT unless asked for");

        let asked = DnsMessageBuilder::new()
            .with_url("example.com", "A")
            .with_dnssec(true)
            .build();
        let mut buf = vec![0u8; 512];
        let n = asked.to_bytes(&mut buf).expect("serializes");
        let back = DnsMessage::try_from_bytes(&buf[..n]).expect("and reads back");
        let edns = back
            .edns_header()
            .expect("a well-formed OPT")
            .expect("which is there");
        assert!(
            edns.do_bit,
            "DO is what asks for RRSIG/NSEC (RFC 4035 §3.2.1)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::record_types as rt;

    /// RFC 1982 §3.2, which is the whole reason [`Serial`] exists.
    ///
    /// This was `secondary::is_newer`'s test and moved here with the function it
    /// covered. It passed there and passes here — nothing in the tree compared
    /// serials wrongly, so there is no failing-first regression to show
    /// (`CLAUDE.md` §1). What the move buys is that the *second* copy of this
    /// arithmetic, in `notify::changed_zones`, is gone.
    #[test]
    fn a_wrapped_serial_is_still_an_increment() {
        let s = Serial::new;
        assert!(s(2).is_newer_than(s(1)));
        assert!(!s(1).is_newer_than(s(2)));
        assert!(!s(5).is_newer_than(s(5)), "the same serial is not newer");
        assert!(
            s(3).is_newer_than(s(u32::MAX - 1)),
            "RFC 1982 §3.2: the forward distance is 4, so this is an increment"
        );
        assert!(!s(u32::MAX - 1).is_newer_than(s(3)));
    }

    /// Half the space apart, RFC 1982 §3.2 leaves the result undefined — neither
    /// is later than the other. An `Ord` would have to invent an answer, which
    /// is one of the two reasons [`Serial`] does not have one.
    #[test]
    fn serials_half_the_space_apart_are_neither_newer() {
        let (a, b) = (Serial::new(0), Serial::new(0x8000_0000));
        assert!(!a.is_newer_than(b));
        assert!(!b.is_newer_than(a));
        assert_ne!(a, b, "and they are still different versions");
    }

    /// `Display` forwards the formatter, so width and alignment survive.
    ///
    /// Not a hypothetical: `zone_writer` lays an SOA out as `{serial:<12}` and
    /// `rdnsctl status` as `{:>6}`, and the obvious one-line impl —
    /// `write!(f, "{}", self.0)`, which is what [`Ttl`] next door has — silently
    /// ignores both. The zone file would still parse, so nothing would fail; the
    /// column would just stop lining up. Checked here rather than asserted in
    /// the doc comment (`CLAUDE.md` §4).
    #[test]
    fn a_serial_keeps_the_padding_it_is_formatted_with() {
        assert_eq!(format!("{:<12}|", Serial::new(2026080201)), "2026080201  |");
        assert_eq!(format!("{:>6}|", Serial::new(42)), "    42|");
    }

    /// The wire form is unchanged by the newtype, which is the claim `TODO.md`
    /// #14a's gate is about: an SOA read off the wire and written back out is
    /// byte-identical, including a serial past the signed ceiling.
    #[test]
    fn a_serial_round_trips_through_the_wire_form() {
        for value in [0, 1, 2_026_080_201, 0x8000_0000, u32::MAX] {
            let soa = ParsedRecord::SOA {
                mname: "ns1.example.com.".to_string(),
                rname: "admin.example.com.".to_string(),
                serial: Serial::new(value),
                refresh: 3600,
                retry: 1800,
                expire: 604_800,
                minimum: 86_400,
            };
            let encoded = RecordData::from_parsed(&soa).expect("an SOA serializes");
            assert_eq!(
                encoded.bytes()[encoded.bytes().len() - 20..encoded.bytes().len() - 16],
                value.to_be_bytes(),
                "the serial is the four bytes after the two names"
            );
            assert_eq!(encoded.parse().expect("and parses back"), soa);
        }
    }

    /// A record may not declare more RDATA than the message actually carries.
    ///
    /// This is an error, not a panic. `ResourceRecord::try_from_bytes` used to
    /// slice `&rest[..rdatalen]` on an attacker-chosen `u16`, which is reachable
    /// before authentication on both of `rdnsd`'s transports, in `rdnsr` with no
    /// validator in front of it, and from a primary mid-transfer.
    #[test]
    fn rdlength_past_end_of_message_is_an_error() {
        // Header: id, QR=1, qd=0, an=1, ns=0, ar=0.
        let mut packet: Vec<u8> = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        packet.push(0x00); // owner name = root
        packet.extend_from_slice(&1u16.to_be_bytes()); // type A
        packet.extend_from_slice(&1u16.to_be_bytes()); // class IN
        packet.extend_from_slice(&3600u32.to_be_bytes()); // ttl
        packet.extend_from_slice(&0xFFFFu16.to_be_bytes()); // RDLENGTH, with nothing following

        let parsed = DnsMessage::try_from_bytes(&packet);
        assert!(
            parsed.is_err(),
            "a record claiming 65535 bytes of RDATA in a message that carries none \
             must be rejected, not sliced"
        );
    }

    /// The same shape in the additional section, which is the one that gets past
    /// `AdmissionCheck::validate_packet` — OPT and TSIG legitimately live
    /// there, so it is only count-capped, and this arrives as a well-formed
    /// QUERY rather than as an obviously bogus response.
    #[test]
    fn rdlength_past_end_in_additional_section_is_an_error() {
        // Header: id, QR=0 opcode=QUERY, qd=0, an=0, ns=0, ar=1.
        let mut packet: Vec<u8> = vec![0x12, 0x34, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 1];
        packet.push(0x00); // OPT owner name is always root
        packet.extend_from_slice(&41u16.to_be_bytes()); // type OPT
        packet.extend_from_slice(&4096u16.to_be_bytes()); // class = UDP payload size
        packet.extend_from_slice(&0u32.to_be_bytes()); // extended rcode and flags
        packet.extend_from_slice(&0xFFFFu16.to_be_bytes()); // RDLENGTH, with nothing following

        let parsed = DnsMessage::try_from_bytes(&packet);
        assert!(
            parsed.is_err(),
            "an OPT record claiming 65535 bytes of options must be rejected, not sliced"
        );
    }

    /// A record whose RDLENGTH exactly consumes the rest of the message is
    /// legal, and the boundary is where an off-by-one in the new check would
    /// live — so pin it rather than only testing the failing side.
    #[test]
    fn rdlength_reaching_exactly_the_end_of_the_message_parses() {
        let mut packet: Vec<u8> = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        packet.push(0x00);
        packet.extend_from_slice(&1u16.to_be_bytes()); // type A
        packet.extend_from_slice(&1u16.to_be_bytes()); // class IN
        packet.extend_from_slice(&3600u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
        packet.extend_from_slice(&[192, 0, 2, 1]); // ...and exactly 4 bytes of A rdata

        let parsed = DnsMessage::try_from_bytes(&packet)
            .expect("a record whose RDATA ends exactly at the message end is well-formed");
        assert_eq!(parsed.answers.len(), 1);
    }

    #[test]
    fn test_query_parse() {
        let query_header: [u8; 31] = [
            0xf5, 0x6f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        let msg = DnsMessage::try_from_bytes(&query_header).unwrap();
        assert!(msg.recursion);

        let query = &msg.queries[0];
        assert_eq!(query.qname, "www.google.fi.");
        assert_eq!(query.qtype, Qtype::of(rt::A));
        assert_eq!(query.qclass, QueryClass::IN);
    }

    #[test]
    fn test_query_builder() {
        let req = DnsMessageBuilder::new()
            .with_id(u16::from_be_bytes([0xf5, 0x6f]))
            .with_url("www.google.fi", "A")
            .build();

        let mut buf = [0u8; 512];
        let n = req.to_bytes(&mut buf).expect("to_bytes");

        let expected: [u8; 31] = [
            0xf5, 0x6f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        assert_eq!(&buf[0..n], &expected);
    }

    /// Every opcode has to survive the wire, and until this test none but QUERY
    /// did: the decoder masked the field in place instead of shifting it down, so
    /// IQUERY arrived as QUERY and NOTIFY, UPDATE and STATUS all arrived as
    /// `Unknown`. The writer shifted correctly, which is why no round trip
    /// noticed — every test used QUERY, and 0 survives any mask.
    #[test]
    fn test_every_opcode_survives_the_wire() {
        for opcode in [
            OpCode::Query,
            OpCode::IQuery,
            OpCode::Status,
            OpCode::Notify,
            OpCode::Update,
        ] {
            let msg = DnsMessage {
                id: 0x1234,
                response: false,
                opcode,
                authoritive: true,
                truncation: false,
                recursion: false,
                recursion_ok: false,
                ad: false,
                cd: false,
                rcode: ResponseCode::Ok,
                queries: vec![QuerySection {
                    qname: "example.com.".to_string(),
                    qtype: Qtype::of(rt::SOA),
                    qclass: QueryClass::IN,
                }],
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
                edns: None,
            };
            let mut buf = vec![0u8; 512];
            let n = msg.to_bytes(&mut buf).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");
            assert_eq!(
                parsed.opcode, opcode,
                "opcode {opcode:?} did not round-trip"
            );
            // And the flags either side of it are unharmed.
            assert!(parsed.authoritive, "AA survived alongside {opcode:?}");
            assert!(!parsed.response);
        }
    }

    /// The *other* direction, and a different bug from the one above.
    ///
    /// `test_every_opcode_survives_the_wire` is the regression test for the
    /// decoder masking the opcode in place instead of shifting it, and it can
    /// only cover opcodes this enum has names for — which is exactly why it did
    /// not catch this. An opcode with no name arrived as an `Unknown = 15`
    /// sentinel that could not carry the value it stood for, so **eleven of the
    /// sixteen** went back onto the wire as 15: 3 and 7-15 are Unassigned, and
    /// **6 is DSO (RFC 8490)**, which is assigned and which this library already
    /// knows exists — it carries `ResponseCode::DsoTypeNotImplemented` for
    /// RFC 8490's rcode 11.
    ///
    /// It reaches a client. `rdnsd` answers an opcode it does not implement with
    /// NOTIMP and echoes `msg.opcode` into the reply, and RFC 1035 §4.1.1 says
    /// that field "is set by the originator of a query and copied into the
    /// response" — so a DSO client got a NOTIMP whose OPCODE said 15, which is
    /// not the question it asked. Same shape as `QueryClass::None` and
    /// `ResponseCode::Unknown` before it (`CLAUDE.md` §2, §17): a sentinel that
    /// cannot hold what it replaces.
    ///
    /// Written from raw bytes rather than from the enum on purpose. A test that
    /// starts by naming a variant can only reach the values that have names,
    /// which is the whole of how this survived (`CLAUDE.md` §1).
    #[test]
    fn an_opcode_this_library_has_no_name_for_is_echoed_unchanged() {
        for raw in 0u8..16 {
            let mut query = vec![0u8; 12];
            query[0] = 0x12;
            query[1] = 0x34;
            query[2] = (raw & 0x0f) << 3;

            let parsed = DnsMessage::try_from_bytes(&query).expect("a bare header parses");
            let mut buf = vec![0u8; 512];
            parsed.to_bytes(&mut buf).expect("serialize");
            let echoed = (buf[2] >> 3) & 0x0f;

            assert_eq!(
                echoed, raw,
                "opcode {raw} came back as {echoed} (parsed as {:?})",
                parsed.opcode
            );
        }
    }

    // -----------------------------------------------------------------
    // TXT <character-string>s (RFC 1035 §3.3.14)
    // -----------------------------------------------------------------

    /// The framing itself: each string is preceded by its length. Stored as one
    /// unframed blob — which is what this was — the first byte of the text is
    /// read as a length by every correct client, and the record arrives short.
    #[test]
    fn test_txt_is_framed_as_character_strings() {
        let one = RecordData::from_parsed(&ParsedRecord::TXT(vec![b"hello".to_vec()])).unwrap();
        assert_eq!(one.bytes(), b"\x05hello");

        let two = RecordData::from_parsed(&ParsedRecord::TXT(vec![
            b"v=spf1".to_vec(),
            b"-all".to_vec(),
        ]))
        .unwrap();
        assert_eq!(two.bytes(), b"\x06v=spf1\x04-all");
    }

    #[test]
    fn test_txt_survives_a_wire_roundtrip() {
        let strings = vec![
            b"first string".to_vec(),
            Vec::new(),
            // Arbitrary octets: a character-string is not text. As a `String`
            // this failed to decode at all — and decoding happens while reading
            // the message, so one such record took the whole response with it.
            vec![0xff, 0x00, 0x80],
        ];
        let encoded = RecordData::from_parsed(&ParsedRecord::TXT(strings.clone())).unwrap();
        assert_eq!(
            encoded.parse().unwrap(),
            ParsedRecord::TXT(strings),
            "an empty character-string is legal too, and must survive"
        );
    }

    /// A character-string's length is one byte, so 255 is the ceiling. Splitting
    /// a longer string in two would change what the record says, so this is the
    /// zone's error to fix rather than ours to paper over.
    #[test]
    fn test_txt_string_longer_than_255_is_refused() {
        let err = RecordData::from_parsed(&ParsedRecord::TXT(vec![vec![b'x'; 256]])).unwrap_err();
        assert!(err.to_string().contains("255"), "got: {err}");

        // 255 exactly is fine.
        assert!(RecordData::from_parsed(&ParsedRecord::TXT(vec![vec![b'y'; 255]])).is_ok());
    }

    #[test]
    fn test_txt_with_no_strings_is_refused() {
        let err = RecordData::from_parsed(&ParsedRecord::TXT(Vec::new())).unwrap_err();
        assert!(err.to_string().contains("at least one"), "got: {err}");
    }

    /// A length byte that runs past the end of the RDATA is malformed, and is
    /// refused as the record is read rather than indexed off the end of.
    #[test]
    fn test_txt_with_a_length_past_the_end_is_an_error() {
        let unpacker = crate::dname::DNameUnpacker::new(&[]);
        let err = RecordData::from_wire(rt::TXT, b"\x09short", &unpacker).unwrap_err();
        assert!(err.to_string().contains("character-string"), "got: {err}");
    }

    #[test]
    fn test_response_roundtrip_with_answer() {
        use std::net::Ipv4Addr;

        let answer = ResourceRecord {
            name: "www.example.com.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        };
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: true,
            recursion_ok: true,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: "www.example.com.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            }],
            answers: vec![answer],
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        };

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        assert_eq!(
            parsed.answers.len(),
            1,
            "answer record must survive round-trip"
        );
        let a = &parsed.answers[0];
        assert_eq!(a.name, "www.example.com.");
        assert_eq!(a.class, Class::new(1));
        assert_eq!(a.ttl, Ttl::from_secs(3600));
        assert_eq!(a.rdata.rtype(), rt::A);
        assert_eq!(a.rdata.bytes(), [192, 0, 2, 1]); // A record: 4 address octets
    }

    /// A response whose records all share the question's owner name should
    /// carry that name once, with 2-byte pointers thereafter.
    #[test]
    fn test_output_compresses_repeated_owner_names() {
        use std::net::Ipv4Addr;

        let answers: Vec<ResourceRecord> = (1..=10)
            .map(|i| ResourceRecord {
                name: "www.example.com.".to_string(),
                class: Class::new(1),
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, i)))
                    .unwrap(),
            })
            .collect();

        let mut msg = query_msg(0x4242);
        msg.response = true;
        msg.queries[0].qname = "www.example.com.".to_string();
        msg.answers = answers;

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");

        // 12 header + 21 question (17-byte name + type + class) + 10 * (2
        // pointer + 2 type + 2 class + 4 TTL + 2 RDLEN + 4 address) = 193.
        // Without compression each answer would carry the 17-byte name instead
        // of a 2-byte pointer: 33 + 10 * 31 = 343.
        assert_eq!(n, 193);

        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");
        assert_eq!(parsed.answers.len(), 10);
        for (i, a) in parsed.answers.iter().enumerate() {
            assert_eq!(a.name, "www.example.com.");
            assert_eq!(a.rdata.bytes(), [192, 0, 2, (i + 1) as u8]);
        }
    }

    /// Names inside NS/CNAME/SOA/MX RDATA are compressed too, and survive the
    /// round-trip — the parser resolves the pointers against the full message.
    #[test]
    fn test_output_compresses_names_inside_rdata() {
        let ns = ResourceRecord {
            name: "example.com.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NS("ns1.example.com.".to_string()))
                .unwrap(),
        };
        let mx = ResourceRecord {
            name: "example.com.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::MX {
                preference: 10,
                exchange: "mail.example.com.".to_string(),
            })
            .unwrap(),
        };
        let cname = ResourceRecord {
            name: "alias.example.com.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::CNAME("www.example.com.".to_string()))
                .unwrap(),
        };

        let mut msg = query_msg(0x5150);
        msg.response = true;
        msg.answers = vec![ns.clone(), mx.clone(), cname.clone()];

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        // RDATA is stored uncompressed, so the parsed records must equal the
        // originals byte for byte even though the wire form used pointers.
        assert_eq!(parsed.answers.len(), 3);
        for (got, want) in parsed.answers.iter().zip([&ns, &mx, &cname]) {
            assert_eq!(got.name, want.name);
            assert_eq!(got.ttl, want.ttl);
            assert_eq!(got.rdata, want.rdata);
        }

        // Every one of those names ends in a pointer rather than spelling the
        // zone out again. (Labels are length-prefixed on the wire, so the
        // literal to look for is the label "example", not "example.com".)
        assert_eq!(
            buf[..n].windows(7).filter(|w| *w == b"example").count(),
            1,
            "the zone name should appear exactly once in the message"
        );
    }

    /// RFC 3597 §4 / RFC 4034: names in types the receiver may not know must
    /// not be compressed. SRV is the canonical example.
    #[test]
    fn test_unknown_and_dnssec_rdata_is_not_compressed() {
        // SRV: priority, weight, port, then a target name we must leave alone.
        let mut srv_rdata = vec![0, 10, 0, 20, 0, 80];
        srv_rdata.extend_from_slice(&dname_to_bytes("www.example.com.").unwrap());
        let srv = ResourceRecord {
            name: "_sip._tcp.example.com.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::new(Rtype::new(33), srv_rdata.clone())
                .expect("SRV has no decoder here, so its bytes are opaque"),
        };

        let mut msg = query_msg(0x1111);
        msg.response = true;
        msg.queries[0].qname = "_sip._tcp.example.com.".to_string();
        msg.answers = vec![srv];

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");

        // The RDATA appears verbatim, pointers and all.
        assert!(
            buf[..n]
                .windows(srv_rdata.len())
                .any(|w| w == srv_rdata.as_slice()),
            "SRV RDATA must go out byte-for-byte"
        );

        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");
        assert_eq!(parsed.answers[0].rdata.bytes(), srv_rdata.as_slice());
    }

    /// A packet that claims more questions than it carries must be an error,
    /// not a panic: the name parser runs off the end of the buffer otherwise.
    #[test]
    fn test_truncated_message_is_an_error_not_a_panic() {
        // Header says qdcount=2, but only one (short) question follows.
        let packet: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, // id, flags
            0x00, 0x02, // qdcount = 2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar = 0
            0x03, b'w', b'w', b'w', 0x00, // "www."
            0x00, 0x01, 0x00, 0x01, // qtype, qclass
        ];
        assert!(DnsMessage::try_from_bytes(&packet).is_err());

        // A name whose length byte overruns the buffer.
        let overrun: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, b'a',
        ];
        assert!(DnsMessage::try_from_bytes(&overrun).is_err());

        // A compression pointer cut in half by the end of the buffer.
        let half_pointer: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        ];
        assert!(DnsMessage::try_from_bytes(&half_pointer).is_err());
    }

    /// Serializing into a buffer that cannot hold the message is an error, not
    /// a silently short write.
    #[test]
    fn test_to_bytes_rejects_undersized_buffer() {
        let mut msg = query_msg(7);
        msg.queries[0].qname = "a-rather-long-name.example.com.".to_string();

        let mut buf = [0u8; 20];
        assert!(msg.to_bytes(&mut buf).is_err());
    }

    fn query_msg(id: u16) -> DnsMessage {
        DnsMessage {
            id,
            response: false,
            opcode: OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: true,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: "example.com.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        }
    }

    /// An unknown QCLASS used to be aliased onto `QueryClass::None`, which is
    /// **254** — RFC 2136's real NONE class, not a sentinel — and re-serialized
    /// as 254. The question echoed in the response was therefore not the
    /// question asked, and a client matching them as RFC 5452 §9.1 requires
    /// discards a reply it was waiting for.
    #[test]
    fn an_unknown_qclass_is_echoed_back_as_the_class_that_was_asked() {
        for qclass in [99u16, 2, 0, 253, 256, 0xffff] {
            let mut msg = query_msg(1);
            msg.queries[0].qclass = QueryClass::from_u16(qclass);

            let bytes = msg.to_bytes_within(512).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
            assert_eq!(
                parsed.queries[0].qclass.to_u16(),
                qclass,
                "QCLASS {qclass} came back as {}",
                parsed.queries[0].qclass.to_u16()
            );
        }
    }

    /// And the classes we do name still travel as themselves, so widening the
    /// type did not turn IN into `Other(1)` on the way through.
    #[test]
    fn the_named_qclasses_round_trip_as_themselves() {
        for (class, value) in [
            (QueryClass::IN, 1u16),
            (QueryClass::CH, 3),
            (QueryClass::HS, 4),
            (QueryClass::None, 254),
            (QueryClass::Any, 255),
        ] {
            assert_eq!(class.to_u16(), value);
            assert_eq!(QueryClass::from_u16(value), class);
        }
    }

    /// An rcode with no name here used to serialize as **0**. `rdnsr` relays
    /// upstream messages, so an unrecognized *failure* reached the client as a
    /// successful empty answer — the one direction a response code must never
    /// fail in. RFC 6895 §2.3 keeps the space open on purpose; a relay that does
    /// not know a code still has to pass it on.
    #[test]
    fn an_unknown_rcode_is_relayed_rather_than_rewritten_to_noerror() {
        // 12 is unassigned; 4095 is the top of the extended range. Both need an
        // OPT record to carry the high bits (RFC 6891 §6.1.3).
        for value in [12u16, 24, 100, 0xfff] {
            let mut msg = query_msg(1);
            msg.response = true;
            msg.rcode = ResponseCode::from_u16(value);
            msg.set_edns(Edns::with_payload_size(4096));

            let bytes = msg.to_bytes_within(512).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
            assert_eq!(
                parsed.rcode.to_u16(),
                value,
                "rcode {value} came back as {}",
                parsed.rcode.to_u16()
            );
            assert_ne!(parsed.rcode, ResponseCode::Ok);
        }
    }

    /// The low four bits still work without EDNS, which is the case every
    /// non-EDNS client sees.
    #[test]
    fn the_named_rcodes_round_trip_as_themselves() {
        for code in [
            ResponseCode::Ok,
            ResponseCode::FormatError,
            ResponseCode::ServerFailure,
            ResponseCode::NoSuchDomain,
            ResponseCode::NotImplemented,
            ResponseCode::Refused,
        ] {
            let mut msg = query_msg(1);
            msg.response = true;
            msg.rcode = code;
            let bytes = msg.to_bytes_within(512).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
            assert_eq!(parsed.rcode, code);
        }
        assert_eq!(ResponseCode::from_u16(23), ResponseCode::BadCookie);
        assert_eq!(ResponseCode::BadCookie.to_u16(), 23);
    }

    /// An OPT record whose option list is whatever bytes the test wants,
    /// including bytes that are not a valid list.
    ///
    /// `Edns::rdata` is private on purpose — the public constructors encode a
    /// well-formed list — so this is how a test reaches the malformed case. It
    /// can, because `mod tests` is a child of the module `Edns` is declared in.
    fn edns_with_rdata(rdata: &[u8]) -> Edns {
        Edns {
            udp_payload_size: 1232,
            version: EDNS_VERSION,
            do_bit: false,
            rdata: rdata.to_vec().into_boxed_slice(),
        }
    }

    /// RFC 6891 §6.1.1: "If a query message with more than one OPT RR is
    /// received, a FORMERR (RCODE=1) MUST be returned."
    ///
    /// **Nothing checked this before OPT became a field.** The first OPT was
    /// read and every one of them was written back out, so a message with two
    /// went through as if it had one and came back malformed. `Option<Edns>`
    /// makes the state unrepresentable in the struct; this is the other half —
    /// refusing it at the door, since the wire can still carry it.
    #[test]
    fn more_than_one_opt_record_is_formerr() {
        // A bare header claiming two additionals, then two OPT records:
        // root NAME, TYPE 41, CLASS 1232, TTL 0, RDLENGTH 0.
        let opt = [
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut two = vec![0x12, 0x34, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0x00, 0x02];
        two.extend_from_slice(&opt);
        two.extend_from_slice(&opt);
        let err = DnsMessage::try_from_bytes(&two).expect_err("two OPT records are FORMERR");
        assert!(
            matches!(
                err,
                WireError::Malformed {
                    what: "the additional section",
                    ..
                }
            ),
            "got {err:?}"
        );

        // And exactly one is still fine, so the check is not simply refusing
        // every OPT record it sees.
        let mut one = vec![0x12, 0x34, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0x00, 0x01];
        one.extend_from_slice(&opt);
        let msg = DnsMessage::try_from_bytes(&one).expect("one OPT record parses");
        assert!(msg.edns().is_some());
        assert!(
            msg.additionals.is_empty(),
            "and it is not left in the section"
        );
    }

    /// ARCOUNT counts the OPT record even though it is no longer in
    /// `additionals` — the arithmetic most likely to break when OPT moved out.
    #[test]
    fn arcount_counts_the_opt_record_that_is_not_in_the_section() {
        let mut msg = query_msg(7);
        msg.additionals.push(ResourceRecord {
            name: "ns1.example.com.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1)))
                .expect("encode"),
        });
        msg.set_edns(Edns::with_payload_size(1232));

        let bytes = msg.to_bytes_within(512).expect("serialize");
        assert_eq!(
            u16::from_be_bytes([bytes[10], bytes[11]]),
            2,
            "one real additional plus the OPT record"
        );

        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.additionals.len(), 1, "the A record, and only it");
        assert!(parsed.edns().is_some(), "the OPT record, in its own field");
    }

    /// RFC 2181 §8, at the boundary that now owns it: "implementations should
    /// treat TTL values received with the most significant bit set as if the
    /// entire value received was zero".
    ///
    /// Driven from the wire rather than from `Ttl::from_wire`, because the
    /// claim being tested is that *parsing a record* applies the rule — that is
    /// what lets fourteen call sites stop applying it themselves.
    #[test]
    fn a_ttl_with_the_high_bit_set_parses_as_zero() {
        for raw in [-1i32, i32::MIN, -3600] {
            let mut wire = vec![0x12, 0x34, 0x00, 0x00, 0, 0, 0x00, 0x01, 0, 0, 0, 0];
            wire.push(0x00); // root owner name
            wire.extend_from_slice(&utils::record_types::A.to_u16().to_be_bytes());
            wire.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            wire.extend_from_slice(&raw.to_be_bytes());
            wire.extend_from_slice(&4u16.to_be_bytes());
            wire.extend_from_slice(&[192, 0, 2, 1]);

            let msg = DnsMessage::try_from_bytes(&wire).expect("parses");
            assert_eq!(
                msg.answers[0].ttl,
                Ttl::ZERO,
                "a wire TTL of {raw} is zero seconds, not {} or a huge unsigned value",
                raw
            );
        }

        // And a TTL without the high bit is untouched.
        let mut wire = vec![0x12, 0x34, 0x00, 0x00, 0, 0, 0x00, 0x01, 0, 0, 0, 0];
        wire.push(0x00);
        wire.extend_from_slice(&utils::record_types::A.to_u16().to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&3600i32.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&[192, 0, 2, 1]);
        let msg = DnsMessage::try_from_bytes(&wire).expect("parses");
        assert_eq!(msg.answers[0].ttl, Ttl::from_secs(3600));
    }

    #[test]
    fn test_edns_absent_defaults_to_512() {
        let msg = query_msg(1);
        assert!(msg.edns().is_none());
        assert!(!msg.has_edns());
        assert_eq!(msg.udp_payload_size(), 512);
    }

    #[test]
    fn test_edns_set_and_read() {
        let mut msg = query_msg(1);
        let mut edns = Edns::with_payload_size(4096);
        edns.do_bit = true;
        msg.set_edns(edns);

        let got = msg.edns().expect("edns present");
        assert_eq!(got.udp_payload_size, 4096);
        assert!(got.do_bit);
        assert_eq!(got.version, 0);
        assert_eq!(msg.udp_payload_size(), 4096);

        // `set_edns` replaces rather than accumulates. This used to be checked
        // by counting the OPT records in the additional section and asserting
        // there was exactly one — a real hazard when `set_edns` pushed onto a
        // `Vec` and had to `retain` the old one away first. With OPT as an
        // `Option` field there is no count to get wrong: a second OPT record in
        // one message is unspellable, which is also what RFC 6891 §6.1.1 says
        // about receiving one (`TODO.md` #13d).
        msg.set_edns(Edns::with_payload_size(1232));
        assert!(msg.additionals.is_empty(), "OPT is not a resource record");
        assert_eq!(msg.edns().expect("still present").udp_payload_size, 1232);
        assert_eq!(msg.udp_payload_size(), 1232);
    }

    #[test]
    fn test_edns_survives_wire_roundtrip() {
        let mut msg = query_msg(0xABCD);
        let mut edns = Edns::with_payload_size(4096);
        edns.do_bit = true;
        msg.set_edns(edns.clone());

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        let got = parsed.edns().expect("edns survives round-trip");
        assert_eq!(*got, edns);
    }

    #[test]
    fn test_edns_payload_size_floored_at_512() {
        // RFC 6891 §6.2.3: values below 512 are treated as 512.
        let mut msg = query_msg(1);
        msg.set_edns(Edns::with_payload_size(300));
        assert_eq!(msg.udp_payload_size(), 512);
    }

    /// RFC 4034 §3.1 fixes the RRSIG field order, and expiration comes *before*
    /// inception. Decoding them the other way round is invisible to a
    /// round-trip test — both halves agree — so this checks the decode against
    /// bytes laid out by hand, which is the only thing a real signer's output
    /// can be compared to.
    #[test]
    fn test_rrsig_reads_expiration_before_inception() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // type covered = A
        rdata.push(13); // algorithm = ECDSAP256SHA256
        rdata.push(3); // labels
        rdata.extend_from_slice(&3600u32.to_be_bytes()); // original TTL
        rdata.extend_from_slice(&0x5000_0000u32.to_be_bytes()); // expiration
        rdata.extend_from_slice(&0x4000_0000u32.to_be_bytes()); // inception
        rdata.extend_from_slice(&12345u16.to_be_bytes()); // key tag
        rdata.extend_from_slice(&dname_to_bytes("example.com.").unwrap());
        rdata.extend_from_slice(&[0xAB; 64]); // signature

        let record = RecordData::from_wire(rt::RRSIG, &rdata, &DNameUnpacker::new(&rdata))
            .expect("RRSIG should decode");
        let ParsedRecord::RRSIG {
            expiration,
            inception,
            key_tag,
            signer_name,
            ref signature,
            ..
        } = record.parse().expect("parse")
        else {
            panic!("not an RRSIG");
        };
        assert_eq!(expiration, 0x5000_0000, "the earlier field is expiration");
        assert_eq!(inception, 0x4000_0000, "the later field is inception");
        assert!(inception < expiration, "a signature is valid over a range");
        assert_eq!(key_tag, 12345);
        assert_eq!(signer_name, "example.com.");
        assert_eq!(signature.len(), 64);

        // And the encoder puts them back in the same order it found them.
        assert_eq!(record.bytes(), rdata.as_slice());
    }

    #[test]
    fn test_edns_options_survive_wire_roundtrip() {
        let mut msg = query_msg(0x0F0F);
        let edns = Edns::with_options(
            1232,
            EDNS_VERSION,
            false,
            &[
                EdnsOption {
                    code: EDNS_OPTION_COOKIE,
                    data: vec![1, 2, 3, 4, 5, 6, 7, 8],
                },
                // A zero-length option is legal and must not be dropped.
                EdnsOption {
                    code: EDNS_OPTION_NSID,
                    data: Vec::new(),
                },
            ],
        )
        .expect("encode the options");
        msg.set_edns(edns.clone());

        // 2 (code) + 2 (len) + 8 (data), then 2 + 2 + 0.
        assert_eq!(msg.edns().expect("OPT present").rdata().len(), 16);

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        let got = parsed.edns().expect("edns present");
        assert_eq!(*got, edns);
        assert_eq!(
            got.option(EDNS_OPTION_COOKIE).unwrap(),
            Some(vec![1u8, 2, 3, 4, 5, 6, 7, 8])
        );
        assert_eq!(got.option(EDNS_OPTION_NSID).unwrap(), Some(Vec::new()));
        assert_eq!(got.option(EDNS_OPTION_PADDING).unwrap(), None);
    }

    /// A malformed option list is an error — but **not** an error that reaching
    /// the OPT record produces.
    ///
    /// This test used to call `msg.edns()` and expect `Err`. Once OPT became a
    /// field carrying its RDATA unparsed (`TODO.md` #13d), "does this message
    /// have EDNS" is infallible and "is its option list well formed" is the
    /// separate, fallible question. The split is deliberate and is what keeps a
    /// bad list answerable: if reading it were part of parsing the message,
    /// `try_from_bytes` would fail, `rdnsd` would return no bytes at all
    /// (`main.rs:1465`), and the FORMERR this deserves could not be built.
    #[test]
    fn test_malformed_edns_options_surface_error() {
        let mut msg = query_msg(1);
        // Option claims 8 bytes of data but supplies 2.
        msg.set_edns(edns_with_rdata(&[0x00, 0x0a, 0x00, 0x08, 0xde, 0xad]));

        let err = msg
            .edns()
            .expect("the OPT record itself is readable")
            .check_options()
            .expect_err("truncated option must be rejected");
        assert_eq!(
            err,
            WireError::Truncated {
                what: "EDNS option data",
                need: 8,
                have: 2,
            },
            "the option declared 8 bytes and supplied 2"
        );
        // The payload size is still readable — it lives in the OPT CLASS field.
        assert_eq!(msg.udp_payload_size(), 1232);
        assert!(msg.has_edns());
    }

    /// `edns_header` sees exactly what `edns` sees, minus the options.
    ///
    /// This is the property the answer path now depends on. Both daemons decide
    /// FORMERR from the cheap one, so if it accepted a list the full parse
    /// rejects — or the reverse — a packet would be answered differently
    /// depending on which of the two a call site happened to use, which is
    /// precisely the drift that comes of writing the walk twice
    /// (`CLAUDE.md` §7). They share it; this holds them to it.
    #[test]
    fn the_edns_header_agrees_with_the_full_parse() {
        // No OPT at all.
        let plain = query_msg(1);
        assert_eq!(plain.edns_header().unwrap(), None);

        // An OPT with options, an OPT without, and a non-zero version — the
        // three shapes the answer path branches on.
        for (payload, version, do_bit, options) in [
            (4096u16, 0u8, true, vec![]),
            (
                1232,
                0,
                false,
                vec![EdnsOption {
                    code: EDNS_OPTION_COOKIE,
                    data: vec![1, 2, 3, 4, 5, 6, 7, 8],
                }],
            ),
            (512, 1, true, vec![]),
        ] {
            let mut msg = query_msg(1);
            msg.set_edns(
                Edns::with_options(payload, version, do_bit, &options).expect("encode the options"),
            );
            // Through the wire, because that is where a request comes from and
            // the version lives in a field `set_edns` writes and the parser
            // re-reads.
            let bytes = msg.to_bytes_within(512).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");

            let full = parsed.edns().expect("OPT present");
            let header = parsed.edns_header().unwrap().expect("OPT present");
            assert_eq!(header, full.header(), "payload {payload} version {version}");
            assert_eq!(header.do_bit, do_bit);
            assert_eq!(header.version, version);
        }
    }

    /// And a malformed option list is malformed to both of them.
    #[test]
    fn the_edns_header_rejects_what_the_full_parse_rejects() {
        for rdata in [
            // An option header cut short: three bytes where four are needed.
            vec![0x00u8, 0x0a, 0x00],
            // Data shorter than the length field claims.
            vec![0x00, 0x0a, 0x00, 0x08, 0xde, 0xad],
            // A well-formed option followed by a truncated one, which only a
            // walk that gets that far can see.
            vec![0x00, 0x0a, 0x00, 0x01, 0xff, 0x00, 0x03, 0x00, 0x04],
        ] {
            let mut msg = query_msg(1);
            msg.set_edns(edns_with_rdata(&rdata));

            assert_eq!(
                msg.edns_header().unwrap_err(),
                msg.edns().expect("OPT present").options().unwrap_err(),
                "{rdata:02x?}: the same walk, so the same error"
            );
        }
    }

    #[test]
    fn test_extended_rcode_splits_across_header_and_opt() {
        // BADVERS is 16: 0 in the header's low 4 bits, 1 in the OPT TTL's top byte.
        let mut msg = query_msg(0x2222);
        msg.response = true;
        msg.rcode = ResponseCode::BadOptVersion;
        msg.set_edns(Edns::with_payload_size(1232));

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        assert_eq!(buf[3] & 0x0f, 0, "low 4 bits of RCODE 16 are 0");

        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");
        assert_eq!(parsed.rcode, ResponseCode::BadOptVersion);
    }

    #[test]
    fn test_extended_rcode_without_opt_is_an_error() {
        let mut msg = query_msg(1);
        msg.response = true;
        msg.rcode = ResponseCode::BadOptVersion;

        let mut buf = [0u8; 512];
        let err = msg
            .to_bytes(&mut buf)
            .expect_err("extended RCODE needs an OPT record");
        assert!(err.to_string().contains("OPT record"), "got: {err}");
    }

    #[test]
    fn test_basic_rcode_unaffected_by_opt() {
        // A plain 4-bit RCODE must not have its bits disturbed by OPT presence.
        let mut msg = query_msg(1);
        msg.response = true;
        msg.rcode = ResponseCode::NoSuchDomain;
        msg.set_edns(Edns::with_payload_size(4096));

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");
        assert_eq!(parsed.rcode, ResponseCode::NoSuchDomain);
        assert_eq!(parsed.udp_payload_size(), 4096);
    }

    #[test]
    fn test_to_bytes_within_truncates_and_sets_tc() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        // Pack in enough answers to blow past 512 bytes.
        for i in 0..60u8 {
            msg.answers.push(ResourceRecord {
                name: format!("host{i}.example.com."),
                class: Class::new(1),
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(10, 0, 0, i)))
                    .unwrap(),
            });
        }
        msg.set_edns(Edns::with_payload_size(4096));

        let bytes = msg.to_bytes_within(512).expect("to_bytes_within");
        assert!(
            bytes.len() <= 512,
            "must fit within 512, got {}",
            bytes.len()
        );

        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse truncated");
        assert!(parsed.truncation, "TC bit must be set on truncation");
        assert!(parsed.answers.is_empty(), "answers dropped on truncation");
        assert!(parsed.has_edns(), "OPT record must survive truncation");
    }

    /// A response used to be built in a zeroed 64 KB scratch that `truncate`
    /// then shrank the *length* of and not the capacity, so the `Vec` handed to
    /// `send_to` and held for the duration of the send was 64 KB whatever the
    /// answer was — a 1000x overshoot at a thousand in flight.
    ///
    /// Asserted on capacity rather than on a timing, deliberately: capacity is
    /// exact and does not care what else is running on the machine
    /// (`CLAUDE.md` §10). Against the old code this reads 65535.
    #[test]
    fn a_small_response_does_not_carry_a_64k_buffer_into_the_send() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        msg.answers.push(ResourceRecord {
            name: "example.com.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(1, 2, 3, 4))).unwrap(),
        });

        let bytes = msg.to_bytes_within(4096).expect("to_bytes_within");
        assert!(bytes.len() < 100, "a one-record answer is small");
        assert!(
            bytes.capacity() <= 4096,
            "a UDP response asked to fit in 4096 bytes must not hold {} of \
             capacity — that is the buffer travelling into send_to",
            bytes.capacity()
        );
    }

    /// The reason [`DnsMessage::to_bytes_within_buf`] exists: a send path that
    /// keeps one buffer allocates nothing per response. Checked by pointer
    /// identity, which is the only way to say "did not reallocate" without
    /// measuring time.
    #[test]
    fn serializing_into_a_reused_buffer_does_not_reallocate() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        msg.answers.push(ResourceRecord {
            name: "example.com.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(1, 2, 3, 4))).unwrap(),
        });

        let mut buf = Vec::new();
        msg.to_bytes_within_buf(4096, &mut buf).expect("first");
        let first_len = buf.len();
        let (ptr, cap) = (buf.as_ptr(), buf.capacity());

        for _ in 0..16 {
            msg.to_bytes_within_buf(4096, &mut buf).expect("again");
            assert_eq!(buf.len(), first_len, "same message, same bytes");
        }
        assert_eq!(buf.as_ptr(), ptr, "the buffer moved, so it reallocated");
        assert_eq!(buf.capacity(), cap);
    }

    /// The boundary the new sizing introduces: with the scratch sized to
    /// `max_len`, "the message is too long" arrives as a `WireError` from the
    /// writer rather than as a comparison, so an off-by-one puts a message that
    /// fits exactly onto the truncation path. The RFC 1035 §4.2.1 answer for a
    /// message of exactly `max_len` bytes is to send it, TC clear.
    #[test]
    fn a_response_of_exactly_the_limit_is_sent_whole() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        msg.answers.push(ResourceRecord {
            name: "example.com.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(1, 2, 3, 4))).unwrap(),
        });
        let exact = msg.to_bytes_within(4096).expect("measure").len();

        let bytes = msg.to_bytes_within(exact).expect("at the limit");
        assert_eq!(bytes.len(), exact);
        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
        assert!(!parsed.truncation, "it fit, so TC must be clear");
        assert_eq!(parsed.answers.len(), 1);

        // One byte less and it must truncate rather than error.
        let bytes = msg.to_bytes_within(exact - 1).expect("under the limit");
        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
        assert!(parsed.truncation, "TC set when it does not fit");
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn test_to_bytes_within_keeps_full_when_it_fits() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        msg.answers.push(ResourceRecord {
            name: "example.com.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(1, 2, 3, 4))).unwrap(),
        });

        let bytes = msg.to_bytes_within(4096).expect("to_bytes_within");
        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
        assert!(!parsed.truncation);
        assert_eq!(parsed.answers.len(), 1);
    }

    #[test]
    fn test_response_parse() {
        let resp: [u8; 295] = [
            0xf5, 0x6f, 0x81, 0x80, 0x00, 0x01, 0x00, 0x07, 0x00, 0x04, 0x00, 0x04, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69, 0x00, 0x00,
            0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0xc4, 0x74, 0x00,
            0x10, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00, 0xc0, 0x2b, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0xc4, 0x6a, 0x00,
            0x08, 0x03, 0x77, 0x77, 0x77, 0x01, 0x6c, 0xc0, 0x2f, 0xc0, 0x47, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x04, 0xad, 0xc2, 0x20, 0x13, 0xc0, 0x47, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x04, 0xad, 0xc2, 0x20, 0x14, 0xc0,
            0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x04, 0xad, 0xc2, 0x20,
            0x10, 0xc0, 0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x04, 0xad,
            0xc2, 0x20, 0x11, 0xc0, 0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8a, 0x00,
            0x04, 0xad, 0xc2, 0x20, 0x12, 0xc0, 0x2f, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x46,
            0xe7, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x32, 0xc0, 0x2f, 0xc0, 0x2f, 0x00, 0x02, 0x00,
            0x01, 0x00, 0x01, 0x46, 0xe7, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x33, 0xc0, 0x2f, 0xc0,
            0x2f, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x46, 0xe7, 0x00, 0x06, 0x03, 0x6e, 0x73,
            0x34, 0xc0, 0x2f, 0xc0, 0x2f, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x46, 0xe7, 0x00,
            0x06, 0x03, 0x6e, 0x73, 0x31, 0xc0, 0x2f, 0xc0, 0xe1, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x00, 0xc5, 0x00, 0x00, 0x04, 0xd8, 0xef, 0x20, 0x0a, 0xc0, 0xab, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x04, 0xd8, 0xef, 0x22, 0x0a, 0xc0, 0xbd, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x04, 0xd8, 0xef, 0x24, 0x0a, 0xc0,
            0xcf, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x04, 0xd8, 0xef, 0x26,
            0x0a,
        ];

        let msg = DnsMessage::try_from_bytes(&resp).expect("deserialize");
        assert!(msg.recursion_ok);
    }

    #[test]
    fn test_ad_bit_serialization() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: true, // Set AD bit
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(parsed.ad, "AD bit should be set");
    }

    #[test]
    fn test_cd_bit_serialization() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: true, // Set CD bit
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(parsed.cd, "CD bit should be set");
    }

    #[test]
    fn test_ad_and_cd_bits_serialization() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: true, // Set AD bit
            cd: true, // Set CD bit
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(parsed.ad, "AD bit should be set");
        assert!(parsed.cd, "CD bit should be set");
    }

    #[test]
    fn test_ad_bit_not_set() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false, // AD bit not set
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(!parsed.ad, "AD bit should not be set");
    }

    #[test]
    fn test_cd_bit_not_set() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: false, // CD bit not set
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(!parsed.cd, "CD bit should not be set");
    }

    #[test]
    fn test_ad_bit_with_ra_bit() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: true, // RA bit set
            ad: true,           // AD bit set
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(parsed.recursion_ok, "RA bit should be set");
        assert!(parsed.ad, "AD bit should be set");
    }

    #[test]
    fn test_dnssec_validator_integration() {
        use crate::dnssec_validation_mode::DnssecValidator;

        let validator = DnssecValidator::new(true);
        let zone = crate::zone::Zone::new("example.com.".to_string());
        let records = vec![];

        let (is_valid, is_signed) = validator.validate_response(&zone, &records, "example.com.");

        // Unsigned zone should be valid but not signed
        assert!(is_valid);
        assert!(!is_signed);

        // AD bit should not be set
        assert!(!validator.should_set_ad_bit(is_valid, is_signed));
    }

    #[test]
    fn test_message_builder_initializes_ad_cd_false() {
        let builder = DnsMessageBuilder::new().with_url("example.com", "A");
        let msg = builder.build();

        assert!(!msg.ad, "AD bit should be false by default");
        assert!(!msg.cd, "CD bit should be false by default");
    }
}
