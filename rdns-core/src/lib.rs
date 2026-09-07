use crate::error::WireError;
use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr};

use compression::NameCompressor;
use dname::{
    dname_from_bytes, dname_to_bytes, DName, DNameUnpacker, TryFromBytes, TryUnpackFromBytes,
};

/// This build, as `<package version> (<git describe>)`. Stamped by `build.rs`
/// and passed to clap's `version` by every binary, so `--version` names a
/// commit.
pub const VERSION: &str = env!("RDNS_VERSION");

pub mod compression;
pub mod control;
pub mod dname;
pub mod error;
pub mod name;
mod record_data;
pub mod response;
pub mod utils;
pub mod validation;

/// [`RecordData`] lives in its own module so its fields are private to it.
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
    pub const ANY: Qtype = Qtype(utils::record_types::ANY_CODE);
    /// A whole-zone transfer (RFC 5936). TCP only.
    pub const AXFR: Qtype = Qtype(utils::record_types::AXFR_CODE);
    /// An incremental transfer (RFC 1995).
    pub const IXFR: Qtype = Qtype(utils::record_types::IXFR_CODE);

    /// The question that asks for exactly this record type. `const`, so
    /// `utils::record_types` stays the one registry of numbers.
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
        use utils::record_types as rt;
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
    /// Through [`utils::qtype_name`], not `record_type_name`: the latter takes
    /// an `Rtype` and prints the question everyone writes `ANY` as `TYPE255`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", utils::qtype_name(*self))
    }
}

#[derive(Debug, Clone)]
pub struct QuerySection {
    pub qname: String,
    /// The type asked for. See [`Qtype`] — a QTYPE is not a TYPE.
    pub qtype: Qtype,
    pub qclass: QueryClass,
}

/// Typed, fully-parsed view of a record's data: produced on demand by
/// [`RecordData::parse`], consumed by [`RecordData::from_parsed`].
///
/// Not what we store — the raw-bytes form avoids keeping these `String`s and
/// `Vec`s resident per cached record. Domain names here are fully-qualified and
/// uncompressed.
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
    /// The `<target>` a whole subtree is redirected to (RFC 6672 §2.1). One
    /// domain name, and the substitution applies to names *below* the owner.
    DNAME(String),
    /// A service binding: how to reach a service rather than only where its
    /// name points (RFC 9460 §2).
    ///
    /// One arm for two type codes. The HTTPS RR "shares the same encoding,
    /// format, and high-level semantics" (§6) and differs only in how its owner
    /// name is built (§9.1), which is not this layer's business — so `rtype`
    /// says which of the two it is. It cannot disagree with the enclosing
    /// [`RecordData`]: [`ParsedRecord::decode`] is handed that rtype and
    /// [`RecordData::from_parsed`] takes this one back.
    SVCB {
        rtype: Rtype,
        /// 0 is AliasMode, anything else ServiceMode; lower is preferred
        /// (§2.4.1).
        priority: u16,
        /// The alias target, or the alternative endpoint. `"."` is special
        /// both ways (§2.5): in ServiceMode it means the owner name, and in
        /// AliasMode that the service does not exist.
        target: String,
        /// The SvcParams, as `(key, wire value)` in strictly increasing key
        /// order (§2.2).
        ///
        /// Values stay as wire octets rather than becoming a typed enum per
        /// key. Three reasons: an unregistered key has to round-trip, which is
        /// the same argument RFC 3597 makes for whole records; the registered
        /// values are already length-prefixed lists or fixed-width fields, so
        /// there is nothing a decode would simplify here; and the presentation
        /// layer is the only place that has to know a key's shape, so knowing
        /// it twice is the duplication `CLAUDE.md` §7 is about.
        params: Vec<(u16, Vec<u8>)>,
    },
    MX {
        preference: u16,
        exchange: String,
    },
    /// One TXT record's `<character-string>`s (RFC 1035 §3.3.14): a run of
    /// length-prefixed strings of at most 255 octets each.
    ///
    /// A sequence, because two strings are a different record from the two
    /// joined. Bytes, because a character-string is arbitrary octets, and a
    /// `String` would fail the whole message on a TXT carrying non-UTF-8 data.
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

/// Read the SvcParams that fill the rest of an SVCB RDATA (RFC 9460 §2.2).
///
/// Each is a 2-octet key, a 2-octet length and that many octets of value.
/// §2.2 lists what makes the record malformed, and two of the three are here:
/// "the end of the RDATA occurs within a SvcParam", and "SvcParamKeys are not
/// in strictly increasing numeric order" — which, as the section notes, also
/// rules out duplicate keys. The third, a value whose format is wrong for its
/// key, belongs to whoever interprets that key.
fn decode_svc_params(mut rest: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, WireError> {
    let mut params: Vec<(u16, Vec<u8>)> = Vec::new();
    while !rest.is_empty() {
        let (key, tail) = read_be!(u16, rest);
        let (len, tail) = read_be!(u16, tail);
        let len = len as usize;
        if tail.len() < len {
            return Err(WireError::Truncated {
                what: "an SVCB parameter value",
                need: len,
                have: tail.len(),
            });
        }
        if let Some((previous, _)) = params.last() {
            if key <= *previous {
                return Err(WireError::malformed(
                    "SVCB RDATA",
                    format!(
                        "SvcParamKeys must be in strictly increasing order \
                         (RFC 9460 §2.2); {key} follows {previous}"
                    ),
                ));
            }
        }
        params.push((key, tail[..len].to_vec()));
        rest = &tail[len..];
    }
    Ok(params)
}

/// The inverse, canonicalizing the order.
///
/// Sorting here rather than asking every caller to: the wire order is a
/// canonical form and carries no information, so an operator writing
/// `port=53 alpn=h2` must get a valid record out. A *duplicate* key is
/// information — two values, and no rule for choosing — so it is an error
/// rather than something to quietly drop (`CLAUDE.md` §4).
fn encode_svc_params(params: &[(u16, Vec<u8>)]) -> Result<Vec<u8>, WireError> {
    let mut sorted: Vec<&(u16, Vec<u8>)> = params.iter().collect();
    sorted.sort_by_key(|(key, _)| *key);
    let mut out = Vec::new();
    for (index, (key, value)) in sorted.iter().enumerate() {
        if index > 0 && *key == sorted[index - 1].0 {
            return Err(WireError::malformed(
                "SVCB RDATA",
                format!("SvcParamKey {key} appears twice, and only one value can be sent"),
            ));
        }
        let len = u16::try_from(value.len()).map_err(|_| WireError::TooLong {
            what: "an SVCB parameter value",
            limit: u16::MAX as usize,
            actual: value.len(),
        })?;
        out.extend_from_slice(&key.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(value);
    }
    Ok(out)
}

impl ParsedRecord {
    /// Decode wire-format RDATA into a typed record. `unpacker` resolves any
    /// compressed domain names against the message it was built over.
    pub(crate) fn decode<'a>(
        record_type: Rtype,
        rdata: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<Self, WireError> {
        // RDLENGTH=0 is legal and means the record is a specifier, not data:
        // RFC 2136 §2.4.1/§2.4.2 and §2.5.2/§2.5.3 spell the RRset prerequisites
        // and deletions that way. Without this the arms below reject it and a
        // legal UPDATE is FORMERR before `update.rs` sees it.
        //
        // The cost is that an A with RDLENGTH 0 in an answer is relayed rather
        // than refused; RFC 3597 §5 already requires carrying RDATA we cannot
        // interpret.
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
            // Read through the unpacker like any other name even though
            // RFC 6672 §2.5 forbids sending <target> compressed: refusing a
            // pointer here would make us unable to read what a
            // non-conforming server sent, and the rule is on the writer.
            utils::record_types::DNAME => {
                let (target, _) = dname_from_bytes(rdata, unpacker)?;
                Ok(ParsedRecord::DNAME(target))
            }
            // Same forgiveness as DNAME about the uncompressed TargetName
            // (RFC 9460 §2.2): the rule binds the writer.
            utils::record_types::SVCB | utils::record_types::HTTPS => {
                let (priority, rest) = read_be!(u16, rdata);
                let (target, rest) = dname_from_bytes(rest, unpacker)?;
                Ok(ParsedRecord::SVCB {
                    rtype: record_type,
                    priority,
                    target,
                    params: decode_svc_params(rest)?,
                })
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
            utils::record_types::DS => {
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
                // RRSIG (RFC 4034 §3.1). Expiration precedes inception on the
                // wire; the other order makes an expired signature look current
                // and round-trips cleanly against ourselves.
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
                let (next_domain_name, rest) = dname_from_bytes(rdata, unpacker)?;
                let type_bitmap = rest.to_vec();
                Ok(ParsedRecord::NSEC {
                    next_domain_name,
                    type_bitmap,
                })
            }
            utils::record_types::DNSKEY => {
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

    /// Encode into `(rtype, uncompressed wire-format RDATA)` — the inverse of
    /// [`ParsedRecord::decode`] for the types we parse.
    pub(crate) fn encode(&self) -> Result<(Rtype, Vec<u8>), WireError> {
        let out = match self {
            ParsedRecord::A(addr) => (utils::record_types::A, addr.octets().to_vec()),
            ParsedRecord::AAAA(addr) => (utils::record_types::AAAA, addr.octets().to_vec()),
            ParsedRecord::NS(name) => (utils::record_types::NS, dname_to_bytes(name)?),
            ParsedRecord::CNAME(name) => (utils::record_types::CNAME, dname_to_bytes(name)?),
            ParsedRecord::PTR(name) => (utils::record_types::PTR, dname_to_bytes(name)?),
            ParsedRecord::DNAME(name) => (utils::record_types::DNAME, dname_to_bytes(name)?),
            ParsedRecord::SVCB {
                rtype,
                priority,
                target,
                params,
            } => {
                let mut v = priority.to_be_bytes().to_vec();
                v.extend_from_slice(&dname_to_bytes(target)?);
                v.extend_from_slice(&encode_svc_params(params)?);
                (*rtype, v)
            }
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
                    // One length byte, so 255 is the ceiling. Splitting a longer
                    // string in two would change what the record says.
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
            // Stored verbatim by `RecordData::from_wire`; nothing to re-encode.
            ParsedRecord::Unknown(rtype) => (*rtype, Vec::new()),
        };
        Ok(out)
    }
}

/// One resource record.
///
/// `PartialEq` is structural and so includes the TTL, which is not what every
/// DNS comparison wants: two records differing only in TTL are a malformed
/// RRset (RFC 2181 §5.2), not two records. `ixfr`'s delta keys and `update`'s
/// §2.5.4 deletion compare the fields they mean instead.
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
    /// The additional section without its OPT record — see [`DnsMessage::edns`].
    pub additionals: Vec<ResourceRecord>,
    /// The EDNS0 OPT pseudo-record, if the message carries one (RFC 6891).
    ///
    /// A field rather than a record in [`DnsMessage::additionals`], because OPT
    /// is not a resource record: its CLASS is a payload size and its TTL a flags
    /// word. `Option` also makes the two-OPT message RFC 6891 §6.1.1 forbids
    /// unspellable.
    pub edns: Option<Edns>,
}

/// The RR TYPE code of the EDNS0 OPT pseudo-record (RFC 6891).
pub const OPT_RECORD_TYPE: Rtype = Rtype::new(41);

/// The classic (pre-EDNS) UDP message size limit (RFC 1035 §4.2.1).
pub const CLASSIC_UDP_SIZE: u16 = 512;

/// The EDNS version we implement. A request at a higher version gets BADVERS
/// (RFC 6891 §6.1.3).
pub const EDNS_VERSION: u8 = 0;

/// A section's record count as the header's `u16`.
///
/// Checked, not cast: `as` would wrap a section past 65,535 records to a count
/// the reader then trusts, and every count here is derived from a `Vec` a caller
/// filled.
fn section_count(len: usize, what: &'static str) -> Result<u16, WireError> {
    len.try_into().map_err(|_| WireError::TooLong {
        what,
        limit: u16::MAX as usize,
        actual: len,
    })
}

/// A message with its RFC 1035 §4.2.2 two-octet length prefix, in one buffer so
/// a writer emits both in a single call.
///
/// The length is checked rather than cast: a wrapped prefix is 0 at exactly
/// 65,536, which every read loop here treats as a broken peer, and above that
/// desynchronises the stream. `rdns::tsig` appends to the *finished* bytes
/// and is the one path that can grow a message past the size it was serialized
/// to.
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

// EDNS option codes (IANA "DNS EDNS0 Option Codes"). None is interpreted;
// options round-trip as opaque bytes.
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
/// OPT repurposes the usual RR fields: NAME is root, CLASS is the requestor's
/// UDP payload size, TTL packs the extended-RCODE / version / flags (including
/// DNSSEC-OK).
///
/// The extended RCODE is not a field here — it belongs to the message, so it
/// lives in [`DnsMessage::rcode`] and is split across the header and the OPT TTL
/// only in [`DnsMessage::to_bytes`]. The option list is held unparsed because it
/// is the only fallible part: parsing it with the message would make a bad list
/// fail `DnsMessage::try_from_bytes`, leaving no parsed message for
/// `error_bytes` to answer FORMERR from.
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
/// The answer path asks only how big a reply may be, whether the version is one
/// we implement, and whether DO is set; building the options costs a `Vec` and a
/// `Vec<u8>` per option at a call site that wanted a flag. `Copy`, so threading
/// it through costs nothing. The options are still on [`DnsMessage::edns`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdnsHeader {
    /// Requestor's advertised UDP payload size (OPT CLASS field), as sent — not
    /// floored at 512. [`DnsMessage::udp_payload_size`] applies RFC 6891
    /// §6.2.3's floor, which is a question about what we may send.
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
    /// partial read: it earns FORMERR, not a truncated view.
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

    /// Whether the option list is well formed, without building it — the
    /// FORMERR question, which the answer path asks and [`Edns::options`] does
    /// more work than it needs to answer.
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
    pub(crate) fn rdata(&self) -> &[u8] {
        &self.rdata
    }

    /// Walk the option list, handing each option's code and data to `each`
    /// without copying either.
    ///
    /// Shared by [`Edns::options`] and [`Edns::check_options`] so the TLV
    /// arithmetic that decides whether a packet is FORMERR exists once.
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
/// Read once and branched on afterwards: the additional section has to know a
/// record's TYPE before it knows whether the record is a resource record at all
/// — an OPT is not — and reading the owner name twice to find out means walking
/// its labels again.
///
/// `ttl_bits` is raw. An OPT record's TTL field is not a TTL — it packs the
/// extended RCODE, the version and the DO bit — so RFC 2181 §8's clamp belongs
/// to whichever branch knows it is holding a real record.
///
/// `name` is the name as it sits on the wire, not its text: the OPT branch
/// throws the owner away (RFC 6891 §6.1.2 makes it the root), and decoding it
/// was a `Vec` and a `String` on every EDNS query.
struct RecordParts<'a> {
    name: DName<'a>,
    rtype: Rtype,
    class: u16,
    ttl_bits: i32,
    rdata: &'a [u8],
}

fn read_record_parts(data: &[u8]) -> Result<(RecordParts<'_>, &[u8]), WireError> {
    let (name, rest) = DName::try_from_bytes(data)?;
    let (rtype, rest) = read_be!(u16, rest);
    let (class, rest) = read_be!(u16, rest);
    let (ttl_bits, rest) = read_be!(i32, rest);
    let (rdatalen, rest) = read_be!(u16, rest);
    // RDLENGTH is attacker-chosen: check before slicing, or a record declaring
    // more RDATA than the message carries panics the parser. Reachable
    // pre-authentication on both transports.
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
        let (parts, rest) = read_record_parts(data)?;
        Ok((ResourceRecord::from_parts(parts, unpacker)?, rest))
    }
}

impl ResourceRecord {
    /// Assemble a record from its wire fields. This is where a real record's
    /// TTL is clamped (RFC 2181 §8) — see [`RecordParts::ttl_bits`].
    fn from_parts<'a>(
        parts: RecordParts<'a>,
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<Self, WireError> {
        Ok(ResourceRecord {
            name: unpacker.decode(parts.name)?,
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
    /// OPT is decoded from the wire fields directly rather than built as a
    /// [`ResourceRecord`] and taken apart: its TTL field is not a TTL but the
    /// extended RCODE, version and DO bit (RFC 6891 §6.1.3), and
    /// [`Ttl::from_wire`]'s RFC 2181 §8 clamp would erase all three whenever the
    /// extended RCODE's high byte has its top bit set.
    fn try_from_bytes<'a>(
        data: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<(Additional, &'a [u8]), WireError> {
        let (parts, rest) = read_record_parts(data)?;
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

        // The opcode is bits 3..6 of the flags' high byte, so it is shifted
        // down, not masked in place. Total, and it has to be: an opcode we have
        // no name for is echoed back unchanged (RFC 1035 §4.1.1).
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
                    // RFC 6891 §6.1.1: more than one OPT RR MUST be FORMERR.
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
        // 8 in the OPT record's flags word. The option list is *not* read here —
        // a malformed one must not fail the parse, or the FORMERR that answers
        // it could not be built (see [`Edns`]).
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
    /// An empty reply to `request`, carrying only what a reply must echo.
    ///
    /// The id, the opcode and RD are the client's and are copied back
    /// (RFC 1035 §4.1.1), and so is the question. CD is copied because
    /// RFC 4035 §3.2.2 says so in one line — "The name server side MUST copy
    /// the setting of the CD bit from a query to the corresponding response".
    ///
    /// AA, RA, AD, the RCODE and the OPT record are *policy*: they are exactly
    /// what five hand-written copies of this skeleton disagreed about
    /// (`TODO.md` #30g), so they are left neutral for the caller to set. This
    /// is deliberately not a finished message; a function that returned one
    /// would fit none of the callers.
    ///
    /// [`response::ResponseWriter::start`] is the same constructor for the path
    /// that writes straight into the send buffer.
    pub fn reply_to(request: &DnsMessage) -> DnsMessage {
        DnsMessage {
            id: request.id,
            response: true,
            opcode: request.opcode,
            authoritive: false,
            truncation: false,
            recursion: request.recursion,
            recursion_ok: false,
            ad: false,
            cd: request.cd,
            rcode: ResponseCode::Ok,
            queries: request.queries.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        }
    }

    pub fn to_bytes(&self, output: &mut [u8]) -> Result<usize, WireError> {
        self.to_bytes_with(output, &mut NameCompressor::new())
    }

    /// [`DnsMessage::to_bytes`] with a compressor the caller keeps.
    ///
    /// Its two allocations are per-message state, so a send loop answering one
    /// datagram after another paid them per answer. `compressor` is cleared
    /// here, not by the caller: offsets do not survive a message, and this is
    /// the only place that knows a message is starting.
    pub fn to_bytes_with(
        &self,
        output: &mut [u8],
        compressor: &mut NameCompressor,
    ) -> Result<usize, WireError> {
        compressor.clear();

        // RCODE is 12 bits, split across the header (low 4) and the OPT record's
        // TTL (high 8). A value past the ceiling is a caller bug, not something
        // to paper over with a success code.
        let rcode = response::wire_rcode(self.rcode, self.edns.is_some())?;

        // ARCOUNT counts the OPT record, which is a field here rather than a
        // member of `additionals`.
        let arcount = self.additionals.len() + usize::from(self.edns.is_some());
        let counts = [
            section_count(self.queries.len(), "the question section")?,
            section_count(self.answers.len(), "the answer section")?,
            section_count(self.authorities.len(), "the authority section")?,
            section_count(arcount, "the additional section")?,
        ];
        let mut pos = response::write_header(
            output,
            response::Header {
                id: self.id,
                response: self.response,
                opcode: self.opcode,
                authoritive: self.authoritive,
                truncation: self.truncation,
                recursion: self.recursion,
                recursion_ok: self.recursion_ok,
                ad: self.ad,
                cd: self.cd,
                rcode: self.rcode,
            },
            rcode,
            counts,
        )?;

        for q in &self.queries {
            pos = response::write_query(compressor, output, pos, q)?;
        }
        for section in [&self.answers, &self.authorities, &self.additionals] {
            for rr in section {
                pos = response::write_rr(
                    compressor, output, pos, &rr.name, rr.class, rr.ttl, &rr.rdata,
                )?;
            }
        }
        if let Some(edns) = &self.edns {
            pos = response::write_opt(output, pos, edns, rcode)?;
        }
        Ok(pos)
    }

    /// The message's EDNS parameters, if it carries an OPT record. Infallible:
    /// "is the option list well formed" is a separate question (see [`Edns`]).
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
    /// Readable even when the option list is malformed: the size lives in the
    /// OPT CLASS field.
    pub fn udp_payload_size(&self) -> u16 {
        self.edns
            .as_ref()
            .map(|e| e.udp_payload_size.max(CLASSIC_UDP_SIZE))
            .unwrap_or(CLASSIC_UDP_SIZE)
    }

    /// Set the message's OPT record, replacing any it already had. Infallible:
    /// encoding the option list is [`Edns::with_options`]' job.
    pub fn set_edns(&mut self, edns: Edns) {
        self.edns = Some(edns);
    }

    /// An upper bound on what [`DnsMessage::to_bytes_with`] writes, for sizing a
    /// scratch buffer.
    ///
    /// Sound in one direction, which is the one that matters: name compression
    /// makes the wire form shorter than this and never longer, RDATA is stored
    /// uncompressed so writing it can only shrink it, and a name's presentation
    /// text is at least its wire length — an escape like `\.` is two characters
    /// for one octet.
    fn wire_size_bound(&self) -> usize {
        // A name's wire form is its text plus a leading length octet and the
        // root label, and shorter than that whenever it is compressed.
        let name = |name: &str| name.len() + 2;
        let mut bound = response::HEADER_LEN;
        for q in &self.queries {
            bound += name(&q.qname) + 4;
        }
        for rr in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
        {
            // TYPE, CLASS, TTL and RDLENGTH, then the RDATA.
            bound += name(&rr.name) + 10 + rr.rdata.bytes().len();
        }
        if let Some(edns) = &self.edns {
            // The owner is the root, so one octet rather than a name.
            bound += 11 + edns.rdata().len();
        }
        bound
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
    /// Lets a hot send path keep one scratch buffer and allocate nothing per
    /// response: `Vec::truncate` does not release capacity, so a buffer sized to
    /// the protocol maximum travels into `send_to` whatever the answer was, and
    /// the allocation escapes into the socket call rather than being optimized
    /// away. The buffer is sized to `max_len` — only the TCP and transfer paths
    /// pass `u16::MAX`; a UDP caller passes its EDNS payload size.
    pub fn to_bytes_within_buf(&self, max_len: usize, out: &mut Vec<u8>) -> Result<(), WireError> {
        self.to_bytes_within_buf_with(max_len, out, &mut NameCompressor::new())
    }

    /// [`DnsMessage::to_bytes_within_buf`] with a compressor the caller keeps
    /// alongside the buffer, so an answer costs the allocator nothing at all.
    ///
    /// Both passes below go through [`DnsMessage::to_bytes_with`], which clears
    /// it: the retry must not see the offsets of the message it is replacing.
    pub fn to_bytes_within_buf_with(
        &self,
        max_len: usize,
        out: &mut Vec<u8>,
        compressor: &mut NameCompressor,
    ) -> Result<(), WireError> {
        // Sized to what this message can need, not to the ceiling: the TCP and
        // transfer paths pass `u16::MAX`, so a 43-byte reply was a 64 KiB
        // allocation and a 64 KiB memset (`TODO.md` #25b).
        let scratch = self.wire_size_bound().min(max_len);
        out.clear();
        out.resize(scratch, 0);
        let mut wrote = self.to_bytes_with(out, compressor);
        // The bound is an upper bound (see it), so this cannot fire — but a
        // wrong bound would truncate a message that fits, silently and only on
        // the shapes nobody tests. Growing to the limit and writing again makes
        // it a hint rather than an invariant (§4).
        if scratch < max_len
            && matches!(
                wrote,
                Err(WireError::Truncated {
                    what: "the output buffer",
                    ..
                })
            )
        {
            debug_assert!(
                false,
                "wire_size_bound said {scratch} and it was not enough"
            );
            out.clear();
            out.resize(max_len, 0);
            wrote = self.to_bytes_with(out, compressor);
        }
        match wrote {
            Ok(n) if n <= max_len => {
                out.truncate(n);
                return Ok(());
            }
            // Fits the buffer but not the limit — only reachable when a caller
            // passes a `max_len` above what it means to send, which none do.
            Ok(_) => {}
            // Sizing the scratch to `max_len` turns "too long" from a comparison
            // into this error, so it is caught rather than propagated; every
            // other `WireError` is a real failure to encode.
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
        // `truncated.edns` is carried over untouched: the size limit is itself
        // signalled via EDNS, so the OPT record must survive truncation.
        truncated.additionals.clear();

        // Floor at the classic 512: a header, a question and an OPT record fit
        // there, so a too-small `max_len` still yields a TC=1 answer to retry on.
        out.clear();
        out.resize(
            truncated
                .wire_size_bound()
                .max(max_len.min(CLASSIC_UDP_SIZE as usize)),
            0,
        );
        let n = truncated.to_bytes_with(out, compressor)?;
        out.truncate(n);
        Ok(())
    }
}

/// The payload size [`DnsMessageBuilder::with_dnssec`] advertises. A signed
/// answer does not fit in the classic 512 bytes; 4096 is what `dig +dnssec`
/// asks with.
const DNSSEC_PAYLOAD_SIZE: u16 = 4096;

/// A query, built field by field.
///
/// The question's type is a [`Qtype`] and not an `Rtype`. It was an `Rtype`, and
/// the presentation-name door resolved through `record_type_name_to_code`, which
/// answers `None` for ANY, AXFR and IXFR because no *record* is one of those
/// types — and the question was then dropped with no `else`, so `rdnsc`, this
/// tree's only query client, could not ask an ANY query at all (`TODO.md` #33b).
/// The name door is [`utils::qtype_name_to_code`], which answers `Option` and
/// leaves the reporting to the caller that has a person to report to.
pub struct DnsMessageBuilder {
    id: u16,
    queries: Vec<(String, Qtype)>,
    recursion: bool,
    /// The OPT record to attach, if any.
    edns: Option<Edns>,
}

impl Default for DnsMessageBuilder {
    /// RD set, because the caller of a query builder is asking a resolver. AXFR
    /// wants it clear (RFC 5936 §4.1.1): [`DnsMessageBuilder::with_recursion`].
    fn default() -> Self {
        DnsMessageBuilder {
            id: 0,
            queries: Vec::new(),
            recursion: true,
            edns: None,
        }
    }
}

impl DnsMessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask `name` for `qtype`.
    pub fn with_query(mut self, name: &str, qtype: Qtype) -> Self {
        self.queries.push((name.to_owned(), qtype));
        self
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    /// Set or clear RD. A transfer asks with it clear (RFC 5936 §4.1.1).
    pub fn with_recursion(mut self, recursion: bool) -> Self {
        self.recursion = recursion;
        self
    }

    /// Attach an EDNS0 OPT record advertising `udp_payload_size`, with DO as
    /// given (RFC 6891 §6.1.2, RFC 4035 §3.2.1).
    pub fn with_edns(mut self, udp_payload_size: u16, do_bit: bool) -> Self {
        let mut edns = Edns::with_payload_size(udp_payload_size);
        edns.do_bit = do_bit;
        self.edns = Some(edns);
        self
    }

    /// Ask for DNSSEC records: an EDNS0 OPT with DO set (RFC 4035 §3.2.1).
    /// Without DO a server must not send RRSIG, NSEC or NSEC3.
    ///
    /// [`DnsMessageBuilder::with_edns`] with the payload size that goes with
    /// asking for signatures — they do not fit in 512 bytes.
    pub fn with_dnssec(self, dnssec: bool) -> Self {
        if dnssec {
            self.with_edns(DNSSEC_PAYLOAD_SIZE, true)
        } else {
            self
        }
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
            recursion: self.recursion,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: self
                .queries
                .iter()
                .map(|(name, qtype)| QuerySection {
                    qname: name.to_owned(),
                    qtype: *qtype,
                    qclass: QueryClass::IN,
                })
                .collect(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: self.edns.clone(),
        }
    }
}

#[cfg(test)]
mod builder_dnssec_tests {
    use super::*;

    /// `--dnssec` has to produce an OPT record with DO set and survive the wire.
    /// Round-tripped rather than inspected, because the flag only matters if a
    /// *server* reads it: `edns_header` is the call `rdnsd` makes to decide
    /// whether to attach signatures.
    #[test]
    fn the_dnssec_flag_sets_do_and_survives_the_wire() {
        let plain = DnsMessageBuilder::new()
            .with_query("example.com", Qtype::of(utils::record_types::A))
            .build();
        assert!(plain.edns.is_none(), "no OPT unless asked for");

        let asked = DnsMessageBuilder::new()
            .with_query("example.com", Qtype::of(utils::record_types::A))
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

    /// #33b: the builder took an `Rtype`, so ANY, AXFR and IXFR resolved to
    /// `None` through the record-type table and the question was dropped with no
    /// `else` — a message with an empty question section went on the wire, and
    /// `rdnsc` re-derived the failure from `queries.is_empty()`. Round-tripped,
    /// because the QTYPE only matters if it survives serialization.
    #[test]
    fn the_question_only_types_can_be_asked_for() {
        for (name, qtype) in [
            ("ANY", Qtype::ANY),
            ("*", Qtype::ANY),
            ("AXFR", Qtype::AXFR),
            ("IXFR", Qtype::IXFR),
        ] {
            let asked = utils::qtype_name_to_code(name).expect("a name this client can ask for");
            assert_eq!(asked, qtype);

            let request = DnsMessageBuilder::new()
                .with_query("example.com.", asked)
                .build();
            let mut buf = vec![0u8; 512];
            let n = request.to_bytes(&mut buf).expect("serializes");
            let back = DnsMessage::try_from_bytes(&buf[..n]).expect("and reads back");
            let question = back.queries.first().expect("a question, not an empty one");
            assert_eq!(question.qtype, qtype, "{name} survives the wire");
        }
    }

    /// RD is set by default because the caller is usually asking a resolver; a
    /// transfer asks with it clear (RFC 5936 §4.1.1).
    #[test]
    fn recursion_and_edns_are_the_callers_to_choose() {
        let plain = DnsMessageBuilder::new()
            .with_query("example.com.", Qtype::of(utils::record_types::A))
            .build();
        assert!(plain.recursion, "RD by default");

        let transfer = DnsMessageBuilder::new()
            .with_query("example.com.", Qtype::AXFR)
            .with_recursion(false)
            .with_edns(1232, false)
            .build();
        assert!(!transfer.recursion);
        let edns = transfer.edns.as_ref().expect("an OPT record");
        assert_eq!(edns.udp_payload_size, 1232);
        assert!(!edns.do_bit, "EDNS without DO asks for no signatures");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::record_types as rt;

    /// RFC 1982 §3.2, which is the whole reason [`Serial`] exists.
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
    /// is later, which is why [`Serial`] has no `Ord` to invent an answer.
    #[test]
    fn serials_half_the_space_apart_are_neither_newer() {
        let (a, b) = (Serial::new(0), Serial::new(0x8000_0000));
        assert!(!a.is_newer_than(b));
        assert!(!b.is_newer_than(a));
        assert_ne!(a, b, "and they are still different versions");
    }

    /// `Display` forwards the formatter, so width and alignment survive:
    /// `zone_writer` lays an SOA out as `{serial:<12}` and `rdnsctl status` as
    /// `{:>6}`, and `write!(f, "{}", self.0)` would silently ignore both.
    #[test]
    fn a_serial_keeps_the_padding_it_is_formatted_with() {
        assert_eq!(format!("{:<12}|", Serial::new(2026080201)), "2026080201  |");
        assert_eq!(format!("{:>6}|", Serial::new(42)), "    42|");
    }

    /// An SOA read off the wire and written back out is byte-identical,
    /// including a serial past the signed ceiling.
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

    /// A record may not declare more RDATA than the message carries — an error,
    /// not a panic on a slice sized by an attacker-chosen `u16`.
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

    /// The same shape in the additional section, which
    /// `AdmissionCheck::validate_packet` only count-caps — OPT and TSIG
    /// legitimately live there.
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
    /// legal — the boundary where an off-by-one in the check would live.
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
            .with_query("www.google.fi", Qtype::of(utils::record_types::A))
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

    /// Every opcode has to survive the wire. A decoder that masks the field in
    /// place instead of shifting it reads every opcode but QUERY wrong, and only
    /// QUERY survives any mask — so a test that uses it alone sees nothing.
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

    /// An opcode with no name here is echoed unchanged. RFC 1035 §4.1.1 has
    /// OPCODE set by the originator and copied into the response, so a sentinel
    /// that cannot carry the value sends a DSO client (opcode 6, RFC 8490) a
    /// NOTIMP naming a different opcode.
    ///
    /// Written from raw bytes: a test that starts by naming a variant can only
    /// reach the values that have names.
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

    /// TXT framing (RFC 1035 §3.3.14): each string is preceded by its length.
    /// Stored as one unframed blob, the first byte of the text is read as a
    /// length and the record arrives short.
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
            // one such record fails to decode and takes the response with it.
            vec![0xff, 0x00, 0x80],
        ];
        let encoded = RecordData::from_parsed(&ParsedRecord::TXT(strings.clone())).unwrap();
        assert_eq!(
            encoded.parse().unwrap(),
            ParsedRecord::TXT(strings),
            "an empty character-string is legal too, and must survive"
        );
    }

    /// A character-string's length is one byte, so 255 is the ceiling; splitting
    /// a longer string in two would change what the record says.
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

    /// RFC 9460 §2.2 lists what makes an SVCB record malformed, and two of the
    /// three are structural: "the end of the RDATA occurs within a SvcParam",
    /// and "SvcParamKeys are not in strictly increasing numeric order" — which,
    /// as the section notes, also rules out duplicates.
    #[test]
    fn svcb_params_must_be_in_strictly_increasing_key_order() {
        // priority 1, target ".", then key 3 (port) and key 1 (alpn).
        let backwards = [
            0x00, 0x01, 0x00, // priority, root target
            0x00, 0x03, 0x00, 0x02, 0x01, 0xbb, // port=443
            0x00, 0x01, 0x00, 0x02, 0x01, b'h', // alpn
        ];
        let err = RecordData::new(utils::record_types::SVCB, &backwards[..])
            .expect_err("out-of-order keys do not make a record");
        assert!(
            err.to_string().contains("increasing"),
            "the error should say which rule: {err}"
        );

        // The same two keys the right way round do read back.
        let forwards = [
            0x00, 0x01, 0x00, //
            0x00, 0x01, 0x00, 0x02, 0x01, b'h', //
            0x00, 0x03, 0x00, 0x02, 0x01, 0xbb,
        ];
        let rdata = RecordData::new(utils::record_types::SVCB, &forwards[..])
            .expect("the right way round is a record");
        let Ok(ParsedRecord::SVCB { params, .. }) = rdata.parse() else {
            panic!("it parses");
        };
        assert_eq!(params.len(), 2);

        // And a value that runs off the end is truncated, not a panic: this is
        // pre-authentication input on both transports (`TODO.md` #12).
        let short = [0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x09, b'h'];
        assert!(RecordData::new(utils::record_types::SVCB, &short[..]).is_err());
    }

    /// The two type codes are one format (RFC 9460 §6), and `rtype` is what
    /// carries which — so a record built as HTTPS comes back as HTTPS.
    #[test]
    fn svcb_and_https_are_one_format_under_two_numbers() {
        for rtype in [utils::record_types::SVCB, utils::record_types::HTTPS] {
            let built = RecordData::from_parsed(&ParsedRecord::SVCB {
                rtype,
                priority: 1,
                target: "foo.example.com.".to_string(),
                params: vec![(3, vec![0x01, 0xbb])],
            })
            .expect("it encodes");
            assert_eq!(built.rtype(), rtype);
            let Ok(ParsedRecord::SVCB {
                rtype: back,
                priority,
                target,
                params,
            }) = built.parse()
            else {
                panic!("it parses")
            };
            assert_eq!(back, rtype, "the rtype survives the round trip");
            assert_eq!(priority, 1);
            assert_eq!(target, "foo.example.com.");
            assert_eq!(params, vec![(3, vec![0x01, 0xbb])]);
        }
    }

    /// The encoder sorts, because the wire order carries no information — but a
    /// duplicate key is two values with no rule for choosing, so it is an error
    /// rather than something to quietly drop.
    #[test]
    fn svcb_encoding_sorts_keys_and_refuses_a_duplicate() {
        let sorted = RecordData::from_parsed(&ParsedRecord::SVCB {
            rtype: utils::record_types::SVCB,
            priority: 1,
            target: ".".to_string(),
            params: vec![(3, vec![0x01, 0xbb]), (1, vec![0x01, b'h'])],
        })
        .expect("it encodes");
        // priority, root target, then key 1 before key 3.
        assert_eq!(
            sorted.bytes(),
            [
                0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x02, 0x01, b'h', 0x00, 0x03, 0x00, 0x02, 0x01,
                0xbb
            ]
        );

        let err = RecordData::from_parsed(&ParsedRecord::SVCB {
            rtype: utils::record_types::SVCB,
            priority: 1,
            target: ".".to_string(),
            params: vec![(3, vec![0x00, 0x35]), (3, vec![0x01, 0xbb])],
        })
        .expect_err("two values for one key");
        assert!(err.to_string().contains("twice"), "{err}");
    }

    /// RFC 6672 §2.5: "The DNAME RDATA target name MUST NOT be sent out in
    /// compressed form." The owner name is compressed like any other, which is
    /// why DNAME is not in `write_rdata`'s single-name arm beside NS and CNAME.
    #[test]
    fn a_dname_target_goes_out_uncompressed() {
        let dname = |owner: &str| ResourceRecord {
            name: owner.to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::DNAME("to.example.net.".to_string()))
                .unwrap(),
        };
        let mut msg = query_msg(0x6672);
        msg.response = true;
        msg.queries[0].qname = "a.example.com.".to_string();
        msg.answers = vec![dname("example.com."), dname("other.example.com.")];

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");

        // The length-prefixed label, so this counts targets and not substrings
        // of some other name. Twice: the second record pointing at the first
        // would be exactly the compression the section forbids.
        assert_eq!(
            buf[..n].windows(3).filter(|w| *w == b"to").count(),
            2,
            "each DNAME spells its own target out"
        );

        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");
        assert_eq!(parsed.answers.len(), 2);
        for (got, want) in parsed.answers.iter().zip(&msg.answers) {
            assert_eq!(got.name, want.name);
            assert_eq!(got.rdata, want.rdata);
        }
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

    /// A compressor carried from one message to the next must produce exactly
    /// what a fresh one produces.
    ///
    /// Compression offsets are positions *in the message being written*, so a
    /// compressor that remembers the last message emits pointers into bytes that
    /// are no longer there — a reply that parses as something else, or does not
    /// parse. Two different messages, alternating, because a leak only shows
    /// when the names differ.
    #[test]
    fn a_carried_compressor_writes_what_a_fresh_one_writes() {
        let messages: Vec<DnsMessage> = ["www.example.com.", "a.very.different.name.test."]
            .iter()
            .map(|name| DnsMessage {
                id: 0x1234,
                response: true,
                opcode: OpCode::Query,
                authoritive: true,
                truncation: false,
                recursion: false,
                recursion_ok: false,
                ad: false,
                cd: false,
                rcode: ResponseCode::Ok,
                queries: vec![QuerySection {
                    qname: (*name).to_string(),
                    qtype: Qtype::of(utils::record_types::A),
                    qclass: QueryClass::IN,
                }],
                answers: vec![ResourceRecord {
                    name: (*name).to_string(),
                    class: Class::IN,
                    ttl: Ttl::from_secs(60),
                    rdata: RecordData::from_parsed(&ParsedRecord::A(std::net::Ipv4Addr::new(
                        192, 0, 2, 1,
                    )))
                    .expect("encode"),
                }],
                authorities: Vec::new(),
                additionals: Vec::new(),
                edns: None,
            })
            .collect();

        let fresh: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| m.to_bytes_within(512).expect("serialize"))
            .collect();

        let mut carried = compression::NameCompressor::new();
        let mut buf = Vec::new();
        for round in 0..3 {
            for (i, message) in messages.iter().enumerate() {
                message
                    .to_bytes_within_buf_with(512, &mut buf, &mut carried)
                    .expect("serialize");
                assert_eq!(
                    buf, fresh[i],
                    "round {round}, message {i}: a carried compressor changed the bytes"
                );
                // And it still decodes to the same message, which is what a
                // stale pointer would break.
                let back = DnsMessage::try_from_bytes(&buf).expect("re-parse");
                assert_eq!(back.queries[0].qname, message.queries[0].qname);
                assert_eq!(back.answers[0].name, message.answers[0].name);
            }
        }
    }

    /// The truncation retry serializes twice through one call, so it is the path
    /// where a compressor cleared by the *caller* rather than per message would
    /// carry the abandoned attempt's offsets into the reply that goes out.
    #[test]
    fn the_truncated_retry_does_not_inherit_the_abandoned_attempt() {
        let big = DnsMessage {
            id: 0x4321,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: "www.example.com.".to_string(),
                qtype: Qtype::of(utils::record_types::A),
                qclass: QueryClass::IN,
            }],
            answers: (0..40)
                .map(|i| ResourceRecord {
                    name: format!("host{i}.example.com."),
                    class: Class::IN,
                    ttl: Ttl::from_secs(60),
                    rdata: RecordData::from_parsed(&ParsedRecord::A(std::net::Ipv4Addr::new(
                        192, 0, 2, i as u8,
                    )))
                    .expect("encode"),
                })
                .collect(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        };

        let fresh = big.to_bytes_within(512).expect("truncate");
        let mut carried = compression::NameCompressor::new();
        let mut buf = Vec::new();
        big.to_bytes_within_buf_with(512, &mut buf, &mut carried)
            .expect("truncate");

        assert_eq!(
            buf, fresh,
            "the retry must not depend on a carried compressor"
        );
        let back = DnsMessage::try_from_bytes(&buf).expect("the truncated reply parses");
        assert!(back.truncation, "TC is set");
        assert!(back.answers.is_empty(), "and it carries no records");
        assert_eq!(back.queries[0].qname, "www.example.com.");
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

    /// An unknown QCLASS is echoed as itself. 254 is RFC 2136's real NONE, not a
    /// free sentinel, and a client matches the echoed question (RFC 5452 §9.1).
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

    /// An rcode with no name here used to serialize as 0. `rdnsr` relays
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
    /// Nothing checked this before OPT became a field. The first OPT was
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
        // there was exactly one. With OPT as an `Option` field a second one is
        // unspellable, which is also what RFC 6891 §6.1.1 says about receiving
        // one.
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

    /// A malformed option list is an error — but not an error that reaching
    /// the OPT record produces.
    ///
    /// OPT is a field carrying its RDATA unparsed, so "does this message have
    /// EDNS" is infallible and "is its option list well formed" is a separate,
    /// fallible question. The split is what keeps a bad list answerable: if
    /// reading it were part of parsing the message,
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
        // The whole message, not a substring of it: this literal carried 22
        // spaces where a `\` continuation belonged, and the assertion above was
        // true throughout. rustfmt does not touch string literals (§12), so a
        // wrapped one has no other check.
        assert!(
            !err.to_string().contains("  "),
            "a wrapped literal leaked its indentation: {err}"
        );
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

        // And the TCP path, which passes the protocol ceiling because the length
        // prefix is its only limit. This is what `TODO.md` #25b measured: 65 535
        // bytes allocated and zeroed for the same 60 bytes of answer, because
        // the scratch was sized to the limit rather than to the message.
        let framed = msg.to_bytes_within(u16::MAX as usize).expect("TCP");
        assert_eq!(framed, bytes, "the limit does not change the bytes");
        assert!(
            framed.capacity() < 1024,
            "a TCP response must not hold {} of capacity for {} bytes of answer",
            framed.capacity(),
            framed.len()
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
    fn test_message_builder_initializes_ad_cd_false() {
        let builder =
            DnsMessageBuilder::new().with_query("example.com", Qtype::of(utils::record_types::A));
        let msg = builder.build();

        assert!(!msg.ad, "AD bit should be false by default");
        assert!(!msg.cd, "CD bit should be false by default");
    }
}
