use anyhow::anyhow;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use rand::Rng;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
};

use compression::NameCompressor;
use dname::{dname_from_bytes, dname_to_bytes, write_bytes, DNameUnpacker, TryUnpackFromBytes};

pub mod compression;
pub mod dname;
pub mod zone;
pub mod zone_writer;
pub mod xfr;
pub mod secondary;
pub mod ixfr;
pub mod rfc5011;
pub mod special_names;
pub mod persist;
pub mod security;
pub mod validation;
pub mod logging;
pub mod bench;
pub mod cache;
pub mod resolver;
pub mod transfer;
pub mod tsig;
pub mod metrics;
pub mod notify;
pub mod nsec_cache;
pub mod negative_cache;
pub mod dnssec;
pub mod dnssec_chain;
pub mod dnssec_denial;
pub mod dnssec_validation_mode;
/// Real DNSSEC signing for tests only — see the module docs for why an
/// in-process signer is the only way to exercise this code here.
#[cfg(test)]
mod dnssec_test_util;
pub mod telemetry;
pub mod utils;
pub mod serialization;

// Re-export cache module for public use
pub use cache::{DnsCache, CacheStats};

#[macro_use]
mod macros {
    macro_rules! read_be {
        ($dt:ty, $data:expr) => {{
            let sz = std::mem::size_of::<$dt>();
            if $data.len() < sz {
                return Err(anyhow::anyhow!("Not enough data to read {}: need {}, have {}", stringify!($dt), sz, $data.len()));
            }
            (
                <$dt>::from_be_bytes($data[..sz].try_into().unwrap()),
                &$data[sz..],
            )
        }};
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Query = 0,
    IQuery = 1, // RFC3425: IQUERY obsolete
    Status = 2,
    Notify = 4,
    Update = 5,
    Unknown = 15,
}

// practically always IN (1), classes are supposed to be sort of
// dimension to the DNS database (see RFC6895 section 3.2). Only CH (3)
// and HS (4) are mentioned but practially never used outside of local tests
#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, Clone)]
pub enum QueryClass {
    IN = 1,
    CH = 3,
    HS = 4,
    None = 254,
    Any = 255,
}

#[derive(Debug, Clone)]
pub struct QuerySection {
    // Contains the domain name for the question
    pub qname: String,
    // Query type, matches ResourceRecordKind discriminant
    pub qtype: u16,
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
        serial: u32,
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
        type_covered: u16,
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
    Unknown(u16),
}

/// A record's data, stored as **uncompressed wire-format bytes**.
///
/// This is the compact, allocation-light form we keep resident (in caches,
/// zones, and messages). It is 24 bytes regardless of record type, versus the
/// ~96-byte typed enum it replaces, because the large/rare DNSSEC and SOA
/// payloads no longer sit inline in every record.
///
/// Any domain names embedded in the data are expanded to their full,
/// uncompressed form when the record is read off the wire (see
/// [`RecordData::from_wire`]), so the bytes are self-contained: they can be
/// re-parsed with [`RecordData::parse`] or re-serialized without needing the
/// original message for compression-pointer resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordData {
    /// The RR TYPE code (e.g. 1 = A, 28 = AAAA).
    pub rtype: u16,
    /// Uncompressed wire-format RDATA.
    pub rdata: Box<[u8]>,
}

impl RecordData {
    /// Map a record-type name (e.g. "A", "AAAA") to its numeric TYPE code.
    fn to_u16(kind: &str) -> Option<u16> {
        utils::record_type_name_to_code(kind)
    }

    /// The RR TYPE code of this record.
    pub fn rtype(&self) -> u16 {
        self.rtype
    }

    /// Read a record's RDATA off the wire and store it compactly.
    ///
    /// `unpacker` is used to follow any compression pointers against the full
    /// message; the result is re-encoded without compression so the stored
    /// bytes are self-contained. Types we don't parse are stored verbatim
    /// (RFC 3597), which — unlike the old typed enum — preserves their bytes.
    pub fn from_wire<'a>(
        record_type: u16,
        rdata: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<Self, anyhow::Error> {
        let parsed = ParsedRecord::decode(record_type, rdata, unpacker)?;
        if let ParsedRecord::Unknown(_) = parsed {
            // Opaque type: keep the original bytes exactly as received.
            return Ok(RecordData {
                rtype: record_type,
                rdata: rdata.to_vec().into_boxed_slice(),
            });
        }
        Self::from_parsed(&parsed)
    }

    /// Parse the stored bytes into a typed [`ParsedRecord`] on demand.
    ///
    /// Records that are only cached and re-served never need this, which is the
    /// whole point of storing raw bytes. Stored names are uncompressed, so no
    /// message context is required — the decoder is handed an unpacker over the
    /// rdata itself, which by construction contains no pointers.
    pub fn parse(&self) -> Result<ParsedRecord, anyhow::Error> {
        let unpacker = DNameUnpacker::new(&self.rdata);
        ParsedRecord::decode(self.rtype, &self.rdata, &unpacker)
    }

    /// Encode a typed record into compact, uncompressed wire-format storage.
    pub fn from_parsed(parsed: &ParsedRecord) -> Result<Self, anyhow::Error> {
        let (rtype, rdata) = parsed.encode()?;
        Ok(RecordData {
            rtype,
            rdata: rdata.into_boxed_slice(),
        })
    }
}

impl ParsedRecord {
    /// Decode wire-format RDATA into a typed record. `unpacker` resolves any
    /// compressed domain names against the message it was built over.
    fn decode<'a>(
        record_type: u16,
        rdata: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<Self, anyhow::Error> {
        match record_type {
            1 => {
                let addr: [u8; 4] = rdata.try_into()?;
                Ok(ParsedRecord::A(Ipv4Addr::from(addr)))
            }
            2 => {
                let (nsname, _) = dname_from_bytes(rdata, unpacker)?;
                Ok(ParsedRecord::NS(nsname))
            }
            5 => {
                let (cname, _) = dname_from_bytes(rdata, unpacker)?;
                Ok(ParsedRecord::CNAME(cname))
            }
            6 => {
                let (mname, rest) = dname_from_bytes(rdata, unpacker)?;
                let (rname, rest) = dname_from_bytes(rest, unpacker)?;
                let (serial, rest) = read_be!(u32, rest);
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
            12 => {
                let (ptrdname, _) = dname_from_bytes(rdata, unpacker)?;
                Ok(ParsedRecord::PTR(ptrdname))
            }
            15 => {
                let (preference, rest) = read_be!(u16, rdata);
                let (exchange, _) = dname_from_bytes(rest, unpacker)?;
                Ok(ParsedRecord::MX {
                    preference,
                    exchange,
                })
            }
            16 => {
                // A run of `<character-string>`s: one length byte, then that
                // many bytes, until the RDATA runs out.
                let mut strings = Vec::new();
                let mut rest = rdata;
                while let Some((&len, after_len)) = rest.split_first() {
                    let len = len as usize;
                    if after_len.len() < len {
                        return Err(anyhow!(
                            "TXT character-string claims {len} bytes but only {} remain",
                            after_len.len()
                        ));
                    }
                    strings.push(after_len[..len].to_vec());
                    rest = &after_len[len..];
                }
                Ok(ParsedRecord::TXT(strings))
            }
            28 => {
                let addr: [u8; 16] = rdata.try_into()?;
                Ok(ParsedRecord::AAAA(Ipv6Addr::from(addr)))
            }
            // DNSSEC types
            43 => {
                // DS: key_tag(2) + algorithm(1) + digest_type(1) + digest(variable)
                let (key_tag, rest) = read_be!(u16, rdata);
                if rest.len() < 2 {
                    return Err(anyhow!("DS record truncated before its digest type"));
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
            46 => {
                // RRSIG (RFC 4034 §3.1): type_covered(2) + algorithm(1) + labels(1)
                // + original_ttl(4) + expiration(4) + inception(4) + key_tag(2) +
                // signer_name + signature. Expiration precedes inception on the
                // wire — reading them the other way round makes an expired
                // signature look current, which is only invisible while both ends
                // of the round trip are ours.
                let (type_covered, rest) = read_be!(u16, rdata);
                if rest.len() < 2 {
                    return Err(anyhow!("RRSIG record truncated before its label count"));
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
                    type_covered,
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
            47 => {
                // NSEC: next_domain_name + type_bitmap
                let (next_domain_name, rest) = dname_from_bytes(rdata, unpacker)?;
                let type_bitmap = rest.to_vec();
                Ok(ParsedRecord::NSEC {
                    next_domain_name,
                    type_bitmap,
                })
            }
            48 => {
                // DNSKEY: flags(2) + protocol(1) + algorithm(1) + public_key(variable)
                let (flags, rest) = read_be!(u16, rdata);
                if rest.len() < 2 {
                    return Err(anyhow!("DNSKEY record truncated before its algorithm"));
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
            50 => {
                // NSEC3: hash_algorithm(1) + flags(1) + iterations(2) + salt_len(1) + salt(variable) + next_hashed_owner + type_bitmap
                if rdata.len() < 5 {
                    return Err(anyhow!("NSEC3 record too short: need at least 5 bytes, got {}", rdata.len()));
                }
                let hash_algorithm = rdata[0];
                let flags = rdata[1];
                let (iterations, rest) = read_be!(u16, &rdata[2..]);
                let salt_len = rest[0] as usize;
                if rest.len() < 1 + salt_len {
                    return Err(anyhow!("NSEC3 salt extends beyond record boundary"));
                }
                let salt = rest[1..1+salt_len].to_vec();
                let rest = &rest[1+salt_len..];

                // next_hashed_owner is a raw byte string (not a domain name)
                if rest.is_empty() {
                    return Err(anyhow!("NSEC3 record missing next_hashed_owner"));
                }
                let next_owner_len = rest[0] as usize;
                if rest.len() < 1 + next_owner_len {
                    return Err(anyhow!("NSEC3 next_hashed_owner extends beyond record boundary"));
                }
                let next_hashed_owner = rest[1..1+next_owner_len].to_vec();
                let type_bitmap = rest[1+next_owner_len..].to_vec();

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
    fn encode(&self) -> Result<(u16, Vec<u8>), anyhow::Error> {
        let out = match self {
            ParsedRecord::A(addr) => (1, addr.octets().to_vec()),
            ParsedRecord::AAAA(addr) => (28, addr.octets().to_vec()),
            ParsedRecord::NS(name) => (2, dname_to_bytes(name)?),
            ParsedRecord::CNAME(name) => (5, dname_to_bytes(name)?),
            ParsedRecord::PTR(name) => (12, dname_to_bytes(name)?),
            ParsedRecord::MX {
                preference,
                exchange,
            } => {
                let mut v = preference.to_be_bytes().to_vec();
                v.extend_from_slice(&dname_to_bytes(exchange)?);
                (15, v)
            }
            ParsedRecord::TXT(strings) => {
                if strings.is_empty() {
                    return Err(anyhow!("a TXT record must carry at least one string"));
                }
                let mut v = Vec::new();
                for s in strings {
                    // The length is one byte, so 255 is the ceiling. Splitting a
                    // longer string across two character-strings would change
                    // what the record says, so this is the zone's mistake to fix.
                    let len = u8::try_from(s.len()).map_err(|_| {
                        anyhow!(
                            "TXT string is {} bytes; a character-string holds at most 255",
                            s.len()
                        )
                    })?;
                    v.push(len);
                    v.extend_from_slice(s);
                }
                (16, v)
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
                v.extend_from_slice(&serial.to_be_bytes());
                v.extend_from_slice(&refresh.to_be_bytes());
                v.extend_from_slice(&retry.to_be_bytes());
                v.extend_from_slice(&expire.to_be_bytes());
                v.extend_from_slice(&minimum.to_be_bytes());
                (6, v)
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
                (48, v)
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
                let mut v = type_covered.to_be_bytes().to_vec();
                v.push(*algorithm);
                v.push(*labels);
                v.extend_from_slice(&original_ttl.to_be_bytes());
                // Expiration first, then inception (RFC 4034 §3.1).
                v.extend_from_slice(&expiration.to_be_bytes());
                v.extend_from_slice(&inception.to_be_bytes());
                v.extend_from_slice(&key_tag.to_be_bytes());
                v.extend_from_slice(&dname_to_bytes(signer_name)?);
                v.extend_from_slice(signature);
                (46, v)
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
                (43, v)
            }
            ParsedRecord::NSEC {
                next_domain_name,
                type_bitmap,
            } => {
                let mut v = dname_to_bytes(next_domain_name)?;
                v.extend_from_slice(type_bitmap);
                (47, v)
            }
            ParsedRecord::NSEC3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmap,
            } => {
                let mut v = Vec::with_capacity(6 + salt.len() + next_hashed_owner.len() + type_bitmap.len());
                v.push(*hash_algorithm);
                v.push(*flags);
                v.extend_from_slice(&iterations.to_be_bytes());
                v.push(salt.len() as u8);
                v.extend_from_slice(salt);
                v.push(next_hashed_owner.len() as u8);
                v.extend_from_slice(next_hashed_owner);
                v.extend_from_slice(type_bitmap);
                (50, v)
            }
            // Opaque types are stored verbatim by `RecordData::from_wire`; there
            // is no typed payload to re-encode here.
            ParsedRecord::Unknown(rtype) => (*rtype, Vec::new()),
        };
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub class: u16,
    pub ttl: i32, // As per 2.3.3 in RFC 1035
    pub rdata: RecordData,
}

#[derive(Debug, FromPrimitive, ToPrimitive, Clone, Copy, PartialEq, Eq)]
pub enum ResponseCode {
    // RFC 1035 - Basic codes
    Ok = 0,
    FormatError = 1,
    ServerFailure = 2,
    NoSuchDomain = 3,
    NotImplemented = 4,
    Refused = 5,
    // RFC 2136 - Domain update related codes
    DomainExistsForSomeReason = 6,
    ResourceRecordSetExistsForSomeReason = 7,
    NoSuchResourceRecordSet = 8,
    NotAuthorized = 9, // Or ServerNotAuthorativeForZone (RFC8945)
    NameNotInZone = 10,

    // RFC 8490 - DNS Stateful Operations
    DsoTypeNotImplemented = 11,

    BadOptVersion = 16, // Or BadTsigSignature (RFC8945)
    BadKey = 17,
    BadTime = 18,

    // RFC 2930 - TKEY RR
    BadTkeyMode = 19,
    BadName = 20,
    BadAlgorithm = 21,
    BadTruncation = 22,
    BadCookie = 23,

    Unknown = 65535,
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
    pub ad: bool,        // Authenticated Data bit (RFC 4035)
    pub cd: bool,        // Checking Disabled bit (RFC 4035)
    pub rcode: ResponseCode, // response status: whether or not response was succesful

    pub queries: Vec<QuerySection>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

/// The RR TYPE code of the EDNS0 OPT pseudo-record (RFC 6891).
pub const OPT_RECORD_TYPE: u16 = 41;

/// The classic (pre-EDNS) UDP message size limit (RFC 1035 §4.2.1).
pub const CLASSIC_UDP_SIZE: u16 = 512;

/// The EDNS version we implement. A request at a higher version gets BADVERS
/// (RFC 6891 §6.1.3).
pub const EDNS_VERSION: u8 = 0;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edns {
    /// Requestor's/responder's advertised UDP payload size (OPT CLASS field).
    pub udp_payload_size: u16,
    /// EDNS version (0 for EDNS0).
    pub version: u8,
    /// DNSSEC OK bit (DO) — the client is willing to receive DNSSEC records.
    pub do_bit: bool,
    /// Options carried in the OPT RDATA, in wire order.
    pub options: Vec<EdnsOption>,
}

impl Edns {
    /// A plain OPT advertising `size` bytes, EDNS version 0, DO clear, no options.
    pub fn with_payload_size(size: u16) -> Self {
        Edns {
            udp_payload_size: size,
            version: EDNS_VERSION,
            do_bit: false,
            options: Vec::new(),
        }
    }

    /// The data of the first option with `code`, if present.
    pub fn option(&self, code: u16) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|o| o.code == code)
            .map(|o| o.data.as_slice())
    }

    /// Pack version and flags into the 32-bit OPT TTL field. The extended-RCODE
    /// byte is left zero; [`DnsMessage::to_bytes`] fills it in from the
    /// message's RCODE.
    fn flags(&self) -> u32 {
        let do_flag: u32 = if self.do_bit { 0x8000 } else { 0 };
        ((self.version as u32) << 16) | do_flag
    }

    /// Decode EDNS parameters from a parsed OPT [`ResourceRecord`].
    fn from_record(rr: &ResourceRecord) -> Result<Self, anyhow::Error> {
        let flags = rr.ttl as u32;
        Ok(Edns {
            udp_payload_size: rr.class,
            version: ((flags >> 16) & 0xff) as u8,
            do_bit: (flags & 0x8000) != 0,
            options: Self::parse_options(&rr.rdata.rdata)?,
        })
    }

    /// Parse the OPT RDATA option list. A malformed list is an error rather
    /// than a partial read: a client that sends one deserves FORMERR, not a
    /// silently truncated view of what it asked for.
    fn parse_options(mut rdata: &[u8]) -> Result<Vec<EdnsOption>, anyhow::Error> {
        let mut options = Vec::new();
        while !rdata.is_empty() {
            if rdata.len() < 4 {
                return Err(anyhow!(
                    "truncated EDNS option header: {} byte(s) left, need 4",
                    rdata.len()
                ));
            }
            let code = u16::from_be_bytes([rdata[0], rdata[1]]);
            let len = u16::from_be_bytes([rdata[2], rdata[3]]) as usize;
            rdata = &rdata[4..];
            if rdata.len() < len {
                return Err(anyhow!(
                    "EDNS option {code} declares {len} bytes but only {} remain",
                    rdata.len()
                ));
            }
            options.push(EdnsOption {
                code,
                data: rdata[..len].to_vec(),
            });
            rdata = &rdata[len..];
        }
        Ok(options)
    }

    /// Build the OPT [`ResourceRecord`] for the additional section, encoding the
    /// option list into RDATA.
    fn to_record(&self) -> Result<ResourceRecord, anyhow::Error> {
        let mut rdata = Vec::new();
        for opt in &self.options {
            let len: u16 = opt.data.len().try_into().map_err(|_| {
                anyhow!(
                    "EDNS option {} data is {} bytes, exceeding the 65535-byte field",
                    opt.code,
                    opt.data.len()
                )
            })?;
            rdata.extend_from_slice(&opt.code.to_be_bytes());
            rdata.extend_from_slice(&len.to_be_bytes());
            rdata.extend_from_slice(&opt.data);
        }
        Ok(ResourceRecord {
            name: ".".to_string(),
            class: self.udp_payload_size,
            ttl: self.flags() as i32,
            rdata: RecordData {
                rtype: OPT_RECORD_TYPE,
                rdata: rdata.into_boxed_slice(),
            },
        })
    }
}

impl<'a> TryUnpackFromBytes<'a> for QuerySection {
    type Output = (QuerySection, &'a [u8]);
    type Error = anyhow::Error;
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
                qtype,
                qclass: QueryClass::from_u16(qclass).unwrap_or(QueryClass::None),
            },
            rest,
        ))
    }
}

impl<'a> TryUnpackFromBytes<'a> for ResourceRecord {
    type Output = (ResourceRecord, &'a [u8]);
    type Error = anyhow::Error;
    fn try_from_bytes(
        data: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<<Self as TryUnpackFromBytes<'a>>::Output, Self::Error> {
        let (name, rest) = dname_from_bytes(data, unpacker)?;
        let (record_type, rest) = read_be!(u16, rest);
        let (class, rest) = read_be!(u16, rest);
        let (ttl, rest) = read_be!(i32, rest);
        let (rdatalen, rest) = read_be!(u16, rest);
        let rdata = &rest[..rdatalen as usize];

        let rdata = RecordData::from_wire(record_type, rdata, unpacker)?;
        Ok((
            Self {
                name,
                class,
                ttl,
                rdata,
            },
            &rest[rdatalen as usize..],
        ))
    }
}

impl DnsMessage {
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, anyhow::Error> {
        if data.len() < 12 {
            return Err(anyhow!("not enough data"));
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
        let opcode = OpCode::from_u8((hi >> 3) & 0x0f).unwrap_or(OpCode::Unknown);

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

        let mut additionals = Vec::new();
        for _ in 0..add_len {
            let (query, r) = ResourceRecord::try_from_bytes(rest, &unpacker)?;
            additionals.push(query);
            rest = r;
        }

        // RCODE is 12 bits (RFC 6891 §6.1.3): the low 4 in the header, the high
        // 8 in the OPT record's TTL when the message carries one. Reassemble
        // them so `rcode` is the whole value; without OPT the high bits are 0
        // and this is the classic 4-bit code.
        let ext_rcode = additionals
            .iter()
            .find(|rr| rr.rdata.rtype == OPT_RECORD_TYPE)
            .map(|rr| ((rr.ttl as u32) >> 24) as u16)
            .unwrap_or(0);
        let rcode = ResponseCode::from_u16((ext_rcode << 4) | (lo & 0x0f) as u16)
            .unwrap_or(ResponseCode::Unknown);

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
        })
    }

    /// Serialize the message into `output`, with domain-name compression
    /// (RFC 1035 §4.1.4). Returns the number of bytes written; errors if the
    /// message does not fit rather than writing a silently truncated one.
    pub fn to_bytes(&self, output: &mut [u8]) -> Result<usize, anyhow::Error> {
        let mut compressor = NameCompressor::new();
        let mut pos = 0;

        pos = write_bytes(output, pos, &self.id.to_be_bytes())?;

        let opcode = self.opcode.to_u8().unwrap_or_default();

        // RCODE is a 12-bit value split across the header (low 4 bits) and the
        // OPT record's TTL (high 8). `ResponseCode::Unknown` is a sentinel for
        // an unrecognized wire value rather than a real code, so it goes out as 0.
        let rcode = match self.rcode.to_u16() {
            Some(v) if v <= 0xfff => v,
            _ => 0,
        };
        let has_opt = self
            .additionals
            .iter()
            .any(|rr| rr.rdata.rtype == OPT_RECORD_TYPE);
        if rcode > 0xf && !has_opt {
            return Err(anyhow!(
                "extended RCODE {rcode} needs an EDNS0 OPT record to carry its high bits (RFC 6891 §6.1.3)"
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
        pos = write_bytes(output, pos, &(self.additionals.len() as u16).to_be_bytes())?;

        for q in &self.queries {
            pos = compressor.write_name(q.qname.as_str(), output, pos)?;
            pos = write_bytes(output, pos, &q.qtype.to_be_bytes())?;
            pos = write_bytes(output, pos, &q.qclass.to_u16().unwrap_or(254).to_be_bytes())?;
        }

        // Resource records. Owner names are compressed against everything
        // written so far; RDATA is stored uncompressed and wire-ready, so it is
        // a straight copy except for the record types whose embedded names may
        // legally be compressed (see [`NameCompressor::write_rdata`]).
        for section in [&self.answers, &self.authorities, &self.additionals] {
            for rr in section {
                pos = compressor.write_name(rr.name.as_str(), output, pos)?;
                pos = write_bytes(output, pos, &rr.rdata.rtype.to_be_bytes())?;
                pos = write_bytes(output, pos, &rr.class.to_be_bytes())?;
                // The OPT TTL's top byte is the extended RCODE's high 8 bits.
                // `self.rcode` owns the whole 12-bit value, so stamp it in here
                // rather than trusting whatever the OPT record was built with.
                let ttl = if rr.rdata.rtype == OPT_RECORD_TYPE {
                    (rr.ttl as u32 & 0x00ff_ffff) | ((rcode as u32 >> 4) << 24)
                } else {
                    rr.ttl as u32
                };
                pos = write_bytes(output, pos, &ttl.to_be_bytes())?;

                // RDLEN can only be known once the RDATA is written, since
                // compression changes its length. Leave a hole and fill it in.
                let rdlen_at = pos;
                pos = write_bytes(output, pos, &[0u8, 0u8])?;
                let rdata_at = pos;
                pos = compressor.write_rdata(rr.rdata.rtype, &rr.rdata.rdata, output, pos)?;
                let rdlen: u16 = (pos - rdata_at)
                    .try_into()
                    .map_err(|_| anyhow!("RDATA exceeds 65535 bytes"))?;
                write_bytes(output, rdlen_at, &rdlen.to_be_bytes())?;
            }
        }
        Ok(pos)
    }

    /// The EDNS0 OPT record from the additional section, if the message carries
    /// one. Errors if the OPT record's option list is malformed — the caller
    /// should answer FORMERR.
    pub fn edns(&self) -> Result<Option<Edns>, anyhow::Error> {
        self.additionals
            .iter()
            .find(|rr| rr.rdata.rtype == OPT_RECORD_TYPE)
            .map(Edns::from_record)
            .transpose()
    }

    /// Whether the message carries an OPT record at all, regardless of whether
    /// its options parse. Use this to decide OPT mirroring (RFC 6891 §6.1.1).
    pub fn has_edns(&self) -> bool {
        self.additionals
            .iter()
            .any(|rr| rr.rdata.rtype == OPT_RECORD_TYPE)
    }

    /// The requestor's advertised UDP payload size: the EDNS value (floored at
    /// the classic 512 per RFC 6891 §6.2.3) if present, else the classic 512.
    ///
    /// The payload size lives in the OPT CLASS field, so it is readable even
    /// when the option list is malformed; a bad option list just falls back to
    /// the safe classic size.
    pub fn udp_payload_size(&self) -> u16 {
        self.additionals
            .iter()
            .find(|rr| rr.rdata.rtype == OPT_RECORD_TYPE)
            .map(|rr| rr.class.max(CLASSIC_UDP_SIZE))
            .unwrap_or(CLASSIC_UDP_SIZE)
    }

    /// Add the OPT record to the additional section, replacing any existing one.
    /// Errors only if an option's data exceeds the 16-bit length field.
    pub fn set_edns(&mut self, edns: Edns) -> Result<(), anyhow::Error> {
        let record = edns.to_record()?;
        self.additionals
            .retain(|rr| rr.rdata.rtype != OPT_RECORD_TYPE);
        self.additionals.push(record);
        Ok(())
    }

    /// Serialize, truncating to `max_len` bytes (RFC 1035 §4.2.1). If the full
    /// message doesn't fit, the answer/authority records are dropped (the OPT
    /// record and question are kept) and TC=1 is set so the client retries over
    /// TCP. Returns the wire bytes.
    pub fn to_bytes_within(&self, max_len: usize) -> Result<Vec<u8>, anyhow::Error> {
        let mut scratch = vec![0u8; u16::MAX as usize];
        let n = self.to_bytes(&mut scratch)?;
        if n <= max_len {
            scratch.truncate(n);
            return Ok(scratch);
        }

        let mut truncated = self.clone();
        truncated.truncation = true;
        truncated.answers.clear();
        truncated.authorities.clear();
        // Keep only the OPT record — the DNS message size limit itself is
        // signalled via EDNS, so it must survive truncation.
        truncated
            .additionals
            .retain(|rr| rr.rdata.rtype == OPT_RECORD_TYPE);

        let mut out = vec![0u8; max_len.max(CLASSIC_UDP_SIZE as usize)];
        let n = truncated.to_bytes(&mut out)?;
        out.truncate(n);
        Ok(out)
    }
}

#[derive(Default)]
pub struct DnsMessageBuilder {
    id: u16,
    queries: Vec<(String, u16)>,
}

impl DnsMessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_url(mut self, url: &str, query_type: &str) -> Self {
        if let Some(q) = RecordData::to_u16(query_type) {
            self.queries.push((url.to_owned(), q));
        }
        self
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
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
                    qtype: *qt,
                    qclass: QueryClass::IN,
                })
                .collect(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(query.qtype, 1);
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
                    qtype: 6,
                    qclass: QueryClass::IN,
                }],
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
            };
            let mut buf = vec![0u8; 512];
            let n = msg.to_bytes(&mut buf).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");
            assert_eq!(parsed.opcode, opcode, "opcode {opcode:?} did not round-trip");
            // And the flags either side of it are unharmed.
            assert!(parsed.authoritive, "AA survived alongside {opcode:?}");
            assert!(!parsed.response);
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
        assert_eq!(&*one.rdata, b"\x05hello");

        let two = RecordData::from_parsed(&ParsedRecord::TXT(vec![
            b"v=spf1".to_vec(),
            b"-all".to_vec(),
        ]))
        .unwrap();
        assert_eq!(&*two.rdata, b"\x06v=spf1\x04-all");
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
        let err =
            RecordData::from_parsed(&ParsedRecord::TXT(vec![vec![b'x'; 256]])).unwrap_err();
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
        let err = RecordData::from_wire(16, b"\x09short", &unpacker).unwrap_err();
        assert!(err.to_string().contains("character-string"), "got: {err}");
    }

    #[test]
    fn test_response_roundtrip_with_answer() {
        use std::net::Ipv4Addr;

        let answer = ResourceRecord {
            name: "www.example.com.".to_string(),
            class: 1,
            ttl: 3600,
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
                qtype: 1,
                qclass: QueryClass::IN,
            }],
            answers: vec![answer],
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        assert_eq!(parsed.answers.len(), 1, "answer record must survive round-trip");
        let a = &parsed.answers[0];
        assert_eq!(a.name, "www.example.com.");
        assert_eq!(a.class, 1);
        assert_eq!(a.ttl, 3600);
        assert_eq!(a.rdata.rtype, 1);
        assert_eq!(&*a.rdata.rdata, &[192, 0, 2, 1]); // A record: 4 address octets
    }

    /// A response whose records all share the question's owner name should
    /// carry that name once, with 2-byte pointers thereafter.
    #[test]
    fn test_output_compresses_repeated_owner_names() {
        use std::net::Ipv4Addr;

        let answers: Vec<ResourceRecord> = (1..=10)
            .map(|i| ResourceRecord {
                name: "www.example.com.".to_string(),
                class: 1,
                ttl: 3600,
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
            assert_eq!(&*a.rdata.rdata, &[192, 0, 2, (i + 1) as u8]);
        }
    }

    /// Names inside NS/CNAME/SOA/MX RDATA are compressed too, and survive the
    /// round-trip — the parser resolves the pointers against the full message.
    #[test]
    fn test_output_compresses_names_inside_rdata() {
        let ns = ResourceRecord {
            name: "example.com.".to_string(),
            class: 1,
            ttl: 3600,
            rdata: RecordData::from_parsed(&ParsedRecord::NS("ns1.example.com.".to_string()))
                .unwrap(),
        };
        let mx = ResourceRecord {
            name: "example.com.".to_string(),
            class: 1,
            ttl: 3600,
            rdata: RecordData::from_parsed(&ParsedRecord::MX {
                preference: 10,
                exchange: "mail.example.com.".to_string(),
            })
            .unwrap(),
        };
        let cname = ResourceRecord {
            name: "alias.example.com.".to_string(),
            class: 1,
            ttl: 3600,
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
            class: 1,
            ttl: 3600,
            rdata: RecordData {
                rtype: 33,
                rdata: srv_rdata.clone().into_boxed_slice(),
            },
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
        assert_eq!(&*parsed.answers[0].rdata.rdata, srv_rdata.as_slice());
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
                qtype: 1,
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    #[test]
    fn test_edns_absent_defaults_to_512() {
        let msg = query_msg(1);
        assert!(msg.edns().expect("no OPT to misparse").is_none());
        assert!(!msg.has_edns());
        assert_eq!(msg.udp_payload_size(), 512);
    }

    #[test]
    fn test_edns_set_and_read() {
        let mut msg = query_msg(1);
        let mut edns = Edns::with_payload_size(4096);
        edns.do_bit = true;
        msg.set_edns(edns).expect("set_edns");

        let got = msg.edns().unwrap().expect("edns present");
        assert_eq!(got.udp_payload_size, 4096);
        assert!(got.do_bit);
        assert_eq!(got.version, 0);
        assert_eq!(msg.udp_payload_size(), 4096);

        // set_edns replaces rather than accumulates.
        msg.set_edns(Edns::with_payload_size(1232)).expect("set_edns");
        assert_eq!(
            msg.additionals
                .iter()
                .filter(|rr| rr.rdata.rtype == OPT_RECORD_TYPE)
                .count(),
            1
        );
        assert_eq!(msg.udp_payload_size(), 1232);
    }

    #[test]
    fn test_edns_survives_wire_roundtrip() {
        let mut msg = query_msg(0xABCD);
        let mut edns = Edns::with_payload_size(4096);
        edns.do_bit = true;
        msg.set_edns(edns.clone()).expect("set_edns");

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        let got = parsed.edns().unwrap().expect("edns survives round-trip");
        assert_eq!(got, edns);
    }

    #[test]
    fn test_edns_payload_size_floored_at_512() {
        // RFC 6891 §6.2.3: values below 512 are treated as 512.
        let mut msg = query_msg(1);
        msg.set_edns(Edns::with_payload_size(300)).expect("set_edns");
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

        let record = RecordData::from_wire(46, &rdata, &DNameUnpacker::new(&rdata))
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
        assert_eq!(&*record.rdata, rdata.as_slice());
    }

    #[test]
    fn test_edns_options_survive_wire_roundtrip() {
        let mut msg = query_msg(0x0F0F);
        let mut edns = Edns::with_payload_size(1232);
        edns.options = vec![
            EdnsOption {
                code: EDNS_OPTION_COOKIE,
                data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            },
            // A zero-length option is legal and must not be dropped.
            EdnsOption {
                code: EDNS_OPTION_NSID,
                data: Vec::new(),
            },
        ];
        msg.set_edns(edns.clone()).expect("set_edns");

        // 2 (code) + 2 (len) + 8 (data), then 2 + 2 + 0.
        let opt = msg
            .additionals
            .iter()
            .find(|rr| rr.rdata.rtype == OPT_RECORD_TYPE)
            .expect("OPT present");
        assert_eq!(opt.rdata.rdata.len(), 16);

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        let got = parsed.edns().unwrap().expect("edns present");
        assert_eq!(got, edns);
        assert_eq!(got.option(EDNS_OPTION_COOKIE), Some(&[1u8, 2, 3, 4, 5, 6, 7, 8][..]));
        assert_eq!(got.option(EDNS_OPTION_NSID), Some(&[][..]));
        assert_eq!(got.option(EDNS_OPTION_PADDING), None);
    }

    #[test]
    fn test_malformed_edns_options_surface_error() {
        let mut msg = query_msg(1);
        msg.set_edns(Edns::with_payload_size(1232)).expect("set_edns");
        // Option claims 8 bytes of data but supplies 2.
        let opt = msg
            .additionals
            .iter_mut()
            .find(|rr| rr.rdata.rtype == OPT_RECORD_TYPE)
            .unwrap();
        opt.rdata.rdata = Box::new([0x00, 0x0a, 0x00, 0x08, 0xde, 0xad]);

        let err = msg.edns().expect_err("truncated option must be rejected");
        assert!(err.to_string().contains("only 2 remain"), "got: {err}");
        // The payload size is still readable — it lives in the OPT CLASS field.
        assert_eq!(msg.udp_payload_size(), 1232);
        assert!(msg.has_edns());
    }

    #[test]
    fn test_extended_rcode_splits_across_header_and_opt() {
        // BADVERS is 16: 0 in the header's low 4 bits, 1 in the OPT TTL's top byte.
        let mut msg = query_msg(0x2222);
        msg.response = true;
        msg.rcode = ResponseCode::BadOptVersion;
        msg.set_edns(Edns::with_payload_size(1232)).expect("set_edns");

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
        msg.set_edns(Edns::with_payload_size(4096)).expect("set_edns");

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
                class: 1,
                ttl: 3600,
                rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(10, 0, 0, i)))
                    .unwrap(),
            });
        }
        msg.set_edns(Edns::with_payload_size(4096)).expect("set_edns");

        let bytes = msg.to_bytes_within(512).expect("to_bytes_within");
        assert!(bytes.len() <= 512, "must fit within 512, got {}", bytes.len());

        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse truncated");
        assert!(parsed.truncation, "TC bit must be set on truncation");
        assert!(parsed.answers.is_empty(), "answers dropped on truncation");
        assert!(parsed.has_edns(), "OPT record must survive truncation");
    }

    #[test]
    fn test_to_bytes_within_keeps_full_when_it_fits() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        msg.answers.push(ResourceRecord {
            name: "example.com.".to_string(),
            class: 1,
            ttl: 3600,
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
            ad: true,  // Set AD bit
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
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
            cd: true,  // Set CD bit
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
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
            ad: true,   // Set AD bit
            cd: true,   // Set CD bit
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
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
            ad: false,  // AD bit not set
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
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
            cd: false,  // CD bit not set
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
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
            recursion_ok: true,  // RA bit set
            ad: true,            // AD bit set
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
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
        let builder = DnsMessageBuilder::new()
            .with_url("example.com", "A");
        let msg = builder.build();
        
        assert!(!msg.ad, "AD bit should be false by default");
        assert!(!msg.cd, "CD bit should be false by default");
    }
}
