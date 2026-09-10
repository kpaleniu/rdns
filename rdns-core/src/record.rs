//! Resource records: the typed view of RDATA, the record itself, and reading
//! one off the wire.

use crate::codes::{Class, Rtype, Serial, Ttl};
use crate::dname::{DName, DNameUnpacker, TryFromBytes, TryUnpackFromBytes};
use crate::edns::{Edns, OPT_RECORD_TYPE};
use crate::error::WireError;
use crate::name::Name;
use crate::record_data::RecordData;
use crate::record_types;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Typed, fully-parsed view of a record's data: produced on demand by
/// [`RecordData::parse`], consumed by [`RecordData::from_parsed`].
///
/// Not what we store — the raw-bytes form avoids keeping these `String`s and
/// `Vec`s resident per cached record. Domain names here are fully-qualified and
/// uncompressed.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedRecord {
    A(Ipv4Addr),
    NS(Name),
    CNAME(Name),
    SOA {
        mname: Name,
        rname: Name,
        /// The zone's version. See [`Serial`] — the comparison is RFC 1982's,
        /// not `>`.
        serial: Serial,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
    PTR(Name),
    /// The `<target>` a whole subtree is redirected to (RFC 6672 §2.1). One
    /// domain name, and the substitution applies to names *below* the owner.
    DNAME(Name),
    /// A service binding: how to reach a service rather than only where its
    /// name points (RFC 9460 §2).
    ///
    /// One arm for two type codes. The HTTPS RR "shares the same encoding,
    /// format, and high-level semantics" (§6) and differs only in how its owner
    /// name is built (§9.1), which is not this layer's business — so `rtype`
    /// says which of the two it is. It cannot disagree with the enclosing
    /// [`RecordData`]: `ParsedRecord::decode` is handed that rtype and
    /// [`RecordData::from_parsed`] takes this one back. Not a link: `decode` is
    /// `pub(crate)`, and rustdoc refuses one from a public page to a private
    /// item.
    SVCB {
        rtype: Rtype,
        /// 0 is AliasMode, anything else ServiceMode; lower is preferred
        /// (§2.4.1).
        priority: u16,
        /// The alias target, or the alternative endpoint. `"."` is special
        /// both ways (§2.5): in ServiceMode it means the owner name, and in
        /// AliasMode that the service does not exist.
        target: Name,
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
        exchange: Name,
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
        signer_name: Name,
        signature: Vec<u8>,
    },
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    NSEC {
        next_domain_name: Name,
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
            record_types::A => {
                let addr: [u8; 4] = rdata.try_into()?;
                Ok(ParsedRecord::A(Ipv4Addr::from(addr)))
            }
            record_types::NS => {
                let (nsname, _) = Name::from_wire_in(rdata, unpacker)?;
                Ok(ParsedRecord::NS(nsname))
            }
            record_types::CNAME => {
                let (cname, _) = Name::from_wire_in(rdata, unpacker)?;
                Ok(ParsedRecord::CNAME(cname))
            }
            record_types::SOA => {
                let (mname, rest) = Name::from_wire_in(rdata, unpacker)?;
                let (rname, rest) = Name::from_wire_in(rest, unpacker)?;
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
            record_types::PTR => {
                let (ptrdname, _) = Name::from_wire_in(rdata, unpacker)?;
                Ok(ParsedRecord::PTR(ptrdname))
            }
            // Read through the unpacker like any other name even though
            // RFC 6672 §2.5 forbids sending <target> compressed: refusing a
            // pointer here would make us unable to read what a
            // non-conforming server sent, and the rule is on the writer.
            record_types::DNAME => {
                let (target, _) = Name::from_wire_in(rdata, unpacker)?;
                Ok(ParsedRecord::DNAME(target))
            }
            // Same forgiveness as DNAME about the uncompressed TargetName
            // (RFC 9460 §2.2): the rule binds the writer.
            record_types::SVCB | record_types::HTTPS => {
                let (priority, rest) = read_be!(u16, rdata);
                let (target, rest) = Name::from_wire_in(rest, unpacker)?;
                Ok(ParsedRecord::SVCB {
                    rtype: record_type,
                    priority,
                    target,
                    params: decode_svc_params(rest)?,
                })
            }
            record_types::MX => {
                let (preference, rest) = read_be!(u16, rdata);
                let (exchange, _) = Name::from_wire_in(rest, unpacker)?;
                Ok(ParsedRecord::MX {
                    preference,
                    exchange,
                })
            }
            record_types::TXT => {
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
            record_types::AAAA => {
                let addr: [u8; 16] = rdata.try_into()?;
                Ok(ParsedRecord::AAAA(Ipv6Addr::from(addr)))
            }
            record_types::DS => {
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
            record_types::RRSIG => {
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
                let (signer_name, rest) = Name::from_wire_in(rest, unpacker)?;
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
            record_types::NSEC => {
                let (next_domain_name, rest) = Name::from_wire_in(rdata, unpacker)?;
                let type_bitmap = rest.to_vec();
                Ok(ParsedRecord::NSEC {
                    next_domain_name,
                    type_bitmap,
                })
            }
            record_types::DNSKEY => {
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
            record_types::NSEC3 => {
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
            ParsedRecord::A(addr) => (record_types::A, addr.octets().to_vec()),
            ParsedRecord::AAAA(addr) => (record_types::AAAA, addr.octets().to_vec()),
            ParsedRecord::NS(name) => (record_types::NS, name.as_ref().as_wire().to_vec()),
            ParsedRecord::CNAME(name) => (record_types::CNAME, name.as_ref().as_wire().to_vec()),
            ParsedRecord::PTR(name) => (record_types::PTR, name.as_ref().as_wire().to_vec()),
            ParsedRecord::DNAME(name) => (record_types::DNAME, name.as_ref().as_wire().to_vec()),
            ParsedRecord::SVCB {
                rtype,
                priority,
                target,
                params,
            } => {
                let mut v = priority.to_be_bytes().to_vec();
                v.extend_from_slice(target.as_ref().as_wire());
                v.extend_from_slice(&encode_svc_params(params)?);
                (*rtype, v)
            }
            ParsedRecord::MX {
                preference,
                exchange,
            } => {
                let mut v = preference.to_be_bytes().to_vec();
                v.extend_from_slice(exchange.as_ref().as_wire());
                (record_types::MX, v)
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
                (record_types::TXT, v)
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
                let mut v = mname.as_ref().as_wire().to_vec();
                v.extend_from_slice(rname.as_ref().as_wire());
                v.extend_from_slice(&serial.to_u32().to_be_bytes());
                v.extend_from_slice(&refresh.to_be_bytes());
                v.extend_from_slice(&retry.to_be_bytes());
                v.extend_from_slice(&expire.to_be_bytes());
                v.extend_from_slice(&minimum.to_be_bytes());
                (record_types::SOA, v)
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
                (record_types::DNSKEY, v)
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
                v.extend_from_slice(signer_name.as_ref().as_wire());
                v.extend_from_slice(signature);
                (record_types::RRSIG, v)
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
                (record_types::DS, v)
            }
            ParsedRecord::NSEC {
                next_domain_name,
                type_bitmap,
            } => {
                let mut v = next_domain_name.as_ref().as_wire().to_vec();
                v.extend_from_slice(type_bitmap);
                (record_types::NSEC, v)
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
                (record_types::NSEC3, v)
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
    pub name: Name,
    /// The class this record is in. See [`Class`].
    pub class: Class,
    /// How long this record may be cached. See [`Ttl`].
    pub ttl: Ttl,
    pub rdata: RecordData,
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
            name: Name::from_dname(parts.name, unpacker)?,
            class: Class::new(parts.class),
            ttl: Ttl::from_wire(parts.ttl_bits),
            rdata: RecordData::from_wire(parts.rtype, parts.rdata, unpacker)?,
        })
    }
}

/// One record of the additional section: an ordinary record, or the OPT
/// pseudo-record it is not.
pub(crate) enum Additional {
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
    pub(crate) fn try_from_bytes<'a>(
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
            Additional::Opt(Edns::from_opt(parts.class, flags, parts.rdata), flags),
            rest,
        ))
    }
}
