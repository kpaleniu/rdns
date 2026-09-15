//! One record's RDATA, built from the presentation fields a zone file line split
//! into.
//!
//! The membership rule is a single record's own data: this module never sees the
//! zone, the owner name's neighbours, or another record. It takes the fields
//! after TTL, class and type and produces a [`crate::RecordData`] — through that
//! type's checking constructors, so a malformed RDATA is refused rather than
//! stored (`CLAUDE.md` §17).
//!
//! Also the two DNSSEC time conversions, which are here rather than in a date
//! utility because RFC 4034 §3.1.5's `YYYYMMDDHHmmSS` is a presentation format
//! and the RRSIG fields that use it are the only reason the tree needs one.
//!
//! The generic `\#` form (RFC 3597) is here too: it is still a record's RDATA,
//! just spelled as a length and hex rather than as fields.

use super::parse::name_at;
use crate::codecs::hex_decode;
use crate::denial_wire::base32hex_decode;
use crate::error::ZoneError;
use crate::record_types as rt;
use crate::{NameRef, ParsedRecord, RecordData, Serial};
use rdns_present::dnssec_time::parse_dnssec_time;
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};

/// The type bitmap for a list of type names, as an NSEC or NSEC3 line writes
/// them.
///
/// An unrecognized name is an error, not a silent omission: dropping one turns
/// an NSEC denying six types into one denying five. `TYPEnnn` (RFC 3597 §5)
/// gives every type a spelling, so there is no case where dropping is better.
fn construct_type_bitmap(types: &[String]) -> Result<Vec<u8>, String> {
    let mut codes = Vec::with_capacity(types.len());
    for name in types {
        let code = crate::record_types::record_type_name_to_code(&name.to_uppercase())
            .ok_or_else(|| format!("unknown record type {name:?} in type bitmap"))?;
        codes.push(code);
    }
    codes.sort_unstable();
    codes.dedup();
    Ok(crate::denial_wire::build_type_bitmap(&codes))
}

/// Read `\# <length> <hex>` (RFC 3597 §5) into stored form.
///
/// The stated length is checked against the digits rather than trusted, and a
/// known type is parsed once to reject RDATA that is not that type: a malformed
/// record fails the load rather than waiting to fail a query.
pub(super) fn parse_generic_rdata(
    record_type: &str,
    fields: &[&str],
) -> Result<RecordData, String> {
    let rtype = crate::record_types::record_type_name_to_code(record_type)
        .ok_or_else(|| format!("unknown record type {record_type:?}"))?;

    let Some((length, hex)) = fields.split_first() else {
        return Err("generic rdata needs a length after '\\#'".to_string());
    };
    let length: usize = length
        .parse()
        .map_err(|e| format!("invalid generic rdata length {length:?}: {e}"))?;

    let bytes = hex_decode(&hex.concat()).map_err(|e| format!("invalid generic rdata: {e}"))?;
    if bytes.len() != length {
        return Err(format!(
            "generic rdata says {length} bytes but carries {}",
            bytes.len()
        ));
    }

    // `RecordData::new` is the check: a type with no parser reads back as
    // `Unknown`, so it only rejects a known type whose bytes are not that type.
    RecordData::new(rtype, bytes)
        .map_err(|e| format!("generic rdata is not valid {record_type}: {e}"))
}

/// The `SvcPriority` and `TargetName` an SVCB or HTTPS record opens with, and
/// the `key=value` fields that follow them (RFC 9460 §2.1).
fn split_svcb_head<'a>(
    record_type: &str,
    fields: &'a [&'a str],
    ln: usize,
) -> Result<(u16, String, &'a [&'a str]), ZoneError> {
    let [priority, target, rest @ ..] = fields else {
        return Err(ZoneError::syntax(
            ln,
            format!("a {record_type} record needs a priority and a target name"),
        ));
    };
    let priority = priority.parse::<u16>().map_err(|e| {
        ZoneError::syntax(
            ln,
            format!("the {record_type} priority {priority:?} is not a number 0-65535: {e}"),
        )
    })?;
    Ok((priority, (*target).to_string(), rest))
}

/// The RDATA half of a zone-file line: everything after the owner name, TTL,
/// class and type have been read off it. Pure, unlike [`parse_into`], which
/// mutates parser state.
///
/// Three views of the fields: `rdata` joined by a space (what every type but TXT
/// wants), `fields` unquoted, and `text_fields` still quoted — a TXT RR is a
/// sequence of character-strings and the quotes say where each ends
/// (RFC 1035 §3.3.14).
pub(super) fn rdata_from_fields(
    record_type: &str,
    rdata: Cow<'_, str>,
    fields: &[&str],
    text_fields: &[Cow<'_, str>],
    origin: NameRef<'_>,
    ln: usize,
) -> Result<RecordData, ZoneError> {
    Ok(match record_type {
        "A" => {
            let addr = rdata
                .parse::<Ipv4Addr>()
                .map_err(|e| ZoneError::syntax(ln, format!("invalid A address {rdata:?}: {e}")))?;
            RecordData::from_parsed(&ParsedRecord::A(addr))
                .map_err(|e| ZoneError::syntax(ln, format!("A record: {e}")))?
        }
        "AAAA" => {
            let addr = rdata.parse::<Ipv6Addr>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid AAAA address {rdata:?}: {e}"))
            })?;
            RecordData::from_parsed(&ParsedRecord::AAAA(addr))
                .map_err(|e| ZoneError::syntax(ln, format!("AAAA record: {e}")))?
        }
        "NS" => RecordData::from_parsed(&ParsedRecord::NS(name_at(&rdata, origin, ln)?))
            .map_err(|e| ZoneError::syntax(ln, format!("NS record: {e}")))?,
        "CNAME" => RecordData::from_parsed(&ParsedRecord::CNAME(name_at(&rdata, origin, ln)?))
            .map_err(|e| ZoneError::syntax(ln, format!("CNAME record: {e}")))?,
        "MX" => {
            let mx_parts: Vec<&str> = rdata.split_whitespace().collect();
            if mx_parts.len() < 2 {
                return Err(ZoneError::syntax(
                    ln,
                    format!("MX record needs preference and exchange, got {:?}", rdata),
                ));
            }
            let preference = mx_parts[0].parse::<u16>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid MX preference {:?}: {e}", mx_parts[0]))
            })?;
            RecordData::from_parsed(&ParsedRecord::MX {
                preference,
                exchange: name_at(&mx_parts[1..].join(" "), origin, ln)?,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("MX record: {e}")))?
        }
        "TXT" => {
            // Every field after the type is one `<character-string>`
            // (RFC 1035 §3.3.14): `"a b" c` is two, `a b c` is three. The
            // 255-byte ceiling is the encoder's, for every caller.
            let strings: Vec<Vec<u8>> = text_fields
                .iter()
                .map(|t| crate::codecs::char_string_decode(t))
                .collect::<Result<_, _>>()
                .map_err(|e| ZoneError::syntax(ln, format!("TXT record: {e}")))?;
            if strings.is_empty() {
                return Err(ZoneError::syntax(ln, "TXT record has no text"));
            }
            RecordData::from_parsed(&ParsedRecord::TXT(strings))
                .map_err(|e| ZoneError::syntax(ln, format!("TXT record: {e}")))?
        }
        "PTR" => RecordData::from_parsed(&ParsedRecord::PTR(name_at(&rdata, origin, ln)?))
            .map_err(|e| ZoneError::syntax(ln, format!("PTR record: {e}")))?,
        "DNAME" => RecordData::from_parsed(&ParsedRecord::DNAME(name_at(&rdata, origin, ln)?))
            .map_err(|e| ZoneError::syntax(ln, format!("DNAME record: {e}")))?,
        // One arm for two type codes: "the same encoding, format, and
        // high-level semantics" (RFC 9460 §6). Only the owner name differs
        // between them, and that is the caller's (§9.1).
        "SVCB" | "HTTPS" => {
            let (priority, target, rest) = split_svcb_head(record_type, fields, ln)?;
            let target = name_at(&target, origin, ln)?;
            let params = crate::svcb::parse_params(rest, ln)?;
            // "In AliasMode, recipients MUST ignore any SvcParams that are
            // present. Zone-file parsers MAY emit a warning" (§2.4.2). Refused
            // rather than warned: a parameter that is ignored is a setting the
            // operator believes is in force and is not (`CLAUDE.md` §15).
            if priority == 0 && !params.is_empty() {
                return Err(ZoneError::syntax(
                    ln,
                    format!(
                        "an AliasMode {record_type} (priority 0) may not carry SvcParams — \
                         RFC 9460 §2.4.2 says recipients must ignore them, so writing one \
                         here means it does nothing"
                    ),
                ));
            }
            let rtype = if record_type == "SVCB" {
                rt::SVCB
            } else {
                rt::HTTPS
            };
            RecordData::from_parsed(&ParsedRecord::SVCB {
                rtype,
                priority,
                target,
                params,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("{record_type} record: {e}")))?
        }
        "SOA" => {
            let soa_parts: Vec<&str> = rdata.split_whitespace().collect();
            if soa_parts.len() < 7 {
                return Err(ZoneError::syntax(
                    ln,
                    format!("SOA record needs 7 fields, got {}", soa_parts.len()),
                ));
            }
            let serial = soa_parts[2].parse::<Serial>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid SOA serial {:?}: {e}", soa_parts[2]))
            })?;
            let refresh = soa_parts[3].parse::<i32>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid SOA refresh {:?}: {e}", soa_parts[3]))
            })?;
            let retry = soa_parts[4].parse::<i32>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid SOA retry {:?}: {e}", soa_parts[4]))
            })?;
            let expire = soa_parts[5].parse::<i32>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid SOA expire {:?}: {e}", soa_parts[5]))
            })?;
            let minimum = soa_parts[6].parse::<u32>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid SOA minimum {:?}: {e}", soa_parts[6]))
            })?;
            RecordData::from_parsed(&ParsedRecord::SOA {
                mname: name_at(soa_parts[0], origin, ln)?,
                rname: name_at(soa_parts[1], origin, ln)?,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("SOA record: {e}")))?
        }
        "DNSKEY" | "CDNSKEY" => {
            let key_parts = fields;
            if key_parts.len() < 4 {
                return Err(ZoneError::syntax(
                    ln,
                    format!("DNSKEY record needs 4 fields, got {}", key_parts.len()),
                ));
            }
            let flags = key_parts[0].parse::<u16>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid DNSKEY flags {:?}: {e}", key_parts[0]))
            })?;
            let protocol = key_parts[1].parse::<u8>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid DNSKEY protocol {:?}: {e}", key_parts[1]),
                )
            })?;
            let algorithm = key_parts[2].parse::<u8>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid DNSKEY algorithm {:?}: {e}", key_parts[2]),
                )
            })?;
            let b64_key = key_parts[3..].join("");
            let public_key = base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &b64_key)
                .map_err(|e| ZoneError::syntax(ln, format!("invalid DNSKEY base64 key: {e}")))?;
            RecordData::from_parsed(&ParsedRecord::DNSKEY {
                // Which of the two codes the operator wrote. `kind` is the
                // mnemonic from the line, so this cannot drift from it.
                rtype: if record_type == "CDNSKEY" {
                    crate::record_types::CDNSKEY
                } else {
                    crate::record_types::DNSKEY
                },
                flags,
                protocol,
                algorithm,
                public_key,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("DNSKEY record: {e}")))?
        }
        "DS" | "CDS" => {
            let ds_parts = fields;
            if ds_parts.len() < 4 {
                return Err(ZoneError::syntax(
                    ln,
                    format!("DS record needs 4 fields, got {}", ds_parts.len()),
                ));
            }
            let key_tag = ds_parts[0].parse::<u16>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid DS key tag {:?}: {e}", ds_parts[0]))
            })?;
            let algorithm = ds_parts[1].parse::<u8>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid DS algorithm {:?}: {e}", ds_parts[1]))
            })?;
            let digest_type = ds_parts[2].parse::<u8>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid DS digest type {:?}: {e}", ds_parts[2]))
            })?;
            let hex_digest = ds_parts[3..].join("");
            let digest = hex_decode(&hex_digest)
                .map_err(|e| ZoneError::syntax(ln, format!("invalid DS digest: {e}")))?;
            RecordData::from_parsed(&ParsedRecord::DS {
                rtype: if record_type == "CDS" {
                    crate::record_types::CDS
                } else {
                    crate::record_types::DS
                },
                key_tag,
                algorithm,
                digest_type,
                digest,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("DS record: {e}")))?
        }
        "RRSIG" => {
            let rrsig_parts = fields;
            if rrsig_parts.len() < 9 {
                return Err(ZoneError::syntax(
                    ln,
                    format!("RRSIG record needs 9 fields, got {}", rrsig_parts.len()),
                ));
            }
            let type_covered = crate::record_types::record_type_name_to_code(rrsig_parts[0])
                .ok_or_else(|| {
                    ZoneError::syntax(
                        ln,
                        format!("unknown RRSIG type covered {:?}", rrsig_parts[0]),
                    )
                })?;
            let algorithm = rrsig_parts[1].parse::<u8>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG algorithm {:?}: {e}", rrsig_parts[1]),
                )
            })?;
            let labels = rrsig_parts[2].parse::<u8>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG labels {:?}: {e}", rrsig_parts[2]),
                )
            })?;
            let original_ttl = rrsig_parts[3].parse::<u32>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG original TTL {:?}: {e}", rrsig_parts[3]),
                )
            })?;
            let expiration = parse_dnssec_time(rrsig_parts[4]).map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG expiration {:?}: {e}", rrsig_parts[4]),
                )
            })?;
            let inception = parse_dnssec_time(rrsig_parts[5]).map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG inception {:?}: {e}", rrsig_parts[5]),
                )
            })?;
            let key_tag = rrsig_parts[6].parse::<u16>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG key tag {:?}: {e}", rrsig_parts[6]),
                )
            })?;
            let signer_name = name_at(rrsig_parts[7], origin, ln)?;
            let b64_sig = rrsig_parts[8..].join("");
            let signature = base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &b64_sig)
                .map_err(|e| {
                    ZoneError::syntax(ln, format!("invalid RRSIG base64 signature: {e}"))
                })?;
            RecordData::from_parsed(&ParsedRecord::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name,
                signature,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("RRSIG record: {e}")))?
        }
        "NSEC" => {
            let nsec_parts = fields;
            if nsec_parts.len() < 2 {
                return Err(ZoneError::syntax(
                    ln,
                    format!(
                        "NSEC record needs next domain and at least one type, got {}",
                        nsec_parts.len()
                    ),
                ));
            }
            let next_domain_name = name_at(nsec_parts[0], origin, ln)?;
            let type_names: Vec<String> = nsec_parts[1..].iter().map(|s| s.to_string()).collect();
            let type_bitmap = construct_type_bitmap(&type_names)
                .map_err(|e| ZoneError::syntax(ln, format!("NSEC record: {e}")))?;
            RecordData::from_parsed(&ParsedRecord::NSEC {
                next_domain_name,
                type_bitmap,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("NSEC record: {e}")))?
        }
        "NSEC3" => {
            let nsec3_parts = fields;
            if nsec3_parts.len() < 5 {
                return Err(ZoneError::syntax(
                    ln,
                    format!(
                        "NSEC3 record needs at least 5 fields, got {}",
                        nsec3_parts.len()
                    ),
                ));
            }
            let hash_algorithm = nsec3_parts[0].parse::<u8>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid NSEC3 hash algorithm {:?}: {e}", nsec3_parts[0]),
                )
            })?;
            let flags = nsec3_parts[1].parse::<u8>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid NSEC3 flags {:?}: {e}", nsec3_parts[1]))
            })?;
            let iterations = nsec3_parts[2].parse::<u16>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid NSEC3 iterations {:?}: {e}", nsec3_parts[2]),
                )
            })?;
            let salt_str = nsec3_parts[3];
            let salt = if salt_str == "-" {
                Vec::new()
            } else {
                hex_decode(salt_str).map_err(|e| {
                    ZoneError::syntax(ln, format!("invalid NSEC3 salt {:?}: {e}", salt_str))
                })?
            };
            // `denial_wire`'s decoder, not a second one: the copy that used to
            // live here folded case with `str::to_uppercase`, which is the
            // Unicode fold RFC 4343 forbids (`TODO.md` #26b).
            let next_hashed_owner = base32hex_decode(nsec3_parts[4]).map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid NSEC3 next hashed owner {:?}: {e}", nsec3_parts[4]),
                )
            })?;
            let type_names: Vec<String> = nsec3_parts[5..].iter().map(|s| s.to_string()).collect();
            let type_bitmap = construct_type_bitmap(&type_names)
                .map_err(|e| ZoneError::syntax(ln, format!("NSEC3 record: {e}")))?;
            RecordData::from_parsed(&ParsedRecord::NSEC3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmap,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("NSEC3 record: {e}")))?
        }
        other => {
            return Err(ZoneError::syntax(
                ln,
                format!("unsupported record type {other:?}"),
            ));
        }
    })
}
