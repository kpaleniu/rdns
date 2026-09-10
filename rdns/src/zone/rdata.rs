use super::parse::name_at;
use crate::denial_wire::base32hex_decode;
use crate::error::ZoneError;
use crate::record_types as rt;
use crate::utils::hex_decode;
use crate::{NameRef, ParsedRecord, RecordData, Serial};
use std::net::{Ipv4Addr, Ipv6Addr};

/// The small parse helpers below return `Result<_, String>` on purpose: they
/// produce a *detail*, and only their caller — the zone parser — knows the line
/// number to attach it to. A `ZoneError` here would have to invent one.
fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// How many days `month` (1-12) has in `year`, or `None` if that is not a
/// month. `None` and not zero: zero reads as an answer to a caller summing
/// days, which turns month 13 into a plausible epoch for a date that does not
/// exist.
fn days_in_month(month: i32, year: i32) -> Option<i32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap(year) { 29 } else { 28 }),
        _ => None,
    }
}

/// An RRSIG's inception or expiration: a bare epoch, or `YYYYMMDDHHmmSS` in UTC
/// (RFC 4034 §3.2). Every field is range-checked and the result is checked to
/// fit. The inverse is [`format_dnssec_time`].
pub(super) fn parse_dnssec_time(time_str: &str) -> Result<u32, String> {
    if let Ok(epoch) = time_str.parse::<u32>() {
        return Ok(epoch);
    }

    // Fourteen ASCII digits, established before anything is sliced: the
    // slicing below is by byte, so a 14-byte string holding a multi-byte
    // character would panic on a boundary rather than fail to parse.
    if time_str.len() != 14 || !time_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "Invalid DNSSEC time format: {time_str} (want a bare epoch or 14 digits)"
        ));
    }

    let year = time_str[0..4].parse::<i32>().map_err(|e| e.to_string())?;
    let month = time_str[4..6].parse::<i32>().map_err(|e| e.to_string())?;
    let day = time_str[6..8].parse::<i32>().map_err(|e| e.to_string())?;
    let hour = time_str[8..10].parse::<i32>().map_err(|e| e.to_string())?;
    let min = time_str[10..12].parse::<i32>().map_err(|e| e.to_string())?;
    let sec = time_str[12..14].parse::<i32>().map_err(|e| e.to_string())?;

    // A year before 1970 makes `total_days` negative, which widens into the far
    // future rather than failing.
    if year < 1970 {
        return Err(format!("{time_str}: year {year} is before the POSIX epoch"));
    }
    let days_this_month = days_in_month(month, year)
        .ok_or_else(|| format!("{time_str}: month {month} is not a month"))?;
    if !(1..=days_this_month).contains(&day) {
        return Err(format!(
            "{time_str}: day {day} is not a day of month {month}"
        ));
    }
    // Seconds stop at 59: this converts to POSIX time, which has no leap
    // seconds, so there is no instant for a `:60` to name.
    if hour > 23 || min > 59 || sec > 59 {
        return Err(format!(
            "{time_str}: {hour:02}:{min:02}:{sec:02} is not a time"
        ));
    }

    let mut total_days = 0;
    for y in 1970..year {
        total_days += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        // Cannot be `None`: `month` is 1-12 by the check above, so `m` is 1-11.
        total_days += days_in_month(m, year).unwrap_or(0);
    }
    total_days += day - 1;

    let epoch = total_days as i64 * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    // Checked, not `as`: one second past the field truncates to 0, turning a
    // signature dated the far future into one that expired in 1970.
    u32::try_from(epoch)
        .map_err(|_| format!("{time_str} is outside the range a 32-bit DNSSEC timestamp can hold"))
}

/// The `YYYYMMDDHHmmSS` form an RRSIG's times are written in, UTC
/// (RFC 4034 §3.2). The inverse of [`parse_dnssec_time`].
///
/// The parser also accepts a bare epoch and writing that would be shorter, but
/// nothing else in the ecosystem does.
pub(crate) fn format_dnssec_time(epoch: u32) -> String {
    let mut days = (epoch / 86400) as i32;
    let seconds = epoch % 86400;

    let mut year = 1970;
    loop {
        let in_year = if is_leap(year) { 366 } else { 365 };
        if days < in_year {
            break;
        }
        days -= in_year;
        year += 1;
    }

    // Bounded at December rather than trusting the day count to run out: a
    // month contributing zero days would spin until `month` overflowed.
    let mut month = 1;
    while month < 12 {
        let Some(in_month) = days_in_month(month, year) else {
            break;
        };
        if days < in_month {
            break;
        }
        days -= in_month;
        month += 1;
    }

    format!(
        "{year:04}{month:02}{:02}{:02}{:02}{:02}",
        days + 1,
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

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
    rdata: String,
    fields: &[&str],
    text_fields: &[String],
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
                .map(|t| crate::utils::char_string_decode(t))
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
        "DNSKEY" => {
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
                flags,
                protocol,
                algorithm,
                public_key,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("DNSKEY record: {e}")))?
        }
        "DS" => {
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
