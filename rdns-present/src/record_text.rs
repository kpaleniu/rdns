//! One resource record as the line a zone file writes it on (RFC 1035 §5.1).
//!
//! What is written must read back as the same bytes: a signature covers RDATA
//! octet for octet, so a re-spelling that re-encodes differently turns a valid
//! RRset bogus. A record is rendered type-specifically only where that provably
//! round-trips — decided by re-encoding what was parsed and comparing the
//! bytes, so the cases need not be enumerated — otherwise in RFC 3597 §5's
//! `\# <len> <hex>` form.
//!
//! An owner name has no such fallback: it is the first field of the line and
//! this parser has no escape syntax, so an unspellable one is refused rather
//! than written as a different name.
//!
//! Every line stands on its own: owner names absolute, TTL and class stated.
//! Assembling those lines into a *file* is `rdns::zone_writer`, which needs a
//! `Zone` and is therefore not here (`TODO.md` #66a).

use std::borrow::Cow;

use rdns_core::codecs::{base64_encode, hex_encode};
use rdns_core::error::ZoneError;
use rdns_core::record_types::record_type_name;
use rdns_core::{Class, NameRef, ParsedRecord, RecordData, ResourceRecord, Ttl};

use crate::denial_wire::{base32hex_encode, bitmap_types_exact};
use crate::dnssec_time::format_dnssec_time;

/// One record as a zone-file line, from its four fields.
///
/// The fields rather than either record type, because there are two of them
/// with the same four fields in a different order — `rdns::zone::ZoneRecord` and
/// [`ResourceRecord`] — and every caller holds one or the other
/// (`TODO.md` #66a). `Ttl` and `Class` are `Copy` and the other two are
/// borrowed, so no caller allocates to call this; taking one of the two record
/// types would have made the other clone four fields to build a temporary,
/// which is exactly what `journal::write_record` used to do.
pub fn record_line(
    name: NameRef<'_>,
    ttl: Ttl,
    class: Class,
    rdata: &RecordData,
) -> Result<String, ZoneError> {
    let owner = writable_name(name);
    let class_text = class_name(class).ok_or_else(|| {
        ZoneError::invalid(format!("record {owner}: unknown class {}", class.to_u16()))
    })?;

    let (rtype, rdata) = rdata_to_string(rdata);
    Ok(format!(
        "{owner:<24} {ttl:<7} {class_text:<3} {rtype:<7} {rdata}"
    ))
}

/// The same, for a record off the wire rather than out of a zone.
///
/// What a transfer hands back and what a journal holds are `ResourceRecord`s,
/// so this is the entry point anything but `zone_to_string` wants.
pub fn resource_record_line(record: &ResourceRecord) -> Result<String, ZoneError> {
    record_line(
        record.name.as_ref(),
        record.ttl,
        record.class,
        &record.rdata,
    )
}

/// The type name and RDATA text for a stored record.
///
/// Type-specific when that is faithful, generic when it is not. "Faithful" is
/// decided by re-encoding what we parsed and comparing the bytes, so the cases
/// need not be enumerated here.
fn rdata_to_string(stored: &RecordData) -> (Cow<'static, str>, String) {
    let name = record_type_name(stored.rtype());
    let generic = (name.clone(), generic_rdata(stored));

    let Ok(parsed) = stored.parse() else {
        return generic;
    };
    match RecordData::from_parsed(&parsed) {
        Ok(reencoded) if reencoded.bytes() == stored.bytes() => {}
        _ => return generic,
    }
    match presentation_rdata(&parsed) {
        Some(text) => (name, text),
        None => generic,
    }
}

/// `\# <length> <hex>` (RFC 3597 §5) — the form that is exact for anything.
fn generic_rdata(stored: &RecordData) -> String {
    let mut out = format!("\\# {}", stored.bytes().len());
    if !stored.bytes().is_empty() {
        out.push(' ');
        for byte in stored.bytes() {
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// The type-specific text for a record, or `None` when this format cannot say
/// it unambiguously — a `<character-string>` holding bytes that are not text,
/// or a bitmap that did not parse to its end. Names are no longer among them
/// (see [`writable_name`]).
fn presentation_rdata(parsed: &ParsedRecord) -> Option<String> {
    Some(match parsed {
        ParsedRecord::A(addr) => addr.to_string(),
        ParsedRecord::AAAA(addr) => addr.to_string(),
        ParsedRecord::NS(name)
        | ParsedRecord::CNAME(name)
        | ParsedRecord::PTR(name)
        | ParsedRecord::DNAME(name) => writable_name(name.as_ref()),
        ParsedRecord::MX {
            preference,
            exchange,
        } => format!("{preference} {}", writable_name(exchange.as_ref())),
        ParsedRecord::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            // One field per line: the five timers are indistinguishable as a row
            // of bare numbers.
            let pad = " ".repeat(45);
            format!(
                "{mname} {rname} (\n\
                 {pad}{serial:<12} ; serial\n\
                 {pad}{refresh:<12} ; refresh\n\
                 {pad}{retry:<12} ; retry\n\
                 {pad}{expire:<12} ; expire\n\
                 {pad}{minimum:<12} ; minimum (negative TTL)\n\
                 {pad})",
                mname = writable_name(mname.as_ref()),
                rname = writable_name(rname.as_ref()),
            )
        }
        ParsedRecord::TXT(strings) => {
            let mut out = String::new();
            for string in strings {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push('"');
                out.push_str(&rdns_core::codecs::char_string_escaped(string));
                out.push('"');
            }
            out
        }
        ParsedRecord::SVCB {
            priority,
            target,
            params,
            ..
        } => {
            let head = format!("{priority} {}", writable_name(target.as_ref()));
            if params.is_empty() {
                head
            } else {
                format!("{head} {}", crate::svcb::present_params(params))
            }
        }
        ParsedRecord::DNSKEY {
            // The mnemonic comes from the record's own type, not from here:
            // a CDNSKEY prints the same RDATA under another name
            // (RFC 7344 §3.2).
            rtype: _,
            flags,
            protocol,
            algorithm,
            public_key,
        } => format!(
            "{flags} {protocol} {algorithm} {}",
            base64_encode(public_key)
        ),
        ParsedRecord::DS {
            rtype: _,
            key_tag,
            algorithm,
            digest_type,
            digest,
        } => format!("{key_tag} {algorithm} {digest_type} {}", hex_encode(digest)),
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
        } => format!(
            "{} {algorithm} {labels} {original_ttl} {} {} {key_tag} {} {}",
            record_type_name(*type_covered),
            format_dnssec_time(*expiration),
            format_dnssec_time(*inception),
            writable_name(signer_name.as_ref()),
            base64_encode(signature),
        ),
        ParsedRecord::NSEC {
            next_domain_name,
            type_bitmap,
        } => {
            let mut out = writable_name(next_domain_name.as_ref());
            out.push_str(&bitmap_to_string(type_bitmap)?);
            out
        }
        ParsedRecord::NSEC3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            type_bitmap,
        } => {
            // An empty salt is written `-`: the field is not optional, and no
            // hex digits at all would leave the next field in its place.
            let salt = if salt.is_empty() {
                "-".to_string()
            } else {
                hex_encode(salt)
            };
            let mut out = format!(
                "{hash_algorithm} {flags} {iterations} {salt} {}",
                base32hex_encode(next_hashed_owner)
            );
            out.push_str(&bitmap_to_string(type_bitmap)?);
            out
        }
        // No typed payload: the caller has already fallen back to generic.
        ParsedRecord::Unknown(_) => return None,
    })
}

/// A type bitmap as the list of type names an NSEC or NSEC3 line ends with, each
/// preceded by a space — or `None` if that would not read back as the same
/// bytes.
///
/// [`rdata_to_string`]'s re-encode check cannot see this: a bitmap is stored
/// verbatim, so padding or an unusual window layout survives it, and only the
/// text form drops them. Compare against the layout the parser will rebuild.
fn bitmap_to_string(bitmap: &[u8]) -> Option<String> {
    let types = bitmap_types_exact(bitmap).ok()?;
    if crate::denial_wire::build_type_bitmap(&types) != bitmap {
        return None;
    }
    Some(
        types
            .into_iter()
            .map(|rtype| format!(" {}", record_type_name(rtype)))
            .collect(),
    )
}

/// A domain name if it can be written as a bare field, `None` otherwise.
///
/// Whitespace ends a field; `;`, `"`, parentheses, `\`, `@` and `$` all mean
/// something to the parser. A name carrying one reads back as a different name.
fn writable_name(name: NameRef<'_>) -> String {
    // Total. ~~"it needs escapes this parser does not read back"~~ was true
    // while a name was presentation text: there was no spelling for a `.`
    // inside a label, and a `;` or `"` written raw came back as syntax rather
    // than as data. A `Name` escapes every one of those (RFC 1035 §5.1) and the
    // parser resolves them, so there is no name this cannot write — which is
    // the deviation D-1 named, closing from the other end.
    name.to_presentation()
}

fn class_name(class: Class) -> Option<&'static str> {
    match class {
        Class::IN => Some("IN"),
        Class::CH => Some("CH"),
        Class::HS => Some("HS"),
        _ => None,
    }
}
