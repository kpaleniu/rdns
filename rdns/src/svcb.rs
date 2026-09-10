//! SvcParams in presentation form: RFC 9460 §2.1 and §7.
//!
//! The wire form is [`rdns_core`]'s — a key, a length and opaque octets, with
//! the ordering rule. What lives here is the *zone-file* half, which is the
//! only place a key's value has a shape: `alpn="h2,h3"` is a comma-separated
//! list of length-prefixed strings, `port=53` is two octets, `ipv4hint` is four
//! octets per address. One module rather than one in the parser and one in the
//! writer, because a value this reads back differently from how it writes it is
//! a record that changes meaning on a reload (`CLAUDE.md` §7).
//!
//! Keys this library has no shape for round-trip as `keyNNNNN` with
//! character-string escaping, which is what RFC 9460 §2.1 asks for and what
//! lets a zone carry a parameter registered after this code was written.

use crate::error::ZoneError;
use crate::utils::{base64_encode, char_string_decode, char_string_escaped};
use std::borrow::Cow;
use std::net::{Ipv4Addr, Ipv6Addr};

use svc_param_keys as key;

/// SvcParamKeys that have a name (RFC 9460 §14.3.2). Everything else is
/// `keyNNNNN`, which is why this is a handful of constants and not an enum.
pub mod svc_param_keys {
    /// Keys a client must understand to use the record at all (§8).
    pub const MANDATORY: u16 = 0;
    /// Application-Layer Protocol Negotiation ids — how `h3` is advertised.
    pub const ALPN: u16 = 1;
    /// Present and empty; the scheme's default ALPN is not supported (§7.1).
    pub const NO_DEFAULT_ALPN: u16 = 2;
    pub const PORT: u16 = 3;
    pub const IPV4HINT: u16 = 4;
    /// Reserved in RFC 9460 for Encrypted ClientHello, which is why this
    /// library carries the name but no value format for it.
    pub const ECH: u16 = 5;
    pub const IPV6HINT: u16 = 6;
}

/// The name of a SvcParamKey, or its `keyNNNNN` form (RFC 9460 §2.1).
///
/// Always a name [`svc_param_key_from_name`] reads back, which is the same
/// contract [`crate::utils::record_type_name`] has with its inverse.
pub fn svc_param_key_name(key: u16) -> Cow<'static, str> {
    let known = match key {
        svc_param_keys::MANDATORY => "mandatory",
        svc_param_keys::ALPN => "alpn",
        svc_param_keys::NO_DEFAULT_ALPN => "no-default-alpn",
        svc_param_keys::PORT => "port",
        svc_param_keys::IPV4HINT => "ipv4hint",
        svc_param_keys::ECH => "ech",
        svc_param_keys::IPV6HINT => "ipv6hint",
        other => return Cow::Owned(format!("key{other}")),
    };
    Cow::Borrowed(known)
}

/// The inverse. `keyNNNNN` is accepted for any key at all.
///
/// RFC 9460 §2.1 spells the generic form `key65535` with no leading zeros and
/// requires the value to fit a `u16`, so `key65536` and `key0001` are not keys.
pub fn svc_param_key_from_name(name: &str) -> Option<u16> {
    match name {
        "mandatory" => Some(svc_param_keys::MANDATORY),
        "alpn" => Some(svc_param_keys::ALPN),
        "no-default-alpn" => Some(svc_param_keys::NO_DEFAULT_ALPN),
        "port" => Some(svc_param_keys::PORT),
        "ipv4hint" => Some(svc_param_keys::IPV4HINT),
        "ech" => Some(svc_param_keys::ECH),
        "ipv6hint" => Some(svc_param_keys::IPV6HINT),
        other => {
            let digits = other.strip_prefix("key")?;
            // "0" is `key0`, but `key0001` is not a spelling of it: the writer
            // never emits a leading zero, so accepting one would break the
            // round trip this pair promises.
            if digits.len() > 1 && digits.starts_with('0') {
                return None;
            }
            digits.parse::<u16>().ok()
        }
    }
}

/// Parse the `key=value` tail of an SVCB or HTTPS record.
///
/// Returned unsorted-safe: [`rdns_core::ParsedRecord`]'s encoder puts the pairs
/// in the strictly increasing order the wire needs (RFC 9460 §2.2), so an
/// operator may write them in any order. A repeated key is refused *here*
/// rather than there, because here is where the line number is.
pub(crate) fn parse_params(fields: &[&str], ln: usize) -> Result<Vec<(u16, Vec<u8>)>, ZoneError> {
    let mut params: Vec<(u16, Vec<u8>)> = Vec::new();
    for field in fields {
        let (name, value) = match field.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            // "no-default-alpn" and friends: the key alone, no "=" at all.
            None => (*field, None),
        };
        let Some(code) = svc_param_key_from_name(name) else {
            return Err(ZoneError::syntax(
                ln,
                format!(
                    "{name:?} is not an SvcParamKey — RFC 9460 §2.1 names seven, and anything \
                     else is written keyNNNNN"
                ),
            ));
        };
        if params.iter().any(|(seen, _)| *seen == code) {
            return Err(ZoneError::syntax(
                ln,
                format!(
                    "SvcParamKey {name:?} appears twice — RFC 9460 §2.2 requires strictly \
                     increasing keys on the wire, so there is nowhere to put a second value"
                ),
            ));
        }
        // The *spelling* picks the value format, not the number. `alpn=h2,h3`
        // is a comma-separated list; `key1="\002h2"` is the same key written
        // opaquely and its value is raw octets. RFC 9460 §7.1.1 says so by
        // example: an implementation may refuse `,` and `\` in ALPN ids
        // "relying on the opaque key format (e.g., key1=\002h2) in the event
        // that these characters are needed" — which only works if `key1` and
        // `alpn` parse differently.
        let written_by_name = svc_param_key_name(code) == name;
        params.push((code, encode_value(code, name, value, written_by_name, ln)?));
    }
    Ok(params)
}

/// One key's presentation value as the octets that go on the wire.
///
/// `written_by_name` is false when the operator spelled the key `keyNNNNN`,
/// which asks for the opaque format whatever the key means.
fn encode_value(
    code: u16,
    name: &str,
    value: Option<&str>,
    written_by_name: bool,
    ln: usize,
) -> Result<Vec<u8>, ZoneError> {
    let syntax = |what: String| ZoneError::syntax(ln, what);
    if !written_by_name {
        return char_string_decode(value.unwrap_or_default())
            .map_err(|e| syntax(format!("the {name:?} value: {e}")));
    }

    // Four keys "MUST NOT contain escape sequences" so that parsing stays
    // simple (RFC 9460 §7.2, §7.3 and §8). Taking them at their word means a
    // stray backslash is a syntax error rather than a silently different value.
    let plain = |value: Option<&str>| -> Result<String, ZoneError> {
        let text = value.unwrap_or_default();
        if text.contains('\\') {
            return Err(syntax(format!(
                "the {name:?} value may not contain escape sequences (RFC 9460 §7.2, §7.3, §8)"
            )));
        }
        Ok(text.to_string())
    };

    match code {
        key::NO_DEFAULT_ALPN => {
            // "The presentation and wire-format values MUST be empty" (§7.1.1).
            if value.is_some_and(|v| !v.is_empty()) {
                return Err(syntax(format!("{name:?} takes no value (RFC 9460 §7.1.1)")));
            }
            Ok(Vec::new())
        }
        key::MANDATORY => {
            let text = plain(value)?;
            let mut codes = Vec::new();
            for item in comma_list(&text, name, ln)? {
                let Some(listed) = svc_param_key_from_name(&item) else {
                    return Err(syntax(format!(
                        "{item:?} in {name:?} is not an SvcParamKey"
                    )));
                };
                // "This SvcParamKey is always automatically mandatory and MUST
                // NOT appear in its own value-list" (§8).
                if listed == key::MANDATORY {
                    return Err(syntax(
                        "\"mandatory\" may not list itself — it is always mandatory \
                         (RFC 9460 §8)"
                            .to_string(),
                    ));
                }
                if codes.contains(&listed) {
                    return Err(syntax(format!("{item:?} is listed twice in {name:?}")));
                }
                codes.push(listed);
            }
            if codes.is_empty() {
                return Err(syntax(format!("{name:?} needs at least one key")));
            }
            // "concatenated in strictly increasing numeric order" (§8) — the
            // operator's order is not information, the same way the SvcParams'
            // own order is not.
            codes.sort_unstable();
            Ok(codes.iter().flat_map(|c| c.to_be_bytes()).collect())
        }
        key::ALPN => {
            let text = value.unwrap_or_default();
            let mut out = Vec::new();
            for item in comma_list(text, name, ln)? {
                let bytes = char_string_decode(&item)
                    .map_err(|e| syntax(format!("an {name:?} id: {e}")))?;
                let len = u8::try_from(bytes.len()).map_err(|_| {
                    syntax(format!(
                        "an {name:?} id is over 255 octets (RFC 9460 §7.1.1)"
                    ))
                })?;
                if len == 0 {
                    return Err(syntax(format!("an empty {name:?} id (RFC 9460 §7.1.1)")));
                }
                out.push(len);
                out.extend_from_slice(&bytes);
            }
            if out.is_empty() {
                return Err(syntax(format!(
                    "{name:?} needs at least one id (RFC 9460 §7.1.1)"
                )));
            }
            Ok(out)
        }
        key::PORT => {
            let text = plain(value)?;
            let port = text.parse::<u16>().map_err(|e| {
                syntax(format!(
                    "the {name:?} value {text:?} is not a number 0-65535: {e}"
                ))
            })?;
            Ok(port.to_be_bytes().to_vec())
        }
        key::IPV4HINT => {
            let text = plain(value)?;
            let mut out = Vec::new();
            for item in comma_list(&text, name, ln)? {
                let addr = item.parse::<Ipv4Addr>().map_err(|e| {
                    syntax(format!("the {name:?} address {item:?} does not parse: {e}"))
                })?;
                out.extend_from_slice(&addr.octets());
            }
            if out.is_empty() {
                return Err(syntax(format!(
                    "{name:?} needs at least one address — \"an empty list of addresses is \
                     invalid\" (RFC 9460 §7.3)"
                )));
            }
            Ok(out)
        }
        key::IPV6HINT => {
            let text = plain(value)?;
            let mut out = Vec::new();
            for item in comma_list(&text, name, ln)? {
                let addr = item.parse::<Ipv6Addr>().map_err(|e| {
                    syntax(format!("the {name:?} address {item:?} does not parse: {e}"))
                })?;
                out.extend_from_slice(&addr.octets());
            }
            if out.is_empty() {
                return Err(syntax(format!(
                    "{name:?} needs at least one address — \"an empty list of addresses is \
                     invalid\" (RFC 9460 §7.3)"
                )));
            }
            Ok(out)
        }
        // RFC 9460 §14.3.2 registers key 5 as "RESERVED (held for Encrypted
        // ClientHello)" and defines no value format, so this looked like one
        // more opaque key — and that is wrong in the silent direction. The
        // format is base64, from the ECH specification that reserved it, and
        // dnspython reads `ech="aGVsbG8="` as the five octets `hello` where an
        // opaque reading stores the eight characters of the base64 itself.
        // Storing the wrong bytes under the right name is worse than refusing
        // (`CLAUDE.md` §4), and the third party disagreeing with us is how this
        // was caught rather than shipped.
        key::ECH => {
            // Not `plain`: that one refuses a backslash citing §7.2, §7.3 and
            // §8, none of which is about this key. A backslash is not base64
            // either, so the decoder's own message is the accurate one.
            base64::Engine::decode(
                &base64::prelude::BASE64_STANDARD,
                value.unwrap_or_default().trim(),
            )
            .map_err(|e| syntax(format!("the {name:?} value is not base64: {e}")))
        }
        // Everything else: opaque octets, spelled with §5.1's escapes.
        _ => char_string_decode(value.unwrap_or_default())
            .map_err(|e| syntax(format!("the {name:?} value: {e}"))),
    }
}

/// Split a comma-separated list (RFC 9460 Appendix A.1).
///
/// Takes the RFC's own simplification: "a value-list parser that splits on `,`
/// and prohibits items containing `\` is sufficient to comply with all
/// requirements in this document". The escaped form exists so that a `,` can
/// appear *inside* an item, which no registered key needs — and §7.1.1 says an
/// implementation "MAY disallow the `,` and `\` characters in ALPN IDs
/// instead", pointing at `key1=\002h2` for the case that does. Refusing is what
/// this codebase already does with escapes it will not resolve
/// (`TODO.md` #13e).
fn comma_list(text: &str, name: &str, ln: usize) -> Result<Vec<String>, ZoneError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if text.contains('\\') {
        return Err(ZoneError::syntax(
            ln,
            format!(
                "the {name:?} list contains a backslash — RFC 9460 Appendix A.1 allows a parser \
                 to prohibit one, and §7.1.1 points at the keyNNNNN form for a value that needs \
                 it"
            ),
        ));
    }
    let items: Vec<String> = text.split(',').map(str::to_string).collect();
    if items.iter().any(String::is_empty) {
        return Err(ZoneError::syntax(
            ln,
            format!("the {name:?} list has an empty item (RFC 9460 Appendix A.1)"),
        ));
    }
    Ok(items)
}

/// The SvcParams as zone-file text.
///
/// Total, and deliberately: a value that does not fit the shape its key
/// requires — an `ipv4hint` off the wire whose length is not a multiple of
/// four, an ALPN id with a comma in it — is written in the `keyNNNNN` opaque
/// form, which says the same octets and reads back the same. Sinking the whole
/// record to RFC 3597 `\#` form would also be correct but loses the six
/// parameters that were fine, and returning `None` would put a "cannot write
/// this" case into every caller for a record we can always write.
pub(crate) fn present_params(params: &[(u16, Vec<u8>)]) -> String {
    let mut out = String::new();
    for (code, value) in params {
        if !out.is_empty() {
            out.push(' ');
        }
        match present_value(*code, value) {
            Some(None) => out.push_str(&svc_param_key_name(*code)),
            Some(Some(text)) => {
                out.push_str(&svc_param_key_name(*code));
                out.push_str("=\"");
                out.push_str(&text);
                out.push('"');
            }
            // The opaque spelling. `key{code}` rather than the name, so the
            // parser reads it back as octets instead of trying the shape that
            // did not fit.
            None => {
                out.push_str(&format!("key{code}"));
                out.push_str("=\"");
                out.push_str(&char_string_escaped(value));
                out.push('"');
            }
        }
    }
    out
}

/// `Some(None)` is a key written bare; `Some(Some(text))` a key with a value;
/// `None` a value that does not fit its key.
fn present_value(code: u16, value: &[u8]) -> Option<Option<String>> {
    let joined = |items: Vec<String>| Some(Some(items.join(",")));
    match code {
        key::NO_DEFAULT_ALPN if value.is_empty() => Some(None),
        key::NO_DEFAULT_ALPN => None,
        key::MANDATORY => {
            if value.is_empty() || !value.len().is_multiple_of(2) {
                return None;
            }
            joined(
                value
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| svc_param_key_name(u16::from_be_bytes(*c)).into_owned())
                    .collect(),
            )
        }
        key::ALPN => {
            let mut items = Vec::new();
            let mut rest = value;
            while let Some((&len, tail)) = rest.split_first() {
                let len = len as usize;
                if len == 0 || tail.len() < len {
                    return None;
                }
                let item = char_string_escaped(&tail[..len]);
                // A `,` inside an id would be read back as a separator, and
                // `comma_list` refuses the escape that would fix it — so such a
                // record goes out generic rather than out wrong.
                if item.contains(',') {
                    return None;
                }
                items.push(item);
                rest = &tail[len..];
            }
            if items.is_empty() {
                return None;
            }
            joined(items)
        }
        key::PORT => {
            let bytes: [u8; 2] = value.try_into().ok()?;
            Some(Some(u16::from_be_bytes(bytes).to_string()))
        }
        key::ECH => Some(Some(base64_encode(value))),
        key::IPV4HINT => {
            if value.is_empty() || !value.len().is_multiple_of(4) {
                return None;
            }
            joined(
                value
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| Ipv4Addr::from(*c).to_string())
                    .collect(),
            )
        }
        key::IPV6HINT => {
            if value.is_empty() || !value.len().is_multiple_of(16) {
                return None;
            }
            // `as_chunks` hands back `&[u8; 16]`, so there is no `try_into`
            // here and no `expect` to be wrong about.
            joined(
                value
                    .as_chunks::<16>()
                    .0
                    .iter()
                    .map(|c| Ipv6Addr::from(*c).to_string())
                    .collect(),
            )
        }
        _ => Some(Some(char_string_escaped(value))),
    }
}

#[cfg(test)]
mod tests {

    use super::{svc_param_key_from_name, svc_param_key_name};
    use crate::utils::{hex_encode, record_types as rt};
    use crate::zone::{parse_zone_file, Zone};
    use crate::zone_writer::zone_to_string;

    /// The RDATA of the one SVCB or HTTPS record in a one-line zone, as hex.
    fn rdata_hex(line: &str) -> String {
        let zone = parse(line);
        let record = one(&zone);
        hex_encode(record)
    }

    fn parse(line: &str) -> Zone {
        parse_zone_file(
            &format!("$ORIGIN example.com.\n$TTL 3600\n{line}\n"),
            "example.com.",
        )
        .unwrap_or_else(|e| panic!("{line}\n  did not parse: {e}"))
    }

    fn one(zone: &Zone) -> &[u8] {
        for rtype in [rt::SVCB, rt::HTTPS] {
            if let Some(record) = zone.records().iter().find(|r| r.rdata.rtype() == rtype) {
                return record.rdata.bytes();
            }
        }
        panic!("no SVCB or HTTPS record in the zone");
    }

    /// RFC 9460 Appendix D, every figure that has a wire form — the inputs the
    /// spec has already committed to an answer for (`CLAUDE.md` §1).
    ///
    /// The hex is the RFC's own, with its whitespace and comments removed.
    #[test]
    fn the_rfc_9460_test_vectors() {
        for (what, line, want) in [
            (
                "D.1 AliasMode",
                "@ IN HTTPS 0 foo.example.com.",
                "000003666F6F076578616D706C6503636F6D00",
            ),
            ("Figure 3, TargetName is \".\"", "@ IN SVCB 1 .", "000100"),
            (
                "Figure 4, specifies a port",
                "@ IN SVCB 16 foo.example.com. port=53",
                "001003666F6F076578616D706C6503636F6D00000300020035",
            ),
            (
                "Figure 5, a generic key and unquoted value",
                "@ IN SVCB 1 foo.example.com. key667=hello",
                "000103666F6F076578616D706C6503636F6D00029B000568656C6C6F",
            ),
            (
                "Figure 6, a quoted value with a decimal escape",
                "@ IN SVCB 1 foo.example.com. key667=\"hello\\210qoo\"",
                "000103666F6F076578616D706C6503636F6D00029B000968656C6C6FD2716F6F",
            ),
            (
                "Figure 7, two quoted IPv6 hints",
                "@ IN SVCB 1 foo.example.com. ipv6hint=\"2001:db8::1,2001:db8::53:1\"",
                "000103666F6F076578616D706C6503636F6D0000060020200\
                 10DB800000000000000000000000120010DB80000000000000000005\
                 30001",
            ),
            (
                "Figure 8, an IPv6 hint using the embedded IPv4 syntax",
                "@ IN SVCB 1 example.com. ipv6hint=\"2001:db8:122:344::192.0.2.33\"",
                "0001076578616D706C6503636F6D000006001020010DB8012203\
                 4400000000C0000221",
            ),
            (
                "Figure 9, presentation order is arbitrary and the wire is sorted",
                "@ IN SVCB 16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn \
                 ipv4hint=192.0.2.1",
                "001003666F6F076578616D706C65036F726700000000040001000400\
                 0100090268320568332D3139000400\
                 04C0000201",
            ),
        ] {
            let want: String = want.chars().filter(|c| !c.is_whitespace()).collect();
            assert_eq!(rdata_hex(line), want, "{what}");
        }
    }

    /// Figure 9 again, from the other side: the operator's order is not
    /// information, so writing the same parameters in any order gives the same
    /// record. "SvcParamKey ordering is arbitrary in presentation format but
    /// sorted in wire format" is the figure's own title.
    #[test]
    fn presentation_order_does_not_change_the_record() {
        let a = rdata_hex("@ IN SVCB 16 foo.example.org. alpn=h2 ipv4hint=192.0.2.1 port=443");
        let b = rdata_hex("@ IN SVCB 16 foo.example.org. port=443 ipv4hint=192.0.2.1 alpn=h2");
        assert_eq!(a, b);
    }

    /// Every shape that has to survive a write and a re-read, because a zone
    /// that changes meaning when `rdnsctl dump` round-trips it is worse than
    /// one that will not load.
    #[test]
    fn presentation_round_trips_through_the_writer() {
        for line in [
            "@ IN HTTPS 0 svc.example.net.",
            "@ IN HTTPS 1 . alpn=\"h2,h3\"",
            "@ IN SVCB 16 foo.example.org. mandatory=alpn,ipv4hint alpn=h2 ipv4hint=192.0.2.1",
            "@ IN SVCB 1 foo.example.com. no-default-alpn alpn=h2",
            "@ IN SVCB 1 foo.example.com. port=8002",
            "@ IN SVCB 1 foo.example.com. ipv6hint=\"2001:db8::1,2001:db8::53:1\"",
            "@ IN SVCB 1 foo.example.com. key667=\"hello\\210qoo\"",
            "@ IN SVCB 1 foo.example.com. ech=\"aGVsbG8=\"",
            "_8080._foo IN SVCB 0 foosvc.example.net.",
        ] {
            let before = parse(line);
            let written = zone_to_string(&before).expect("the zone writes");
            let after = parse_zone_file(&written, "example.com.").unwrap_or_else(|e| {
                panic!("{line}\n  wrote {written}\n  and did not re-read: {e}")
            });
            assert_eq!(
                hex_encode(one(&before)),
                hex_encode(one(&after)),
                "{line}\n  wrote: {written}"
            );
        }
    }

    /// The presentation rules that are refusals. Each cites the section that
    /// makes it one.
    #[test]
    fn the_shapes_rfc_9460_does_not_allow() {
        for (what, line, expect) in [
            (
                "AliasMode with SvcParams (§2.4.2)",
                "@ IN HTTPS 0 foo.example.com. alpn=h2",
                "2.4.2",
            ),
            (
                "a repeated key (§2.2)",
                "@ IN SVCB 1 foo.example.com. port=53 port=54",
                "twice",
            ),
            (
                "a value for no-default-alpn (§7.1.1)",
                "@ IN SVCB 1 foo.example.com. no-default-alpn=x",
                "7.1.1",
            ),
            (
                "\"mandatory\" listing itself (§8)",
                "@ IN SVCB 1 foo.example.com. mandatory=mandatory,alpn alpn=h2",
                "itself",
            ),
            (
                "an empty ipv4hint list (§7.3)",
                "@ IN SVCB 1 foo.example.com. ipv4hint=",
                "7.3",
            ),
            (
                "an escape where the key forbids one (§7.2)",
                "@ IN SVCB 1 foo.example.com. port=\"5\\0513\"",
                "escape",
            ),
            (
                "a key that is not a key",
                "@ IN SVCB 1 foo.example.com. nonsuch=1",
                "keyNNNNN",
            ),
            (
                "a priority that is not a number",
                "@ IN SVCB fast foo.example.com.",
                "priority",
            ),
        ] {
            let err = parse_zone_file(
                &format!("$ORIGIN example.com.\n$TTL 3600\n{line}\n"),
                "example.com.",
            )
            .expect_err(&format!("{what} should not load: {line}"));
            assert!(
                err.to_string().contains(expect),
                "{what}: the error should say {expect:?}, said: {err}"
            );
        }
    }

    /// RFC 9460 Appendix D Figure 10 is `alpn="f\\\\oo\\,bar,h2"` — a comma
    /// *inside* an ALPN id, escaped. This parser refuses it, which the RFC
    /// allows twice over: Appendix A.1 says "a value-list parser that splits on
    /// `,` and prohibits items containing `\` is sufficient to comply with all
    /// requirements in this document", and §7.1.1 says an implementation "MAY
    /// disallow the `,` and `\` characters in ALPN IDs instead of implementing
    /// the value-list escaping procedure, relying on the opaque key format
    /// (e.g., `key1=\002h2`)".
    ///
    /// Recorded as a test rather than a comment because it is a deliberate
    /// limit, and the error has to point at the way out.
    #[test]
    fn an_escaped_comma_inside_an_alpn_id_is_refused_with_the_way_out() {
        let err = parse_zone_file(
            "$ORIGIN example.com.\n$TTL 3600\n@ IN SVCB 16 foo.example.org. alpn=\"f\\\\oo\\,bar,h2\"\n",
            "example.com.",
        )
        .expect_err("an escaped comma in an alpn id");
        assert!(err.to_string().contains("keyNNNNN"), "{err}");

        // And the way out works: the same two ids through the opaque form.
        assert_eq!(
            rdata_hex("@ IN SVCB 16 foo.example.org. key1=\"\\008f\\092oo,bar\\002h2\""),
            "001003666F6F076578616D706C65036F72670000010\
             00C08665C6F6F2C626172026832"
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        );
    }

    /// RFC 9460 §14.3.2 registers `ech` as "RESERVED (held for Encrypted
    /// ClientHello)" and gives no value format, so it read as one more opaque
    /// key — and that was wrong in the silent direction: the format is base64.
    ///
    /// The number here is dnspython's, which is the point. Asked to encode
    /// `1 . ech="aGVsbG8="` it produces `...0005 68656C6C6F` — key 5, length 5,
    /// the octets `hello` — where the opaque reading stored the eight
    /// characters of the base64 text. A third party disagreeing is how this
    /// was caught (`CLAUDE.md` §1: our parser agreeing with our serializer
    /// proves nothing).
    #[test]
    fn ech_is_base64_which_dnspython_had_to_settle() {
        assert_eq!(
            rdata_hex("@ IN HTTPS 1 . ech=\"aGVsbG8=\""),
            "00010000050005".to_string() + "68656C6C6F",
        );
        // And back out as the base64 it was written as.
        let zone = parse("@ IN HTTPS 1 . ech=\"aGVsbG8=\"");
        let written = zone_to_string(&zone).expect("the zone writes");
        assert!(written.contains("ech=\"aGVsbG8=\""), "{written}");

        // Not base64 is a syntax error, not eight stored characters.
        let err = parse_zone_file(
            "$ORIGIN example.com.
$TTL 3600
@ IN HTTPS 1 . ech=\"not base64!\"
",
            "example.com.",
        )
        .expect_err("a value that is not base64");
        assert!(err.to_string().contains("base64"), "{err}");
    }

    /// `keyNNNNN` is the generic spelling, and the writer never emits a leading
    /// zero — so accepting one would break the round trip the pair promises.
    #[test]
    fn the_generic_key_spelling_has_one_form() {
        assert_eq!(svc_param_key_from_name("key667"), Some(667));
        assert_eq!(svc_param_key_from_name("key0"), Some(0));
        assert_eq!(svc_param_key_name(667), "key667");
        assert_eq!(svc_param_key_from_name("key0001"), None);
        assert_eq!(svc_param_key_from_name("key65536"), None);
        assert_eq!(svc_param_key_from_name("keyfoo"), None);
        // The named ones read back both ways.
        for key in 0u16..=6 {
            let name = svc_param_key_name(key);
            assert_eq!(svc_param_key_from_name(&name), Some(key), "{name}");
        }
    }
}
