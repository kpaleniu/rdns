//! Octets as presentation text, and back: hex, base64 and RFC 1035 §5.1's
//! character-strings.
//!
//! Split out of `utils` (`TODO.md` #38c). The membership rule is the whole of
//! it: a conversion between bytes and the text a zone file, an anchor file or a
//! generic-format record writes them as. Nothing here knows what the bytes mean.

use crate::error::{WireError, WireResult};

/// Hex, upper case, as a zone file and an anchor file write a digest or a salt.
///
/// Existed twice as `bytes.iter().map(|b| format!("{b:02X}")).collect()`, which
/// is **a heap allocation per output byte** — `rdnsctl dump` of a signed zone
/// runs it over every DS digest and NSEC3 salt (`TODO.md` #26a).
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// The inverse, tolerating whitespace anywhere.
///
/// A DS digest is written across lines in IANA's own root-anchors file and
/// inside parentheses in a zone file, so "skip whitespace" is the rule at every
/// call site rather than a kindness. One pass and no intermediate `String`:
/// there were three of these, one of them inline and so invisible to a grep for
/// the name (`TODO.md` #26c).
pub fn hex_decode(text: &str) -> WireResult<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut high: Option<u8> = None;
    for c in text.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let nibble = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => {
                return Err(WireError::malformed(
                    "hex text",
                    format!("invalid character {:?}", c as char),
                ))
            }
        };
        match high.take() {
            None => high = Some(nibble),
            Some(h) => out.push((h << 4) | nibble),
        }
    }
    if high.is_some() {
        return Err(WireError::malformed("hex text", "an odd number of digits"));
    }
    Ok(out)
}

/// base64, standard alphabet with padding (RFC 4648 §4) — how a DNSKEY, an
/// RRSIG and a TSIG secret are written.
///
/// A one-line wrapper that existed three times. The *decoder* deliberately does
/// not move: it is one call to the crate at each site and every site wraps the
/// failure in its own error type, so a shared one would add an indirection and
/// nothing else.
pub fn base64_encode(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::prelude::BASE64_STANDARD, bytes)
}

/// Decode RFC 1035 §5.1's escapes: `\X` is a literal `X`, and `\DDD` is the
/// octet with that three-digit decimal value.
///
/// RFC 9460 Appendix A calls this "character-string decoding" and defers to
/// §5.1 for it; `escaped = "\" ( non-digit / dec-octet )`, so the digit form is
/// exactly three digits and nothing else counts as one.
///
/// Bytes out, not a `String`: §5.1 can spell any octet and most of them are not
/// UTF-8. The zone tokenizer keeps backslashes rather than resolving them, so
/// this is the one place they are resolved — which is why `\DDD` had no
/// spelling anywhere in this tree until SVCB needed one.
pub fn char_string_decode(text: &str) -> WireResult<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let rest = &bytes[i + 1..];
        let Some(&next) = rest.first() else {
            return Err(WireError::malformed(
                "a character-string",
                "it ends with a backslash, which escapes nothing",
            ));
        };
        if !next.is_ascii_digit() {
            out.push(next);
            i += 2;
            continue;
        }
        // A digit starts the three-digit form, and only the three-digit form:
        // `\1` and `\12` are not escapes of anything.
        if rest.len() < 3 || !rest[..3].iter().all(u8::is_ascii_digit) {
            return Err(WireError::malformed(
                "a character-string",
                "a backslash before a digit begins a three-digit decimal escape",
            ));
        }
        let value =
            (rest[0] - b'0') as u16 * 100 + (rest[1] - b'0') as u16 * 10 + (rest[2] - b'0') as u16;
        let byte = u8::try_from(value).map_err(|_| {
            WireError::malformed(
                "a character-string",
                format!("the decimal escape \\{value:03} is over 255"),
            )
        })?;
        out.push(byte);
        i += 4;
    }
    Ok(out)
}

/// The inverse: the text that goes *between quotes* in a zone file.
///
/// Escapes the two characters that would end the string or start an escape,
/// and spells every non-printable octet as `\DDD`. Total — there is no byte
/// §5.1 cannot say — which is why callers of this do not have a "cannot write
/// it" case to handle.
///
/// The quotes are the caller's to add: a value inside a comma-separated list
/// is escaped the same way but not quoted individually.
pub fn char_string_escaped(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(byte as char);
            }
            0x20..=0x7e => out.push(byte as char),
            other => out.push_str(&format!("\\{other:03}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A number that does not fit a TYPE code is not a type name.
    /// RFC 1035 §5.1's escapes, both directions.
    ///
    /// `\X` is a literal `X` and `\DDD` is one octet, and the digit form is
    /// exactly three digits — `escaped = "\" ( non-digit / dec-octet )` in
    /// RFC 9460 Appendix A's ABNF, where `dec-octet` is three digits and
    /// nothing shorter.
    #[test]
    fn character_string_escapes_decode_and_come_back() {
        for (text, want) in [
            ("plain", b"plain".to_vec()),
            (r#"say \"hi\""#, b"say \"hi\"".to_vec()),
            (r"a\\b", b"a\\b".to_vec()),
            (r"a\.b", b"a.b".to_vec()),
            // RFC 9460 Appendix D Figure 6's value.
            (r"hello\210qoo", b"hello\xd2qoo".to_vec()),
            (r"\000\255", vec![0x00, 0xff]),
            ("", Vec::new()),
        ] {
            assert_eq!(char_string_decode(text).unwrap(), want, "{text}");
        }

        // Every octet has a spelling, and it reads back as itself.
        let every: Vec<u8> = (0u8..=255).collect();
        let spelled = char_string_escaped(&every);
        assert_eq!(char_string_decode(&spelled).unwrap(), every);
    }

    /// The three ways an escape can be malformed. Refused rather than guessed
    /// at, because each guess is a different octet string.
    #[test]
    fn a_malformed_escape_is_refused() {
        for text in [
            // Nothing to escape.
            "ends with a backslash\\",
            // A digit starts the three-digit form and there are not three.
            r"\1",
            r"\12",
            r"\12x",
            // Three digits, over 255.
            r"\256",
            r"\999",
        ] {
            assert!(
                char_string_decode(text).is_err(),
                "{text:?} should not decode"
            );
        }
    }

    /// Both directions, and the two things the three deleted copies disagreed
    /// about: whitespace, and how many allocations an encode costs.
    #[test]
    fn hex_round_trips_and_is_written_into_one_string() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa5, 0xff]), "000FA5FF");
        assert_eq!(
            hex_encode(&[0u8; 20]).capacity(),
            40,
            "sized once for the whole digest, not grown a byte at a time"
        );

        // A DS digest wraps across lines in IANA's root-anchors file and inside
        // parentheses in a zone file.
        assert_eq!(
            hex_decode(
                "A5 FF
	00"
            )
            .unwrap(),
            vec![0xa5, 0xff, 0x00]
        );
        assert_eq!(hex_decode("a5ff").unwrap(), hex_decode("A5FF").unwrap());
        assert_eq!(hex_decode("").unwrap(), Vec::<u8>::new());

        assert!(hex_decode("abc").is_err(), "an odd number of digits");
        assert!(hex_decode("a5 f").is_err(), "odd once the spaces are gone");
        assert!(hex_decode("zz").is_err(), "not a hex digit");

        for bytes in [
            [].as_slice(),
            &[0x00],
            &[0xde, 0xad, 0xbe, 0xef],
            &[0xff; 32],
        ] {
            assert_eq!(hex_decode(&hex_encode(bytes)).unwrap(), bytes);
        }
    }

    /// RFC 4648 §10's vector, so the wrapper is pinned to the alphabet a DNSKEY
    /// is written in rather than to whatever the crate defaults to next.
    #[test]
    fn base64_is_the_padded_standard_alphabet() {
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8=", "padded");
    }
}
