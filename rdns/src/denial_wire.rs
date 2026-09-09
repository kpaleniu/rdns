//! The wire encodings a denial record is written in, with no cryptography in
//! them: canonical name order (RFC 4034 §6.1), type bitmaps (§4.1.2) and
//! base32hex (RFC 4648 §7).
//!
//! Split out of [`crate::dnssec_denial`] because `zone` and `zone_writer` need
//! all three to read and write NSEC and NSEC3 records, and a zone file is not a
//! DNSSEC question: those two edges were the only ones blocking the crate cut
//! #31 measured, and they carried no crypto across. `dnssec_denial` keeps
//! everything that hashes, proves or verifies.
//!
//! It is also why `zone` had grown a second base32hex decoder (`TODO.md` #26b)
//! — one that folded case with `str::to_uppercase`, the Unicode fold RFC 4343
//! forbids (`CLAUDE.md` §8), and disagreed with this one about `=` padding.

use crate::error::{WireError, WireResult};
use crate::NameRef;
use crate::Rtype;
use std::cmp::Ordering;

/// Compare two names in DNSSEC canonical order (RFC 4034 §6.1).
///
/// Labels sort from the *right*, and a name sorts ahead of everything beneath
/// it. String comparison gets both wrong, and an NSEC range check built on it
/// accepts names outside the gap.
/// `Iterator::cmp` gives both remaining rules for free: the first differing
/// label decides, and a name that runs out of labels first is an ancestor and
/// sorts before its descendants.
pub fn canonical_name_cmp(a: NameRef<'_>, b: NameRef<'_>) -> Ordering {
    reversed_labels(a).cmp(reversed_labels(b))
}

/// A byte string whose plain `Ord` is exactly [`canonical_name_cmp`], so a
/// `BTreeMap` can answer "which NSEC's range contains this name?" by range query.
///
/// Labels are written right to left, each terminated by a zero byte. The
/// terminator is what makes an ancestor sort before its descendants and keeps a
/// label from sorting after a longer label it is a prefix of (`ab\0` before
/// `abc\0`). Zero cannot occur inside a label.
pub fn canonical_sort_key(name: NameRef<'_>) -> Vec<u8> {
    let mut key = Vec::with_capacity(name.as_wire().len());
    for label in reversed_labels(name) {
        key.extend(label.folded());
        key.push(0);
    }
    key
}

/// A name's labels, right to left. The root has none.
///
/// Borrowed, and folded only where they are compared: this returned a
/// `Vec<String>`, so a name comparison cost a `Vec` and a `String` per label at
/// each side — eight allocations for two three-label names, and `Nsec::covers`
/// makes three comparisons. A signed NXDOMAIN spent 142 allocations, most of
/// them here.
///
/// It also read presentation text, and split it on `.`, which RFC 4034 §6.1
/// ordering cannot survive for a name holding RFC 1035 §5.1's `\.`:
/// `a\.b.example.com.` came apart into four labels, one of them ending in a
/// backslash, so it sorted somewhere no other implementation puts it
/// (`TODO.md` #37a). Reading the wire form is the same rule with nothing to get
/// wrong — a label is what the length octet says it is.
///
/// `suffix(n)` per label rather than a reversed iterator: [`NameRef::labels`]
/// walks forwards, since the wire form is a chain of length octets, and the
/// alternative to re-walking it is an offset table on the stack for a name that
/// has three labels.
pub(crate) fn reversed_labels(name: NameRef<'_>) -> impl Iterator<Item = Folded<'_>> {
    (1..=name.label_count()).map(move |n| Folded(name.suffix(n).labels().next().unwrap_or(&[])))
}

/// One label as the octets it stands for, ordered as RFC 4034 §6.1 requires:
/// octet by octet, with ASCII case folded (RFC 4343).
///
/// A newtype because `Iterator::cmp` needs `Ord` and `Iterator::cmp_by` is
/// unstable. `Eq` is written in terms of `Ord` rather than derived, since a
/// derived one would compare the bytes without folding and disagree with it.
pub(crate) struct Folded<'a>(&'a [u8]);

impl Folded<'_> {
    fn folded(&self) -> impl Iterator<Item = u8> + '_ {
        self.0.iter().map(|b| b.to_ascii_lowercase())
    }
}

impl Ord for Folded<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.folded().cmp(other.folded())
    }
}

impl PartialOrd for Folded<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Folded<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Folded<'_> {}

/// Whether `rtype` is set in an NSEC/NSEC3 type bitmap (RFC 4034 §4.1.2).
///
/// A malformed bitmap reads as "type not present": a bitmap we cannot parse must
/// never be taken as proof that something is there.
pub fn bitmap_has_type(bitmap: &[u8], rtype: Rtype) -> bool {
    let want_window = (rtype.to_u16() >> 8) as u8;
    let want_bit = (rtype.to_u16() & 0xff) as usize;

    let mut rest = bitmap;
    while rest.len() >= 2 {
        let window = rest[0];
        let len = rest[1] as usize;
        if len == 0 || len > 32 || rest.len() < 2 + len {
            return false; // malformed: stop rather than guess
        }
        let bits = &rest[2..2 + len];
        if window == want_window {
            let byte = want_bit / 8;
            return byte < bits.len() && bits[byte] & (0x80 >> (want_bit % 8)) != 0;
        }
        rest = &rest[2 + len..];
    }
    false
}

/// Build a type bitmap covering `types`.
pub fn build_type_bitmap(types: &[Rtype]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut windows: Vec<(u8, Vec<u8>)> = Vec::new();
    for &t in types {
        let t = t.to_u16();
        let window = (t >> 8) as u8;
        let bit = (t & 0xff) as usize;
        let entry = match windows.iter_mut().find(|(w, _)| *w == window) {
            Some(e) => e,
            None => {
                windows.push((window, Vec::new()));
                windows.last_mut().expect("just pushed")
            }
        };
        let byte = bit / 8;
        if entry.1.len() <= byte {
            entry.1.resize(byte + 1, 0);
        }
        entry.1[byte] |= 0x80 >> (bit % 8);
    }
    windows.sort_by_key(|(w, _)| *w);
    for (window, bits) in windows {
        out.push(window);
        out.push(bits.len() as u8);
        out.extend_from_slice(&bits);
    }
    out
}

/// Every type set in a bitmap, ascending. A malformed bitmap silently truncates;
/// [`bitmap_types_exact`] is the checked form.
#[cfg(test)]
fn bitmap_types(bitmap: &[u8]) -> Vec<Rtype> {
    bitmap_types_exact(bitmap).unwrap_or_else(|partial| partial)
}

/// Every type set in a bitmap, ascending — or `Err(what was read before the
/// damage)` when the bitmap does not parse to its end. Re-encoding a bitmap only
/// partly understood would emit a record other than the one we were given.
pub fn bitmap_types_exact(bitmap: &[u8]) -> Result<Vec<Rtype>, Vec<Rtype>> {
    let mut types = Vec::new();
    let mut rest = bitmap;
    while !rest.is_empty() {
        if rest.len() < 2 {
            return Err(types);
        }
        let window = rest[0] as u16;
        let len = rest[1] as usize;
        if len == 0 || len > 32 || rest.len() < 2 + len {
            return Err(types);
        }
        for (byte, bits) in rest[2..2 + len].iter().enumerate() {
            // Bit 0 is the *high* bit (RFC 4034 §4.1.2), so it is
            // `leading_zeros` that names the next set type and taking them from
            // the top keeps the output ascending — `TODO.md` #26i said
            // `trailing_zeros`, which is the idiom for the other bit order and
            // would list each byte's types backwards.
            let mut remaining = *bits;
            while remaining != 0 {
                let bit = remaining.leading_zeros() as u16;
                types.push(Rtype::new((window << 8) | (byte as u16 * 8 + bit)));
                remaining &= !(0x80u8 >> bit);
            }
        }
        rest = &rest[2 + len..];
    }
    Ok(types)
}

/// base32hex (RFC 4648 §7): how an NSEC3 owner label carries a hash.
const BASE32HEX: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// The same alphabet down-cased, for [`nsec3_owner_name`]. A second table
/// rather than a fold of the first: the fold was the allocation.
pub(crate) const BASE32HEX_LOWER: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

/// The number of base32hex characters `len` octets encode to, unpadded.
pub(crate) fn base32hex_len(len: usize) -> usize {
    (len * 8).div_ceil(5)
}

/// Encode bytes as unpadded base32hex.
pub fn base32hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(base32hex_len(data.len()));
    encode_base32hex(data, BASE32HEX, &mut out);
    out
}

/// The same into a caller's byte buffer, which must hold
/// [`base32hex_len`] octets.
///
/// Returns how many were written. For an owner name the encoding is a *label*,
/// so the bytes are what is wanted and a `String` is the conversion.
pub(crate) fn encode_base32hex_in(data: &[u8], alphabet: &[u8; 32], out: &mut [u8]) -> usize {
    let mut at = 0;
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..chars {
            let shift = 35 - i * 5;
            out[at] = alphabet[((bits >> shift) & 0x1f) as usize];
            at += 1;
        }
    }
    at
}

pub(crate) fn encode_base32hex(data: &[u8], alphabet: &[u8; 32], out: &mut String) {
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        // 5 input bytes make 8 output characters; a short final chunk makes
        // ceil(len * 8 / 5) of them.
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..chars {
            let shift = 35 - i * 5;
            out.push(alphabet[((bits >> shift) & 0x1f) as usize] as char);
        }
    }
}

/// Decode unpadded base32hex. Case-insensitive, as DNS labels are.
pub fn base32hex_decode(text: &str) -> WireResult<Vec<u8>> {
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in text.bytes() {
        let value = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'v' => c - b'a' + 10,
            b'A'..=b'V' => c - b'A' + 10,
            _ => {
                return Err(WireError::malformed(
                    "base32hex text",
                    format!("invalid character {:?}", c as char),
                ))
            }
        };
        acc = (acc << 5) | value as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_records::nm;
    use crate::utils::record_types as rt;

    /// The two orderings under test, over names written as text. Both take a
    /// `NameRef` now, and a test that spelled the conversion at every call site
    /// would be reading about `Name` rather than about the ordering.
    fn cmp(a: &str, b: &str) -> Ordering {
        canonical_name_cmp(nm(a).as_ref(), nm(b).as_ref())
    }

    fn key(name: &str) -> Vec<u8> {
        canonical_sort_key(nm(name).as_ref())
    }

    /// Sorting is by label from the right, so a deeper name under an earlier
    /// label comes first.
    #[test]
    fn test_canonical_order_is_by_label_from_the_right() {
        // The rightmost differing label decides.
        assert_eq!(cmp("a.z.example.com.", "b.example.com."), Ordering::Greater);
        // Plain string comparison gets exactly this backwards.
        assert!("a.z.example.com." < "b.example.com.");

        // A name sorts before everything beneath it.
        assert_eq!(cmp("example.com.", "www.example.com."), Ordering::Less);
        // Case and trailing dots do not matter.
        assert_eq!(cmp("EXAMPLE.com", "example.com."), Ordering::Equal);
        // RFC 4034 §6.1's own example ordering, less the two names it spells
        // with escapes (`\001.z.example` and `\200.z.example`): a label holding
        // `\` is refused outright here (`dname::unrepresentable_octet`), so
        // those are not names this library can hold, and comparing them as
        // presentation text would order them by the backslash rather than by
        // the octet they stand for.
        //
        // `Z.a.example` and `zABC.a.EXAMPLE` are the case-folding half of the
        // example, and they are load-bearing: unfolded, `EXAMPLE` sorts before
        // `example` and the last three lines come out in the wrong order.
        let mut names = vec![
            "z.example.",
            "yljkjljk.a.example.",
            "*.z.example.",
            "example.",
            "zABC.a.EXAMPLE.",
            "a.example.",
            "Z.a.example.",
        ];
        names.sort_by(|a, b| cmp(a, b));
        assert_eq!(
            names,
            vec![
                "example.",
                "a.example.",
                "yljkjljk.a.example.",
                "Z.a.example.",
                "zABC.a.EXAMPLE.",
                "z.example.",
                "*.z.example.",
            ]
        );
    }

    /// If the sort key and `canonical_name_cmp` disagree, a range query returns
    /// the wrong NSEC and the covering check silently examines a record that
    /// cannot prove anything.
    #[test]
    fn test_sort_key_ordering_matches_canonical_ordering() {
        let names = [
            ".",
            "example.",
            "a.example.",
            "yljkjljk.a.example.",
            "Z.a.example.",
            "zABC.a.EXAMPLE.",
            "z.example.",
            "*.z.example.",
            "\\200.z.example.",
            "b.example.",
            "a.z.example.",
            "ab.example.",
            "abc.example.",
        ];
        for a in names {
            for b in names {
                assert_eq!(
                    key(a).cmp(&key(b)),
                    cmp(a, b),
                    "sort key disagrees with canonical order for {a:?} vs {b:?}"
                );
            }
        }
        // The two properties the zero terminator buys, spelled out.
        assert!(key("example.") < key("a.example."));
        assert!(key("ab.example.") < key("abc.example."));

        // `a\.b` is one label of three octets (RFC 1035 §5.1), so the key holds
        // the dot it stands for and not the backslash that spells it. Splitting
        // on `.` made three labels of it and wrote `example\0b\0a\\0`, which is
        // where no other implementation puts the name (`TODO.md` #37a).
        assert_eq!(key(r"a\.b.example."), b"example\0a.b\0".to_vec());
        assert!(key("a.example.") < key(r"a\.b.example."));
        assert!(key(r"a\.b.example.") < key("b.example."));
    }

    #[test]
    fn test_type_bitmap_roundtrip() {
        let bitmap = build_type_bitmap(&[rt::A, rt::NS, rt::SOA, rt::RRSIG, rt::NSEC, rt::DNSKEY]);
        for present in [rt::A, rt::NS, rt::SOA, rt::RRSIG, rt::NSEC, rt::DNSKEY] {
            assert!(
                bitmap_has_type(&bitmap, present),
                "type {present} should be set"
            );
        }
        for absent in [rt::AAAA, rt::MX, rt::DS, rt::CNAME] {
            assert!(
                !bitmap_has_type(&bitmap, absent),
                "type {absent} should not be set"
            );
        }
    }

    #[test]
    fn test_type_bitmap_spans_windows() {
        // TYPE1234 lives in window 4; A lives in window 0.
        let bitmap = build_type_bitmap(&[rt::A, Rtype::new(1234)]);
        assert!(bitmap_has_type(&bitmap, rt::A));
        assert!(bitmap_has_type(&bitmap, Rtype::new(1234)));
        assert!(!bitmap_has_type(&bitmap, Rtype::new(1235)));
    }

    /// A bitmap we cannot parse must read as "absent", never as "present".
    #[test]
    fn test_malformed_bitmap_denies_nothing() {
        assert!(!bitmap_has_type(&[0x00], rt::A), "truncated window header");
        assert!(
            !bitmap_has_type(&[0x00, 0x09, 0x40], rt::A),
            "length overruns"
        );
        assert!(!bitmap_has_type(&[], rt::A));
    }

    /// Listing the types back out is what turns an NSEC into a zone-file line.
    #[test]
    fn test_bitmap_types_lists_what_was_built() {
        let types = [
            rt::A,
            rt::NS,
            rt::SOA,
            rt::RRSIG,
            rt::NSEC,
            rt::DNSKEY,
            Rtype::new(1234),
        ];
        let bitmap = build_type_bitmap(&types);

        let mut expected = types.to_vec();
        expected.sort_unstable();
        assert_eq!(bitmap_types(&bitmap), expected, "ascending, across windows");
        assert_eq!(bitmap_types_exact(&bitmap), Ok(expected));
        assert_eq!(bitmap_types(&[]), Vec::<Rtype>::new());
    }

    /// A short read must be reported: re-encoding only the types understood
    /// would emit a record other than the one handed in.
    #[test]
    fn test_bitmap_types_reports_a_short_read() {
        let mut damaged = build_type_bitmap(&[rt::A]);
        damaged.push(0x01); // a window header with nothing behind it
        assert_eq!(
            bitmap_types_exact(&damaged),
            Err(vec![rt::A]),
            "what was read, and that there was more"
        );
        assert_eq!(bitmap_types_exact(&[0x00, 0x09, 0x40]), Err(vec![]));
    }

    #[test]
    fn test_base32hex_roundtrip() {
        // RFC 4648 §10 test vectors, in base32hex.
        assert_eq!(base32hex_encode(b"f"), "CO");
        assert_eq!(base32hex_encode(b"fo"), "CPNG");
        assert_eq!(base32hex_encode(b"foo"), "CPNMU");
        assert_eq!(base32hex_encode(b"foob"), "CPNMUOG");
        assert_eq!(base32hex_encode(b"fooba"), "CPNMUOJ1");
        assert_eq!(base32hex_encode(b"foobar"), "CPNMUOJ1E8");

        for input in [b"".as_slice(), b"f", b"fo", b"foo", b"foobar", &[0u8; 20]] {
            let encoded = base32hex_encode(input);
            assert_eq!(
                base32hex_decode(&encoded).unwrap(),
                input,
                "roundtrip of {encoded}"
            );
        }
        // Lowercase decodes the same, since DNS labels are case-insensitive.
        assert_eq!(
            base32hex_decode("cpnmuoj1e8").unwrap(),
            base32hex_decode("CPNMUOJ1E8").unwrap()
        );
        assert!(base32hex_decode("not-base32!").is_err());
    }

    /// The decoder `zone` used to carry beside this one folded case with
    /// `str::to_uppercase`, and RFC 4343 says case folding is ASCII-only
    /// (`CLAUDE.md` §8). U+017F LATIN SMALL LETTER LONG S upper-cases to `S`,
    /// which *is* in the base32hex alphabet, so that copy decoded a character
    /// no DNS name can contain (`TODO.md` #26b).
    #[test]
    fn a_unicode_character_is_not_a_base32hex_digit() {
        assert_eq!(
            "\u{017f}".to_uppercase(),
            "S",
            "the fold that made this a bug"
        );
        assert!(
            base32hex_decode("\u{017f}").is_err(),
            "the long s is not a digit, whatever it upper-cases to"
        );
    }

    /// RFC 5155 §3.3: the Next Hashed Owner Name is "an unpadded sequence of
    /// case-insensitive base32 digits". The other copy skipped `=` silently,
    /// so a padded field loaded as a *shorter* hash — a chain that then
    /// matches nothing.
    #[test]
    fn padding_is_refused_rather_than_skipped() {
        assert!(base32hex_decode("CPNMUOJ1E8======").is_err());
    }
}
