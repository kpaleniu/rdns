//! The wire encodings a denial record is written in, with no cryptography in
//! them: canonical name order (RFC 4034 §6.1), type bitmaps (§4.1.2) and
//! base32hex (RFC 4648 §7).
//!
//! Not in `rdns::dnssec_denial`, because `zone` and `zone_writer` need all
//! three to read and write NSEC and NSEC3 records, and a zone file is not a
//! DNSSEC question: those two edges carry no crypto across (`TODO.md` #31).
//! `dnssec_denial` keeps everything that *computes* a hash, proves or verifies
//! — [`Nsec3Hash`] is here because it is a 20-octet value, not a hash function,
//! and `zone` keys a map on it.
//!
//! One base32hex decoder, because a second is one that folds case with
//! `str::to_uppercase`, the Unicode fold RFC 4343 forbids (`CLAUDE.md` §8), or
//! disagrees with this one about `=` padding.

use rdns_core::error::{WireError, WireResult};
use rdns_core::NameRef;
use rdns_core::Rtype;
use std::cmp::Ordering;

/// The length of an NSEC3 hash. SHA-1 is the only algorithm RFC 5155 §5
/// defines, and the registry it points at has no second entry.
pub const NSEC3_HASH_LEN: usize = 20;

/// The 20 octets RFC 5155 §5 hashes a name to, and the only length one can be.
///
/// `rdns::dnssec_denial`'s `Nsec3` refuses any algorithm but SHA-1, so a hash
/// of another length is not a hash, and a remote record carrying one is refused
/// at parse rather than stored to never match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nsec3Hash([u8; NSEC3_HASH_LEN]);

impl Nsec3Hash {
    /// The hash these octets are, if they are the right number of them.
    pub fn from_wire(bytes: &[u8]) -> Option<Nsec3Hash> {
        Some(Nsec3Hash(bytes.try_into().ok()?))
    }

    /// The hash these exactly-[`NSEC3_HASH_LEN`] octets are.
    ///
    /// For `dnssec_denial::hash_wire`, which computed them. Total, where
    /// `from_wire` on a known-good array would be an `expect` (`CLAUDE.md` §4).
    pub fn from_octets(octets: [u8; NSEC3_HASH_LEN]) -> Nsec3Hash {
        Nsec3Hash(octets)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Compare two names in DNSSEC canonical order (RFC 4034 §6.1).
///
/// Labels sort from the *right*, and a name sorts ahead of everything beneath
/// it; string comparison gets both wrong, and an NSEC range check built on it
/// accepts names outside the gap. `Iterator::cmp` over reversed labels gives
/// both.
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
pub fn canonical_sort_key(name: NameRef<'_>) -> CanonicalKey {
    let mut key = Vec::with_capacity(name.as_wire().len());
    for label in reversed_labels(name) {
        key.extend(label.folded());
        key.push(0);
    }
    CanonicalKey(key)
}

/// A name in RFC 4034 §6.1 order, which is the only reason this encoding exists.
///
/// Its `Ord` *is* the ordering — that is the whole point, and it is why the type
/// is not interchangeable with a folded name even though both are octets of a
/// name. `zone_signer` held two `BTreeMap<(Vec<u8>, Rtype), _>`, one keyed this
/// way and one keyed on folded wire, and nothing but the argument type kept them
/// apart (`TODO.md` #40a).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CanonicalKey(Vec<u8>);

/// A name's labels, right to left. The root has none.
///
/// Borrowed, and folded only where compared. Read from the wire form: text
/// split on `.` breaks a label holding RFC 1035 §5.1's `\.`. `suffix(n)` per
/// label because [`NameRef::labels`] walks forwards only.
pub fn reversed_labels(name: NameRef<'_>) -> impl Iterator<Item = Folded<'_>> {
    (1..=name.label_count()).map(move |n| Folded(name.suffix(n).labels().next().unwrap_or(&[])))
}

/// One label as the octets it stands for, ordered as RFC 4034 §6.1 requires:
/// octet by octet, with ASCII case folded (RFC 4343).
///
/// A newtype because `Iterator::cmp` needs `Ord` and `Iterator::cmp_by` is
/// unstable. `Eq` is written in terms of `Ord` rather than derived, since a
/// derived one would compare the bytes without folding and disagree with it.
pub struct Folded<'a>(&'a [u8]);

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
pub(crate) fn bitmap_types_exact(bitmap: &[u8]) -> Result<Vec<Rtype>, Vec<Rtype>> {
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
            // Bit 0 is the high bit (RFC 4034 §4.1.2), so `leading_zeros` names
            // the next type and keeps the output ascending.
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

/// The same alphabet down-cased, for `rdns::dnssec_denial`'s owner-name
/// builder. A second table
/// rather than a fold of the first: the fold was the allocation.
pub const BASE32HEX_LOWER: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

/// The number of base32hex characters `len` octets encode to, unpadded.
pub(crate) fn base32hex_len(len: usize) -> usize {
    (len * 8).div_ceil(5)
}

/// Encode bytes as unpadded base32hex.
pub fn base32hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(base32hex_len(data.len()));
    out.extend(base32hex_chars(data, BASE32HEX).map(char::from));
    out
}

/// The same into a caller's buffer of `base32hex_len` octets; returns how many
/// were written.
///
/// For an owner name the encoding is a *label*, so bytes are what is wanted.
pub fn encode_base32hex_in(data: &[u8], alphabet: &[u8; 32], out: &mut [u8]) -> usize {
    let mut at = 0;
    for c in base32hex_chars(data, alphabet) {
        out[at] = c;
        at += 1;
    }
    at
}

/// The characters of `data` in `alphabet`: one computation for both encoders.
fn base32hex_chars<'a>(data: &'a [u8], alphabet: &'a [u8; 32]) -> impl Iterator<Item = u8> + 'a {
    data.chunks(5).flat_map(move |chunk| {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        // 5 input bytes make 8 output characters; a short final chunk makes
        // ceil(len * 8 / 5) of them.
        (0..base32hex_len(chunk.len()))
            .map(move |i| alphabet[((bits >> (35 - i * 5)) & 0x1f) as usize])
    })
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
    use rdns_core::record_types as rt;
    /// `rdns::test_records::nm`, which is `#[cfg(test)]` there and so invisible
    /// across a crate boundary. Three lines rather than making that module
    /// public for one helper (`TODO.md` #67).
    fn nm(text: &str) -> rdns_core::Name {
        rdns_core::Name::from_presentation(text).expect("a name")
    }

    /// The two orderings under test, over names written as text. Both take a
    /// `NameRef` now, and a test that spelled the conversion at every call site
    /// would be reading about `Name` rather than about the ordering.
    fn cmp(a: &str, b: &str) -> Ordering {
        canonical_name_cmp(nm(a).as_ref(), nm(b).as_ref())
    }

    fn key(name: &str) -> CanonicalKey {
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
        // RFC 4034 §6.1's example less two escaped names `dname` refuses.
        // Unfolded, the mixed-case names would misorder the last three.
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

        // `a\.b` is one label (RFC 1035 §5.1): the key holds the dot, not the
        // backslash, where splitting on `.` would make three labels.
        assert_eq!(
            key(r"a\.b.example."),
            CanonicalKey(b"example\0a.b\0".to_vec())
        );
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

    /// RFC 4343 says case folding is ASCII-only (`CLAUDE.md` §8). U+017F LATIN
    /// SMALL LETTER LONG S upper-cases to `S`, which *is* in the base32hex
    /// alphabet, so a decoder folding with `str::to_uppercase` decodes a
    /// character no DNS name can contain.
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
