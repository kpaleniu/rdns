//! A domain name, stored the way the wire spells it.
//!
//! `TODO.md` #13e settled the representation question and deviation **D-1** is
//! the cost of not having acted on it. Names were presentation `String`s, and
//! two things follow from that which no call site can fix:
//!
//! - **A `String` cannot hold every legal name.** A label is "any binary
//!   string" (RFC 2181 §11) and Rust's `String` is UTF-8, so a zone carrying
//!   one could not be served and a *response* carrying one could not be
//!   parsed — `rdnsr` could not relay someone else's zone that had one.
//! - **Presentation text is not injective.** The one-label name
//!   `[03 'a' '.' 'b']` and the two-label `[01 'a' 01 'b']` both read as
//!   `"a.b."`, so a tree question asked of the text — is this under that? —
//!   answers wrong for one of them. #13e closed that by *refusing* the first,
//!   which made the invariant true at exactly the price D-1 names.
//!
//! Wire form rather than `Vec<Label>`: one allocation, not one per label —
//! `TODO.md` #27 got a whole answer down to two allocations and a name per
//! label would spend that on the question alone. It also makes every suffix at
//! a label boundary a name in its own right, so [`NameRef::parent`] borrows
//! instead of copying, which is what the ancestor walks in `zone` and
//! `resolver` do once per label of a name the client chose.
//!
//! **Comparison no longer folds.** [`NameRef`]'s `Eq` and `Hash` fold ASCII as
//! they go (RFC 4343), so the nine lowercased copies the string form needed to
//! compare two names are gone. A copy survives in one place and one only: a
//! `HashMap` key, because `Borrow` cannot hand out a borrowed view of a type
//! with a lifetime without the `unsafe` pointer cast `str` uses, and this
//! library has none. [`NameRef::folded`] is that one place, and it borrows when
//! the name is already lower case, which is the ordinary query.
//!
//! A `Name` is always **absolute**. A relative name exists only in zone-file
//! text and is resolved against the origin before it becomes one, so nothing
//! below this type has to ask.

use crate::dname::{
    check_name_len, name_wire_from_bytes, name_wire_from_bytes_in, DNameUnpacker, MAX_LABEL_LEN,
};
use crate::error::{WireError, WireResult};
use std::borrow::Cow;
use std::hash::{Hash, Hasher};

/// A domain name in wire form: each label a length octet and that many octets,
/// ending in the root's zero.
///
/// Owned; [`NameRef`] is the borrowed form, and the two compare equal.
#[derive(Clone)]
pub struct Name(Box<[u8]>);

/// A borrowed [`Name`] — usually a suffix of one, since every suffix at a label
/// boundary is itself a name.
///
/// A separate type rather than `Deref` to an unsized `#[repr(transparent)]`
/// newtype, which is how `String` reaches `str`: that needs a pointer cast, and
/// this library has no `unsafe` in it. The cost is `name.as_ref()` where a
/// `Name` is passed to something asking for a `NameRef`.
#[derive(Clone, Copy)]
pub struct NameRef<'a>(&'a [u8]);

impl Name {
    /// The root, `.` — one zero octet.
    pub fn root() -> Name {
        Name(Box::new([0u8]))
    }

    /// Borrow the whole name.
    pub fn as_ref(&self) -> NameRef<'_> {
        NameRef(&self.0)
    }

    /// Read an uncompressed name from the front of `bytes`, with what follows.
    ///
    /// For stored RDATA and anything else with no message behind it: a pointer
    /// here is malformed rather than something to follow.
    pub fn from_wire(bytes: &[u8]) -> WireResult<(Name, &[u8])> {
        let (wire, rest) = name_wire_from_bytes(bytes)?;
        Ok((Name(wire.into_boxed_slice()), rest))
    }

    /// The same, following compression pointers against the message `unpacker`
    /// was built over.
    pub fn from_wire_in<'a>(
        bytes: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> WireResult<(Name, &'a [u8])> {
        let (wire, rest) = name_wire_from_bytes_in(bytes, unpacker)?;
        Ok((Name(wire.into_boxed_slice()), rest))
    }

    /// Read presentation text, resolving RFC 1035 §5.1's escapes.
    ///
    /// The text is taken as **absolute**: a trailing `.` is optional and adds
    /// nothing, because there is no origin here to resolve against. A zone
    /// file's relative name is joined to its origin before it arrives.
    ///
    /// `\.` is a dot *inside* a label and `\\` a backslash — the two octets
    /// #13e had to refuse, because presentation storage could not tell either
    /// of them from the separator.
    pub fn from_presentation(text: &str) -> WireResult<Name> {
        if text.is_empty() || text == "." {
            return Ok(Name::root());
        }
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() + 2);
        // Where the current label's length octet is reserved, or `None` between
        // labels. Reserved on the first octet of a label rather than after each
        // separator, so a trailing dot leaves nothing half-written.
        let mut label_start: Option<usize> = None;
        let mut i = 0;
        while i < bytes.len() {
            let byte = match bytes[i] {
                b'\\' => {
                    let (decoded, used) = decode_escape(&bytes[i..])?;
                    i += used;
                    decoded
                }
                b'.' => {
                    i += 1;
                    let Some(start) = label_start.take() else {
                        return Err(WireError::malformed(
                            "a domain name",
                            "a label may not be empty",
                        ));
                    };
                    let len = out.len() - start - 1;
                    finish_label(&mut out, start, len)?;
                    continue;
                }
                other => {
                    i += 1;
                    other
                }
            };
            if label_start.is_none() {
                label_start = Some(out.len());
                out.push(0);
            }
            out.push(byte);
        }
        // A name that did not end on a separator still owes its last length.
        if let Some(start) = label_start {
            let len = out.len() - start - 1;
            finish_label(&mut out, start, len)?;
        }
        out.push(0);
        check_name_len(out.len())?;
        Ok(Name(out.into_boxed_slice()))
    }
}

/// Write a label's length into the octet reserved for it.
fn finish_label(out: &mut [u8], start: usize, len: usize) -> WireResult<()> {
    if len > MAX_LABEL_LEN {
        return Err(WireError::TooLong {
            what: "a label",
            limit: MAX_LABEL_LEN,
            actual: len,
        });
    }
    out[start] = len as u8;
    Ok(())
}

/// One escape from the front of `bytes`, and how many octets it spanned.
///
/// RFC 1035 §5.1, the grammar `utils::char_string_decode` reads: `\X` is a
/// literal `X`, `\DDD` is one octet, and the digit form is exactly three
/// digits. Not that function, because this one runs inside a label walk and
/// returns one octet at a time rather than decoding a whole string.
fn decode_escape(bytes: &[u8]) -> WireResult<(u8, usize)> {
    let Some(&next) = bytes.get(1) else {
        return Err(WireError::malformed(
            "a domain name",
            "it ends with a backslash, which escapes nothing",
        ));
    };
    if !next.is_ascii_digit() {
        return Ok((next, 2));
    }
    let Some(digits) = bytes.get(1..4).filter(|d| d.iter().all(u8::is_ascii_digit)) else {
        return Err(WireError::malformed(
            "a domain name",
            "a backslash before a digit begins a three-digit decimal escape",
        ));
    };
    let value = (digits[0] - b'0') as u16 * 100
        + (digits[1] - b'0') as u16 * 10
        + (digits[2] - b'0') as u16;
    let byte = u8::try_from(value).map_err(|_| {
        WireError::malformed(
            "a domain name",
            format!("the decimal escape \\{value:03} is over 255"),
        )
    })?;
    Ok((byte, 4))
}

impl<'a> NameRef<'a> {
    /// The wire octets, root terminator included.
    pub fn as_wire(&self) -> &'a [u8] {
        self.0
    }

    /// Whether this is the root, which is the only name with no labels.
    pub fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    /// The labels, without their length octets and without the root.
    pub fn labels(&self) -> impl Iterator<Item = &'a [u8]> {
        let mut rest = self.0;
        std::iter::from_fn(move || {
            let (&len, tail) = rest.split_first()?;
            let len = len as usize;
            if len == 0 || tail.len() < len {
                return None;
            }
            let (label, next) = tail.split_at(len);
            rest = next;
            Some(label)
        })
    }

    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// This name with its first label removed — its parent in the tree.
    ///
    /// `None` at the root alone. Borrowed rather than built: a suffix of a
    /// wire-form name at a label boundary is a name, which is what makes the
    /// walk to a zone's apex free.
    pub fn parent(&self) -> Option<NameRef<'a>> {
        let (&len, tail) = self.0.split_first()?;
        let len = len as usize;
        if len == 0 || tail.len() < len {
            return None;
        }
        Some(NameRef(&tail[len..]))
    }

    /// This name, then every ancestor, ending at the root.
    pub fn ancestors(&self) -> impl Iterator<Item = NameRef<'a>> {
        let mut next = Some(*self);
        std::iter::from_fn(move || {
            let current = next?;
            next = current.parent();
            Some(current)
        })
    }

    /// Whether this name is `other` or sits below it.
    ///
    /// Whole labels, always. The wire form cannot express a partial one, which
    /// is the half of the rule a string-suffix test gets wrong: `ab.example.com`
    /// is not under `b.example.com`.
    pub fn is_at_or_under(&self, other: NameRef<'_>) -> bool {
        if other.0.len() > self.0.len() {
            return false;
        }
        // Walked rather than subtracted, because the walk is what proves the
        // suffix begins at a label boundary.
        self.ancestors()
            .find(|ancestor| ancestor.0.len() <= other.0.len())
            .is_some_and(|ancestor| ancestor == other)
    }

    /// The name folded to lower case, for use as a `HashMap` key.
    ///
    /// Borrowed when there is nothing to fold, which is every name that arrived
    /// in lower case — so the ordinary query pays nothing and a DNS-0x20 one
    /// pays a copy. The single place a fold survives; see this module's header
    /// for why `Borrow` cannot remove it.
    pub fn folded(&self) -> Cow<'a, [u8]> {
        if self.0.iter().any(u8::is_ascii_uppercase) {
            Cow::Owned(self.0.to_ascii_lowercase())
        } else {
            Cow::Borrowed(self.0)
        }
    }

    /// The name as zone-file text, escaping what RFC 1035 §5.1 requires.
    ///
    /// Always absolute: the root is `"."` and everything else ends in one.
    pub fn to_presentation(&self) -> String {
        if self.is_root() {
            return ".".to_string();
        }
        let mut out = String::with_capacity(self.0.len() + 8);
        for label in self.labels() {
            escape_label(label, &mut out);
            out.push('.');
        }
        out
    }

    pub fn to_owned(&self) -> Name {
        Name(self.0.to_vec().into_boxed_slice())
    }
}

/// One label as presentation text.
///
/// Not `utils::char_string_escaped`: a label must escape `.`, which separates
/// labels and is ordinary data inside one, and need not escape `"`, which means
/// nothing outside a quoted character-string. Two rules that overlap without
/// either containing the other, so two functions — `CLAUDE.md` §7 is about one
/// rule written twice, not about two rules that resemble each other.
fn escape_label(label: &[u8], out: &mut String) {
    for &byte in label {
        match byte {
            b'.' | b'\\' => {
                out.push('\\');
                out.push(byte as char);
            }
            0x21..=0x7e => out.push(byte as char),
            other => out.push_str(&format!("\\{other:03}")),
        }
    }
}

// Case-insensitive throughout, and ASCII-only: `str::to_lowercase` folds
// U+212A KELVIN SIGN onto `k` and merges two names that differ on the wire
// (RFC 4343). `Eq` and `Hash` agree by construction, both folding the same
// octets the same way.

impl PartialEq for NameRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Eq for NameRef<'_> {}

impl Hash for NameRef<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for &byte in self.0 {
            state.write_u8(byte.to_ascii_lowercase());
        }
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq<NameRef<'_>> for Name {
    fn eq(&self, other: &NameRef<'_>) -> bool {
        self.as_ref() == *other
    }
}

impl PartialEq<Name> for NameRef<'_> {
    fn eq(&self, other: &Name) -> bool {
        *self == other.as_ref()
    }
}

impl std::fmt::Display for NameRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_presentation())
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

impl std::fmt::Debug for NameRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.to_presentation())
    }
}

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::collections::HashMap;

    fn wire(name: &str) -> Vec<u8> {
        Name::from_presentation(name)
            .unwrap()
            .as_ref()
            .as_wire()
            .to_vec()
    }

    fn hash_of(name: NameRef<'_>) -> u64 {
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn presentation_and_wire_are_inverses() {
        for (text, bytes) in [
            (".", vec![0u8]),
            ("com.", vec![3, b'c', b'o', b'm', 0]),
            (
                "example.com.",
                vec![
                    7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
                ],
            ),
            // Absolute either way: there is no origin here to resolve against.
            (
                "example.com",
                vec![
                    7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
                ],
            ),
        ] {
            assert_eq!(wire(text), bytes, "{text}");
            let name = Name::from_presentation(text).unwrap();
            let back = name.as_ref().to_presentation();
            assert_eq!(
                Name::from_presentation(&back).unwrap(),
                name,
                "{text} -> {back}"
            );
        }
    }

    /// **This is D-1.** A label is "any binary string" (RFC 2181 §11), and the
    /// three cases below are what presentation storage could not hold: an octet
    /// that is not UTF-8, a dot *inside* a label, and a backslash.
    ///
    /// The middle one is also the injectivity case: the one-label name `a.b`
    /// and the two-label `a`,`b` read as the same text and must not be the same
    /// name.
    #[test]
    fn a_label_may_hold_any_octet() {
        // Not UTF-8: 0xff is not a valid first byte of any UTF-8 sequence.
        let binary = Name::from_presentation(r"\255.example.com.").unwrap();
        assert_eq!(binary.as_ref().labels().next().unwrap(), &[0xffu8]);
        assert_eq!(binary.as_ref().to_presentation(), r"\255.example.com.");
        assert_eq!(
            Name::from_presentation(r"\255.example.com.").unwrap(),
            binary
        );

        // A dot inside a label, and the two-label name it is not.
        let one = Name::from_presentation(r"a\.b.").unwrap();
        let two = Name::from_presentation("a.b.").unwrap();
        assert_eq!(one.as_ref().label_count(), 1);
        assert_eq!(two.as_ref().label_count(), 2);
        assert_ne!(
            one, two,
            "two different names, and they used to be one string"
        );
        assert_eq!(one.as_ref().as_wire(), &[3, b'a', b'.', b'b', 0]);
        assert_eq!(two.as_ref().as_wire(), &[1, b'a', 1, b'b', 0]);
        assert_eq!(one.as_ref().to_presentation(), r"a\.b.");

        // And a backslash.
        let slash = Name::from_presentation(r"a\\b.").unwrap();
        assert_eq!(slash.as_ref().labels().next().unwrap(), br"a\b");
        assert_eq!(slash.as_ref().to_presentation(), r"a\\b.");
    }

    /// D-1 from the other side: the same name through the *wire*, which is the
    /// path `rdnsr` uses to relay somebody else's zone.
    ///
    /// `dname_from_bytes` — the presentation door — refuses this name, and that
    /// refusal is the deviation. The two are asserted together so the contrast
    /// is the test rather than a claim in a comment.
    #[test]
    fn a_non_utf8_label_survives_the_wire_where_the_string_form_refused_it() {
        // One label of a single 0xff octet, then `example`, then the root.
        let wire = [1u8, 0xff, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0];

        let (name, rest) = Name::from_wire(&wire).expect("a label is any binary string");
        assert!(rest.is_empty());
        assert_eq!(name.as_ref().labels().next().unwrap(), &[0xffu8]);
        // And it goes back out as the octets it arrived as.
        assert_eq!(name.as_ref().as_wire(), &wire);

        // The presentation pipeline cannot hold it, which is D-1: `String` is
        // UTF-8 and 0xff begins no UTF-8 sequence.
        let unpacker = DNameUnpacker::new(&wire);
        assert!(
            crate::dname::dname_from_bytes(&wire, &unpacker).is_err(),
            "the string form refuses it, and that refusal is the deviation"
        );
    }

    /// Every octet has a spelling and reads back as itself, so no name that
    /// arrives can fail to be written down.
    #[test]
    fn every_octet_survives_the_round_trip() {
        for byte in 0u8..=255 {
            let name = Name(Box::new([1, byte, 0]));
            let text = name.as_ref().to_presentation();
            assert_eq!(
                Name::from_presentation(&text).unwrap(),
                name,
                "{byte} spelled {text:?}"
            );
        }
    }

    /// Comparison folds ASCII and nothing else (RFC 4343). U+212A KELVIN SIGN
    /// is the case `str::to_lowercase` gets wrong: it folds onto `k` and merges
    /// two names that differ on the wire.
    #[test]
    fn comparison_folds_ascii_only() {
        let lower = Name::from_presentation("www.example.com.").unwrap();
        let mixed = Name::from_presentation("WwW.ExAmPlE.CoM.").unwrap();
        assert_eq!(lower, mixed);
        assert_eq!(hash_of(lower.as_ref()), hash_of(mixed.as_ref()));
        // Different octets, so a different name whatever it looks like.
        let kelvin = Name::from_presentation("\u{212A}.example.com.").unwrap();
        let k = Name::from_presentation("k.example.com.").unwrap();
        assert_ne!(kelvin, k);

        // Which is what lets a map be keyed on the name itself.
        let mut map: HashMap<Name, u8> = HashMap::new();
        map.insert(lower.clone(), 1);
        assert_eq!(map.get(&mixed), Some(&1));
    }

    /// The walk to a zone's apex, which runs once per label of a name the
    /// client chose — so it borrows.
    #[test]
    fn ancestors_are_suffixes_and_cost_nothing() {
        let name = Name::from_presentation("a.b.example.com.").unwrap();
        let seen: Vec<String> = name
            .as_ref()
            .ancestors()
            .map(|n| n.to_presentation())
            .collect();
        assert_eq!(
            seen,
            [
                "a.b.example.com.",
                "b.example.com.",
                "example.com.",
                "com.",
                "."
            ]
        );
        assert!(
            name.as_ref().parent().unwrap().as_wire().as_ptr() > name.as_ref().as_wire().as_ptr()
        );
        assert!(Name::root().as_ref().parent().is_none());
    }

    /// Whole labels, which is the test a string suffix gets wrong.
    #[test]
    fn is_at_or_under_matches_whole_labels() {
        let under = |a: &str, b: &str| {
            Name::from_presentation(a)
                .unwrap()
                .as_ref()
                .is_at_or_under(Name::from_presentation(b).unwrap().as_ref())
        };
        assert!(under("a.example.com.", "example.com."));
        assert!(under("example.com.", "example.com."));
        assert!(under("example.com.", "."));
        assert!(!under("example.com.", "a.example.com."));
        assert!(!under("com.", "example.com."));
        // The one a `str::ends_with` answers wrong.
        assert!(!under("ab.example.com.", "b.example.com."));
        // Case-insensitively, like everything else.
        assert!(under("A.ExAmPlE.CoM.", "example.com."));
    }

    /// A name off the wire, uncompressed and compressed, is the same name.
    #[test]
    fn wire_and_pointers_reach_the_same_name() {
        let message = [
            // A name at offset 0: example.com.
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            // At offset 13: www + a pointer back to offset 0.
            3, b'w', b'w', b'w', 0xc0, 0x00,
        ];
        let (plain, rest) = Name::from_wire(&message[..13]).unwrap();
        assert_eq!(plain, Name::from_presentation("example.com.").unwrap());
        assert!(rest.is_empty());

        let unpacker = DNameUnpacker::new(&message);
        let (compressed, rest) = Name::from_wire_in(&message[13..], &unpacker).unwrap();
        assert_eq!(
            compressed,
            Name::from_presentation("www.example.com.").unwrap()
        );
        assert!(rest.is_empty());

        // A pointer with no message to resolve it against is malformed, not
        // something to follow.
        assert!(Name::from_wire(&message[13..]).is_err());
    }

    /// The limits are RFC 1035 §2.3.4's, checked on the assembled name.
    #[test]
    fn the_length_limits_are_enforced() {
        let label = "a".repeat(MAX_LABEL_LEN);
        let ok = format!("{label}.{label}.{label}.{}.", "a".repeat(61));
        assert_eq!(
            Name::from_presentation(&ok)
                .unwrap()
                .as_ref()
                .as_wire()
                .len(),
            255
        );
        let over = format!("{label}.{label}.{label}.{}.", "a".repeat(62));
        assert!(Name::from_presentation(&over).is_err());

        assert!(Name::from_presentation(&format!("{}.", "a".repeat(MAX_LABEL_LEN + 1))).is_err());
        assert!(Name::from_presentation("a..b.").is_err());
        assert!(Name::from_presentation(".a.").is_err());
    }

    /// The three ways an escape can be malformed, refused rather than guessed
    /// at — each guess is a different name.
    #[test]
    fn a_malformed_escape_is_refused() {
        for text in [r"a\", r"a\1.b.", r"a\12.b.", r"a\256.b."] {
            assert!(
                Name::from_presentation(text).is_err(),
                "{text:?} should not parse"
            );
        }
    }

    /// One allocation per name, whatever it holds — the reason for wire form
    /// over a label per `Vec`.
    #[test]
    fn a_name_is_one_allocation() {
        let name = Name::from_presentation("a.b.c.d.e.example.com.").unwrap();
        assert_eq!(name.as_ref().label_count(), 7);
        // The `Box<[u8]>` is the whole of it; the ancestors borrow from it.
        assert_eq!(
            name.as_ref().ancestors().count(),
            8,
            "seven labels and the root"
        );
    }
}
