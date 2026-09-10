//! The presentation-text name helpers #36 left behind.
//!
//! A zone file is text, so text names do not go away: these fold and absolutize
//! what a parser reads and what an operator writes. What did go away is names as
//! *keys* — the caches hold folded wire octets now ([`crate::name_keys`],
//! `TODO.md` #38a) — which is why the escape-aware `.`-splitting that made a
//! text key safe is down to [`ends_with_root`] and nothing else walks a name as
//! text.

/// A name in the form DNS compares names by: ASCII case folded, and nothing else.
///
/// Case-insensitivity is ASCII-only (RFC 4343). `str::to_lowercase` folds U+212A
/// KELVIN SIGN into `k`, merging two names that differ on the wire — so any
/// table keyed by name reaches for this one.
pub fn ascii_lowered(name: &str) -> String {
    let mut owned = name.to_string();
    owned.make_ascii_lowercase();
    owned
}

/// Whether `name` holds an ASCII capital, and so needs folding at all.
///
/// A fold, not a search. `bytes().any(..)` exits on the first hit, and LLVM will
/// not vectorize a loop whose exit depends on the data — so it ran one byte per
/// iteration while the `make_ascii_lowercase` it exists to avoid ran thirty-two
/// (`TODO.md` #25g). Reducing with OR has no early exit and vectorizes, and the
/// name's length is the client's to choose.
///
/// `wrapping_sub(b'A') < 26` is `is_ascii_uppercase` without the second
/// comparison and a branch.
fn has_ascii_uppercase(name: &str) -> bool {
    name.bytes()
        .fold(0u8, |seen, b| seen | u8::from(b.wrapping_sub(b'A') < 26))
        != 0
}

/// A name in absolute form — the trailing root dot added if it is not there.
/// Borrows when the name already has one.
///
/// Not `rdns::zone::absolutize`, which resolves a *relative* zone-file name
/// against an origin. This one has no origin: it appends the root dot and
/// nothing more.
pub fn absolute(name: &str) -> std::borrow::Cow<'_, str> {
    if ends_with_root(name) {
        std::borrow::Cow::Borrowed(name)
    } else {
        std::borrow::Cow::Owned(format!("{name}."))
    }
}

/// A name in absolute, ASCII-lowercased form — the shape comparisons and map
/// keys in this crate assume. Borrows when the name is already both.
///
/// Not `rdns::zone::absolutize`; see [`absolute`].
pub fn absolute_lowered(name: &str) -> std::borrow::Cow<'_, str> {
    let needs_dot = !ends_with_root(name);
    let needs_fold = has_ascii_uppercase(name);
    if !needs_dot && !needs_fold {
        return std::borrow::Cow::Borrowed(name);
    }
    let mut owned = String::with_capacity(name.len() + usize::from(needs_dot));
    owned.push_str(name);
    owned.make_ascii_lowercase();
    if needs_dot {
        owned.push('.');
    }
    std::borrow::Cow::Owned(owned)
}

/// Whether the `.` at byte `at` separates two labels, or is one *inside* a
/// label.
///
/// RFC 1035 §5.1 spells a literal dot `\.` and a literal backslash `\\`, so a
/// dot is a separator exactly when an even number of backslashes precedes it.
/// Only presentation text has this ambiguity — [`crate::Name`] holds wire
/// octets, where a label carries its own length — so every helper below asks
/// this one function instead of splitting on `.` for itself (`CLAUDE.md` §7).
///
/// It began to matter when RFC 9460's presentation form (`TODO.md` #35) and
/// `Name` (#36) between them made such a name loadable, signable and servable.
/// Before that a `\` in an owner was refused at the door and counting dots was
/// right by accident.
fn separates_labels(bytes: &[u8], at: usize) -> bool {
    let mut back = at;
    while back > 0 && bytes[back - 1] == b'\\' {
        back -= 1;
    }
    (at - back).is_multiple_of(2)
}

/// Whether `name` ends in the root separator, as opposed to a label that ends
/// in an escaped dot — `foo\.` is one relative label, not `foo` at the root.
pub fn ends_with_root(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty() && bytes[bytes.len() - 1] == b'.' && separates_labels(bytes, bytes.len() - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absolute and folded, borrowing when it is already both.
    #[test]
    fn absolute_lowering_copies_only_when_it_has_something_to_do() {
        use std::borrow::Cow;
        assert!(matches!(
            absolute_lowered("www.example.com."),
            Cow::Borrowed("www.example.com.")
        ));
        assert!(matches!(
            absolute_lowered("www.example.com"),
            Cow::Owned(ref n) if n == "www.example.com."
        ));
        assert!(matches!(
            absolute_lowered("WWW.Example.COM."),
            Cow::Owned(ref n) if n == "www.example.com."
        ));
        assert!(matches!(
            absolute_lowered("WWW.Example.COM"),
            Cow::Owned(ref n) if n == "www.example.com."
        ));
        // The empty name is the root, and gets the dot that says so.
        assert_eq!(absolute_lowered(""), ".");
        assert!(matches!(absolute_lowered("."), Cow::Borrowed(".")));

        // U+212A is upper case to `char::is_uppercase` and not to
        // `u8::is_ascii_uppercase`, so it takes the borrowing arm.
        assert!(matches!(
            absolute_lowered("\u{212A}.example.com."),
            Cow::Borrowed("\u{212A}.example.com.")
        ));
    }

    /// The fold has no early exit, so the classic mistakes are the ends: a
    /// capital in the last octet must still be seen, and `@` and `[` sit either
    /// side of `A`-`Z` in ASCII (`TODO.md` #25g).
    #[test]
    fn the_uppercase_scan_sees_both_ends_and_nothing_beside_them() {
        assert!(has_ascii_uppercase("example.coM"), "the last octet counts");
        assert!(has_ascii_uppercase("Example.com"), "and the first");
        assert!(!has_ascii_uppercase("example.com."));
        assert!(!has_ascii_uppercase(""));
        // 0x40 and 0x5b bracket the capitals; a `<= b'Z'` off by one takes them.
        assert!(!has_ascii_uppercase("@[`{-_0129"));
        assert!(has_ascii_uppercase("@A["), "and the range itself is right");
        assert!(has_ascii_uppercase("@Z["));
        // Non-ASCII is not folded at all (RFC 4343): U+212A KELVIN SIGN is not
        // a capital K here, and its bytes must not read as one either.
        assert!(!has_ascii_uppercase("\u{212a}.example.com."));
    }

    /// ASCII case folding, and nothing else (RFC 4343).
    #[test]
    fn ascii_lowering_does_not_fold_unicode_into_ascii() {
        assert_eq!(ascii_lowered("WWW.Example.COM."), "www.example.com.");
        // U+212A KELVIN SIGN lowercases to `k` under Unicode rules, and the two
        // are different bytes on the wire.
        assert_ne!(ascii_lowered("\u{212A}.example.com."), "k.example.com.");
        assert_eq!(
            "\u{212A}".to_lowercase(),
            "k",
            "which is what to_lowercase does"
        );
    }
}
