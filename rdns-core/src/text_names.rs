//! The presentation-text name helpers #36 left behind, and the map keys built
//! from them.
//!
//! Everything here compares or folds a name as *text*. A name is wire octets
//! now ([`crate::NameRef`]), where a label is length-prefixed and there is no
//! separator to mis-read, so each of these exists only because some map is
//! still keyed on that text — which is what `TODO.md` #38a is about. A module
//! rather than a corner of `utils`, so that item has something to delete.

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

/// [`absolute_lowered`] into a buffer the caller keeps, so a name that *does*
/// need folding costs no allocation either.
///
/// The only form a name may be a map key in: absolute and ASCII case-folded
/// (RFC 4343). One constructor, and it folds, so an insertion cannot skip it.
///
/// Borrowed lookup is `Borrow<str>` rather than an unsized `NameKey(str)`: the
/// `Path`/`PathBuf` shape needs a transmute, and this workspace has no `unsafe`.
/// A lookup therefore takes a `&str` the caller folded with [`absolute_lowered`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NameKeyBuf(String);

impl NameKeyBuf {
    /// Fold `name` into key form. The only way to make one.
    pub fn new(name: &str) -> NameKeyBuf {
        NameKeyBuf(absolute_lowered(name).into_owned())
    }

    /// The key as text, for the callers that still hold names as `String`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for NameKeyBuf {
    /// Lets `map.get(absolute_lowered(name).as_ref())` work without building a
    /// key, so the lookup path allocates nothing.
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NameKeyBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A cache key of a folded name and a query type, which can be looked up
/// without building one.
///
/// A `HashMap` reaches its key only through `Borrow`, and `Borrow<(str, Qtype)>`
/// cannot exist: a tuple with an unsized field is not a type. The borrowed form
/// is therefore a trait object over "a name and a type", which both this and a
/// plain `(&str, Qtype)` are. One virtual call per lookup, against the `String`
/// per lookup that a `(String, Qtype)` key costs on the resolver's hottest path
/// (`TODO.md` #25e).
///
/// Folding is [`NameKeyBuf`]'s, so a name and the same name without its trailing
/// dot are one key, as they are in every other map in this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameTypeKey {
    name: NameKeyBuf,
    qtype: crate::Qtype,
}

/// A name and a query type: [`NameTypeKey`] owned, `(&str, Qtype)` borrowed.
///
/// The `&str` must already be folded — [`absolute_lowered`] — because a lookup
/// compares bytes.
pub trait NameType {
    fn name(&self) -> &str;
    fn qtype(&self) -> crate::Qtype;
}

impl NameTypeKey {
    pub fn new(name: &str, qtype: crate::Qtype) -> NameTypeKey {
        NameTypeKey {
            name: NameKeyBuf::new(name),
            qtype,
        }
    }
}

impl NameType for NameTypeKey {
    fn name(&self) -> &str {
        self.name.as_str()
    }
    fn qtype(&self) -> crate::Qtype {
        self.qtype
    }
}

impl NameType for (&str, crate::Qtype) {
    fn name(&self) -> &str {
        self.0
    }
    fn qtype(&self) -> crate::Qtype {
        self.1
    }
}

/// Hashed field by field, and identically for the owned and borrowed forms:
/// `HashMap` requires that a key and what it is looked up by hash alike.
impl std::hash::Hash for NameTypeKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name().hash(state);
        self.qtype().hash(state);
    }
}

impl std::hash::Hash for dyn NameType + '_ {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name().hash(state);
        self.qtype().hash(state);
    }
}

impl PartialEq for dyn NameType + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name() && self.qtype() == other.qtype()
    }
}

impl Eq for dyn NameType + '_ {}

impl<'a> std::borrow::Borrow<dyn NameType + 'a> for NameTypeKey {
    fn borrow(&self) -> &(dyn NameType + 'a) {
        self
    }
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

/// The byte offsets of `name`'s label separators, left to right.
fn separators(name: &str) -> impl DoubleEndedIterator<Item = usize> + '_ {
    let bytes = name.as_bytes();
    (0..bytes.len()).filter(move |&i| bytes[i] == b'.' && separates_labels(bytes, i))
}

/// The parent of an absolute name: its first label removed. `None` at the root,
/// which terminates every walk up the tree.
///
/// A *relative* name loses its last label instead of terminating, so callers
/// pass a key form: absolute, and folded if the map they walk is.
///
/// The last of the presentation-text name helpers, and it has one caller:
/// `rdns::negative_cache` walks the ancestors of its own text keys
/// (`TODO.md` #38a). Ask a tree question about a *name* with
/// [`crate::NameRef`]'s `parent`, `ancestors` or `is_at_or_under` — the wire
/// form is what a label is, so there is nothing to get wrong about escapes.
pub fn parent_name(name: &str) -> Option<&str> {
    if name == "." {
        return None;
    }
    let cut = separators(name).next()?;
    let rest = &name[cut + 1..];
    Some(if rest.is_empty() { "." } else { rest })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record_types;

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

    /// The one text walk left: [`crate::negative_cache`]'s ancestors. The rule
    /// it must not get wrong is RFC 1035 §5.1's escape — `a\.b.com.` is two
    /// labels, so the parent of `x.a\.b.com.` steps over the whole first one.
    ///
    /// Its wire-form counterparts are tested in `name.rs`; what those cannot get
    /// wrong is exactly this, because a wire label is what its length octet
    /// says.
    #[test]
    fn a_parent_is_the_name_with_its_first_whole_label_removed() {
        assert_eq!(parent_name("www.example.com."), Some("example.com."));
        assert_eq!(parent_name("com."), Some("."));
        assert_eq!(parent_name("."), None);
        assert_eq!(parent_name(r"x.a\.b.com."), Some(r"a\.b.com."));
        assert_eq!(parent_name(r"a\.b.com."), Some("com."));
    }

    /// The whole point of the type: a key put in owned is found borrowed. If the
    /// two forms hashed differently every lookup would miss and a cache would
    /// silently never hit — the failure this test exists for.
    #[test]
    fn a_name_type_key_is_found_by_its_borrowed_form() {
        use crate::Qtype;
        use std::collections::HashMap;

        let a = Qtype::of(record_types::A);
        let aaaa = Qtype::of(record_types::AAAA);
        let mut map: HashMap<NameTypeKey, u8> = HashMap::new();
        map.insert(NameTypeKey::new("WWW.Example.COM", a), 1);

        let probe: &dyn NameType = &("www.example.com.", a);
        assert_eq!(map.get(probe), Some(&1), "the folded name, borrowed");
        let other_type: &dyn NameType = &("www.example.com.", aaaa);
        assert_eq!(map.get(other_type), None, "the type is part of the key");
        let other_name: &dyn NameType = &("ww.example.com.", a);
        assert_eq!(map.get(other_name), None);

        // Unfolded: the borrowed form compares bytes, so this is the caller's
        // job and the doc comment says so.
        let unfolded: &dyn NameType = &("WWW.Example.COM.", a);
        assert_eq!(map.get(unfolded), None);
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
