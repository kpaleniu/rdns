//! A name as a map key, and a name and a type as one.
//!
//! Folded wire octets, not folded text. `TODO.md` #38a: the caches were the last
//! thing holding a name as presentation text, and text made them pay twice — a
//! `String` per probe at the call site, because what arrives off the wire is a
//! [`crate::NameRef`], and an escape-aware `.`-splitter to fold and walk it,
//! because presentation text can spell a dot two ways and wire octets cannot.
//!
//! Folding on the way in is the invariant, and the constructors are the only way
//! in, so an insertion cannot skip it (`CLAUDE.md` §17). It is not
//! [`crate::NameRef`]'s own case-folding `Hash` and `Eq` that does the work
//! here: a `HashMap` reaches its key only through `Borrow`, and a `Name` cannot
//! borrow to a `NameRef` — so the key is the octets and the borrowed form is
//! `[u8]`, which is the `Path`/`PathBuf` shape without a transmute.

use crate::{NameRef, Qtype};

/// A name in the one form a map key may take: ASCII case-folded wire octets
/// (RFC 4343).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NameKeyBuf(Box<[u8]>);

impl NameKeyBuf {
    /// Fold `name` into key form. The only way to make one.
    pub fn new(name: NameRef<'_>) -> NameKeyBuf {
        NameKeyBuf(name.folded().into_owned().into_boxed_slice())
    }

    /// The key as the name it is. Infallible: it was a name on the way in, and
    /// folding does not change a length octet.
    pub fn as_name(&self) -> NameRef<'_> {
        NameRef::from_wire_slice(&self.0).expect("a key was a name when it was made")
    }
}

impl std::borrow::Borrow<[u8]> for NameKeyBuf {
    /// Lets `map.get(name.folded().as_ref())` work without building a key, so
    /// the lookup path allocates nothing for a name that is already folded —
    /// which is most of them.
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for NameKeyBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_name())
    }
}

/// A cache key of a folded name and a query type, which can be looked up
/// without building one.
///
/// A `HashMap` reaches its key only through `Borrow`, and `Borrow<([u8], Qtype)>`
/// cannot exist: a tuple with an unsized field is not a type. The borrowed form
/// is therefore a trait object over "a name and a type", which both this and a
/// plain `(&[u8], Qtype)` are. One virtual call per lookup, against the
/// allocation per lookup that an owned key costs on the resolver's hottest path
/// (`TODO.md` #25e).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameTypeKey {
    name: NameKeyBuf,
    qtype: Qtype,
}

/// A name and a query type: [`NameTypeKey`] owned, `(&[u8], Qtype)` borrowed.
///
/// The octets must already be folded — [`NameRef::folded`] — because a lookup
/// compares bytes.
pub trait NameType {
    fn name(&self) -> &[u8];
    fn qtype(&self) -> Qtype;
}

impl NameTypeKey {
    pub fn new(name: NameRef<'_>, qtype: Qtype) -> NameTypeKey {
        NameTypeKey {
            name: NameKeyBuf::new(name),
            qtype,
        }
    }
}

impl NameType for NameTypeKey {
    fn name(&self) -> &[u8] {
        &self.name.0
    }
    fn qtype(&self) -> Qtype {
        self.qtype
    }
}

impl NameType for (&[u8], Qtype) {
    fn name(&self) -> &[u8] {
        self.0
    }
    fn qtype(&self) -> Qtype {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::nm;
    use crate::record_types;
    use std::collections::HashMap;

    /// The whole point of the type: a key put in owned is found borrowed. If the
    /// two forms hashed differently every lookup would miss and a cache would
    /// silently never hit — the failure this test exists for.
    #[test]
    fn a_name_type_key_is_found_by_its_borrowed_form() {
        let a = Qtype::of(record_types::A);
        let aaaa = Qtype::of(record_types::AAAA);
        let mut map: HashMap<NameTypeKey, u8> = HashMap::new();
        map.insert(NameTypeKey::new(nm("WWW.Example.COM.").as_ref(), a), 1);

        let folded = nm("www.example.com.");
        let probe: &dyn NameType = &(folded.as_ref().as_wire(), a);
        assert_eq!(map.get(probe), Some(&1), "the folded name, borrowed");
        let other_type: &dyn NameType = &(folded.as_ref().as_wire(), aaaa);
        assert_eq!(map.get(other_type), None, "the type is part of the key");
        let shorter = nm("ww.example.com.");
        let other_name: &dyn NameType = &(shorter.as_ref().as_wire(), a);
        assert_eq!(map.get(other_name), None);

        // Unfolded: the borrowed form compares octets, so folding is the
        // caller's job and the doc comment says so.
        let unfolded = nm("WWW.Example.COM.");
        let probe: &dyn NameType = &(unfolded.as_ref().as_wire(), a);
        assert_eq!(map.get(probe), None);
    }

    /// A key is the name it was made from, whatever case it arrived in — which
    /// is what lets the metrics gauges print one back as a label.
    #[test]
    fn a_key_reads_back_as_the_name_it_folded() {
        let key = NameKeyBuf::new(nm("WWW.Example.COM.").as_ref());
        assert_eq!(key.as_name(), nm("www.example.com.").as_ref());
        assert_eq!(key.to_string(), "www.example.com.");
    }
}
