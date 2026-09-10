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
//! **Comparing two names no longer copies either.** [`NameRef`]'s `Eq` and
//! `Hash` fold ASCII as they go (RFC 4343), so the lowercased copy a comparison
//! used to make is gone. Two things still need the folded octets themselves: a
//! `HashMap` key, because `Borrow` cannot hand out a borrowed view of a type
//! carrying a lifetime without the `unsafe` pointer cast `str` uses and this
//! library has none; and DNSSEC's canonical form, which is down-cased by
//! definition (RFC 4034 §6.2). [`NameRef::folded`] serves the first and borrows
//! when the name is already lower case, which is the ordinary query;
//! [`NameRef::to_folded`] serves the second.
//!
//! A `Name` is always **absolute**. A relative name exists only in zone-file
//! text and is resolved against the origin before it becomes one, so nothing
//! below this type has to ask.

use crate::dname::{
    check_name_len, name_wire_from_bytes, name_wire_from_bytes_in, DNameUnpacker, MAX_LABEL_LEN,
    MAX_NAME_LEN,
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

    /// The name a message parser has already located, pointers resolved.
    ///
    /// The one door for a *record's owner*, which `RecordParts` carries as a
    /// parsed `DName` so that reading past it costs nothing.
    pub(crate) fn from_dname<'a>(
        name: crate::dname::DName<'a>,
        unpacker: &DNameUnpacker<'a>,
    ) -> WireResult<Name> {
        Ok(Name(unpacker.decode_wire(name)?.into_boxed_slice()))
    }

    /// Zone-file text that is relative to an origin (RFC 1035 §5.1): the labels
    /// of `text`, then `origin`.
    ///
    /// The caller has already decided the text *is* relative — `@`, the empty
    /// name and a trailing dot are the zone parser's to interpret, not this
    /// type's.
    pub fn relative_to(text: &str, origin: NameRef<'_>) -> WireResult<Name> {
        let head = Name::from_presentation(text)?;
        // Everything but the root terminator, which `origin` supplies.
        let head = &head.0[..head.0.len() - 1];
        let mut out = Vec::with_capacity(head.len() + origin.0.len());
        out.extend_from_slice(head);
        out.extend_from_slice(origin.0);
        check_name_len(out.len())?;
        Ok(Name(out.into_boxed_slice()))
    }

    /// `label` prepended to `parent` — how a wildcard name is built from the
    /// closest encloser (RFC 4592 §3.3.1).
    ///
    /// Octets, not text, so the label is taken as it is: a `*` here is the
    /// wildcard label and a label that happens to contain a `.` is one label.
    pub fn prefixed(label: &[u8], parent: NameRef<'_>) -> WireResult<Name> {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(WireError::TooLong {
                what: "a label",
                limit: MAX_LABEL_LEN,
                actual: label.len(),
            });
        }
        let parent = parent.as_wire();
        let mut out = Vec::with_capacity(1 + label.len() + parent.len());
        out.push(label.len() as u8);
        out.extend_from_slice(label);
        out.extend_from_slice(parent);
        check_name_len(out.len())?;
        Ok(Name(out.into_boxed_slice()))
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
        // Exactly one allocation, sized after the escapes have been resolved:
        // `Name` keeps a boxed slice, so a `Vec` grown and then shrunk would
        // copy twice.
        let mut buf = [0u8; MAX_NAME_LEN];
        let len = presentation_wire_in(text, &mut buf)?;
        Ok(Name(buf[..len].into()))
    }
}

/// Read presentation text into `buf` as wire octets, returning the length.
///
/// The spelling [`Name::from_presentation`] is built on, and the one a caller
/// that throws the bytes away should use: RFC 5155 §5 hashes a name per label
/// of the QNAME (§8.3) and keeps none of them, so the NSEC3 walk puts its
/// buffer on the stack. `buf` must hold [`MAX_NAME_LEN`] octets; a name that
/// does not fit is over §2.3.4's limit and is refused.
pub fn presentation_wire_in(text: &str, buf: &mut [u8]) -> WireResult<usize> {
    debug_assert!(buf.len() >= MAX_NAME_LEN, "a name needs 255 octets");
    if text.is_empty() || text == "." {
        buf[0] = 0;
        return Ok(1);
    }
    let bytes = text.as_bytes();
    let mut at = 0usize;
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
                finish_label(buf, start, at - start - 1)?;
                continue;
            }
            other => {
                i += 1;
                other
            }
        };
        if label_start.is_none() {
            label_start = Some(at);
            at = push(buf, at, 0)?;
        }
        at = push(buf, at, byte)?;
    }
    // A name that did not end on a separator still owes its last length.
    if let Some(start) = label_start {
        finish_label(buf, start, at - start - 1)?;
    }
    at = push(buf, at, 0)?;
    check_name_len(at)?;
    Ok(at)
}

/// One octet into `buf`, returning the position after it.
///
/// Running off the end is a name over RFC 1035 §2.3.4's limit, reported as such
/// rather than as a buffer failure. `actual` is 256 — the first length that does
/// not fit — not the name's full encoded length, which is not known without
/// decoding the rest of it; the limit is what an operator has to act on.
fn push(buf: &mut [u8], at: usize, byte: u8) -> WireResult<usize> {
    if at >= buf.len() {
        return Err(WireError::TooLong {
            what: "a domain name",
            limit: MAX_NAME_LEN,
            actual: at + 1,
        });
    }
    buf[at] = byte;
    Ok(at + 1)
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
/// RFC 1035 §5.1, the grammar `codecs::char_string_decode` reads: `\X` is a
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
    /// Borrow a name from octets that already hold one.
    ///
    /// Validating, and cheap — one walk of the labels — so there is no
    /// constructor here that trusts its caller. The case it exists for is a
    /// name folded into a scratch buffer for use as a map key: the fold
    /// preserves every length octet and label boundary, so what comes back is
    /// the same name in lower case.
    pub fn from_wire_slice(wire: &[u8]) -> WireResult<NameRef<'_>> {
        let mut pos = 0;
        loop {
            let Some(&len) = wire.get(pos) else {
                return Err(WireError::malformed(
                    "a domain name",
                    "the octets end before the root label",
                ));
            };
            let len = len as usize;
            if len > MAX_LABEL_LEN {
                return Err(WireError::TooLong {
                    what: "a label",
                    limit: MAX_LABEL_LEN,
                    actual: len,
                });
            }
            pos += 1 + len;
            if len == 0 {
                break;
            }
        }
        if pos != wire.len() {
            return Err(WireError::malformed(
                "a domain name",
                "octets follow the root label",
            ));
        }
        check_name_len(wire.len())?;
        Ok(NameRef(wire))
    }

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

    /// The last `labels` labels of this name. Asking for more than it has
    /// yields the whole name.
    ///
    /// An ancestor counted from the other end — which is how QNAME
    /// minimisation asks for it (RFC 9156 §2.3), one label deeper each round.
    pub fn suffix(&self, labels: usize) -> NameRef<'a> {
        let skip = self.label_count().saturating_sub(labels);
        self.ancestors()
            .nth(skip)
            .unwrap_or(NameRef(&self.0[self.0.len() - 1..]))
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

    /// This name folded to lower case, as a name.
    ///
    /// The buffer is the caller's, so a name already in lower case — the
    /// ordinary query — borrows and costs nothing, and a DNS-0x20 one costs one
    /// copy into a buffer a server reuses. Returns a `NameRef` rather than
    /// octets so that no constructor here has to trust unvalidated bytes:
    /// folding changes no length octet and no label boundary, so the result is
    /// the same name and is known to be one.
    pub fn folded_in<'b>(self, buf: &'b mut Vec<u8>) -> NameRef<'b>
    where
        'a: 'b,
    {
        if self.0.iter().any(u8::is_ascii_uppercase) {
            buf.clear();
            buf.extend(self.0.iter().map(u8::to_ascii_lowercase));
            NameRef(buf)
        } else {
            NameRef(self.0)
        }
    }

    /// This name folded to lower case, owned.
    ///
    /// DNSSEC's canonical form for a name is exactly this — "the DNS names ...
    /// are replaced by their lower-case equivalents" (RFC 4034 §6.2) — which
    /// over wire form is one pass and no re-encoding.
    pub fn to_folded(&self) -> Name {
        Name(self.0.to_ascii_lowercase().into_boxed_slice())
    }

    /// The name folded to lower case, for use as a `HashMap` key.
    ///
    /// Borrowed when there is nothing to fold, which is every name that arrived
    /// in lower case — so the ordinary query pays nothing and a DNS-0x20 one
    /// pays a copy. See this module's header for why `Borrow` cannot remove it.
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

/// One label as presentation text, escaped so a zone file reads it back as
/// the same octets.
///
/// Three groups, and the third is the one that is easy to miss:
///
/// - `.` and `\`, which are the separator and the escape.
/// - Anything outside printable ASCII, as `\DDD` — space included, since a
///   bare space ends a field.
/// - **The characters a zone file gives its own meaning**: `;` starts a
///   comment, `"` opens a quoted string, `(` and `)` group a line, `@` is the
///   origin and `$` begins a directive. A label may hold any of them
///   (RFC 2181 §11), and one written raw would be read back as syntax rather
///   than as data. RFC 1035 §5.1's `\X` covers every one of them.
///
/// Not `codecs::char_string_escaped`: that one escapes `"` and not `.`, because
/// a character-string's separator is the quote and a dot inside one is
/// ordinary. Two rules that overlap without either containing the other, so
/// two functions — `CLAUDE.md` §7 is about one rule written twice, not about
/// two rules that resemble each other.
fn escape_label(label: &[u8], out: &mut String) {
    for &byte in label {
        match byte {
            b'.' | b'\\' | b';' | b'"' | b'(' | b')' | b'@' | b'$' => {
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

/// Presentation text, parsed — [`Name::from_presentation`] under the spelling
/// a caller reaches for first.
///
/// Fallible, because text can fail to be a name: an escape that goes nowhere,
/// a label over 63 octets, a name over 255. That is the whole reason there is
/// no `From<&str>`.
impl std::str::FromStr for Name {
    type Err = WireError;

    fn from_str(text: &str) -> WireResult<Name> {
        Name::from_presentation(text)
    }
}

/// The root: the empty name, and what a `#[derive(Default)]` struct holding a
/// name means by "none yet".
impl Default for Name {
    fn default() -> Self {
        Name::root()
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

/// A name from a literal, for tests only: `Name` is fallible to build and a test
/// that writes a bad one should fail loudly at that line rather than threading a
/// `Result` through a fixture. `rdns::test_records::nm` is the same helper for
/// the crate above.
/// What a DNAME does to one query name (RFC 6672 §2.2).
///
/// Three answers rather than an `Option<Result<..>>`, because the caller
/// branches three ways: substitute and carry on, decline, or YXDOMAIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redirect {
    /// The substituted name: the labels of the query name above the DNAME's
    /// owner, followed by its target.
    To(Name),
    /// The query name is not strictly below the owner, so the DNAME says
    /// nothing about it — Table 1's `<no match>`, which the first and fifth
    /// rows share with the second.
    NoMatch,
    /// The substitution overflows RFC 1035 §2.3.4's 255 octets. "If this
    /// occurs, the server returns an RCODE of YXDOMAIN" (§2.2), and the
    /// resolver "return\[s\] an implementation-dependent error" (§3.4.1 step 4D).
    TooLong,
}

/// Apply a DNAME to a query name: RFC 6672 §2.2's substitution, and Table 1.
///
/// "A DNAME substitution is performed by replacing the suffix labels of the
/// name being sought matching the owner name of the DNAME resource record with
/// the string of labels in the RDATA field. The matching labels end with the
/// root label in all cases. Only whole labels are replaced."
///
/// **Whole labels is structural here.** Over wire form a suffix at a label
/// boundary is the only kind of suffix there is, so `ab.example.com.` simply is
/// not under `b.example.com.` — where the presentation form needed the rule
/// spelled out and a `str::ends_with` got it wrong. The root as owner or as
/// target needed a case of its own for the same reason, and does not now.
///
/// Strictly below, so the owner is not redirected by its own DNAME (§2.3) —
/// Table 1's second row, whose answer depends on the QTYPE and so is not a
/// substitution at all.
pub fn dname_redirect(qname: NameRef<'_>, owner: NameRef<'_>, target: NameRef<'_>) -> Redirect {
    if !qname.is_at_or_under(owner) || qname == owner {
        return Redirect::NoMatch;
    }
    let qwire = qname.as_wire();
    let prefix = &qwire[..qwire.len() - owner.as_wire().len()];
    let mut out = Vec::with_capacity(prefix.len() + target.as_wire().len());
    out.extend_from_slice(prefix);
    out.extend_from_slice(target.as_wire());
    match NameRef::from_wire_slice(&out) {
        Ok(name) => Redirect::To(name.to_owned()),
        // The only way octets that were two names can fail to be one is
        // §2.3.4's limit, which §2.2 answers with YXDOMAIN.
        Err(_) => Redirect::TooLong,
    }
}

#[cfg(test)]
pub(crate) fn nm(text: &str) -> Name {
    text.parse().expect("a test name parses")
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
    /// There is no presentation door left to contrast with — reading a name as
    /// text is what this replaced, and `dname.rs` lost that half — so what is
    /// asserted is that the octets arrive and leave unchanged.
    #[test]
    fn a_non_utf8_label_survives_the_wire() {
        // One label of a single 0xff octet, then `example`, then the root.
        let wire = [1u8, 0xff, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0];

        let (name, rest) = Name::from_wire(&wire).expect("a label is any binary string");
        assert!(rest.is_empty());
        assert_eq!(name.as_ref().labels().next().unwrap(), &[0xffu8]);
        // And it goes back out as the octets it arrived as.
        assert_eq!(name.as_ref().as_wire(), &wire);

        // And it has a spelling, which is what a zone file needs: `String` is
        // UTF-8 and 0xff begins no UTF-8 sequence, so the octet has to be
        // escaped rather than carried (RFC 1035 §5.1).
        assert_eq!(name.as_ref().to_presentation(), r"\255.example.");
        assert_eq!(Name::from_presentation(r"\255.example.").unwrap(), name);
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
        // RFC 1035 §5.1's escape is a dot *inside* a label, and on the wire it
        // is not a boundary at all — which is the half the text version of this
        // had to be taught (`TODO.md` #37a) and this one cannot get wrong.
        assert!(!under(r"x.a\.b.com.", "b.com."));
        assert!(under(r"x.a\.b.com.", r"a\.b.com."));
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

    /// RFC 6672 §2.2's Table 1, verbatim — the twelve inputs the spec has
    /// already committed to an answer for, corner cases and loops included.
    ///
    /// Row two, `example.com. / example.com. / example.net.`, is the RFC's
    /// `[0]`: "The result depends on the QTYPE. If the QTYPE = DNAME, then the
    /// result is `example.com.`, else `<no match>`." Neither is a substitution
    /// — the owner is not redirected by its own DNAME (§2.3) — so this function
    /// answers `NoMatch` and the caller decides what the QTYPE means.
    #[test]
    fn the_rfc_6672_substitution_table() {
        let no_match = Redirect::NoMatch;
        let to = |n: &str| Redirect::To(nm(n));
        for (qname, owner, target, want) in [
            ("com.", "example.com.", "example.net.", no_match.clone()),
            (
                "example.com.",
                "example.com.",
                "example.net.",
                no_match.clone(),
            ),
            (
                "a.example.com.",
                "example.com.",
                "example.net.",
                to("a.example.net."),
            ),
            (
                "a.b.example.com.",
                "example.com.",
                "example.net.",
                to("a.b.example.net."),
            ),
            (
                "ab.example.com.",
                "b.example.com.",
                "example.net.",
                no_match.clone(),
            ),
            (
                "foo.example.com.",
                "example.com.",
                "example.net.",
                to("foo.example.net."),
            ),
            (
                "a.x.example.com.",
                "x.example.com.",
                "example.net.",
                to("a.example.net."),
            ),
            (
                "a.example.com.",
                "example.com.",
                "y.example.net.",
                to("a.y.example.net."),
            ),
            (
                "cyc.example.com.",
                "example.com.",
                "example.com.",
                to("cyc.example.com."),
            ),
            (
                "cyc.example.com.",
                "example.com.",
                "c.example.com.",
                to("cyc.c.example.com."),
            ),
            ("shortloop.x.x.", "x.", ".", to("shortloop.x.")),
            ("shortloop.x.", "x.", ".", to("shortloop.")),
        ] {
            assert_eq!(
                dname_redirect(nm(qname).as_ref(), nm(owner).as_ref(), nm(target).as_ref()),
                want,
                "QNAME {qname} against {owner} DNAME {target}"
            );
        }
    }

    /// A DNAME at the root redirects every name but the root itself. Not in
    /// Table 1, and the one shape where the owner's text is the separator: the
    /// prefix is the whole query name, not the query name with its last
    /// character cut off.
    #[test]
    fn a_dname_at_the_root_keeps_the_whole_prefix() {
        assert_eq!(
            dname_redirect(
                nm("a.").as_ref(),
                nm(".").as_ref(),
                nm("example.net.").as_ref()
            ),
            Redirect::To(nm("a.example.net."))
        );
        assert_eq!(
            dname_redirect(
                nm(".").as_ref(),
                nm(".").as_ref(),
                nm("example.net.").as_ref()
            ),
            Redirect::NoMatch
        );
    }

    /// RFC 6672 §2.2: "suppose the target name of the DNAME RR is 250 octets in
    /// length (multiple labels), if an incoming QNAME that has a first label
    /// over 5 octets in length, the result would be a name over 255 octets. If
    /// this occurs, the server returns an RCODE of YXDOMAIN."
    ///
    /// The RFC's own arithmetic, so the target is built to exactly 250 encoded
    /// octets: four 49-octet labels and one of 48 are 4 × 50 + 49 = 249, and
    /// the root's terminator is the 250th.
    #[test]
    fn a_substitution_that_overflows_255_octets_is_yxdomain() {
        let label = "a".repeat(49);
        let last = "a".repeat(48);
        let target = format!("{label}.{label}.{label}.{label}.{last}.");
        assert_eq!(nm(&target).as_ref().as_wire().len(), 250);

        // One label of six octets over a 250-octet target: 250 + 7 = 257.
        assert_eq!(
            dname_redirect(
                nm("abcdef.example.com.").as_ref(),
                nm("example.com.").as_ref(),
                nm(&target).as_ref()
            ),
            Redirect::TooLong
        );
        // And one that fits: 250 + 2 = 252.
        assert!(matches!(
            dname_redirect(
                nm("a.example.com.").as_ref(),
                nm("example.com.").as_ref(),
                nm(&target).as_ref()
            ),
            Redirect::To(_)
        ));
    }

    /// Case is the client's on the left of the substitution and the zone's on
    /// the right, because the result is echoed as the owner of the synthesized
    /// CNAME (RFC 1034 §4.3.3) and a DNS-0x20 client compares it byte for byte.
    #[test]
    fn a_substitution_keeps_the_case_it_was_given() {
        assert_eq!(
            dname_redirect(
                nm("WwW.ExAmPlE.CoM.").as_ref(),
                nm("example.com.").as_ref(),
                nm("Example.Net.").as_ref()
            ),
            Redirect::To(nm("WwW.Example.Net."))
        );
    }
}
