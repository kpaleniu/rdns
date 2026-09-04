//! Name folding, timestamps, and record-type constants shared across the crate.

use crate::error::{DnssecError, DnssecResult};
use crate::{ParsedRecord, RecordData, Rtype};
use std::time::{SystemTime, UNIX_EPOCH};

/// DNS record type constants
pub mod record_types {
    use crate::Rtype;
    pub const A: Rtype = Rtype::new(1);
    pub const NS: Rtype = Rtype::new(2);
    pub const CNAME: Rtype = Rtype::new(5);
    pub const SOA: Rtype = Rtype::new(6);
    pub const PTR: Rtype = Rtype::new(12);
    pub const MX: Rtype = Rtype::new(15);
    pub const TXT: Rtype = Rtype::new(16);
    pub const AAAA: Rtype = Rtype::new(28);
    pub const DS: Rtype = Rtype::new(43);
    pub const RRSIG: Rtype = Rtype::new(46);
    pub const NSEC: Rtype = Rtype::new(47);
    pub const DNSKEY: Rtype = Rtype::new(48);
    pub const NSEC3: Rtype = Rtype::new(50);
    /// The salt and iteration count of a zone's NSEC3 chain (RFC 5155 §4). Held
    /// as opaque RDATA, so there is no `ParsedRecord` arm for it.
    pub const NSEC3PARAM: Rtype = Rtype::new(51);
    /// A QTYPE only, and over TCP alone (RFC 5936).
    pub const AXFR: Rtype = Rtype::new(252);
    /// The raw codes, so `Rtype::is_meta` and `Qtype`'s constants can be `const`
    /// without a second registry of numbers.
    pub const AXFR_CODE: u16 = 252;
    /// A QTYPE only (RFC 1995), and the one request carrying a record of its
    /// own: the client's SOA, saying which version it already holds.
    pub const IXFR: Rtype = Rtype::new(251);
    pub const IXFR_CODE: u16 = 251;
    /// A QTYPE only.
    pub const ANY: Rtype = Rtype::new(255);
    pub const ANY_CODE: u16 = 255;
}

/// WSAEMSGSIZE: the datagram was larger than the buffer offered for it. Rust has
/// no [`std::io::ErrorKind`] for it — it arrives as `Uncategorized` — so the raw
/// code is the only way to recognize it.
const WSAEMSGSIZE: i32 = 10040;

/// Whether a UDP receive error is about a datagram rather than about the health
/// of the socket.
///
/// Both servers end their receive loop, and with it the process, when `recv_from`
/// returns `Err`, so anything a remote party can provoke has to be recognized
/// here or it is a remote kill switch. Two such: Windows reports a stray ICMP
/// port-unreachable on the socket's *next* `recv_from`, and fails an oversized
/// receive (WSAEMSGSIZE) instead of truncating it.
pub fn recv_error_is_transient(e: &std::io::Error) -> bool {
    if e.raw_os_error() == Some(WSAEMSGSIZE) {
        return true;
    }
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            // The portable spelling of "that datagram did not fit".
            | std::io::ErrorKind::InvalidInput
    )
}

/// The receive buffer one datagram needs.
///
/// Not the EDNS payload size either server advertises: that bounds *responses*,
/// and a client may send anything a UDP length field can express.
pub const UDP_RECEIVE_BUFFER: usize = 65_535;

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

/// [`ascii_lowered`] without the copy when there is nothing to fold — which is
/// most names, and this sits on the query path.
pub fn ascii_lowered_cow(name: &str) -> std::borrow::Cow<'_, str> {
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(ascii_lowered(name))
    } else {
        std::borrow::Cow::Borrowed(name)
    }
}

/// Whether two names are the same name: ASCII case folding (RFC 4343) and a
/// trailing dot that is optional on either side.
///
/// Allocation-free — comparing is not the same operation as producing a
/// normalized name, and only the latter needs to allocate.
pub fn names_equal(a: &str, b: &str) -> bool {
    let a = a.strip_suffix('.').unwrap_or(a);
    let b = b.strip_suffix('.').unwrap_or(b);
    a.eq_ignore_ascii_case(b)
}

/// A random DNS transaction id. The one implementation: an id is not a security
/// boundary here, but that is no reason to make it predictable.
pub fn rand_id() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// A name in absolute form — the trailing root dot added if it is not there.
/// Borrows when the name already has one.
///
/// Not [`crate::zone::absolutize`], which resolves a *relative* zone-file name
/// against an origin. This one has no origin: it appends the root dot and
/// nothing more.
pub fn absolute(name: &str) -> std::borrow::Cow<'_, str> {
    if name.ends_with('.') {
        std::borrow::Cow::Borrowed(name)
    } else {
        std::borrow::Cow::Owned(format!("{name}."))
    }
}

/// A name in absolute, ASCII-lowercased form — the shape comparisons and map
/// keys in this crate assume. Borrows when the name is already both.
///
/// Not [`crate::zone::absolutize`]; see [`absolute`].
pub fn absolute_lowered(name: &str) -> std::borrow::Cow<'_, str> {
    let needs_dot = !name.ends_with('.');
    let needs_fold = name.bytes().any(|b| b.is_ascii_uppercase());
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

    /// Take ownership of a string that is already in key form.
    ///
    /// For `Zone`, whose key is `absolutize`-against-the-origin then fold, which
    /// [`NameKeyBuf::new`] cannot express because it has no origin. The debug
    /// check does not allocate: the allocation tests run in debug.
    pub fn from_folded(name: String) -> NameKeyBuf {
        debug_assert!(
            name.ends_with('.') && !name.bytes().any(|b| b.is_ascii_uppercase()),
            "from_folded was handed {name:?}, which is not in key form"
        );
        NameKeyBuf(name)
    }

    /// The key as text, for the callers that still hold names as `String`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
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

/// How many labels a name has, the root (`.`) being zero. `example.com.` is 2.
///
/// Neither case folding nor the trailing dot changes the answer, so this does
/// neither and allocates nothing.
pub fn label_count(name: &str) -> usize {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        0
    } else {
        trimmed.split('.').count()
    }
}

/// The parent of an absolute name: its first label removed. `None` at the root,
/// which terminates every walk up the tree.
///
/// A *relative* name loses its last label instead of terminating, so callers
/// pass a key form: absolute, and folded if the map they walk is.
pub fn parent_name(name: &str) -> Option<&str> {
    if name == "." {
        return None;
    }
    let (_first_label, rest) = name.split_once('.')?;
    Some(if rest.is_empty() { "." } else { rest })
}

/// The last `labels` labels of an absolute name, as a slice of it.
///
/// A suffix of whole labels *is* a slice, so walking up the tree costs nothing.
/// The owning spelling ([`crate::dnssec::suffix_labels`]) builds a `Vec` of the
/// labels, a `join` and a `format!` per candidate, and four walks paid that per
/// label of a name the client chose.
///
/// `name` must be absolute, and folded if it is compared against folded keys:
/// slicing can fix neither. Zero labels is the root; asking for more labels than
/// the name has yields the whole name.
pub fn suffix_labels(name: &str, labels: usize) -> &str {
    if labels == 0 {
        return ".";
    }
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return ".";
    }
    let start = trimmed
        .rmatch_indices('.')
        .nth(labels - 1)
        .map_or(0, |(dot, _)| dot + 1);
    &name[start..]
}

/// Whether `name` is `origin` or sits below it — "is this name in that zone".
///
/// A suffix match is not enough: `notexample.com.` ends with `example.com.` and
/// is a different name, so the boundary must land on a label separator. The
/// trailing dot is optional on either side; an empty origin is the root.
///
/// Compares bytes, ASCII case-insensitively (RFC 4343), so neither side has to
/// be folded first and no slice can land inside a multi-byte character.
pub fn is_at_or_under(name: &str, origin: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name).as_bytes();
    let origin = origin.strip_suffix('.').unwrap_or(origin).as_bytes();
    if origin.is_empty() {
        return true;
    }
    let Some(prefix) = name.len().checked_sub(origin.len()) else {
        return false;
    };
    name[prefix..].eq_ignore_ascii_case(origin) && (prefix == 0 || name[prefix - 1] == b'.')
}

/// The current Unix timestamp in seconds, or 0 if the clock is before the epoch.
///
/// # Examples
/// ```ignore
/// let now = current_unix_timestamp();
/// assert!(now > 0);
/// ```
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether now is outside the inception..expiration range, either side of it.
///
/// # Examples
/// ```ignore
/// let now = current_unix_timestamp() as u32;
/// assert!(is_time_expired(now + 3600, now)); // Future inception
/// assert!(is_time_expired(now - 7200, now - 3600)); // Expired
/// ```
pub fn is_time_expired(inception: u32, expiration: u32) -> bool {
    let now = current_unix_timestamp();
    now < (inception as u64) || now > (expiration as u64)
}

/// Whether a cache entry has expired.
///
/// # Examples
/// ```ignore
/// let now = current_unix_timestamp();
/// assert!(!is_cache_expired(now + 3600)); // Valid for 1 hour
/// assert!(is_cache_expired(now - 1)); // Already expired
/// ```
pub fn is_cache_expired(expires_at: u64) -> bool {
    current_unix_timestamp() >= expires_at
}

/// A DNSKEY's (algorithm, public_key, flags, protocol). Errors on any other type.
pub fn extract_dnskey_fields(key: &ParsedRecord) -> DnssecResult<(u8, Vec<u8>, u16, u8)> {
    match key {
        ParsedRecord::DNSKEY {
            algorithm,
            public_key,
            flags,
            protocol,
        } => Ok((*algorithm, public_key.clone(), *flags, *protocol)),
        _ => Err(DnssecError::parse("not a DNSKEY record")),
    }
}

/// The record type code of a stored record.
pub fn record_type_code(rdata: &RecordData) -> Rtype {
    rdata.rtype()
}

/// A record type name as its numeric code. `TYPEnnn` is accepted for any type
/// at all (RFC 3597 §5).
///
/// # Examples
/// ```ignore
/// assert_eq!(record_type_name_to_code("A"), Some(1));
/// assert_eq!(record_type_name_to_code("MX"), Some(15));
/// assert_eq!(record_type_name_to_code("TYPE1234"), Some(Rtype::new(1234)));
/// assert_eq!(record_type_name_to_code("UNKNOWN"), None);
/// ```
pub fn record_type_name_to_code(kind: &str) -> Option<Rtype> {
    match kind {
        "A" => Some(record_types::A),
        "NS" => Some(record_types::NS),
        "CNAME" => Some(record_types::CNAME),
        "SOA" => Some(record_types::SOA),
        "PTR" => Some(record_types::PTR),
        "MX" => Some(record_types::MX),
        "TXT" => Some(record_types::TXT),
        "AAAA" => Some(record_types::AAAA),
        "DS" => Some(record_types::DS),
        "DNSKEY" => Some(record_types::DNSKEY),
        "RRSIG" => Some(record_types::RRSIG),
        "NSEC" => Some(record_types::NSEC),
        "NSEC3" => Some(record_types::NSEC3),
        other => other
            .strip_prefix("TYPE")
            .or_else(|| other.strip_prefix("type"))
            .and_then(|n| n.parse::<u16>().ok())
            .map(Rtype::new),
    }
}

/// The mnemonic for a type code, or its `TYPEnnn` form (RFC 3597 §5) when this
/// library has none. Always a name [`record_type_name_to_code`] reads back.
pub fn record_type_name(code: Rtype) -> String {
    match code {
        record_types::A => "A".to_string(),
        record_types::NS => "NS".to_string(),
        record_types::CNAME => "CNAME".to_string(),
        record_types::SOA => "SOA".to_string(),
        record_types::PTR => "PTR".to_string(),
        record_types::MX => "MX".to_string(),
        record_types::TXT => "TXT".to_string(),
        record_types::AAAA => "AAAA".to_string(),
        record_types::DS => "DS".to_string(),
        record_types::DNSKEY => "DNSKEY".to_string(),
        record_types::RRSIG => "RRSIG".to_string(),
        record_types::NSEC => "NSEC".to_string(),
        record_types::NSEC3 => "NSEC3".to_string(),
        other => format!("TYPE{}", other.to_u16()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_equal_by_ascii_folding_and_an_optional_trailing_dot() {
        assert!(names_equal("EXAMPLE.COM.", "example.com"));
        assert!(names_equal("Example.Com", "EXAMPLE.COM."));
        assert!(names_equal("example.com.", "example.com."));
        assert!(!names_equal("example.com.", "other.com."));

        // The root, written either way.
        assert!(names_equal(".", "."));
        assert!(names_equal(".", ""));

        // A suffix is not a name.
        assert!(!names_equal("notexample.com.", "example.com."));

        // The fold is ASCII only (RFC 4343): U+212A KELVIN SIGN lowercases to
        // `k` under Unicode, and they are different bytes on the wire.
        assert!(!names_equal("\u{212A}.example.com.", "k.example.com."));
    }

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

    #[test]
    fn label_count_ignores_case_and_the_trailing_dot() {
        assert_eq!(label_count("."), 0);
        assert_eq!(label_count(""), 0);
        assert_eq!(label_count("com."), 1);
        assert_eq!(label_count("example.com"), 2);
        assert_eq!(label_count("www.example.com."), 3);
        assert_eq!(label_count("WWW.Example.COM."), 3);
    }

    /// The same answers [`crate::dnssec::suffix_labels`] gives, and the same
    /// bytes: a suffix of whole labels is a slice, so this must be a *slice* of
    /// the input and not merely equal to one.
    #[test]
    fn a_suffix_of_whole_labels_is_a_slice_of_the_name() {
        let name = "www.example.com.";
        assert_eq!(suffix_labels(name, 0), ".");
        assert_eq!(suffix_labels(name, 1), "com.");
        assert_eq!(suffix_labels(name, 2), "example.com.");
        assert_eq!(suffix_labels(name, 3), name);
        // More labels than the name has: the whole name.
        assert_eq!(suffix_labels(name, 9), name);
        assert_eq!(suffix_labels(".", 3), ".");

        // Borrowed, not built: the two agree on the answer and this one does not
        // allocate to give it.
        let inside = suffix_labels(name, 2);
        assert!(std::ptr::eq(inside.as_ptr(), name[4..].as_ptr()));
        for labels in 0..5 {
            assert_eq!(
                crate::dnssec::suffix_labels(name, labels),
                suffix_labels(name, labels)
            );
        }
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

    #[test]
    fn test_current_unix_timestamp() {
        let ts = current_unix_timestamp();
        assert!(ts > 0);

        let ts2 = current_unix_timestamp();
        assert!(ts2 >= ts);
    }

    #[test]
    fn test_is_time_expired_not_yet_valid() {
        let now = current_unix_timestamp() as u32;
        let inception = now + 3600; // 1 hour in future
        let expiration = now + 7200; // 2 hours in future

        assert!(is_time_expired(inception, expiration));
    }

    #[test]
    fn test_is_time_expired_already_expired() {
        let now = current_unix_timestamp() as u32;
        let inception = now - 7200; // 2 hours ago
        let expiration = now - 3600; // 1 hour ago

        assert!(is_time_expired(inception, expiration));
    }

    #[test]
    fn test_is_time_not_expired() {
        let now = current_unix_timestamp() as u32;
        let inception = now - 3600; // 1 hour ago
        let expiration = now + 3600; // 1 hour in future

        assert!(!is_time_expired(inception, expiration));
    }

    #[test]
    fn test_is_cache_expired_valid() {
        let now = current_unix_timestamp();
        let expires_at = now + 3600; // 1 hour from now

        assert!(!is_cache_expired(expires_at));
    }

    #[test]
    fn test_is_cache_expired_expired() {
        let now = current_unix_timestamp();
        let expires_at = now - 1; // Already expired

        assert!(is_cache_expired(expires_at));
    }

    #[test]
    fn test_extract_dnskey_fields() {
        let key = ParsedRecord::DNSKEY {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3, 4],
        };

        let result = extract_dnskey_fields(&key).expect("extract failed");
        assert_eq!(result.0, 8); // algorithm
        assert_eq!(result.1, vec![1, 2, 3, 4]); // public_key
        assert_eq!(result.2, 0x0100); // flags
        assert_eq!(result.3, 3); // protocol
    }

    #[test]
    fn test_extract_dnskey_fields_not_dnskey() {
        let record = ParsedRecord::DS {
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: vec![1, 2, 3],
        };

        let result = extract_dnskey_fields(&record);
        assert!(result.is_err());
    }

    #[test]
    fn test_record_type_code_standard() {
        use std::net::Ipv4Addr;

        let a_record =
            RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap();
        assert_eq!(record_type_code(&a_record), record_types::A);

        let aaaa_record =
            RecordData::from_parsed(&ParsedRecord::AAAA("::1".parse().unwrap())).unwrap();
        assert_eq!(record_type_code(&aaaa_record), record_types::AAAA);
    }

    #[test]
    fn test_record_type_code_dnssec() {
        let dnskey = RecordData::from_parsed(&ParsedRecord::DNSKEY {
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3],
        })
        .unwrap();
        assert_eq!(record_type_code(&dnskey), record_types::DNSKEY);

        let ds = RecordData::from_parsed(&ParsedRecord::DS {
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: vec![1, 2, 3],
        })
        .unwrap();
        assert_eq!(record_type_code(&ds), record_types::DS);
    }

    #[test]
    fn test_record_type_code_unknown() {
        let unknown = RecordData::from_parsed(&ParsedRecord::Unknown(Rtype::new(99))).unwrap();
        assert_eq!(record_type_code(&unknown), Rtype::new(99));
    }

    #[test]
    fn test_record_type_name_to_code() {
        assert_eq!(record_type_name_to_code("A"), Some(record_types::A));
        assert_eq!(record_type_name_to_code("AAAA"), Some(record_types::AAAA));
        assert_eq!(record_type_name_to_code("MX"), Some(record_types::MX));
        assert_eq!(
            record_type_name_to_code("DNSKEY"),
            Some(record_types::DNSKEY)
        );
        assert_eq!(record_type_name_to_code("UNKNOWN"), None);
    }

    /// RFC 3597 §5: any type at all can be named.
    #[test]
    fn test_generic_type_names_round_trip() {
        assert_eq!(record_type_name_to_code("TYPE1234"), Some(Rtype::new(1234)));
        assert_eq!(record_type_name_to_code("TYPE1"), Some(record_types::A));
        assert_eq!(record_type_name(Rtype::new(1234)), "TYPE1234");
        assert_eq!(record_type_name(record_types::A), "A");

        for code in [1u16, 15, 50, 99, 257, 65535] {
            let name = record_type_name(Rtype::new(code));
            assert_eq!(
                record_type_name_to_code(&name),
                Some(Rtype::new(code)),
                "{name} should read back as {code}"
            );
        }
    }

    /// A number that does not fit a TYPE code is not a type name.
    #[test]
    fn test_out_of_range_generic_type_name_is_rejected() {
        assert_eq!(record_type_name_to_code("TYPE65536"), None);
        assert_eq!(record_type_name_to_code("TYPE"), None);
        assert_eq!(record_type_name_to_code("TYPEA"), None);
    }

    /// The oversized-datagram case, tested through the raw code because
    /// WSAEMSGSIZE's `ErrorKind` is `Uncategorized` and carries no information.
    #[test]
    fn an_oversized_datagram_is_not_a_reason_to_stop_serving() {
        let too_big = std::io::Error::from_raw_os_error(WSAEMSGSIZE);
        assert!(
            recv_error_is_transient(&too_big),
            "WSAEMSGSIZE arrives as {:?}, which is why matching on the kind alone missed it",
            too_big.kind()
        );
    }

    #[test]
    fn a_stray_icmp_report_is_not_a_reason_to_stop_serving() {
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::NetworkUnreachable,
            std::io::ErrorKind::HostUnreachable,
        ] {
            assert!(
                recv_error_is_transient(&std::io::Error::from(kind)),
                "{kind:?}"
            );
        }
    }

    /// The predicate has to stay narrow: a server that cannot receive is not
    /// serving, and pretending otherwise looks healthy and answers nothing.
    #[test]
    fn a_broken_socket_is_still_fatal() {
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::AddrNotAvailable,
            std::io::ErrorKind::OutOfMemory,
        ] {
            assert!(
                !recv_error_is_transient(&std::io::Error::from(kind)),
                "{kind:?}"
            );
        }
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

    /// `notexample.com.` is the case worth naming: it ends with `example.com.`
    /// and belongs to somebody else, so a suffix match answers authoritatively
    /// for a zone we do not hold.
    #[test]
    fn a_name_is_under_a_zone_only_at_a_label_boundary() {
        assert!(is_at_or_under("www.example.com.", "example.com."));
        assert!(is_at_or_under("example.com.", "example.com."), "the apex");
        assert!(!is_at_or_under("notexample.com.", "example.com."));
        assert!(!is_at_or_under("example.com.", "www.example.com."), "above");
        assert!(!is_at_or_under("example.org.", "example.com."));

        // The trailing dot is optional on either side.
        assert!(is_at_or_under("www.example.com", "example.com."));
        assert!(is_at_or_under("www.example.com.", "example.com"));

        // The root contains everything, itself included.
        assert!(is_at_or_under("www.example.com.", "."));
        assert!(is_at_or_under(".", "."));

        // ASCII case folds; U+212A KELVIN SIGN does not become `k`.
        assert!(is_at_or_under("WWW.Example.COM.", "example.com."));
        assert!(!is_at_or_under("\u{212A}.example.com.", "k.example.com."));
    }

    /// The borrowing form folds the same octets and no others. U+212A is upper
    /// case to `char::is_uppercase` and not to `u8::is_ascii_uppercase`, so
    /// scanning with the former would take the copying arm and still not fold it.
    #[test]
    fn borrowing_ascii_lowering_copies_only_when_it_folds_something() {
        use std::borrow::Cow;
        assert!(matches!(
            ascii_lowered_cow("www.example.com."),
            Cow::Borrowed("www.example.com.")
        ));
        assert!(matches!(
            ascii_lowered_cow("WWW.Example.COM."),
            Cow::Owned(ref name) if name == "www.example.com."
        ));
        assert!(matches!(
            ascii_lowered_cow("\u{212A}.example.com."),
            Cow::Borrowed("\u{212A}.example.com.")
        ));
    }

    #[test]
    fn test_record_types_constants() {
        assert_eq!(record_types::A, record_types::A);
        assert_eq!(record_types::NS, record_types::NS);
        assert_eq!(record_types::CNAME, record_types::CNAME);
        assert_eq!(record_types::SOA, record_types::SOA);
        assert_eq!(record_types::PTR, record_types::PTR);
        assert_eq!(record_types::MX, record_types::MX);
        assert_eq!(record_types::TXT, record_types::TXT);
        assert_eq!(record_types::AAAA, record_types::AAAA);
        assert_eq!(record_types::DS, record_types::DS);
        assert_eq!(record_types::RRSIG, record_types::RRSIG);
        assert_eq!(record_types::NSEC, record_types::NSEC);
        assert_eq!(record_types::DNSKEY, record_types::DNSKEY);
        assert_eq!(record_types::NSEC3, record_types::NSEC3);
    }
}
