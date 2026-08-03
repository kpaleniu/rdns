//! Shared utility functions for RDNSC
//!
//! This module contains common functions that are used across multiple modules
//! to eliminate code duplication and provide a consistent interface for:
//! - Domain name normalization
//! - Unix timestamp retrieval
//! - Expiration checking
//! - Record type constants and conversion

use crate::error::{DnssecError, DnssecResult};
use crate::{ParsedRecord, RecordData, Rtype};
use std::time::{SystemTime, UNIX_EPOCH};

/// DNS record type constants
pub mod record_types {
    use crate::Rtype;
    /// A record (IPv4 address)
    pub const A: Rtype = Rtype::new(1);
    /// NS record (nameserver)
    pub const NS: Rtype = Rtype::new(2);
    /// CNAME record (canonical name)
    pub const CNAME: Rtype = Rtype::new(5);
    /// SOA record (start of authority)
    pub const SOA: Rtype = Rtype::new(6);
    /// PTR record (pointer)
    pub const PTR: Rtype = Rtype::new(12);
    /// MX record (mail exchange)
    pub const MX: Rtype = Rtype::new(15);
    /// TXT record (text)
    pub const TXT: Rtype = Rtype::new(16);
    /// AAAA record (IPv6 address)
    pub const AAAA: Rtype = Rtype::new(28);
    /// DS record (delegation signer)
    pub const DS: Rtype = Rtype::new(43);
    /// RRSIG record (DNSSEC signature)
    pub const RRSIG: Rtype = Rtype::new(46);
    /// NSEC record (next secure)
    pub const NSEC: Rtype = Rtype::new(47);
    /// DNSKEY record (DNSSEC key)
    pub const DNSKEY: Rtype = Rtype::new(48);
    /// NSEC3 record (next secure v3)
    pub const NSEC3: Rtype = Rtype::new(50);
    /// NSEC3PARAM — the salt and iteration count a zone's NSEC3 chain was built
    /// with, published at the apex so an authoritative server can find the chain
    /// it is meant to answer from (RFC 5155 §4). It carries no names and is
    /// stored as opaque RDATA rather than parsed, which is why there is no
    /// `ParsedRecord` arm for it.
    pub const NSEC3PARAM: Rtype = Rtype::new(51);
    /// AXFR — a whole-zone transfer. A QTYPE only: no record ever has this type,
    /// and it is defined over TCP alone (RFC 5936).
    pub const AXFR: Rtype = Rtype::new(252);
    /// The raw code, so [`crate::Rtype::is_meta`] and [`crate::Qtype`]'s
    /// constants can be `const` without a second registry of numbers.
    pub const AXFR_CODE: u16 = 252;
    /// IXFR — an incremental transfer (RFC 1995). A QTYPE only, and the one
    /// request that carries a record of its own: the client's SOA, in the
    /// authority section, saying which version it already holds.
    pub const IXFR: Rtype = Rtype::new(251);
    /// The raw code, so [`crate::Rtype::is_meta`] and [`crate::Qtype`]'s
    /// constants can be `const` without a second registry of numbers.
    pub const IXFR_CODE: u16 = 251;
    /// ANY (`*`) — also a QTYPE only.
    pub const ANY: Rtype = Rtype::new(255);
    /// The raw code, so [`crate::Rtype::is_meta`] and [`crate::Qtype`]'s
    /// constants can be `const` without a second registry of numbers.
    pub const ANY_CODE: u16 = 255;
}

// `normalize_domain_name` and `normalize_domain_name_for_comparison` used to be
// here, and they were the trap this module also documents the cure for: their
// body was `name.to_lowercase()`, the full Unicode fold, which turns U+212A
// KELVIN SIGN into `k` and so makes two names that differ on the wire compare
// equal (RFC 4343, `CLAUDE.md` §8 — and see [`ascii_lowered`] below, which
// spends a paragraph saying why). Nothing outside their own tests ever called
// them, but they had the obvious name, which is worse than useless: the next
// module to need this would have reached for them. Deleted rather than fixed —
// [`names_equal`] and [`absolute_lowered`] are what they should have been, and
// two functions doing this is how the count got to nine (`TODO.md` #13b).

/// WSAEMSGSIZE: the datagram was larger than the buffer offered for it.
///
/// Windows fails the receive rather than truncating, and Rust has no
/// [`std::io::ErrorKind`] for it — it arrives as `Uncategorized`, which no
/// `matches!` on kinds can catch, so the raw code is the only way to recognize
/// it.
const WSAEMSGSIZE: i32 = 10040;

/// Whether a UDP receive error is about a *previous* datagram, or about the one
/// just dropped, rather than about the health of the socket.
///
/// Both servers end their receive loop — and with it the process — when
/// `recv_from` returns `Err`. So anything a remote party can provoke has to be
/// recognized here, or it is a remote kill switch. This lives in the library
/// because it was written twice, in `rdnsd` and in `rdnsr`, and the second
/// oversight below was found in one copy only.
///
/// **A stray ICMP report.** A server that replies to a client which has already
/// gone away gets an ICMP port-unreachable back, and Windows reports it on the
/// socket's **next** `recv_from` (WSAECONNRESET; `WSAENETRESET` for a TTL
/// expiry). Unix only does this on a connected socket, which is why the shape is
/// invisible there and fatal here — any client that closed its socket before our
/// reply landed could stop the server.
///
/// **An oversized datagram.** On Windows a datagram larger than the buffer makes
/// `recv_from` fail with WSAEMSGSIZE instead of truncating, so one large packet
/// from anywhere — before authentication, before the rate limiter, before any
/// zone is consulted — exited the process. Same class as the ICMP bug, and missed
/// because the original fix was a list of `ErrorKind`s and this error has no kind
/// of its own. On Unix the packet is truncated instead and then fails to parse,
/// so a receive buffer large enough for any datagram is the other half of the
/// fix.
///
/// Errors that are neither are still fatal, because a server that cannot receive
/// is not serving.
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
            // The portable spelling of "that datagram did not fit", which is
            // what some platforms report and what a future Rust may map
            // WSAEMSGSIZE onto.
            | std::io::ErrorKind::InvalidInput
    )
}

/// The receive buffer one datagram needs.
///
/// Not the EDNS payload size either server advertises: that is a statement about
/// *responses*, and a request is not bound by it. A client may send anything a
/// UDP length field can express.
pub const UDP_RECEIVE_BUFFER: usize = 65_535;

/// A name in the form DNS compares names by: ASCII case folded, and nothing
/// else.
///
/// The "and nothing else" is the point. DNS case-insensitivity is defined over
/// ASCII only (RFC 4343): the octets 0x41–0x5A match 0x61–0x7A and every other
/// octet matches only itself, because a label is a byte string and the protocol
/// has no idea what encoding is in it. `str::to_lowercase` applies the full
/// Unicode mapping instead, which folds codepoints *into* ASCII — U+212A KELVIN
/// SIGN becomes `k` — so two names that differ on the wire come out equal. Any
/// table keyed on the result then merges them, which for a cache means one
/// entry answering for two owners.
///
/// This lives here because it was independently written, correctly, in `zone`
/// and incorrectly in `cache`, with the comment explaining why only in the
/// former. Every keyed-by-name structure should reach for this one.
pub fn ascii_lowered(name: &str) -> String {
    let mut owned = name.to_string();
    owned.make_ascii_lowercase();
    owned
}

/// [`ascii_lowered`] without the copy when there is nothing to fold.
///
/// Most names are already lower case: a zone file is written the way its author
/// types names, and a query carries what the client was asked for.
/// `ascii_lowered` allocates for those anyway, and a lookup key is where that
/// gets paid several times per query — the DHAT profile had `zone::absolutize`
/// and the down-casing after it at four allocations per query, ~14% of the whole
/// answer path (`TODO.md` #9e).
///
/// A resolver using 0x20 encoding sends mixed case on purpose, so the copying
/// arm is a real path and not a corner: what happens then is exactly what
/// happened before, one allocation, after a scan that is cheaper than the copy
/// it was deciding about.
pub fn ascii_lowered_cow(name: &str) -> std::borrow::Cow<'_, str> {
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(ascii_lowered(name))
    } else {
        std::borrow::Cow::Borrowed(name)
    }
}

/// Whether two names are the same name, by the rules DNS compares them with:
/// ASCII case folding (RFC 4343) and a trailing dot that is optional on either
/// side.
///
/// **Allocation-free, and that is the point of it being here.** This was
/// `resolver::names_equal`, written as `normalize(a) == normalize(b)` where
/// `normalize` is `to_ascii_lowercase` plus a `format!` — so every comparison
/// built two `String`s and dropped them, inside `.any()` loops over an answer
/// section. Comparing is not the same operation as producing a normalized name,
/// and only the latter needs to allocate.
///
/// `eq_ignore_ascii_case` is the whole of the fold: the octets 0x41-0x5A match
/// 0x61-0x7A and every other byte matches only itself, which is exactly what
/// RFC 4343 says and exactly what `to_lowercase` does not do.
pub fn names_equal(a: &str, b: &str) -> bool {
    let a = a.strip_suffix('.').unwrap_or(a);
    let b = b.strip_suffix('.').unwrap_or(b);
    a.eq_ignore_ascii_case(b)
}

/// A random DNS transaction id.
///
/// **One implementation, because there were two of the same name with different
/// security properties** (`TODO.md` #19h, `docs/spec` D-3): `xfr::rand_id` used
/// `rand::thread_rng()`, and `rdnsd`'s used `SystemTime`'s `subsec_nanos()`
/// XOR-folded to 16 bits, so two NOTIFYs sent in the same clock tick shared an
/// id. The stated reason for the second — "a full CSPRNG is overkill for a
/// message we also match by source and opcode, and the workspace's `rand` is a
/// library dependency rather than this crate's" — held for the threat, and did
/// not make it a good idea to have two functions of one name that a reader would
/// assume were the same.
///
/// The dependency argument is what this removes: `rdns` already has `rand`, so
/// exposing the good one costs `rdnsd` nothing and needs no new dependency.
///
/// An id is not a security boundary here — a NOTIFY is matched by source address
/// and opcode as well, and a transfer runs over TCP — but "not a boundary" is a
/// reason to keep it cheap, not a reason to make it predictable.
pub fn rand_id() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen()
}

/// A name in absolute form — the trailing root dot added if it is not there.
///
/// **Six copies of these three lines existed** (`TODO.md` #19c): `rfc5011`,
/// `secondary`, `xfr` and `zone` byte-identical, `rdnsd::config` differing only
/// in a parameter name and `rdnsd::absolute_name` only in the function name.
/// That is what happens when the shared module is one accessor short — `utils`
/// had [`absolute_lowered`], which absolutizes *and* folds, and no way to ask
/// for only the first half. A caller that wanted the dot and not the fold had
/// nowhere to go, so it wrote the three lines.
///
/// Borrows when the name is already absolute, which is every name that arrived
/// off the wire; the copies all returned a fresh `String` unconditionally.
///
/// Not to be confused with [`crate::zone::absolutize`], which resolves a
/// *relative* zone-file name against an origin. This one has no origin to
/// resolve against: it appends the root dot and nothing more.
pub fn absolute(name: &str) -> std::borrow::Cow<'_, str> {
    if name.ends_with('.') {
        std::borrow::Cow::Borrowed(name)
    } else {
        std::borrow::Cow::Owned(format!("{name}."))
    }
}

/// A name in absolute, ASCII-lowercased form — the shape comparisons and map
/// keys in this crate assume.
///
/// Borrows when the name is already both, which is every name that arrived off
/// the wire from a client that does not use 0x20 encoding. This was written
/// twice, identically, as a private `normalize` in `resolver` and in
/// `special_names`, and both allocated unconditionally (`TODO.md` #13b).
///
/// Not to be confused with [`crate::zone::absolutize`], which resolves a
/// *relative* zone-file name against an origin. This one has no origin to
/// resolve against: it appends the root dot and nothing more, which is the
/// right operation for a name that is already fully qualified but may have been
/// written without its final dot.
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

/// The only form a name may be a map **key** in: absolute and ASCII case-folded
/// (RFC 4343).
///
/// There is one constructor and it folds, so a key that has not been through
/// [`absolute_lowered`] cannot be inserted. That is the bug this exists to make
/// unspellable: `cache` once keyed on the name as it arrived, so `WWW.example.com.`
/// and `www.example.com.` were two entries for one owner — and the fix was a call
/// to a helper that the next map to be written would have had to remember.
///
/// **Borrowed lookup is `Borrow<str>`, not a borrowed newtype**, and that is a
/// deliberate limit rather than an oversight. The `str`/`String`-shaped pair —
/// an unsized `NameKey(str)` with `Borrow<NameKey>` — is what `std` does for
/// `Path`/`PathBuf`, and it cannot be built without transmuting `&str` to
/// `&NameKey`. This workspace contains **no `unsafe` at all**, and a newtype's
/// ergonomics is not a good enough reason to introduce the first of it.
///
/// What that costs: a *lookup* takes a `&str` the caller folded (with
/// `absolute_lowered`, which borrows when there is nothing to fold, so nothing
/// allocates). What it keeps: an *insertion* cannot skip the fold, which is the
/// direction the bug came from. See `TODO.md` #13e.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NameKeyBuf(String);

impl NameKeyBuf {
    /// Fold `name` into key form. The only way to make one.
    pub fn new(name: &str) -> NameKeyBuf {
        NameKeyBuf(absolute_lowered(name).into_owned())
    }

    /// Take ownership of a string that is **already** in key form.
    ///
    /// For the one caller that has done the work: `Zone`'s lookup key is
    /// `absolutize`-against-the-origin *then* fold, which [`NameKeyBuf::new`]
    /// cannot express because it has no origin. Without this, `add_record`
    /// folded a second time and allocated twice per record — caught by
    /// `tests/allocations.rs` as 208 -> 215 on an eight-record zone, which is
    /// what that file is for.
    ///
    /// The invariant is checked in debug rather than taken on trust, and checked
    /// *without allocating*, because the allocation test runs in debug and a
    /// checking `absolute_lowered` would have shown up as the very number it is
    /// there to hold.
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
    /// What makes `map.get(absolute_lowered(name).as_ref())` work without
    /// building a key — the lookup path allocates nothing.
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NameKeyBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How many labels a name has, the root (`.`) being zero. `example.com.` is 2.
///
/// Neither case folding nor the trailing dot changes the answer, so this does
/// neither — the version this replaced called `normalize` first and paid an
/// allocation to count something normalization cannot affect.
pub fn label_count(name: &str) -> usize {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        0
    } else {
        trimmed.split('.').count()
    }
}

/// Whether `name` is `origin` or sits below it — "is this name in that zone",
/// which every part of this codebase has to ask and which **four** of them used
/// to answer separately: this one, `zone`'s caller, `special_names::in_zone`
/// (which built a `format!(".{zone}")` per call) and `resolver::is_subdomain`
/// (which normalized both sides into fresh `String`s and *then* built the
/// `format!`, three allocations to answer a question about bytes). All of them
/// got the label-boundary rule right, which is the only reason folding them in
/// was a cleanup rather than a finding (`TODO.md` #13b).
///
/// **A suffix match is not enough**, and getting that wrong is how a server
/// answers for somebody else's zone: `notexample.com.` ends with `example.com.`
/// and is a different name entirely, so the boundary has to land on a label
/// separator.
///
/// The trailing dot is optional on either side, because the two callers hold
/// their names in different forms — `zone` walks absolute names, `rdnsd`
/// compares a QNAME against a zone origin — and which form they are in is not
/// the question being asked. An empty origin is the root, which contains
/// everything including itself.
///
/// Comparison is ASCII case-insensitive (RFC 4343), so neither side has to be
/// folded first: folding costs an allocation, and this sits on the query path.
/// It compares bytes rather than `str`s, which also means no slice of it can
/// land inside a multi-byte character and panic on a name that came off the
/// wire.
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

/// Get the current Unix timestamp in seconds
///
/// Returns 0 if the system time is before UNIX_EPOCH (unlikely in practice)
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

/// Check if a time range (inception to expiration) has expired
///
/// Returns true if the current time is outside the valid range:
/// - Current time < inception (not yet valid)
/// - Current time > expiration (expired)
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

/// Check if a cache entry has expired
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

/// Extract fields from a DNSKEY record
///
/// Returns a tuple of (algorithm, public_key, flags, protocol)
///
/// # Errors
/// Returns an error if the record is not a DNSKEY record
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

/// Get the record type code from a stored record.
///
/// The type code is carried directly on [`RecordData`], so this is just an
/// accessor kept for call-site compatibility.
pub fn record_type_code(rdata: &RecordData) -> Rtype {
    rdata.rtype()
}

/// Convert record type name to its numeric code
///
/// `TYPEnnn` is accepted for any type at all (RFC 3597 §5), which is what makes
/// a type this library has no mnemonic for still expressible in a zone file — an
/// NSEC bitmap listing one, or a record carried in the generic `\#` form.
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
/// library has none. Always a name the parser reads back, which is what the zone
/// writer relies on.
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

    /// The replacement for `normalize_domain_name_for_comparison`, holding the
    /// same answers it did — plus the one it got wrong.
    #[test]
    fn names_are_equal_by_ascii_folding_and_an_optional_trailing_dot() {
        assert!(names_equal("EXAMPLE.COM.", "example.com"));
        assert!(names_equal("Example.Com", "EXAMPLE.COM."));
        assert!(names_equal("example.com.", "example.com."));
        assert!(!names_equal("example.com.", "other.com."));

        // The root, written either way.
        assert!(names_equal(".", "."));
        assert!(names_equal(".", ""));

        // A suffix is not a name: this is the `notexample.com.` rule that
        // `is_at_or_under` exists for, and equality must not blur it.
        assert!(!names_equal("notexample.com.", "example.com."));

        // The fold is ASCII only (RFC 4343). U+212A KELVIN SIGN lowercases to
        // `k` under Unicode, and the function this replaced used `to_lowercase`
        // — so it answered `true` here, merging two names that are different
        // bytes on the wire.
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
        // `u8::is_ascii_uppercase`, so it takes the borrowing arm and is left
        // alone — the same rule [`ascii_lowered_cow`] obeys.
        assert!(matches!(
            absolute_lowered("\u{212A}.example.com."),
            Cow::Borrowed("\u{212A}.example.com.")
        ));
    }

    /// Counting labels needs neither the fold nor the dot, which is why the
    /// version this replaced allocated for nothing.
    #[test]
    fn label_count_ignores_case_and_the_trailing_dot() {
        assert_eq!(label_count("."), 0);
        assert_eq!(label_count(""), 0);
        assert_eq!(label_count("com."), 1);
        assert_eq!(label_count("example.com"), 2);
        assert_eq!(label_count("www.example.com."), 3);
        assert_eq!(label_count("WWW.Example.COM."), 3);
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

    /// RFC 3597 §5: any type at all can be named, which is what keeps a type we
    /// have no mnemonic for from being unwritable.
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

    /// The oversized-datagram case, which the `ErrorKind` list could not express.
    ///
    /// Windows reports WSAEMSGSIZE for a datagram bigger than the buffer, Rust
    /// maps it to `kind = Uncategorized`, and an `Uncategorized` error matched
    /// none of the arms — so the receive loop treated it as fatal and one
    /// oversized packet from any source exited the process, before
    /// authentication and before the rate limiter. The predicate has to be
    /// tested through the raw code because the kind carries no information.
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

    /// And a socket that has genuinely failed still stops the loop — the point of
    /// the predicate is to be narrow. A server that cannot receive is not
    /// serving, and pretending otherwise is a process that looks healthy and
    /// answers nothing.
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
        // U+212A KELVIN SIGN lowercases to `k` under Unicode rules. Two names
        // that are different bytes on the wire must not come out equal.
        assert_ne!(ascii_lowered("\u{212A}.example.com."), "k.example.com.");
        assert_eq!(
            "\u{212A}".to_lowercase(),
            "k",
            "which is what to_lowercase does"
        );
    }

    /// The containment test both callers used to write for themselves, at the
    /// boundary conditions each of them got right separately.
    ///
    /// `notexample.com.` is the one worth naming: it ends with `example.com.`
    /// and belongs to somebody else, so a server matching on the suffix alone
    /// answers authoritatively for a zone it does not hold.
    #[test]
    fn a_name_is_under_a_zone_only_at_a_label_boundary() {
        assert!(is_at_or_under("www.example.com.", "example.com."));
        assert!(is_at_or_under("example.com.", "example.com."), "the apex");
        assert!(!is_at_or_under("notexample.com.", "example.com."));
        assert!(!is_at_or_under("example.com.", "www.example.com."), "above");
        assert!(!is_at_or_under("example.org.", "example.com."));

        // The trailing dot is optional on either side, because the callers hold
        // their names in different forms and that is not the question asked.
        assert!(is_at_or_under("www.example.com", "example.com."));
        assert!(is_at_or_under("www.example.com.", "example.com"));

        // The root contains everything, itself included.
        assert!(is_at_or_under("www.example.com.", "."));
        assert!(is_at_or_under(".", "."));

        // ASCII case folds; U+212A KELVIN SIGN does not become `k`, which is
        // what `str::to_lowercase` on both sides used to do here.
        assert!(is_at_or_under("WWW.Example.COM.", "example.com."));
        assert!(!is_at_or_under("\u{212A}.example.com.", "k.example.com."));
    }

    /// The borrowing form folds the same octets and no others, and copies only
    /// when it has something to fold.
    ///
    /// The Unicode case is the one worth having twice: U+212A is upper case to
    /// `char::is_uppercase` and *not* to `u8::is_ascii_uppercase`, so it takes
    /// the borrowing arm — which is right, and is the same rule the copying form
    /// obeys. A version of this that scanned with `char::is_uppercase` would
    /// return `Owned` and still not fold it, which would be merely wasteful; one
    /// that then folded it with `to_lowercase` would be the cache bug in
    /// [`ascii_lowered`]'s comment.
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
