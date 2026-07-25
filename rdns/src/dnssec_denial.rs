//! Denial of existence: NSEC and NSEC3.
//!
//! A signed "no" is harder than a signed "yes". There is no record to sign when
//! a name does not exist, so a zone instead signs statements about the *gaps*
//! between the names that do — NSEC spells the neighbours out, NSEC3 publishes
//! their hashes so the zone cannot be walked. Validating one means checking
//! that the gap really does contain the name asked about, which needs the
//! canonical name ordering of RFC 4034 §6.1 (not string order) and, for NSEC3,
//! the salted iterated hash of RFC 5155 §5.
//!
//! Two of those were wrong here before anything called them: names were
//! compared as plain lowercased strings, and the NSEC3 hash was a single bare
//! SHA-1 pass with the salt and iteration count parsed and then ignored.

use crate::dname::dname_to_bytes;
use crate::utils::record_types as rt;
use crate::{ParsedRecord, ResourceRecord};
use anyhow::anyhow;
use sha1::{Digest, Sha1};
use std::cmp::Ordering;

/// The most NSEC3 iterations we will compute before refusing.
///
/// Each iteration hashes the whole name, and the count is a `u16` chosen by
/// whoever signed the zone, so 65535 iterations on every name in a response is
/// a CPU amplification vector aimed at the validator. RFC 9276 §3.1 says treat
/// anything above zero as suspect and gives 0 as the only recommended value;
/// this ceiling is generous next to that and still bounds the work. Beyond it
/// we return an error, which the chain validator turns into "insecure" rather
/// than "bogus" — a zone that signs itself unreasonably is not proof of an
/// attack on the answer.
pub const MAX_NSEC3_ITERATIONS: u16 = 150;

// ---------------------------------------------------------------------------
// Canonical name ordering (RFC 4034 §6.1)
// ---------------------------------------------------------------------------

/// Compare two names in DNSSEC canonical order.
///
/// Names sort by label from the *right*: `a.example.com.` and `z.example.com.`
/// are neighbours, while `example.com.` sorts before both because a name is
/// ordered ahead of everything beneath it. Comparing the whole strings instead
/// gets this wrong in both directions — `z.example.com` would sort before
/// `a.b.example.com` — and an NSEC range check built on string order will
/// happily accept a name outside the gap it was given.
pub fn canonical_name_cmp(a: &str, b: &str) -> Ordering {
    let a = reversed_labels(a);
    let b = reversed_labels(b);
    for i in 0.. {
        match (a.get(i), b.get(i)) {
            (None, None) => return Ordering::Equal,
            // Fewer labels means an ancestor, which sorts first.
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => match x.as_bytes().cmp(y.as_bytes()) {
                Ordering::Equal => continue,
                other => return other,
            },
        }
    }
    unreachable!("the loop returns on the first differing or missing label")
}

/// A name's labels, down-cased and right to left. The root has none.
fn reversed_labels(name: &str) -> Vec<String> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed
        .split('.')
        .map(|l| l.to_ascii_lowercase())
        .rev()
        .collect()
}

// ---------------------------------------------------------------------------
// Type bitmaps (RFC 4034 §4.1.2)
// ---------------------------------------------------------------------------

/// Whether `rtype` is set in an NSEC/NSEC3 type bitmap.
///
/// The bitmap is a sequence of windows: a window number, a length, and that
/// many bytes of bits for types `window * 256 ..`. A malformed bitmap reads as
/// "type not present", which is the safe direction — a bitmap we cannot parse
/// must never be taken as proof that something *is* there.
pub fn bitmap_has_type(bitmap: &[u8], rtype: u16) -> bool {
    let want_window = (rtype >> 8) as u8;
    let want_bit = (rtype & 0xff) as usize;

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

/// Build a type bitmap covering `types`. Used by tests and by anything that
/// needs to synthesize a denial.
pub fn build_type_bitmap(types: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut windows: Vec<(u8, Vec<u8>)> = Vec::new();
    for &t in types {
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

// ---------------------------------------------------------------------------
// base32hex (RFC 4648 §7) — how NSEC3 owner names carry a hash
// ---------------------------------------------------------------------------

const BASE32HEX: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Encode bytes as unpadded base32hex, the form an NSEC3 owner label takes.
pub fn base32hex_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes([0, 0, 0, buf[0], buf[1], buf[2], buf[3], buf[4]]);
        // 5 input bytes make 8 output characters; a short final chunk makes
        // ceil(len * 8 / 5) of them.
        let chars = (chunk.len() * 8).div_ceil(5);
        for i in 0..chars {
            let shift = 35 - i * 5;
            out.push(BASE32HEX[((bits >> shift) & 0x1f) as usize] as char);
        }
    }
    out
}

/// Decode unpadded base32hex. Case-insensitive, as DNS labels are.
pub fn base32hex_decode(text: &str) -> Result<Vec<u8>, anyhow::Error> {
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in text.bytes() {
        let value = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'v' => c - b'a' + 10,
            b'A'..=b'V' => c - b'A' + 10,
            _ => return Err(anyhow!("invalid base32hex character {:?}", c as char)),
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

// ---------------------------------------------------------------------------
// The NSEC3 hash (RFC 5155 §5)
// ---------------------------------------------------------------------------

/// The NSEC3 hash of `name`: SHA-1 over the name's wire form, salted and
/// iterated.
///
/// ```text
/// IH(salt, x, 0) = H(x || salt)
/// IH(salt, x, k) = H(IH(salt, x, k-1) || salt)
/// ```
///
/// The salt is appended at *every* round, not just the first, and the input to
/// round zero is the down-cased wire-format name — not its text. Hashing the
/// text with a single unsalted pass, as this used to, produces a value that
/// matches no real zone, so every negative answer fails to prove anything.
pub fn nsec3_hash(name: &str, salt: &[u8], iterations: u16) -> Result<Vec<u8>, anyhow::Error> {
    if iterations > MAX_NSEC3_ITERATIONS {
        return Err(anyhow!(
            "NSEC3 iteration count {iterations} exceeds the {MAX_NSEC3_ITERATIONS} we will compute (RFC 9276)"
        ));
    }
    let wire = dname_to_bytes(&name.to_ascii_lowercase())?;

    let mut hasher = Sha1::new();
    hasher.update(&wire);
    hasher.update(salt);
    let mut digest = hasher.finalize().to_vec();

    for _ in 0..iterations {
        let mut hasher = Sha1::new();
        hasher.update(&digest);
        hasher.update(salt);
        digest = hasher.finalize().to_vec();
    }
    Ok(digest)
}

// ---------------------------------------------------------------------------
// Typed views
// ---------------------------------------------------------------------------

/// An NSEC record and the name it sits at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec {
    pub owner: String,
    pub next: String,
    pub type_bitmap: Vec<u8>,
}

impl Nsec {
    pub fn from_record(rr: &ResourceRecord) -> Option<Self> {
        if rr.rdata.rtype != rt::NSEC {
            return None;
        }
        match rr.rdata.parse().ok()? {
            ParsedRecord::NSEC {
                next_domain_name,
                type_bitmap,
            } => Some(Nsec {
                owner: rr.name.to_ascii_lowercase(),
                next: next_domain_name.to_ascii_lowercase(),
                type_bitmap,
            }),
            _ => None,
        }
    }

    /// Whether this NSEC's owner *is* `name`.
    pub fn matches(&self, name: &str) -> bool {
        canonical_name_cmp(&self.owner, name) == Ordering::Equal
    }

    /// Whether `name` falls strictly inside the gap this NSEC describes.
    ///
    /// The endpoints are excluded: a name equal to either neighbour exists, so
    /// the record proves the opposite of non-existence for it. The last NSEC in
    /// a zone points back at the apex, so a `next` at or below `owner` means
    /// the range wraps around the end of the zone.
    pub fn covers(&self, name: &str) -> bool {
        let after_owner = canonical_name_cmp(name, &self.owner) == Ordering::Greater;
        let before_next = canonical_name_cmp(name, &self.next) == Ordering::Less;
        if canonical_name_cmp(&self.next, &self.owner) == Ordering::Greater {
            after_owner && before_next
        } else {
            // Wrapped: everything after the owner, or before the next.
            after_owner || before_next
        }
    }

    pub fn has_type(&self, rtype: u16) -> bool {
        bitmap_has_type(&self.type_bitmap, rtype)
    }
}

/// An NSEC3 record, with its owner hash decoded out of the first label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3 {
    pub owner: String,
    /// The hash in the owner's first label, decoded from base32hex.
    pub owner_hash: Vec<u8>,
    /// Everything after that label — the zone the NSEC3 belongs to.
    pub zone: String,
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next_hashed_owner: Vec<u8>,
    pub type_bitmap: Vec<u8>,
}

impl Nsec3 {
    pub fn from_record(rr: &ResourceRecord) -> Option<Self> {
        if rr.rdata.rtype != rt::NSEC3 {
            return None;
        }
        let owner = rr.name.to_ascii_lowercase();
        let (first, zone) = owner.split_once('.')?;
        let owner_hash = base32hex_decode(first).ok()?;
        match rr.rdata.parse().ok()? {
            ParsedRecord::NSEC3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmap,
            } => Some(Nsec3 {
                owner: owner.clone(),
                owner_hash,
                zone: zone.to_string(),
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmap,
            }),
            _ => None,
        }
    }

    /// The Opt-Out flag (RFC 5155 §6): this NSEC3's span may contain
    /// unsigned delegations it says nothing about. It weakens what a covering
    /// record proves — enough for "no DS here", never enough for "no name here".
    pub fn opt_out(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// The hash of `name` under this record's parameters.
    pub fn hash(&self, name: &str) -> Result<Vec<u8>, anyhow::Error> {
        if self.hash_algorithm != 1 {
            return Err(anyhow!(
                "unsupported NSEC3 hash algorithm {}",
                self.hash_algorithm
            ));
        }
        nsec3_hash(name, &self.salt, self.iterations)
    }

    /// Whether this NSEC3 is the record *for* `name`.
    pub fn matches(&self, name: &str) -> Result<bool, anyhow::Error> {
        Ok(self.hash(name)? == self.owner_hash)
    }

    /// Whether `name`'s hash falls strictly inside this record's span.
    pub fn covers(&self, name: &str) -> Result<bool, anyhow::Error> {
        let hash = self.hash(name)?;
        if hash.is_empty() || self.owner_hash.is_empty() || self.next_hashed_owner.is_empty() {
            return Ok(false);
        }
        let after = hash.as_slice() > self.owner_hash.as_slice();
        let before = hash.as_slice() < self.next_hashed_owner.as_slice();
        Ok(
            if self.next_hashed_owner.as_slice() > self.owner_hash.as_slice() {
                after && before
            } else {
                // The last NSEC3 wraps around to the first.
                after || before
            },
        )
    }

    pub fn has_type(&self, rtype: u16) -> bool {
        bitmap_has_type(&self.type_bitmap, rtype)
    }
}

/// Every NSEC record in a section.
pub fn nsecs_in(records: &[ResourceRecord]) -> Vec<Nsec> {
    records.iter().filter_map(Nsec::from_record).collect()
}

/// Every NSEC3 record in a section.
pub fn nsec3s_in(records: &[ResourceRecord]) -> Vec<Nsec3> {
    records.iter().filter_map(Nsec3::from_record).collect()
}

// ---------------------------------------------------------------------------
// The proofs themselves
// ---------------------------------------------------------------------------

/// The outcome of asking a set of NSEC/NSEC3 records to prove something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The records prove it.
    Proved,
    /// They do not — either they say nothing about this name, or they say the
    /// opposite. The string is for the log, not for control flow.
    NotProved(String),
}

impl Denial {
    pub fn is_proved(&self) -> bool {
        matches!(self, Denial::Proved)
    }
}

/// Whether these records prove that `zone` has no DS record — that is, that the
/// delegation is genuinely unsigned rather than having had its DS stripped.
///
/// This is the single most security-relevant proof in the whole chain. Without
/// it, an attacker removes the DS from a referral and the validator concludes
/// "unsigned zone, nothing to check", which turns every signed zone below into
/// an unsigned one. RFC 4035 §5.2 and RFC 5155 §8.9.
pub fn proves_no_ds(zone: &str, nsecs: &[Nsec], nsec3s: &[Nsec3]) -> Denial {
    for nsec in nsecs {
        if !nsec.matches(zone) {
            continue;
        }
        if nsec.has_type(rt::DS) {
            return Denial::NotProved(format!("the NSEC at {zone} says a DS does exist"));
        }
        // An NSEC at the delegation point must show NS and must not show SOA;
        // otherwise it is the child's own apex NSEC, which the child could have
        // made say anything about its own DS.
        if !nsec.has_type(rt::NS) {
            return Denial::NotProved(format!("the NSEC at {zone} is not at a delegation"));
        }
        if nsec.has_type(rt::SOA) {
            return Denial::NotProved(format!(
                "the NSEC at {zone} is the zone apex, not the parent side of the cut"
            ));
        }
        return Denial::Proved;
    }

    for nsec3 in nsec3s {
        match nsec3.matches(zone) {
            Ok(true) => {
                if nsec3.has_type(rt::DS) {
                    return Denial::NotProved(format!("the NSEC3 for {zone} says a DS does exist"));
                }
                if !nsec3.has_type(rt::NS) {
                    return Denial::NotProved(format!("the NSEC3 for {zone} is not at a delegation"));
                }
                return Denial::Proved;
            }
            Ok(false) => {}
            Err(e) => return Denial::NotProved(format!("NSEC3 for {zone} unusable: {e}")),
        }
    }

    // No NSEC3 names the delegation. Opt-out (RFC 5155 §6) is what lets a large
    // TLD skip signing every unsigned delegation: a covering NSEC3 with the
    // flag set means "there may be insecure delegations in this span I have not
    // named", which is exactly the claim we need. Without the flag, a covering
    // record proves the name does not exist at all — and it plainly does, since
    // we were just referred to it — so it proves nothing here.
    for nsec3 in nsec3s {
        if nsec3.opt_out() && nsec3.covers(zone).unwrap_or(false) {
            return Denial::Proved;
        }
    }

    Denial::NotProved(format!("no NSEC or NSEC3 record covers the DS at {zone}"))
}

/// Whether these records prove `qname` does not exist at all (NXDOMAIN).
///
/// For NSEC that is one record covering the name, plus one covering the
/// wildcard that would otherwise have answered for it (RFC 4035 §5.4) — a
/// single record often does both. For NSEC3 it is the closest-encloser proof of
/// RFC 5155 §8.4.
pub fn proves_nxdomain(qname: &str, zone: &str, nsecs: &[Nsec], nsec3s: &[Nsec3]) -> Denial {
    if !nsecs.is_empty() {
        let Some(covering) = nsecs.iter().find(|n| n.covers(qname)) else {
            return Denial::NotProved(format!("no NSEC covers {qname}"));
        };
        // The name is absent; now show that no wildcard would have answered
        // for it either. The wildcard to disprove sits at the closest encloser,
        // which for an NSEC proof is the longest suffix of qname that the
        // covering record's owner and next name share with it.
        let encloser = closest_encloser_nsec(qname, covering);
        let wildcard = format!("*.{encloser}");
        if nsecs.iter().any(|n| n.covers(&wildcard)) {
            return Denial::Proved;
        }
        return Denial::NotProved(format!(
            "no NSEC covers the wildcard {wildcard} that could have answered {qname}"
        ));
    }

    if !nsec3s.is_empty() {
        return nsec3_closest_encloser_proof(qname, zone, nsec3s);
    }

    Denial::NotProved(format!("nothing was offered to deny {qname}"))
}

/// Whether these records prove `qname` exists but has no record of `qtype`
/// (NODATA).
pub fn proves_nodata(qname: &str, qtype: u16, nsecs: &[Nsec], nsec3s: &[Nsec3]) -> Denial {
    for nsec in nsecs {
        if !nsec.matches(qname) {
            continue;
        }
        if nsec.has_type(qtype) {
            return Denial::NotProved(format!("the NSEC at {qname} says type {qtype} exists"));
        }
        // A CNAME at the name would have been followed instead of answered
        // NODATA, so its presence contradicts the proof.
        if nsec.has_type(rt::CNAME) {
            return Denial::NotProved(format!("{qname} has a CNAME, which is not NODATA"));
        }
        return Denial::Proved;
    }

    for nsec3 in nsec3s {
        match nsec3.matches(qname) {
            Ok(true) => {
                if nsec3.has_type(qtype) {
                    return Denial::NotProved(format!(
                        "the NSEC3 for {qname} says type {qtype} exists"
                    ));
                }
                if nsec3.has_type(rt::CNAME) {
                    return Denial::NotProved(format!("{qname} has a CNAME, which is not NODATA"));
                }
                return Denial::Proved;
            }
            Ok(false) => {}
            Err(e) => return Denial::NotProved(format!("NSEC3 for {qname} unusable: {e}")),
        }
    }

    Denial::NotProved(format!("no NSEC or NSEC3 record denies type {qtype} at {qname}"))
}

/// The longest suffix `qname` shares with either end of the NSEC that covers
/// it. That name provably exists (an NSEC's owner and next name both do), so it
/// is the closest ancestor of `qname` that does.
fn closest_encloser_nsec(qname: &str, covering: &Nsec) -> String {
    let from_owner = common_suffix(qname, &covering.owner);
    let from_next = common_suffix(qname, &covering.next);
    if crate::dnssec::label_count(&from_owner) >= crate::dnssec::label_count(&from_next) {
        from_owner
    } else {
        from_next
    }
}

/// The longest suffix of whole labels that two names share.
fn common_suffix(a: &str, b: &str) -> String {
    let a = reversed_labels(a);
    let b = reversed_labels(b);
    let shared: Vec<String> = a
        .iter()
        .zip(b.iter())
        .take_while(|(x, y)| x == y)
        .map(|(x, _)| x.clone())
        .collect();
    if shared.is_empty() {
        ".".to_string()
    } else {
        let mut labels = shared;
        labels.reverse();
        format!("{}.", labels.join("."))
    }
}

/// The RFC 5155 §8.4 closest-encloser proof: find the deepest ancestor of
/// `qname` that an NSEC3 matches, show the name one label below it is covered
/// (so `qname` itself cannot exist), and show the wildcard at the encloser is
/// covered too.
fn nsec3_closest_encloser_proof(qname: &str, zone: &str, nsec3s: &[Nsec3]) -> Denial {
    let qname = crate::dnssec::canonical_name(qname);
    let zone = crate::dnssec::canonical_name(zone);
    let qlabels = crate::dnssec::label_count(&qname);
    let zlabels = crate::dnssec::label_count(&zone);

    // Walk up from the name towards the apex looking for a match. The apex
    // always exists, so the search terminates there at the latest.
    for depth in (zlabels..=qlabels).rev() {
        let candidate = crate::dnssec::suffix_labels(&qname, depth);
        let matched = nsec3s
            .iter()
            .any(|n| n.matches(&candidate).unwrap_or(false));
        if !matched {
            continue;
        }
        if depth == qlabels {
            return Denial::NotProved(format!("an NSEC3 matches {qname}, so it exists"));
        }
        // The "next closer" name: one label longer than the encloser.
        let next_closer = crate::dnssec::suffix_labels(&qname, depth + 1);
        if !nsec3s
            .iter()
            .any(|n| n.covers(&next_closer).unwrap_or(false))
        {
            return Denial::NotProved(format!("no NSEC3 covers the next closer name {next_closer}"));
        }
        let wildcard = format!("*.{candidate}");
        let wildcard_denied = nsec3s.iter().any(|n| {
            n.covers(&wildcard).unwrap_or(false) || n.matches(&wildcard).unwrap_or(false)
        });
        if !wildcard_denied {
            return Denial::NotProved(format!("no NSEC3 accounts for the wildcard {wildcard}"));
        }
        return Denial::Proved;
    }

    Denial::NotProved(format!("no NSEC3 matches any ancestor of {qname}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecordData;

    fn nsec(owner: &str, next: &str, types: &[u16]) -> Nsec {
        Nsec {
            owner: owner.to_string(),
            next: next.to_string(),
            type_bitmap: build_type_bitmap(types),
        }
    }

    // -----------------------------------------------------------------
    // Canonical ordering
    // -----------------------------------------------------------------

    /// The case plain string comparison gets wrong: sorting is by label from
    /// the right, so a deeper name under an earlier label comes first.
    #[test]
    fn test_canonical_order_is_by_label_from_the_right() {
        // The rightmost differing label decides, so `z` beats `b` even though
        // the name starting with `a` looks smaller as a string.
        assert_eq!(
            canonical_name_cmp("a.z.example.com.", "b.example.com."),
            Ordering::Greater
        );
        // Plain string comparison gets exactly this backwards — which is what
        // an NSEC range check used to be built on.
        assert!("a.z.example.com." < "b.example.com.");

        // A name sorts before everything beneath it.
        assert_eq!(
            canonical_name_cmp("example.com.", "www.example.com."),
            Ordering::Less
        );
        // Case and trailing dots do not matter.
        assert_eq!(
            canonical_name_cmp("EXAMPLE.com", "example.com."),
            Ordering::Equal
        );
        // RFC 4034 §6.1's own example ordering.
        let mut names = vec![
            "z.example.",
            "yljkjljk.a.example.",
            "*.z.example.",
            "example.",
            "a.example.",
        ];
        names.sort_by(|a, b| canonical_name_cmp(a, b));
        assert_eq!(
            names,
            vec![
                "example.",
                "a.example.",
                "yljkjljk.a.example.",
                "z.example.",
                "*.z.example.",
            ]
        );
    }

    #[test]
    fn test_nsec_covers_excludes_its_endpoints() {
        let n = nsec("a.example.com.", "z.example.com.", &[rt::A]);
        assert!(n.covers("m.example.com."));
        assert!(!n.covers("a.example.com."), "the owner exists");
        assert!(!n.covers("z.example.com."), "the next name exists");
        assert!(!n.covers("zz.example.com."));
    }

    #[test]
    fn test_nsec_covers_wraps_at_the_end_of_the_zone() {
        // The last NSEC in a zone points back at the apex.
        let n = nsec("z.example.com.", "example.com.", &[rt::A]);
        assert!(n.covers("zz.example.com."), "after the last name");
        assert!(!n.covers("m.example.com."), "before it");
    }

    // -----------------------------------------------------------------
    // Type bitmaps
    // -----------------------------------------------------------------

    #[test]
    fn test_type_bitmap_roundtrip() {
        let bitmap = build_type_bitmap(&[rt::A, rt::NS, rt::SOA, rt::RRSIG, rt::NSEC, rt::DNSKEY]);
        for present in [rt::A, rt::NS, rt::SOA, rt::RRSIG, rt::NSEC, rt::DNSKEY] {
            assert!(bitmap_has_type(&bitmap, present), "type {present} should be set");
        }
        for absent in [rt::AAAA, rt::MX, rt::DS, rt::CNAME] {
            assert!(!bitmap_has_type(&bitmap, absent), "type {absent} should not be set");
        }
    }

    #[test]
    fn test_type_bitmap_spans_windows() {
        // TYPE1234 lives in window 4; A lives in window 0.
        let bitmap = build_type_bitmap(&[rt::A, 1234]);
        assert!(bitmap_has_type(&bitmap, rt::A));
        assert!(bitmap_has_type(&bitmap, 1234));
        assert!(!bitmap_has_type(&bitmap, 1235));
    }

    /// A bitmap we cannot parse must read as "absent", never as "present".
    #[test]
    fn test_malformed_bitmap_denies_nothing() {
        assert!(!bitmap_has_type(&[0x00], rt::A), "truncated window header");
        assert!(!bitmap_has_type(&[0x00, 0x09, 0x40], rt::A), "length overruns");
        assert!(!bitmap_has_type(&[], rt::A));
    }

    // -----------------------------------------------------------------
    // base32hex
    // -----------------------------------------------------------------

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

    // -----------------------------------------------------------------
    // The NSEC3 hash
    // -----------------------------------------------------------------

    /// RFC 5155 Appendix A: the zone `example.` with salt `aabbccdd` and 12
    /// iterations hashes `a.example.` to `35mthgpgcu1qg68fab165klnsnk3dpvl`.
    /// This is the one test that would have caught the old single-pass hash.
    #[test]
    fn test_nsec3_hash_matches_rfc5155_appendix_a() {
        // NSEC3PARAM 1 0 12 aabbccdd, from the RFC's example zone.
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        let hash = nsec3_hash("a.example.", &salt, 12).unwrap();
        assert_eq!(
            base32hex_encode(&hash).to_lowercase(),
            "35mthgpgcu1qg68fab165klnsnk3dpvl"
        );

        // And the apex itself.
        let hash = nsec3_hash("example.", &salt, 12).unwrap();
        assert_eq!(
            base32hex_encode(&hash).to_lowercase(),
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
        );
    }

    /// The salt and iteration count both change the hash — the old code read
    /// them off the wire and then ignored both.
    #[test]
    fn test_salt_and_iterations_change_the_hash() {
        let base = nsec3_hash("a.example.", &[], 0).unwrap();
        assert_ne!(base, nsec3_hash("a.example.", &[0xaa], 0).unwrap());
        assert_ne!(base, nsec3_hash("a.example.", &[], 1).unwrap());
        assert_eq!(base.len(), 20, "SHA-1 output");
        // Case does not: the name is down-cased first.
        assert_eq!(base, nsec3_hash("A.Example.", &[], 0).unwrap());
    }

    /// A hostile iteration count must be refused, not computed.
    #[test]
    fn test_iteration_count_is_capped() {
        assert!(nsec3_hash("a.example.", &[], MAX_NSEC3_ITERATIONS).is_ok());
        let err = nsec3_hash("a.example.", &[], u16::MAX).expect_err("65535 rounds must be refused");
        assert!(err.to_string().contains("exceeds"), "got: {err}");
    }

    // -----------------------------------------------------------------
    // Proofs
    // -----------------------------------------------------------------

    #[test]
    fn test_nsec_proves_an_unsigned_delegation() {
        // The parent's NSEC at the delegation: NS present, DS absent.
        let n = nsec("insecure.example.com.", "z.example.com.", &[rt::NS, rt::RRSIG, rt::NSEC]);
        assert!(proves_no_ds("insecure.example.com.", &[n], &[]).is_proved());
    }

    /// The attack this proof exists to stop: strip the DS and claim the zone
    /// below is unsigned. The NSEC still lists DS, so the claim fails.
    #[test]
    fn test_nsec_listing_ds_does_not_prove_absence() {
        let n = nsec(
            "secure.example.com.",
            "z.example.com.",
            &[rt::NS, rt::DS, rt::RRSIG],
        );
        let denial = proves_no_ds("secure.example.com.", &[n], &[]);
        assert!(!denial.is_proved(), "{denial:?}");
    }

    /// An NSEC from the child's own apex must not be accepted as the parent's
    /// statement about the delegation — the child would be vouching for itself.
    #[test]
    fn test_apex_nsec_does_not_prove_no_ds() {
        let n = nsec(
            "child.example.com.",
            "a.child.example.com.",
            &[rt::SOA, rt::NS, rt::DNSKEY, rt::RRSIG],
        );
        let denial = proves_no_ds("child.example.com.", &[n], &[]);
        assert!(!denial.is_proved(), "{denial:?}");
    }

    #[test]
    fn test_nothing_at_all_proves_nothing() {
        let denial = proves_no_ds("child.example.com.", &[], &[]);
        assert!(!denial.is_proved());
    }

    #[test]
    fn test_nsec_nodata_proof() {
        let n = nsec("www.example.com.", "z.example.com.", &[rt::A, rt::RRSIG, rt::NSEC]);
        // No AAAA in the bitmap, so NODATA for AAAA is proven.
        assert!(proves_nodata("www.example.com.", rt::AAAA, std::slice::from_ref(&n), &[]).is_proved());
        // But A is listed, so it cannot deny that.
        assert!(!proves_nodata("www.example.com.", rt::A, &[n], &[]).is_proved());
    }

    #[test]
    fn test_nsec_nxdomain_needs_the_wildcard_denied_too() {
        // One record covering both the name and *.example.com.
        let wide = nsec("example.com.", "z.example.com.", &[rt::SOA, rt::NS]);
        assert!(proves_nxdomain("nope.example.com.", "example.com.", &[wide], &[]).is_proved());

        // A record covering the name but not the wildcard proves nothing: a
        // wildcard could still have answered.
        let narrow = nsec("m.example.com.", "z.example.com.", &[rt::A]);
        let denial = proves_nxdomain("nope.example.com.", "example.com.", &[narrow], &[]);
        assert!(!denial.is_proved(), "{denial:?}");
    }

    // -----------------------------------------------------------------
    // NSEC3 records off the wire
    // -----------------------------------------------------------------

    fn nsec3_record(zone: &str, name: &str, next: &[u8], flags: u8, types: &[u16]) -> Nsec3 {
        let salt = vec![0x01, 0x02];
        let hash = nsec3_hash(name, &salt, 5).unwrap();
        Nsec3 {
            owner: format!("{}.{}", base32hex_encode(&hash).to_lowercase(), zone),
            owner_hash: hash,
            zone: zone.to_string(),
            hash_algorithm: 1,
            flags,
            iterations: 5,
            salt,
            next_hashed_owner: next.to_vec(),
            type_bitmap: build_type_bitmap(types),
        }
    }

    #[test]
    fn test_nsec3_matching_record_proves_no_ds() {
        let n = nsec3_record("example.com.", "child.example.com.", &[0xff; 20], 0, &[rt::NS]);
        assert!(n.matches("child.example.com.").unwrap());
        assert!(proves_no_ds("child.example.com.", &[], &[n]).is_proved());
    }

    #[test]
    fn test_nsec3_with_ds_in_the_bitmap_proves_nothing() {
        let n = nsec3_record(
            "example.com.",
            "child.example.com.",
            &[0xff; 20],
            0,
            &[rt::NS, rt::DS],
        );
        assert!(!proves_no_ds("child.example.com.", &[], &[n]).is_proved());
    }

    /// Opt-out is what lets a covering (rather than matching) NSEC3 stand in
    /// for an unsigned delegation — and only when the flag is actually set.
    #[test]
    fn test_nsec3_opt_out_covering_proves_no_ds_but_only_with_the_flag() {
        // A span covering everything: owner hash all zeros, next all ones.
        let salt = vec![0x01, 0x02];
        let covering = |flags: u8| Nsec3 {
            owner: "00000000000000000000000000000000.example.com.".into(),
            owner_hash: vec![0x00; 20],
            zone: "example.com.".into(),
            hash_algorithm: 1,
            flags,
            iterations: 5,
            salt: salt.clone(),
            next_hashed_owner: vec![0xff; 20],
            type_bitmap: build_type_bitmap(&[rt::NS]),
        };

        assert!(
            proves_no_ds("child.example.com.", &[], &[covering(0x01)]).is_proved(),
            "opt-out set: the span may hold unsigned delegations"
        );
        assert!(
            !proves_no_ds("child.example.com.", &[], &[covering(0x00)]).is_proved(),
            "without opt-out a covering record claims the name does not exist, \
             which contradicts the referral we just followed"
        );
    }

    #[test]
    fn test_nsec3_record_parses_its_owner_hash() {
        use crate::ParsedRecord;
        let salt = vec![0xde, 0xad];
        let hash = nsec3_hash("child.example.com.", &salt, 3).unwrap();
        let rr = crate::ResourceRecord {
            name: format!("{}.example.com.", base32hex_encode(&hash)),
            class: 1,
            ttl: 3600,
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC3 {
                hash_algorithm: 1,
                flags: 1,
                iterations: 3,
                salt: salt.clone(),
                next_hashed_owner: vec![0xff; 20],
                type_bitmap: build_type_bitmap(&[rt::NS]),
            })
            .unwrap(),
        };

        let parsed = Nsec3::from_record(&rr).expect("NSEC3 should parse");
        assert_eq!(parsed.owner_hash, hash, "the owner label is the hash");
        assert_eq!(parsed.zone, "example.com.");
        assert!(parsed.opt_out());
        assert!(parsed.matches("child.example.com.").unwrap());
        assert!(parsed.has_type(rt::NS));
        assert!(!parsed.has_type(rt::DS));
    }

    /// An NSEC3 whose iteration count is absurd must fail closed rather than
    /// burn CPU on every name we check against it.
    #[test]
    fn test_hostile_nsec3_iterations_are_refused() {
        let n = Nsec3 {
            owner: "aaaa.example.com.".into(),
            owner_hash: vec![0x00; 20],
            zone: "example.com.".into(),
            hash_algorithm: 1,
            flags: 0,
            iterations: u16::MAX,
            salt: vec![0xff; 32],
            next_hashed_owner: vec![0xff; 20],
            type_bitmap: build_type_bitmap(&[rt::NS]),
        };
        assert!(n.matches("child.example.com.").is_err());
        let denial = proves_no_ds("child.example.com.", &[], &[n]);
        assert!(!denial.is_proved(), "{denial:?}");
    }
}
