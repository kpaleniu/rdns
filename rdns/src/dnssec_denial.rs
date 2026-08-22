//! Denial of existence: NSEC and NSEC3.
//!
//! A zone signs statements about the gaps between the names that exist. Checking
//! that a gap contains the name asked about needs the canonical name ordering of
//! RFC 4034 §6.1 — not string order — and, for NSEC3, the salted iterated hash
//! of RFC 5155 §5.

use crate::dname::dname_to_bytes;
use crate::error::{DnssecError, DnssecResult};
use crate::utils::record_types as rt;
use crate::Rtype;
use crate::{ParsedRecord, ResourceRecord};
use sha1::{Digest, Sha1};
use std::cmp::Ordering;

/// The most NSEC3 iterations we will compute before refusing.
///
/// The count is a `u16` the zone's signer chooses, so 65535 iterations per name
/// in a response is CPU amplification aimed at the validator. RFC 9276 §3.1
/// recommends 0. Over the cap we error, which the chain validator turns into
/// "insecure" rather than "bogus".
pub const MAX_NSEC3_ITERATIONS: u16 = 150;

/// Compare two names in DNSSEC canonical order (RFC 4034 §6.1).
///
/// Labels sort from the *right*, and a name sorts ahead of everything beneath
/// it. String comparison gets both wrong, and an NSEC range check built on it
/// accepts names outside the gap.
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

/// A byte string whose plain `Ord` is exactly [`canonical_name_cmp`], so a
/// `BTreeMap` can answer "which NSEC's range contains this name?" by range query.
///
/// Labels are written right to left, each terminated by a zero byte. The
/// terminator is what makes an ancestor sort before its descendants and keeps a
/// label from sorting after a longer label it is a prefix of (`ab\0` before
/// `abc\0`). Zero cannot occur inside a label.
pub fn canonical_sort_key(name: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(name.len() + 1);
    for label in reversed_labels(name) {
        key.extend_from_slice(label.as_bytes());
        key.push(0);
    }
    key
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
pub fn bitmap_types(bitmap: &[u8]) -> Vec<Rtype> {
    bitmap_types_exact(bitmap).unwrap_or_else(|partial| partial)
}

/// [`bitmap_types`], but `Err(what was read before the damage)` when the bitmap
/// does not parse to its end. Re-encoding a bitmap only partly understood would
/// emit a record other than the one we were given.
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
            for bit in 0..8 {
                if bits & (0x80 >> bit) != 0 {
                    types.push(Rtype::new((window << 8) | (byte as u16 * 8 + bit)));
                }
            }
        }
        rest = &rest[2 + len..];
    }
    Ok(types)
}

/// base32hex (RFC 4648 §7): how an NSEC3 owner label carries a hash.
const BASE32HEX: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Encode bytes as unpadded base32hex.
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
pub fn base32hex_decode(text: &str) -> DnssecResult<Vec<u8>> {
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in text.bytes() {
        let value = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'v' => c - b'a' + 10,
            b'A'..=b'V' => c - b'A' + 10,
            _ => {
                return Err(DnssecError::parse(format!(
                    "invalid base32hex character {:?}",
                    c as char,
                )))
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

/// The NSEC3 hash of `name` (RFC 5155 §5): SHA-1 over the name's wire form,
/// salted and iterated.
///
/// ```text
/// IH(salt, x, 0) = H(x || salt)
/// IH(salt, x, k) = H(IH(salt, x, k-1) || salt)
/// ```
///
/// The salt is appended at every round, and round zero's input is the down-cased
/// *wire-format* name, not its text.
pub fn nsec3_hash(name: &str, salt: &[u8], iterations: u16) -> DnssecResult<Vec<u8>> {
    if iterations > MAX_NSEC3_ITERATIONS {
        return Err(DnssecError::parse(format!(
            "NSEC3 iteration count {iterations} exceeds the {MAX_NSEC3_ITERATIONS} we will compute (RFC 9276)",
        )));
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

/// An NSEC record and the name it sits at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec {
    pub owner: String,
    pub next: String,
    pub type_bitmap: Vec<u8>,
}

impl Nsec {
    pub fn from_record(rr: &ResourceRecord) -> Option<Self> {
        if rr.rdata.rtype() != rt::NSEC {
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
    /// Endpoints are excluded: a name equal to either neighbour exists. The last
    /// NSEC in a zone points back at the apex, so a `next` at or below `owner`
    /// means the range wraps.
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

    pub fn has_type(&self, rtype: Rtype) -> bool {
        bitmap_has_type(&self.type_bitmap, rtype)
    }
}

/// The only NSEC3 hash algorithm IANA has assigned (RFC 5155 §11 registry);
/// anything else must be ignored rather than objected to (§8.1).
const SHA1_HASH_ALGORITHM: u8 = 1;

/// The three fields an NSEC3 hash is a function of (RFC 5155 §5).
///
/// Separate from [`Nsec3`] so a caller searching a chain hashes a name once for
/// the whole chain rather than once per record. A zone mid-NSEC3PARAM roll
/// publishes two chains at once, so a set of records is not always one chain —
/// hence a value to compare rather than an assumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nsec3Params<'a> {
    pub hash_algorithm: u8,
    pub iterations: u16,
    pub salt: &'a [u8],
}

impl Nsec3Params<'_> {
    /// The hash of `name` under these parameters.
    pub fn hash(&self, name: &str) -> DnssecResult<Vec<u8>> {
        if self.hash_algorithm != SHA1_HASH_ALGORITHM {
            return Err(DnssecError::parse(format!(
                "unsupported NSEC3 hash algorithm {}",
                self.hash_algorithm,
            )));
        }
        nsec3_hash(name, self.salt, self.iterations)
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
        if rr.rdata.rtype() != rt::NSEC3 {
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
            } if hash_algorithm == SHA1_HASH_ALGORITHM => Some(Nsec3 {
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

    /// The Opt-Out flag (RFC 5155 §6): the span may contain unsigned delegations
    /// it says nothing about. Enough for "no DS here", never enough for "no name
    /// here".
    pub fn opt_out(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// What this record's hashes are computed under.
    pub fn params(&self) -> Nsec3Params<'_> {
        Nsec3Params {
            hash_algorithm: self.hash_algorithm,
            iterations: self.iterations,
            salt: &self.salt,
        }
    }

    /// The hash of `name` under this record's parameters.
    pub fn hash(&self, name: &str) -> DnssecResult<Vec<u8>> {
        self.params().hash(name)
    }

    /// Whether this NSEC3 is the record for the name whose hash is `hash`.
    ///
    /// The caller owns the check that [`Nsec3::params`] agree; a hash under other
    /// parameters answers a different question.
    pub fn matches_hash(&self, hash: &[u8]) -> bool {
        hash == self.owner_hash
    }

    /// Whether this NSEC3 is the record *for* `name`.
    pub fn matches(&self, name: &str) -> DnssecResult<bool> {
        Ok(self.matches_hash(&self.hash(name)?))
    }

    /// Whether `hash` falls strictly inside this record's span, on the same terms
    /// as [`Nsec3::matches_hash`].
    pub fn covers_hash(&self, hash: &[u8]) -> bool {
        if hash.is_empty() || self.owner_hash.is_empty() || self.next_hashed_owner.is_empty() {
            return false;
        }
        let after = hash > self.owner_hash.as_slice();
        let before = hash < self.next_hashed_owner.as_slice();
        if self.next_hashed_owner.as_slice() > self.owner_hash.as_slice() {
            after && before
        } else {
            // The last NSEC3 wraps around to the first.
            after || before
        }
    }

    /// Whether `name`'s hash falls strictly inside this record's span.
    pub fn covers(&self, name: &str) -> DnssecResult<bool> {
        Ok(self.covers_hash(&self.hash(name)?))
    }

    pub fn has_type(&self, rtype: Rtype) -> bool {
        bitmap_has_type(&self.type_bitmap, rtype)
    }
}

/// One name's NSEC3 hash, computed once per set of parameters it is asked for.
///
/// Use this rather than the record when a name is tested against several
/// records: [`Nsec3::matches`] and [`Nsec3::covers`] each recompute the salted,
/// iterated SHA-1 the previous record just computed — up to
/// `MAX_NSEC3_ITERATIONS + 1` passes thrown away per record.
struct NameHash<'a> {
    name: &'a str,
    /// The parameters `hash` was computed under, and the hash. Replaced whenever
    /// a record's parameters differ.
    computed: Option<(Nsec3Params<'a>, Vec<u8>)>,
}

impl<'a> NameHash<'a> {
    fn new(name: &'a str) -> Self {
        NameHash {
            name,
            computed: None,
        }
    }

    fn under<'r: 'a>(&mut self, record: &'r Nsec3) -> DnssecResult<&[u8]> {
        let params = record.params();
        match &self.computed {
            Some((have, _)) if *have == params => {}
            _ => self.computed = Some((params, params.hash(self.name)?)),
        }
        Ok(&self.computed.as_ref().expect("just filled").1)
    }

    fn matches<'r: 'a>(&mut self, record: &'r Nsec3) -> DnssecResult<bool> {
        Ok(record.matches_hash(self.under(record)?))
    }

    fn covers<'r: 'a>(&mut self, record: &'r Nsec3) -> DnssecResult<bool> {
        Ok(record.covers_hash(self.under(record)?))
    }

    /// Whether any of these records is the one for the name.
    fn matched_by<'r: 'a>(&mut self, records: &'r [Nsec3]) -> bool {
        records.iter().any(|n| self.matches(n).unwrap_or(false))
    }

    /// Whether any of these records' spans contains the name.
    fn covered_by<'r: 'a>(&mut self, records: &'r [Nsec3]) -> bool {
        records.iter().any(|n| self.covers(n).unwrap_or(false))
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

/// Whether these records prove `zone` has no DS — that the delegation is really
/// unsigned rather than having had its DS stripped (RFC 4035 §5.2,
/// RFC 5155 §8.9).
///
/// Without it, stripping the DS from a referral makes every signed zone below
/// look unsigned.
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

    // RFC 5155 §8.1: ignore records we cannot hash; only a set of *nothing but*
    // those is bogus. So skip rather than return, and report the reason below
    // only if nothing matched — the RFC 9276 iteration cap is the likeliest
    // cause and an operator needs it named.
    let mut unusable: Option<String> = None;
    let mut hash = NameHash::new(zone);
    for nsec3 in nsec3s {
        match hash.matches(nsec3) {
            Ok(true) => {
                if nsec3.has_type(rt::DS) {
                    return Denial::NotProved(format!("the NSEC3 for {zone} says a DS does exist"));
                }
                if !nsec3.has_type(rt::NS) {
                    return Denial::NotProved(format!(
                        "the NSEC3 for {zone} is not at a delegation"
                    ));
                }
                return Denial::Proved;
            }
            Ok(false) => {}
            Err(e) => unusable = unusable.or(Some(e.to_string())),
        }
    }

    // No NSEC3 names the delegation. A covering record with Opt-Out set
    // (RFC 5155 §6) claims there may be insecure delegations in the span, which
    // is the claim needed here. Without the flag it claims the name does not
    // exist at all, contradicting the referral we just followed.
    for nsec3 in nsec3s {
        if nsec3.opt_out() && hash.covers(nsec3).unwrap_or(false) {
            return Denial::Proved;
        }
    }

    if let Some(why) = unusable {
        return Denial::NotProved(format!("NSEC3 for {zone} unusable: {why}"));
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
        // The wildcard to disprove sits at the closest encloser, which for an
        // NSEC proof is the longest suffix of qname shared with either end of
        // the covering record.
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
///
/// Two shapes. Usually a record sits *at* the name and its bitmap lacks `qtype`.
/// But the name may not exist and a wildcard may be what answered, having no
/// record of this type either: that proof is one record showing the name absent
/// plus the one *at the wildcard* showing what a wildcard would have answered
/// with (RFC 4035 §5.4, RFC 5155 §8.7).
pub fn proves_nodata(
    qname: &str,
    zone: &str,
    qtype: Rtype,
    nsecs: &[Nsec],
    nsec3s: &[Nsec3],
) -> Denial {
    for nsec in nsecs {
        if !nsec.matches(qname) {
            continue;
        }
        return nodata_bitmap(qtype, qname, |t| nsec.has_type(t));
    }

    // As in `proves_no_ds`: skip an unusable record rather than return on it, so
    // it cannot poison a set a later record — or the wildcard path below — would
    // have answered from.
    let mut unusable: Option<String> = None;
    let mut hash = NameHash::new(qname);
    for nsec3 in nsec3s {
        match hash.matches(nsec3) {
            Ok(true) => return nodata_bitmap(qtype, qname, |t| nsec3.has_type(t)),
            Ok(false) => {}
            Err(e) => unusable = unusable.or(Some(e.to_string())),
        }
    }

    // Nothing is at the name, so the name does not exist and a wildcard is what
    // answered. Both halves of that have to be shown.
    if !nsecs.is_empty() {
        return nsec_wildcard_nodata(qname, qtype, nsecs);
    }
    if !nsec3s.is_empty() {
        // Report a skipped record's reason only if the wildcard proof also
        // failed; checking above this branch would re-introduce the
        // short-circuit. `nsec3_closest_encloser` swallows the same failure with
        // `unwrap_or(false)`, so without this the RFC 9276 iteration cap reaches
        // the operator as "no closest encloser".
        return match (nsec3_wildcard_nodata(qname, zone, qtype, nsec3s), unusable) {
            (Denial::NotProved(_), Some(why)) => {
                Denial::NotProved(format!("NSEC3 for {qname} unusable: {why}"))
            }
            (proof, _) => proof,
        };
    }

    Denial::NotProved(format!(
        "no NSEC or NSEC3 record denies type {qtype} at {qname}"
    ))
}

/// The bitmap half of a NODATA proof: the type asked for must be absent, and so
/// must CNAME — a CNAME would have been followed rather than answered NODATA.
fn nodata_bitmap(qtype: Rtype, at: &str, has_type: impl Fn(Rtype) -> bool) -> Denial {
    if has_type(qtype) {
        return Denial::NotProved(format!("the denial at {at} says type {qtype} exists"));
    }
    if has_type(rt::CNAME) {
        return Denial::NotProved(format!("{at} has a CNAME, which is not NODATA"));
    }
    Denial::Proved
}

/// Wildcard NODATA with NSEC: the name is covered (so it does not exist), and
/// the wildcard at its closest encloser has an NSEC whose bitmap lacks the type.
///
/// The closest encloser is derived from the covering record, not taken on the
/// responder's word — otherwise a wildcard higher up the tree than the one
/// governing the name would do, as in [`proves_wildcard_expansion`].
fn nsec_wildcard_nodata(qname: &str, qtype: Rtype, nsecs: &[Nsec]) -> Denial {
    let Some(covering) = nsecs.iter().find(|n| n.covers(qname)) else {
        return Denial::NotProved(format!("no NSEC matches or covers {qname}"));
    };
    let wildcard = format!("*.{}", closest_encloser_nsec(qname, covering));
    let Some(matching) = nsecs.iter().find(|n| n.matches(&wildcard)) else {
        return Denial::NotProved(format!(
            "{qname} does not exist and no NSEC at {wildcard} says what a wildcard would \
             have answered"
        ));
    };
    nodata_bitmap(qtype, &wildcard, |t| matching.has_type(t))
}

/// Wildcard NODATA with NSEC3 (RFC 5155 §8.7): the closest-encloser proof for
/// `qname`, and an NSEC3 matching the wildcard at that encloser whose bitmap
/// lacks the type.
fn nsec3_wildcard_nodata(qname: &str, zone: &str, qtype: Rtype, nsec3s: &[Nsec3]) -> Denial {
    let encloser = match nsec3_closest_encloser(qname, zone, nsec3s) {
        Ok(encloser) => encloser,
        Err(why) => return Denial::NotProved(why),
    };
    let wildcard = format!("*.{encloser}");
    let mut hash = NameHash::new(&wildcard);
    let Some(matching) = nsec3s.iter().find(|n| hash.matches(n).unwrap_or(false)) else {
        return Denial::NotProved(format!(
            "{qname} does not exist and no NSEC3 matches the wildcard {wildcard}"
        ));
    };
    nodata_bitmap(qtype, &wildcard, |t| matching.has_type(t))
}

/// The outcome of checking a wildcard-expanded answer.
///
/// Three states rather than [`Denial`]'s two: an Opt-Out NSEC3 span declines to
/// say whether a delegation sits in the gap, so the answer is neither authentic
/// nor forged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WildcardVerdict {
    /// The name really had nothing of its own: expanding the wildcard was right.
    Proved,
    /// The records offered cannot settle it, through no fault of the answer.
    /// Insecure, not bogus.
    Unjudgeable(String),
    /// No proof, or a proof of something else.
    NotProved(String),
}

/// Whether these records prove that `owner` — a name answered out of the
/// wildcard `wildcard` — had nothing of its own, so expanding that wildcard was
/// correct (RFC 4035 §5.3.4, RFC 5155 §8.8).
///
/// A wildcard signature verifies at every name the wildcard could expand to, so
/// a genuine RRset can be re-owned onto any name under the encloser. Two things
/// rule that substitution out:
///
/// - The name asked about has no records of its own.
/// - The wildcard is the one that name's closest encloser publishes, not one
///   further up the tree: if an ancestor of `owner` below `wildcard`'s parent
///   exists, RFC 4592 §3.3.1 says the wildcard at *that* name governs. NSEC gets
///   this from the closest encloser the covering record implies; NSEC3 gets it
///   from the "next closer" name, which is derived from where the wildcard sits.
pub fn proves_wildcard_expansion(
    owner: &str,
    wildcard: &str,
    nsecs: &[Nsec],
    nsec3s: &[Nsec3],
) -> WildcardVerdict {
    let owner = crate::dnssec::canonical_name(owner);
    let Some(encloser) = wildcard_encloser(wildcard) else {
        return WildcardVerdict::NotProved(format!("{wildcard} is not a wildcard name"));
    };
    if crate::dnssec::label_count(&owner) <= crate::dnssec::label_count(&encloser) {
        return WildcardVerdict::NotProved(format!(
            "{owner} is not below {encloser}, so {wildcard} cannot have expanded to it"
        ));
    }

    if !nsecs.is_empty() {
        let Some(covering) = nsecs.iter().find(|n| n.covers(&owner)) else {
            return WildcardVerdict::NotProved(format!(
                "no NSEC covers {owner}, so nothing rules out records of its own"
            ));
        };
        // Both ends of a covering NSEC exist, so the longest suffix shared with
        // either is the deepest ancestor of `owner` known to exist. Deeper than
        // the wildcard's own parent means this wildcard never applied.
        let found = closest_encloser_nsec(&owner, covering);
        if canonical_name_cmp(&found, &encloser) != Ordering::Equal {
            return WildcardVerdict::NotProved(format!(
                "the NSEC covering {owner} puts its closest encloser at {found}, \
                 not at {encloser} where {wildcard} lives"
            ));
        }
        return WildcardVerdict::Proved;
    }

    if !nsec3s.is_empty() {
        // RFC 5155 §8.8: show the "next closer" name — one label below the
        // encloser, towards `owner` — absent. Naming it from the wildcard's own
        // position pins the expansion to the right depth.
        let next_closer =
            crate::dnssec::suffix_labels(&owner, crate::dnssec::label_count(&encloser) + 1);
        let mut hash = NameHash::new(&next_closer);
        if nsec3s
            .iter()
            .any(|n| !n.opt_out() && hash.covers(n).unwrap_or(false))
        {
            return WildcardVerdict::Proved;
        }
        // Opt-out (RFC 5155 §6): if the next closer name is one of the
        // delegations the span never named, `owner` lives in a child zone and a
        // referral was the honest answer. Proves nothing, accuses nothing.
        if hash.covered_by(nsec3s) {
            return WildcardVerdict::Unjudgeable(format!(
                "the NSEC3 covering the next closer name {next_closer} has Opt-Out set"
            ));
        }
        return WildcardVerdict::NotProved(format!(
            "no NSEC3 covers the next closer name {next_closer}"
        ));
    }

    WildcardVerdict::NotProved(format!(
        "{owner} was answered from {wildcard} with no denial of {owner} at all"
    ))
}

/// The name a wildcard hangs off. `None` for a name that is not a wildcard.
fn wildcard_encloser(wildcard: &str) -> Option<String> {
    let name = crate::dnssec::canonical_name(wildcard);
    let rest = name.strip_prefix("*.")?;
    Some(if rest.is_empty() {
        ".".to_string()
    } else {
        rest.to_string()
    })
}

/// The longest suffix `qname` shares with either end of the NSEC covering it.
/// Both ends provably exist, so this is `qname`'s closest ancestor that does.
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

/// The RFC 5155 §8.4 closest-encloser proof: the encloser is proven, the name one
/// label below it is absent, and the wildcard at the encloser is accounted for —
/// without which one could still have answered.
fn nsec3_closest_encloser_proof(qname: &str, zone: &str, nsec3s: &[Nsec3]) -> Denial {
    let encloser = match nsec3_closest_encloser(qname, zone, nsec3s) {
        Ok(encloser) => encloser,
        Err(why) => return Denial::NotProved(why),
    };
    let wildcard = format!("*.{encloser}");
    let mut hash = NameHash::new(&wildcard);
    let wildcard_denied = hash.covered_by(nsec3s) || hash.matched_by(nsec3s);
    if !wildcard_denied {
        return Denial::NotProved(format!("no NSEC3 accounts for the wildcard {wildcard}"));
    }
    Denial::Proved
}

/// The closest encloser of `qname` these NSEC3 records prove (RFC 5155 §8.3):
/// the deepest ancestor one of them matches, provided the "next closer" name one
/// label below it is covered. That pair makes `qname` impossible and names the
/// only wildcard that could have applied.
///
/// `Err` carries why the proof does not stand — including a record matching
/// `qname` itself, which says the name exists.
fn nsec3_closest_encloser(qname: &str, zone: &str, nsec3s: &[Nsec3]) -> Result<String, String> {
    let qname = crate::dnssec::canonical_name(qname);
    let zone = crate::dnssec::canonical_name(zone);
    let qlabels = crate::dnssec::label_count(&qname);
    let zlabels = crate::dnssec::label_count(&zone);

    // Walk up towards the apex, which always exists, so the search terminates.
    for depth in (zlabels..=qlabels).rev() {
        let candidate = crate::dnssec::suffix_labels(&qname, depth);
        if !NameHash::new(&candidate).matched_by(nsec3s) {
            continue;
        }
        if depth == qlabels {
            return Err(format!("an NSEC3 matches {qname}, so it exists"));
        }
        // The "next closer" name: one label longer than the encloser.
        let next_closer = crate::dnssec::suffix_labels(&qname, depth + 1);
        if !NameHash::new(&next_closer).covered_by(nsec3s) {
            return Err(format!(
                "no NSEC3 covers the next closer name {next_closer}"
            ));
        }
        return Ok(candidate);
    }

    Err(format!("no NSEC3 matches any ancestor of {qname}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Class;
    use crate::RecordData;
    use crate::Ttl;

    fn nsec(owner: &str, next: &str, types: &[Rtype]) -> Nsec {
        Nsec {
            owner: owner.to_string(),
            next: next.to_string(),
            type_bitmap: build_type_bitmap(types),
        }
    }

    /// Sorting is by label from the right, so a deeper name under an earlier
    /// label comes first.
    #[test]
    fn test_canonical_order_is_by_label_from_the_right() {
        // The rightmost differing label decides.
        assert_eq!(
            canonical_name_cmp("a.z.example.com.", "b.example.com."),
            Ordering::Greater
        );
        // Plain string comparison gets exactly this backwards.
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
                    canonical_sort_key(a).cmp(&canonical_sort_key(b)),
                    canonical_name_cmp(a, b),
                    "sort key disagrees with canonical order for {a:?} vs {b:?}"
                );
            }
        }
        // The two properties the zero terminator buys, spelled out.
        assert!(canonical_sort_key("example.") < canonical_sort_key("a.example."));
        assert!(canonical_sort_key("ab.example.") < canonical_sort_key("abc.example."));
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

    /// RFC 5155 Appendix A: the zone `example.` with salt `aabbccdd` and 12
    /// iterations hashes `a.example.` to `35mthgpgcu1qg68fab165klnsnk3dpvl`.
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

    /// The salt and the iteration count each change the hash.
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
        let err =
            nsec3_hash("a.example.", &[], u16::MAX).expect_err("65535 rounds must be refused");
        assert!(err.to_string().contains("exceeds"), "got: {err}");
    }

    #[test]
    fn test_nsec_proves_an_unsigned_delegation() {
        // The parent's NSEC at the delegation: NS present, DS absent.
        let n = nsec(
            "insecure.example.com.",
            "z.example.com.",
            &[rt::NS, rt::RRSIG, rt::NSEC],
        );
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
        let n = nsec(
            "www.example.com.",
            "z.example.com.",
            &[rt::A, rt::RRSIG, rt::NSEC],
        );
        // No AAAA in the bitmap, so NODATA for AAAA is proven.
        assert!(proves_nodata(
            "www.example.com.",
            "example.com.",
            rt::AAAA,
            std::slice::from_ref(&n),
            &[]
        )
        .is_proved());
        // But A is listed, so it cannot deny that.
        assert!(!proves_nodata("www.example.com.", "example.com.", rt::A, &[n], &[]).is_proved());
    }

    /// A CNAME at the name would have been followed rather than answered NODATA,
    /// so a bitmap listing one contradicts the proof.
    #[test]
    fn test_nsec_nodata_refuses_a_name_with_a_cname() {
        let n = nsec(
            "www.example.com.",
            "z.example.com.",
            &[rt::CNAME, rt::RRSIG],
        );
        let denial = proves_nodata("www.example.com.", "example.com.", rt::A, &[n], &[]);
        assert!(!denial.is_proved(), "{denial:?}");
    }

    /// Wildcard NODATA: the name does not exist, a wildcard answered, and the
    /// wildcard has no record of this type either. One NSEC does both jobs
    /// here — it sits at the wildcard and covers `a.example.com.`.
    #[test]
    fn test_wildcard_nodata_is_proved() {
        let at_wildcard = nsec(
            "*.example.com.",
            "www.example.com.",
            &[rt::A, rt::RRSIG, rt::NSEC],
        );
        let denial = proves_nodata(
            "a.example.com.",
            "example.com.",
            rt::AAAA,
            std::slice::from_ref(&at_wildcard),
            &[],
        );
        assert!(denial.is_proved(), "{denial:?}");

        // A is in the wildcard's bitmap, so the wildcard *would* have answered
        // that — this is not NODATA for A.
        let denial = proves_nodata(
            "a.example.com.",
            "example.com.",
            rt::A,
            std::slice::from_ref(&at_wildcard),
            &[],
        );
        assert!(!denial.is_proved(), "{denial:?}");
    }

    /// Covering the name is not enough: without the record at the wildcard,
    /// nothing says which types a wildcard would have answered with.
    #[test]
    fn test_wildcard_nodata_needs_the_record_at_the_wildcard() {
        let covering = nsec("m.example.com.", "z.example.com.", &[rt::A, rt::RRSIG]);
        let denial = proves_nodata(
            "nope.example.com.",
            "example.com.",
            rt::AAAA,
            &[covering],
            &[],
        );
        assert!(!denial.is_proved(), "{denial:?}");
    }

    /// `b.example.com.` exists, so `*.example.com.` never governed
    /// `a.b.example.com.` and its bitmap says nothing about that name.
    #[test]
    fn test_wildcard_nodata_at_the_wrong_depth_is_refused() {
        let at_wildcard = nsec(
            "*.example.com.",
            "b.example.com.",
            &[rt::A, rt::RRSIG, rt::NSEC],
        );
        let covering = nsec(
            "b.example.com.",
            "c.example.com.",
            &[rt::A, rt::RRSIG, rt::NSEC],
        );
        assert!(covering.covers("a.b.example.com."), "the name is covered");

        let denial = proves_nodata(
            "a.b.example.com.",
            "example.com.",
            rt::AAAA,
            &[at_wildcard, covering],
            &[],
        );
        assert!(
            !denial.is_proved(),
            "the closest encloser is b.example.com., whose wildcard was never shown: {denial:?}"
        );
    }

    /// RFC 5155 §8.7: the closest-encloser proof, plus an NSEC3 matching the
    /// wildcard whose bitmap lacks the type.
    #[test]
    fn test_nsec3_wildcard_nodata_is_proved() {
        // `a.example.com.` does not exist: the encloser is the apex (matched),
        // the next closer name is `a.example.com.` itself (covered), and the
        // wildcard is matched with only A in its bitmap.
        let apex = nsec3_matching("example.com.", &[rt::SOA, rt::NS, rt::RRSIG]);
        let next_closer = nsec3_span_around("a.example.com.", 0);
        let wildcard = nsec3_matching("*.example.com.", &[rt::A, rt::RRSIG]);
        let proofs = vec![apex, next_closer, wildcard];

        let denial = proves_nodata("a.example.com.", "example.com.", rt::AAAA, &[], &proofs);
        assert!(denial.is_proved(), "{denial:?}");

        // A is in the wildcard's bitmap.
        let denial = proves_nodata("a.example.com.", "example.com.", rt::A, &[], &proofs);
        assert!(!denial.is_proved(), "{denial:?}");

        // And without the record at the wildcard there is no proof at all.
        let denial = proves_nodata(
            "a.example.com.",
            "example.com.",
            rt::AAAA,
            &[],
            &proofs[..2],
        );
        assert!(!denial.is_proved(), "{denial:?}");

        // Without the next closer name covered, `a.example.com.` may exist in
        // its own right and the wildcard is not what answered.
        let denial = proves_nodata(
            "a.example.com.",
            "example.com.",
            rt::AAAA,
            &[],
            &[proofs[0].clone(), proofs[2].clone()],
        );
        assert!(!denial.is_proved(), "{denial:?}");
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

    /// `a.example.com.` answered from `*.example.com.`, with the NSEC showing
    /// it has nothing of its own — often the wildcard's own NSEC, since `*`
    /// sorts before every ordinary label.
    #[test]
    fn test_wildcard_expansion_proved_by_a_covering_nsec() {
        let covering = nsec("*.example.com.", "www.example.com.", &[rt::A, rt::RRSIG]);
        let verdict = proves_wildcard_expansion(
            "a.example.com.",
            "*.example.com.",
            std::slice::from_ref(&covering),
            &[],
        );
        assert_eq!(verdict, WildcardVerdict::Proved, "{verdict:?}");
    }

    /// No denial at all: the signature verified, and that is all it did.
    #[test]
    fn test_wildcard_expansion_without_any_nsec_is_not_proved() {
        let verdict = proves_wildcard_expansion("a.example.com.", "*.example.com.", &[], &[]);
        assert!(
            matches!(verdict, WildcardVerdict::NotProved(_)),
            "{verdict:?}"
        );
    }

    /// An NSEC whose range does not contain the name is not the proof asked for.
    #[test]
    fn test_wildcard_expansion_needs_the_name_covered() {
        let elsewhere = nsec("m.example.com.", "n.example.com.", &[rt::A]);
        let verdict =
            proves_wildcard_expansion("a.example.com.", "*.example.com.", &[elsewhere], &[]);
        assert!(
            matches!(verdict, WildcardVerdict::NotProved(_)),
            "{verdict:?}"
        );
    }

    /// The attack the closest-encloser check stops: `b.example.com.` exists, so
    /// only `*.b.example.com.` governs `a.b.example.com.` — yet the NSEC at
    /// `b.example.com.` covers it, since a name sorts before everything beneath
    /// it. "Some NSEC covers the name" would accept a re-owned RRset here.
    #[test]
    fn test_wildcard_expansion_at_the_wrong_depth_is_refused() {
        let covering = nsec("b.example.com.", "c.example.com.", &[rt::A, rt::RRSIG]);
        assert!(
            covering.covers("a.b.example.com."),
            "the fact that makes the attack possible"
        );

        let verdict = proves_wildcard_expansion(
            "a.b.example.com.",
            "*.example.com.",
            std::slice::from_ref(&covering),
            &[],
        );
        assert!(
            matches!(verdict, WildcardVerdict::NotProved(_)),
            "the wildcard sits above the closest encloser: {verdict:?}"
        );

        // The wildcard at the closest encloser itself is fine.
        let verdict =
            proves_wildcard_expansion("a.b.example.com.", "*.b.example.com.", &[covering], &[]);
        assert_eq!(verdict, WildcardVerdict::Proved, "{verdict:?}");
    }

    /// A name that is not below the wildcard cannot have come from it, whatever
    /// else is offered.
    #[test]
    fn test_wildcard_expansion_outside_the_wildcard_is_refused() {
        let wide = nsec("example.com.", "z.example.com.", &[rt::SOA]);
        let verdict = proves_wildcard_expansion("other.test.", "*.example.com.", &[wide], &[]);
        assert!(
            matches!(verdict, WildcardVerdict::NotProved(_)),
            "{verdict:?}"
        );
    }

    /// RFC 5155 §8.8: the "next closer" name is what has to be covered, one
    /// label below the wildcard, which pins the expansion to the right depth.
    #[test]
    fn test_nsec3_wildcard_expansion_covers_the_next_closer_name() {
        let span = nsec3_span_around;

        // `a.example.com.` from `*.example.com.`: the next closer name is
        // `a.example.com.` itself.
        let verdict = proves_wildcard_expansion(
            "a.example.com.",
            "*.example.com.",
            &[],
            &[span("a.example.com.", 0)],
        );
        assert_eq!(verdict, WildcardVerdict::Proved, "{verdict:?}");

        // Two labels down, the next closer is the intermediate name — covering
        // the leaf instead proves nothing about `b.example.com.`.
        let verdict = proves_wildcard_expansion(
            "a.b.example.com.",
            "*.example.com.",
            &[],
            &[span("a.b.example.com.", 0)],
        );
        assert!(
            matches!(verdict, WildcardVerdict::NotProved(_)),
            "covering the leaf says nothing about its parent: {verdict:?}"
        );
        let verdict = proves_wildcard_expansion(
            "a.b.example.com.",
            "*.example.com.",
            &[],
            &[span("b.example.com.", 0)],
        );
        assert_eq!(verdict, WildcardVerdict::Proved, "{verdict:?}");
    }

    /// Opt-out says nothing about delegations in the span, so the name may live
    /// in a child zone: neither a proof nor an accusation, so insecure.
    #[test]
    fn test_nsec3_wildcard_expansion_over_an_opt_out_span_is_unjudgeable() {
        let opt_out = nsec3_span_around("a.example.com.", 0x01);
        let verdict =
            proves_wildcard_expansion("a.example.com.", "*.example.com.", &[], &[opt_out]);
        assert!(
            matches!(verdict, WildcardVerdict::Unjudgeable(_)),
            "{verdict:?}"
        );
    }

    /// An NSEC3 matching `name` and covering nothing — its span is the empty
    /// interval above its own hash, so it cannot stand in for a covering record.
    fn nsec3_matching(name: &str, types: &[Rtype]) -> Nsec3 {
        let salt = vec![0x01, 0x02];
        let hash = nsec3_hash(name, &salt, 5).expect("hash");
        Nsec3 {
            owner: format!("{}.example.com.", base32hex_encode(&hash).to_lowercase()),
            next_hashed_owner: hash_step(&hash, true),
            owner_hash: hash,
            zone: "example.com.".into(),
            hash_algorithm: 1,
            flags: 0,
            iterations: 5,
            salt,
            type_bitmap: build_type_bitmap(types),
        }
    }

    /// An NSEC3 whose span contains exactly `name`'s hash: one step below to one
    /// step above. Derived from the hash, since fixed bytes would cover or miss
    /// it by luck.
    fn nsec3_span_around(name: &str, flags: u8) -> Nsec3 {
        let salt = vec![0x01, 0x02];
        let hash = nsec3_hash(name, &salt, 5).expect("hash");
        let low = hash_step(&hash, false);
        Nsec3 {
            owner: format!("{}.example.com.", base32hex_encode(&low).to_lowercase()),
            owner_hash: low,
            zone: "example.com.".into(),
            hash_algorithm: 1,
            flags,
            iterations: 5,
            salt,
            next_hashed_owner: hash_step(&hash, true),
            type_bitmap: build_type_bitmap(&[rt::A]),
        }
    }

    /// A hash one step up or down as the big-endian number it is compared as.
    fn hash_step(hash: &[u8], up: bool) -> Vec<u8> {
        let mut out = hash.to_vec();
        for byte in out.iter_mut().rev() {
            if up {
                *byte = byte.wrapping_add(1);
                if *byte != 0x00 {
                    break;
                }
            } else {
                *byte = byte.wrapping_sub(1);
                if *byte != 0xff {
                    break;
                }
            }
        }
        out
    }

    fn nsec3_record(zone: &str, name: &str, next: &[u8], flags: u8, types: &[Rtype]) -> Nsec3 {
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
        let n = nsec3_record(
            "example.com.",
            "child.example.com.",
            &[0xff; 20],
            0,
            &[rt::NS],
        );
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
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
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

    /// An absurd iteration count fails closed rather than burning CPU per name.
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

    /// One NSEC3 we cannot hash must not poison a set another record answers
    /// from: RFC 5155 §8.1 ignores such records, and only a set of nothing but
    /// them is bogus. The set comes out of a response, so the order in it is
    /// not ours to choose.
    #[test]
    fn one_unhashable_nsec3_does_not_poison_the_rest_of_the_set() {
        // Over the RFC 9276 cap, so `matches` is an `Err` rather than a
        // mismatch. Everything else about it is well formed.
        let mut poison = nsec3_matching("other.example.com.", &[rt::A]);
        poison.iterations = MAX_NSEC3_ITERATIONS + 1;

        let good = nsec3_matching("example.com.", &[rt::NS]);
        assert_eq!(
            proves_no_ds("example.com.", &[], std::slice::from_ref(&good)),
            Denial::Proved,
            "the usable record alone proves it",
        );

        // The same set with the unusable record placed first.
        assert_eq!(
            proves_no_ds("example.com.", &[], &[poison, good]),
            Denial::Proved,
            "an ignorable record before it must not change the answer",
        );
    }

    /// When *every* record is unusable the reason still reaches the caller
    /// rather than being flattened into "nothing covers this". Skipping
    /// unusable records is what puts that diagnostic at risk. Not a regression
    /// test: it passes against the returning-on-first-`Err` form too.
    #[test]
    fn a_set_of_only_unhashable_nsec3s_reports_why() {
        let mut poison = nsec3_matching("example.com.", &[rt::NS]);
        poison.iterations = MAX_NSEC3_ITERATIONS + 1;

        match proves_no_ds("example.com.", &[], &[poison]) {
            Denial::NotProved(why) => assert!(
                why.contains("iteration count"),
                "the cap should be named, got {why:?}",
            ),
            other => panic!("expected NotProved, got {other:?}"),
        }
    }

    /// An NSEC3 whose hash algorithm is not SHA-1 is dropped as it is read
    /// (RFC 5155 §8.1), so the set the parser hands on is all usable. The
    /// §11 registry reserves 0 and leaves 2-255 unassigned.
    #[test]
    fn an_nsec3_with_an_unknown_hash_algorithm_is_not_read_at_all() {
        let usable = nsec3_matching("example.com.", &[rt::NS]);
        let mut rdata = Vec::new();
        rdata.push(2u8); // hash algorithm 2 — unassigned
        rdata.push(usable.flags);
        rdata.extend_from_slice(&usable.iterations.to_be_bytes());
        rdata.push(usable.salt.len() as u8);
        rdata.extend_from_slice(&usable.salt);
        rdata.push(usable.next_hashed_owner.len() as u8);
        rdata.extend_from_slice(&usable.next_hashed_owner);
        rdata.extend_from_slice(&usable.type_bitmap);

        let rr = ResourceRecord {
            name: usable.owner.clone(),
            class: Class::IN,
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::new(rt::NSEC3, rdata).expect("well-formed NSEC3 rdata"),
        };
        assert!(
            Nsec3::from_record(&rr).is_none(),
            "an unknown hash type must be ignored, not stored",
        );
    }
}
