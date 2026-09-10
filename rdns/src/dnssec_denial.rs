//! Denial of existence: NSEC and NSEC3.
//!
//! A zone signs statements about the gaps between the names that exist. Checking
//! that a gap contains the name asked about needs the canonical name ordering of
//! RFC 4034 §6.1 — not string order — and, for NSEC3, the salted iterated hash
//! of RFC 5155 §5.

use crate::denial_wire::{
    base32hex_decode, bitmap_has_type, canonical_name_cmp, encode_base32hex, encode_base32hex_in,
    BASE32HEX_LOWER,
};
use crate::dname::MAX_NAME_LEN;
use crate::error::WireResult;
use crate::error::{DnssecError, DnssecResult};
use crate::record_types as rt;
use crate::Name;
use crate::NameRef;
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

/// The length of an NSEC3 hash. SHA-1 is the only algorithm RFC 5155 §5
/// defines, and the registry it points at has had no second entry since.
pub const NSEC3_HASH_LEN: usize = 20;

/// The owner name of the NSEC3 record for `hash` in `origin`: the hash as a
/// base32hex label (RFC 5155 §3.3), prepended to the zone.
///
/// Down-cased, because that is the form this server's signer writes and the
/// zone index folds to. It was spelled out per module as
/// `format!("{}.{origin}", base32hex_encode(h).to_lowercase())` — three
/// allocations where one does, and a Unicode fold over ASCII (CLAUDE.md §8).
pub fn nsec3_owner_name_at(hash: Nsec3Hash, origin: NameRef<'_>) -> WireResult<Name> {
    // The label is base32hex of a 20-octet SHA-1 digest — 32 characters, so it
    // fits a label and needs no heap of its own. Building the name directly
    // skips a `String` and a re-parse of text this already knows the shape of.
    let mut label = [0u8; 32];
    let len = encode_base32hex_in(hash.as_bytes(), BASE32HEX_LOWER, &mut label);
    Name::prefixed(&label[..len], origin)
}

pub fn nsec3_owner_name(hash: &[u8], origin: &str) -> String {
    let mut out =
        String::with_capacity(crate::denial_wire::base32hex_len(hash.len()) + 1 + origin.len());
    encode_base32hex(hash, BASE32HEX_LOWER, &mut out);
    out.push('.');
    out.push_str(origin);
    out
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
pub fn nsec3_hash(name: &str, salt: &[u8], iterations: u16) -> DnssecResult<Nsec3Hash> {
    nsec3_hash_in(name, salt, iterations)
}

/// [`nsec3_hash`] without allocating.
///
/// SHA-1 is the only algorithm RFC 5155 §5 defines, so the digest is twenty
/// octets and neither it nor the wire name it starts from needs the heap. The
/// closest-encloser walk hashes a name per label of the QNAME and each
/// iteration used to rebuild the digest as a fresh `Vec`.
pub fn nsec3_hash_in(name: &str, salt: &[u8], iterations: u16) -> DnssecResult<Nsec3Hash> {
    // Into the stack: §8.3's walk hashes a name per label of the QNAME and
    // keeps none of them, so this is the one place presentation text is read
    // without building a `Name`.
    let mut buf = [0u8; MAX_NAME_LEN];
    let len = crate::name::presentation_wire_in(name, &mut buf)?;
    hash_wire(&mut buf[..len], salt, iterations)
}

/// The same for a name that is already wire octets — which is what §5 hashes,
/// so this is the direct spelling and the text forms are the conversions.
///
/// The closest-encloser walk hashes one name per label of the QNAME, and going
/// through presentation text cost a `String` per candidate for a round trip
/// back to the octets already at hand.
pub fn nsec3_hash_name(name: NameRef<'_>, salt: &[u8], iterations: u16) -> DnssecResult<Nsec3Hash> {
    let wire = name.as_wire();
    let mut buf = [0u8; MAX_NAME_LEN];
    // `NameRef` cannot exceed RFC 1035 §2.3.4's limit, so this cannot overrun.
    buf[..wire.len()].copy_from_slice(wire);
    hash_wire(&mut buf[..wire.len()], salt, iterations)
}

/// `wire` is down-cased in place, so it is taken by value rather than shared.
fn hash_wire(wire: &mut [u8], salt: &[u8], iterations: u16) -> DnssecResult<Nsec3Hash> {
    if iterations > MAX_NSEC3_ITERATIONS {
        return Err(DnssecError::parse(format!(
            "NSEC3 iteration count {iterations} exceeds the {MAX_NSEC3_ITERATIONS} we will compute (RFC 9276)",
        )));
    }
    // Down-cased in the encoded form rather than in the text: a length octet is
    // at most 63 (RFC 1035 §2.3.4) and `A` is 65, so no length is touched.
    wire.make_ascii_lowercase();

    let mut digest = [0u8; NSEC3_HASH_LEN];
    let mut hasher = Sha1::new();
    hasher.update(&wire);
    hasher.update(salt);
    digest.copy_from_slice(&hasher.finalize());

    for _ in 0..iterations {
        let mut hasher = Sha1::new();
        hasher.update(digest);
        hasher.update(salt);
        digest.copy_from_slice(&hasher.finalize());
    }
    Ok(Nsec3Hash(digest))
}

/// An NSEC record and the name it sits at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec {
    pub owner: Name,
    pub next: Name,
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
                owner: rr.name.as_ref().to_folded(),
                next: next_domain_name.as_ref().to_folded(),
                type_bitmap,
            }),
            _ => None,
        }
    }

    /// Whether this NSEC's owner *is* `name`.
    pub fn matches(&self, name: NameRef<'_>) -> bool {
        self.owner.as_ref() == name
    }

    /// Whether `name` falls strictly inside the gap this NSEC describes.
    ///
    /// Endpoints are excluded: a name equal to either neighbour exists. The last
    /// NSEC in a zone points back at the apex, so a `next` at or below `owner`
    /// means the range wraps.
    pub fn covers(&self, name: NameRef<'_>) -> bool {
        let after_owner = canonical_name_cmp(name, self.owner.as_ref()) == Ordering::Greater;
        let before_next = canonical_name_cmp(name, self.next.as_ref()) == Ordering::Less;
        if canonical_name_cmp(self.next.as_ref(), self.owner.as_ref()) == Ordering::Greater {
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
    pub fn hash(&self, name: NameRef<'_>) -> DnssecResult<Nsec3Hash> {
        if self.hash_algorithm != SHA1_HASH_ALGORITHM {
            return Err(DnssecError::parse(format!(
                "unsupported NSEC3 hash algorithm {}",
                self.hash_algorithm,
            )));
        }
        nsec3_hash_name(name, self.salt, self.iterations)
    }
}

/// The 20 octets RFC 5155 §5 hashes a name to, and the only length one can be.
///
/// SHA-1 is the only algorithm IANA has registered for NSEC3 and [`Nsec3`]
/// refuses any other, so a hash of another length is not a short hash — it is
/// not a hash. As a `Vec<u8>` it was a heap allocation per map key for 20 bytes,
/// and a wrong length from a remote record was stored and then silently never
/// matched, which is what `covers` carried an `is_empty()` guard for
/// (`TODO.md` #40a).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nsec3Hash([u8; NSEC3_HASH_LEN]);

impl Nsec3Hash {
    /// The hash these octets are, if they are the right number of them.
    pub fn from_wire(bytes: &[u8]) -> Option<Nsec3Hash> {
        Some(Nsec3Hash(bytes.try_into().ok()?))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// An NSEC3 record, with its owner hash decoded out of the first label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3 {
    pub owner: Name,
    /// The hash in the owner's first label, decoded from base32hex.
    pub owner_hash: Nsec3Hash,
    /// Everything after that label — the zone the NSEC3 belongs to.
    pub zone: Name,
    pub hash_algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
    pub next_hashed_owner: Nsec3Hash,
    pub type_bitmap: Vec<u8>,
}

impl Nsec3 {
    pub fn from_record(rr: &ResourceRecord) -> Option<Self> {
        if rr.rdata.rtype() != rt::NSEC3 {
            return None;
        }
        // The first label and the rest, taken on the wire: the hash label is
        // base32hex, but the zone below it can hold RFC 1035 §5.1's `\.`, which
        // splitting the text on a dot would cut in the wrong place.
        let owner = rr.name.as_ref().to_folded();
        let first = owner.as_ref().labels().next()?;
        let zone = owner.as_ref().parent()?.to_owned();
        let owner_hash =
            Nsec3Hash::from_wire(&base32hex_decode(std::str::from_utf8(first).ok()?).ok()?)?;
        match rr.rdata.parse().ok()? {
            ParsedRecord::NSEC3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmap,
            } if hash_algorithm == SHA1_HASH_ALGORITHM => Some(Nsec3 {
                owner,
                owner_hash,
                zone,
                hash_algorithm,
                flags,
                iterations,
                salt,
                // RFC 5155 §3.1.7 gives this an explicit length octet, so a
                // record can name a length the algorithm does not produce. It
                // is refused here rather than kept and never matched.
                next_hashed_owner: Nsec3Hash::from_wire(&next_hashed_owner)?,
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
    pub fn hash(&self, name: NameRef<'_>) -> DnssecResult<Nsec3Hash> {
        self.params().hash(name)
    }

    /// Whether this NSEC3 is the record for the name whose hash is `hash`.
    ///
    /// The caller owns the check that [`Nsec3::params`] agree; a hash under other
    /// parameters answers a different question.
    fn matches_hash(&self, hash: Nsec3Hash) -> bool {
        hash == self.owner_hash
    }

    /// Whether this NSEC3 is the record *for* `name`.
    pub fn matches(&self, name: NameRef<'_>) -> DnssecResult<bool> {
        Ok(self.matches_hash(self.hash(name)?))
    }

    /// Whether `hash` falls strictly inside this record's span, on the same terms
    /// as `Nsec3::matches_hash`.
    pub fn covers_hash(&self, hash: Nsec3Hash) -> bool {
        let after = hash > self.owner_hash;
        let before = hash < self.next_hashed_owner;
        if self.next_hashed_owner > self.owner_hash {
            after && before
        } else {
            // The last NSEC3 wraps around to the first.
            after || before
        }
    }

    /// Whether `name`'s hash falls strictly inside this record's span.
    pub fn covers(&self, name: NameRef<'_>) -> DnssecResult<bool> {
        Ok(self.covers_hash(self.hash(name)?))
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
    name: NameRef<'a>,
    /// The parameters `hash` was computed under, and the hash. Replaced whenever
    /// a record's parameters differ.
    computed: Option<(Nsec3Params<'a>, Nsec3Hash)>,
}

impl<'a> NameHash<'a> {
    fn new(name: NameRef<'a>) -> Self {
        NameHash {
            name,
            computed: None,
        }
    }

    fn under<'r: 'a>(&mut self, record: &'r Nsec3) -> DnssecResult<Nsec3Hash> {
        let params = record.params();
        match &self.computed {
            Some((have, _)) if *have == params => {}
            _ => self.computed = Some((params, params.hash(self.name)?)),
        }
        Ok(self.computed.as_ref().expect("just filled").1)
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
pub fn proves_no_ds(zone: NameRef<'_>, nsecs: &[Nsec], nsec3s: &[Nsec3]) -> Denial {
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
pub fn proves_nxdomain(
    qname: NameRef<'_>,
    zone: NameRef<'_>,
    nsecs: &[Nsec],
    nsec3s: &[Nsec3],
) -> Denial {
    if !nsecs.is_empty() {
        let Some(covering) = nsecs.iter().find(|n| n.covers(qname)) else {
            return Denial::NotProved(format!("no NSEC covers {qname}"));
        };
        // The wildcard to disprove sits at the closest encloser, which for an
        // NSEC proof is the longest suffix of qname shared with either end of
        // the covering record.
        let encloser = closest_encloser_nsec(qname, covering);
        let Ok(wildcard) = Name::prefixed(b"*", encloser) else {
            return Denial::NotProved(format!("{encloser} is too long to carry a wildcard label"));
        };
        if nsecs.iter().any(|n| n.covers(wildcard.as_ref())) {
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
    qname: NameRef<'_>,
    zone: NameRef<'_>,
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
fn nodata_bitmap(qtype: Rtype, at: NameRef<'_>, has_type: impl Fn(Rtype) -> bool) -> Denial {
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
fn nsec_wildcard_nodata(qname: NameRef<'_>, qtype: Rtype, nsecs: &[Nsec]) -> Denial {
    let Some(covering) = nsecs.iter().find(|n| n.covers(qname)) else {
        return Denial::NotProved(format!("no NSEC matches or covers {qname}"));
    };
    let encloser = closest_encloser_nsec(qname, covering);
    let Ok(wildcard) = Name::prefixed(b"*", encloser) else {
        return Denial::NotProved(format!("{encloser} is too long to carry a wildcard label"));
    };
    let Some(matching) = nsecs.iter().find(|n| n.matches(wildcard.as_ref())) else {
        return Denial::NotProved(format!(
            "{qname} does not exist and no NSEC at {wildcard} says what a wildcard would \
             have answered"
        ));
    };
    nodata_bitmap(qtype, wildcard.as_ref(), |t| matching.has_type(t))
}

/// Wildcard NODATA with NSEC3 (RFC 5155 §8.7): the closest-encloser proof for
/// `qname`, and an NSEC3 matching the wildcard at that encloser whose bitmap
/// lacks the type.
fn nsec3_wildcard_nodata(
    qname: NameRef<'_>,
    zone: NameRef<'_>,
    qtype: Rtype,
    nsec3s: &[Nsec3],
) -> Denial {
    let encloser = match nsec3_closest_encloser(qname, zone, nsec3s) {
        Ok(encloser) => encloser,
        Err(why) => return Denial::NotProved(why),
    };
    let Ok(wildcard) = Name::prefixed(b"*", encloser) else {
        return Denial::NotProved(format!("{encloser} is too long to carry a wildcard label"));
    };
    let mut hash = NameHash::new(wildcard.as_ref());
    let Some(matching) = nsec3s.iter().find(|n| hash.matches(n).unwrap_or(false)) else {
        return Denial::NotProved(format!(
            "{qname} does not exist and no NSEC3 matches the wildcard {wildcard}"
        ));
    };
    nodata_bitmap(qtype, wildcard.as_ref(), |t| matching.has_type(t))
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
    owner: NameRef<'_>,
    wildcard: NameRef<'_>,
    nsecs: &[Nsec],
    nsec3s: &[Nsec3],
) -> WildcardVerdict {
    let Some(encloser) = wildcard_encloser(wildcard) else {
        return WildcardVerdict::NotProved(format!("{wildcard} is not a wildcard name"));
    };
    if owner.label_count() <= encloser.label_count() {
        return WildcardVerdict::NotProved(format!(
            "{owner} is not below {encloser}, so {wildcard} cannot have expanded to it"
        ));
    }

    if !nsecs.is_empty() {
        let Some(covering) = nsecs.iter().find(|n| n.covers(owner)) else {
            return WildcardVerdict::NotProved(format!(
                "no NSEC covers {owner}, so nothing rules out records of its own"
            ));
        };
        // Both ends of a covering NSEC exist, so the longest suffix shared with
        // either is the deepest ancestor of `owner` known to exist. Deeper than
        // the wildcard's own parent means this wildcard never applied.
        let found = closest_encloser_nsec(owner, covering);
        if found != encloser {
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
        let next_closer = owner.suffix(encloser.label_count() + 1);
        let mut hash = NameHash::new(next_closer);
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
fn wildcard_encloser(wildcard: NameRef<'_>) -> Option<NameRef<'_>> {
    (wildcard.labels().next()? == b"*").then(|| wildcard.parent())?
}

/// The longest suffix `qname` shares with either end of the NSEC covering it.
/// Both ends provably exist, so this is `qname`'s closest ancestor that does.
fn closest_encloser_nsec<'n>(qname: NameRef<'n>, covering: &Nsec) -> NameRef<'n> {
    let from_owner = common_suffix(qname, covering.owner.as_ref());
    let from_next = common_suffix(qname, covering.next.as_ref());
    if from_owner.label_count() >= from_next.label_count() {
        from_owner
    } else {
        from_next
    }
}

/// The longest suffix of whole labels that two names share — a suffix of `a`,
/// so it borrows rather than building a name of its own.
fn common_suffix<'n>(a: NameRef<'n>, b: NameRef<'_>) -> NameRef<'n> {
    let shared = crate::denial_wire::reversed_labels(a)
        .zip(crate::denial_wire::reversed_labels(b))
        .take_while(|(x, y)| x == y)
        .count();
    a.suffix(shared)
}

/// The RFC 5155 §8.4 closest-encloser proof: the encloser is proven, the name one
/// label below it is absent, and the wildcard at the encloser is accounted for —
/// without which one could still have answered.
fn nsec3_closest_encloser_proof(qname: NameRef<'_>, zone: NameRef<'_>, nsec3s: &[Nsec3]) -> Denial {
    let encloser = match nsec3_closest_encloser(qname, zone, nsec3s) {
        Ok(encloser) => encloser,
        Err(why) => return Denial::NotProved(why),
    };
    let Ok(wildcard) = Name::prefixed(b"*", encloser) else {
        return Denial::NotProved(format!("{encloser} is too long to carry a wildcard label"));
    };
    let mut hash = NameHash::new(wildcard.as_ref());
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
/// Each ancestor is a suffix of `qname` rather than a name of its own, and the
/// next closer name is the candidate visited one step before.
fn nsec3_closest_encloser<'n>(
    qname: NameRef<'n>,
    zone: NameRef<'_>,
    nsec3s: &[Nsec3],
) -> Result<NameRef<'n>, String> {
    let qlabels = qname.label_count();
    let zlabels = zone.label_count();

    // Walk up towards the apex, which always exists, so the search terminates.
    let mut candidate = qname;
    let mut depth = qlabels;
    let mut below: Option<NameRef<'n>> = None;
    loop {
        if NameHash::new(candidate).matched_by(nsec3s) {
            if depth == qlabels {
                return Err(format!("an NSEC3 matches {qname}, so it exists"));
            }
            // The "next closer" name: one label longer than the encloser, which
            // is the candidate this walk rejected on its way here.
            let next_closer = below.expect("below the top of the walk, one was visited");
            if !NameHash::new(next_closer).covered_by(nsec3s) {
                return Err(format!(
                    "no NSEC3 covers the next closer name {next_closer}"
                ));
            }
            return Ok(candidate);
        }
        // The apex ends the walk. Stopping on the label count rather than on the
        // name keeps the old bound for a QNAME that is not under `zone` at all.
        if depth == zlabels {
            break;
        }
        below = Some(candidate);
        let Some(up) = candidate.parent() else {
            break;
        };
        candidate = up;
        depth -= 1;
    }

    Err(format!("no NSEC3 matches any ancestor of {qname}"))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::denial_wire::{base32hex_encode, build_type_bitmap};
    use crate::test_records::nm;
    use crate::test_records::{nsec3, NSEC3_ITERATIONS, NSEC3_SALT};
    use crate::Class;
    use crate::RecordData;
    use crate::Ttl;

    fn nsec(owner: &str, next: &str, types: &[Rtype]) -> Nsec {
        Nsec {
            owner: nm(owner),
            next: nm(next),
            type_bitmap: build_type_bitmap(types),
        }
    }

    /// The longest shared suffix is a suffix of the first name — a borrow, not
    /// a name built label by label, which is why this exists. Case is not folded
    /// here any more and does not need to be: `NameRef`'s equality folds ASCII
    /// as it compares (RFC 4343).
    #[test]
    fn test_common_suffix_is_the_shared_labels_folded() {
        for (a, b, want) in [
            ("www.Example.COM.", "mail.example.com.", "example.com."),
            ("a.b.example.", "example.", "example."),
            ("example.com.", "example.net.", "."),
            ("com.", "com.", "com."),
            ("a.example.", "a.example.", "a.example."),
            (".", "example.", "."),
        ] {
            let (a_name, b_name) = (nm(a), nm(b));
            let shared = common_suffix(a_name.as_ref(), b_name.as_ref());
            assert_eq!(shared, nm(want).as_ref(), "{a} against {b}");
        }
    }

    #[test]
    fn test_nsec_covers_excludes_its_endpoints() {
        let n = nsec("a.example.com.", "z.example.com.", &[rt::A]);
        assert!(n.covers(nm("m.example.com.").as_ref()));
        assert!(!n.covers(nm("a.example.com.").as_ref()), "the owner exists");
        assert!(
            !n.covers(nm("z.example.com.").as_ref()),
            "the next name exists"
        );
        assert!(!n.covers(nm("zz.example.com.").as_ref()));
    }

    #[test]
    fn test_nsec_covers_wraps_at_the_end_of_the_zone() {
        // The last NSEC in a zone points back at the apex.
        let n = nsec("z.example.com.", "example.com.", &[rt::A]);
        assert!(
            n.covers(nm("zz.example.com.").as_ref()),
            "after the last name"
        );
        assert!(!n.covers(nm("m.example.com.").as_ref()), "before it");
    }

    /// RFC 5155 Appendix A: the zone `example.` with salt `aabbccdd` and 12
    /// iterations hashes `a.example.` to `35mthgpgcu1qg68fab165klnsnk3dpvl`.
    #[test]
    fn test_nsec3_hash_matches_rfc5155_appendix_a() {
        // NSEC3PARAM 1 0 12 aabbccdd, from the RFC's example zone.
        let salt = [0xaa, 0xbb, 0xcc, 0xdd];
        let hash = nsec3_hash("a.example.", &salt, 12).unwrap();
        assert_eq!(
            base32hex_encode(hash.as_bytes()).to_lowercase(),
            "35mthgpgcu1qg68fab165klnsnk3dpvl"
        );

        // And the apex itself.
        let hash = nsec3_hash("example.", &salt, 12).unwrap();
        assert_eq!(
            base32hex_encode(hash.as_bytes()).to_lowercase(),
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"
        );
    }

    /// The salt and the iteration count each change the hash.
    #[test]
    fn test_salt_and_iterations_change_the_hash() {
        let base = nsec3_hash("a.example.", &[], 0).unwrap();
        assert_ne!(base, nsec3_hash("a.example.", &[0xaa], 0).unwrap());
        assert_ne!(base, nsec3_hash("a.example.", &[], 1).unwrap());
        assert_eq!(base.as_bytes().len(), 20, "SHA-1 output");
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
        assert!(proves_no_ds(nm("insecure.example.com.").as_ref(), &[n], &[]).is_proved());
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
        let denial = proves_no_ds(nm("secure.example.com.").as_ref(), &[n], &[]);
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
        let denial = proves_no_ds(nm("child.example.com.").as_ref(), &[n], &[]);
        assert!(!denial.is_proved(), "{denial:?}");
    }

    #[test]
    fn test_nothing_at_all_proves_nothing() {
        let denial = proves_no_ds(nm("child.example.com.").as_ref(), &[], &[]);
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
            nm("www.example.com.").as_ref(),
            nm("example.com.").as_ref(),
            rt::AAAA,
            std::slice::from_ref(&n),
            &[]
        )
        .is_proved());
        // But A is listed, so it cannot deny that.
        assert!(!proves_nodata(
            nm("www.example.com.").as_ref(),
            nm("example.com.").as_ref(),
            rt::A,
            &[n],
            &[]
        )
        .is_proved());
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
        let denial = proves_nodata(
            nm("www.example.com.").as_ref(),
            nm("example.com.").as_ref(),
            rt::A,
            &[n],
            &[],
        );
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
            nm("a.example.com.").as_ref(),
            nm("example.com.").as_ref(),
            rt::AAAA,
            std::slice::from_ref(&at_wildcard),
            &[],
        );
        assert!(denial.is_proved(), "{denial:?}");

        // A is in the wildcard's bitmap, so the wildcard *would* have answered
        // that — this is not NODATA for A.
        let denial = proves_nodata(
            nm("a.example.com.").as_ref(),
            nm("example.com.").as_ref(),
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
            nm("nope.example.com.").as_ref(),
            nm("example.com.").as_ref(),
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
        assert!(
            covering.covers(nm("a.b.example.com.").as_ref()),
            "the name is covered"
        );

        let denial = proves_nodata(
            nm("a.b.example.com.").as_ref(),
            nm("example.com.").as_ref(),
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

        let denial = proves_nodata(
            nm("a.example.com.").as_ref(),
            nm("example.com.").as_ref(),
            rt::AAAA,
            &[],
            &proofs,
        );
        assert!(denial.is_proved(), "{denial:?}");

        // A is in the wildcard's bitmap.
        let denial = proves_nodata(
            nm("a.example.com.").as_ref(),
            nm("example.com.").as_ref(),
            rt::A,
            &[],
            &proofs,
        );
        assert!(!denial.is_proved(), "{denial:?}");

        // And without the record at the wildcard there is no proof at all.
        let denial = proves_nodata(
            nm("a.example.com.").as_ref(),
            nm("example.com.").as_ref(),
            rt::AAAA,
            &[],
            &proofs[..2],
        );
        assert!(!denial.is_proved(), "{denial:?}");

        // Without the next closer name covered, `a.example.com.` may exist in
        // its own right and the wildcard is not what answered.
        let denial = proves_nodata(
            nm("a.example.com.").as_ref(),
            nm("example.com.").as_ref(),
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
        assert!(proves_nxdomain(
            nm("nope.example.com.").as_ref(),
            nm("example.com.").as_ref(),
            &[wide],
            &[]
        )
        .is_proved());

        // A record covering the name but not the wildcard proves nothing: a
        // wildcard could still have answered.
        let narrow = nsec("m.example.com.", "z.example.com.", &[rt::A]);
        let denial = proves_nxdomain(
            nm("nope.example.com.").as_ref(),
            nm("example.com.").as_ref(),
            &[narrow],
            &[],
        );
        assert!(!denial.is_proved(), "{denial:?}");
    }

    /// `a.example.com.` answered from `*.example.com.`, with the NSEC showing
    /// it has nothing of its own — often the wildcard's own NSEC, since `*`
    /// sorts before every ordinary label.
    #[test]
    fn test_wildcard_expansion_proved_by_a_covering_nsec() {
        let covering = nsec("*.example.com.", "www.example.com.", &[rt::A, rt::RRSIG]);
        let verdict = proves_wildcard_expansion(
            nm("a.example.com.").as_ref(),
            nm("*.example.com.").as_ref(),
            std::slice::from_ref(&covering),
            &[],
        );
        assert_eq!(verdict, WildcardVerdict::Proved, "{verdict:?}");
    }

    /// No denial at all: the signature verified, and that is all it did.
    #[test]
    fn test_wildcard_expansion_without_any_nsec_is_not_proved() {
        let verdict = proves_wildcard_expansion(
            nm("a.example.com.").as_ref(),
            nm("*.example.com.").as_ref(),
            &[],
            &[],
        );
        assert!(
            matches!(verdict, WildcardVerdict::NotProved(_)),
            "{verdict:?}"
        );
    }

    /// An NSEC whose range does not contain the name is not the proof asked for.
    #[test]
    fn test_wildcard_expansion_needs_the_name_covered() {
        let elsewhere = nsec("m.example.com.", "n.example.com.", &[rt::A]);
        let verdict = proves_wildcard_expansion(
            nm("a.example.com.").as_ref(),
            nm("*.example.com.").as_ref(),
            &[elsewhere],
            &[],
        );
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
            covering.covers(nm("a.b.example.com.").as_ref()),
            "the fact that makes the attack possible"
        );

        let verdict = proves_wildcard_expansion(
            nm("a.b.example.com.").as_ref(),
            nm("*.example.com.").as_ref(),
            std::slice::from_ref(&covering),
            &[],
        );
        assert!(
            matches!(verdict, WildcardVerdict::NotProved(_)),
            "the wildcard sits above the closest encloser: {verdict:?}"
        );

        // The wildcard at the closest encloser itself is fine.
        let verdict = proves_wildcard_expansion(
            nm("a.b.example.com.").as_ref(),
            nm("*.b.example.com.").as_ref(),
            &[covering],
            &[],
        );
        assert_eq!(verdict, WildcardVerdict::Proved, "{verdict:?}");
    }

    /// A name that is not below the wildcard cannot have come from it, whatever
    /// else is offered.
    #[test]
    fn test_wildcard_expansion_outside_the_wildcard_is_refused() {
        let wide = nsec("example.com.", "z.example.com.", &[rt::SOA]);
        let verdict = proves_wildcard_expansion(
            nm("other.test.").as_ref(),
            nm("*.example.com.").as_ref(),
            &[wide],
            &[],
        );
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
            nm("a.example.com.").as_ref(),
            nm("*.example.com.").as_ref(),
            &[],
            &[span("a.example.com.", 0)],
        );
        assert_eq!(verdict, WildcardVerdict::Proved, "{verdict:?}");

        // Two labels down, the next closer is the intermediate name — covering
        // the leaf instead proves nothing about `b.example.com.`.
        let verdict = proves_wildcard_expansion(
            nm("a.b.example.com.").as_ref(),
            nm("*.example.com.").as_ref(),
            &[],
            &[span("a.b.example.com.", 0)],
        );
        assert!(
            matches!(verdict, WildcardVerdict::NotProved(_)),
            "covering the leaf says nothing about its parent: {verdict:?}"
        );
        let verdict = proves_wildcard_expansion(
            nm("a.b.example.com.").as_ref(),
            nm("*.example.com.").as_ref(),
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
        let verdict = proves_wildcard_expansion(
            nm("a.example.com.").as_ref(),
            nm("*.example.com.").as_ref(),
            &[],
            &[opt_out],
        );
        assert!(
            matches!(verdict, WildcardVerdict::Unjudgeable(_)),
            "{verdict:?}"
        );
    }

    /// An NSEC3 matching `name` and covering nothing — its span is the empty
    /// interval above its own hash, so it cannot stand in for a covering record.
    fn nsec3_matching(name: &str, types: &[Rtype]) -> Nsec3 {
        // Overwritten on the next line; a hash is 20 octets even as a placeholder.
        let mut n = nsec3("example.com.", name, &[0; NSEC3_HASH_LEN], 0, types);
        n.next_hashed_owner = hash_step(n.owner_hash, true);
        n
    }

    /// An NSEC3 whose span contains exactly `name`'s hash: one step below to one
    /// step above. Derived from the hash, since fixed bytes would cover or miss
    /// it by luck.
    fn nsec3_span_around(name: &str, flags: u8) -> Nsec3 {
        let hash = nsec3_hash(name, &NSEC3_SALT, NSEC3_ITERATIONS).expect("hash");
        let low = hash_step(hash, false);
        Nsec3 {
            owner: nsec3_owner_name_at(low, nm("example.com.").as_ref()).unwrap(),
            owner_hash: low,
            zone: nm("example.com."),
            hash_algorithm: 1,
            flags,
            iterations: NSEC3_ITERATIONS,
            salt: NSEC3_SALT.to_vec(),
            next_hashed_owner: hash_step(hash, true),
            type_bitmap: build_type_bitmap(&[rt::A]),
        }
    }

    /// A hash one step up or down as the big-endian number it is compared as.
    fn hash_step(hash: Nsec3Hash, up: bool) -> Nsec3Hash {
        let mut out = hash.as_bytes().to_vec();
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
        Nsec3Hash::from_wire(&out).expect("a stepped hash is still 20 octets")
    }

    /// Every octet the same, for a fixture that only needs an ordering.
    fn test_hash(byte: u8) -> Nsec3Hash {
        Nsec3Hash::from_wire(&[byte; NSEC3_HASH_LEN]).expect("20 octets")
    }

    #[test]
    fn test_nsec3_matching_record_proves_no_ds() {
        let n = nsec3(
            "example.com.",
            "child.example.com.",
            &[0xff; 20],
            0,
            &[rt::NS],
        );
        assert!(n.matches(nm("child.example.com.").as_ref()).unwrap());
        assert!(proves_no_ds(nm("child.example.com.").as_ref(), &[], &[n]).is_proved());
    }

    #[test]
    fn test_nsec3_with_ds_in_the_bitmap_proves_nothing() {
        let n = nsec3(
            "example.com.",
            "child.example.com.",
            &[0xff; 20],
            0,
            &[rt::NS, rt::DS],
        );
        assert!(!proves_no_ds(nm("child.example.com.").as_ref(), &[], &[n]).is_proved());
    }

    /// Opt-out is what lets a covering (rather than matching) NSEC3 stand in
    /// for an unsigned delegation — and only when the flag is actually set.
    #[test]
    fn test_nsec3_opt_out_covering_proves_no_ds_but_only_with_the_flag() {
        // A span covering everything: owner hash all zeros, next all ones.
        let covering = |flags: u8| Nsec3 {
            owner: nm("00000000000000000000000000000000.example.com."),
            owner_hash: test_hash(0x00),
            zone: nm("example.com."),
            hash_algorithm: 1,
            flags,
            iterations: NSEC3_ITERATIONS,
            salt: NSEC3_SALT.to_vec(),
            next_hashed_owner: test_hash(0xff),
            type_bitmap: build_type_bitmap(&[rt::NS]),
        };

        assert!(
            proves_no_ds(nm("child.example.com.").as_ref(), &[], &[covering(0x01)]).is_proved(),
            "opt-out set: the span may hold unsigned delegations"
        );
        assert!(
            !proves_no_ds(nm("child.example.com.").as_ref(), &[], &[covering(0x00)]).is_proved(),
            "without opt-out a covering record claims the name does not exist, \
             which contradicts the referral we just followed"
        );
    }

    /// A hash of the wrong length is not a short hash, it is not a hash.
    ///
    /// RFC 5155 registers one algorithm, SHA-1, and this refuses any other — so
    /// 20 octets is the only length either hash in the record can have. Both
    /// come off the wire under a remote party's control: the owner's first label
    /// is base32hex of whatever they put there, and §3.1.7 gives
    /// `next_hashed_owner` an explicit length octet. Before `Nsec3Hash`
    /// (`TODO.md` #40a) a wrong length parsed, went into the cache, and then
    /// matched nothing for as long as it lived, which is what `covers_hash`
    /// carried an `is_empty()` guard for.
    #[test]
    fn an_nsec3_whose_hashes_are_the_wrong_length_is_refused() {
        use crate::ParsedRecord;

        let good = |owner_hash: &[u8], next: Vec<u8>| crate::ResourceRecord {
            name: nm(&format!("{}.example.com.", base32hex_encode(owner_hash))),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 3,
                salt: vec![0xde, 0xad],
                next_hashed_owner: next,
                type_bitmap: build_type_bitmap(&[rt::A]),
            })
            .unwrap(),
        };

        assert!(
            Nsec3::from_record(&good(&[0x11; NSEC3_HASH_LEN], vec![0xff; NSEC3_HASH_LEN]))
                .is_some(),
            "20 octets either side is the record that should parse"
        );
        assert!(
            Nsec3::from_record(&good(&[0x11; 17], vec![0xff; NSEC3_HASH_LEN])).is_none(),
            "a 17-octet owner label is not an owner hash"
        );
        assert!(
            Nsec3::from_record(&good(&[0x11; NSEC3_HASH_LEN], vec![0xff; 21])).is_none(),
            "nor is a 21-octet next hashed owner"
        );
    }

    #[test]
    fn test_nsec3_record_parses_its_owner_hash() {
        use crate::ParsedRecord;
        let salt = vec![0xde, 0xad];
        let hash = nsec3_hash("child.example.com.", &salt, 3).unwrap();
        let rr = crate::ResourceRecord {
            name: nm(&format!(
                "{}.example.com.",
                base32hex_encode(hash.as_bytes())
            )),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC3 {
                hash_algorithm: 1,
                flags: 1,
                iterations: 3,
                salt: salt.clone(),
                next_hashed_owner: vec![0xff; NSEC3_HASH_LEN],
                type_bitmap: build_type_bitmap(&[rt::NS]),
            })
            .unwrap(),
        };

        let parsed = Nsec3::from_record(&rr).expect("NSEC3 should parse");
        assert_eq!(parsed.owner_hash, hash, "the owner label is the hash");
        assert_eq!(parsed.zone, nm("example.com."));
        assert!(parsed.opt_out());
        assert!(parsed.matches(nm("child.example.com.").as_ref()).unwrap());
        assert!(parsed.has_type(rt::NS));
        assert!(!parsed.has_type(rt::DS));
    }

    /// An absurd iteration count fails closed rather than burning CPU per name.
    #[test]
    fn test_hostile_nsec3_iterations_are_refused() {
        let n = Nsec3 {
            owner: nm("aaaa.example.com."),
            owner_hash: test_hash(0x00),
            zone: nm("example.com."),
            hash_algorithm: 1,
            flags: 0,
            iterations: u16::MAX,
            salt: vec![0xff; 32],
            next_hashed_owner: test_hash(0xff),
            type_bitmap: build_type_bitmap(&[rt::NS]),
        };
        assert!(n.matches(nm("child.example.com.").as_ref()).is_err());
        let denial = proves_no_ds(nm("child.example.com.").as_ref(), &[], &[n]);
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
            proves_no_ds(
                nm("example.com.").as_ref(),
                &[],
                std::slice::from_ref(&good)
            ),
            Denial::Proved,
            "the usable record alone proves it",
        );

        // The same set with the unusable record placed first.
        assert_eq!(
            proves_no_ds(nm("example.com.").as_ref(), &[], &[poison, good]),
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

        match proves_no_ds(nm("example.com.").as_ref(), &[], &[poison]) {
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
        rdata.push(usable.next_hashed_owner.as_bytes().len() as u8);
        rdata.extend_from_slice(usable.next_hashed_owner.as_bytes());
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
