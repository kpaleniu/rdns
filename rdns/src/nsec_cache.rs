//! Aggressive use of DNSSEC-validated denial of existence (RFC 8198).
//!
//! An NSEC record does not say "this one name does not exist". It says "nothing
//! exists between these two names", and it is signed. So a validator that has
//! one in hand already knows the answer for *every* name in that gap, and
//! asking the authoritative server again learns nothing it was not already
//! told. Caching the gap rather than the question is what turns a random-name
//! flood — the shape of a water-torture attack, and of any typo storm — from
//! one upstream query per name into one query per zone.
//!
//! This is not the ordinary cache with a different key. [`crate::DnsCache`] maps
//! `(name, type)` to records, which can only ever answer the question it was
//! asked; a gap has to be searched by *range*, which is why the proofs live here
//! in a `BTreeMap` ordered by [`canonical_sort_key`] instead.
//!
//! Everything here is a way of *not* asking, so every mistake is invisible until
//! it denies a name that exists. The rules that keep that from happening:
//!
//! - **Only Secure material.** An unvalidated NSEC is an attacker's assertion
//!   about which names do not exist, which is a denial-of-service primitive.
//! - **Never across an opt-out NSEC3 span** (RFC 8198 §5.2). Opt-out means the
//!   span may contain delegations the zone never named, so it proves nothing
//!   about what is inside it.
//! - **Never below a delegation.** A gap says nothing exists *in this zone*
//!   between two names; names beneath a delegation at the gap's lower edge live
//!   in the child zone and exist perfectly well. This one is not in the RFC's
//!   list and is the easiest to get wrong — see [`ZoneProofs::covering_nsec`].
//! - **NXDOMAIN needs the wildcard denied too**, or a name the gap covers could
//!   still have been answered by a wildcard.
//! - **TTL is bounded by the proof**, not by the question.

use crate::dnssec_denial::{
    canonical_sort_key, proves_nodata, proves_nxdomain, Denial, Nsec, Nsec3,
};
use crate::dnssec::{canonical_name, label_count, suffix_labels};
use crate::utils::{current_unix_timestamp, record_types as rt};
use crate::{DnsMessage, ParsedRecord, ResourceRecord, ResponseCode};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

/// Query types we will not answer from a gap.
///
/// ANY is not a type, so a bitmap saying "no ANY" means nothing; and RRSIG's
/// presence in a bitmap describes the *other* types' signatures rather than an
/// RRSIG RRset of its own. Neither can be reasoned about from a type bitmap, so
/// both go upstream.
fn synthesizable_qtype(qtype: u16) -> bool {
    qtype != 255 && qtype != rt::RRSIG
}

/// One zone's validated denial material.
#[derive(Debug, Default)]
struct ZoneProofs {
    /// NSEC records by the canonical sort key of their owner, so the record
    /// whose range could contain a name is one range query away.
    nsecs: BTreeMap<Vec<u8>, CachedProof<Nsec>>,
    /// NSEC3 records by owner hash, which is already ordered by plain bytes.
    nsec3s: BTreeMap<Vec<u8>, CachedProof<Nsec3>>,
    /// The zone's SOA and its signatures. A negative answer must carry it
    /// (RFC 2308 §2.1), and its MINIMUM bounds how long the answer may live.
    soa: Option<CachedSoa>,
}

#[derive(Debug, Clone)]
struct CachedProof<T> {
    proof: T,
    /// The record and its RRSIGs, kept whole so a DO client gets the proof it
    /// would have got from the zone.
    records: Vec<ResourceRecord>,
    expires_at: u64,
}

#[derive(Debug, Clone)]
struct CachedSoa {
    records: Vec<ResourceRecord>,
    /// The negative-caching TTL: `min(SOA TTL, SOA MINIMUM)` (RFC 2308 §5).
    negative_ttl: u32,
    expires_at: u64,
}

impl<T> CachedProof<T> {
    fn live(&self, now: u64) -> bool {
        self.expires_at > now
    }

    fn remaining(&self, now: u64) -> u32 {
        self.expires_at.saturating_sub(now).min(u32::MAX as u64) as u32
    }
}

/// What synthesizing produced.
pub struct Synthesis {
    /// NXDOMAIN, or NOERROR for a NODATA answer.
    pub rcode: ResponseCode,
    /// SOA and the proof records, TTLs already counted down.
    pub authority: Vec<ResourceRecord>,
    /// How long this answer may itself be held.
    pub ttl: u32,
}

/// Validated NSEC/NSEC3 proofs, searchable by range.
#[derive(Debug)]
pub struct NsecCache {
    zones: Mutex<HashMap<String, ZoneProofs>>,
    /// Zones to remember. Combined with [`MAX_PROOFS_PER_ZONE`] this bounds the
    /// whole structure; a zone with a large NSEC chain cannot crowd out the
    /// rest, and a flood of one-off zones cannot grow it without limit.
    max_zones: usize,
}

/// Proof records kept per zone. A zone's chain can be enormous — the point of
/// NSEC3 was to stop people walking exactly this — so keeping all of it is
/// neither possible nor useful; the gaps that get queried are the ones worth
/// holding.
const MAX_PROOFS_PER_ZONE: usize = 256;

/// Never hold a proof longer than this, whatever its TTL claims.
const MAX_PROOF_TTL: u64 = 3600;

impl NsecCache {
    pub fn new(max_zones: usize) -> Self {
        NsecCache {
            zones: Mutex::new(HashMap::new()),
            max_zones,
        }
    }

    /// Store the denial carried by `response`.
    ///
    /// **Only call this for an answer that validated as Secure.** Nothing here
    /// re-checks a signature; the caller's validation is the entire basis for
    /// trusting these records later, and a resolver that stored unvalidated
    /// NSECs would be caching an attacker's opinion about which names exist.
    pub fn insert_validated(&self, response: &DnsMessage) {
        if self.max_zones == 0 {
            return;
        }
        // The SOA names the zone the denial came from, and without it there is
        // no negative TTL and nothing to put in a synthesized authority section.
        let Some(soa_rr) = response
            .authorities
            .iter()
            .find(|rr| rr.rdata.rtype == rt::SOA)
        else {
            return;
        };
        let Ok(ParsedRecord::SOA { minimum, .. }) = soa_rr.rdata.parse() else {
            return;
        };
        let zone = canonical_name(&soa_rr.name);
        let now = current_unix_timestamp();

        let soa_ttl = soa_rr.ttl.max(0) as u32;
        let negative_ttl = soa_ttl.min(minimum);
        let soa = CachedSoa {
            records: records_at(&response.authorities, &zone, rt::SOA),
            negative_ttl,
            expires_at: now + (negative_ttl as u64).min(MAX_PROOF_TTL),
        };

        let Ok(mut zones) = self.zones.lock() else {
            return;
        };
        if !zones.contains_key(&zone) && zones.len() >= self.max_zones {
            evict_zone(&mut zones, now);
        }
        let entry = zones.entry(zone.clone()).or_default();
        entry.soa = Some(soa);

        for rr in &response.authorities {
            match rr.rdata.rtype {
                rt::NSEC => {
                    let Some(nsec) = Nsec::from_record(rr) else {
                        continue;
                    };
                    // A proof from outside the zone that signed the SOA is not
                    // this zone's to make.
                    if !is_at_or_below(&nsec.owner, &zone) {
                        continue;
                    }
                    let ttl = (rr.ttl.max(0) as u64).min(MAX_PROOF_TTL);
                    let key = canonical_sort_key(&nsec.owner);
                    let records = records_covering(&response.authorities, &nsec.owner, rt::NSEC);
                    insert_bounded(
                        &mut entry.nsecs,
                        key,
                        CachedProof {
                            proof: nsec,
                            records,
                            expires_at: now + ttl,
                        },
                        now,
                    );
                }
                rt::NSEC3 => {
                    let Some(nsec3) = Nsec3::from_record(rr) else {
                        continue;
                    };
                    if !is_at_or_below(&nsec3.zone, &zone) {
                        continue;
                    }
                    // RFC 8198 §5.2: an opt-out span may hold delegations the
                    // zone never named, so it cannot be used to deny anything.
                    // Refused at insert rather than at lookup, so there is no
                    // path by which one is consulted at all.
                    if nsec3.opt_out() {
                        continue;
                    }
                    let ttl = (rr.ttl.max(0) as u64).min(MAX_PROOF_TTL);
                    let key = nsec3.owner_hash.clone();
                    let records = records_covering(&response.authorities, &nsec3.owner, rt::NSEC3);
                    insert_bounded(
                        &mut entry.nsec3s,
                        key,
                        CachedProof {
                            proof: nsec3,
                            records,
                            expires_at: now + ttl,
                        },
                        now,
                    );
                }
                _ => {}
            }
        }
    }

    /// Answer `qname`/`qtype` from cached proofs, or `None` to go and ask.
    ///
    /// `None` is always safe and is the answer whenever anything is in doubt.
    pub fn synthesize(&self, qname: &str, qtype: u16) -> Option<Synthesis> {
        if !synthesizable_qtype(qtype) {
            return None;
        }
        let qname = canonical_name(qname);
        let now = current_unix_timestamp();
        let zones = self.zones.lock().ok()?;

        // The deepest cached zone enclosing the name is the one whose NSEC
        // chain covers it; a shallower zone's chain stops at the delegation.
        let (zone_name, zone) = zones
            .iter()
            .filter(|(z, _)| is_at_or_below(&qname, z))
            .max_by_key(|(z, _)| label_count(z))?;

        let soa = zone.soa.as_ref().filter(|s| s.expires_at > now)?;

        let (rcode, proof_records, proof_ttl) = zone
            .synthesize_nodata(&qname, qtype, now)
            .or_else(|| zone.synthesize_nxdomain(&qname, zone_name, now))?;

        // The answer lives as long as the shortest-lived thing it rests on: the
        // proof records, the SOA's negative TTL (RFC 2308 §5), and what is left
        // of the SOA itself. Applied once, here, to every record going out —
        // handing back a proof still carrying its original TTL would let a
        // client re-cache it for longer than we may hold it ourselves.
        let ttl = proof_ttl
            .min(soa.negative_ttl)
            .min(soa.expires_at.saturating_sub(now) as u32);
        if ttl == 0 {
            return None;
        }

        let mut authority = with_ttl(&soa.records, ttl);
        authority.extend(with_ttl(&proof_records, ttl));
        Some(Synthesis {
            rcode,
            authority,
            ttl,
        })
    }

    /// How many zones are held. For tests and diagnostics.
    pub fn len(&self) -> usize {
        self.zones.lock().map(|z| z.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        if let Ok(mut zones) = self.zones.lock() {
            zones.clear();
        }
    }
}

impl ZoneProofs {
    /// The cached NSEC whose range could contain `name`, if any.
    ///
    /// The range query finds the greatest owner at or below `name`; if there is
    /// none, the candidate is the last record in the chain, which is the one
    /// that wraps around to the apex.
    ///
    /// **The delegation check is the subtle part.** A gap says nothing exists
    /// *in this zone* between its endpoints. If the lower endpoint is a
    /// delegation — NS set, SOA clear — then everything beneath it lives in the
    /// child zone, and those names sort inside the gap: `sub.example.com.` and
    /// `x.sub.example.com.` are adjacent in canonical order, so the gap after a
    /// delegation swallows the entire subtree below it. Synthesizing NXDOMAIN
    /// there denies every name in a zone we were never authoritative for.
    fn covering_nsec(&self, name: &str, now: u64) -> Option<&CachedProof<Nsec>> {
        let key = canonical_sort_key(name);
        let candidate = self
            .nsecs
            .range(..=key)
            .next_back()
            .or_else(|| self.nsecs.iter().next_back())
            .map(|(_, v)| v)?;

        if !candidate.live(now) || !candidate.proof.covers(name) {
            return None;
        }
        if is_below_delegation(&candidate.proof, name) {
            return None;
        }
        Some(candidate)
    }

    /// The cached NSEC whose owner *is* `name`.
    fn matching_nsec(&self, name: &str, now: u64) -> Option<&CachedProof<Nsec>> {
        self.nsecs
            .get(&canonical_sort_key(name))
            .filter(|c| c.live(now))
    }

    /// NODATA: the name exists, but not with this type.
    fn synthesize_nodata(
        &self,
        qname: &str,
        qtype: u16,
        now: u64,
    ) -> Option<(ResponseCode, Vec<ResourceRecord>, u32)> {
        if let Some(cached) = self.matching_nsec(qname, now) {
            // At a delegation the parent holds only the DS; everything else is
            // the child's to answer, and the real reply is a referral rather
            // than NODATA.
            if is_delegation(&cached.proof) && qtype != rt::DS {
                return None;
            }
            if proves_nodata(qname, qtype, std::slice::from_ref(&cached.proof), &[]).is_proved() {
                return Some((
                    ResponseCode::Ok,
                    with_ttl(&cached.records, cached.remaining(now)),
                    cached.remaining(now),
                ));
            }
            return None;
        }

        // NSEC3: the record for a name that exists is the one its hash matches.
        for cached in self.nsec3s.values().filter(|c| c.live(now)) {
            if !cached.proof.matches(qname).unwrap_or(false) {
                continue;
            }
            if cached.proof.has_type(rt::NS) && !cached.proof.has_type(rt::SOA) && qtype != rt::DS {
                return None;
            }
            if proves_nodata(qname, qtype, &[], std::slice::from_ref(&cached.proof)).is_proved() {
                return Some((
                    ResponseCode::Ok,
                    with_ttl(&cached.records, cached.remaining(now)),
                    cached.remaining(now),
                ));
            }
            return None;
        }
        None
    }

    /// NXDOMAIN: the name does not exist, and no wildcard would have answered.
    fn synthesize_nxdomain(
        &self,
        qname: &str,
        zone: &str,
        now: u64,
    ) -> Option<(ResponseCode, Vec<ResourceRecord>, u32)> {
        // Gather the records that could bear on it, then let the same proof
        // logic that validated them decide. Re-deriving the argument here would
        // be a second implementation of it, and the two would drift.
        let mut candidates: Vec<&CachedProof<Nsec>> = Vec::new();
        if let Some(covering) = self.covering_nsec(qname, now) {
            candidates.push(covering);
        } else if self.nsecs.is_empty() {
            return self.synthesize_nxdomain_nsec3(qname, zone, now);
        } else {
            return None;
        }
        // The wildcard that could have answered sits at some ancestor, so every
        // ancestor's wildcard needs a covering record too. `proves_nxdomain`
        // picks the one that matters from what it is handed.
        for depth in label_count(zone)..label_count(qname) {
            let wildcard = format!("*.{}", suffix_labels(qname, depth));
            if let Some(covering) = self.covering_nsec(&wildcard, now) {
                if !candidates
                    .iter()
                    .any(|c| c.proof.owner == covering.proof.owner)
                {
                    candidates.push(covering);
                }
            }
        }

        let proofs: Vec<Nsec> = candidates.iter().map(|c| c.proof.clone()).collect();
        if !proves_nxdomain(qname, zone, &proofs, &[]).is_proved() {
            return None;
        }

        let ttl = candidates
            .iter()
            .map(|c| c.remaining(now))
            .min()
            .unwrap_or(0);
        let mut records = Vec::new();
        for cached in candidates {
            records.extend(with_ttl(&cached.records, ttl));
        }
        Some((ResponseCode::NoSuchDomain, records, ttl))
    }

    /// The NSEC3 form of the same thing: the closest-encloser proof needs the
    /// record matching some ancestor, one covering the name below it, and one
    /// accounting for the wildcard.
    fn synthesize_nxdomain_nsec3(
        &self,
        qname: &str,
        zone: &str,
        now: u64,
    ) -> Option<(ResponseCode, Vec<ResourceRecord>, u32)> {
        let live: Vec<&CachedProof<Nsec3>> =
            self.nsec3s.values().filter(|c| c.live(now)).collect();
        if live.is_empty() {
            return None;
        }

        // Anything the proof might reference: every ancestor of the name, the
        // names one label below them, and their wildcards.
        let mut names: Vec<String> = Vec::new();
        for depth in label_count(zone)..=label_count(qname) {
            let ancestor = suffix_labels(qname, depth);
            names.push(format!("*.{ancestor}"));
            names.push(ancestor);
        }

        let mut candidates: Vec<&CachedProof<Nsec3>> = Vec::new();
        for name in &names {
            for cached in &live {
                let relevant = cached.proof.matches(name).unwrap_or(false)
                    || cached.proof.covers(name).unwrap_or(false);
                if relevant
                    && !candidates
                        .iter()
                        .any(|c| c.proof.owner_hash == cached.proof.owner_hash)
                {
                    candidates.push(cached);
                }
            }
        }
        if candidates.is_empty() {
            return None;
        }

        // Same delegation trap as NSEC: if the closest encloser we can prove is
        // a delegation, the name below it belongs to the child zone.
        for cached in &candidates {
            let is_delegation =
                cached.proof.has_type(rt::NS) && !cached.proof.has_type(rt::SOA);
            if !is_delegation {
                continue;
            }
            for depth in label_count(zone)..label_count(qname) {
                let ancestor = suffix_labels(qname, depth);
                if cached.proof.matches(&ancestor).unwrap_or(false) {
                    return None;
                }
            }
        }

        let proofs: Vec<Nsec3> = candidates.iter().map(|c| c.proof.clone()).collect();
        if !matches!(
            proves_nxdomain(qname, zone, &[], &proofs),
            Denial::Proved
        ) {
            return None;
        }

        let ttl = candidates
            .iter()
            .map(|c| c.remaining(now))
            .min()
            .unwrap_or(0);
        let mut records = Vec::new();
        for cached in candidates {
            records.extend(with_ttl(&cached.records, ttl));
        }
        Some((ResponseCode::NoSuchDomain, records, ttl))
    }
}

/// Whether an NSEC sits at a delegation point: NS present, SOA absent.
fn is_delegation(nsec: &Nsec) -> bool {
    nsec.has_type(rt::NS) && !nsec.has_type(rt::SOA)
}

/// Whether `name` lies beneath a delegation at the NSEC's owner — in which case
/// the gap says nothing about it, however neatly it falls inside.
fn is_below_delegation(nsec: &Nsec, name: &str) -> bool {
    is_delegation(nsec) && is_at_or_below(name, &nsec.owner) && canonical_name(name) != nsec.owner
}

fn is_at_or_below(name: &str, ancestor: &str) -> bool {
    let name = canonical_name(name);
    let ancestor = canonical_name(ancestor);
    ancestor == "." || name == ancestor || name.ends_with(&format!(".{ancestor}"))
}

/// Records of `rtype` at `owner`, plus the RRSIGs that cover them.
fn records_covering(records: &[ResourceRecord], owner: &str, rtype: u16) -> Vec<ResourceRecord> {
    let owner = canonical_name(owner);
    records
        .iter()
        .filter(|rr| canonical_name(&rr.name) == owner)
        .filter(|rr| {
            rr.rdata.rtype == rtype
                || matches!(
                    rr.rdata.parse(),
                    Ok(ParsedRecord::RRSIG { type_covered, .. }) if type_covered == rtype
                )
        })
        .cloned()
        .collect()
}

fn records_at(records: &[ResourceRecord], owner: &str, rtype: u16) -> Vec<ResourceRecord> {
    records_covering(records, owner, rtype)
}

/// The same records with their TTLs set to what is left of them. A cached
/// record must count down, or a client re-caching it extends its life forever.
fn with_ttl(records: &[ResourceRecord], ttl: u32) -> Vec<ResourceRecord> {
    records
        .iter()
        .map(|rr| ResourceRecord {
            ttl: ttl.min(i32::MAX as u32) as i32,
            ..rr.clone()
        })
        .collect()
}

/// Insert into a bounded map, making room by dropping expired entries first and
/// then the one that expires soonest.
fn insert_bounded<T>(
    map: &mut BTreeMap<Vec<u8>, CachedProof<T>>,
    key: Vec<u8>,
    value: CachedProof<T>,
    now: u64,
) {
    if !map.contains_key(&key) && map.len() >= MAX_PROOFS_PER_ZONE {
        map.retain(|_, v| v.live(now));
        if map.len() >= MAX_PROOFS_PER_ZONE {
            if let Some(soonest) = map
                .iter()
                .min_by_key(|(_, v)| v.expires_at)
                .map(|(k, _)| k.clone())
            {
                map.remove(&soonest);
            }
        }
    }
    map.insert(key, value);
}

fn evict_zone(zones: &mut HashMap<String, ZoneProofs>, now: u64) {
    zones.retain(|_, z| z.soa.as_ref().is_some_and(|s| s.expires_at > now));
    if let Some(soonest) = zones
        .iter()
        .min_by_key(|(_, z)| z.soa.as_ref().map(|s| s.expires_at).unwrap_or(0))
        .map(|(k, _)| k.clone())
    {
        zones.remove(&soonest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec_denial::{build_type_bitmap, nsec3_hash, base32hex_encode};
    use crate::{OpCode, QueryClass, QuerySection, RecordData};

    fn soa_record(zone: &str, minimum: u32, ttl: i32) -> ResourceRecord {
        ResourceRecord {
            name: zone.to_string(),
            class: 1,
            ttl,
            rdata: RecordData::from_parsed(&ParsedRecord::SOA {
                mname: format!("ns1.{zone}"),
                rname: format!("admin.{zone}"),
                serial: 1,
                refresh: 10800,
                retry: 3600,
                expire: 604800,
                minimum,
            })
            .unwrap(),
        }
    }

    fn nsec_record(owner: &str, next: &str, types: &[u16], ttl: i32) -> ResourceRecord {
        ResourceRecord {
            name: owner.to_string(),
            class: 1,
            ttl,
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC {
                next_domain_name: next.to_string(),
                type_bitmap: build_type_bitmap(types),
            })
            .unwrap(),
        }
    }

    fn nsec3_record(
        zone: &str,
        name: &str,
        next: &[u8],
        flags: u8,
        types: &[u16],
        ttl: i32,
    ) -> ResourceRecord {
        let salt = vec![0xaa, 0xbb];
        let hash = nsec3_hash(name, &salt, 3).unwrap();
        ResourceRecord {
            name: format!("{}.{}", base32hex_encode(&hash).to_lowercase(), zone),
            class: 1,
            ttl,
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC3 {
                hash_algorithm: 1,
                flags,
                iterations: 3,
                salt,
                next_hashed_owner: next.to_vec(),
                type_bitmap: build_type_bitmap(types),
            })
            .unwrap(),
        }
    }

    /// A negative response as a zone would send it.
    fn negative(qname: &str, rcode: ResponseCode, authority: Vec<ResourceRecord>) -> DnsMessage {
        DnsMessage {
            id: 1,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: true,
            recursion_ok: true,
            ad: true,
            cd: false,
            rcode,
            queries: vec![QuerySection {
                qname: qname.to_string(),
                qtype: rt::A,
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: authority,
            additionals: Vec::new(),
        }
    }

    /// The ordinary case: one gap, and every name inside it is denied without
    /// another query.
    fn cache_with_a_gap() -> NsecCache {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("example.com.", 3600, 3600),
                // The apex NSEC covers everything from the apex to www, which
                // includes the wildcard position, so a name in the gap has no
                // wildcard to fall back on either.
                nsec_record(
                    "example.com.",
                    "www.example.com.",
                    &[rt::SOA, rt::NS, rt::RRSIG, rt::NSEC],
                    3600,
                ),
            ],
        ));
        cache
    }

    #[test]
    fn test_one_gap_denies_every_name_inside_it() {
        let cache = cache_with_a_gap();
        for name in ["nope.example.com.", "also-nope.example.com.", "b.example.com."] {
            let s = cache
                .synthesize(name, rt::A)
                .unwrap_or_else(|| panic!("{name} is inside the cached gap"));
            assert_eq!(s.rcode, ResponseCode::NoSuchDomain);
            assert!(
                s.authority.iter().any(|rr| rr.rdata.rtype == rt::SOA),
                "a negative answer must carry the SOA (RFC 2308 2.1)"
            );
            assert!(s.authority.iter().any(|rr| rr.rdata.rtype == rt::NSEC));
            assert!(s.ttl > 0 && s.ttl <= 3600);
        }
    }

    /// Names outside the gap must go upstream, not be denied.
    #[test]
    fn test_names_outside_the_gap_are_not_denied() {
        let cache = cache_with_a_gap();
        // Past the end of the gap.
        assert!(cache.synthesize("zzz.example.com.", rt::A).is_none());
        // The gap's own endpoints exist.
        assert!(cache.synthesize("www.example.com.", rt::A).is_none());
        // A different zone entirely.
        assert!(cache.synthesize("nope.example.org.", rt::A).is_none());
        // And a name above the zone.
        assert!(cache.synthesize("com.", rt::A).is_none());
    }

    /// The trap this cache is most likely to fall into. `sub.example.com.` and
    /// everything under it sort adjacently, so the gap starting at a delegation
    /// swallows the whole child zone — whose names exist perfectly well.
    #[test]
    fn test_never_denies_a_name_below_a_delegation() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "gone.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("example.com.", 3600, 3600),
                // A delegation at sub.example.com., with the next name in the
                // parent zone being www. Canonically, x.sub.example.com. falls
                // inside (sub.example.com., www.example.com.).
                nsec_record(
                    "sub.example.com.",
                    "www.example.com.",
                    &[rt::NS, rt::RRSIG, rt::NSEC],
                    3600,
                ),
            ],
        ));

        // Sanity: the name really does fall in the gap, so this test is testing
        // the guard and not an accident of ordering.
        let nsec = Nsec {
            owner: "sub.example.com.".into(),
            next: "www.example.com.".into(),
            type_bitmap: build_type_bitmap(&[rt::NS]),
        };
        assert!(
            nsec.covers("x.sub.example.com."),
            "the gap does span the child zone's names"
        );

        assert!(
            cache.synthesize("x.sub.example.com.", rt::A).is_none(),
            "names in a delegated child zone must never be denied from the parent's gap"
        );
        assert!(cache.synthesize("deep.x.sub.example.com.", rt::A).is_none());
    }

    /// At a delegation the parent holds only the DS. A NODATA there is right
    /// for DS and wrong for anything else, which would really be a referral.
    #[test]
    fn test_delegation_nodata_only_answers_ds() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "sub.example.com.",
            ResponseCode::Ok,
            vec![
                soa_record("example.com.", 3600, 3600),
                nsec_record(
                    "sub.example.com.",
                    "www.example.com.",
                    &[rt::NS, rt::RRSIG, rt::NSEC],
                    3600,
                ),
            ],
        ));

        let ds = cache.synthesize("sub.example.com.", rt::DS);
        assert!(ds.is_some(), "no DS at the delegation is a real NODATA");
        assert_eq!(ds.unwrap().rcode, ResponseCode::Ok);

        assert!(
            cache.synthesize("sub.example.com.", rt::A).is_none(),
            "an A query at a delegation is a referral, not NODATA"
        );
    }

    #[test]
    fn test_nodata_for_a_type_the_bitmap_lacks() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "www.example.com.",
            ResponseCode::Ok,
            vec![
                soa_record("example.com.", 3600, 3600),
                nsec_record(
                    "www.example.com.",
                    "zzz.example.com.",
                    &[rt::A, rt::RRSIG, rt::NSEC],
                    3600,
                ),
            ],
        ));

        let s = cache.synthesize("www.example.com.", rt::AAAA).expect("NODATA");
        assert_eq!(s.rcode, ResponseCode::Ok);
        assert!(s.authority.iter().all(|rr| rr.rdata.rtype != rt::A));
        // A is in the bitmap, so that one has to go upstream.
        assert!(cache.synthesize("www.example.com.", rt::A).is_none());
    }

    /// NXDOMAIN needs the wildcard denied as well: a gap alone does not rule
    /// out a wildcard higher up answering for the name.
    #[test]
    fn test_nxdomain_requires_the_wildcard_denied() {
        let cache = NsecCache::new(16);
        // This gap covers the name but sits above the wildcard position, so
        // *.example.com. is not accounted for.
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("example.com.", 3600, 3600),
                nsec_record(
                    "m.example.com.",
                    "zzz.example.com.",
                    &[rt::A, rt::RRSIG, rt::NSEC],
                    3600,
                ),
            ],
        ));
        assert!(
            cache.synthesize("nope.example.com.", rt::A).is_none(),
            "without a wildcard denial a wildcard could still have answered"
        );
    }

    #[test]
    fn test_any_and_rrsig_are_never_synthesized() {
        let cache = cache_with_a_gap();
        assert!(cache.synthesize("nope.example.com.", 255).is_none(), "ANY");
        assert!(cache.synthesize("nope.example.com.", rt::RRSIG).is_none());
    }

    /// An expired proof denies nothing.
    #[test]
    fn test_expired_proofs_are_not_used() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("example.com.", 0, 0),
                nsec_record(
                    "example.com.",
                    "www.example.com.",
                    &[rt::SOA, rt::NS, rt::RRSIG, rt::NSEC],
                    0,
                ),
            ],
        ));
        assert!(
            cache.synthesize("nope.example.com.", rt::A).is_none(),
            "a zero TTL means do not reuse this"
        );
    }

    /// The TTL of a synthesized answer is bounded by the proof it rests on and
    /// by the SOA's negative TTL, never by the question.
    #[test]
    fn test_ttl_is_bounded_by_the_proof_and_the_soa() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                // SOA MINIMUM of 60 caps the negative answer, even though the
                // NSEC itself is good for an hour.
                soa_record("example.com.", 60, 3600),
                nsec_record(
                    "example.com.",
                    "www.example.com.",
                    &[rt::SOA, rt::NS, rt::RRSIG, rt::NSEC],
                    3600,
                ),
            ],
        ));

        let s = cache.synthesize("nope.example.com.", rt::A).expect("denied");
        assert!(s.ttl <= 60, "SOA MINIMUM bounds the negative TTL, got {}", s.ttl);
        assert!(
            s.authority.iter().all(|rr| rr.ttl <= 60),
            "the records handed back must count down too"
        );
    }

    /// No SOA means no zone and no negative TTL, so nothing is stored.
    #[test]
    fn test_response_without_a_soa_is_not_cached() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![nsec_record(
                "example.com.",
                "www.example.com.",
                &[rt::SOA, rt::NS],
                3600,
            )],
        ));
        assert!(cache.is_empty());
        assert!(cache.synthesize("nope.example.com.", rt::A).is_none());
    }

    /// A proof from outside the zone that signed the SOA is not that zone's to
    /// make, and must not be filed under it.
    #[test]
    fn test_out_of_zone_nsec_is_ignored() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("example.com.", 3600, 3600),
                nsec_record("a.evil.test.", "z.evil.test.", &[rt::A], 3600),
            ],
        ));
        assert!(cache.synthesize("m.evil.test.", rt::A).is_none());
    }

    // -----------------------------------------------------------------
    // NSEC3
    // -----------------------------------------------------------------

    /// Opt-out spans may hold delegations the zone never named, so RFC 8198
    /// §5.2 forbids aggressive use across them. Refused at insert, so no
    /// lookup path can reach one.
    #[test]
    fn test_opt_out_nsec3_is_never_stored() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("example.com.", 3600, 3600),
                nsec3_record(
                    "example.com.",
                    "example.com.",
                    &[0xff; 20],
                    0x01, // opt-out
                    &[rt::SOA, rt::NS],
                    3600,
                ),
            ],
        ));
        assert!(
            cache.synthesize("nope.example.com.", rt::A).is_none(),
            "an opt-out span proves nothing about what is inside it"
        );
    }

    #[test]
    fn test_nsec3_nodata_is_synthesized() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "www.example.com.",
            ResponseCode::Ok,
            vec![
                soa_record("example.com.", 3600, 3600),
                nsec3_record(
                    "example.com.",
                    "www.example.com.",
                    &[0xff; 20],
                    0x00,
                    &[rt::A, rt::RRSIG],
                    3600,
                ),
            ],
        ));

        let s = cache
            .synthesize("www.example.com.", rt::AAAA)
            .expect("the matching NSEC3 denies AAAA");
        assert_eq!(s.rcode, ResponseCode::Ok);
        assert!(cache.synthesize("www.example.com.", rt::A).is_none());
    }

    // -----------------------------------------------------------------
    // Bookkeeping
    // -----------------------------------------------------------------

    #[test]
    fn test_zone_capacity_is_bounded() {
        let cache = NsecCache::new(2);
        for i in 0..6 {
            let zone = format!("zone{i}.test.");
            cache.insert_validated(&negative(
                &format!("nope.{zone}"),
                ResponseCode::NoSuchDomain,
                vec![
                    soa_record(&zone, 3600, 3600),
                    nsec_record(&zone, &format!("www.{zone}"), &[rt::SOA, rt::NS], 3600),
                ],
            ));
        }
        assert!(cache.len() <= 2, "held {} zones", cache.len());
    }

    #[test]
    fn test_zero_capacity_stores_nothing() {
        let cache = NsecCache::new(0);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("example.com.", 3600, 3600),
                nsec_record("example.com.", "www.example.com.", &[rt::SOA], 3600),
            ],
        ));
        assert!(cache.is_empty());
        assert!(cache.synthesize("nope.example.com.", rt::A).is_none());
    }

    /// The deepest zone wins: a parent's chain stops at the delegation, so its
    /// gaps say nothing about names inside the child.
    #[test]
    fn test_deepest_zone_is_consulted() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "x.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("com.", 3600, 3600),
                nsec_record("com.", "zzz.com.", &[rt::SOA, rt::NS], 3600),
            ],
        ));
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::Ok,
            vec![
                soa_record("example.com.", 3600, 3600),
                nsec_record(
                    "nope.example.com.",
                    "zzz.example.com.",
                    &[rt::A, rt::RRSIG, rt::NSEC],
                    3600,
                ),
            ],
        ));

        // Answered from example.com.'s NODATA proof, not com.'s gap.
        let s = cache
            .synthesize("nope.example.com.", rt::AAAA)
            .expect("the child zone's proof applies");
        assert_eq!(s.rcode, ResponseCode::Ok, "NODATA, not the parent's NXDOMAIN");
    }
}
