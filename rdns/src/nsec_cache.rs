//! Aggressive use of DNSSEC-validated denial of existence (RFC 8198).
//!
//! A signed NSEC answers for every name in its gap, so caching the gap rather
//! than the question turns a random-name flood into one upstream query per zone.
//! Gaps are searched by range, which [`crate::DnsCache`]'s `(name, type)` map
//! cannot do — hence the `BTreeMap` over [`canonical_sort_key`].
//!
//! A mistake here denies a name that exists. The rules that prevent it:
//!
//! - Only material that validated as Secure.
//! - Never across an opt-out NSEC3 span (RFC 8198 §5.2): it may hold delegations
//!   the zone never named.
//! - Never below a delegation — names in the child zone sort inside the gap and
//!   exist perfectly well. See [`ZoneProofs::covering_nsec`].
//! - NXDOMAIN needs the wildcard denied too.
//! - TTL is bounded by the proof, not by the question.

use crate::dnssec::{canonical_name, label_count, Rrsig};
use crate::dnssec_denial::{
    canonical_sort_key, proves_nodata, proves_nxdomain, Denial, Nsec, Nsec3, Nsec3Params,
};
use crate::utils::{current_unix_timestamp, record_types as rt, NameKeyBuf};
use crate::Qtype;
use crate::Rtype;
use crate::Ttl;
use crate::{DnsMessage, ParsedRecord, ResourceRecord, ResponseCode};
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;
use std::sync::Mutex;

/// Query types we will not answer from a gap.
///
/// ANY is not a type, and RRSIG in a bitmap describes the *other* types'
/// signatures rather than an RRSIG RRset. Neither can be read off a bitmap.
fn synthesizable_qtype(qtype: Qtype) -> bool {
    qtype != Qtype::ANY && !qtype.is(rt::RRSIG)
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
    /// Validated RRsets that came from a wildcard, keyed by (wildcard owner,
    /// type) — the name asked for is the one part that is not reusable.
    wildcards: HashMap<(String, Qtype), CachedWildcard>,
}

#[derive(Debug, Clone)]
struct CachedProof<T> {
    proof: T,
    /// The record and its RRSIGs, kept whole so a DO client gets the proof it
    /// would have got from the zone.
    records: Vec<ResourceRecord>,
    expires_at: u64,
}

/// An RRset that a wildcard answered with, ready to answer with again.
#[derive(Debug, Clone)]
struct CachedWildcard {
    /// The RRset and its RRSIGs, owned at the name they arrived under; the owner
    /// is rewritten on the way out. A wildcard signature verifies at the new name
    /// unchanged, which is also why the answer needs its own denial proof
    /// (RFC 4035 §5.3.4).
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

/// A positive answer built from a cached wildcard.
pub struct WildcardSynthesis {
    /// The wildcard's records, re-owned onto the name that was asked for.
    pub answers: Vec<ResourceRecord>,
    /// The NSEC proving that name does not exist, which is what makes the
    /// wildcard apply — and what a DO client needs to check the answer itself.
    pub authority: Vec<ResourceRecord>,
    pub ttl: u32,
}

/// The wildcard a signature was made at.
///
/// `labels` counts the signed name's labels, excluding the leading `*` and the
/// root (RFC 4034 §3.1.3), so the wildcard is `*.` plus that many trailing
/// labels of the owner.
fn wildcard_for_expansion(owner: &str, labels: u8) -> Option<String> {
    let owner = canonical_name(owner);
    let parts: Vec<&str> = owner.trim_end_matches('.').split('.').collect();
    let labels = labels as usize;
    if labels >= parts.len() {
        // Not an expansion after all: nothing was stripped.
        return None;
    }
    let suffix = parts[parts.len() - labels..].join(".");
    Some(format!("*.{suffix}."))
}

/// `*.` plus the immediate parent of `name`.
///
/// A deliberate under-approximation, not a reading of RFC 4592 §3.3.1: real
/// synthesis reaches any depth. See `synthesize_wildcard` for why the narrow
/// form is the safe one here.
fn wildcard_for_parent_of(name: &str) -> Option<String> {
    let name = canonical_name(name);
    let (_first, rest) = name.trim_end_matches('.').split_once('.')?;
    if rest.is_empty() {
        return None;
    }
    Some(format!("*.{rest}."))
}

/// Validated NSEC/NSEC3 proofs, searchable by range.
#[derive(Debug)]
pub struct NsecCache {
    zones: Mutex<HashMap<NameKeyBuf, ZoneProofs>>,
    /// Zones to remember. With [`MAX_PROOFS_PER_ZONE`] this bounds the whole
    /// structure against a flood of one-off zones or one enormous chain.
    max_zones: usize,
}

/// Proof records kept per zone. A chain can be arbitrarily long; the gaps that
/// get queried are the ones worth holding.
const MAX_PROOFS_PER_ZONE: usize = 256;

/// Never hold a proof longer than this, whatever its TTL claims.
const MAX_PROOF_TTL: u64 = 3600;

/// Wildcard RRsets kept per zone.
const MAX_WILDCARDS_PER_ZONE: usize = 64;

impl NsecCache {
    pub fn new(max_zones: usize) -> Self {
        NsecCache {
            zones: Mutex::new(HashMap::new()),
            max_zones,
        }
    }

    /// Store the denial carried by `response`.
    ///
    /// Only for an answer that validated as Secure. Nothing here re-checks a
    /// signature, so the caller's validation is the whole basis for trusting
    /// these records later.
    pub fn insert_validated(&self, response: &DnsMessage) {
        if self.max_zones == 0 {
            return;
        }
        // The SOA names the zone the denial came from, and without it there is
        // no negative TTL and nothing to put in a synthesized authority section.
        let Some(soa_rr) = response
            .authorities
            .iter()
            .find(|rr| rr.rdata.rtype() == rt::SOA)
        else {
            return;
        };
        let Ok(ParsedRecord::SOA { minimum, .. }) = soa_rr.rdata.parse() else {
            return;
        };
        let zone = canonical_name(&soa_rr.name);
        let now = current_unix_timestamp();

        let soa_ttl = soa_rr.ttl.as_secs();
        let negative_ttl = soa_ttl.min(minimum);
        let soa = CachedSoa {
            records: records_at(&response.authorities, &zone, rt::SOA),
            negative_ttl,
            expires_at: now + (negative_ttl as u64).min(MAX_PROOF_TTL),
        };

        let Ok(mut zones) = self.zones.lock() else {
            return;
        };
        if !zones.contains_key(zone.as_str()) && zones.len() >= self.max_zones {
            evict_zone(&mut zones, now);
        }
        let entry = zones.entry(NameKeyBuf::new(&zone)).or_default();
        entry.soa = Some(soa);

        for rr in &response.authorities {
            match rr.rdata.rtype() {
                rt::NSEC => {
                    let Some(nsec) = Nsec::from_record(rr) else {
                        continue;
                    };
                    // A proof from outside the zone that signed the SOA is not
                    // this zone's to make.
                    if !is_at_or_below(&nsec.owner, &zone) {
                        continue;
                    }
                    let ttl = rr.ttl.capped_at(MAX_PROOF_TTL as u32).as_u64();
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
                    // zone never named, so it denies nothing. Refused at insert,
                    // so no lookup path can reach one.
                    if nsec3.opt_out() {
                        continue;
                    }
                    let ttl = rr.ttl.capped_at(MAX_PROOF_TTL as u32).as_u64();
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

    /// Store the wildcard RRset that answered `response`, and the denial that
    /// came with it.
    ///
    /// Only for an answer that validated as Secure, on the same terms as
    /// [`NsecCache::insert_validated`].
    ///
    /// RFC 8198 §5.3: a validated wildcard answer covers every name the wildcard
    /// reaches. The zone comes from the RRSIG's signer name, since a positive
    /// answer has no SOA. Its authority NSECs are stored too — validated denial
    /// material on a path `insert_validated` never sees.
    pub fn insert_validated_wildcard(&self, response: &DnsMessage) {
        if self.max_zones == 0 {
            return;
        }
        let now = current_unix_timestamp();

        // Fewer labels in the RRSIG than in the owner name means the signature
        // was made at a wildcard (RFC 4035 §5.3.4).
        let mut pending: Vec<(String, String, Rtype)> = Vec::new();
        for rr in &response.answers {
            let Some(rrsig) = Rrsig::from_record(rr) else {
                continue;
            };
            if !rrsig.is_wildcard_expansion() {
                continue;
            }
            let Some(wildcard) = wildcard_for_expansion(&rrsig.owner, rrsig.labels) else {
                continue;
            };
            let zone = canonical_name(&rrsig.signer_name);
            // A signature made outside the zone it claims to sign is not this
            // zone's to keep. A consistency check, not the security boundary:
            // the chain validator already established the signer.
            if !is_at_or_below(&wildcard, &zone) {
                continue;
            }
            pending.push((zone, wildcard, rrsig.type_covered));
        }
        if pending.is_empty() {
            return;
        }

        let Ok(mut zones) = self.zones.lock() else {
            return;
        };
        for (zone, wildcard, rtype) in pending {
            if !synthesizable_qtype(Qtype::of(rtype)) {
                continue;
            }
            if !zones.contains_key(zone.as_str()) && zones.len() >= self.max_zones {
                evict_zone(&mut zones, now);
            }
            let entry = zones.entry(NameKeyBuf::new(&zone)).or_default();

            // The RRset as it arrived, plus its signatures, under the owner name
            // it came with; synthesis rewrites that.
            let owner = canonical_name(
                &response
                    .answers
                    .iter()
                    .find(|rr| rr.rdata.rtype() == rtype)
                    .map(|rr| rr.name.clone())
                    .unwrap_or_default(),
            );
            let mut records = records_at(&response.answers, &owner, rtype);
            records.extend(
                response
                    .answers
                    .iter()
                    .filter(|rr| rr.rdata.rtype() == rt::RRSIG)
                    .filter(|rr| {
                        Rrsig::from_record(rr).is_some_and(|s| {
                            s.type_covered == rtype && canonical_name(&s.owner) == owner
                        })
                    })
                    .cloned(),
            );
            if records.is_empty() {
                continue;
            }
            let ttl = records
                .iter()
                .map(|rr| rr.ttl.capped_at(MAX_PROOF_TTL as u32).as_u64())
                .min()
                .unwrap_or(0);
            if ttl == 0 {
                continue;
            }

            insert_bounded_map(
                &mut entry.wildcards,
                (wildcard, Qtype::of(rtype)),
                CachedWildcard {
                    records,
                    expires_at: now + ttl,
                },
                now,
            );

            // The NSEC riding along proves the queried name absent, and is what
            // a later synthesis needs to show the *next* name absent too.
            for rr in &response.authorities {
                if rr.rdata.rtype() != rt::NSEC {
                    continue;
                }
                let Some(nsec) = Nsec::from_record(rr) else {
                    continue;
                };
                if !is_at_or_below(&nsec.owner, &zone) {
                    continue;
                }
                let ttl = rr.ttl.capped_at(MAX_PROOF_TTL as u32).as_u64();
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
        }
    }

    /// Answer `qname`/`qtype` positively from a cached wildcard (RFC 8198 §5.3).
    ///
    /// Two things must hold. A cached NSEC must cover the name, or a wildcard
    /// would answer for a name with records of its own that shadow it
    /// (RFC 1034 §4.3.3). And the wildcard must be `*.<immediate parent>` and
    /// nothing shallower: `*.example.com.` may answer for `a.b.example.com.`
    /// only if `b.example.com.` does not exist, which a covering NSEC cannot
    /// establish — a name sorts before everything beneath it, so
    /// `b.example.com.`'s own NSEC covers `a.b.example.com.` either way.
    /// Deriving the wildcard from the queried name makes that unavailable, at
    /// the cost of a missed synthesis.
    pub fn synthesize_wildcard(&self, qname: &str, qtype: Qtype) -> Option<WildcardSynthesis> {
        if !synthesizable_qtype(qtype) {
            return None;
        }
        let qname = canonical_name(qname);
        let wildcard = wildcard_for_parent_of(&qname)?;
        let now = current_unix_timestamp();
        let zones = self.zones.lock().ok()?;

        let (_, zone) = zones
            .iter()
            .filter(|(z, _)| is_at_or_below(&qname, z.as_str()))
            .max_by_key(|(z, _)| label_count(z.as_str()))?;

        let cached = zone
            .wildcards
            .get(&(wildcard.clone(), qtype))
            .filter(|w| w.expires_at > now)?;
        // The queried name must not exist. `covering_nsec` also refuses a gap
        // below a delegation, whose names sort inside it.
        let denial = zone.covering_nsec(&qname, now)?;

        let ttl = cached
            .expires_at
            .saturating_sub(now)
            .min(denial.expires_at.saturating_sub(now))
            .min(u32::MAX as u64) as u32;
        if ttl == 0 {
            return None;
        }

        // Re-owned onto the name that was asked for. The wildcard signature
        // verifies there unchanged, so a DO client can check this itself.
        let answers: Vec<ResourceRecord> = with_ttl(&cached.records, ttl)
            .into_iter()
            .map(|mut rr| {
                rr.name = qname.clone();
                rr
            })
            .collect();

        Some(WildcardSynthesis {
            answers,
            authority: with_ttl(&denial.records, ttl),
            ttl,
        })
    }

    /// Answer `qname`/`qtype` from cached proofs, or `None` to go and ask.
    ///
    /// `None` is always safe and is the answer whenever anything is in doubt.
    pub fn synthesize(&self, qname: &str, qtype: Qtype) -> Option<Synthesis> {
        if !synthesizable_qtype(qtype) {
            return None;
        }
        let qname = canonical_name(qname);
        let now = current_unix_timestamp();

        // Under the lock: find the zone and take what bears on the question.
        // Whether it proves anything is decided below, with the guard dropped.
        let (zone_name, soa_records, soa_ttl, gathered) = {
            let zones = self.zones.lock().ok()?;

            // The deepest cached zone enclosing the name is the one whose NSEC
            // chain covers it; a shallower zone's chain stops at the delegation.
            let (zone_name, zone) = zones
                .iter()
                .filter(|(z, _)| is_at_or_below(&qname, z.as_str()))
                .max_by_key(|(z, _)| label_count(z.as_str()))?;

            let soa = zone.soa.as_ref().filter(|s| s.expires_at > now)?;
            let gathered = zone
                .gather_nodata(&qname, qtype, now)
                .or_else(|| zone.gather_nxdomain(&qname, zone_name.as_str(), now))?;

            let soa_ttl = soa
                .negative_ttl
                .min(soa.expires_at.saturating_sub(now).min(u32::MAX as u64) as u32);
            (
                zone_name.as_str().to_string(),
                soa.records.clone(),
                soa_ttl,
                gathered,
            )
        };

        if !gathered.proved(&qname, &zone_name, qtype) {
            return None;
        }

        // The shortest-lived thing the answer rests on: the proofs, the SOA's
        // negative TTL (RFC 2308 §5), and what is left of the SOA. Applied to
        // every record going out, or a client re-caches it past our own hold.
        let ttl = gathered.ttl.min(soa_ttl);
        if ttl == 0 {
            return None;
        }

        let mut authority = with_ttl(&soa_records, ttl);
        authority.extend(with_ttl(&gathered.records, ttl));
        Some(Synthesis {
            rcode: gathered.rcode,
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
    /// The greatest owner at or below `name`, or failing that the last record in
    /// the chain, which is the one that wraps around to the apex.
    ///
    /// A gap says nothing exists *in this zone*. If its lower endpoint is a
    /// delegation — NS set, SOA clear — everything beneath it lives in the child
    /// zone and sorts inside the gap, so the gap swallows the whole subtree.
    /// Denying there denies a zone we were never authoritative for.
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

    /// The distinct NSEC3 hash parameters among the live records — one, unless
    /// the zone is mid-NSEC3PARAM roll and publishing two chains. A name is
    /// hashed once per set, never once per record.
    fn nsec3_params(&self, now: u64) -> Vec<Nsec3Params<'_>> {
        let mut sets: Vec<Nsec3Params<'_>> = Vec::new();
        for cached in self.nsec3s.values().filter(|c| c.live(now)) {
            let params = cached.proof.params();
            if !sets.contains(&params) {
                sets.push(params);
            }
        }
        sets
    }

    /// The live NSEC3 whose owner hash *is* `hash`.
    fn matching_nsec3(
        &self,
        hash: &[u8],
        params: &Nsec3Params,
        now: u64,
    ) -> Option<&CachedProof<Nsec3>> {
        self.nsec3s
            .get(hash)
            .filter(|c| c.live(now) && c.proof.params() == *params)
    }

    /// The live NSEC3 whose span contains `hash`.
    ///
    /// The map is keyed by owner hash, so this is the predecessor — or, with
    /// nothing below it, the last record, whose span wraps. Records under other
    /// parameters are skipped rather than ending the walk: two interleaved
    /// chains share this map and have different predecessors.
    fn covering_nsec3(
        &self,
        hash: &[u8],
        params: &Nsec3Params,
        now: u64,
    ) -> Option<&CachedProof<Nsec3>> {
        let usable = |c: &&CachedProof<Nsec3>| c.live(now) && c.proof.params() == *params;
        let candidate = self
            .nsec3s
            .range::<[u8], _>((Bound::Unbounded, Bound::Excluded(hash)))
            .rev()
            .map(|(_, v)| v)
            .find(usable)
            .or_else(|| self.nsec3s.values().rev().find(usable))?;
        candidate.proof.covers_hash(hash).then_some(candidate)
    }

    /// NODATA: the name exists, but not with this type.
    ///
    /// Only the record *at* the name is consulted, so `proves_nodata`'s wildcard
    /// case never applies: that would mean synthesizing from a wildcard here.
    ///
    /// `Some` says a record sits at the name, not that it proves anything. It
    /// also settles NXDOMAIN — the name exists — so the caller does not fall
    /// through to [`ZoneProofs::gather_nxdomain`].
    fn gather_nodata(&self, qname: &str, qtype: Qtype, now: u64) -> Option<Gathered> {
        if let Some(cached) = self.matching_nsec(qname, now) {
            // At a delegation the parent holds only the DS; the real reply for
            // anything else is a referral, not NODATA.
            if is_delegation(&cached.proof) && !qtype.is(rt::DS) {
                return None;
            }
            return Some(Gathered {
                rcode: ResponseCode::Ok,
                nsecs: vec![cached.proof.clone()],
                nsec3s: Vec::new(),
                records: cached.records.clone(),
                ttl: cached.remaining(now),
            });
        }

        // NSEC3: the record for a name that exists is the one its hash matches,
        // and the map is already keyed by that hash.
        for params in self.nsec3_params(now) {
            let Ok(hash) = params.hash(qname) else {
                continue;
            };
            let Some(cached) = self.matching_nsec3(&hash, &params, now) else {
                continue;
            };
            if cached.proof.has_type(rt::NS) && !cached.proof.has_type(rt::SOA) && !qtype.is(rt::DS)
            {
                return None;
            }
            return Some(Gathered {
                rcode: ResponseCode::Ok,
                nsecs: Vec::new(),
                nsec3s: vec![cached.proof.clone()],
                records: cached.records.clone(),
                ttl: cached.remaining(now),
            });
        }
        None
    }

    /// NXDOMAIN: the name does not exist, and no wildcard would have answered.
    fn gather_nxdomain(&self, qname: &str, zone: &str, now: u64) -> Option<Gathered> {
        let mut candidates: Vec<&CachedProof<Nsec>> = Vec::new();
        if let Some(covering) = self.covering_nsec(qname, now) {
            candidates.push(covering);
        } else if self.nsecs.is_empty() {
            return self.gather_nxdomain_nsec3(qname, zone, now);
        } else {
            return None;
        }
        // The wildcard that could have answered sits at some ancestor, so gather
        // every ancestor's; `proves_nxdomain` picks the one that matters.
        // `qname` is canonical here, so each ancestor is a slice of it.
        for depth in label_count(zone)..label_count(qname) {
            let wildcard = format!("*.{}", crate::utils::suffix_labels(qname, depth));
            if let Some(covering) = self.covering_nsec(&wildcard, now) {
                if !candidates
                    .iter()
                    .any(|c| c.proof.owner == covering.proof.owner)
                {
                    candidates.push(covering);
                }
            }
        }
        Some(Gathered {
            rcode: ResponseCode::NoSuchDomain,
            nsecs: candidates.iter().map(|c| c.proof.clone()).collect(),
            nsec3s: Vec::new(),
            records: candidates
                .iter()
                .flat_map(|c| c.records.iter().cloned())
                .collect(),
            ttl: candidates
                .iter()
                .map(|c| c.remaining(now))
                .min()
                .unwrap_or(0),
        })
    }

    /// The NSEC3 form: RFC 5155 §8.4 wants the record matching the deepest
    /// ancestor that exists, one covering the name a label below it, and one
    /// accounting for the wildcard there.
    fn gather_nxdomain_nsec3(&self, qname: &str, zone: &str, now: u64) -> Option<Gathered> {
        self.nsec3_params(now)
            .iter()
            .find_map(|params| self.gather_nxdomain_under(qname, zone, params, now))
    }

    /// One chain's attempt at that proof: three names hashed, one map lookup
    /// each. The client picks both the label count and the number of cached
    /// records, so the hash must not be re-derived per record.
    ///
    /// The walk starts at the QNAME and stops at the first ancestor with a
    /// record (RFC 5155 §8.3): a responder sends the encloser's record and none
    /// of its ancestors', so walking down from the apex would stop at the first
    /// name nobody had asked about. `qname` is canonical — [`NsecCache`]'s entry
    /// points make it so — hence each ancestor is a slice of it.
    fn gather_nxdomain_under(
        &self,
        qname: &str,
        zone: &str,
        params: &Nsec3Params,
        now: u64,
    ) -> Option<Gathered> {
        let qlabels = label_count(qname);
        let zlabels = label_count(zone);
        let mut candidate = qname;
        let mut depth = qlabels;
        // The next closer name is the candidate this walk rejected one step
        // earlier, so it is never derived a second time.
        let mut below: Option<&str> = None;
        let mut encloser = None;
        loop {
            let hash = params.hash(candidate).ok()?;
            if let Some(cached) = self.matching_nsec3(&hash, params, now) {
                // A record at the name itself says it exists: nothing to deny.
                if depth == qlabels {
                    return None;
                }
                encloser = Some((below?, candidate, cached));
                break;
            }
            if depth == zlabels {
                break;
            }
            below = Some(candidate);
            candidate = crate::utils::parent_name(candidate)?;
            depth -= 1;
        }
        let (next_closer, encloser_name, matching) = encloser?;

        // As with NSEC: below a delegation the names are the child's, and this
        // zone's chain says nothing about them.
        if matching.proof.has_type(rt::NS) && !matching.proof.has_type(rt::SOA) {
            return None;
        }
        let mut candidates = vec![matching];

        // The next closer name must be absent...
        let hash = params.hash(next_closer).ok()?;
        push_unique(&mut candidates, self.covering_nsec3(&hash, params, now)?);

        // ...and the wildcard at the encloser must be accounted for, whether by
        // being absent or by existing and not having been expanded.
        let wildcard = format!("*.{encloser_name}");
        let hash = params.hash(&wildcard).ok()?;
        let accounted = self
            .matching_nsec3(&hash, params, now)
            .or_else(|| self.covering_nsec3(&hash, params, now))?;
        push_unique(&mut candidates, accounted);

        Some(Gathered {
            rcode: ResponseCode::NoSuchDomain,
            nsecs: Vec::new(),
            nsec3s: candidates.iter().map(|c| c.proof.clone()).collect(),
            records: candidates
                .iter()
                .flat_map(|c| c.records.iter().cloned())
                .collect(),
            ttl: candidates
                .iter()
                .map(|c| c.remaining(now))
                .min()
                .unwrap_or(0),
        })
    }
}

/// What a lookup found, before the proof logic has been asked whether it stands.
///
/// Split from the verdict so the verdict is reached with the lock dropped:
/// verifying hashes once per label of a name the *client* chose.
struct Gathered {
    rcode: ResponseCode,
    /// What the proof rests on, in the form the `proves_*` functions take —
    /// asking them rather than re-deciding here keeps one set of rules.
    nsecs: Vec<Nsec>,
    nsec3s: Vec<Nsec3>,
    /// The proof records as cached, and what is left of the shortest-lived of
    /// them. The TTL going out is lower still; `synthesize` applies it.
    records: Vec<ResourceRecord>,
    ttl: u32,
}

impl Gathered {
    fn proved(&self, qname: &str, zone: &str, qtype: Qtype) -> bool {
        match self.rcode {
            ResponseCode::NoSuchDomain => {
                matches!(
                    proves_nxdomain(qname, zone, &self.nsecs, &self.nsec3s),
                    Denial::Proved
                )
            }
            _ => proves_nodata(
                qname,
                zone,
                Rtype::new(qtype.to_u16()),
                &self.nsecs,
                &self.nsec3s,
            )
            .is_proved(),
        }
    }
}

/// Add a proof to the list unless that record is already in it.
fn push_unique<'a>(candidates: &mut Vec<&'a CachedProof<Nsec3>>, cached: &'a CachedProof<Nsec3>) {
    if !candidates
        .iter()
        .any(|c| c.proof.owner_hash == cached.proof.owner_hash)
    {
        candidates.push(cached);
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
fn records_covering(records: &[ResourceRecord], owner: &str, rtype: Rtype) -> Vec<ResourceRecord> {
    let owner = canonical_name(owner);
    records
        .iter()
        .filter(|rr| canonical_name(&rr.name) == owner)
        .filter(|rr| {
            rr.rdata.rtype() == rtype
                || matches!(
                    rr.rdata.parse(),
                    Ok(ParsedRecord::RRSIG { type_covered, .. }) if type_covered == rtype
                )
        })
        .cloned()
        .collect()
}

fn records_at(records: &[ResourceRecord], owner: &str, rtype: Rtype) -> Vec<ResourceRecord> {
    records_covering(records, owner, rtype)
}

/// The same records with their TTLs set to what is left of them. A cached
/// record must count down, or a client re-caching it extends its life forever.
fn with_ttl(records: &[ResourceRecord], ttl: u32) -> Vec<ResourceRecord> {
    records
        .iter()
        .map(|rr| ResourceRecord {
            ttl: Ttl::from_secs(ttl),
            ..rr.clone()
        })
        .collect()
}

/// Insert into a bounded map, making room by dropping expired entries first and
/// then the one that expires soonest.
/// The same bound for the wildcard store: drop what has expired first, and
/// otherwise the entry closest to expiring. A zone can hold a wildcard per type
/// at every level, and this is bounded for the same reason everything else here
/// is — the alternative is unbounded.
fn insert_bounded_map(
    map: &mut HashMap<(String, Qtype), CachedWildcard>,
    key: (String, Qtype),
    value: CachedWildcard,
    now: u64,
) {
    if !map.contains_key(&key) && map.len() >= MAX_WILDCARDS_PER_ZONE {
        map.retain(|_, v| v.expires_at > now);
        if map.len() >= MAX_WILDCARDS_PER_ZONE {
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

fn evict_zone(zones: &mut HashMap<NameKeyBuf, ZoneProofs>, now: u64) {
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
    use crate::dnssec_denial::{build_type_bitmap, nsec3_hash, nsec3_owner_name};
    use crate::Class;
    use crate::Serial;
    use crate::{OpCode, QueryClass, QuerySection, RecordData};

    fn soa_record(zone: &str, minimum: u32, ttl: Ttl) -> ResourceRecord {
        ResourceRecord {
            name: zone.to_string(),
            class: Class::new(1),
            ttl,
            rdata: RecordData::from_parsed(&ParsedRecord::SOA {
                mname: format!("ns1.{zone}"),
                rname: format!("admin.{zone}"),
                serial: Serial::new(1),
                refresh: 10800,
                retry: 3600,
                expire: 604800,
                minimum,
            })
            .unwrap(),
        }
    }

    fn nsec_record(owner: &str, next: &str, types: &[Rtype], ttl: Ttl) -> ResourceRecord {
        ResourceRecord {
            name: owner.to_string(),
            class: Class::new(1),
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
        types: &[Rtype],
        ttl: Ttl,
    ) -> ResourceRecord {
        let salt = vec![0xaa, 0xbb];
        let hash = nsec3_hash(name, &salt, 3).unwrap();
        ResourceRecord {
            name: nsec3_owner_name(&hash, zone),
            class: Class::new(1),
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
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: authority,
            additionals: Vec::new(),
            edns: None,
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
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                // The apex NSEC covers everything from the apex to www, which
                // includes the wildcard position, so a name in the gap has no
                // wildcard to fall back on either.
                nsec_record(
                    "example.com.",
                    "www.example.com.",
                    &[rt::SOA, rt::NS, rt::RRSIG, rt::NSEC],
                    Ttl::from_secs(3600),
                ),
            ],
        ));
        cache
    }

    /// A zone's worth of NSEC3 that proves nothing about anything: every span is
    /// one hash wide, so no name is covered and only the `fill` names match.
    ///
    /// The worst case for a scan, and what a flood of random names produces —
    /// the cache fills with real proofs about names nobody asks for twice.
    fn cache_of_n_nsec3s(n: usize) -> NsecCache {
        let salt = vec![0xaa, 0xbb];
        let mut authority = vec![soa_record("example.com.", 3600, Ttl::from_secs(3600))];
        let mut i = 0;
        while authority.len() <= n {
            let hash = nsec3_hash(&format!("fill{i}.example.com."), &salt, 3).unwrap();
            i += 1;
            // The span runs from the owner to the same hash with its last octet
            // at 0xff, so it wraps around nothing and contains nothing. A hash
            // already ending in 0xff would make the range empty *and* wrapped,
            // which covers everything instead.
            if *hash.last().unwrap() == 0xff {
                continue;
            }
            let mut next = hash.clone();
            *next.last_mut().unwrap() = 0xff;
            authority.push(ResourceRecord {
                name: nsec3_owner_name(&hash, "example.com."),
                class: Class::new(1),
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::NSEC3 {
                    hash_algorithm: 1,
                    flags: 0,
                    iterations: 3,
                    salt: salt.clone(),
                    next_hashed_owner: next,
                    type_bitmap: build_type_bitmap(&[rt::A]),
                })
                .unwrap(),
            });
        }
        let cache = NsecCache::new(4);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            authority,
        ));
        cache
    }

    /// A name as deep as the protocol allows, which is the multiplier the client
    /// chooses.
    fn deepest_name() -> String {
        format!("{}example.com.", "a.".repeat(115))
    }

    /// Filling the cache must not make a lookup in it slower. The NSEC3 half is
    /// keyed by owner hash and hashes a name once per chain, so what is cached
    /// is not in the cost.
    ///
    /// A ratio rather than a floor (`CLAUDE.md` §10): the absolute numbers are
    /// the machine's, the complexity class is the code's. Watched failing
    /// against the scan this replaced — 31.6× and 1.6 s per lookup in a debug
    /// build, where the query the finding came from cost 1 156 ms of CPU in a
    /// release one, with the cache's one lock held for all of it.
    #[test]
    fn a_lookup_costs_the_same_however_many_proofs_are_cached() {
        use std::time::Instant;

        let qname = deepest_name();
        let few = cache_of_n_nsec3s(8);
        let many = cache_of_n_nsec3s(MAX_PROOFS_PER_ZONE);
        // Nothing in either cache bears on the name, which is the case a flood
        // produces and the one the scan was worst at.
        assert!(few.synthesize(&qname, Qtype::of(rt::A)).is_none());
        assert!(many.synthesize(&qname, Qtype::of(rt::A)).is_none());

        let batch = 20;
        let time = |cache: &NsecCache| {
            let start = Instant::now();
            for _ in 0..batch {
                cache.synthesize(&qname, Qtype::of(rt::A));
            }
            start.elapsed()
        };
        // Once through each before measuring: the first call in a process pays
        // for pages nobody has touched yet.
        time(&few);
        time(&many);

        let small = time(&few);
        let large = time(&many);
        let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-9);
        assert!(
            ratio < 3.0,
            "a lookup got {ratio:.1}x slower with {} cached proofs instead of 8 \
             ({small:?} -> {large:?}); the NSEC3 lookup is scanning them again",
            MAX_PROOFS_PER_ZONE
        );
    }

    #[test]
    fn test_one_gap_denies_every_name_inside_it() {
        let cache = cache_with_a_gap();
        for name in [
            "nope.example.com.",
            "also-nope.example.com.",
            "b.example.com.",
        ] {
            let s = cache
                .synthesize(name, Qtype::of(rt::A))
                .unwrap_or_else(|| panic!("{name} is inside the cached gap"));
            assert_eq!(s.rcode, ResponseCode::NoSuchDomain);
            assert!(
                s.authority.iter().any(|rr| rr.rdata.rtype() == rt::SOA),
                "a negative answer must carry the SOA (RFC 2308 2.1)"
            );
            assert!(s.authority.iter().any(|rr| rr.rdata.rtype() == rt::NSEC));
            assert!(s.ttl > 0 && s.ttl <= 3600);
        }
    }

    /// Names outside the gap must go upstream, not be denied.
    #[test]
    fn test_names_outside_the_gap_are_not_denied() {
        let cache = cache_with_a_gap();
        // Past the end of the gap.
        assert!(cache
            .synthesize("zzz.example.com.", Qtype::of(rt::A))
            .is_none());
        // The gap's own endpoints exist.
        assert!(cache
            .synthesize("www.example.com.", Qtype::of(rt::A))
            .is_none());
        // A different zone entirely.
        assert!(cache
            .synthesize("nope.example.org.", Qtype::of(rt::A))
            .is_none());
        // And a name above the zone.
        assert!(cache.synthesize("com.", Qtype::of(rt::A)).is_none());
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
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                // A delegation at sub.example.com., with the next name in the
                // parent zone being www. Canonically, x.sub.example.com. falls
                // inside (sub.example.com., www.example.com.).
                nsec_record(
                    "sub.example.com.",
                    "www.example.com.",
                    &[rt::NS, rt::RRSIG, rt::NSEC],
                    Ttl::from_secs(3600),
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
            cache
                .synthesize("x.sub.example.com.", Qtype::of(rt::A))
                .is_none(),
            "names in a delegated child zone must never be denied from the parent's gap"
        );
        assert!(cache
            .synthesize("deep.x.sub.example.com.", Qtype::of(rt::A))
            .is_none());
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
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                nsec_record(
                    "sub.example.com.",
                    "www.example.com.",
                    &[rt::NS, rt::RRSIG, rt::NSEC],
                    Ttl::from_secs(3600),
                ),
            ],
        ));

        let ds = cache.synthesize("sub.example.com.", Qtype::of(rt::DS));
        assert!(ds.is_some(), "no DS at the delegation is a real NODATA");
        assert_eq!(ds.unwrap().rcode, ResponseCode::Ok);

        assert!(
            cache
                .synthesize("sub.example.com.", Qtype::of(rt::A))
                .is_none(),
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
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                nsec_record(
                    "www.example.com.",
                    "zzz.example.com.",
                    &[rt::A, rt::RRSIG, rt::NSEC],
                    Ttl::from_secs(3600),
                ),
            ],
        ));

        let s = cache
            .synthesize("www.example.com.", Qtype::of(rt::AAAA))
            .expect("NODATA");
        assert_eq!(s.rcode, ResponseCode::Ok);
        assert!(s.authority.iter().all(|rr| rr.rdata.rtype() != rt::A));
        // A is in the bitmap, so that one has to go upstream.
        assert!(cache
            .synthesize("www.example.com.", Qtype::of(rt::A))
            .is_none());
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
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                nsec_record(
                    "m.example.com.",
                    "zzz.example.com.",
                    &[rt::A, rt::RRSIG, rt::NSEC],
                    Ttl::from_secs(3600),
                ),
            ],
        ));
        assert!(
            cache
                .synthesize("nope.example.com.", Qtype::of(rt::A))
                .is_none(),
            "without a wildcard denial a wildcard could still have answered"
        );
    }

    #[test]
    fn test_any_and_rrsig_are_never_synthesized() {
        let cache = cache_with_a_gap();
        assert!(
            cache.synthesize("nope.example.com.", Qtype::ANY).is_none(),
            "ANY"
        );
        assert!(cache
            .synthesize("nope.example.com.", Qtype::of(rt::RRSIG))
            .is_none());
    }

    /// An expired proof denies nothing.
    #[test]
    fn test_expired_proofs_are_not_used() {
        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("example.com.", 0, Ttl::from_secs(0)),
                nsec_record(
                    "example.com.",
                    "www.example.com.",
                    &[rt::SOA, rt::NS, rt::RRSIG, rt::NSEC],
                    Ttl::from_secs(0),
                ),
            ],
        ));
        assert!(
            cache
                .synthesize("nope.example.com.", Qtype::of(rt::A))
                .is_none(),
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
                soa_record("example.com.", 60, Ttl::from_secs(3600)),
                nsec_record(
                    "example.com.",
                    "www.example.com.",
                    &[rt::SOA, rt::NS, rt::RRSIG, rt::NSEC],
                    Ttl::from_secs(3600),
                ),
            ],
        ));

        let s = cache
            .synthesize("nope.example.com.", Qtype::of(rt::A))
            .expect("denied");
        assert!(
            s.ttl <= 60,
            "SOA MINIMUM bounds the negative TTL, got {}",
            s.ttl
        );
        assert!(
            s.authority.iter().all(|rr| rr.ttl <= Ttl::from_secs(60)),
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
                Ttl::from_secs(3600),
            )],
        ));
        assert!(cache.is_empty());
        assert!(cache
            .synthesize("nope.example.com.", Qtype::of(rt::A))
            .is_none());
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
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                nsec_record(
                    "a.evil.test.",
                    "z.evil.test.",
                    &[rt::A],
                    Ttl::from_secs(3600),
                ),
            ],
        ));
        assert!(cache.synthesize("m.evil.test.", Qtype::of(rt::A)).is_none());
    }

    // NSEC3

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
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                nsec3_record(
                    "example.com.",
                    "example.com.",
                    &[0xff; 20],
                    0x01, // opt-out
                    &[rt::SOA, rt::NS],
                    Ttl::from_secs(3600),
                ),
            ],
        ));
        assert!(
            cache
                .synthesize("nope.example.com.", Qtype::of(rt::A))
                .is_none(),
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
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                nsec3_record(
                    "example.com.",
                    "www.example.com.",
                    &[0xff; 20],
                    0x00,
                    &[rt::A, rt::RRSIG],
                    Ttl::from_secs(3600),
                ),
            ],
        ));

        let s = cache
            .synthesize("www.example.com.", Qtype::of(rt::AAAA))
            .expect("the matching NSEC3 denies AAAA");
        assert_eq!(s.rcode, ResponseCode::Ok);
        assert!(cache
            .synthesize("www.example.com.", Qtype::of(rt::A))
            .is_none());
    }

    /// An NSEC3 with the owner and next hashes given outright. The cache reads
    /// the owner hash out of the first label, so a chain can be laid out by hand
    /// rather than by finding names that hash where they are wanted.
    fn nsec3_span(owner: &[u8], next: &[u8], types: &[Rtype]) -> ResourceRecord {
        ResourceRecord {
            name: nsec3_owner_name(owner, "example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC3 {
                hash_algorithm: 1,
                flags: 0,
                iterations: 3,
                salt: vec![0xaa, 0xbb],
                next_hashed_owner: next.to_vec(),
                type_bitmap: build_type_bitmap(types),
            })
            .unwrap(),
        }
    }

    /// A span containing `name`'s hash and, for these purposes, nothing else:
    /// the same hash with its last octet at 0x00 and at 0xff.
    fn span_around(name: &str) -> (Vec<u8>, Vec<u8>) {
        let hash = nsec3_hash(name, &[0xaa, 0xbb], 3).unwrap();
        let last = *hash.last().unwrap();
        assert!(
            last != 0x00 && last != 0xff,
            "{name} hashes to something this fixture cannot bracket"
        );
        let mut owner = hash.clone();
        let mut next = hash;
        *owner.last_mut().unwrap() = 0x00;
        *next.last_mut().unwrap() = 0xff;
        (owner, next)
    }

    /// The closest-encloser proof of RFC 5155 §8.4, out of the cache: the apex
    /// matched, the queried name covered, and the wildcard covered.
    ///
    /// The shape a scan and a map lookup could disagree about in silence.
    fn cache_with_an_nsec3_chain() -> NsecCache {
        let apex = nsec3_hash("example.com.", &[0xaa, 0xbb], 3).unwrap();
        let mut apex_next = apex.clone();
        *apex_next.last_mut().unwrap() = apex.last().unwrap().wrapping_add(1);
        let (nope_owner, nope_next) = span_around("nope.example.com.");
        let (star_owner, star_next) = span_around("*.example.com.");

        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                nsec3_span(&apex, &apex_next, &[rt::SOA, rt::NS, rt::DNSKEY]),
                nsec3_span(&nope_owner, &nope_next, &[rt::A]),
                nsec3_span(&star_owner, &star_next, &[rt::A]),
            ],
        ));
        cache
    }

    #[test]
    fn test_nsec3_nxdomain_is_synthesized() {
        let cache = cache_with_an_nsec3_chain();
        let s = cache
            .synthesize("nope.example.com.", Qtype::of(rt::A))
            .expect("apex matched, name covered, wildcard covered");
        assert_eq!(s.rcode, ResponseCode::NoSuchDomain);
        assert!(s.authority.iter().any(|rr| rr.rdata.rtype() == rt::SOA));
        assert_eq!(
            s.authority
                .iter()
                .filter(|rr| rr.rdata.rtype() == rt::NSEC3)
                .count(),
            3,
            "the encloser, the next closer and the wildcard"
        );
    }

    /// A name the chain says nothing about must go upstream. `nope` and
    /// `elsewhere` differ only in where they hash, which is the whole of what
    /// the lookup keys on.
    #[test]
    fn test_nsec3_nxdomain_needs_the_name_covered() {
        let cache = cache_with_an_nsec3_chain();
        assert!(cache
            .synthesize("elsewhere.example.com.", Qtype::of(rt::A))
            .is_none());
    }

    /// The wildcard is the half that is easy to drop: without a record
    /// accounting for `*.example.com.`, a wildcard could have answered and the
    /// name is not proved absent (RFC 5155 §8.4).
    #[test]
    fn test_nsec3_nxdomain_needs_the_wildcard_accounted_for() {
        let apex = nsec3_hash("example.com.", &[0xaa, 0xbb], 3).unwrap();
        let mut apex_next = apex.clone();
        *apex_next.last_mut().unwrap() = apex.last().unwrap().wrapping_add(1);
        let (nope_owner, nope_next) = span_around("nope.example.com.");

        let cache = NsecCache::new(16);
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::NoSuchDomain,
            vec![
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                nsec3_span(&apex, &apex_next, &[rt::SOA, rt::NS, rt::DNSKEY]),
                nsec3_span(&nope_owner, &nope_next, &[rt::A]),
            ],
        ));
        assert!(cache
            .synthesize("nope.example.com.", Qtype::of(rt::A))
            .is_none());
    }

    // Bookkeeping

    #[test]
    fn test_zone_capacity_is_bounded() {
        let cache = NsecCache::new(2);
        for i in 0..6 {
            let zone = format!("zone{i}.test.");
            cache.insert_validated(&negative(
                &format!("nope.{zone}"),
                ResponseCode::NoSuchDomain,
                vec![
                    soa_record(&zone, 3600, Ttl::from_secs(3600)),
                    nsec_record(
                        &zone,
                        &format!("www.{zone}"),
                        &[rt::SOA, rt::NS],
                        Ttl::from_secs(3600),
                    ),
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
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                nsec_record(
                    "example.com.",
                    "www.example.com.",
                    &[rt::SOA],
                    Ttl::from_secs(3600),
                ),
            ],
        ));
        assert!(cache.is_empty());
        assert!(cache
            .synthesize("nope.example.com.", Qtype::of(rt::A))
            .is_none());
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
                soa_record("com.", 3600, Ttl::from_secs(3600)),
                nsec_record("com.", "zzz.com.", &[rt::SOA, rt::NS], Ttl::from_secs(3600)),
            ],
        ));
        cache.insert_validated(&negative(
            "nope.example.com.",
            ResponseCode::Ok,
            vec![
                soa_record("example.com.", 3600, Ttl::from_secs(3600)),
                nsec_record(
                    "nope.example.com.",
                    "zzz.example.com.",
                    &[rt::A, rt::RRSIG, rt::NSEC],
                    Ttl::from_secs(3600),
                ),
            ],
        ));

        // Answered from example.com.'s NODATA proof, not com.'s gap.
        let s = cache
            .synthesize("nope.example.com.", Qtype::of(rt::AAAA))
            .expect("the child zone's proof applies");
        assert_eq!(
            s.rcode,
            ResponseCode::Ok,
            "NODATA, not the parent's NXDOMAIN"
        );
    }
    // Wildcard synthesis (RFC 8198 section 5.3)

    /// A positive answer as a zone sends one from a wildcard: the records owned at
    /// the *queried* name, an RRSIG whose label count says a wildcard signed it,
    /// and in the authority section the NSEC proving the queried name absent.
    fn wildcard_answer(qname: &str, wildcard_labels: u8, nsec: ResourceRecord) -> DnsMessage {
        let a = ResourceRecord {
            name: qname.to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.7".parse().unwrap())).unwrap(),
        };
        let sig = ResourceRecord {
            name: qname.to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::RRSIG {
                type_covered: rt::A,
                algorithm: 13,
                labels: wildcard_labels,
                original_ttl: 300,
                inception: 1,
                expiration: u32::MAX,
                key_tag: 1234,
                signer_name: "example.com.".to_string(),
                signature: vec![9; 64],
            })
            .unwrap(),
        };
        let nsec_sig = ResourceRecord {
            name: nsec.name.clone(),
            class: Class::new(1),
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::RRSIG {
                type_covered: rt::NSEC,
                algorithm: 13,
                labels: 2,
                original_ttl: 300,
                inception: 1,
                expiration: u32::MAX,
                key_tag: 1234,
                signer_name: "example.com.".to_string(),
                signature: vec![8; 64],
            })
            .unwrap(),
        };
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
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: qname.to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            }],
            answers: vec![a, sig],
            authorities: vec![nsec, nsec_sig],
            additionals: Vec::new(),
            edns: None,
        }
    }

    fn apex_gap() -> ResourceRecord {
        nsec_record(
            "example.com.",
            "zzz.example.com.",
            &[rt::SOA, rt::NS],
            Ttl::from_secs(300),
        )
    }

    /// The point of section 5.3: one validated wildcard answer answers for every
    /// name that wildcard reaches, without asking again.
    #[test]
    fn test_a_validated_wildcard_answers_another_name_it_reaches() {
        let cache = NsecCache::new(4);
        // `a.example.com.` was answered by `*.example.com.` — labels=2 for a
        // three-label owner — and the NSEC gap runs from the apex to `zzz`.
        cache.insert_validated_wildcard(&wildcard_answer("a.example.com.", 2, apex_gap()));

        let s = cache
            .synthesize_wildcard("b.example.com.", Qtype::of(rt::A))
            .expect("the same wildcard reaches this name too");
        assert_eq!(
            s.answers
                .iter()
                .filter(|rr| rr.rdata.rtype() == rt::A)
                .count(),
            1
        );
        for rr in &s.answers {
            assert_eq!(
                rr.name, "b.example.com.",
                "re-owned onto the name asked for"
            );
            assert!(rr.ttl.as_secs() <= 300);
        }
        assert!(
            s.answers.iter().any(|rr| rr.rdata.rtype() == rt::RRSIG),
            "the signature goes with it: it verifies at the new name unchanged"
        );
        assert!(
            s.authority.iter().any(|rr| rr.rdata.rtype() == rt::NSEC),
            "with the proof the name does not exist, so a client can check it"
        );
        assert!(
            matches!(
                s.answers[0].rdata.parse(),
                Ok(ParsedRecord::A(a)) if a == "192.0.2.7".parse::<std::net::Ipv4Addr>().unwrap()
            ),
            "and the address the wildcard holds"
        );
    }

    /// The rule that makes this safe. A wildcard covers exactly one label
    /// (RFC 4592 section 2.1.1), so `*.example.com.` must never answer for a name
    /// that `b.example.com.` governs — and "some cached NSEC covers the name" does
    /// not distinguish the two, because a name sorts before everything beneath it.
    #[test]
    fn test_a_wildcard_never_answers_for_a_deeper_name() {
        let cache = NsecCache::new(4);
        cache.insert_validated_wildcard(&wildcard_answer("a.example.com.", 2, apex_gap()));

        assert!(
            cache
                .synthesize_wildcard("x.b.example.com.", Qtype::of(rt::A))
                .is_none(),
            "*.example.com. does not reach a name two labels down"
        );
        assert!(
            cache
                .synthesize_wildcard("x.y.z.example.com.", Qtype::of(rt::A))
                .is_none(),
            "nor any deeper"
        );
    }

    /// Only for a name that does not exist. An existing name shadows the wildcard
    /// entirely (RFC 1034 section 4.3.3), so without a covering NSEC there is no
    /// basis to answer at all.
    #[test]
    fn test_nothing_is_synthesized_without_a_proof_the_name_is_absent() {
        let cache = NsecCache::new(4);
        // A gap that stops short of `b`, so nothing proves `b` absent.
        cache.insert_validated_wildcard(&wildcard_answer(
            "a.example.com.",
            2,
            nsec_record(
                "example.com.",
                "aa.example.com.",
                &[rt::SOA, rt::NS],
                Ttl::from_secs(300),
            ),
        ));

        assert!(cache
            .synthesize_wildcard("b.example.com.", Qtype::of(rt::A))
            .is_none());
    }

    /// The type has to match: a wildcard holding an A says nothing about AAAA.
    #[test]
    fn test_a_cached_wildcard_answers_only_its_own_type() {
        let cache = NsecCache::new(4);
        cache.insert_validated_wildcard(&wildcard_answer("a.example.com.", 2, apex_gap()));

        assert!(cache
            .synthesize_wildcard("b.example.com.", Qtype::of(rt::A))
            .is_some());
        assert!(cache
            .synthesize_wildcard("b.example.com.", Qtype::of(rt::AAAA))
            .is_none());
        assert!(cache
            .synthesize_wildcard("b.example.com.", Qtype::of(rt::MX))
            .is_none());
    }

    /// An answer that was *not* a wildcard expansion must not be stored as one, or
    /// an ordinary answer for one name would start answering for its siblings.
    #[test]
    fn test_an_ordinary_answer_is_not_a_wildcard() {
        let cache = NsecCache::new(4);
        // labels=3 for a three-label owner: signed at its own name.
        cache.insert_validated_wildcard(&wildcard_answer("a.example.com.", 3, apex_gap()));

        assert!(cache
            .synthesize_wildcard("b.example.com.", Qtype::of(rt::A))
            .is_none());
        assert!(cache.is_empty(), "nothing was stored at all");
    }

    /// The same delegation rule as the denial side, and for the same reason: the
    /// names under a delegation sort inside the gap that follows it, so a wildcard
    /// above must not answer for them.
    #[test]
    fn test_no_synthesis_below_a_delegation() {
        let cache = NsecCache::new(4);
        cache.insert_validated_wildcard(&wildcard_answer(
            "a.example.com.",
            2,
            // The gap's lower edge is a delegation: NS set, no SOA.
            nsec_record(
                "sub.example.com.",
                "zzz.example.com.",
                &[rt::NS],
                Ttl::from_secs(300),
            ),
        ));

        assert!(
            cache
                .synthesize_wildcard("x.sub.example.com.", Qtype::of(rt::A))
                .is_none(),
            "the child zone's names are not ours to answer for"
        );
    }

    #[test]
    fn test_the_wildcard_derivations() {
        assert_eq!(
            wildcard_for_expansion("a.example.com.", 2).as_deref(),
            Some("*.example.com.")
        );
        assert_eq!(
            wildcard_for_expansion("x.y.example.com.", 2).as_deref(),
            Some("*.example.com."),
            "two labels stripped is still the same wildcard name"
        );
        assert_eq!(
            wildcard_for_expansion("a.example.com.", 3),
            None,
            "nothing stripped is not an expansion"
        );

        assert_eq!(
            wildcard_for_parent_of("b.example.com.").as_deref(),
            Some("*.example.com.")
        );
        assert_eq!(
            wildcard_for_parent_of("x.b.example.com.").as_deref(),
            Some("*.b.example.com."),
            "the immediate parent, which is what makes the depth check work"
        );
        // A top-level name's parent is the root, so the wildcard that would
        // govern it is `*.` — refused rather than derived. The root publishes no
        // wildcard, and a rule about synthesizing TLDs is not one to have.
        assert_eq!(wildcard_for_parent_of("com."), None);
        assert_eq!(wildcard_for_parent_of("."), None);
    }

    /// A disabled cache stores nothing, the same as for denials.
    #[test]
    fn test_a_zero_capacity_cache_holds_no_wildcards() {
        let cache = NsecCache::new(0);
        cache.insert_validated_wildcard(&wildcard_answer("a.example.com.", 2, apex_gap()));
        assert!(cache
            .synthesize_wildcard("b.example.com.", Qtype::of(rt::A))
            .is_none());
        assert!(cache.is_empty());
    }
}
