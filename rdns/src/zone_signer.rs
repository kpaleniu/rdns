//! Signing a zone: a DNSKEY RRset, an RRSIG over every authoritative RRset, and
//! a chain that denies everything else.
//!
//! The validator in [`crate::dnssec`] and [`crate::dnssec_denial`] was written
//! first and is the harder half; this is the half that produces what it reads.
//! The two meet in the tests — a zone signed here is put through
//! `verify_rrset`, `proves_nxdomain` and `proves_nodata` unmodified, so the
//! output is checked against the same code that judges a real zone off the
//! internet rather than against a second opinion written alongside it.
//!
//! **Signing is done in memory, on load, and the zone file is never rewritten.**
//! The file on disk stays the unsigned thing an operator edits. That is one
//! decision with three reasons: a signer that rewrites its input has to solve
//! the same "who owns this file" problem the transfer sidecar deliberately
//! stepped around (see "Architecture: persistence"), an editor and a resigning
//! timer racing for one file is a way to lose a zone, and — most of all —
//! nothing here needs the file, because what a client validates is what leaves
//! the socket. Writing the signed form out is available
//! ([`crate::zone_writer`] will spell it) but is a debugging convenience, not
//! where the signatures live.
//!
//! **What does not get signed is as important as what does.** A zone's
//! authority stops at a delegation: the NS RRset that points down is not
//! authoritative data and carries no signature, the glue below it is not in the
//! zone at all, and the only signed thing at a delegation point is the DS that
//! says the child is secure — plus the denial record, which exists precisely so
//! the *absence* of a DS can be proved. Signing a delegation's NS RRset is the
//! classic signer bug: every validator ignores the signature, and the extra
//! RRSIG turns up in the parent's NSEC bitmap as a type that is not there.

use crate::dnssec::{canonical_name, Dnskey, Rrset};
use crate::dnssec_denial::{
    base32hex_encode, build_type_bitmap, canonical_sort_key, nsec3_hash, MAX_NSEC3_ITERATIONS,
};
use crate::dnssec_key::SigningKey;
use crate::utils::record_types as rt;
use crate::zone::{Zone, ZoneRecord};
use crate::{ParsedRecord, RecordData};
use anyhow::{anyhow, Context, Result};
use std::collections::{BTreeMap, BTreeSet};

/// How a zone proves that a name is not in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialChain {
    /// NSEC (RFC 4034 §4): each name points at the next in canonical order.
    /// Simple, cheap to generate, and lets anyone walk the zone one query at a
    /// time — which is a disclosure question, not a security one.
    Nsec,
    /// NSEC3 (RFC 5155): the same chain over hashed names.
    Nsec3 {
        /// RFC 9276 §3.1 is blunt about this: use an empty salt. A salt is
        /// re-hashed with the zone at every rollover and buys nothing against
        /// an attacker who can simply hash the guesses they were going to make
        /// anyway.
        salt: Vec<u8>,
        /// And zero iterations, for the same reason — the cost lands on the
        /// server and on every validator, not on the attacker.
        iterations: u16,
        /// Opt-out (RFC 5155 §6): leave insecure delegations out of the chain,
        /// so a zone full of unsigned children does not pay for a record per
        /// child. What it costs is that "this name does not exist" weakens to
        /// "this name does not exist, or is an insecure delegation I did not
        /// list" — which is why [`crate::dnssec_denial`] treats an opt-out span
        /// as unjudgeable rather than as proof.
        opt_out: bool,
    },
}

impl DenialChain {
    /// The RFC 9276 §3.1 recommendation: NSEC3 with no salt and no extra
    /// iterations.
    pub fn nsec3() -> Self {
        DenialChain::Nsec3 {
            salt: Vec::new(),
            iterations: 0,
            opt_out: false,
        }
    }

    fn check(&self) -> Result<()> {
        if let DenialChain::Nsec3 {
            salt, iterations, ..
        } = self
        {
            if salt.len() > 255 {
                return Err(anyhow!(
                    "an NSEC3 salt is a length-prefixed byte string and cannot exceed 255 bytes, \
                     this one is {}",
                    salt.len()
                ));
            }
            if *iterations > MAX_NSEC3_ITERATIONS {
                // Refusing to *sign* what we would refuse to *validate* is the
                // point: this library caps verification at the RFC 9276 limit,
                // so a zone signed above it here would be a zone we could not
                // read ourselves.
                return Err(anyhow!(
                    "{iterations} NSEC3 iterations exceeds the {MAX_NSEC3_ITERATIONS} \
                     RFC 9276 permits"
                ));
            }
        }
        Ok(())
    }
}

/// The choices a signing run makes that are not in the zone or in the keys.
#[derive(Debug, Clone)]
pub struct SigningPolicy {
    /// When the signatures start being valid.
    pub inception: u32,
    /// When they stop.
    pub expiration: u32,
    pub chain: DenialChain,
}

impl SigningPolicy {
    /// Signatures good for `validity` seconds, starting an hour ago.
    ///
    /// The backdating is not padding: a validator compares the inception
    /// against *its own* clock, and clocks disagree. RFC 6781 §4.4.2 asks for
    /// exactly this, and without it a zone re-signed and published in the same
    /// second is invalid at every client running slightly slow.
    pub fn valid_for(now: u64, validity: u64) -> Self {
        const CLOCK_SKEW_ALLOWANCE: u64 = 3600;
        SigningPolicy {
            inception: now.saturating_sub(CLOCK_SKEW_ALLOWANCE) as u32,
            expiration: now.saturating_add(validity) as u32,
            chain: DenialChain::Nsec,
        }
    }

    pub fn with_chain(mut self, chain: DenialChain) -> Self {
        self.chain = chain;
        self
    }
}

/// Sign `zone` with `keys`, returning the signed zone.
///
/// The input is left alone. What comes back is the same records — with their
/// TTLs normalized per RRset, see below — plus the DNSKEY RRset, an RRSIG over
/// everything the zone is authoritative for, and an NSEC or NSEC3 chain.
///
/// Re-signing is idempotent in the sense that matters: the signer's own previous
/// output (RRSIG, NSEC, NSEC3, NSEC3PARAM) is dropped before anything is
/// generated, so signing a signed zone produces a freshly signed zone rather
/// than a zone with two chains in it. DNSKEY records are *not* dropped, because
/// a key published without its private half is how every rollover starts and
/// deleting it would undo the operator's preparation.
pub fn sign_zone(zone: &Zone, keys: &[SigningKey], policy: &SigningPolicy) -> Result<Zone> {
    policy.chain.check()?;
    let origin = canonical_name(zone.origin());
    check_keys(keys, &origin)?;
    if policy.expiration <= policy.inception {
        return Err(anyhow!(
            "a signature that expires at {} cannot have been made at {}",
            policy.expiration,
            policy.inception
        ));
    }

    let mut signed = Zone::new(origin.clone());
    let (soa_ttl, minimum) = carry_over_records(zone, &origin, &mut signed)?;
    let dnskey_ttl = publish_dnskeys(keys, &origin, soa_ttl, &mut signed);
    let layout = Layout::of(&signed, &origin);

    let denial_ttl = minimum.min(i32::MAX as u32) as i32;
    match &policy.chain {
        DenialChain::Nsec => build_nsec_chain(&layout, denial_ttl, &mut signed)?,
        DenialChain::Nsec3 {
            salt,
            iterations,
            opt_out,
        } => {
            build_nsec3_chain(&layout, salt, *iterations, *opt_out, denial_ttl, &mut signed)?;
            signed.add_record(ZoneRecord {
                name: origin.clone(),
                ttl: dnskey_ttl,
                class: 1,
                rdata: nsec3param_rdata(salt, *iterations),
            });
        }
    }

    sign_everything(&layout, keys, policy, &mut signed)?;
    Ok(signed)
}

/// The keys must all belong to this zone, and at least one must be able to sign
/// its data. Both are checked before anything is generated: a signing run that
/// discovers halfway through that a key names another zone has already produced
/// signatures nobody can use.
fn check_keys(keys: &[SigningKey], origin: &str) -> Result<()> {
    if keys.is_empty() {
        return Err(anyhow!("no keys to sign {origin} with"));
    }
    for key in keys {
        if key.owner() != origin {
            return Err(anyhow!(
                "the key with tag {} is published at {}, not at {origin} — a signature from it \
                 names the wrong signer and verifies against nothing",
                key.key_tag(),
                key.owner()
            ));
        }
    }
    Ok(())
}

/// Copy everything that is not this signer's own previous output into `signed`,
/// normalizing owner names and per-RRset TTLs. Returns the apex SOA's TTL and
/// its MINIMUM field.
fn carry_over_records(zone: &Zone, origin: &str, signed: &mut Zone) -> Result<(i32, u32)> {
    let mut soa: Option<(i32, u32)> = None;
    // The TTL an RRset is signed with has to be one number (RFC 4034 §3.1.3
    // stores it in the RRSIG so a validator can restore it), and RFC 2181 §5.2
    // requires the records to agree on it anyway. Where they do not, the
    // smallest wins: a record cannot be made to live longer than its RRset was
    // told to, and taking the largest would publish data past the point some
    // record of it was meant to expire.
    let mut ttls: BTreeMap<(String, u16), i32> = BTreeMap::new();
    let mut carried: Vec<ZoneRecord> = Vec::new();

    for record in zone.records() {
        if is_signer_output(record.rdata.rtype) {
            continue;
        }
        if record.class != 1 {
            return Err(anyhow!(
                "{} carries class {}, and DNSSEC is defined per class — a zone mixing them has \
                 no single chain to sign",
                record.name,
                record.class
            ));
        }
        let name = canonical_name(&zone.normalize_name(&record.name));
        if !is_at_or_under(&name, origin) {
            return Err(anyhow!(
                "{name} is not in {origin}, so this zone has no authority to sign it"
            ));
        }
        if record.rdata.rtype == rt::SOA && name == origin {
            let ParsedRecord::SOA { minimum, .. } = record.rdata.parse()? else {
                return Err(anyhow!("the apex SOA does not parse as an SOA"));
            };
            soa = Some((record.ttl, minimum));
        }
        let key = (name.clone(), record.rdata.rtype);
        ttls.entry(key)
            .and_modify(|t| *t = (*t).min(record.ttl))
            .or_insert(record.ttl);
        carried.push(ZoneRecord { name, ..record.clone() });
    }

    for mut record in carried {
        record.ttl = ttls[&(record.name.clone(), record.rdata.rtype)];
        signed.add_record(record);
    }

    soa.ok_or_else(|| {
        anyhow!("{origin} has no SOA at its apex, so there is no zone here to sign")
    })
}

/// Records this signer generates, and therefore replaces rather than preserves.
fn is_signer_output(rtype: u16) -> bool {
    matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3 | rt::NSEC3PARAM)
}

/// Publish the DNSKEY for every key, returning the TTL the RRset ended up with.
///
/// A key already in the zone with identical RDATA is left where it is rather
/// than duplicated — that is the same key, and an RRset holding it twice is one
/// a validator has to de-duplicate before it can verify anything.
fn publish_dnskeys(keys: &[SigningKey], origin: &str, soa_ttl: i32, signed: &mut Zone) -> i32 {
    let existing: Vec<RecordData> = signed
        .query(origin, rt::DNSKEY)
        .iter()
        .map(|r| r.rdata.clone())
        .collect();
    // An RRset has one TTL: keys already published set it, since changing it
    // would be changing records the operator put there.
    let ttl = signed
        .query(origin, rt::DNSKEY)
        .first()
        .map(|r| r.ttl)
        .unwrap_or(soa_ttl);

    for key in keys {
        let rdata = dnskey_rdata(&key.dnskey());
        if existing.contains(&rdata) {
            continue;
        }
        signed.add_record(ZoneRecord {
            name: origin.to_string(),
            ttl,
            class: 1,
            rdata,
        });
    }
    ttl
}

// ---------------------------------------------------------------------------
// What is where: delegations, occlusion, and the names that need a denial
// ---------------------------------------------------------------------------

/// One owner name, as the signer sees it.
#[derive(Debug, Default, Clone)]
struct NameEntry {
    /// The types with records at this name, whether or not they are signed.
    types: BTreeSet<u16>,
    /// A non-apex NS RRset: the zone stops here.
    is_delegation: bool,
    /// Below a delegation, so present in the file but not in the zone.
    occluded: bool,
}

impl NameEntry {
    /// Whether a delegation is one this zone vouches for.
    fn is_secure_delegation(&self) -> bool {
        self.is_delegation && self.types.contains(&rt::DS)
    }

    /// The types a denial record at this name must list.
    ///
    /// At a delegation this is not the same as "the types here": glue is not
    /// authoritative data, so an A record at the delegation point is invisible
    /// to the chain even though the zone file holds it and the server hands it
    /// out as a hint.
    fn published_types(&self) -> BTreeSet<u16> {
        if self.is_delegation {
            let mut types = BTreeSet::from([rt::NS]);
            if self.types.contains(&rt::DS) {
                types.insert(rt::DS);
            }
            types
        } else {
            self.types.clone()
        }
    }

    /// Whether any RRset at this name gets a signature — which decides whether
    /// RRSIG belongs in its NSEC3 bitmap. (Under NSEC the answer is always yes,
    /// because the NSEC record itself is signed.)
    fn has_signed_data(&self) -> bool {
        if self.is_delegation {
            self.types.contains(&rt::DS)
        } else {
            !self.types.is_empty()
        }
    }
}

/// Every name in the zone, and what the signer has to know about each.
struct Layout {
    origin: String,
    names: BTreeMap<String, NameEntry>,
}

impl Layout {
    fn of(zone: &Zone, origin: &str) -> Self {
        let mut names: BTreeMap<String, NameEntry> = BTreeMap::new();
        for record in zone.records() {
            let entry = names.entry(record.name.to_ascii_lowercase()).or_default();
            entry.types.insert(record.rdata.rtype);
        }
        for (name, entry) in names.iter_mut() {
            entry.is_delegation = name != origin && entry.types.contains(&rt::NS);
        }

        let delegations: BTreeSet<String> = names
            .iter()
            .filter(|(_, e)| e.is_delegation)
            .map(|(n, _)| n.clone())
            .collect();
        for (name, entry) in names.iter_mut() {
            // Glue, and anything else written below a delegation: present in
            // the file, not part of this zone (RFC 4035 §2.2). It gets no
            // signature and no place in the chain, and if it did, the chain
            // would assert the existence of names this zone does not serve.
            entry.occluded = ancestors_of(name)
                .iter()
                .any(|ancestor| delegations.contains(ancestor));
        }

        Layout {
            origin: origin.to_string(),
            names,
        }
    }

    /// The names a denial chain must cover, in canonical order.
    ///
    /// Three things go in beyond the obvious. Delegation points, because the
    /// proof that a child is *not* signed is an authenticated denial of its DS.
    /// Empty non-terminals — a name with no records of its own that has
    /// descendants — because such a name exists, and a query for it is NODATA
    /// rather than NXDOMAIN; without a record at the name the only available
    /// proof would be one denying it exists, which is the wrong answer signed.
    /// And under opt-out, neither insecure delegations nor the empty
    /// non-terminals that exist only to hold them.
    fn chain_names(&self, opt_out: bool) -> Vec<String> {
        let mut included: BTreeSet<String> = self
            .names
            .iter()
            .filter(|(_, e)| !e.occluded)
            .filter(|(_, e)| !(opt_out && e.is_delegation && !e.is_secure_delegation()))
            .map(|(n, _)| n.clone())
            .collect();

        let mut empty_non_terminals = BTreeSet::new();
        for name in &included {
            for ancestor in ancestors_of(name) {
                if !is_under(&ancestor, &self.origin) {
                    break;
                }
                if !included.contains(&ancestor) {
                    empty_non_terminals.insert(ancestor);
                }
            }
        }
        included.extend(empty_non_terminals);

        let mut names: Vec<String> = included.into_iter().collect();
        names.sort_by_key(|name| canonical_sort_key(name));
        names
    }

    fn entry(&self, name: &str) -> NameEntry {
        self.names.get(name).cloned().unwrap_or_default()
    }
}

/// Every strict ancestor of `name`, nearest first. `a.b.example.com.` gives
/// `b.example.com.`, `example.com.`, `com.`, `.`.
fn ancestors_of(name: &str) -> Vec<String> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return Vec::new();
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    (1..labels.len())
        .map(|i| format!("{}.", labels[i..].join(".")))
        .chain(std::iter::once(".".to_string()))
        .collect()
}

/// Whether `name` is strictly below `origin`.
fn is_under(name: &str, origin: &str) -> bool {
    name != origin && is_at_or_under(name, origin)
}

fn is_at_or_under(name: &str, origin: &str) -> bool {
    if origin == "." {
        return true;
    }
    name.eq_ignore_ascii_case(origin)
        || name
            .to_ascii_lowercase()
            .ends_with(&format!(".{}", origin.to_ascii_lowercase()))
}

// ---------------------------------------------------------------------------
// The denial chains
// ---------------------------------------------------------------------------

fn build_nsec_chain(layout: &Layout, ttl: i32, signed: &mut Zone) -> Result<()> {
    let names = layout.chain_names(false);
    for (index, name) in names.iter().enumerate() {
        // The last name points back at the apex, closing the loop — which is
        // what makes the chain able to deny a name sorting after everything in
        // the zone (RFC 4034 §4.1.1).
        let next = &names[(index + 1) % names.len()];
        let mut types = layout.entry(name).published_types();
        // Every NSEC lists itself and its own signature (RFC 4035 §2.3).
        types.insert(rt::RRSIG);
        types.insert(rt::NSEC);

        let rdata = RecordData::from_parsed(&ParsedRecord::NSEC {
            next_domain_name: next.clone(),
            type_bitmap: build_type_bitmap(&types.into_iter().collect::<Vec<_>>()),
        })
        .context("encoding an NSEC")?;
        signed.add_record(ZoneRecord {
            name: name.clone(),
            ttl,
            class: 1,
            rdata,
        });
    }
    Ok(())
}

fn build_nsec3_chain(
    layout: &Layout,
    salt: &[u8],
    iterations: u16,
    opt_out: bool,
    ttl: i32,
    signed: &mut Zone,
) -> Result<()> {
    let mut hashed: Vec<(Vec<u8>, String)> = Vec::new();
    for name in layout.chain_names(opt_out) {
        let hash = nsec3_hash(&name, salt, iterations)
            .with_context(|| format!("hashing {name} for the NSEC3 chain"))?;
        hashed.push((hash, name));
    }
    hashed.sort();

    // Two names hashing alike would make one of them undeniable and the other
    // unprovable, and the chain would silently be a lie about one of them. It
    // takes a SHA-1 collision to happen, but the check is one comparison.
    if let Some(window) = hashed.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(anyhow!(
            "{} and {} have the same NSEC3 hash — pick a different salt",
            window[0].1,
            window[1].1
        ));
    }

    for (index, (hash, name)) in hashed.iter().enumerate() {
        let next = &hashed[(index + 1) % hashed.len()].0;
        let entry = layout.entry(name);
        let mut types = entry.published_types();
        // Unlike NSEC, the record does not sit at the name it describes, so it
        // does not list itself — and RRSIG appears only if something at the
        // original name is actually signed. An insecure delegation's NSEC3
        // therefore says NS and nothing else.
        if entry.has_signed_data() {
            types.insert(rt::RRSIG);
        }

        let rdata = RecordData::from_parsed(&ParsedRecord::NSEC3 {
            hash_algorithm: 1,
            flags: u8::from(opt_out),
            iterations,
            salt: salt.to_vec(),
            next_hashed_owner: next.clone(),
            type_bitmap: build_type_bitmap(&types.into_iter().collect::<Vec<_>>()),
        })
        .context("encoding an NSEC3")?;
        signed.add_record(ZoneRecord {
            name: format!("{}.{}", base32hex_encode(hash).to_lowercase(), layout.origin),
            ttl,
            class: 1,
            rdata,
        });
    }
    Ok(())
}

/// NSEC3PARAM's RDATA (RFC 5155 §4.2): the same first four fields as an NSEC3,
/// and nothing else.
///
/// The flags octet is zero even when the chain is opt-out. RFC 5155 §4.1.2 says
/// so directly: the flags here describe the *parameters*, and a server matching
/// this record against the chain compares the salt and iterations, so a bit set
/// here that is also set in every NSEC3 would just be a second place to get it
/// wrong.
fn nsec3param_rdata(salt: &[u8], iterations: u16) -> RecordData {
    let mut rdata = Vec::with_capacity(5 + salt.len());
    rdata.push(1); // SHA-1, the only NSEC3 hash there is
    rdata.push(0);
    rdata.extend_from_slice(&iterations.to_be_bytes());
    rdata.push(salt.len() as u8);
    rdata.extend_from_slice(salt);
    RecordData {
        rtype: rt::NSEC3PARAM,
        rdata: rdata.into_boxed_slice(),
    }
}

// ---------------------------------------------------------------------------
// The signatures
// ---------------------------------------------------------------------------

fn sign_everything(
    layout: &Layout,
    keys: &[SigningKey],
    policy: &SigningPolicy,
    signed: &mut Zone,
) -> Result<()> {
    // The convention every real zone follows: the key the parent's DS points at
    // signs only the DNSKEY RRset, and a separate key signs the data. It is not
    // required — a single key may do both, which is what happens here when only
    // one is present — but it is what lets the data key roll without the parent
    // being involved.
    let sep: Vec<&SigningKey> = keys.iter().filter(|k| k.is_sep()).collect();
    let rest: Vec<&SigningKey> = keys.iter().filter(|k| !k.is_sep()).collect();
    let all: Vec<&SigningKey> = keys.iter().collect();
    let dnskey_signers = if sep.is_empty() { &all } else { &sep };
    let data_signers = if rest.is_empty() { &all } else { &rest };

    // (owner, type) -> the RDATA of that RRset, in the order they were added.
    let mut rrsets: BTreeMap<(String, u16), (i32, Vec<RecordData>)> = BTreeMap::new();
    for record in signed.records() {
        let name = record.name.to_ascii_lowercase();
        let entry = rrsets
            .entry((name, record.rdata.rtype))
            .or_insert((record.ttl, Vec::new()));
        entry.1.push(record.rdata.clone());
    }

    let mut signatures = Vec::new();
    for ((name, rtype), (ttl, rdatas)) in rrsets {
        let entry = layout.entry(&name);
        if !signable(&entry, &name, rtype, &layout.origin) {
            continue;
        }
        let signers = if rtype == rt::DNSKEY {
            dnskey_signers
        } else {
            data_signers
        };
        let original_ttl = ttl.max(0) as u32;
        let rrset = Rrset::new(&name, rtype, 1, &rdatas);
        for key in signers.iter() {
            let sig = key
                .sign_rrset(&rrset, original_ttl, policy.inception, policy.expiration)
                .with_context(|| format!("signing the {rtype} RRset at {name}"))?;
            signatures.push(ZoneRecord {
                name: name.clone(),
                ttl,
                class: 1,
                rdata: RecordData::from_parsed(&ParsedRecord::RRSIG {
                    type_covered: sig.type_covered,
                    algorithm: sig.algorithm,
                    labels: sig.labels,
                    original_ttl: sig.original_ttl,
                    inception: sig.inception,
                    expiration: sig.expiration,
                    key_tag: sig.key_tag,
                    signer_name: sig.signer_name,
                    signature: sig.signature,
                })
                .context("encoding an RRSIG")?,
            });
        }
    }

    for signature in signatures {
        signed.add_record(signature);
    }
    Ok(())
}

/// Whether this RRset is one the zone is authoritative for, and so must sign.
fn signable(entry: &NameEntry, name: &str, rtype: u16, origin: &str) -> bool {
    if rtype == rt::RRSIG {
        // A signature over a signature says nothing: a validator checks an
        // RRSIG against a key, never against another RRSIG.
        return false;
    }
    if entry.occluded {
        return false;
    }
    // NSEC3 records live at names invented by the hash, which are in no
    // delegation and have no entry of their own — they are always ours to sign.
    if rtype == rt::NSEC3 {
        return true;
    }
    if entry.is_delegation && name != origin {
        // The zone's authority ends here: the NS RRset belongs to the child and
        // the glue is a hint. What is left is the DS, which is this zone's own
        // statement about the child, and the NSEC that can deny it.
        return matches!(rtype, rt::DS | rt::NSEC);
    }
    true
}

fn dnskey_rdata(key: &Dnskey) -> RecordData {
    RecordData {
        rtype: rt::DNSKEY,
        rdata: key.rdata().into_boxed_slice(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::{
        dnskeys_in, rrsigs_in, verify_rrset, Ds, RrsetProof, DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE,
    };
    use crate::dnssec_denial::{
        nsec3s_in, nsecs_in, proves_no_ds, proves_nodata, proves_nxdomain,
        proves_wildcard_expansion, Denial, Nsec, Nsec3, WildcardVerdict,
    };
    use crate::dnssec_key::{SigningAlgorithm, SigningKey};
    use crate::zone::parse_zone_file;
    use crate::ResourceRecord;

    const NOW: u64 = 1_700_000_000;
    const ORIGIN: &str = "example.com.";

    /// One of everything the signer has to treat differently: an apex,
    /// ordinary names, a wildcard, an empty non-terminal two deep, a secure
    /// delegation, an insecure one, and glue below both.
    const ZONE: &str = r#"$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1.example.com. admin.example.com. ( 2024051300 3600 600 604800 300 )
@       IN NS  ns1.example.com.
@       IN NS  ns2.example.com.
ns1     IN A   192.0.2.1
ns2     IN A   192.0.2.2
www     IN A   192.0.2.10
www     IN A   192.0.2.11
www     IN AAAA 2001:db8::10
mail    IN MX  10 mail.example.com.
mail    IN A   192.0.2.20
*       IN A   192.0.2.99
deep.a.b IN TXT "down here"
secure  IN NS  ns.secure.example.com.
secure  IN DS  12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns.secure IN A 192.0.2.30
plain   IN NS  ns.plain.example.com.
ns.plain IN A  192.0.2.40
"#;

    fn keys() -> Vec<SigningKey> {
        vec![
            SigningKey::generate(
                SigningAlgorithm::EcdsaP256Sha256,
                ORIGIN,
                DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
            )
            .unwrap(),
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                .unwrap(),
        ]
    }

    fn policy(chain: DenialChain) -> SigningPolicy {
        SigningPolicy::valid_for(NOW, 30 * 86_400).with_chain(chain)
    }

    fn sign_test_zone(chain: DenialChain) -> Zone {
        let zone = parse_zone_file(ZONE, ORIGIN).expect("the test zone parses");
        sign_zone(&zone, &keys(), &policy(chain)).expect("signing succeeds")
    }

    fn resources(zone: &Zone) -> Vec<ResourceRecord> {
        zone.records()
            .iter()
            .map(|r| ResourceRecord {
                name: r.name.clone(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.clone(),
            })
            .collect()
    }

    fn published_keys(zone: &Zone) -> Vec<Dnskey> {
        dnskeys_in(&resources(zone))
    }

    fn chain_records(zone: &Zone) -> (Vec<Nsec>, Vec<Nsec3>) {
        let records = resources(zone);
        (nsecs_in(&records), nsec3s_in(&records))
    }

    /// Every RRset in the zone, grouped as the signer groups them.
    fn rrsets(zone: &Zone) -> BTreeMap<(String, u16), Vec<RecordData>> {
        let mut out: BTreeMap<(String, u16), Vec<RecordData>> = BTreeMap::new();
        for record in zone.records() {
            out.entry((record.name.clone(), record.rdata.rtype))
                .or_default()
                .push(record.rdata.clone());
        }
        out
    }

    fn proof_for(zone: &Zone, name: &str, rtype: u16) -> RrsetProof {
        let rdatas: Vec<RecordData> = zone
            .query(name, rtype)
            .iter()
            .map(|r| r.rdata.clone())
            .collect();
        assert!(!rdatas.is_empty(), "no records of type {rtype} at {name}");
        let sigs: Vec<_> = rrsigs_in(&resources(zone))
            .into_iter()
            .filter(|s| s.owner == canonical_name(name))
            .collect();
        verify_rrset(
            &Rrset::new(name, rtype, 1, &rdatas),
            &sigs,
            &published_keys(zone),
            ORIGIN,
            NOW,
        )
    }

    #[test]
    fn every_authoritative_rrset_verifies_against_the_published_keys() {
        let zone = sign_test_zone(DenialChain::Nsec);
        let keys = published_keys(&zone);
        let sigs = rrsigs_in(&resources(&zone));
        let layout = Layout::of(&zone, ORIGIN);

        let mut checked = 0;
        for ((name, rtype), rdatas) in rrsets(&zone) {
            if rtype == rt::RRSIG {
                continue;
            }
            let at_name: Vec<_> = sigs.iter().filter(|s| s.owner == name).cloned().collect();
            let proof = verify_rrset(
                &Rrset::new(&name, rtype, 1, &rdatas),
                &at_name,
                &keys,
                ORIGIN,
                NOW,
            );
            if signable(&layout.entry(&name), &name, rtype, ORIGIN) {
                assert!(
                    matches!(proof, RrsetProof::Verified { .. }),
                    "{name} type {rtype}: {proof:?}"
                );
                checked += 1;
            } else {
                assert!(
                    matches!(proof, RrsetProof::Unsigned),
                    "{name} type {rtype} should carry no signature: {proof:?}"
                );
            }
        }
        // Without this, a signer that emitted nothing at all would pass the
        // loop above by never entering it.
        assert!(checked > 10, "only {checked} signed RRsets");
    }

    #[test]
    fn a_delegation_carries_a_signed_ds_and_an_unsigned_ns() {
        let zone = sign_test_zone(DenialChain::Nsec);
        assert!(matches!(
            proof_for(&zone, "secure.example.com.", rt::DS),
            RrsetProof::Verified { .. }
        ));
        assert!(matches!(
            proof_for(&zone, "secure.example.com.", rt::NS),
            RrsetProof::Unsigned
        ));
        // The apex NS is a different matter: that RRset is the zone's own.
        assert!(matches!(
            proof_for(&zone, ORIGIN, rt::NS),
            RrsetProof::Verified { .. }
        ));
    }

    #[test]
    fn glue_below_a_delegation_is_served_but_neither_signed_nor_chained() {
        let zone = sign_test_zone(DenialChain::Nsec);
        assert!(
            !zone.query("ns.secure.example.com.", rt::A).is_empty(),
            "glue has to still be there to hand out"
        );
        assert!(matches!(
            proof_for(&zone, "ns.secure.example.com.", rt::A),
            RrsetProof::Unsigned
        ));
        assert!(
            zone.query("ns.secure.example.com.", rt::NSEC).is_empty(),
            "an occluded name has no place in the chain"
        );
    }

    #[test]
    fn the_nsec_chain_visits_every_name_once_and_closes() {
        let zone = sign_test_zone(DenialChain::Nsec);
        let (nsecs, _) = chain_records(&zone);

        // A chain with a name missing, duplicated, or pointing somewhere it
        // should not looks like a pile of plausible records until it is walked.
        let apex = canonical_name(ORIGIN);
        let mut seen = vec![apex.clone()];
        let mut at = apex.clone();
        for _ in 0..nsecs.len() {
            let nsec = nsecs
                .iter()
                .find(|n| n.owner == at)
                .unwrap_or_else(|| panic!("no NSEC at {at}"));
            at = nsec.next.clone();
            if at == apex {
                break;
            }
            assert!(!seen.contains(&at), "{at} appears twice in the chain");
            seen.push(at.clone());
        }
        assert_eq!(at, apex, "the chain does not close");
        assert_eq!(seen.len(), nsecs.len());

        assert!(seen.contains(&"a.b.example.com.".to_string()));
        assert!(seen.contains(&"b.example.com.".to_string()));
        assert!(seen.contains(&"*.example.com.".to_string()));
        assert!(!seen.contains(&"ns.secure.example.com.".to_string()));
    }

    #[test]
    fn an_empty_non_terminal_reads_as_nodata_rather_than_nxdomain() {
        // The reason empty non-terminals are in the chain at all.
        // `b.example.com.` holds no records, but it exists — a query for it is
        // NOERROR with nothing in it, and the proof of that has to be a record
        // *at* the name. Left out, the only record available would be one
        // denying the name exists, which is a different answer with a
        // signature on it.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = sign_test_zone(chain.clone());
            let (nsecs, nsec3s) = chain_records(&zone);
            assert!(
                matches!(
                    proves_nodata("b.example.com.", ORIGIN, rt::A, &nsecs, &nsec3s),
                    Denial::Proved
                ),
                "{chain:?}"
            );
            assert!(
                !matches!(
                    proves_nxdomain("b.example.com.", ORIGIN, &nsecs, &nsec3s),
                    Denial::Proved
                ),
                "{chain:?}: a name that exists must not be deniable"
            );
        }
    }

    #[test]
    fn the_chain_proves_a_name_that_is_not_there_is_not_there() {
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = sign_test_zone(chain.clone());
            let (nsecs, nsec3s) = chain_records(&zone);
            // Both are below a name that exists, so the closest encloser is
            // not the apex — the case a chain built only from the names
            // written in the file gets wrong. Neither is reachable by the
            // apex wildcard either, which covers one label and no more
            // (RFC 4592 §2.1.1); a name it *does* cover is not deniable at
            // all, which is what the wildcard test checks from the other side.
            for absent in ["x.a.b.example.com.", "y.deep.a.b.example.com."] {
                let denial = proves_nxdomain(absent, ORIGIN, &nsecs, &nsec3s);
                assert!(
                    matches!(denial, Denial::Proved),
                    "{chain:?} could not deny {absent}: {denial:?}"
                );
            }
        }
    }

    #[test]
    fn the_chain_proves_a_type_that_is_not_there_is_not_there() {
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = sign_test_zone(chain.clone());
            let (nsecs, nsec3s) = chain_records(&zone);
            assert!(
                matches!(
                    proves_nodata("www.example.com.", ORIGIN, rt::MX, &nsecs, &nsec3s),
                    Denial::Proved
                ),
                "{chain:?}"
            );
            // And a type that *is* there is not deniable, which is the same
            // bitmap read the other way.
            assert!(
                !matches!(
                    proves_nodata("www.example.com.", ORIGIN, rt::AAAA, &nsecs, &nsec3s),
                    Denial::Proved
                ),
                "{chain:?}"
            );
        }
    }

    #[test]
    fn a_wildcards_signature_carries_to_the_names_it_expands_to() {
        let zone = sign_test_zone(DenialChain::Nsec);
        let rdatas: Vec<RecordData> = zone
            .query("*.example.com.", rt::A)
            .iter()
            .map(|r| r.rdata.clone())
            .collect();
        let sigs: Vec<_> = rrsigs_in(&resources(&zone))
            .into_iter()
            .filter(|s| s.owner == "*.example.com." && s.type_covered == rt::A)
            .collect();
        assert_eq!(sigs.len(), 1);

        // Re-owned onto the name a server would answer with, exactly as the
        // serving path does it, the signature still verifies — and comes back
        // flagged as an expansion, which is what obliges the answer to carry a
        // denial of the queried name.
        let mut expanded = sigs[0].clone();
        expanded.owner = "anything.example.com.".to_string();
        let proof = verify_rrset(
            &Rrset::new("anything.example.com.", rt::A, 1, &rdatas),
            &[expanded],
            &published_keys(&zone),
            ORIGIN,
            NOW,
        );
        let RrsetProof::Verified {
            wildcard: Some(wildcard),
            ..
        } = proof
        else {
            panic!("expected a wildcard expansion: {proof:?}");
        };
        assert_eq!(wildcard, "*.example.com.");

        // The other half: the chain has to show the queried name has nothing of
        // its own and that this is the wildcard covering it.
        let (nsecs, nsec3s) = chain_records(&zone);
        assert!(matches!(
            proves_wildcard_expansion("anything.example.com.", &wildcard, &nsecs, &nsec3s),
            WildcardVerdict::Proved
        ));
    }

    #[test]
    fn nsec3_publishes_the_parameters_its_chain_was_built_with() {
        let salt = vec![0xde, 0xad, 0xbe, 0xef];
        let zone = sign_test_zone(DenialChain::Nsec3 {
            salt: salt.clone(),
            iterations: 5,
            opt_out: false,
        });
        let params = zone.query(ORIGIN, rt::NSEC3PARAM);
        assert_eq!(params.len(), 1, "one NSEC3PARAM at the apex");
        // Hash 1, flags 0, five iterations, a four-byte salt.
        assert_eq!(
            params[0].rdata.rdata.as_ref(),
            &[1, 0, 0, 5, 4, 0xde, 0xad, 0xbe, 0xef]
        );

        for nsec3 in nsec3s_in(&resources(&zone)) {
            assert_eq!(nsec3.salt, salt);
            assert_eq!(nsec3.iterations, 5);
        }
    }

    #[test]
    fn opt_out_drops_insecure_delegations_and_says_so_in_the_flag() {
        let zone = sign_test_zone(DenialChain::Nsec3 {
            salt: Vec::new(),
            iterations: 0,
            opt_out: true,
        });
        let (_, nsec3s) = chain_records(&zone);
        assert!(nsec3s.iter().all(|n| n.opt_out()));

        let matched = |name: &str| {
            nsec3s
                .iter()
                .any(|n| n.matches(name).unwrap_or(false))
        };
        // No DS, so opt-out leaves it out: nothing matches its hash.
        assert!(
            !matched("plain.example.com."),
            "an opted-out delegation must not be in the chain"
        );
        // The secure one stays, because its DS is a statement this zone signs.
        assert!(
            matched("secure.example.com."),
            "a secure delegation is always in the chain"
        );
    }

    #[test]
    fn without_opt_out_an_insecure_delegation_is_chained_so_its_ds_can_be_denied() {
        // The whole point of chaining a delegation: "is there a DS here" has to
        // be answerable with a proof, or a validator cannot tell an unsigned
        // child from one whose DS was stripped in transit.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = sign_test_zone(chain.clone());
            let (nsecs, nsec3s) = chain_records(&zone);
            let denial = proves_no_ds("plain.example.com.", &nsecs, &nsec3s);
            assert!(matches!(denial, Denial::Proved), "{chain:?}: {denial:?}");
        }
    }

    #[test]
    fn the_ksk_signs_the_keys_and_the_zsk_signs_the_data() {
        let keys = keys();
        let ksk = keys[0].key_tag();
        let zsk = keys[1].key_tag();
        let zone = sign_zone(
            &parse_zone_file(ZONE, ORIGIN).unwrap(),
            &keys,
            &policy(DenialChain::Nsec),
        )
        .unwrap();

        let sigs = rrsigs_in(&resources(&zone));
        let tags = |name: &str, rtype: u16| -> Vec<u16> {
            let mut tags: Vec<u16> = sigs
                .iter()
                .filter(|s| s.owner == name && s.type_covered == rtype)
                .map(|s| s.key_tag)
                .collect();
            tags.sort_unstable();
            tags
        };
        assert_eq!(tags(ORIGIN, rt::DNSKEY), vec![ksk]);
        assert_eq!(tags(ORIGIN, rt::SOA), vec![zsk]);
        assert_eq!(tags("www.example.com.", rt::A), vec![zsk]);
    }

    #[test]
    fn one_key_signs_everything_when_that_is_all_there_is() {
        // A combined key is what a small zone usually runs. A signer that
        // reserved the entry-point key for the DNSKEY RRset would produce a
        // zone with no signed data in it at all.
        let key = vec![SigningKey::generate(
            SigningAlgorithm::Ed25519,
            ORIGIN,
            DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
        )
        .unwrap()];
        let zone = sign_zone(
            &parse_zone_file(ZONE, ORIGIN).unwrap(),
            &key,
            &policy(DenialChain::Nsec),
        )
        .unwrap();
        assert!(matches!(
            proof_for(&zone, "www.example.com.", rt::A),
            RrsetProof::Verified { .. }
        ));
        assert!(matches!(
            proof_for(&zone, ORIGIN, rt::DNSKEY),
            RrsetProof::Verified { .. }
        ));
    }

    #[test]
    fn re_signing_replaces_the_previous_run_rather_than_stacking_on_it() {
        // The same keys both times. Signing again with *different* keys keeps
        // the old DNSKEYs on purpose — that is a rollover, not a mistake.
        let keys = keys();
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        let once = sign_zone(&zone, &keys, &policy(DenialChain::Nsec)).unwrap();
        let twice = sign_zone(&once, &keys, &policy(DenialChain::Nsec)).unwrap();

        let count = |z: &Zone, rtype: u16| z.records().iter().filter(|r| r.rdata.rtype == rtype).count();
        assert_eq!(count(&once, rt::NSEC), count(&twice, rt::NSEC));
        assert_eq!(count(&once, rt::RRSIG), count(&twice, rt::RRSIG));
        assert_eq!(count(&once, rt::DNSKEY), count(&twice, rt::DNSKEY));

        // Switching chain type must not leave the old one behind either — that
        // would serve two contradictory denials of the same name.
        let nsec3ed = sign_zone(&once, &keys, &policy(DenialChain::nsec3())).unwrap();
        assert_eq!(count(&nsec3ed, rt::NSEC), 0);
        assert!(count(&nsec3ed, rt::NSEC3) > 0);
    }

    #[test]
    fn a_key_published_at_another_name_is_refused() {
        let wrong = vec![SigningKey::generate(
            SigningAlgorithm::Ed25519,
            "example.net.",
            DNSKEY_FLAG_ZONE,
        )
        .unwrap()];
        let err = sign_zone(
            &parse_zone_file(ZONE, ORIGIN).unwrap(),
            &wrong,
            &policy(DenialChain::Nsec),
        )
        .unwrap_err();
        assert!(err.to_string().contains("example.net."), "{err}");
    }

    #[test]
    fn a_zone_without_an_apex_soa_is_not_a_zone() {
        let mut zone = Zone::new(ORIGIN.to_string());
        zone.add_record(ZoneRecord {
            name: "www.example.com.".to_string(),
            ttl: 3600,
            class: 1,
            rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.1".parse().unwrap())).unwrap(),
        });
        let err = sign_zone(&zone, &keys(), &policy(DenialChain::Nsec)).unwrap_err();
        assert!(err.to_string().contains("SOA"), "{err}");
    }

    #[test]
    fn an_rrset_whose_records_disagree_on_ttl_is_signed_at_the_smallest() {
        // RFC 2181 §5.2 says they must not disagree; a zone file can still say
        // so. A signature covers one TTL, so the records have to be brought to
        // it — otherwise what is served is not what was signed.
        let text = "$ORIGIN example.com.\n$TTL 3600\n\
                    @ IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                    @ IN NS ns1.example.com.\n\
                    ns1 IN A 192.0.2.1\n\
                    www 60 IN A 192.0.2.10\n\
                    www 300 IN A 192.0.2.11\n";
        let zone = sign_zone(
            &parse_zone_file(text, ORIGIN).unwrap(),
            &keys(),
            &policy(DenialChain::Nsec),
        )
        .unwrap();

        for record in zone.query("www.example.com.", rt::A) {
            assert_eq!(record.ttl, 60);
        }
        let sig = rrsigs_in(&resources(&zone))
            .into_iter()
            .find(|s| s.owner == "www.example.com." && s.type_covered == rt::A)
            .expect("the RRset is signed");
        assert_eq!(sig.original_ttl, 60);
        assert!(matches!(
            proof_for(&zone, "www.example.com.", rt::A),
            RrsetProof::Verified { .. }
        ));
    }

    #[test]
    fn the_ds_to_hand_the_parent_digests_the_key_as_published() {
        // The one output that leaves this zone entirely. If it does not digest
        // the DNSKEY as published, the delegation is insecure at best and
        // bogus at worst.
        let keys = keys();
        let zone = sign_zone(
            &parse_zone_file(ZONE, ORIGIN).unwrap(),
            &keys,
            &policy(DenialChain::Nsec),
        )
        .unwrap();
        let ds: Ds = keys[0].ds(2).unwrap();
        let published = published_keys(&zone)
            .into_iter()
            .find(|k| k.key_tag() == ds.key_tag)
            .expect("the entry-point key is published");
        assert!(ds.matches_key(&published).unwrap());
    }

    #[test]
    fn nsec3_iterations_above_the_cap_are_refused_at_signing_time() {
        let err = sign_zone(
            &parse_zone_file(ZONE, ORIGIN).unwrap(),
            &keys(),
            &policy(DenialChain::Nsec3 {
                salt: Vec::new(),
                iterations: MAX_NSEC3_ITERATIONS + 1,
                opt_out: false,
            }),
        )
        .unwrap_err();
        assert!(err.to_string().contains("RFC 9276"), "{err}");
    }
}
