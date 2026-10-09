//! Signing a zone: a DNSKEY RRset, an RRSIG over every authoritative RRset, and
//! a chain that denies everything else.
//!
//! What this produces is read back by [`crate::dnssec`] and
//! [`crate::dnssec_denial`] in the tests — `verify_rrset`, `proves_nxdomain`
//! and `proves_nodata` unmodified, so the output is judged by the same code that
//! judges a real zone rather than by a second opinion written alongside it.
//!
//! Signing happens in memory on load; the file on disk stays the unsigned thing
//! an operator edits. A signer that rewrites its input inherits the "who owns
//! this file" problem, an editor racing a re-signing timer is a way to lose a
//! zone, and what a client validates is what leaves the socket.
//! [`crate::zone_writer`] can spell the signed form out for debugging.
//!
//! A zone's authority stops at a delegation: the NS RRset pointing down is not
//! authoritative data and carries no signature, the glue below it is not in the
//! zone, and the only signed things at a delegation point are the DS and the
//! denial record proving its absence. Signing a delegation's NS RRset is the
//! classic signer bug — validators ignore the signature, and the extra RRSIG
//! shows up in the parent's NSEC bitmap as a type that is not there.

use std::borrow::Cow;

use crate::denial_wire::{build_type_bitmap, canonical_sort_key, CanonicalKey};
use crate::dnssec::{key_tag_of_rdata, Dnskey, Rrset};
use crate::dnssec_denial::{nsec3_hash_name, nsec3_owner_name_at, Nsec3Hash, MAX_NSEC3_ITERATIONS};
use crate::dnssec_key::SigningKey;
use crate::error::DnssecError;
use crate::error::DnssecResult as Result;
use crate::folded_hash::folded_hash;
use crate::record_types as rt;
use crate::zone::{Zone, ZoneRecord, ZoneRecordRef};
use crate::Class;
use crate::Qtype;
use crate::Rtype;
use crate::Serial;
use crate::Ttl;
use crate::{Name, NameRef, ParsedRecord, RecordData, RecordDataRef};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Where the apex DNSKEY RRset's signature comes from.
///
/// [`DnskeySignature::Imported`] is RFC 8901 §2.1.1's Model 1: the owner signs
/// the DNSKEY RRset, so its RRSIG arrives in the zone file and survives
/// signing. Model 2 (§2.1.2) needs only the zone file
/// (`rfc_8901_model_2_needs_only_the_zone_file`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnskeySignature {
    /// Made here, by the SEP keys — or by all of them when no key is a SEP.
    #[default]
    Local,
    /// Kept from the zone file, made by a key this server does not hold.
    Imported,
}

/// How a zone proves that a name is not in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialChain {
    /// NSEC (RFC 4034 §4): each name points at the next in canonical order.
    /// Cheap, and lets anyone walk the zone one query at a time — a disclosure
    /// question, not a security one.
    Nsec,
    /// NSEC3 (RFC 5155): the same chain over hashed names.
    Nsec3 {
        /// RFC 9276 §3.1: empty. A salt is re-hashed with the zone at every
        /// rollover and buys nothing against an attacker who can hash the
        /// guesses they were going to make anyway.
        salt: Vec<u8>,
        /// And zero iterations, for the same reason — the cost lands on the
        /// server and on every validator, not on the attacker.
        iterations: u16,
        /// Opt-out (RFC 5155 §6): leave insecure delegations out of the chain,
        /// so a zone of unsigned children does not pay a record per child. The
        /// cost is that "does not exist" weakens to "does not exist, or is an
        /// insecure delegation I did not list", which is why
        /// [`crate::dnssec_denial`] treats an opt-out span as unjudgeable.
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
                return Err(DnssecError::signing(format!(
                    "an NSEC3 salt is a length-prefixed byte string and cannot exceed 255 bytes, \
                     this one is {}",
                    salt.len(),
                )));
            }
            if *iterations > MAX_NSEC3_ITERATIONS {
                // Verification is capped at the RFC 9276 limit, so signing
                // above it produces a zone we could not read ourselves.
                return Err(DnssecError::signing(format!(
                    "{iterations} NSEC3 iterations exceeds the {MAX_NSEC3_ITERATIONS} \
                     RFC 9276 permits",
                )));
            }
        }
        Ok(())
    }
}

/// How much of the validity window signature expiry is spread across.
///
/// One expiration for the whole zone means every validating resolver SERVFAILs
/// the entire zone in the same second. Spreading turns that cliff into a slope,
/// as BIND does. A fifth is the compromise: wider shortens the effective life of
/// the earliest signatures, narrower steepens the slope.
const EXPIRY_JITTER_FRACTION: u64 = 5;

/// The fraction of the validity window after which a zone wants re-signing.
///
/// A third, so a failed run or a server down over one still has two attempts
/// before anything expires. BIND uses a quarter for the same reason.
const RESIGN_FRACTION: u64 = 3;

/// How long after signing a zone wants signing again, in seconds.
///
/// The daemon's re-signing timer calls this rather than dividing by three
/// itself: the fraction has to agree with the validity it is a fraction *of*,
/// and a second copy of the number is where that stops being true
/// (`CLAUDE.md` §7).
pub fn resign_after(validity_secs: u64) -> u64 {
    (validity_secs / RESIGN_FRACTION).max(1)
}

/// The choices a signing run makes that are not in the zone or in the keys.
#[derive(Debug, Clone)]
pub struct SigningPolicy {
    /// When the signatures start being valid.
    pub inception: u32,
    /// When they stop — the *latest* expiry in the zone. Individual RRsets
    /// expire earlier, spread back over `EXPIRY_JITTER_FRACTION` of the
    /// window; see `SigningPolicy::expiry_for`.
    pub expiration: u32,
    pub chain: DenialChain,
    /// Where the apex DNSKEY RRset's RRSIG comes from. See
    /// [`DnskeySignature`].
    pub dnskey_signature: DnskeySignature,
    /// Kept so the policy can say when to re-sign and how far to spread expiry.
    validity: u64,
    /// The wall-clock second this run belongs to, which the served SOA serial is
    /// derived from. Not `inception`, which is backdated for clock skew — a
    /// serial from a backdated time steps backwards when the allowance changes.
    signed_at: u64,
}

impl SigningPolicy {
    /// Signatures good for `validity` seconds, starting an hour ago.
    ///
    /// The backdating is not padding: a validator compares the inception against
    /// *its own* clock (RFC 6781 §4.4.2). Without it, a zone published in the
    /// second it was signed is invalid at every client running slightly slow.
    pub fn valid_for(now: u64, validity: u64) -> Self {
        const CLOCK_SKEW_ALLOWANCE: u64 = 3600;
        SigningPolicy {
            inception: now.saturating_sub(CLOCK_SKEW_ALLOWANCE) as u32,
            expiration: now.saturating_add(validity) as u32,
            chain: DenialChain::Nsec,
            dnskey_signature: DnskeySignature::Local,
            validity,
            signed_at: now,
        }
    }

    pub fn with_chain(mut self, chain: DenialChain) -> Self {
        self.chain = chain;
        self
    }

    /// RFC 8901 Model 1: keep the apex DNSKEY RRset's RRSIG from the zone file
    /// and make none here. See [`DnskeySignature`].
    pub fn with_imported_dnskey_rrsig(mut self) -> Self {
        self.dnskey_signature = DnskeySignature::Imported;
        self
    }

    /// The expiry for one RRset's signature: the window's end, pulled back by a
    /// deterministic amount derived from the owner name and type.
    ///
    /// Deterministic, so every reload and every server agrees; never later than
    /// [`Self::expiration`].
    fn expiry_for(&self, name: NameRef<'_>, rtype: Rtype) -> u32 {
        let spread = self.validity / EXPIRY_JITTER_FRACTION;
        if spread == 0 {
            return self.expiration;
        }
        // Over the *wire* octets, so the spread is a function of (owner, type)
        // alone.
        let hash = folded_hash(
            name.as_wire()
                .iter()
                .copied()
                .chain(rtype.to_u16().to_be_bytes()),
        );
        self.expiration
            .saturating_sub((hash % spread) as u32)
            .max(self.inception.saturating_add(1))
    }

    /// The SOA serial to serve for the zone this policy signs.
    /// See [`signed_serial`] for why it is what it is.
    fn serial_for(&self, file_serial: Serial) -> Serial {
        signed_serial(file_serial, self.signed_at)
    }
}

/// The serial to serve for a zone we signed ourselves: the file's serial plus
/// hours since the epoch.
///
/// Re-signing is a new version, or a secondary keeps signatures that expire
/// under it. Time is the counter: monotone with nothing to persist, unlike
/// BIND's and Knot's journals. Added, not `max`ed, so a date-style serial still
/// bumps; hours keep the term small, and the epoch makes it immune to
/// `--signature-validity`.
pub fn signed_serial(file_serial: Serial, signed_at: u64) -> Serial {
    const HOUR: u64 = 3600;
    // RFC 1982 §3.1 defines addition in the sequence space as wrapping, so
    // passing the ceiling is an increment, not the panic a bare `+` would be.
    file_serial.wrapping_add((signed_at / HOUR) as u32)
}

/// Sign `zone` with `keys`, returning the signed zone.
///
/// The same records, TTLs normalized per RRset, plus DNSKEY, RRSIGs and a
/// chain. Previous signer output is dropped first; DNSKEY records are not, as a
/// key published without its private half starts every rollover.
pub fn sign_zone(zone: &Zone, keys: &[SigningKey], policy: &SigningPolicy) -> Result<Zone> {
    Ok(sign_zone_inner(zone, keys, policy, None)?.0)
}

/// The keys that sign at `now`, which is not the keys that are published (RFC
/// 6781 §4.1.1.1): pre-published keys do not sign, retired ones stay published.
/// `pub` so a caller keys its decisions on this exact set (§7).
pub fn active_signing_keys(keys: &[SigningKey], now: u64) -> Vec<&SigningKey> {
    keys.iter().filter(|k| k.is_active(now)).collect()
}

/// Sign `zone`, carrying forward any signature from `previous` that still
/// covers exactly what it covered before.
///
/// For UPDATE: a full re-sign changes every RRSIG, so the IXFR delta is the
/// whole zone. The chain is still built in full, as one new name changes its
/// predecessor's NSEC too (RFC 4034 §4.1.2, RFC 5155 §7.1); only signing is
/// saved.
pub fn sign_zone_incrementally(
    previous: &Zone,
    zone: &Zone,
    keys: &[SigningKey],
    policy: &SigningPolicy,
) -> Result<Resigned> {
    let carried = PreviousSignatures::of(previous);
    let (zone, fresh) = sign_zone_inner(zone, keys, policy, Some(&carried))?;
    Ok(Resigned { zone, fresh })
}

/// An incrementally signed zone, and which of its RRsets this run signed.
///
/// The new signatures are what nothing has checked, and diffing the zones to
/// find them is the O(zone) pass this path avoids. A full [`sign_zone`] does
/// not collect them (`TODO.md` #64e).
pub struct Resigned {
    pub zone: Zone,
    /// The `(owner, type)` pairs whose RRSIGs came out of this run.
    pub fresh: FreshRrsets,
}

/// The RRsets a run signed rather than carried, as [`Resigned::fresh`].
pub type FreshRrsets = Vec<(Name, Rtype)>;

/// The signed zone, and the RRsets this run signed rather than carried — empty
/// unless `previous` was given. See [`Resigned`].
fn sign_zone_inner(
    zone: &Zone,
    keys: &[SigningKey],
    policy: &SigningPolicy,
    previous: Option<&PreviousSignatures>,
) -> Result<(Zone, FreshRrsets)> {
    policy.chain.check()?;
    let origin = zone.origin().to_folded();
    check_keys(keys, origin.as_ref())?;
    if policy.expiration <= policy.inception {
        return Err(DnssecError::signing(format!(
            "a signature that expires at {} cannot have been made at {}",
            policy.expiration, policy.inception,
        )));
    }

    let mut signed = Zone::new(origin.clone());
    let (soa_ttl, minimum) = carry_over_records(zone, origin.as_ref(), policy, &mut signed)?;
    let dnskey_ttl = publish_dnskeys(
        keys,
        origin.as_ref(),
        soa_ttl,
        policy.signed_at,
        &mut signed,
    );
    publish_sync_records(
        keys,
        origin.as_ref(),
        dnskey_ttl,
        policy.signed_at,
        &mut signed,
    )?;

    // Before `Layout::of` snapshots the types: an NSEC3 bitmap lists every type
    // present (RFC 5155 §7.1), NSEC3PARAM included.
    if let DenialChain::Nsec3 {
        salt, iterations, ..
    } = &policy.chain
    {
        signed.add_record(ZoneRecord {
            name: origin.clone(),
            ttl: dnskey_ttl,
            class: Class::IN,
            rdata: nsec3param_rdata(salt, *iterations),
        });
    }

    if policy.dnskey_signature == DnskeySignature::Imported
        && !has_dnskey_rrsig(&signed, origin.as_ref())
    {
        return Err(DnssecError::signing(format!(
            "{origin} is configured for an imported DNSKEY signature (RFC 8901 §2.1.1) and its \
             zone file carries no RRSIG over the apex DNSKEY RRset — signing it here would \
             publish a key set this server cannot vouch for",
        )));
    }

    let layout = Layout::of(&signed, origin.as_ref());

    let denial_ttl = Ttl::negative_answer(soa_ttl, minimum);
    match &policy.chain {
        DenialChain::Nsec => build_nsec_chain(&layout, denial_ttl, &mut signed)?,
        DenialChain::Nsec3 {
            salt,
            iterations,
            opt_out,
        } => build_nsec3_chain(
            &layout,
            salt,
            *iterations,
            *opt_out,
            denial_ttl,
            &mut signed,
        )?,
    }

    let fresh = sign_everything(&layout, keys, policy, previous, &mut signed)?;
    Ok((signed, fresh))
}

/// A previous signed version of a zone, indexed so that an RRset which has not
/// moved can keep the signature it already had.
///
/// Both the RRsets and the signatures: a name that merely still exists would
/// keep a signature over data it no longer holds. Borrowed from `previous`, not
/// copied (`TODO.md` #64e).
struct PreviousSignatures<'a> {
    /// folded owner -> type -> the RRset as it was signed: its TTL, and its
    /// RDATA in the order the previous run saw them.
    rrsets: ByName<'a, SignedRrset<'a>>,
    /// folded owner -> covered type -> the signatures over that RRset.
    signatures: ByName<'a, Vec<CarriedSignature<'a>>>,
}

/// Something held per (owner, type), nested so the outer map is probed with a
/// folded name through `Borrow<[u8]>` rather than with a key built per probe.
type ByName<'a, V> = BTreeMap<Cow<'a, [u8]>, Vec<(Rtype, V)>>;

/// An RRset as the previous run signed it: its TTL, and its RDATA borrowed from
/// that run's zone.
type SignedRrset<'a> = (Ttl, Vec<RecordDataRef<'a>>);

/// The entry for `rtype` under an owner, or a new empty one.
///
/// A `Vec` scanned rather than a second map: a name holds a handful of types,
/// and the whole point of the nesting is that the outer key is probed through
/// `Borrow<[u8]>` without building one.
fn slot<V: Default>(types: &mut Vec<(Rtype, V)>, rtype: Rtype) -> &mut V {
    if let Some(at) = types.iter().position(|(t, _)| *t == rtype) {
        return &mut types[at].1;
    }
    types.push((rtype, V::default()));
    &mut types.last_mut().expect("just pushed").1
}

/// One RRSIG from the previous run, with the two fields the reuse decision
/// turns on read out once rather than per lookup.
struct CarriedSignature<'a> {
    rdata: RecordDataRef<'a>,
    expiration: u32,
    key_tag: u16,
}

impl<'a> PreviousSignatures<'a> {
    fn of(previous: &'a Zone) -> Self {
        let mut rrsets: ByName<'a, SignedRrset<'a>> = BTreeMap::new();
        let mut signatures: ByName<'a, Vec<CarriedSignature<'a>>> = BTreeMap::new();

        for record in previous.records() {
            // A `Cow`, so a name already folded, as every previous run's is,
            // costs nothing.
            let name = record.name.folded();
            if record.rdata.rtype() == rt::RRSIG {
                // Not offered for reuse; the RRset gets a fresh signature.
                if let Ok(ParsedRecord::RRSIG {
                    type_covered,
                    expiration,
                    key_tag,
                    ..
                }) = record.rdata.parse()
                {
                    slot(signatures.entry(name).or_default(), type_covered).push(
                        CarriedSignature {
                            rdata: record.rdata,
                            expiration,
                            key_tag,
                        },
                    );
                }
                continue;
            }
            let rtype = record.rdata.rtype();
            let rrset = slot(rrsets.entry(name).or_default(), rtype);
            // The TTL of the first record of the RRset, as the previous run
            // normalized it; `reuse` compares it against this run's.
            rrset.0 = record.ttl;
            rrset.1.push(record.rdata);
        }

        PreviousSignatures { rrsets, signatures }
    }

    /// The signatures to carry forward for this RRset, or `None` to sign it
    /// afresh.
    ///
    /// 1. The RRset is identical as a set (RFC 2181 §5): same TTL and RDATA.
    /// 2. It has at least one signature.
    /// 3. The signing key tags are unchanged as a set, and vouched for by
    ///    [`PreviousSignatures::tags_naming`].
    /// 4. No carried signature has expired. Nearness is [`resign_after`]'s, or
    ///    one UPDATE would re-sign every stale RRset.
    fn reuse(
        &self,
        name: NameRef<'_>,
        rtype: Rtype,
        ttl: Ttl,
        rdatas: &[RecordDataRef<'_>],
        key_tags: &[u16],
        signed_at: u64,
    ) -> Option<&[CarriedSignature<'a>]> {
        // One folded key probes both maps (`Cow<[u8]>: Borrow<[u8]>`), so a
        // folded name costs nothing (`TODO.md` #64e).
        let folded = name.folded();
        let (was_ttl, was) = &self
            .rrsets
            .get(folded.as_ref())?
            .iter()
            .find(|(t, _)| *t == rtype)?
            .1;
        if *was_ttl != ttl || was.len() != rdatas.len() {
            return None;
        }
        if !was.iter().all(|r| rdatas.contains(r)) || !rdatas.iter().all(|r| was.contains(r)) {
            return None;
        }

        let carried = &self
            .signatures
            .get(folded.as_ref())?
            .iter()
            .find(|(t, _)| *t == rtype)?
            .1;
        if carried.is_empty() {
            return None;
        }
        if u64::from(carried.iter().map(|s| s.expiration).min()?) <= signed_at {
            return None;
        }

        let mut had: Vec<u16> = carried.iter().map(|s| s.key_tag).collect();
        had.sort_unstable();
        had.dedup();
        let mut want: Vec<u16> = key_tags.to_vec();
        want.sort_unstable();
        want.dedup();
        if had != want {
            return None;
        }

        Some(carried)
    }

    /// The signers' tags, if each names that signer and nothing else in the
    /// previous run's apex DNSKEY RRset; `None` if any does not.
    ///
    /// A carried RRSIG names its key by tag alone, and a tag "is not a unique
    /// identifier" (RFC 4034 Appendix B). A key added or swapped in with an
    /// existing key's tag would read as no change and carry the old signature
    /// alone. Two published keys sharing a tag also refuse, re-signing
    /// everything until one leaves: telling their signatures apart means
    /// verifying each one, and a pair collides once in 65 536.
    fn tags_naming(&self, origin: NameRef<'_>, signers: &[&SigningKey]) -> Option<Vec<u16>> {
        let (_, published) = &self
            .rrsets
            .get(origin.folded().as_ref())?
            .iter()
            .find(|(t, _)| *t == rt::DNSKEY)?
            .1;
        signers
            .iter()
            .map(|key| {
                let tag = key.key_tag();
                let mut same_tag = published
                    .iter()
                    .filter(|r| key_tag_of_rdata(r.bytes()) == tag);
                let only = same_tag.next()?;
                (same_tag.next().is_none() && only.bytes() == key.dnskey().rdata()).then_some(tag)
            })
            .collect()
    }
}

/// The keys must all belong to this zone and at least one must be able to sign
/// its data. Checked before anything is generated, so a run that discovers a key
/// naming another zone has not already produced unusable signatures.
fn check_keys(keys: &[SigningKey], origin: NameRef<'_>) -> Result<()> {
    if keys.is_empty() {
        return Err(DnssecError::signing(format!(
            "no keys to sign {origin} with"
        )));
    }
    for key in keys {
        // `Name` compares with ASCII case folded (RFC 4343), so a zone whose
        // origin is spelled with a capital still matches its key.
        if key.owner() != origin {
            return Err(DnssecError::signing(format!(
                "the key with tag {} is published at {}, not at {origin} — a signature from it \
                 names the wrong signer and verifies against nothing",
                key.key_tag(),
                key.owner(),
            )));
        }
    }
    Ok(())
}

/// Copy everything that is not this signer's own previous output into `signed`,
/// normalizing owner names and per-RRset TTLs. Returns the apex SOA's TTL and
/// its MINIMUM field.
fn carry_over_records(
    zone: &Zone,
    origin: NameRef<'_>,
    policy: &SigningPolicy,
    signed: &mut Zone,
) -> Result<(Ttl, u32)> {
    let mut soa: Option<(Ttl, u32)> = None;
    // An RRset signs with one TTL (RFC 4034 §3.1.3; RFC 2181 §5.2); the
    // smallest wins, so no record outlives its own TTL.
    let mut ttls: HashMap<(Name, Rtype), Ttl> = HashMap::new();
    let mut carried: Vec<ZoneRecord> = Vec::new();

    for record in zone.records() {
        if is_signer_output(record.rdata.rtype())
            && !is_imported_dnskey_rrsig(record, origin, policy)
        {
            continue;
        }
        if record.class != Class::IN {
            return Err(DnssecError::signing(format!(
                "{} carries class {}, and DNSSEC is defined per class — a zone mixing them has \
                 no single chain to sign",
                record.name, record.class,
            )));
        }
        let name = record.name;
        if !name.is_at_or_under(origin) {
            return Err(DnssecError::signing(format!(
                "{name} is not in {origin}, so this zone has no authority to sign it",
            )));
        }
        let mut record = record.to_owned();
        if record.rdata.rtype() == rt::SOA && name == origin {
            let ParsedRecord::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } = record.rdata.parse()?
            else {
                return Err(DnssecError::signing(
                    "the apex SOA does not parse as an SOA",
                ));
            };
            soa = Some((record.ttl, minimum));
            // The served serial is not the file's — see `signed_serial`.
            record.rdata = RecordData::from_parsed(&ParsedRecord::SOA {
                mname,
                rname,
                serial: policy.serial_for(serial),
                refresh,
                retry,
                expire,
                minimum,
            })
            .map_err(|e| DnssecError::signing(format!("re-encoding the apex SOA: {e}")))?;
        }
        let key = (name.to_owned(), record.rdata.rtype());
        ttls.entry(key)
            .and_modify(|t| *t = (*t).min(record.ttl))
            .or_insert(record.ttl);
        carried.push(record);
    }

    for mut record in carried {
        record.ttl = ttls[&(record.name.clone(), record.rdata.rtype())];
        signed.add_record(record);
    }

    soa.ok_or_else(|| {
        DnssecError::signing(format!(
            "{origin} has no SOA at its apex, so there is no zone here to sign",
        ))
    })
}

/// Records this signer generates, and therefore replaces rather than preserves.
fn is_signer_output(rtype: Rtype) -> bool {
    matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3 | rt::NSEC3PARAM)
}

/// The one RRSIG a signing run may carry through rather than replace: the apex
/// DNSKEY RRset's, under [`DnskeySignature::Imported`].
///
/// Narrow on purpose. Model 1 hands a provider exactly one signature it did not
/// make, and every other RRSIG in the file is this signer's own stale output —
/// keeping those is how a zone comes to publish two generations of signature
/// over the same RRset.
fn is_imported_dnskey_rrsig(
    record: ZoneRecordRef<'_>,
    origin: NameRef<'_>,
    policy: &SigningPolicy,
) -> bool {
    policy.dnskey_signature == DnskeySignature::Imported
        && record.rdata.rtype() == rt::RRSIG
        && record.name == origin
        && matches!(
            record.rdata.parse(),
            Ok(ParsedRecord::RRSIG { type_covered, .. }) if type_covered == rt::DNSKEY
        )
}

/// Whether `zone` holds an RRSIG over the apex DNSKEY RRset.
fn has_dnskey_rrsig(zone: &Zone, origin: NameRef<'_>) -> bool {
    zone.query(origin, Qtype::of(rt::RRSIG)).iter().any(|r| {
        matches!(
            r.rdata.parse(),
            Ok(ParsedRecord::RRSIG { type_covered, .. }) if type_covered == rt::DNSKEY
        )
    })
}

/// The DNSSEC algorithms in `zone`'s apex DNSKEY RRset that no RRSIG in the
/// zone was made with, in the order they first appear.
///
/// RFC 6840 §5.11: each algorithm in the DNSKEY RRset must sign, which binds
/// servers, so no validator will notice. RFC 8901 §4 imports and half-done
/// rollovers get here. Reads the signed zone: what was published.
pub fn algorithms_missing_signatures(zone: &Zone) -> Vec<u8> {
    let origin = zone.origin();
    let signed_with: BTreeSet<u8> = zone
        .records()
        .iter()
        .filter_map(|r| match r.rdata.parse() {
            Ok(ParsedRecord::RRSIG { algorithm, .. }) => Some(algorithm),
            _ => None,
        })
        .collect();

    let mut missing = Vec::new();
    for record in zone.query(origin, Qtype::of(rt::DNSKEY)) {
        let Ok(ParsedRecord::DNSKEY {
            rtype: _,
            flags,
            algorithm,
            ..
        }) = record.rdata.parse()
        else {
            continue;
        };
        // A key with the Zone Key bit clear signs nothing by definition
        // (RFC 4034 §2.1.1), so its algorithm is not one the zone owes.
        if flags & crate::dnssec::DNSKEY_FLAG_ZONE == 0 {
            continue;
        }
        if !signed_with.contains(&algorithm) && !missing.contains(&algorithm) {
            missing.push(algorithm);
        }
    }
    missing
}

/// Publish the DNSKEY for every key, returning the TTL the RRset ended up with.
///
/// A key already in the zone with identical RDATA is left alone rather than
/// duplicated: an RRset holding one twice is one a validator must de-duplicate
/// before it can verify anything.
fn publish_dnskeys(
    keys: &[SigningKey],
    origin: NameRef<'_>,
    soa_ttl: Ttl,
    now: u64,
    signed: &mut Zone,
) -> Ttl {
    let published = signed.query(origin, Qtype::of(rt::DNSKEY));
    let existing: Vec<RecordData> = published.iter().map(|r| r.rdata.to_owned()).collect();
    // An RRset has one TTL: keys already published set it, since changing it
    // would be changing records the operator put there.
    let ttl = published.first().map_or(soa_ttl, |r| r.ttl);

    for key in keys {
        // Before `Publish` or past `Delete`: loaded, not published (RFC 6781
        // §4.1.1.1).
        if !key.is_published(now) {
            continue;
        }
        let rdata = dnskey_rdata(&key.dnskey());
        if existing.contains(&rdata) {
            continue;
        }
        signed.add_record(ZoneRecord {
            name: origin.to_owned(),
            ttl,
            class: Class::IN,
            rdata,
        });
    }
    ttl
}

/// Ask the parent to publish a DS for every key inside its sync window (RFC
/// 7344): a CDS and a CDNSKEY per key, at the apex (§4.1).
///
/// The window is `SyncPublish`/`SyncDelete`, not the rollover schedule: asking
/// a registrar to act is a deliberate step. SHA-256 only (RFC 8624 §3.3). RFC
/// 8078 §4's "delete" CDS is never produced; an operator writes it in the zone
/// file (`TODO.md` #55).
fn publish_sync_records(
    keys: &[SigningKey],
    origin: NameRef<'_>,
    ttl: Ttl,
    now: u64,
    signed: &mut Zone,
) -> Result<()> {
    /// RFC 8624 §3.3's only MUST for a DS digest.
    const SHA256: u8 = 2;

    let existing: Vec<RecordData> = signed
        .query(origin, Qtype::of(rt::CDS))
        .iter()
        .chain(signed.query(origin, Qtype::of(rt::CDNSKEY)).iter())
        .map(|r| r.rdata.to_owned())
        .collect();

    let wanted: Vec<&SigningKey> = keys
        .iter()
        .filter(|k| k.timing().is_sync_published(now))
        .collect();
    if wanted.is_empty() {
        return Ok(());
    }

    // RFC 8078 §4's algorithm 0 says "go insecure"; with a DS request beside it
    // the parent picks, so fail the run (`CLAUDE.md` §4).
    if existing.iter().any(|rdata| is_go_insecure(rdata.as_ref())) {
        return Err(DnssecError::signing(format!(
            "{origin} carries a CDS or CDNSKEY with algorithm 0, which asks the parent to \
             withdraw the DS (RFC 8078 §4), and {} key(s) are inside a SyncPublish window \
             asking it to publish one",
            wanted.len(),
        )));
    }

    for key in wanted {
        let ds = key.ds(SHA256)?;
        let dnskey = key.dnskey();
        for rdata in [
            RecordData::from_parsed(&ParsedRecord::DS {
                rtype: rt::CDS,
                key_tag: ds.key_tag,
                algorithm: ds.algorithm,
                digest_type: ds.digest_type,
                digest: ds.digest.clone(),
            })?,
            RecordData::from_parsed(&ParsedRecord::DNSKEY {
                rtype: rt::CDNSKEY,
                flags: dnskey.flags,
                protocol: dnskey.protocol,
                algorithm: dnskey.algorithm,
                public_key: dnskey.public_key.clone(),
            })?,
        ] {
            // An operator who wrote the record by hand keeps theirs, the way a
            // hand-written DNSKEY is kept.
            if existing.contains(&rdata) {
                continue;
            }
            signed.add_record(ZoneRecord {
                name: origin.to_owned(),
                ttl,
                class: Class::IN,
                rdata,
            });
        }
    }
    Ok(())
}

/// RFC 8078 §4's "delete" signal: algorithm 0 in a CDS or CDNSKEY.
///
/// Read off the RDATA rather than the parsed record, because the two types put
/// the algorithm in different places — a CDS is DS-shaped (key tag, algorithm,
/// digest type, digest) and a CDNSKEY is DNSKEY-shaped (flags, protocol,
/// algorithm, key), so the offset is 2 in one and 3 in the other.
fn is_go_insecure(rdata: RecordDataRef<'_>) -> bool {
    let at = match rdata.rtype() {
        rt::CDS => 2,
        rt::CDNSKEY => 3,
        _ => return false,
    };
    rdata.bytes().get(at) == Some(&0)
}

// What is where: delegations, occlusion, and the names that need a denial

/// One owner name, as the signer sees it.
#[derive(Debug, Default, Clone)]
struct NameEntry {
    /// The types with records at this name, whether or not they are signed.
    types: BTreeSet<Rtype>,
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
    /// At a delegation this is not "the types here": glue is not authoritative
    /// data, so an A record at the delegation point is invisible to the chain
    /// even though the server hands it out as a hint.
    fn published_types(&self) -> BTreeSet<Rtype> {
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
///
/// Keyed by [`canonical_sort_key`], so the map is already in the RFC 4034 §6.1
/// order the chain needs and `chain_names` does not sort again. The name itself
/// rides in the value: a `Name` has no `Ord`, on purpose — wire order is not
/// canonical order, and a type that sorted would be an invitation to use the
/// wrong one.
struct Layout {
    origin: Name,
    names: BTreeMap<CanonicalKey, (Name, NameEntry)>,
}

impl Layout {
    fn of(zone: &Zone, origin: NameRef<'_>) -> Self {
        let mut names: BTreeMap<CanonicalKey, (Name, NameEntry)> = BTreeMap::new();
        for record in zone.records() {
            let key = canonical_sort_key(record.name);
            let entry = names
                .entry(key)
                .or_insert_with(|| (record.name.to_folded(), NameEntry::default()));
            entry.1.types.insert(record.rdata.rtype());
        }
        for (name, entry) in names.values_mut() {
            entry.is_delegation = name.as_ref() != origin && entry.types.contains(&rt::NS);
        }

        // Occluded (RFC 2136 §7.18): below a delegation (RFC 4035 §2.2) or
        // below a DNAME owner (RFC 6672 §2.4), not the owner (§2.3, §5.3.2).
        let occluders: BTreeSet<CanonicalKey> = names
            .values()
            .filter(|(_, e)| e.is_delegation || e.types.contains(&rt::DNAME))
            .map(|(n, _)| canonical_sort_key(n.as_ref()))
            .collect();
        for (name, entry) in names.values_mut() {
            entry.occluded = name
                .as_ref()
                .ancestors()
                .skip(1)
                .any(|ancestor| occluders.contains(&canonical_sort_key(ancestor)));
        }

        Layout {
            origin: origin.to_folded(),
            names,
        }
    }

    /// The names a denial chain must cover, in canonical order.
    ///
    /// Beyond the obvious: delegation points, because the proof that a child is
    /// *not* signed is an authenticated denial of its DS; and empty
    /// non-terminals, because such a name exists and a query for it is NODATA,
    /// so without a record there the only available proof would deny a name that
    /// exists. Under opt-out, neither insecure delegations nor the empty
    /// non-terminals that exist only to hold them.
    fn chain_names(&self, opt_out: bool) -> Vec<Name> {
        let mut included: BTreeMap<CanonicalKey, Name> = self
            .names
            .iter()
            .filter(|(_, (_, e))| !e.occluded)
            .filter(|(_, (_, e))| !(opt_out && e.is_delegation && !e.is_secure_delegation()))
            .map(|(k, (n, _))| (k.clone(), n.clone()))
            .collect();

        let mut empty_non_terminals: BTreeMap<CanonicalKey, Name> = BTreeMap::new();
        for name in included.values() {
            // `skip(1)`: strict ancestors. The walk stops at the origin, which
            // is in the chain already.
            for ancestor in name.as_ref().ancestors().skip(1) {
                if ancestor == self.origin.as_ref()
                    || !ancestor.is_at_or_under(self.origin.as_ref())
                {
                    break;
                }
                let key = canonical_sort_key(ancestor);
                if !included.contains_key(&key) {
                    empty_non_terminals.insert(key, ancestor.to_owned());
                }
            }
        }
        included.extend(empty_non_terminals);

        // Already in canonical order: that is what the map is keyed by.
        included.into_values().collect()
    }

    /// What is at `name`, for a caller that holds only the name.
    ///
    /// Owned, because it ends in a default for a name the layout does not hold
    /// — an NSEC3 owner, which the hash invented and no record sits at. Costs a
    /// [`canonical_sort_key`] and a `BTreeSet<Rtype>` clone, so a caller that
    /// already has the key and only reads the entry wants [`Layout::at`]
    /// instead (`TODO.md` #64e).
    fn entry(&self, name: NameRef<'_>) -> NameEntry {
        self.at(&canonical_sort_key(name))
            .cloned()
            .unwrap_or_default()
    }

    /// What is at a name the caller already has the key for, borrowed.
    ///
    /// `None` is a name with no records — see [`Layout::entry`] for what that
    /// means and why the other spelling substitutes a default for it.
    fn at(&self, key: &CanonicalKey) -> Option<&NameEntry> {
        self.names.get(key).map(|(_, e)| e)
    }
}

// The denial chains

fn build_nsec_chain(layout: &Layout, ttl: Ttl, signed: &mut Zone) -> Result<()> {
    let names = layout.chain_names(false);
    for (index, name) in names.iter().enumerate() {
        // The last name points back at the apex, closing the loop, so the chain
        // can deny a name sorting after everything in it (RFC 4034 §4.1.1).
        let next = &names[(index + 1) % names.len()];
        let mut types = layout.entry(name.as_ref()).published_types();
        // Every NSEC lists itself and its own signature (RFC 4035 §2.3).
        types.insert(rt::RRSIG);
        types.insert(rt::NSEC);

        let rdata = RecordData::from_parsed(&ParsedRecord::NSEC {
            next_domain_name: next.clone(),
            type_bitmap: build_type_bitmap(&types.into_iter().collect::<Vec<_>>()),
        })
        .map_err(|e| DnssecError::key(format!("encoding an NSEC: {e}")))?;
        signed.add_record(ZoneRecord {
            name: name.clone(),
            ttl,
            class: Class::IN,
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
    ttl: Ttl,
    signed: &mut Zone,
) -> Result<()> {
    let mut hashed: Vec<(Nsec3Hash, Name)> = Vec::new();
    for name in layout.chain_names(opt_out) {
        let hash = nsec3_hash_name(name.as_ref(), salt, iterations)
            .map_err(|e| DnssecError::key(format!("hashing {name} for the NSEC3 chain: {e}")))?;
        hashed.push((hash, name));
    }
    hashed.sort_by_key(|(hash, _)| *hash);

    // Two names hashing alike leaves one undeniable and the other unprovable.
    // It takes a SHA-1 collision, but the check is one comparison.
    if let Some(window) = hashed.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(DnssecError::signing(format!(
            "{} and {} have the same NSEC3 hash — pick a different salt",
            window[0].1, window[1].1,
        )));
    }

    for (index, (hash, name)) in hashed.iter().enumerate() {
        let next = hashed[(index + 1) % hashed.len()].0;
        let entry = layout.entry(name.as_ref());
        let mut types = entry.published_types();
        // Not at the name it describes, so no NSEC3 in its own bitmap; RRSIG
        // only if something there is signed.
        if entry.has_signed_data() {
            types.insert(rt::RRSIG);
        }

        let rdata = RecordData::from_parsed(&ParsedRecord::NSEC3 {
            hash_algorithm: 1,
            flags: u8::from(opt_out),
            iterations,
            salt: salt.to_vec(),
            next_hashed_owner: next.as_bytes().to_vec(),
            type_bitmap: build_type_bitmap(&types.into_iter().collect::<Vec<_>>()),
        })
        .map_err(|e| DnssecError::key(format!("encoding an NSEC3: {e}")))?;
        signed.add_record(ZoneRecord {
            name: nsec3_owner_name_at(*hash, layout.origin.as_ref())
                .map_err(|e| DnssecError::key(format!("an NSEC3 owner name: {e}")))?,
            ttl,
            class: Class::IN,
            rdata,
        });
    }
    Ok(())
}

/// NSEC3PARAM's RDATA (RFC 5155 §4.2): the same first four fields as an NSEC3,
/// and nothing else.
///
/// The flags octet is zero even for an opt-out chain (RFC 5155 §4.1.2): these
/// flags describe the *parameters*, and a server matching this record against
/// the chain compares only salt and iterations.
fn nsec3param_rdata(salt: &[u8], iterations: u16) -> RecordData {
    let mut rdata = Vec::with_capacity(5 + salt.len());
    rdata.push(1); // SHA-1, the only NSEC3 hash there is
    rdata.push(0);
    rdata.extend_from_slice(&iterations.to_be_bytes());
    rdata.push(salt.len() as u8);
    rdata.extend_from_slice(salt);
    RecordData::new(rt::NSEC3PARAM, rdata).expect("an NSEC3PARAM we just built decodes")
}

// The signatures

/// One signing run's RRsets: keyed in canonical order (RFC 4034 §6.1), so the
/// signatures come out in a deterministic order, with the owner carried in the
/// value because a `Name` has no `Ord`.
type Rrsets<'a> = BTreeMap<(CanonicalKey, Rtype), (NameRef<'a>, Ttl, Vec<RecordDataRef<'a>>)>;

/// The RRsets of `signed`, in RFC 4034 §6.1 order.
///
/// A `BTreeMap` on [`canonical_sort_key`], the chain's order. It borrows from
/// `signed`, which saves allocations but not wall time: a clone gave the
/// signing loop locality (`TODO.md` #64g).
fn rrsets_of(signed: &Zone) -> Rrsets<'_> {
    // (owner, type) -> the RDATA of that RRset, in insertion order, borrowed
    // from `signed`.
    let mut rrsets: Rrsets<'_> = BTreeMap::new();
    for record in signed.records() {
        let key = canonical_sort_key(record.name);
        let entry = rrsets
            .entry((key, record.rdata.rtype()))
            .or_insert_with(|| (record.name, record.ttl, Vec::new()));
        entry.2.push(record.rdata);
    }
    rrsets
}

/// An RRSIG for every RRset this zone is authoritative for, reusing a
/// signature from `previous` wherever one still covers exactly what it covered.
///
/// Takes `rrsets` by value: the RDATA in it is what gets signed, and a caller
/// has no use for the map afterwards.
fn signatures_for(
    rrsets: Rrsets<'_>,
    layout: &Layout,
    policy: &SigningPolicy,
    previous: Option<&PreviousSignatures>,
    dnskey_signers: &[&SigningKey],
    data_signers: &[&SigningKey],
) -> Result<(Vec<ZoneRecord>, FreshRrsets)> {
    let mut signatures = Vec::new();
    // Only on the incremental path — see [`Resigned`] for why a full run does
    // not pay for the clones.
    let mut fresh = Vec::new();
    let origin = layout.origin.as_ref();
    let dnskey_tags = previous.and_then(|p| p.tags_naming(origin, dnskey_signers));
    let data_tags = previous.and_then(|p| p.tags_naming(origin, data_signers));
    for ((key, rtype), (name, ttl, rdatas)) in rrsets {
        // The map's own key, rather than `Layout::entry` deriving and cloning
        // it (`TODO.md` #64e).
        if !signable(layout.at(&key), name, rtype, origin) {
            continue;
        }
        let (signers, tags) = if rtype == rt::DNSKEY {
            // Model 1's signature is carried in `signed`; signing again would
            // add one from a key the DS does not name.
            if policy.dnskey_signature == DnskeySignature::Imported {
                continue;
            }
            (dnskey_signers, &dnskey_tags)
        } else if rtype == rt::CDS || rtype == rt::CDNSKEY {
            // RFC 7344 §4.1: signed "with a key" in both DNSKEY and DS, the SEP
            // keys; every check here would pass a ZSK signature.
            (dnskey_signers, &dnskey_tags)
        } else {
            (data_signers, &data_tags)
        };

        // The whole of the incremental path: not re-signed, so the RDATA does
        // not move, so it does not appear in the next IXFR delta.
        if let (Some(previous), Some(tags)) = (previous, tags) {
            if let Some(carried) = previous.reuse(name, rtype, ttl, &rdatas, tags, policy.signed_at)
            {
                for signature in carried {
                    signatures.push(ZoneRecord {
                        name: name.to_owned(),
                        ttl,
                        class: Class::IN,
                        rdata: signature.rdata.to_owned(),
                    });
                }
                continue;
            }
        }

        if previous.is_some() {
            fresh.push((name.to_owned(), rtype));
        }
        let original_ttl = ttl.as_secs();
        let rrset = Rrset::new(name, rtype, Class::IN, &rdatas);
        // Spread back from the window's end so the zone degrades over a slope
        // rather than one cliff — see `SigningPolicy::expiry_for`.
        let expiration = policy.expiry_for(name, rtype);
        for key in signers.iter() {
            let sig = key
                .sign_rrset(&rrset, original_ttl, policy.inception, expiration)
                .map_err(|e| {
                    DnssecError::key(format!("signing the {rtype} RRset at {name}: {e}"))
                })?;
            signatures.push(ZoneRecord {
                name: name.to_owned(),
                ttl,
                class: Class::IN,
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
                .map_err(|e| DnssecError::key(format!("encoding an RRSIG: {e}")))?,
            });
        }
    }
    Ok((signatures, fresh))
}

/// Three O(zone) passes, and the split is where it is because #64e measured
/// them: assembling the RRsets, signing them, and filing the signatures back
/// into the zone's index.
fn sign_everything(
    layout: &Layout,
    keys: &[SigningKey],
    policy: &SigningPolicy,
    previous: Option<&PreviousSignatures>,
    signed: &mut Zone,
) -> Result<FreshRrsets> {
    // The DS's key signs only DNSKEY and another the data, so the data key
    // rolls without the parent; one key may do both.
    let now = policy.signed_at;
    let active = active_signing_keys(keys, now);
    let sep: Vec<&SigningKey> = active.iter().copied().filter(|k| k.is_sep()).collect();
    let rest: Vec<&SigningKey> = active.iter().copied().filter(|k| !k.is_sep()).collect();
    let all: Vec<&SigningKey> = active.clone();
    let dnskey_signers = if sep.is_empty() { &all } else { &sep };
    let data_signers = if rest.is_empty() { &all } else { &rest };
    if data_signers.is_empty() {
        // No active key: unsigned data under a DNSKEY RRset is bogus, so fail
        // (`CLAUDE.md` §4). Usually a past `Inactive`, no successor.
        return Err(DnssecError::signing(format!(
            "no key is active at {now} to sign {} with — every key this zone has is \
             before its Activate or past its Inactive (RFC 6781 §4.1.1.1)",
            layout.origin,
        )));
    }

    // After the check above, so a zone with no active key fails without paying
    // for a pass it throws away.
    let rrsets = rrsets_of(signed);
    let (signatures, fresh) = signatures_for(
        rrsets,
        layout,
        policy,
        previous,
        dnskey_signers,
        data_signers,
    )?;
    for signature in signatures {
        signed.add_record(signature);
    }
    Ok(fresh)
}

/// Whether this RRset is one the zone is authoritative for, and so must sign.
///
/// `None` is a name the layout does not hold, which is an NSEC3 owner: not in
/// any delegation, not occluded, always ours.
fn signable(
    entry: Option<&NameEntry>,
    name: NameRef<'_>,
    rtype: Rtype,
    origin: NameRef<'_>,
) -> bool {
    if rtype == rt::RRSIG {
        // A validator checks an RRSIG against a key, never another RRSIG.
        return false;
    }
    let Some(entry) = entry else {
        return true;
    };
    if entry.occluded {
        return false;
    }
    // NSEC3 owners are invented by the hash: in no delegation, no entry of
    // their own, always ours to sign.
    if rtype == rt::NSEC3 {
        return true;
    }
    if entry.is_delegation && name != origin {
        // Authority ends at the cut: NS and glue are the child's; the DS and
        // its NSEC are ours.
        return matches!(rtype, rt::DS | rt::NSEC);
    }
    true
}

fn dnskey_rdata(key: &Dnskey) -> RecordData {
    RecordData::new(rt::DNSKEY, key.rdata()).expect("a DNSKEY we just built decodes")
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
    use crate::dnssec_key::{KeyTiming, SigningAlgorithm, SigningKey};
    use crate::dnssec_test_util::{colliding_zsks, signing_keys, signing_policy};
    use crate::test_records::nm;
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
redir   IN DNAME target.example.net.
; One label holding a dot (RFC 1035 §5.1), which the whole module then signs,
; chains and verifies alongside everything else. Not a regression test for the
; ordering — signer and checker share `canonical_sort_key`, so a wrong order is
; a self-consistent one here; that one is in `denial_wire`.
a\.b    IN A   192.0.2.50
"#;

    fn policy(chain: DenialChain) -> SigningPolicy {
        signing_policy(NOW, chain)
    }

    fn sign_test_zone(chain: DenialChain) -> Zone {
        let zone = parse_zone_file(ZONE, ORIGIN).expect("the test zone parses");
        sign_zone(&zone, &signing_keys(ORIGIN), &policy(chain)).expect("signing succeeds")
    }

    // RFC 6781 key rollover, driven by the four moments in a key file.

    /// A key with no timing is published and signing at every instant, which is
    /// every key file that carries no timing fields.
    #[test]
    fn a_key_with_no_timing_is_published_and_active_at_every_instant() {
        let timing = KeyTiming::default();
        for now in [0, 1, NOW, u64::MAX] {
            assert!(timing.is_published(now), "{now}");
            assert!(timing.is_active(now), "{now}");
        }
        assert_eq!(timing.next_change(NOW), None, "nothing is ever scheduled");
    }

    /// RFC 6781 §4.1.1.1's Pre-Publish ZSK rollover, walked through: the
    /// successor is published before it signs, the predecessor stays published
    /// after it stops, and only one of them signs in the middle.
    #[test]
    fn a_pre_publish_zsk_rollover_is_four_moments_and_no_state() {
        let old = KeyTiming {
            inactive: Some(NOW + 200),
            delete: Some(NOW + 300),
            ..KeyTiming::default()
        };
        let new = KeyTiming {
            publish: Some(NOW + 100),
            activate: Some(NOW + 200),
            ..KeyTiming::default()
        };

        // Before anything: the old key alone, doing both jobs.
        assert!(old.is_published(NOW) && old.is_active(NOW));
        assert!(!new.is_published(NOW), "the successor is not visible yet");

        // Pre-publish: both in the DNSKEY RRset, one signing. This window has
        // to outlast the old DNSKEY RRset in every cache.
        assert!(new.is_published(NOW + 150) && !new.is_active(NOW + 150));
        assert!(old.is_active(NOW + 150));

        // The switch: the successor signs, the predecessor stays published so
        // the signatures it made still verify.
        assert!(new.is_active(NOW + 250));
        assert!(old.is_published(NOW + 250) && !old.is_active(NOW + 250));

        // And the withdrawal.
        assert!(!old.is_published(NOW + 350));
        assert!(new.is_active(NOW + 350));
    }

    /// The ordering is refused rather than sorted: each inversion is a
    /// different mistake, and a signer that quietly reordered them would hide
    /// the one the operator made.
    #[test]
    fn timing_that_cannot_happen_in_that_order_is_refused() {
        for (timing, expected) in [
            (
                KeyTiming {
                    publish: Some(200),
                    activate: Some(100),
                    ..KeyTiming::default()
                },
                "Publish is after Activate",
            ),
            (
                KeyTiming {
                    activate: Some(200),
                    inactive: Some(100),
                    ..KeyTiming::default()
                },
                "Activate is after Inactive",
            ),
            (
                KeyTiming {
                    inactive: Some(200),
                    delete: Some(100),
                    ..KeyTiming::default()
                },
                "Inactive is after Delete",
            ),
            (
                KeyTiming {
                    publish: Some(200),
                    delete: Some(100),
                    ..KeyTiming::default()
                },
                "Publish is after Delete",
            ),
        ] {
            let err = timing.check().expect_err("{expected}");
            assert!(err.to_string().contains(expected), "got: {err}");
        }
        // And the one that is legal at every pair: a key that is published,
        // signs, retires and goes.
        assert!(KeyTiming {
            publish: Some(1),
            activate: Some(2),
            inactive: Some(3),
            delete: Some(4),
            ..KeyTiming::default()
        }
        .check()
        .is_ok());
    }

    /// `Activate` before `Publish` is a contradiction rather than a wider
    /// window: a signature from a key the zone does not carry verifies against
    /// nothing. `check` refuses it, and `is_active` would too.
    #[test]
    fn a_key_cannot_sign_before_it_is_published() {
        let timing = KeyTiming {
            publish: Some(NOW + 100),
            ..KeyTiming::default()
        };
        assert!(!timing.is_active(NOW), "not published, so not signing");
        assert!(timing.is_active(NOW + 100));
    }

    /// What the re-signing timer asks: when does anything change next.
    #[test]
    fn the_next_change_is_the_nearest_moment_still_ahead() {
        let timing = KeyTiming {
            publish: Some(100),
            activate: Some(200),
            inactive: Some(300),
            delete: Some(400),
            ..KeyTiming::default()
        };
        assert_eq!(timing.next_change(0), Some(100));
        assert_eq!(timing.next_change(100), Some(200), "exactly on one is past");
        assert_eq!(timing.next_change(250), Some(300));
        assert_eq!(timing.next_change(400), None, "nothing left to wait for");

        // The sync moments too: a CDS due at noon reaches the zone at noon, not
        // at the next tick.
        let syncing = KeyTiming {
            publish: Some(100),
            sync_publish: Some(150),
            sync_delete: Some(350),
            delete: Some(400),
            ..KeyTiming::default()
        };
        assert_eq!(syncing.next_change(100), Some(150));
        assert_eq!(syncing.next_change(150), Some(350));
        assert_eq!(syncing.next_change(350), Some(400));
    }

    /// The whole of it against a real zone: three keys, one instant, and the
    /// zone that comes out. Judged with `verify_rrset`, so the rollover is
    /// checked by the validator rather than by counting records.
    #[test]
    fn the_signer_publishes_and_signs_with_what_the_moment_allows() {
        let ksk = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            ORIGIN,
            DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
        )
        .expect("KSK");
        let retiring =
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                .expect("the ZSK on its way out")
                .with_timing(KeyTiming {
                    inactive: Some(NOW + 200),
                    delete: Some(NOW + 300),
                    ..KeyTiming::default()
                })
                .expect("legal timing");
        let successor =
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                .expect("the ZSK coming in")
                .with_timing(KeyTiming {
                    publish: Some(NOW + 100),
                    activate: Some(NOW + 200),
                    ..KeyTiming::default()
                })
                .expect("legal timing");
        let keys = vec![ksk, retiring, successor];
        let (ksk, retiring, successor) = (&keys[0], &keys[1], &keys[2]);

        let zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        let at = |now: u64| {
            let policy = signing_policy(now, DenialChain::Nsec);
            sign_zone(&zone, &keys, &policy).expect("signs")
        };
        let published = |signed: &Zone| -> BTreeSet<u16> {
            dnskeys_in(&resources(signed))
                .iter()
                .map(|k| k.key_tag())
                .collect()
        };
        let data_signers = |signed: &Zone| -> BTreeSet<u16> {
            rrsigs_in(&resources(signed))
                .iter()
                .filter(|s| s.type_covered == rt::A)
                .map(|s| s.key_tag)
                .collect()
        };

        // Before the successor is published: two keys, the old ZSK signing.
        let early = at(NOW);
        assert_eq!(
            published(&early),
            BTreeSet::from([ksk.key_tag(), retiring.key_tag()])
        );
        assert_eq!(data_signers(&early), BTreeSet::from([retiring.key_tag()]));

        // Pre-publish window: three keys, still one signer. This is the state
        // that has to outlast the old DNSKEY RRset in every cache.
        let waiting = at(NOW + 150);
        assert_eq!(
            published(&waiting),
            BTreeSet::from([ksk.key_tag(), retiring.key_tag(), successor.key_tag()])
        );
        assert_eq!(data_signers(&waiting), BTreeSet::from([retiring.key_tag()]));

        // The switch: still three keys, the successor signing alone.
        let switched = at(NOW + 250);
        assert_eq!(
            published(&switched),
            BTreeSet::from([ksk.key_tag(), retiring.key_tag(), successor.key_tag()])
        );
        assert_eq!(
            data_signers(&switched),
            BTreeSet::from([successor.key_tag()])
        );

        // And after the withdrawal: two keys again, and nothing in the zone
        // refers to the one that went.
        let done = at(NOW + 350);
        assert_eq!(
            published(&done),
            BTreeSet::from([ksk.key_tag(), successor.key_tag()])
        );
        assert_eq!(data_signers(&done), BTreeSet::from([successor.key_tag()]));

        // Every one of the four states is a zone a validator accepts, which is
        // the assertion the tag counting above is only evidence for.
        for (label, signed) in [
            ("before", &early),
            ("pre-publish", &waiting),
            ("switched", &switched),
            ("after", &done),
        ] {
            assert!(
                matches!(
                    proof_for(signed, "www.example.com.", rt::A),
                    RrsetProof::Verified { .. }
                ),
                "{label}"
            );
            assert!(
                matches!(
                    proof_for(signed, ORIGIN, rt::DNSKEY),
                    RrsetProof::Verified { .. }
                ),
                "{label}: the DNSKEY RRset"
            );
        }
    }

    /// RFC 7344, end to end: a key inside its sync window puts a CDS and a
    /// CDNSKEY at the apex, and they go away again when the window closes.
    ///
    /// The two windows are separate on purpose, which is what this asserts
    /// against the alternative the row proposed ("the keys whose `Delete` is
    /// not in the near future"): the key here is published the whole time and
    /// its CDS is not. A rollover step must not ask a registrar to act.
    #[test]
    fn a_key_in_its_sync_window_asks_the_parent_for_a_ds() {
        let ksk = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            ORIGIN,
            DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
        )
        .expect("KSK")
        .with_timing(KeyTiming {
            sync_publish: Some(NOW + 100),
            sync_delete: Some(NOW + 300),
            ..KeyTiming::default()
        })
        .expect("legal timing");
        let zsk = SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
            .expect("ZSK");
        let tag = ksk.key_tag();
        let keys = vec![ksk, zsk];

        let zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        let at = |now: u64| {
            sign_zone(&zone, &keys, &signing_policy(now, DenialChain::Nsec)).expect("signs")
        };
        let count =
            |signed: &Zone, rtype: Rtype| signed.query(nm(ORIGIN).as_ref(), Qtype::of(rtype)).len();

        // Before the window: the key is published and the parent is asked
        // nothing.
        let before = at(NOW);
        assert_eq!(count(&before, rt::CDS), 0);
        assert_eq!(count(&before, rt::CDNSKEY), 0);
        assert_eq!(
            dnskeys_in(&resources(&before)).len(),
            2,
            "both keys are published throughout"
        );

        // Inside it: one of each, naming this key.
        let inside = at(NOW + 200);
        assert_eq!(count(&inside, rt::CDS), 1);
        assert_eq!(count(&inside, rt::CDNSKEY), 1);
        let cds = inside.query(nm(ORIGIN).as_ref(), Qtype::of(rt::CDS))[0]
            .rdata
            .parse()
            .expect("CDS RDATA");
        let ParsedRecord::DS {
            rtype,
            key_tag,
            digest_type,
            ..
        } = cds
        else {
            panic!("a CDS parses as a DS: RFC 7344 §3.1");
        };
        assert_eq!(rtype, rt::CDS, "and knows which of the two codes it is");
        assert_eq!(key_tag, tag, "the KSK the operator scheduled");
        assert_eq!(digest_type, 2, "SHA-256, RFC 8624 §3.3's only MUST");

        // And after: the parent has acted, so the request stops being made. A
        // request left standing is one the parent may act on twice.
        let after = at(NOW + 400);
        assert_eq!(count(&after, rt::CDS), 0);
        assert_eq!(count(&after, rt::CDNSKEY), 0);
        assert_eq!(dnskeys_in(&resources(&after)).len(), 2);

        // Every state verifies, which is the assertion the counting is evidence
        // for.
        for (label, signed) in [("before", &before), ("inside", &inside), ("after", &after)] {
            assert!(
                matches!(
                    proof_for(signed, ORIGIN, rt::DNSKEY),
                    RrsetProof::Verified { .. }
                ),
                "{label}"
            );
        }
        assert!(matches!(
            proof_for(&inside, ORIGIN, rt::CDS),
            RrsetProof::Verified { .. }
        ));
        assert!(matches!(
            proof_for(&inside, ORIGIN, rt::CDNSKEY),
            RrsetProof::Verified { .. }
        ));
    }

    /// The CDS/CDNSKEY RRset is signed by a key the *parent's* DS names, not by
    /// the data key.
    ///
    /// RFC 7344 §4.1: it "MUST be signed with a key that is represented in both
    /// the current DNSKEY and DS RRsets". The ZSK is in the first and not the
    /// second, so signing these as ordinary data publishes a rollover
    /// instruction the parent cannot verify — and nothing downstream would say
    /// so, because the RRset *does* verify against the zone's own keys. That is
    /// why this asserts on the key tag and not on `RrsetProof`.
    #[test]
    fn a_sync_rrset_is_signed_by_the_key_the_parent_knows() {
        let ksk = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            ORIGIN,
            DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
        )
        .expect("KSK")
        .with_timing(KeyTiming {
            sync_publish: Some(NOW),
            ..KeyTiming::default()
        })
        .expect("legal timing");
        let zsk = SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
            .expect("ZSK");
        let (ksk_tag, zsk_tag) = (ksk.key_tag(), zsk.key_tag());
        let keys = vec![ksk, zsk];

        let zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        let signed =
            sign_zone(&zone, &keys, &signing_policy(NOW, DenialChain::Nsec)).expect("signs");
        let signers = |rtype: Rtype| -> BTreeSet<u16> {
            rrsigs_in(&resources(&signed))
                .iter()
                .filter(|s| s.type_covered == rtype)
                .map(|s| s.key_tag)
                .collect()
        };

        assert_eq!(signers(rt::CDS), BTreeSet::from([ksk_tag]));
        assert_eq!(signers(rt::CDNSKEY), BTreeSet::from([ksk_tag]));
        // The control: ordinary data is the ZSK's, which is the whole reason
        // the two are split.
        assert_eq!(signers(rt::A), BTreeSet::from([zsk_tag]));
        assert_eq!(signers(rt::DNSKEY), BTreeSet::from([ksk_tag]));
    }

    /// RFC 8078 §4's "withdraw the DS" record and a SyncPublish window are two
    /// contradictory instructions to one parent.
    ///
    /// The delete signal is never *generated* — no timing field reaches a
    /// DNSSEC-sized footgun — so a zone carrying one got it from an operator
    /// who wrote it by hand, and a run that then adds a request to publish is
    /// asking the parent to choose. Failing the run beats serving both
    /// (`CLAUDE.md` §4).
    #[test]
    fn asking_the_parent_to_publish_and_to_withdraw_at_once_is_a_failed_run() {
        let ksk = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            ORIGIN,
            DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
        )
        .expect("KSK")
        .with_timing(KeyTiming {
            sync_publish: Some(NOW),
            ..KeyTiming::default()
        })
        .expect("legal timing");
        let zsk = SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
            .expect("ZSK");
        let keys = vec![ksk, zsk];

        // Written by hand, which is the only way to get one, and which works
        // because CDS is a name this tree parses (`TODO.md` #55).
        let text = format!("{ZONE}\n@ IN CDS 0 0 0 00\n");
        let zone = parse_zone_file(&text, ORIGIN).expect("parses");
        let err = sign_zone(&zone, &keys, &signing_policy(NOW, DenialChain::Nsec))
            .expect_err("two instructions");
        assert!(err.to_string().contains("algorithm 0"), "{err}");

        // Without the window it is the operator's record and the signer leaves
        // it alone: RFC 8078 §4 is a thing an operator is allowed to mean.
        let no_window = vec![
            SigningKey::generate(
                SigningAlgorithm::EcdsaP256Sha256,
                ORIGIN,
                DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
            )
            .expect("KSK"),
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                .expect("ZSK"),
        ];
        let signed =
            sign_zone(&zone, &no_window, &signing_policy(NOW, DenialChain::Nsec)).expect("signs");
        assert_eq!(
            signed.query(nm(ORIGIN).as_ref(), Qtype::of(rt::CDS)).len(),
            1
        );
        assert!(matches!(
            proof_for(&signed, ORIGIN, rt::CDS),
            RrsetProof::Verified { .. }
        ));
    }

    /// A rollover that was set up and never finished: every key inactive at
    /// once. A DNSKEY RRset promising DNSSEC over data carrying no signature is
    /// bogus at every validator, so the run fails rather than producing it.
    #[test]
    fn a_zone_whose_keys_have_all_retired_is_a_failed_run_not_a_bare_zone() {
        let keys =
            vec![
                SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                    .expect("a ZSK")
                    .with_timing(KeyTiming {
                        inactive: Some(NOW),
                        ..KeyTiming::default()
                    })
                    .expect("legal timing"),
            ];

        let zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        let err = sign_zone(&zone, &keys, &policy(DenialChain::Nsec))
            .expect_err("nothing is left to sign with");
        assert!(err.to_string().contains("no key is active"), "got: {err}");
    }

    // RFC 8901, multi-signer DNSSEC.

    /// Publish a foreign ZSK at the apex and it stays there, vouched for by our
    /// KSK, while our ZSK goes on signing the data.
    ///
    /// The signer does not assume it owns every key in the apex DNSKEY set:
    /// [`publish_dnskeys`] leaves a key it did not put there alone. Model 2
    /// (§2.1.2) is "each provider has their own KSK and ZSK sets" with the
    /// other providers' ZSKs imported, and that is a zone-file edit here
    /// (`CLAUDE.md` §19).
    #[test]
    fn rfc_8901_model_2_needs_only_the_zone_file() {
        let ours = signing_keys(ORIGIN);
        let theirs =
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                .expect("the other provider's ZSK");

        let mut zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        zone.add_record(ZoneRecord {
            name: nm(ORIGIN),
            ttl: Ttl::from_secs(3600),
            class: Class::IN,
            rdata: dnskey_rdata(&theirs.dnskey()),
        });
        let signed = sign_zone(&zone, &ours, &policy(DenialChain::Nsec)).expect("signs");
        let res = resources(&signed);

        let published: BTreeSet<u16> = dnskeys_in(&res).iter().map(|k| k.key_tag()).collect();
        let mut expected: BTreeSet<u16> = ours.iter().map(|k| k.key_tag()).collect();
        expected.insert(theirs.key_tag());
        assert_eq!(published, expected, "all three keys are published");

        // Vouched for by our KSK: §2.1.2's "the DNSKEY RRset is signed
        // independently by each provider using their own KSK".
        let apex_signers: Vec<u16> = rrsigs_in(&res)
            .iter()
            .filter(|sig| sig.type_covered == rt::DNSKEY)
            .map(|sig| sig.key_tag)
            .collect();
        let ksk = ours.iter().find(|k| k.is_sep()).expect("a KSK").key_tag();
        assert_eq!(apex_signers, vec![ksk]);
        assert!(matches!(
            proof_for(&signed, ORIGIN, rt::DNSKEY),
            RrsetProof::Verified { .. }
        ));

        // And the other provider's key signs nothing here, which is the point:
        // we do not hold its private half.
        assert!(
            rrsigs_in(&res)
                .iter()
                .all(|s| s.key_tag != theirs.key_tag()),
            "a key we have no private half of cannot have signed anything"
        );
        assert!(matches!(
            proof_for(&signed, "www.example.com.", rt::A),
            RrsetProof::Verified { .. }
        ));
    }

    /// RFC 8901 §4: providers "need to use a common DNSSEC signing algorithm".
    /// Import a ZSK on an algorithm we hold no key for and the zone is
    /// published one algorithm short of RFC 6840 §5.11's "the zone MUST also be
    /// signed with each algorithm ... present in the DNSKEY RRset" — invisibly,
    /// since §5.11 also tells validators not to check.
    #[test]
    fn an_imported_key_on_an_algorithm_we_cannot_sign_with_is_reported() {
        let ours = signing_keys(ORIGIN);
        let theirs = SigningKey::generate(SigningAlgorithm::Ed25519, ORIGIN, DNSKEY_FLAG_ZONE)
            .expect("the other provider's ZSK, on another algorithm");

        let mut zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        zone.add_record(ZoneRecord {
            name: nm(ORIGIN),
            ttl: Ttl::from_secs(3600),
            class: Class::IN,
            rdata: dnskey_rdata(&theirs.dnskey()),
        });
        let signed = sign_zone(&zone, &ours, &policy(DenialChain::Nsec)).expect("signs");

        assert_eq!(
            algorithms_missing_signatures(&signed),
            vec![theirs.algorithm().code()],
            "Ed25519 is in the DNSKEY RRset and signs nothing"
        );
        // The zone still validates, which is why this is reported rather than
        // refused: §5.11's rule is on the server alone.
        assert!(matches!(
            proof_for(&signed, "www.example.com.", rt::A),
            RrsetProof::Verified { .. }
        ));

        // The same zone with a matching algorithm owes nothing.
        let matched = sign_test_zone(DenialChain::Nsec);
        assert!(algorithms_missing_signatures(&matched).is_empty());
    }

    /// A DNSKEY with the Zone Key bit clear signs nothing by definition
    /// (RFC 4034 §2.1.1), so its algorithm is not one the zone owes a signature
    /// for. Without this the check would fire on any zone publishing one.
    #[test]
    fn a_key_that_is_not_a_zone_key_is_not_an_algorithm_the_zone_owes() {
        let ours = signing_keys(ORIGIN);
        let other =
            SigningKey::generate(SigningAlgorithm::Ed25519, ORIGIN, DNSKEY_FLAG_ZONE).expect("key");
        let mut dnskey = other.dnskey();
        dnskey.flags &= !DNSKEY_FLAG_ZONE;

        let mut zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        zone.add_record(ZoneRecord {
            name: nm(ORIGIN),
            ttl: Ttl::from_secs(3600),
            class: Class::IN,
            rdata: dnskey_rdata(&dnskey),
        });
        let signed = sign_zone(&zone, &ours, &policy(DenialChain::Nsec)).expect("signs");
        assert!(algorithms_missing_signatures(&signed).is_empty());
    }

    /// RFC 8901 §2.1.1, Model 1: the zone owner signs the DNSKEY RRset with a
    /// KSK no provider holds and distributes it. A provider's signing run has
    /// to carry that one signature through and make none of its own.
    #[test]
    fn rfc_8901_model_1_keeps_the_dnskey_rrsig_it_was_given() {
        // The owner's KSK. Nothing but this fixture ever holds its private half.
        let owner_ksk = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            ORIGIN,
            DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
        )
        .expect("the zone owner's KSK");
        let ours =
            vec![
                SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                    .expect("this provider's ZSK, and no KSK"),
            ];
        let theirs =
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                .expect("the other provider's ZSK");

        // What the owner's API hands over: the combined DNSKEY RRset and one
        // RRSIG over it.
        let mut zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        let mut rdatas = Vec::new();
        for key in [&owner_ksk, &ours[0], &theirs] {
            let rdata = dnskey_rdata(&key.dnskey());
            rdatas.push(rdata.clone());
            zone.add_record(ZoneRecord {
                name: nm(ORIGIN),
                ttl: Ttl::from_secs(3600),
                class: Class::IN,
                rdata,
            });
        }
        let run = policy(DenialChain::Nsec);
        let apex = nm(ORIGIN);
        let sig = owner_ksk
            .sign_rrset(
                &Rrset::new(apex.as_ref(), rt::DNSKEY, Class::IN, &rdatas),
                3600,
                run.inception,
                run.expiration,
            )
            .expect("the owner signs the DNSKEY RRset");
        zone.add_record(ZoneRecord {
            name: apex.clone(),
            ttl: Ttl::from_secs(3600),
            class: Class::IN,
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
            .expect("encodes"),
        });

        let signed =
            sign_zone(&zone, &ours, &run.clone().with_imported_dnskey_rrsig()).expect("signs");
        let res = resources(&signed);

        let apex: Vec<u16> = rrsigs_in(&res)
            .iter()
            .filter(|s| s.type_covered == rt::DNSKEY)
            .map(|s| s.key_tag)
            .collect();
        assert_eq!(
            apex,
            vec![owner_ksk.key_tag()],
            "exactly the signature we were given, and no second one"
        );
        assert!(matches!(
            proof_for(&signed, ORIGIN, rt::DNSKEY),
            RrsetProof::Verified { .. }
        ));
        // Our ZSK still signs the data, and the other provider's still does not.
        assert!(matches!(
            proof_for(&signed, "www.example.com.", rt::A),
            RrsetProof::Verified { .. }
        ));
        assert!(rrsigs_in(&res)
            .iter()
            .all(|s| s.key_tag != theirs.key_tag()));
        assert!(algorithms_missing_signatures(&signed).is_empty());
    }

    /// Model 1 with nothing to import. Publishing an unsigned DNSKEY RRset is a
    /// bogus zone at every validator, so this fails the run rather than
    /// producing one (`CLAUDE.md` §4).
    #[test]
    fn model_1_without_the_signature_it_was_promised_is_an_error() {
        let ours =
            vec![
                SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                    .expect("a ZSK"),
            ];
        let zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        let err = sign_zone(
            &zone,
            &ours,
            &policy(DenialChain::Nsec).with_imported_dnskey_rrsig(),
        )
        .expect_err("no imported signature, so no zone");
        assert!(
            err.to_string().contains("imported DNSKEY signature"),
            "got: {err}"
        );
    }

    /// One expiration for the whole zone means every validating resolver
    /// SERVFAILs it in the same second. Spread turns the cliff into a slope.
    #[test]
    fn signature_expiry_is_spread_across_the_zone() {
        let signed = sign_test_zone(DenialChain::Nsec);
        let expiries: BTreeSet<u32> = rrsigs_in(&resources(&signed))
            .iter()
            .map(|sig| sig.expiration)
            .collect();
        assert!(
            expiries.len() > 5,
            "expiry should be spread over the zone, got {} distinct value(s)",
            expiries.len()
        );

        let policy = policy(DenialChain::Nsec);
        let spread = 30 * 86_400 / EXPIRY_JITTER_FRACTION;
        for expiry in &expiries {
            assert!(
                *expiry <= policy.expiration,
                "an operator who asked for 30 days must never get more"
            );
            assert!(
                *expiry > policy.expiration - spread as u32,
                "and never much less: {expiry} is outside the spread"
            );
            assert!(*expiry > policy.inception, "and always after inception");
        }
    }

    /// The slope itself, pinned: the same number as before, which two servers
    /// holding one zone need and a shared hash can silently break. A change
    /// here re-signs every zone, which should have to be typed.
    #[test]
    fn the_spread_is_the_spread_it_was() {
        let policy = policy(DenialChain::Nsec);
        for (name, rtype, offset) in [
            ("example.com.", rt::SOA, 164_892),
            ("www.example.com.", rt::A, 316_449),
            ("www.example.com.", rt::AAAA, 2_418),
            ("mail.example.com.", rt::A, 369_622),
            ("*.example.com.", rt::TXT, 203_755),
            ("a.very.deep.name.example.com.", rt::NS, 41_079),
        ] {
            assert_eq!(
                policy.expiration - policy.expiry_for(nm(name).as_ref(), rtype),
                offset,
                "{name} {rtype:?}"
            );
        }
    }

    /// Deterministic, not random: a reload re-signs, and random jitter would
    /// reshuffle the slope each time, so two servers holding the same zone would
    /// never agree about it.
    #[test]
    fn the_spread_is_deterministic_for_a_given_name_and_type() {
        let policy = policy(DenialChain::Nsec);
        let first = policy.expiry_for(nm("www.example.com.").as_ref(), rt::A);
        assert_eq!(
            first,
            policy.expiry_for(nm("www.example.com.").as_ref(), rt::A)
        );
        assert_ne!(
            first,
            policy.expiry_for(nm("www.example.com.").as_ref(), rt::AAAA),
            "a different type at the same name sits elsewhere on the slope"
        );
        assert_ne!(
            first,
            policy.expiry_for(nm("mail.example.com.").as_ref(), rt::A)
        );
        assert_eq!(
            first,
            policy.expiry_for(nm("WWW.EXAMPLE.COM.").as_ref(), rt::A),
            "case folds, like every other name comparison here (RFC 4343)"
        );
    }

    /// A zone with a validity too short to spread across still signs, rather
    /// than dividing by zero or producing an expiry before inception.
    #[test]
    fn a_validity_too_short_to_spread_still_signs() {
        let policy = SigningPolicy::valid_for(NOW, 2);
        assert_eq!(
            policy.expiry_for(nm("www.example.com.").as_ref(), rt::A),
            policy.expiration
        );
        let zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        let signed = sign_zone(&zone, &signing_keys(ORIGIN), &policy).expect("signs");
        for sig in rrsigs_in(&resources(&signed)) {
            assert!(sig.expiration > sig.inception);
        }
    }

    /// New signatures are a new version of the zone to a secondary, which
    /// decides whether to transfer by comparing serials. The bump must survive a
    /// restart without being persisted, hence the clock.
    #[test]
    fn signing_moves_the_soa_serial_and_keeps_moving_it() {
        let unsigned = parse_zone_file(ZONE, ORIGIN).expect("parses");
        let file_serial = unsigned.serial().expect("the file has a serial");
        assert_eq!(file_serial, Serial::new(2024051300));

        let first =
            sign_zone(&unsigned, &signing_keys(ORIGIN), &policy(DenialChain::Nsec)).expect("signs");
        let first_serial = first.serial().expect("still has one");
        assert_ne!(
            first_serial, file_serial,
            "the served serial is not the file's — new signatures are a new version"
        );

        // Later gives a higher serial, so a secondary transfers; the same moment
        // gives the same one, so a restart is not a change.
        let later = SigningPolicy::valid_for(NOW + 7 * 86_400, 30 * 86_400);
        let later_serial = sign_zone(&unsigned, &signing_keys(ORIGIN), &later)
            .expect("signs")
            .serial()
            .expect("has a serial");
        assert!(
            later_serial.is_newer_than(first_serial),
            "{later_serial} must be newer than {first_serial} by RFC 1982"
        );
        let again = sign_zone(&unsigned, &signing_keys(ORIGIN), &policy(DenialChain::Nsec))
            .expect("signs")
            .serial()
            .expect("has a serial");
        assert_eq!(again, first_serial, "same file, same moment, same serial");
    }

    /// `max(file, time)` would keep a date-style serial forever, since
    /// `2024051300` is far larger than any current Unix timestamp — which is why
    /// PowerDNS's `INCEPTION-EPOCH` requires epoch-based backend serials.
    #[test]
    fn a_date_style_serial_still_moves() {
        let date_style = Serial::new(2_026_073_001);
        let signed = signed_serial(date_style, NOW);
        assert!(
            signed.is_newer_than(date_style),
            "{signed} must be newer than {date_style}"
        );
        // On the numbers: the result is larger, so the time term was added, not
        // `max`ed; a wrapped serial passes `is_newer_than` too.
        assert!(
            signed.to_u32() > date_style.to_u32(),
            "and it is addition, not max — max would have returned the file's number"
        );
        // An operator's own bump still registers as one.
        assert_eq!(
            signed_serial(date_style.wrapping_add(1), NOW),
            signed.wrapping_add(1),
            "editing the file by one moves the served serial by one"
        );
    }

    /// A third of the validity leaves two more chances before anything expires.
    #[test]
    fn re_signing_is_due_well_before_anything_expires() {
        let validity = 30 * 86_400;
        let policy = SigningPolicy::valid_for(NOW, validity);
        let due = u64::from(policy.inception).saturating_add(resign_after(validity));
        assert!(
            due < u64::from(policy.expiration),
            "due at {due}, expires at {}",
            policy.expiration
        );
        let slack = u64::from(policy.expiration) - due;
        assert!(
            slack >= validity / 2,
            "at least half the window should remain when re-signing is due, got {slack}s"
        );
    }

    fn resources(zone: &Zone) -> Vec<ResourceRecord> {
        zone.records()
            .iter()
            .map(|r| ResourceRecord {
                name: r.name.to_owned(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.to_owned(),
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
    fn rrsets(zone: &Zone) -> BTreeMap<(String, Rtype), Vec<RecordData>> {
        let mut out: BTreeMap<(String, Rtype), Vec<RecordData>> = BTreeMap::new();
        for record in zone.records() {
            out.entry((record.name.to_string(), record.rdata.rtype()))
                .or_default()
                .push(record.rdata.to_owned());
        }
        out
    }

    fn proof_for(zone: &Zone, name: &str, rtype: Rtype) -> RrsetProof {
        let rdatas: Vec<RecordData> = zone
            .query(nm(name).as_ref(), Qtype::of(rtype))
            .iter()
            .map(|r| r.rdata.to_owned())
            .collect();
        assert!(!rdatas.is_empty(), "no records of type {rtype} at {name}");
        let sigs: Vec<_> = rrsigs_in(&resources(zone))
            .into_iter()
            .filter(|s| s.owner == nm(name))
            .collect();
        verify_rrset(
            &Rrset::new(nm(name).as_ref(), rtype, Class::IN, &rdatas),
            &sigs,
            &published_keys(zone),
            nm(ORIGIN).as_ref(),
            NOW,
        )
    }

    #[test]
    fn every_authoritative_rrset_verifies_against_the_published_keys() {
        assert_every_rrset_verifies(&sign_test_zone(DenialChain::Nsec));
    }

    /// RSA is imported, never generated. The key goes through the operator's
    /// path — a key file written and read back by `load_dir` — and signs at
    /// algorithm 8 and 10. Fails if `Pair::Rsa` signs PKCS#1 SHA-256 at both
    /// algorithms: the first algorithm-10 RRset checked is bogus.
    #[test]
    fn a_zone_signs_with_an_imported_rsa_key() {
        use crate::dnssec::{DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE};
        for algorithm in [SigningAlgorithm::RsaSha256, SigningAlgorithm::RsaSha512] {
            let dir = crate::testutil::ScratchDir::new("rsa-import");
            SigningKey::from_pkcs8_base64(
                algorithm,
                ORIGIN,
                DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
                crate::dnssec_test_util::RSA_2048_PKCS8,
            )
            .write_to_dir(dir.path())
            .expect("written");
            let keys = SigningKey::load_dir(dir.path()).expect("read back");
            assert_eq!(keys.len(), 1);
            assert_eq!(keys[0].algorithm(), algorithm);

            let zone = parse_zone_file(ZONE, ORIGIN).expect("the test zone parses");
            let signed = sign_zone(&zone, &keys, &policy(DenialChain::Nsec)).expect("signs");
            assert!(rrsigs_in(&resources(&signed))
                .iter()
                .all(|s| s.algorithm == algorithm.code()));
            assert_every_rrset_verifies(&signed);
        }
    }

    fn assert_every_rrset_verifies(zone: &Zone) {
        let keys = published_keys(zone);
        let sigs = rrsigs_in(&resources(zone));
        let layout = Layout::of(zone, nm(ORIGIN).as_ref());

        let mut checked = 0;
        for ((name, rtype), rdatas) in rrsets(zone) {
            if rtype == rt::RRSIG {
                continue;
            }
            let at_name: Vec<_> = sigs
                .iter()
                .filter(|s| s.owner == nm(&name))
                .cloned()
                .collect();
            let proof = verify_rrset(
                &Rrset::new(nm(&name).as_ref(), rtype, Class::IN, &rdatas),
                &at_name,
                &keys,
                nm(ORIGIN).as_ref(),
                NOW,
            );
            if signable(
                layout.at(&canonical_sort_key(nm(&name).as_ref())),
                nm(&name).as_ref(),
                rtype,
                nm(ORIGIN).as_ref(),
            ) {
                // `wildcard: None` everywhere, `*` included: a signer signs
                // existing names; dot-counting would misread `a\.b`.
                assert!(
                    matches!(proof, RrsetProof::Verified { wildcard: None, .. }),
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

    /// RFC 6672 §2.4: a name below a DNAME owner is occluded, as glue below a
    /// cut is (RFC 2136 §7.18), so it is not chained. Built by hand, as
    /// `check_dname_rules` refuses the file; a transfer or UPDATE makes it.
    #[test]
    fn a_name_below_a_dname_is_occluded_from_the_chain() {
        let mut zone = parse_zone_file(ZONE, ORIGIN).expect("the test zone parses");
        zone.add_record(ZoneRecord {
            name: nm("occluded.redir.example.com."),
            ttl: Ttl::from_secs(3600),
            class: crate::Class::IN,
            rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.66".parse().unwrap()))
                .unwrap(),
        });
        let signed = sign_zone(&zone, &signing_keys(ORIGIN), &policy(DenialChain::Nsec))
            .expect("signing succeeds");

        assert!(
            signed
                .query(
                    nm("occluded.redir.example.com.").as_ref(),
                    Qtype::of(rt::NSEC)
                )
                .is_empty(),
            "an occluded name has no place in the chain"
        );
        // The owner is not occluded (§2.3), and its bitmap must list DNAME
        // (§5.3.2).
        let nsecs = signed.query(nm("redir.example.com.").as_ref(), Qtype::of(rt::NSEC));
        assert_eq!(nsecs.len(), 1, "the DNAME owner is still chained");
        let Ok(ParsedRecord::NSEC { type_bitmap, .. }) = nsecs[0].rdata.parse() else {
            panic!("the NSEC parses");
        };
        assert!(
            crate::denial_wire::bitmap_has_type(&type_bitmap, rt::DNAME),
            "§5.3.2: the DNAME bit belongs in the bitmap"
        );
    }

    /// Every denial in the chain is capped at [`Ttl::negative_answer`], both
    /// ways round (RFC 9077 §§3.1-3.3).
    ///
    /// The module's `ZONE` is `$TTL 3600` over `minimum 300`, so it shows one
    /// direction; the second fixture shows the other. Fails with a `denial_ttl`
    /// of MINIMUM alone, and of the SOA TTL alone.
    #[test]
    fn a_denial_is_capped_at_the_lesser_of_the_soa_ttl_and_minimum() {
        const SHORT_SOA_TTL: &str = r#"$ORIGIN example.com.
$TTL 60
@   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 3600 )
@   IN NS  ns1.example.com.
ns1 IN A   192.0.2.1
www IN A   192.0.2.10
"#;
        for (source, origin, expected, which) in [
            (ZONE, ORIGIN, 300, "MINIMUM is the lesser"),
            (SHORT_SOA_TTL, ORIGIN, 60, "the SOA's own TTL is the lesser"),
        ] {
            let zone = parse_zone_file(source, origin).expect("the fixture parses");
            for chain in [
                DenialChain::Nsec,
                DenialChain::Nsec3 {
                    salt: Vec::new(),
                    iterations: 0,
                    opt_out: false,
                },
            ] {
                let signed = sign_zone(&zone, &signing_keys(origin), &policy(chain))
                    .expect("signing succeeds");
                let denials: Vec<_> = signed
                    .records()
                    .iter()
                    .filter(|r| matches!(r.rdata.rtype(), rt::NSEC | rt::NSEC3))
                    .collect();
                assert!(!denials.is_empty(), "{which}: the chain was built");
                for denial in denials {
                    assert_eq!(
                        denial.ttl,
                        Ttl::from_secs(expected),
                        "{which}: {} {}",
                        denial.name,
                        denial.rdata.rtype(),
                    );
                }
            }
        }
    }

    #[test]
    fn glue_below_a_delegation_is_served_but_neither_signed_nor_chained() {
        let zone = sign_test_zone(DenialChain::Nsec);
        assert!(
            !zone
                .query(nm("ns.secure.example.com.").as_ref(), Qtype::of(rt::A))
                .is_empty(),
            "glue has to still be there to hand out"
        );
        assert!(matches!(
            proof_for(&zone, "ns.secure.example.com.", rt::A),
            RrsetProof::Unsigned
        ));
        assert!(
            zone.query(nm("ns.secure.example.com.").as_ref(), Qtype::of(rt::NSEC))
                .is_empty(),
            "an occluded name has no place in the chain"
        );
    }

    #[test]
    fn the_nsec_chain_visits_every_name_once_and_closes() {
        let zone = sign_test_zone(DenialChain::Nsec);
        let (nsecs, _) = chain_records(&zone);

        // A chain with a name missing, duplicated or pointing wrong looks like
        // a pile of plausible records until it is walked.
        let apex = nm(ORIGIN);
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

        assert!(seen.contains(&nm("a.b.example.com.")));
        assert!(seen.contains(&nm("b.example.com.")));
        assert!(seen.contains(&nm("*.example.com.")));
        assert!(!seen.contains(&nm("ns.secure.example.com.")));
    }

    /// Every denial record's bitmap must list every type at the name it
    /// describes (RFC 5155 §7.1, RFC 4034 §4.1.2). Over the whole zone, because
    /// the bug is "a record added after the layout snapshot" and it can happen
    /// at any name — a signed NODATA proof for a record also being served, which
    /// an RFC 8198 resolver then synthesizes for other clients from its cache.
    #[test]
    fn every_bitmap_lists_every_type_at_the_name_it_describes() {
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = sign_test_zone(chain.clone());
            let layout = Layout::of(&zone, nm(ORIGIN).as_ref());
            let (nsecs, nsec3s) = chain_records(&zone);

            for (name, entry) in layout.names.values() {
                if entry.occluded {
                    continue;
                }
                if entry.types.contains(&rt::NSEC3) {
                    // An NSEC3's owner is invented by the hash: not a name of
                    // the zone, and nothing describes it.
                    continue;
                }
                let mut expected = entry.published_types();
                // Under NSEC3 the chain lives at hashed names, so NSEC3 is
                // never in the bitmap, while NSEC always is.
                expected.remove(&rt::NSEC3);

                let lists: Box<dyn Fn(Rtype) -> bool> = match &chain {
                    DenialChain::Nsec => {
                        let Some(nsec) = nsecs.iter().find(|n| n.owner == *name) else {
                            panic!("{chain:?}: no NSEC at {name}");
                        };
                        Box::new(move |rtype| nsec.has_type(rtype))
                    }
                    DenialChain::Nsec3 {
                        salt, iterations, ..
                    } => {
                        let hash = nsec3_hash_name(name.as_ref(), salt, *iterations).unwrap();
                        let owner = nsec3_owner_name_at(hash, nm(ORIGIN).as_ref()).unwrap();
                        let Some(nsec3) = nsec3s.iter().find(|n| n.owner == owner) else {
                            panic!("{chain:?}: no NSEC3 for {name}");
                        };
                        Box::new(move |rtype| nsec3.has_type(rtype))
                    }
                };

                for rtype in expected {
                    assert!(
                        lists(rtype),
                        "{chain:?}: {name} has type {rtype}, and the denial record \
                         describing it does not list it"
                    );
                }
            }
        }
    }

    /// The apex specifically, because NSEC3PARAM is the type that goes missing.
    #[test]
    fn the_apex_nsec3_lists_nsec3param() {
        let zone = sign_test_zone(DenialChain::nsec3());
        assert_eq!(
            zone.query(nm(ORIGIN).as_ref(), Qtype::of(rt::NSEC3PARAM))
                .len(),
            1,
            "an NSEC3-signed zone publishes NSEC3PARAM at its apex (RFC 5155 §4)"
        );

        let (_, nsec3s) = chain_records(&zone);
        let DenialChain::Nsec3 {
            salt, iterations, ..
        } = policy(DenialChain::nsec3()).chain
        else {
            unreachable!()
        };
        let hash = nsec3_hash_name(nm(ORIGIN).as_ref(), &salt, iterations).unwrap();
        let owner = nsec3_owner_name_at(hash, nm(ORIGIN).as_ref()).unwrap();
        let apex = nsec3s
            .iter()
            .find(|n| n.owner == owner)
            .expect("an NSEC3 for the apex");

        for rtype in [rt::SOA, rt::NS, rt::DNSKEY, rt::RRSIG, rt::NSEC3PARAM] {
            assert!(
                apex.has_type(rtype),
                "the apex NSEC3 omits type {rtype}, which is present at the apex"
            );
        }
    }

    #[test]
    fn an_empty_non_terminal_reads_as_nodata_rather_than_nxdomain() {
        // An empty non-terminal exists, so NOERROR, and its proof must be a
        // record at the name; without one only an NXDOMAIN proof is available.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = sign_test_zone(chain.clone());
            let (nsecs, nsec3s) = chain_records(&zone);
            assert!(
                matches!(
                    proves_nodata(
                        nm("b.example.com.").as_ref(),
                        nm(ORIGIN).as_ref(),
                        rt::A,
                        &nsecs,
                        &nsec3s
                    ),
                    Denial::Proved
                ),
                "{chain:?}"
            );
            assert!(
                !matches!(
                    proves_nxdomain(
                        nm("b.example.com.").as_ref(),
                        nm(ORIGIN).as_ref(),
                        &nsecs,
                        &nsec3s
                    ),
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
            // Below an existing name, so the closest encloser is not the apex,
            // and no apex wildcard reaches them (RFC 4592 §3.3.1).
            for absent in ["x.a.b.example.com.", "y.deep.a.b.example.com."] {
                let denial =
                    proves_nxdomain(nm(absent).as_ref(), nm(ORIGIN).as_ref(), &nsecs, &nsec3s);
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
                    proves_nodata(
                        nm("www.example.com.").as_ref(),
                        nm(ORIGIN).as_ref(),
                        rt::MX,
                        &nsecs,
                        &nsec3s
                    ),
                    Denial::Proved
                ),
                "{chain:?}"
            );
            // And a type that *is* there is not deniable, which is the same
            // bitmap read the other way.
            assert!(
                !matches!(
                    proves_nodata(
                        nm("www.example.com.").as_ref(),
                        nm(ORIGIN).as_ref(),
                        rt::AAAA,
                        &nsecs,
                        &nsec3s
                    ),
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
            .query(nm("*.example.com.").as_ref(), Qtype::of(rt::A))
            .iter()
            .map(|r| r.rdata.to_owned())
            .collect();
        let sigs: Vec<_> = rrsigs_in(&resources(&zone))
            .into_iter()
            .filter(|s| s.owner == nm("*.example.com.") && s.type_covered == rt::A)
            .collect();
        assert_eq!(sigs.len(), 1);

        // Re-owned onto the answered name it still verifies, flagged as an
        // expansion, which obliges a denial.
        let mut expanded = sigs[0].clone();
        expanded.owner = nm("anything.example.com.");
        let proof = verify_rrset(
            &Rrset::new(
                nm("anything.example.com.").as_ref(),
                rt::A,
                Class::IN,
                &rdatas,
            ),
            &[expanded],
            &published_keys(&zone),
            nm(ORIGIN).as_ref(),
            NOW,
        );
        let RrsetProof::Verified {
            wildcard: Some(wildcard),
            ..
        } = proof
        else {
            panic!("expected a wildcard expansion: {proof:?}");
        };
        assert_eq!(wildcard, nm("*.example.com."));

        // The other half: the chain has to show the queried name has nothing of
        // its own and that this is the wildcard covering it.
        let (nsecs, nsec3s) = chain_records(&zone);
        assert!(matches!(
            proves_wildcard_expansion(
                nm("anything.example.com.").as_ref(),
                wildcard.as_ref(),
                &nsecs,
                &nsec3s
            ),
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
        let params = zone.query(nm(ORIGIN).as_ref(), Qtype::of(rt::NSEC3PARAM));
        assert_eq!(params.len(), 1, "one NSEC3PARAM at the apex");
        // Hash 1, flags 0, five iterations, a four-byte salt.
        assert_eq!(
            params[0].rdata.bytes(),
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
                .any(|n| n.matches(nm(name).as_ref()).unwrap_or(false))
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
        // A delegation is chained, or a validator cannot tell an unsigned child
        // from a stripped DS.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = sign_test_zone(chain.clone());
            let (nsecs, nsec3s) = chain_records(&zone);
            let denial = proves_no_ds(nm("plain.example.com.").as_ref(), &nsecs, &nsec3s);
            assert!(matches!(denial, Denial::Proved), "{chain:?}: {denial:?}");
        }
    }

    #[test]
    fn the_ksk_signs_the_keys_and_the_zsk_signs_the_data() {
        let keys = signing_keys(ORIGIN);
        let ksk = keys[0].key_tag();
        let zsk = keys[1].key_tag();
        let zone = sign_zone(
            &parse_zone_file(ZONE, ORIGIN).unwrap(),
            &keys,
            &policy(DenialChain::Nsec),
        )
        .unwrap();

        let sigs = rrsigs_in(&resources(&zone));
        let tags = |name: &str, rtype: Rtype| -> Vec<u16> {
            let mut tags: Vec<u16> = sigs
                .iter()
                .filter(|s| s.owner == nm(name) && s.type_covered == rtype)
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
        // A combined key is what a small zone runs. Reserving the entry-point
        // key for the DNSKEY RRset would leave the data unsigned.
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

    /// What a full re-sign costs an IXFR: every RRSIG's RDATA derives from
    /// `signed_at`, so one added record to a 53-record zone gives a 52-record
    /// delta, one short of `ixfr_response`'s AXFR threshold.
    #[test]
    fn re_signing_after_an_update_currently_rewrites_every_signature() {
        use crate::ixfr::diff;

        let keys = signing_keys(ORIGIN);
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        let before = sign_zone(&zone, &keys, &policy(DenialChain::Nsec)).unwrap();

        // The smallest possible update: one A record, and the §3.6 serial bump.
        let updated = crate::update::apply(
            &zone,
            &[crate::update::Change::Add(ResourceRecord {
                name: nm("new.example.com."),
                class: Class::IN,
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.77".parse().unwrap()))
                    .unwrap(),
            })],
        );
        assert_eq!(updated.changed, 1, "one record changed");

        // Signed a minute later, as a real update would be.
        let later = SigningPolicy::valid_for(NOW + 60, 30 * 86_400).with_chain(DenialChain::Nsec);
        let after = sign_zone(&updated.zone, &keys, &later).unwrap();

        let delta = diff(&before, &after).expect("both versions have an SOA");
        let signatures = before
            .records()
            .iter()
            .filter(|r| r.rdata.rtype() == rt::RRSIG)
            .count();
        let signatures_deleted = delta
            .deleted
            .iter()
            .filter(|r| r.rdata.rtype() == rt::RRSIG)
            .count();

        assert_eq!(
            signatures_deleted, signatures,
            "every signature in the zone is in the delta, not just the changed one"
        );
        assert!(
            delta.len() > before.records().len() / 2,
            "the delta ({}) is most of the zone ({}) for a one-record change",
            delta.len(),
            before.records().len()
        );

        // Signing incrementally carries every untouched signature forward, so
        // the delta collapses to what moved plus the chain around it.
        let incremental = sign_zone_incrementally(&before, &updated.zone, &keys, &later)
            .expect("signs")
            .zone;
        let small = diff(&before, &incremental).expect("both have an SOA");
        assert!(
            small.len() * 4 < delta.len(),
            "the incremental delta ({}) must be a small fraction of the full one ({})",
            small.len(),
            delta.len()
        );
        assert!(
            small
                .deleted
                .iter()
                .chain(small.added.iter())
                .all(|r| r.rdata.rtype() != rt::RRSIG
                    || r.name == nm("new.example.com.")
                    || r.name == nm(ORIGIN)
                    || small
                        .added
                        .iter()
                        .any(|a| a.name == r.name && a.rdata.rtype() == rt::NSEC)
                    || small
                        .deleted
                        .iter()
                        .any(|d| d.name == r.name && d.rdata.rtype() == rt::NSEC)),
            "the only signatures that moved belong to the new name, the apex \
             whose SOA changed, or a denial record the insertion displaced: {:?}",
            small
                .deleted
                .iter()
                .chain(small.added.iter())
                .filter(|r| r.rdata.rtype() == rt::RRSIG)
                .map(|r| r.name.to_string())
                .collect::<Vec<_>>()
        );
    }

    /// Carrying a signature forward is only sound if it still covers what it
    /// says it covers, so the incremental path is judged with `proof_for` — the
    /// same code that judges a real zone.
    #[test]
    fn an_incrementally_signed_zone_still_verifies() {
        let keys = signing_keys(ORIGIN);
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        let before = sign_zone(&zone, &keys, &policy(DenialChain::Nsec)).unwrap();

        let updated = crate::update::apply(
            &zone,
            &[crate::update::Change::Add(ResourceRecord {
                name: nm("new.example.com."),
                class: Class::IN,
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.77".parse().unwrap()))
                    .unwrap(),
            })],
        );
        let later = SigningPolicy::valid_for(NOW + 60, 30 * 86_400).with_chain(DenialChain::Nsec);
        let signed = sign_zone_incrementally(&before, &updated.zone, &keys, &later)
            .unwrap()
            .zone;

        // The record the update added, whose signature is new.
        assert!(matches!(
            proof_for(&signed, "new.example.com.", rt::A),
            RrsetProof::Verified { .. }
        ));
        // One that was carried forward untouched.
        assert!(matches!(
            proof_for(&signed, "www.example.com.", rt::A),
            RrsetProof::Verified { .. }
        ));
        // The apex SOA, which moved because the serial did.
        assert!(matches!(
            proof_for(&signed, ORIGIN, rt::SOA),
            RrsetProof::Verified { .. }
        ));
        assert!(matches!(
            proof_for(&signed, ORIGIN, rt::DNSKEY),
            RrsetProof::Verified { .. }
        ));
    }

    /// A carried-forward signature must not outlive the RRset it covers, and the
    /// three ways it could are each refused.
    #[test]
    fn a_signature_is_not_carried_forward_when_anything_it_covers_changed() {
        let keys = signing_keys(ORIGIN);
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        let before = sign_zone(&zone, &keys, &policy(DenialChain::Nsec)).unwrap();
        let later = SigningPolicy::valid_for(NOW + 60, 30 * 86_400).with_chain(DenialChain::Nsec);

        let sig_at = |z: &Zone, name: &str, covered: Rtype| -> Vec<RecordData> {
            z.records()
                .iter()
                .filter(|r| {
                    r.name == nm(name)
                        && r.rdata.rtype() == rt::RRSIG
                        && matches!(
                            r.rdata.parse(),
                            Ok(ParsedRecord::RRSIG { type_covered, .. }) if type_covered == covered
                        )
                })
                .map(|r| r.rdata.to_owned())
                .collect()
        };

        // A record added to an existing RRset: its signature must be remade.
        let mut grown = zone.clone();
        grown.add_record(ZoneRecord {
            name: nm("www.example.com."),
            ttl: Ttl::from_secs(3600),
            class: Class::IN,
            rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.88".parse().unwrap()))
                .unwrap(),
        });
        let signed = sign_zone_incrementally(&before, &grown, &keys, &later)
            .unwrap()
            .zone;
        assert_ne!(
            sig_at(&signed, "www.example.com.", rt::A),
            sig_at(&before, "www.example.com.", rt::A),
            "an RRset that gained a record is signed afresh"
        );

        // A TTL change, same RDATA: the RRSIG stores the original TTL (RFC 4034
        // §3.1.3), so it is stale.
        let retimed = crate::update::apply(
            &zone,
            &[crate::update::Change::Add(ResourceRecord {
                name: nm("www.example.com."),
                class: Class::IN,
                ttl: Ttl::from_secs(60),
                rdata: zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))[0]
                    .rdata
                    .to_owned(),
            })],
        );
        let signed = sign_zone_incrementally(&before, &retimed.zone, &keys, &later)
            .unwrap()
            .zone;
        assert_ne!(
            sig_at(&signed, "www.example.com.", rt::A),
            sig_at(&before, "www.example.com.", rt::A),
            "a TTL change is a change: the RRSIG carries the original TTL"
        );

        // A key added: what it must sign is signed afresh, or its DNSKEY has no
        // signatures of its own.
        let mut rolling = keys;
        rolling.push(
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                .unwrap(),
        );
        let signed = sign_zone_incrementally(&before, &zone, &rolling, &later)
            .unwrap()
            .zone;
        assert_eq!(
            sig_at(&signed, "www.example.com.", rt::A).len(),
            2,
            "both zone-signing keys now sign it"
        );
    }

    /// A key tag "is not a unique identifier" (RFC 4034 Appendix B), so a key
    /// sharing its tag with the one it joins or replaces is still a new key.
    #[test]
    fn a_key_sharing_a_tag_with_the_one_it_joins_or_replaces_still_signs() {
        let [zsk, twin] = colliding_zsks(ORIGIN);
        assert_eq!(zsk.key_tag(), twin.key_tag(), "the fixture's premise");
        let ksk = SigningKey::generate(
            SigningAlgorithm::Ed25519,
            ORIGIN,
            DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
        )
        .unwrap();
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        let mut keys = vec![ksk, zsk];
        let before = sign_zone(&zone, &keys, &policy(DenialChain::Nsec)).unwrap();
        let later = SigningPolicy::valid_for(NOW + 60, 30 * 86_400).with_chain(DenialChain::Nsec);
        let signatures_over_www = |z: &Zone| {
            rrsigs_in(&resources(z))
                .iter()
                .filter(|s| s.owner == nm("www.example.com.") && s.type_covered == rt::A)
                .count()
        };

        keys.push(twin);
        let joined = sign_zone_incrementally(&before, &zone, &keys, &later)
            .unwrap()
            .zone;
        assert_eq!(signatures_over_www(&joined), 2, "both twins sign it");

        keys.remove(1);
        let replaced = sign_zone_incrementally(&before, &zone, &keys, &later)
            .unwrap()
            .zone;
        assert_eq!(signatures_over_www(&replaced), 1);
        assert!(
            matches!(
                proof_for(&replaced, "www.example.com.", rt::A),
                RrsetProof::Verified { .. }
            ),
            "signed by the key now published, not carried from the one withdrawn"
        );
    }

    #[test]
    fn re_signing_replaces_the_previous_run_rather_than_stacking_on_it() {
        // The same keys both times. Signing again with *different* keys keeps
        // the old DNSKEYs on purpose — that is a rollover, not a mistake.
        let keys = signing_keys(ORIGIN);
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        let once = sign_zone(&zone, &keys, &policy(DenialChain::Nsec)).unwrap();
        let twice = sign_zone(&once, &keys, &policy(DenialChain::Nsec)).unwrap();

        let count = |z: &Zone, rtype: Rtype| {
            z.records()
                .iter()
                .filter(|r| r.rdata.rtype() == rtype)
                .count()
        };
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
        let wrong =
            vec![
                SigningKey::generate(SigningAlgorithm::Ed25519, "example.net.", DNSKEY_FLAG_ZONE)
                    .unwrap(),
            ];
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
        let mut zone = Zone::new(nm(ORIGIN));
        zone.add_record(ZoneRecord {
            name: nm("www.example.com."),
            ttl: Ttl::from_secs(3600),
            class: Class::IN,
            rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.1".parse().unwrap())).unwrap(),
        });
        let err = sign_zone(&zone, &signing_keys(ORIGIN), &policy(DenialChain::Nsec)).unwrap_err();
        assert!(err.to_string().contains("SOA"), "{err}");
    }

    #[test]
    fn an_rrset_whose_records_disagree_on_ttl_is_signed_at_the_smallest() {
        // Disagreeing TTLs (RFC 2181 §5.2 forbids it) are unified, as a
        // signature covers one TTL.
        let text = "$ORIGIN example.com.\n$TTL 3600\n\
                    @ IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                    @ IN NS ns1.example.com.\n\
                    ns1 IN A 192.0.2.1\n\
                    www 60 IN A 192.0.2.10\n\
                    www 300 IN A 192.0.2.11\n";
        let zone = sign_zone(
            &parse_zone_file(text, ORIGIN).unwrap(),
            &signing_keys(ORIGIN),
            &policy(DenialChain::Nsec),
        )
        .unwrap();

        for record in zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A)) {
            assert_eq!(record.ttl, Ttl::from_secs(60));
        }
        let sig = rrsigs_in(&resources(&zone))
            .into_iter()
            .find(|s| s.owner == nm("www.example.com.") && s.type_covered == rt::A)
            .expect("the RRset is signed");
        assert_eq!(sig.original_ttl, 60);
        assert!(matches!(
            proof_for(&zone, "www.example.com.", rt::A),
            RrsetProof::Verified { .. }
        ));
    }

    #[test]
    fn the_ds_to_hand_the_parent_digests_the_key_as_published() {
        // The one output leaving the zone: the DS must digest the DNSKEY as
        // published.
        let keys = signing_keys(ORIGIN);
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
            &signing_keys(ORIGIN),
            &policy(DenialChain::Nsec3 {
                salt: Vec::new(),
                iterations: MAX_NSEC3_ITERATIONS + 1,
                opt_out: false,
            }),
        )
        .unwrap_err();
        assert!(err.to_string().contains("RFC 9276"), "{err}");
    }

    /// A zone of `records` `A` records under `example.com.`, the fixture both
    /// cost measurements below build.
    fn cost_fixture(records: usize) -> Zone {
        use std::fmt::Write as _;
        let mut text = String::from("$ORIGIN example.com.\n$TTL 3600\n");
        text.push_str("@ IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n");
        text.push_str("@ IN NS ns.example.com.\n");
        text.push_str("ns IN A 192.0.2.1\n");
        for i in 0..records {
            let (a, b, c) = ((i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
            let _ = writeln!(text, "h{i} IN A 10.{a}.{b}.{c}");
        }
        parse_zone_file(&text, ORIGIN).expect("the fixture parses")
    }

    /// One timing per O(zone) pass inside [`sign_zone_inner`].
    ///
    /// The carry-forward index is not here: only the incremental path has one,
    /// and its caller owns both ends of it, since it is built before these
    /// timers start and freed after they stop.
    struct Passes {
        carry_over: std::time::Duration,
        /// Everything in `sign_zone_inner` that is not O(zone): preamble
        /// checks, `Zone::new`, DNSKEY and CDS publication, NSEC3PARAM and key
        /// selection; one column, near zero (`TODO.md` #111d), so the split
        /// covers the function.
        fixed: std::time::Duration,
        layout: std::time::Duration,
        /// NSEC or NSEC3, whichever `policy.chain` asks for.
        denial_chain: std::time::Duration,
        build_rrsets: std::time::Duration,
        sign_rrsets: std::time::Duration,
        file_sigs: std::time::Duration,
    }

    impl Passes {
        fn sign_everything(&self) -> std::time::Duration {
            self.build_rrsets + self.sign_rrsets + self.file_sigs
        }

        fn total(&self) -> std::time::Duration {
            self.carry_over + self.fixed + self.layout + self.denial_chain + self.sign_everything()
        }
    }

    /// `sign_zone_inner`'s body, its own arguments, its own order, timed: one
    /// copy for both measurements (`CLAUDE.md` §7). The zone is returned, as
    /// production returns it, so freeing it is not charged to a timer.
    fn split_passes(
        zone: &Zone,
        keys: &[SigningKey],
        policy: &SigningPolicy,
        previous: Option<&PreviousSignatures>,
    ) -> (Passes, Zone) {
        use std::time::Instant;

        // The preamble production runs; `check_keys` makes the later `expect`s
        // honest.
        let start = Instant::now();
        policy
            .chain
            .check()
            .expect("the chain parameters are in range");
        let origin = zone.origin().to_folded();
        check_keys(keys, origin.as_ref()).expect("the keys are usable");
        assert!(
            policy.expiration > policy.inception,
            "a signature that expires before it was made"
        );
        let mut signed = Zone::new(origin.clone());
        let mut fixed = start.elapsed();

        let start = Instant::now();
        let (soa_ttl, minimum) = carry_over_records(zone, origin.as_ref(), policy, &mut signed)
            .expect("the records carry over");
        let carry_over = start.elapsed();
        let start = Instant::now();
        let dnskey_ttl = publish_dnskeys(
            keys,
            origin.as_ref(),
            soa_ttl,
            policy.signed_at,
            &mut signed,
        );
        publish_sync_records(
            keys,
            origin.as_ref(),
            dnskey_ttl,
            policy.signed_at,
            &mut signed,
        )
        .expect("the sync records publish");
        // Before `Layout::of`, as production (RFC 5155 §7.1): an earlier bitmap
        // denies a present type.
        if let DenialChain::Nsec3 {
            salt, iterations, ..
        } = &policy.chain
        {
            signed.add_record(ZoneRecord {
                name: origin.clone(),
                ttl: dnskey_ttl,
                class: Class::IN,
                rdata: nsec3param_rdata(salt, *iterations),
            });
        }
        assert!(
            policy.dnskey_signature != DnskeySignature::Imported
                || has_dnskey_rrsig(&signed, origin.as_ref()),
            "an imported DNSKEY signature with no RRSIG over the apex DNSKEY"
        );
        fixed += start.elapsed();

        let start = Instant::now();
        let layout = Layout::of(&signed, origin.as_ref());
        let layout_time = start.elapsed();

        // RFC 9077 §3's lesser, as production; `SPLIT_ZONE`'s TTLs tell it from
        // MINIMUM alone.
        let denial_ttl = Ttl::from_secs(minimum).min(soa_ttl);
        // Production branches here, so this does too.
        let start = Instant::now();
        match &policy.chain {
            DenialChain::Nsec => {
                build_nsec_chain(&layout, denial_ttl, &mut signed).expect("the chain")
            }
            DenialChain::Nsec3 {
                salt,
                iterations,
                opt_out,
            } => build_nsec3_chain(
                &layout,
                salt,
                *iterations,
                *opt_out,
                denial_ttl,
                &mut signed,
            )
            .expect("the chain"),
        }
        let denial_chain = start.elapsed();

        // `sign_everything`'s own three, and its key selection.
        let start = Instant::now();
        let active = active_signing_keys(keys, policy.signed_at);
        let sep: Vec<&SigningKey> = active.iter().copied().filter(|k| k.is_sep()).collect();
        let rest: Vec<&SigningKey> = active.iter().copied().filter(|k| !k.is_sep()).collect();
        // Production's fallback and refusal, or a single-key fixture measures a
        // run that signs no data.
        let all: Vec<&SigningKey> = active.clone();
        let dnskey_signers = if sep.is_empty() { &all } else { &sep };
        let data_signers = if rest.is_empty() { &all } else { &rest };
        assert!(
            !data_signers.is_empty(),
            "no key is active to sign with; production fails the run here"
        );
        fixed += start.elapsed();
        let start = Instant::now();
        let rrsets = rrsets_of(&signed);
        let build_rrsets = start.elapsed();
        let start = Instant::now();
        let (signatures, _fresh) = signatures_for(
            rrsets,
            &layout,
            policy,
            previous,
            dnskey_signers,
            data_signers,
        )
        .expect("the signatures");
        let sign_rrsets = start.elapsed();
        let start = Instant::now();
        for signature in signatures {
            signed.add_record(signature);
        }
        let file_sigs = start.elapsed();

        (
            Passes {
                carry_over,
                fixed,
                layout: layout_time,
                denial_chain,
                build_rrsets,
                sign_rrsets,
                file_sigs,
            },
            signed,
        )
    }

    /// A zone each drift of the split from `sign_zone_inner` changes.
    ///
    /// The SOA's TTL is under its MINIMUM, so a denial TTL of MINIMUM alone is
    /// a different number; `cost_fixture` is 3600 over 3600, where it is not.
    const SPLIT_ZONE: &str = "$ORIGIN example.com.
$TTL 60
@   IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 86400
@   IN NS  ns.example.com.
ns  IN A   192.0.2.1
a   IN A   192.0.2.2
b   IN A   192.0.2.3
b   IN TXT \"two rrsets at one name\"
deep.b IN A 192.0.2.4
";

    /// Every record of `split_passes`'s zone, ordered so two zones compare.
    fn canonical(zone: &Zone) -> Vec<(String, u16, u32, Vec<u8>)> {
        let mut records: Vec<_> = zone
            .records()
            .iter()
            .map(|r| {
                (
                    r.name.to_string(),
                    r.rdata.rtype().to_u16(),
                    r.ttl.as_secs(),
                    r.rdata.bytes().to_vec(),
                )
            })
            .collect();
        records.sort();
        records
    }

    /// `split_passes` builds the zone `sign_zone_inner` builds: every chain,
    /// both key shapes, record for record.
    ///
    /// The guard that runs, as the cost tests are ignored benchmarks. Ed25519,
    /// deterministic (RFC 8032), so "the same number of records" can be "the
    /// same records".
    #[test]
    fn the_split_builds_what_sign_zone_inner_builds() {
        let zone = parse_zone_file(SPLIT_ZONE, ORIGIN).expect("the fixture parses");
        let ed = |flags| {
            SigningKey::generate(SigningAlgorithm::Ed25519, ORIGIN, flags).expect("generate")
        };
        // One SEP alone makes the signer fallback fire: `rest` is empty, so the
        // data is signed with `all`.
        let sep_only = vec![ed(DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP)];
        let ksk_and_zsk = vec![ed(DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP), ed(DNSKEY_FLAG_ZONE)];

        for (keys, shape) in [
            (&sep_only, "one SEP key"),
            (&ksk_and_zsk, "a KSK and a ZSK"),
        ] {
            for chain in [
                DenialChain::Nsec,
                DenialChain::Nsec3 {
                    salt: vec![0xde, 0xad, 0xbe, 0xef],
                    iterations: 5,
                    opt_out: false,
                },
            ] {
                let policy = policy(chain.clone());
                let (whole, _) =
                    sign_zone_inner(&zone, keys, &policy, None).expect("the whole signs");
                let (_, split) = split_passes(&zone, keys, &policy, None);
                assert_eq!(
                    canonical(&whole),
                    canonical(&split),
                    "the split is not the function: {shape}, {chain:?}"
                );
            }
        }
    }

    /// The parts are the function or they are fiction: the same zone out, and
    /// the sum within 0.8x-1.25x of the whole.
    ///
    /// The whole pays the cold allocator and the parts inherit it warm, which
    /// pushes the ratio *down*: 0.78 at 10 000 records, 2 runs in 3 on Linux,
    /// unless a run at the same size is discarded first, as both callers do
    /// (`TODO.md` #111d). What the 1.25 side is for is unmeasured.
    fn check_split(
        parts: std::time::Duration,
        whole: std::time::Duration,
        built: usize,
        was: usize,
        records: usize,
    ) {
        assert_eq!(built, was, "the split built a different zone at {records}");
        let drift = parts.as_secs_f64() / whole.as_secs_f64();
        assert!(
            (0.8..1.25).contains(&drift),
            "the parts sum to {drift:.2} of the whole at {records}: they are no longer \
             what `sign_zone_inner` runs",
        );
    }

    fn refuse_debug(name: &str) {
        if cfg!(debug_assertions) {
            panic!(
                "this would measure the debug build. Run:\n  \
                 cargo test -p rdns --release {name} -- --ignored --nocapture"
            );
        }
    }

    /// Where an incremental sign spends its time (`TODO.md` #64e).
    ///
    /// ```text
    ///   records  incremental previous-sigs carry-over    layout nsec-chain sign-everything     free  build-rrsets sign-rrsets   file-sigs
    ///     10000       50.6ms        10.8ms      4.7ms     3.0ms      8.2ms          20.8ms    2.2ms        5.6ms      12.9ms       2.3ms
    ///    100000      735.5ms       150.6ms     60.6ms    37.2ms     97.6ms         313.3ms   67.8ms       69.5ms     209.7ms      34.1ms
    ///   1000000     9397.4ms      1816.8ms   1104.9ms   512.8ms   1519.2ms        3627.7ms 1092.2ms      980.8ms    2221.5ms     425.4ms
    /// ```
    ///
    /// The last three columns split `sign-everything`; the parts sum to the
    /// whole, which is asserted. The reading is in `docs/closed/064.md`.
    ///
    /// ```sh
    /// cargo test -p rdns --release incremental_sign_cost -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn incremental_sign_cost_by_pass() {
        use crate::update;
        use std::time::Instant;

        refuse_debug("incremental_sign_cost");

        let keys = signing_keys(ORIGIN);
        let policy = policy(DenialChain::Nsec);
        println!(
            "{:>9}  {:>11} {:>13} {:>10} {:>7} {:>9} {:>12} {:>15} {:>8}  {:>11} {:>11} {:>11}",
            "records",
            "incremental",
            "previous-sigs",
            "carry-over",
            "fixed",
            "layout",
            "denial-chain",
            "sign-everything",
            "free",
            "build-rrsets",
            "sign-rrsets",
            "file-sigs",
        );
        for records in [10_000usize, 100_000, 1_000_000] {
            let source = cost_fixture(records);
            let previous = sign_zone(&source, &keys, &policy).expect("the fixture signs");
            let change = update::Change::Add(ResourceRecord {
                name: nm("added.example.com."),
                class: Class::IN,
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::A(std::net::Ipv4Addr::new(
                    198, 51, 100, 1,
                )))
                .expect("the rdata builds"),
            });
            let zone = update::apply(&source, std::slice::from_ref(&change)).zone;
            drop(source);

            // Each side run once and discarded: allocator growth lands on
            // whichever runs first (`TODO.md` #111d, #111e).
            drop(
                sign_zone_incrementally(&previous, &zone, &keys, &policy)
                    .expect("the discarded run signs"),
            );
            drop(split_passes(
                &zone,
                &keys,
                &policy,
                Some(&PreviousSignatures::of(&previous)),
            ));
            let start = Instant::now();
            let whole = sign_zone_incrementally(&previous, &zone, &keys, &policy)
                .expect("signs")
                .zone;
            let incremental = start.elapsed();

            let start = Instant::now();
            let carried = PreviousSignatures::of(&previous);
            let previous_sigs = start.elapsed();

            let (passes, built) = split_passes(&zone, &keys, &policy, Some(&carried));

            // Freeing the index is a pass too: `carried` dies inside
            // `sign_zone_incrementally`, after every timer.
            let start = Instant::now();
            drop(carried);
            let free_carried = start.elapsed();

            check_split(
                passes.total() + previous_sigs + free_carried,
                incremental,
                built.records().len(),
                whole.records().len(),
                records,
            );
            println!(
                "{records:>9}  {:>9.1}ms {:>11.1}ms {:>8.1}ms {:>5.1}ms {:>7.1}ms {:>10.1}ms {:>13.1}ms {:>6.1}ms  {:>9.1}ms {:>9.1}ms {:>9.1}ms",
                incremental.as_secs_f64() * 1000.0,
                previous_sigs.as_secs_f64() * 1000.0,
                passes.carry_over.as_secs_f64() * 1000.0,
                passes.fixed.as_secs_f64() * 1000.0,
                passes.layout.as_secs_f64() * 1000.0,
                passes.denial_chain.as_secs_f64() * 1000.0,
                passes.sign_everything().as_secs_f64() * 1000.0,
                free_carried.as_secs_f64() * 1000.0,
                passes.build_rrsets.as_secs_f64() * 1000.0,
                passes.sign_rrsets.as_secs_f64() * 1000.0,
                passes.file_sigs.as_secs_f64() * 1000.0,
            );
        }
    }

    /// What a carry-forward saves at a *reload*, where the file has changed
    /// (`TODO.md` #65b).
    ///
    /// ```text
    ///   edit   records   incremental       full    saved  fresh sigs
    /// in place         1      9685.3ms  27610.2ms    64.9%           1
    /// in place      1000     10089.5ms  27610.2ms    63.5%        1000
    /// in place     10000     10115.4ms  27610.2ms    63.4%       10000
    /// in place    100000     10955.7ms  27610.2ms    60.3%      100000
    ///    add         1      9831.3ms  27610.2ms    64.4%           3
    ///    add      1000      9798.5ms  27610.2ms    64.5%        2001
    ///    add     10000     10260.0ms  27610.2ms    62.8%       20001
    ///    add    100000     12824.2ms  27610.2ms    53.6%      200001
    /// ```
    ///
    /// Edits in place and additions, as adding moves each predecessor's NSEC
    /// (RFC 4034 §4.1.1). The reading is in `docs/closed/065.md`.
    ///
    /// ```sh
    /// cargo test -p rdns --release reload_carry_forward -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn reload_carry_forward_saving_by_change_size() {
        use std::time::Instant;

        refuse_debug("reload_carry_forward");

        const RECORDS: usize = 1_000_000;
        let keys = signing_keys(ORIGIN);
        let policy = policy(DenialChain::Nsec);
        let source = cost_fixture(RECORDS);
        let previous = sign_zone(&source, &keys, &policy).expect("the fixture signs");

        // One full sign of the changed zone, the column every row compares
        // against; the change does not move it.
        let start = Instant::now();
        let full = sign_zone(&source, &keys, &policy).expect("signs");
        let full_time = start.elapsed();
        drop(full);

        let rrsig = crate::record_types::RRSIG;
        let was: std::collections::HashSet<(NameRef<'_>, &[u8])> = previous
            .records()
            .iter()
            .filter(|r| r.rdata.rtype() == rrsig)
            .map(|r| (r.name, r.rdata.bytes()))
            .collect();

        println!(
            "{:>6} {:>9}  {:>12} {:>10} {:>8}  {:>10}",
            "edit", "records", "incremental", "full", "saved", "fresh sigs"
        );
        // In place leaves the chain unmoved, the cheap end; adding moves
        // predecessors, the case that could refute the row (§19).
        for adding in [false, true] {
            for changed in [1usize, 1_000, 10_000, 100_000] {
                let mut edited = Zone::new(source.origin().to_folded());
                for (i, record) in source.records().iter().enumerate() {
                    let mut record = record.to_owned();
                    if !adding && i >= source.records().len() - changed {
                        record.rdata = RecordData::from_parsed(&ParsedRecord::A(
                            std::net::Ipv4Addr::new(198, 51, 100, 2),
                        ))
                        .expect("the rdata builds");
                    }
                    edited.add_record(record);
                }
                if adding {
                    for i in 0..changed {
                        edited.add_record(ZoneRecord {
                            name: nm(&format!("new{i}.example.com.")),
                            ttl: Ttl::from_secs(3600),
                            class: Class::IN,
                            rdata: RecordData::from_parsed(&ParsedRecord::A(
                                std::net::Ipv4Addr::new(198, 51, 100, 3),
                            ))
                            .expect("the rdata builds"),
                        });
                    }
                }

                let start = Instant::now();
                let signed = sign_zone_incrementally(&previous, &edited, &keys, &policy)
                    .expect("signs")
                    .zone;
                let incremental = start.elapsed();

                let fresh = signed
                    .records()
                    .iter()
                    .filter(|r| r.rdata.rtype() == rrsig)
                    .filter(|r| !was.contains(&(r.name, r.rdata.bytes())))
                    .count();
                println!(
                    "{:>6} {changed:>9}  {:>10.1}ms {:>8.1}ms {:>7.1}% {:>11}",
                    if adding { "add" } else { "in place" },
                    incremental.as_secs_f64() * 1000.0,
                    full_time.as_secs_f64() * 1000.0,
                    100.0 - 100.0 * incremental.as_secs_f64() / full_time.as_secs_f64(),
                    fresh,
                );
                assert!(
                    fresh >= changed,
                    "changing {changed} records made only {fresh} fresh signatures",
                );
            }
        }
    }

    /// The same split for a *full* sign (`TODO.md` #65): the four passes every
    /// sign pays, where #64e's table is the UPDATE path.
    ///
    /// ```text
    ///   records        full carry-over    layout nsec-chain sign-everything  build-rrsets sign-rrsets   file-sigs
    ///     10000     249.6ms      5.0ms     3.3ms      8.3ms         231.8ms        5.4ms     223.0ms       3.4ms
    ///    100000    2547.5ms     64.0ms    39.8ms    107.0ms        2418.3ms       79.7ms    2299.5ms      39.1ms
    ///   1000000   27139.9ms   1131.3ms   520.0ms   1436.5ms       24217.8ms      884.7ms   22919.3ms     413.7ms
    /// ```
    ///
    /// The reading is in `docs/closed/065.md`.
    ///
    /// ```sh
    /// cargo test -p rdns --release full_sign_cost -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn full_sign_cost_by_pass() {
        use std::time::Instant;

        refuse_debug("full_sign_cost");

        let keys = signing_keys(ORIGIN);
        let policy = policy(DenialChain::Nsec);
        println!(
            "{:>9}  {:>10} {:>10} {:>7} {:>9} {:>12} {:>15}  {:>11} {:>11} {:>11}",
            "records",
            "full",
            "carry-over",
            "fixed",
            "layout",
            "denial-chain",
            "sign-everything",
            "build-rrsets",
            "sign-rrsets",
            "file-sigs",
        );
        for records in [10_000usize, 100_000, 1_000_000] {
            let zone = cost_fixture(records);

            // One of each discarded first, as in `incremental_sign_cost_by_pass`
            // and for the same measurement (`TODO.md` #111d, #111e).
            drop(sign_zone(&zone, &keys, &policy).expect("the discarded run signs"));
            drop(split_passes(&zone, &keys, &policy, None));
            let start = Instant::now();
            let whole = sign_zone(&zone, &keys, &policy).expect("signs");
            let full = start.elapsed();

            let (passes, built) = split_passes(&zone, &keys, &policy, None);
            check_split(
                passes.total(),
                full,
                built.records().len(),
                whole.records().len(),
                records,
            );
            println!(
                "{records:>9}  {:>8.1}ms {:>8.1}ms {:>5.1}ms {:>7.1}ms {:>10.1}ms {:>13.1}ms  {:>9.1}ms {:>9.1}ms {:>9.1}ms",
                full.as_secs_f64() * 1000.0,
                passes.carry_over.as_secs_f64() * 1000.0,
                passes.fixed.as_secs_f64() * 1000.0,
                passes.layout.as_secs_f64() * 1000.0,
                passes.denial_chain.as_secs_f64() * 1000.0,
                passes.sign_everything().as_secs_f64() * 1000.0,
                passes.build_rrsets.as_secs_f64() * 1000.0,
                passes.sign_rrsets.as_secs_f64() * 1000.0,
                passes.file_sigs.as_secs_f64() * 1000.0,
            );
        }
    }

    /// No refresh threshold can spread a re-signing run across ticks, because
    /// the expiry spread is narrower than the interval.
    ///
    /// `TODO.md` #65c option B, declined: `expiry_for` spreads over a fifth of
    /// the validity and the timer runs every third, so every expiry crosses a
    /// threshold together. A tripwire on the two constants, not a measurement;
    /// `docs/closed/065.md` has the argument.
    #[test]
    fn a_refresh_threshold_is_all_or_nothing_per_resigning_tick() {
        const VALIDITY: u64 = 30 * 86_400;
        let tick = resign_after(VALIDITY);
        assert!(
            VALIDITY / EXPIRY_JITTER_FRACTION < tick,
            "the spread is inside one interval, which is what makes the rest of this true",
        );

        // One expiry per (owner, type), which is what `expiry_for` keys on.
        let names: Vec<Name> = (0..200)
            .map(|i| nm(&format!("h{i}.example.com.")))
            .collect();
        let expiries = |at: u64| -> Vec<u32> {
            let policy = SigningPolicy::valid_for(at, VALIDITY);
            names
                .iter()
                .map(|n| policy.expiry_for(n.as_ref(), rt::A))
                .collect()
        };

        for slack in 0..=2u64 {
            let mut expiry = expiries(NOW);
            for k in 1..=6u64 {
                let at = NOW + k * tick;
                let must_outlive = at + slack * tick;
                let due = expiry
                    .iter()
                    .filter(|e| u64::from(**e) <= must_outlive)
                    .count();
                assert!(
                    due == 0 || due == names.len(),
                    "tick {k} at slack {slack} refreshed {due} of {} — a partial run means \
                     the spread has grown past the interval",
                    names.len(),
                );
                if due == 0 {
                    continue;
                }
                // The life left on the replaced signature: a failed run is
                // survivable only while it is an interval or more.
                let left = u64::from(*expiry.iter().min().expect("expiries")).saturating_sub(at);
                assert_eq!(
                    left >= tick,
                    slack == 2,
                    "at slack {slack} a refresh happens with {left}s left against a \
                     {tick}s interval",
                );
                expiry = expiries(at);
            }
        }
    }
}
