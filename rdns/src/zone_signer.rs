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
use crate::error::DnssecError;
use crate::error::DnssecResult as Result;
use crate::utils::record_types as rt;
use crate::zone::{Zone, ZoneRecord};
use crate::Class;
use crate::Qtype;
use crate::Rtype;
use crate::Serial;
use crate::Ttl;
use crate::{ParsedRecord, RecordData};
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
                return Err(DnssecError::signing(format!(
                    "an NSEC3 salt is a length-prefixed byte string and cannot exceed 255 bytes, \
                     this one is {}",
                    salt.len(),
                )));
            }
            if *iterations > MAX_NSEC3_ITERATIONS {
                // Refusing to *sign* what we would refuse to *validate* is the
                // point: this library caps verification at the RFC 9276 limit,
                // so a zone signed above it here would be a zone we could not
                // read ourselves.
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
/// **Why spread it at all.** Every RRSIG in a zone used to be given the same
/// expiration, so the whole zone expired in the same second — which is precisely
/// why the failure this guards against is "*every* validating resolver SERVFAILs
/// the *entire* zone at once". Jitter turns that cliff into a slope: the zone
/// degrades over a fifth of its validity instead of vanishing, which is the
/// difference between a page that says "one zone is losing signatures" and an
/// outage. BIND jitters expiry for the same reason.
///
/// A fifth is a compromise. Wider spreads the risk further but shortens the
/// effective life of the earliest signatures; narrower makes the slope steeper.
const EXPIRY_JITTER_FRACTION: u64 = 5;

/// The fraction of the validity window after which a zone wants re-signing.
///
/// A third, so there are two whole windows of slack: if a re-signing run fails,
/// or a server is down over one, the signatures are still valid for the next two
/// attempts. BIND's default is a quarter of the validity, and the reasoning is
/// the same — the point is that a *missed* re-sign is survivable, because the one
/// thing that must never happen is serving expired signatures.
const RESIGN_FRACTION: u64 = 3;

/// The choices a signing run makes that are not in the zone or in the keys.
#[derive(Debug, Clone)]
pub struct SigningPolicy {
    /// When the signatures start being valid.
    pub inception: u32,
    /// When they stop — the *latest* expiry in the zone. Individual RRsets
    /// expire earlier, spread back over [`EXPIRY_JITTER_FRACTION`] of the
    /// window; see [`SigningPolicy::expiry_for`].
    pub expiration: u32,
    pub chain: DenialChain,
    /// The validity window in seconds, kept so the policy can say when the zone
    /// should be signed again and how far to spread expiry.
    validity: u64,
    /// The wall-clock second this signing run belongs to, which is what the
    /// served SOA serial is derived from. Not the same as `inception`, which is
    /// backdated for clock skew — a serial derived from a backdated time would
    /// step backwards the moment the allowance changed.
    signed_at: u64,
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
            validity,
            signed_at: now,
        }
    }

    pub fn with_chain(mut self, chain: DenialChain) -> Self {
        self.chain = chain;
        self
    }

    /// When the zone signed under this policy should be signed again.
    ///
    /// A third of the validity after inception, so a failed run has two more
    /// chances before anything expires. Nothing calls this inside the signer —
    /// it is for the daemon's re-signing timer, and it lives here because the
    /// number has to agree with the validity it is a fraction *of*.
    pub fn resign_at(&self) -> u64 {
        let after = (self.validity / RESIGN_FRACTION).max(1);
        u64::from(self.inception).saturating_add(after)
    }

    /// The expiry for one RRset's signature: the window's end, pulled back by a
    /// deterministic amount derived from the owner name and type.
    ///
    /// **Deterministic, not random**, and that matters twice. A reload re-signs,
    /// and random jitter would reshuffle which names expire when on every reload
    /// — so the slope would be a different slope each time and no two servers
    /// holding the same zone would agree about it. Deterministic jitter means the
    /// same RRset always sits at the same point on the slope.
    ///
    /// Never later than [`Self::expiration`]: an operator who asked for 30 days
    /// gets at most 30 days, never 35.
    pub fn expiry_for(&self, name: &str, rtype: Rtype) -> u32 {
        let spread = self.validity / EXPIRY_JITTER_FRACTION;
        if spread == 0 {
            return self.expiration;
        }
        // FNV-1a over the owner name and type. Not a security choice — nothing
        // adversarial depends on it — just a cheap, stable spread that does not
        // pull in a hasher whose output is randomized per process, which is
        // exactly what `DefaultHasher` would do and would destroy the
        // determinism above.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in name
            .as_bytes()
            .iter()
            .copied()
            .chain(rtype.to_u16().to_be_bytes().iter().copied())
        {
            hash ^= u64::from(byte.to_ascii_lowercase());
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        self.expiration
            .saturating_sub((hash % spread) as u32)
            .max(self.inception.saturating_add(1))
    }

    /// The SOA serial to serve for the zone this policy signs.
    /// See [`signed_serial`] for why it is what it is.
    pub fn serial_for(&self, file_serial: Serial) -> Serial {
        signed_serial(file_serial, self.signed_at)
    }
}

/// The serial to serve for a zone we signed ourselves.
///
/// **The problem.** Re-signing produces a new version of the zone as far as a
/// secondary is concerned — new RRSIGs are new data — and a secondary decides
/// whether to transfer by comparing serials. Without a bump the replica keeps
/// the signatures it already has and they expire underneath it, which is the same
/// outage as never re-signing at all, one hop downstream.
///
/// **How everyone else does it.** BIND's inline-signing keeps a signed copy with
/// its *own* serial and increments it on every re-signing run, so the number it
/// serves diverges from the number in the file — one report has a file at
/// `2016090105` being served as `2016090133`. Knot takes the field away from the
/// operator entirely (`zonefile-load: difference-no-serial`). Both persist the
/// divergence in a **journal**, and we have none (`TODO.md` #7 step 6), so
/// neither is available: without persistence a restart would go *backwards*, and
/// RFC 1982 makes that worse than it sounds — a secondary that saw `N` and then
/// sees `N-k` reads it as older and will not transfer, so it keeps the signatures
/// that are about to expire. The outage moves to restart time.
///
/// **So the time is the counter.** Hours since the Unix epoch, *added* to the
/// file's serial. That is monotone in wall time by construction, needs nothing
/// persisted, and an operator's `+1` in the file still shows up as `+1` served.
///
/// Added rather than `max`ed, which is the correction to the obvious design:
/// PowerDNS's `INCEPTION-EPOCH` documents itself as "requiring epoch-based
/// backend serials" for exactly this reason — a date-style serial like
/// `2026073001` is numerically *larger* than any current Unix timestamp, so a
/// `max` would keep the file's number and never bump at all.
///
/// Hours, not seconds: the term stays small (about 495,000 today) so it does not
/// crowd a date-style serial towards the 32-bit ceiling, and a re-sign every ten
/// days is far coarser than an hour anyway. And hours since the *epoch* rather
/// than a fraction of the validity, so that changing `--signature-validity` does
/// not move the serial backwards.
pub fn signed_serial(file_serial: Serial, signed_at: u64) -> Serial {
    const HOUR: u64 = 3600;
    // Wrapping, and [`Serial::wrapping_add`] says so in its own name: RFC 1982
    // §3.1 defines addition in the sequence space that way, so passing the
    // ceiling is an increment rather than the overflow a bare `+` would panic on
    // in a debug build.
    file_serial.wrapping_add((signed_at / HOUR) as u32)
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
    sign_zone_inner(zone, keys, policy, None)
}

/// Sign `zone`, carrying forward any signature from `previous` that still
/// covers exactly what it covered before.
///
/// **For applying a dynamic UPDATE, where re-signing everything is not merely
/// expensive but actively harmful.** Every RRSIG's inception and expiration
/// derive from the run's `signed_at` ([`SigningPolicy::valid_for`]), so a full
/// re-sign a minute after the last one produces different RDATA for *every*
/// signature in the zone — and `ixfr::diff` compares whole records, so all of
/// them land in the delta. Measured on the signer's own test zone before this
/// existed: a one-record UPDATE to a 53-record zone produced a **52-record**
/// delta, which is a full transfer wearing an incremental's framing, retained 32
/// times over by `DeltaLog`. See `TODO.md` #10.
///
/// **The chain is still built in full**, and that is the point rather than a
/// shortcut not taken. An NSEC's bitmap lists every type at its name and its
/// `next` names its successor (RFC 4034 §4.1.2, RFC 5155 §7.1), so adding one
/// name changes the denial record at that name *and* at its predecessor.
/// Computing "the changed names plus their chain neighbours" is a thing to get
/// wrong — and getting it wrong yields a chain that validates against itself
/// while denying a name that exists. Building the chain and then asking which
/// records came out identical never computes a neighbour set at all, so it
/// cannot compute one incorrectly. What is saved is the signing, which is the
/// expensive half.
pub fn sign_zone_incrementally(
    previous: &Zone,
    zone: &Zone,
    keys: &[SigningKey],
    policy: &SigningPolicy,
) -> Result<Zone> {
    let carried = PreviousSignatures::of(previous);
    sign_zone_inner(zone, keys, policy, Some(&carried))
}

fn sign_zone_inner(
    zone: &Zone,
    keys: &[SigningKey],
    policy: &SigningPolicy,
    previous: Option<&PreviousSignatures>,
) -> Result<Zone> {
    policy.chain.check()?;
    let origin = canonical_name(zone.origin());
    check_keys(keys, &origin)?;
    if policy.expiration <= policy.inception {
        return Err(DnssecError::signing(format!(
            "a signature that expires at {} cannot have been made at {}",
            policy.expiration, policy.inception,
        )));
    }

    let mut signed = Zone::new(origin.clone());
    let (soa_ttl, minimum) = carry_over_records(zone, &origin, policy, &mut signed)?;
    let dnskey_ttl = publish_dnskeys(keys, &origin, soa_ttl, &mut signed);

    // NSEC3PARAM goes in *before* the layout is taken, and the order is the
    // whole of the bug this line fixes. `Layout::of` is a snapshot of which
    // types are at which name, and every NSEC3's bitmap "MUST indicate the
    // presence of all types present at the original owner name" (RFC 5155 §7.1)
    // — so adding the record after the snapshot left the apex NSEC3 denying a
    // type that is there, signed. `dnssec-verify`, `ldns-verify-zone` and
    // `validns` all reject that zone, and worse: a validator asking for
    // `<apex> NSEC3PARAM` with DO gets a signed NODATA proof for a record it is
    // also being served, and an RFC 8198 aggressive-NSEC resolver — this
    // repo's own `rdnsr` among them — then synthesizes that false NODATA for
    // other clients out of its cache.
    if let DenialChain::Nsec3 {
        salt, iterations, ..
    } = &policy.chain
    {
        signed.add_record(ZoneRecord {
            name: origin.clone(),
            ttl: dnskey_ttl,
            class: Class::new(1),
            rdata: nsec3param_rdata(salt, *iterations),
        });
    }

    let layout = Layout::of(&signed, &origin);

    let denial_ttl = Ttl::from_secs(minimum);
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

    sign_everything(&layout, keys, policy, previous, &mut signed)?;
    Ok(signed)
}

/// A previous signed version of a zone, indexed so that an RRset which has not
/// moved can keep the signature it already had.
///
/// Both halves are needed and neither is sufficient. The RRsets answer "is this
/// exactly what was signed"; the signatures answer "and what was the answer".
/// Keeping a signature because the *name* still exists, without checking the
/// records under it, is how a zone comes to serve a signature over data it no
/// longer holds.
struct PreviousSignatures {
    /// (folded owner, type) -> the RRset as it was signed: its TTL, and its
    /// RDATA in the order the previous run saw them.
    rrsets: BTreeMap<(String, Rtype), (Ttl, Vec<RecordData>)>,
    /// (folded owner, covered type) -> the signatures over that RRset.
    signatures: BTreeMap<(String, Rtype), Vec<CarriedSignature>>,
}

/// One RRSIG from the previous run, with the two fields the reuse decision
/// turns on read out once rather than per lookup.
struct CarriedSignature {
    rdata: RecordData,
    expiration: u32,
    key_tag: u16,
}

impl PreviousSignatures {
    fn of(previous: &Zone) -> Self {
        let mut rrsets: BTreeMap<(String, Rtype), (Ttl, Vec<RecordData>)> = BTreeMap::new();
        let mut signatures: BTreeMap<(String, Rtype), Vec<CarriedSignature>> = BTreeMap::new();

        for record in previous.records() {
            let name = record.name.to_ascii_lowercase();
            if record.rdata.rtype() == rt::RRSIG {
                // An RRSIG that will not parse is one this run cannot reason
                // about, so it is simply not offered for reuse and the RRset it
                // covers gets a fresh signature.
                if let Ok(ParsedRecord::RRSIG {
                    type_covered,
                    expiration,
                    key_tag,
                    ..
                }) = record.rdata.parse()
                {
                    signatures
                        .entry((name, type_covered))
                        .or_default()
                        .push(CarriedSignature {
                            rdata: record.rdata.clone(),
                            expiration,
                            key_tag,
                        });
                }
                continue;
            }
            let entry = rrsets
                .entry((name, record.rdata.rtype()))
                .or_insert((record.ttl, Vec::new()));
            entry.1.push(record.rdata.clone());
        }

        PreviousSignatures { rrsets, signatures }
    }

    /// The signatures to carry forward for this RRset, or `None` to sign it
    /// afresh.
    ///
    /// Four conditions, and each one is a way the reuse would otherwise be
    /// wrong:
    ///
    /// 1. **The RRset is byte-identical**, as a set — same TTL, same RDATA, no
    ///    member added or removed. Compared as a set rather than a sequence
    ///    because an RRset has no order (RFC 2181 §5) and the two runs walk the
    ///    zone's record vector, which an update rebuilds.
    /// 2. **There is at least one signature**, so an RRset that was somehow
    ///    unsigned before does not stay unsigned by being copied.
    /// 3. **The signing keys have not changed**, compared by key tag as a set.
    ///    A key added is a rollover starting and the RRset needs the new
    ///    signature; a key removed is one leaving and its signature must not
    ///    survive it.
    /// 4. **No carried signature has already expired.** Anything else would
    ///    publish a signature known to be dead at the moment of writing it,
    ///    while holding the key that could have replaced it.
    ///
    /// **What is deliberately *not* a condition: being close to expiry.** A
    /// signature with a day left is carried forward unchanged. Refreshing it
    /// here would mean any single UPDATE re-signs every stale RRset in the
    /// zone — which is the whole-zone delta this exists to avoid, and worse, it
    /// would let update traffic quietly stand in for the re-signing timer. A
    /// zone whose timer has died must degrade the same way whether or not
    /// anyone is updating it, because that is the failure the operator has
    /// alerts for. Expiry is [`SigningPolicy::resign_interval`]'s business and
    /// this does not take it on.
    fn reuse(
        &self,
        name: &str,
        rtype: Rtype,
        ttl: Ttl,
        rdatas: &[RecordData],
        key_tags: &[u16],
        signed_at: u64,
    ) -> Option<&[CarriedSignature]> {
        let (was_ttl, was) = self.rrsets.get(&(name.to_string(), rtype))?;
        if *was_ttl != ttl || was.len() != rdatas.len() {
            return None;
        }
        if !was.iter().all(|r| rdatas.contains(r)) || !rdatas.iter().all(|r| was.contains(r)) {
            return None;
        }

        let carried = self.signatures.get(&(name.to_string(), rtype))?;
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
}

/// The keys must all belong to this zone, and at least one must be able to sign
/// its data. Both are checked before anything is generated: a signing run that
/// discovers halfway through that a key names another zone has already produced
/// signatures nobody can use.
fn check_keys(keys: &[SigningKey], origin: &str) -> Result<()> {
    if keys.is_empty() {
        return Err(DnssecError::signing(format!(
            "no keys to sign {origin} with"
        )));
    }
    for key in keys {
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
    origin: &str,
    policy: &SigningPolicy,
    signed: &mut Zone,
) -> Result<(Ttl, u32)> {
    let mut soa: Option<(Ttl, u32)> = None;
    // The TTL an RRset is signed with has to be one number (RFC 4034 §3.1.3
    // stores it in the RRSIG so a validator can restore it), and RFC 2181 §5.2
    // requires the records to agree on it anyway. Where they do not, the
    // smallest wins: a record cannot be made to live longer than its RRset was
    // told to, and taking the largest would publish data past the point some
    // record of it was meant to expire.
    let mut ttls: BTreeMap<(String, Rtype), Ttl> = BTreeMap::new();
    let mut carried: Vec<ZoneRecord> = Vec::new();

    for record in zone.records() {
        if is_signer_output(record.rdata.rtype()) {
            continue;
        }
        if record.class != Class::new(1) {
            return Err(DnssecError::signing(format!(
                "{} carries class {}, and DNSSEC is defined per class — a zone mixing them has \
                 no single chain to sign",
                record.name, record.class,
            )));
        }
        let name = canonical_name(&zone.normalize_name(&record.name));
        if !crate::utils::is_at_or_under(&name, origin) {
            return Err(DnssecError::signing(format!(
                "{name} is not in {origin}, so this zone has no authority to sign it",
            )));
        }
        let mut record = record.clone();
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
            // The served serial is not the file's. New RRSIGs are a new version
            // of the zone as far as a secondary is concerned, and a secondary
            // decides whether to transfer by comparing serials — so without a
            // bump the replica keeps signatures that then expire underneath it.
            // See `signed_serial`: this is BIND's inline-signing shape, where the
            // number served diverges from the number in the file, with a
            // time-derived counter instead of BIND's journal because we have no
            // journal to persist one in.
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
        let key = (name.clone(), record.rdata.rtype());
        ttls.entry(key)
            .and_modify(|t| *t = (*t).min(record.ttl))
            .or_insert(record.ttl);
        carried.push(ZoneRecord { name, ..record });
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

/// Publish the DNSKEY for every key, returning the TTL the RRset ended up with.
///
/// A key already in the zone with identical RDATA is left where it is rather
/// than duplicated — that is the same key, and an RRset holding it twice is one
/// a validator has to de-duplicate before it can verify anything.
fn publish_dnskeys(keys: &[SigningKey], origin: &str, soa_ttl: Ttl, signed: &mut Zone) -> Ttl {
    let existing: Vec<RecordData> = signed
        .query(origin, Qtype::of(rt::DNSKEY))
        .iter()
        .map(|r| r.rdata.clone())
        .collect();
    // An RRset has one TTL: keys already published set it, since changing it
    // would be changing records the operator put there.
    let ttl = signed
        .query(origin, Qtype::of(rt::DNSKEY))
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
            class: Class::new(1),
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
    /// At a delegation this is not the same as "the types here": glue is not
    /// authoritative data, so an A record at the delegation point is invisible
    /// to the chain even though the zone file holds it and the server hands it
    /// out as a hint.
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
struct Layout {
    origin: String,
    names: BTreeMap<String, NameEntry>,
}

impl Layout {
    fn of(zone: &Zone, origin: &str) -> Self {
        let mut names: BTreeMap<String, NameEntry> = BTreeMap::new();
        for record in zone.records() {
            let entry = names.entry(record.name.to_ascii_lowercase()).or_default();
            entry.types.insert(record.rdata.rtype());
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
///
/// The containment test is [`crate::utils::is_at_or_under`]. This module used to
/// carry a **private function of the same name shadowing the public one in the
/// same crate**, which is why #13b's four-copy sweep did not find it: nothing
/// greps as a second definition when the call sites read identically
/// (`TODO.md` #19b).
///
/// The two disagreed. The shared version makes the trailing dot optional on
/// either side, so `is_at_or_under("www.example.com", "example.com.")` is true
/// there and was false here — unreachable in practice, because the one caller
/// passes `canonical_name` output, but that is a property of the caller and not
/// of the function. The copy also built two `String`s and a `format!` per call,
/// which is word for word what `utils::is_at_or_under`'s doc comment says it was
/// written to remove from `resolver::is_subdomain`.
fn is_under(name: &str, origin: &str) -> bool {
    name != origin && crate::utils::is_at_or_under(name, origin)
}

// ---------------------------------------------------------------------------
// The denial chains
// ---------------------------------------------------------------------------

fn build_nsec_chain(layout: &Layout, ttl: Ttl, signed: &mut Zone) -> Result<()> {
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
        .map_err(|e| DnssecError::key(format!("encoding an NSEC: {e}")))?;
        signed.add_record(ZoneRecord {
            name: name.clone(),
            ttl,
            class: Class::new(1),
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
    let mut hashed: Vec<(Vec<u8>, String)> = Vec::new();
    for name in layout.chain_names(opt_out) {
        let hash = nsec3_hash(&name, salt, iterations)
            .map_err(|e| DnssecError::key(format!("hashing {name} for the NSEC3 chain: {e}")))?;
        hashed.push((hash, name));
    }
    hashed.sort();

    // Two names hashing alike would make one of them undeniable and the other
    // unprovable, and the chain would silently be a lie about one of them. It
    // takes a SHA-1 collision to happen, but the check is one comparison.
    if let Some(window) = hashed.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(DnssecError::signing(format!(
            "{} and {} have the same NSEC3 hash — pick a different salt",
            window[0].1, window[1].1,
        )));
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
        .map_err(|e| DnssecError::key(format!("encoding an NSEC3: {e}")))?;
        signed.add_record(ZoneRecord {
            name: format!(
                "{}.{}",
                base32hex_encode(hash).to_lowercase(),
                layout.origin
            ),
            ttl,
            class: Class::new(1),
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
    RecordData::new(rt::NSEC3PARAM, rdata).expect("an NSEC3PARAM we just built decodes")
}

// ---------------------------------------------------------------------------
// The signatures
// ---------------------------------------------------------------------------

fn sign_everything(
    layout: &Layout,
    keys: &[SigningKey],
    policy: &SigningPolicy,
    previous: Option<&PreviousSignatures>,
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
    let mut rrsets: BTreeMap<(String, Rtype), (Ttl, Vec<RecordData>)> = BTreeMap::new();
    for record in signed.records() {
        let name = record.name.to_ascii_lowercase();
        let entry = rrsets
            .entry((name, record.rdata.rtype()))
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

        // Unchanged since the last run, and signed by exactly these keys: keep
        // what is there. This is the whole of the incremental path — the RRset
        // is not re-signed, so its RDATA does not move, so it does not appear in
        // the next IXFR delta.
        if let Some(previous) = previous {
            let tags: Vec<u16> = signers.iter().map(|k| k.key_tag()).collect();
            if let Some(carried) =
                previous.reuse(&name, rtype, ttl, &rdatas, &tags, policy.signed_at)
            {
                for signature in carried {
                    signatures.push(ZoneRecord {
                        name: name.clone(),
                        ttl,
                        class: Class::new(1),
                        rdata: signature.rdata.clone(),
                    });
                }
                continue;
            }
        }

        let original_ttl = ttl.as_secs();
        let rrset = Rrset::new(&name, rtype, Class::new(1), &rdatas);
        // Spread this RRset's expiry back from the window's end, so the zone
        // degrades over a slope rather than expiring as one cliff. Deterministic
        // per (owner, type) — see `SigningPolicy::expiry_for`.
        let expiration = policy.expiry_for(&name, rtype);
        for key in signers.iter() {
            let sig = key
                .sign_rrset(&rrset, original_ttl, policy.inception, expiration)
                .map_err(|e| {
                    DnssecError::key(format!("signing the {rtype} RRset at {name}: {e}"))
                })?;
            signatures.push(ZoneRecord {
                name: name.clone(),
                ttl,
                class: Class::new(1),
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

    for signature in signatures {
        signed.add_record(signature);
    }
    Ok(())
}

/// Whether this RRset is one the zone is authoritative for, and so must sign.
fn signable(entry: &NameEntry, name: &str, rtype: Rtype, origin: &str) -> bool {
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

    // -----------------------------------------------------------------
    // Re-signing: the serial, the jitter, and when to do it again
    // -----------------------------------------------------------------

    /// Every RRSIG in a zone used to be given the same expiration, so the whole
    /// zone expired in the same second — which is *why* the failure this guards
    /// against is "every validating resolver SERVFAILs the entire zone at once".
    /// Spread turns the cliff into a slope.
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

    /// Deterministic, not random. A reload re-signs, and random jitter would put
    /// every name at a different point on the slope each time — so the slope
    /// would be a different slope on every reload, and two servers holding the
    /// same zone would never agree about it.
    #[test]
    fn the_spread_is_deterministic_for_a_given_name_and_type() {
        let policy = policy(DenialChain::Nsec);
        let first = policy.expiry_for("www.example.com.", rt::A);
        assert_eq!(first, policy.expiry_for("www.example.com.", rt::A));
        assert_ne!(
            first,
            policy.expiry_for("www.example.com.", rt::AAAA),
            "a different type at the same name sits elsewhere on the slope"
        );
        assert_ne!(first, policy.expiry_for("mail.example.com.", rt::A));
        assert_eq!(
            first,
            policy.expiry_for("WWW.EXAMPLE.COM.", rt::A),
            "case folds, like every other name comparison here (RFC 4343)"
        );
    }

    /// A zone with a validity too short to spread across still signs, rather
    /// than dividing by zero or producing an expiry before inception.
    #[test]
    fn a_validity_too_short_to_spread_still_signs() {
        let policy = SigningPolicy::valid_for(NOW, 2);
        assert_eq!(
            policy.expiry_for("www.example.com.", rt::A),
            policy.expiration
        );
        let zone = parse_zone_file(ZONE, ORIGIN).expect("parses");
        let signed = sign_zone(&zone, &keys(), &policy).expect("signs");
        for sig in rrsigs_in(&resources(&signed)) {
            assert!(sig.expiration > sig.inception);
        }
    }

    /// New signatures are a new version of the zone as far as a secondary is
    /// concerned, and a secondary decides whether to transfer by comparing
    /// serials — so without a bump the replica keeps signatures that then expire
    /// underneath it. The bump has to survive a restart without being persisted,
    /// which is why it is derived from the clock.
    #[test]
    fn signing_moves_the_soa_serial_and_keeps_moving_it() {
        let unsigned = parse_zone_file(ZONE, ORIGIN).expect("parses");
        let file_serial = unsigned.serial().expect("the file has a serial");
        assert_eq!(file_serial, Serial::new(2024051300));

        let first = sign_zone(&unsigned, &keys(), &policy(DenialChain::Nsec)).expect("signs");
        let first_serial = first.serial().expect("still has one");
        assert_ne!(
            first_serial, file_serial,
            "the served serial is not the file's — new signatures are a new version"
        );

        // Signing the same file later gives a *higher* serial, and signing it
        // again at the same moment gives the same one. Both matter: the first is
        // what makes a secondary transfer, the second is what stops a restart
        // from looking like a change.
        let later = SigningPolicy::valid_for(NOW + 7 * 86_400, 30 * 86_400);
        let later_serial = sign_zone(&unsigned, &keys(), &later)
            .expect("signs")
            .serial()
            .expect("has a serial");
        assert!(
            later_serial.is_newer_than(first_serial),
            "{later_serial} must be newer than {first_serial} by RFC 1982"
        );
        let again = sign_zone(&unsigned, &keys(), &policy(DenialChain::Nsec))
            .expect("signs")
            .serial()
            .expect("has a serial");
        assert_eq!(again, first_serial, "same file, same moment, same serial");
    }

    /// The correction that made this design work: `max(file, time)` would keep a
    /// date-style serial forever, because `2024051300` is numerically far larger
    /// than any current Unix timestamp. PowerDNS documents its `INCEPTION-EPOCH`
    /// as "requiring epoch-based backend serials" for exactly this reason.
    #[test]
    fn a_date_style_serial_still_moves() {
        let date_style = Serial::new(2_026_073_001);
        let signed = signed_serial(date_style, NOW);
        assert!(
            signed.is_newer_than(date_style),
            "{signed} must be newer than {date_style}"
        );
        // Deliberately the *plain* comparison, on the numbers rather than on the
        // serials, and the only place in the tree that unwraps a `Serial` to make
        // one. The claim is arithmetical — the result is larger than the input, so
        // the time term was added and not `max`ed — and `is_newer_than` above
        // cannot carry it, because a wrapped serial would satisfy that too.
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

    /// Re-signing at a third of the validity leaves two whole windows of slack:
    /// a run that fails, or a server down over one, still has two more chances
    /// before anything expires.
    #[test]
    fn re_signing_is_due_well_before_anything_expires() {
        let validity = 30 * 86_400;
        let policy = SigningPolicy::valid_for(NOW, validity);
        let due = policy.resign_at();
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
    fn rrsets(zone: &Zone) -> BTreeMap<(String, Rtype), Vec<RecordData>> {
        let mut out: BTreeMap<(String, Rtype), Vec<RecordData>> = BTreeMap::new();
        for record in zone.records() {
            out.entry((record.name.clone(), record.rdata.rtype()))
                .or_default()
                .push(record.rdata.clone());
        }
        out
    }

    fn proof_for(zone: &Zone, name: &str, rtype: Rtype) -> RrsetProof {
        let rdatas: Vec<RecordData> = zone
            .query(name, Qtype::of(rtype))
            .iter()
            .map(|r| r.rdata.clone())
            .collect();
        assert!(!rdatas.is_empty(), "no records of type {rtype} at {name}");
        let sigs: Vec<_> = rrsigs_in(&resources(zone))
            .into_iter()
            .filter(|s| s.owner == canonical_name(name))
            .collect();
        verify_rrset(
            &Rrset::new(name, rtype, Class::new(1), &rdatas),
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
                &Rrset::new(&name, rtype, Class::new(1), &rdatas),
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
            !zone
                .query("ns.secure.example.com.", Qtype::of(rt::A))
                .is_empty(),
            "glue has to still be there to hand out"
        );
        assert!(matches!(
            proof_for(&zone, "ns.secure.example.com.", rt::A),
            RrsetProof::Unsigned
        ));
        assert!(
            zone.query("ns.secure.example.com.", Qtype::of(rt::NSEC))
                .is_empty(),
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

    /// Every denial record's bitmap must list every type actually at the name it
    /// describes (RFC 5155 §7.1, RFC 4034 §4.1.2) — checked over the whole zone,
    /// because the class of bug is "a record was added after the layout was
    /// taken" and it can happen at any name.
    ///
    /// It happened at the apex, with NSEC3PARAM. The type was inserted after
    /// `Layout::of` snapshotted the zone, so the apex NSEC3 said NSEC3PARAM was
    /// absent while an NSEC3PARAM record sat at the apex, signed. That is a zone
    /// `dnssec-verify`, `ldns-verify-zone` and `validns` all reject — and worse
    /// than a lint failure: a validator asking for the type gets a *signed*
    /// NODATA proof for a record it is also being served, and an RFC 8198
    /// aggressive-NSEC resolver then synthesizes that false NODATA for other
    /// clients out of its cache.
    #[test]
    fn every_bitmap_lists_every_type_at_the_name_it_describes() {
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = sign_test_zone(chain.clone());
            let layout = Layout::of(&zone, ORIGIN);
            let (nsecs, nsec3s) = chain_records(&zone);

            for (name, entry) in &layout.names {
                if entry.occluded {
                    continue;
                }
                if entry.types.contains(&rt::NSEC3) {
                    // An NSEC3's own owner name is invented by the hash. It is
                    // not a name of the zone and nothing describes it.
                    continue;
                }
                let mut expected = entry.published_types();
                // The record that describes a name is not itself at it under
                // NSEC3 — the chain lives at hashed names — so NSEC3 is never
                // in the bitmap, while NSEC always is.
                expected.remove(&rt::NSEC3);

                let lists: Box<dyn Fn(Rtype) -> bool> = match &chain {
                    DenialChain::Nsec => {
                        let Some(nsec) = nsecs.iter().find(|n| &n.owner == name) else {
                            panic!("{chain:?}: no NSEC at {name}");
                        };
                        Box::new(move |rtype| nsec.has_type(rtype))
                    }
                    DenialChain::Nsec3 {
                        salt, iterations, ..
                    } => {
                        let hash = nsec3_hash(name, salt, *iterations).unwrap();
                        let owner = format!("{}.{ORIGIN}", base32hex_encode(&hash).to_lowercase());
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

    /// The apex specifically, spelled out, because the NSEC3PARAM case is the one
    /// that was wrong and a reader should be able to see it named.
    #[test]
    fn the_apex_nsec3_lists_nsec3param() {
        let zone = sign_test_zone(DenialChain::nsec3());
        assert_eq!(
            zone.query(ORIGIN, Qtype::of(rt::NSEC3PARAM)).len(),
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
        let hash = nsec3_hash(ORIGIN, &salt, iterations).unwrap();
        let owner = format!("{}.{ORIGIN}", base32hex_encode(&hash).to_lowercase());
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
            // written in the file gets wrong. That is also what puts them out
            // of the apex wildcard's reach, and the distinction matters:
            // synthesis is not limited to one label (RFC 4592 §3.3.2), it is
            // limited to the closest encloser (§3.3.1). `a.b.example.com.`
            // exists as an empty non-terminal, so the source of synthesis for
            // `x.a.b.example.com.` would have to be `*.a.b.example.com.`, and
            // there is none. A name the wildcard *does* reach is not deniable
            // at all, which is what the wildcard test checks from the other
            // side.
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
            .query("*.example.com.", Qtype::of(rt::A))
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
            &Rrset::new("anything.example.com.", rt::A, Class::new(1), &rdatas),
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
        let params = zone.query(ORIGIN, Qtype::of(rt::NSEC3PARAM));
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

        let matched = |name: &str| nsec3s.iter().any(|n| n.matches(name).unwrap_or(false));
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
        let tags = |name: &str, rtype: Rtype| -> Vec<u16> {
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

    /// **A one-record UPDATE to a signed zone currently produces a whole-zone
    /// IXFR delta**, and this measures it rather than describing it.
    ///
    /// Every RRSIG's inception and expiration derive from the signing run's
    /// `signed_at` ([`SigningPolicy::valid_for`]), so two runs a minute apart
    /// produce different RDATA for *every* signature in the zone. `ixfr::diff`
    /// compares whole records, correctly, so all of them land in the delta —
    /// and the one A record the client actually added is lost among them.
    ///
    /// Measured here: a 53-record zone with 23 RRSIGs, one record added, and a
    /// delta of **52 records**. That is the whole zone, one short of the
    /// threshold at which `ixfr_response` would give up and send an AXFR
    /// instead — so a secondary receives an "incremental" transfer the size of a
    /// full one, and `DeltaLog` keeps 32 of them per zone.
    ///
    /// **This is a characterization test, not a regression test** (`CLAUDE.md`
    /// §10 — say what a test is and what it is not). It asserts what the code
    /// does today so that the number moves visibly when incremental re-signing
    /// lands (`TODO.md` #10); it is not asserting that this behaviour is
    /// correct, and the assertion below is written to *fail* once the fix
    /// arrives rather than to quietly keep passing.
    #[test]
    fn re_signing_after_an_update_currently_rewrites_every_signature() {
        use crate::ixfr::diff;

        let keys = keys();
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        let before = sign_zone(&zone, &keys, &policy(DenialChain::Nsec)).unwrap();

        // The smallest possible update: one A record, and the §3.6 serial bump.
        let updated = crate::update::apply(
            &zone,
            &[crate::update::Change::Add(ResourceRecord {
                name: "new.example.com.".to_string(),
                class: Class::new(1),
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

        // And the fix, measured against the same case: signing incrementally
        // carries every untouched signature forward, so the delta collapses to
        // the records that actually moved plus the denial chain around them.
        let incremental =
            sign_zone_incrementally(&before, &updated.zone, &keys, &later).expect("signs");
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
                    || r.name == "new.example.com."
                    || r.name == ORIGIN
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
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>()
        );
    }

    /// The incremental path must still produce a zone that *verifies*, which is
    /// the assertion that matters: carrying a signature forward is only sound if
    /// it still covers what it says it covers.
    ///
    /// Judged with `proof_for` — the same code that judges a real zone off the
    /// internet — rather than by comparing our output to our own expectations
    /// (`CLAUDE.md` §1).
    #[test]
    fn an_incrementally_signed_zone_still_verifies() {
        let keys = keys();
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        let before = sign_zone(&zone, &keys, &policy(DenialChain::Nsec)).unwrap();

        let updated = crate::update::apply(
            &zone,
            &[crate::update::Change::Add(ResourceRecord {
                name: "new.example.com.".to_string(),
                class: Class::new(1),
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.77".parse().unwrap()))
                    .unwrap(),
            })],
        );
        let later = SigningPolicy::valid_for(NOW + 60, 30 * 86_400).with_chain(DenialChain::Nsec);
        let signed = sign_zone_incrementally(&before, &updated.zone, &keys, &later).unwrap();

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
        let keys = keys();
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        let before = sign_zone(&zone, &keys, &policy(DenialChain::Nsec)).unwrap();
        let later = SigningPolicy::valid_for(NOW + 60, 30 * 86_400).with_chain(DenialChain::Nsec);

        let sig_at = |z: &Zone, name: &str, covered: Rtype| -> Vec<RecordData> {
            z.records()
                .iter()
                .filter(|r| {
                    r.name == name
                        && r.rdata.rtype() == rt::RRSIG
                        && matches!(
                            r.rdata.parse(),
                            Ok(ParsedRecord::RRSIG { type_covered, .. }) if type_covered == covered
                        )
                })
                .map(|r| r.rdata.clone())
                .collect()
        };

        // A record added to an existing RRset: its signature must be remade.
        let mut grown = zone.clone();
        grown.add_record(ZoneRecord {
            name: "www.example.com.".to_string(),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A("192.0.2.88".parse().unwrap()))
                .unwrap(),
        });
        let signed = sign_zone_incrementally(&before, &grown, &keys, &later).unwrap();
        assert_ne!(
            sig_at(&signed, "www.example.com.", rt::A),
            sig_at(&before, "www.example.com.", rt::A),
            "an RRset that gained a record is signed afresh"
        );

        // A TTL change with the same RDATA. The RRSIG stores the original TTL
        // (RFC 4034 §3.1.3), so keeping the old signature would publish one
        // covering a TTL the RRset no longer has.
        let retimed = crate::update::apply(
            &zone,
            &[crate::update::Change::Add(ResourceRecord {
                name: "www.example.com.".to_string(),
                class: Class::new(1),
                ttl: Ttl::from_secs(60),
                rdata: zone.query("www.example.com.", Qtype::of(rt::A))[0]
                    .rdata
                    .clone(),
            })],
        );
        let signed = sign_zone_incrementally(&before, &retimed.zone, &keys, &later).unwrap();
        assert_ne!(
            sig_at(&signed, "www.example.com.", rt::A),
            sig_at(&before, "www.example.com.", rt::A),
            "a TTL change is a change: the RRSIG carries the original TTL"
        );

        // A key added — the start of a rollover. Every RRset the new key must
        // also sign has to be signed afresh, or the zone publishes a DNSKEY
        // whose signatures are missing.
        let mut rolling = keys;
        rolling.push(
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                .unwrap(),
        );
        let signed = sign_zone_incrementally(&before, &zone, &rolling, &later).unwrap();
        assert_eq!(
            sig_at(&signed, "www.example.com.", rt::A).len(),
            2,
            "both zone-signing keys now sign it"
        );
    }

    #[test]
    fn re_signing_replaces_the_previous_run_rather_than_stacking_on_it() {
        // The same keys both times. Signing again with *different* keys keeps
        // the old DNSKEYs on purpose — that is a rollover, not a mistake.
        let keys = keys();
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
        let mut zone = Zone::new(ORIGIN.to_string());
        zone.add_record(ZoneRecord {
            name: "www.example.com.".to_string(),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
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

        for record in zone.query("www.example.com.", Qtype::of(rt::A)) {
            assert_eq!(record.ttl, Ttl::from_secs(60));
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
