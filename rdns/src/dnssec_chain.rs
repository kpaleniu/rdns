//! The chain of trust: trust anchors, and the walk from one down to an answer.
//!
//! ```text
//! root DNSKEY, vouched for by a trust anchor we ship
//!   → the KSK signs the root's DNSKEY RRset, so the whole set is trusted
//!   → the root signs a DS for com., which is the hash of com.'s KSK
//!   → com.'s KSK signs com.'s DNSKEY RRset
//!   → … repeat at every zone cut …
//!   → the last zone's ZSK signs the answer
//! ```
//!
//! Everything here is synchronous and takes the records as arguments: fetching
//! them means asking servers, which is the resolver's job, not this module's.
//! The resolver drives the loop and calls in at each step.
//!
//! The outcome is one of four states, and the difference between two of them is
//! the whole point. **Insecure** means the chain legitimately ends — some zone
//! along the way proved it has no DS, so nothing below it is signed and there
//! is nothing to check. **Bogus** means the chain was supposed to continue and
//! did not: a signature that failed, a DS with no matching key, a missing proof.
//! Most of the internet is insecure and must keep resolving; bogus is an attack
//! or a broken zone and must not be served.

use crate::dnssec::{
    algorithm_supported, canonical_name, digest_type_supported, label_count, verify_rrset, Dnskey,
    Ds, Rrset, RrsetProof, Rrsig,
};
use crate::dnssec_denial::{
    proves_no_ds, proves_wildcard_expansion, Denial, Nsec, Nsec3, WildcardVerdict,
};
use crate::utils::record_types as rt;
use crate::{ParsedRecord, RecordData, ResourceRecord};
use crate::error::DnssecError;
use std::collections::HashMap;

/// How much authentication an answer carries (RFC 4035 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationState {
    /// Signed, and every signature verified up to a trust anchor. This is the
    /// only state that earns the AD bit.
    Secure,
    /// Provably unsigned: some zone on the path proved it has no DS. The
    /// ordinary case for most of the internet — serve it, without AD.
    Insecure,
    /// Signed, but the signatures do not add up. Withhold it: SERVFAIL is the
    /// correct answer, because handing over data we know to be unverifiable is
    /// worse than handing over nothing.
    Bogus(String),
    /// We have no trust anchor covering this name, so there is no chain to
    /// walk. Treated like insecure when serving, but it is a different fact:
    /// insecure was *proven*, this was never in scope.
    Indeterminate(String),
}

impl ValidationState {
    pub fn is_secure(&self) -> bool {
        matches!(self, ValidationState::Secure)
    }

    pub fn is_bogus(&self) -> bool {
        matches!(self, ValidationState::Bogus(_))
    }

    /// A short reason, for logging a refusal.
    pub fn reason(&self) -> &str {
        match self {
            ValidationState::Secure => "secure",
            ValidationState::Insecure => "insecure (provably unsigned)",
            ValidationState::Bogus(why) | ValidationState::Indeterminate(why) => why,
        }
    }
}

impl std::fmt::Display for ValidationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationState::Secure => write!(f, "secure"),
            ValidationState::Insecure => write!(f, "insecure"),
            ValidationState::Bogus(why) => write!(f, "bogus: {why}"),
            ValidationState::Indeterminate(why) => write!(f, "indeterminate: {why}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Trust anchors
// ---------------------------------------------------------------------------

/// The keys we trust a priori, in DS form.
///
/// DS rather than DNSKEY on purpose: an anchor is a commitment to a key, and
/// holding the hash means a zone can publish a new key under the same anchor
/// without us shipping a new build. It is also the form IANA publishes.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    anchors: Vec<Ds>,
}

/// The ICANN root zone KSK (KSK-2017, key tag 20326) as a SHA-256 DS.
///
/// Compiled in as a fallback so a fresh install validates without
/// configuration, which is the whole reason to hardcode anything. It is also
/// why `--trust-anchor` exists: the root KSK does roll over, and when it does a
/// build shipped before the roll is wrong until it is rebuilt. A file beats a
/// rebuild, and a file plus this fallback beats a file alone.
const ICANN_ROOT_DS: &str =
    ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

impl TrustAnchors {
    pub fn new(anchors: Vec<Ds>) -> Self {
        TrustAnchors { anchors }
    }

    /// The built-in root anchor.
    pub fn icann_root() -> Self {
        Self::parse(ICANN_ROOT_DS).expect("the compiled-in root anchor must parse")
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    pub fn all(&self) -> &[Ds] {
        &self.anchors
    }

    /// Parse anchors in DS presentation format, one per line:
    ///
    /// ```text
    /// ; comments start with a semicolon (or a hash)
    /// . IN DS 20326 8 2 E06D44B8...
    /// example.test. DS 12345 13 2 ABCD...
    /// ```
    ///
    /// The class is optional, as it is in a zone file. A line that does not
    /// parse is an error rather than a skip: a trust anchor file with a typo in
    /// it should stop the process, not quietly leave us trusting less than the
    /// operator intended.
    pub fn parse(text: &str) -> Result<Self, DnssecError> {
        let mut anchors = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split(';').next().unwrap_or("");
            let line = line.split('#').next().unwrap_or("");
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            anchors.push(parse_ds_line(line).map_err(|e| {
                DnssecError::parse(format!(
                    "trust anchor line {}: {e} in {:?}",
                    lineno + 1,
                    raw.trim(),
                ))
            })?);
        }
        if anchors.is_empty() {
            return Err(DnssecError::parse("no DS records found"));
        }
        Ok(TrustAnchors { anchors })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, DnssecError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| DnssecError::parse(format!(
                "reading trust anchors {}: {e}",
                path.display(),
            )))?;
        Self::parse(&text).map_err(|e| DnssecError::parse(format!(
            "{}: {e}",
            path.display(),
        )))
    }

    /// The anchors published exactly at `zone`.
    pub fn for_zone(&self, zone: &str) -> Vec<Ds> {
        let zone = canonical_name(zone);
        self.anchors
            .iter()
            .filter(|ds| ds.owner == zone)
            .cloned()
            .collect()
    }

    /// The deepest anchored zone at or above `name` — where a chain walk for
    /// that name has to start. `None` means the name is outside every island of
    /// trust we hold, which is [`ValidationState::Indeterminate`].
    pub fn deepest_enclosing(&self, name: &str) -> Option<String> {
        let name = canonical_name(name);
        self.anchors
            .iter()
            .filter(|ds| is_at_or_below(&name, &ds.owner))
            .max_by_key(|ds| label_count(&ds.owner))
            .map(|ds| ds.owner.clone())
    }
}

/// One `owner [class] DS key_tag algorithm digest_type digest` line.
fn parse_ds_line(line: &str) -> Result<Ds, DnssecError> {
    let mut tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 6 {
        return Err(DnssecError::parse(format!(
            "expected at least 6 fields, got {}",
            tokens.len(),
        )));
    }
    let owner = canonical_name(tokens.remove(0));
    // A TTL and a class may sit between the owner and the type keyword, in
    // either order and either optional — the same latitude a zone file gives.
    let mut skipped = 0;
    while !tokens.is_empty() && !tokens[0].eq_ignore_ascii_case("DS") && skipped < 2 {
        tokens.remove(0);
        skipped += 1;
    }
    if tokens.is_empty() || !tokens[0].eq_ignore_ascii_case("DS") {
        return Err(DnssecError::parse(format!(
            "expected the DS type keyword, found {:?}",
            tokens.first(),
        )));
    }
    tokens.remove(0);
    if tokens.len() < 4 {
        return Err(DnssecError::parse("DS needs key tag, algorithm, digest type and digest"));
    }

    let key_tag: u16 = tokens[0].parse().map_err(|_| DnssecError::parse(format!(
        "bad key tag {:?}",
        tokens[0],
    )))?;
    let algorithm: u8 = tokens[1]
        .parse()
        .map_err(|_| DnssecError::parse(format!(
            "bad algorithm {:?}",
            tokens[1],
        )))?;
    let digest_type: u8 = tokens[2]
        .parse()
        .map_err(|_| DnssecError::parse(format!(
            "bad digest type {:?}",
            tokens[2],
        )))?;
    // The digest may be split across whitespace, as it is in IANA's own file.
    let hex: String = tokens[3..].concat();
    if !hex.len().is_multiple_of(2) {
        return Err(DnssecError::parse("digest has an odd number of hex characters"));
    }
    let digest = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| DnssecError::parse("digest is not hexadecimal"))?;

    Ok(Ds {
        owner,
        key_tag,
        algorithm,
        digest_type,
        digest,
    })
}

/// Whether `name` is at or below `ancestor`.
fn is_at_or_below(name: &str, ancestor: &str) -> bool {
    let name = canonical_name(name);
    let ancestor = canonical_name(ancestor);
    ancestor == "." || name == ancestor || name.ends_with(&format!(".{ancestor}"))
}

// ---------------------------------------------------------------------------
// What a delegation told us
// ---------------------------------------------------------------------------

/// Everything a referral said about whether the child zone is signed.
///
/// Collected while walking the delegation chain, because that is the only
/// moment the parent's side of the cut is in front of us: ask the child for its
/// own DS afterwards and the child gets to answer a question about itself.
#[derive(Debug, Clone, Default)]
pub struct DelegationEvidence {
    /// The child zone being delegated to.
    pub zone: String,
    /// The DS RRset from the parent's authority section, if any.
    pub ds: Vec<Ds>,
    /// The signatures over that DS RRset.
    pub rrsigs: Vec<Rrsig>,
    /// NSEC records offered instead, when there is no DS.
    pub nsecs: Vec<Nsec>,
    /// NSEC3 records offered instead, when there is no DS.
    pub nsec3s: Vec<Nsec3>,
    /// The class the records came in.
    pub class: u16,
}

impl DelegationEvidence {
    /// Read a referral's authority section for everything bearing on the
    /// child's security.
    pub fn from_authority(zone: &str, authorities: &[ResourceRecord]) -> Self {
        let zone = canonical_name(zone);
        let relevant: Vec<&ResourceRecord> = authorities
            .iter()
            .filter(|rr| canonical_name(&rr.name) == zone)
            .collect();
        DelegationEvidence {
            class: relevant.first().map(|rr| rr.class).unwrap_or(1),
            ds: relevant.iter().filter_map(|rr| Ds::from_record(rr)).collect(),
            rrsigs: authorities.iter().filter_map(Rrsig::from_record).collect(),
            nsecs: authorities.iter().filter_map(Nsec::from_record).collect(),
            nsec3s: authorities.iter().filter_map(Nsec3::from_record).collect(),
            zone,
        }
    }
}

/// What checking a delegation established about the child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationVerdict {
    /// The parent published a DS we verified: the child must be signed, and
    /// these are the keys it has to match.
    Secure(Vec<Ds>),
    /// The parent proved there is no DS, or published only DS records naming
    /// algorithms we cannot verify. Either way the chain ends here.
    Insecure(String),
    /// The parent's statement about the child does not hold up.
    Bogus(String),
}

/// The keys established for each zone so far, keyed by canonical zone name.
pub type KeyStore = HashMap<String, Vec<Dnskey>>;

/// An RRset that turned out to have been synthesized from a wildcard.
///
/// Kept rather than discarded because verifying its signature is only half of
/// what RFC 4035 §5.3.4 asks: the other half is a denial, and the records that
/// carry it are in a different section of the response from the ones that were
/// just checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WildcardExpansion {
    /// The name the records were served at.
    pub owner: String,
    /// The wildcard they were really signed at — `*.example.com.`.
    pub wildcard: String,
    /// The zone that signed them, and therefore the only zone whose denial of
    /// `owner` counts.
    pub signer: String,
}

/// What validating a set of records established.
///
/// `state` is not the whole verdict on its own: a `Secure` state alongside a
/// non-empty `wildcards` means every signature checked out *and* one or more
/// answers still owe a proof that the name they were served at does not exist
/// (RFC 4035 §5.3.4). [`ChainValidator::validate_wildcard_proofs`] settles that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordsVerdict {
    pub state: ValidationState,
    pub wildcards: Vec<WildcardExpansion>,
}

impl RecordsVerdict {
    fn state(state: ValidationState) -> Self {
        RecordsVerdict {
            state,
            wildcards: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// The validator
// ---------------------------------------------------------------------------

pub struct ChainValidator<'a> {
    anchors: &'a TrustAnchors,
    now: u64,
}

impl<'a> ChainValidator<'a> {
    pub fn new(anchors: &'a TrustAnchors, now: u64) -> Self {
        ChainValidator { anchors, now }
    }

    /// Where a walk for `name` starts, and with what DS records.
    pub fn start(&self, name: &str) -> Option<(String, Vec<Ds>)> {
        let zone = self.anchors.deepest_enclosing(name)?;
        let ds = self.anchors.for_zone(&zone);
        Some((zone, ds))
    }

    /// Establish a zone's DNSKEY set from the DS records that commit to it.
    ///
    /// The DS decides which key is allowed to sign the DNSKEY RRset; that
    /// signature then extends trust to *every* key in the set, which is how a
    /// zone can use a separate ZSK for its data without publishing a DS for it.
    /// Skipping the signature check and simply trusting each key the DS names
    /// would work for the KSK and quietly trust an attacker's injected ZSK.
    pub fn validate_dnskeys(
        &self,
        zone: &str,
        records: &[ResourceRecord],
        ds_set: &[Ds],
    ) -> Result<Vec<Dnskey>, ValidationState> {
        let zone = canonical_name(zone);

        let keys: Vec<Dnskey> = records
            .iter()
            .filter_map(Dnskey::from_record)
            .filter(|k| k.owner == zone)
            .collect();
        if keys.is_empty() {
            return Err(ValidationState::Bogus(format!(
                "{zone} has a DS in its parent but published no DNSKEY"
            )));
        }

        // A DS naming only algorithms or digests we cannot compute leaves us
        // unable to judge — insecure, not bogus (RFC 4035 §5.2).
        if !ds_set
            .iter()
            .any(|ds| algorithm_supported(ds.algorithm) && digest_type_supported(ds.digest_type))
        {
            return Err(ValidationState::Insecure);
        }

        // Which of the published keys the parent actually vouched for.
        let mut vouched: Vec<Dnskey> = Vec::new();
        for ds in ds_set {
            if !algorithm_supported(ds.algorithm) || !digest_type_supported(ds.digest_type) {
                continue;
            }
            for key in &keys {
                if key.is_zone_key() && ds.matches_key(key).unwrap_or(false) {
                    vouched.push(key.clone());
                }
            }
        }
        if vouched.is_empty() {
            return Err(ValidationState::Bogus(format!(
                "no DNSKEY at {zone} matches any DS its parent published"
            )));
        }

        let rdatas: Vec<RecordData> = records
            .iter()
            .filter(|rr| rr.rdata.rtype == rt::DNSKEY && canonical_name(&rr.name) == zone)
            .map(|rr| rr.rdata.clone())
            .collect();
        let class = records.first().map(|rr| rr.class).unwrap_or(1);
        let rrsigs: Vec<Rrsig> = records.iter().filter_map(Rrsig::from_record).collect();

        match verify_rrset(
            &Rrset::new(&zone, rt::DNSKEY, class, &rdatas),
            &rrsigs,
            &vouched,
            &zone,
            self.now,
        ) {
            RrsetProof::Verified { .. } => Ok(keys),
            RrsetProof::Unsigned => Err(ValidationState::Bogus(format!(
                "the DNSKEY RRset at {zone} is unsigned, but its parent published a DS"
            ))),
            // Signed with something we cannot read: no opinion, so the chain
            // ends here rather than condemning the zone.
            RrsetProof::Unsupported(_) => Err(ValidationState::Insecure),
            RrsetProof::Bogus(why) => Err(ValidationState::Bogus(format!(
                "the DNSKEY RRset at {zone} did not verify under its DS-vouched key: {why}"
            ))),
        }
    }

    /// Check what a referral said about its child, using the parent's keys.
    pub fn validate_delegation(
        &self,
        evidence: &DelegationEvidence,
        parent_zone: &str,
        parent_keys: &[Dnskey],
    ) -> DelegationVerdict {
        let parent_zone = canonical_name(parent_zone);

        if evidence.ds.is_empty() {
            // No DS: the parent must *prove* that, or an attacker who simply
            // deletes the DS records from a referral turns a signed zone into
            // an unsigned one. That is why the proof is mandatory here rather
            // than best-effort.
            if let Denial::NotProved(why) =
                proves_no_ds(&evidence.zone, &evidence.nsecs, &evidence.nsec3s)
            {
                return DelegationVerdict::Bogus(format!(
                    "{} has no DS and its parent did not prove it: {why}",
                    evidence.zone
                ));
            }
            // The proof itself is a signed RRset and has to be verified as one,
            // otherwise it is just bytes an attacker supplied.
            return match self.verify_denial_records(evidence, &parent_zone, parent_keys) {
                Ok(()) => {
                    DelegationVerdict::Insecure(format!("{} is provably unsigned", evidence.zone))
                }
                Err(ValidationState::Insecure) => {
                    DelegationVerdict::Insecure(format!("{} could not be judged", evidence.zone))
                }
                Err(other) => DelegationVerdict::Bogus(other.reason().to_string()),
            };
        }

        // There is a DS. It lives in the parent zone, so the parent's keys sign
        // it — and it must be signed, or anyone could inject one.
        let rdatas: Vec<RecordData> = evidence
            .ds
            .iter()
            .map(|ds| {
                RecordData::from_parsed(&crate::ParsedRecord::DS {
                    key_tag: ds.key_tag,
                    algorithm: ds.algorithm,
                    digest_type: ds.digest_type,
                    digest: ds.digest.clone(),
                })
                .expect("a DS we parsed must re-encode")
            })
            .collect();

        match verify_rrset(
            &Rrset::new(&evidence.zone, rt::DS, evidence.class, &rdatas),
            &evidence.rrsigs,
            parent_keys,
            &parent_zone,
            self.now,
        ) {
            RrsetProof::Verified { .. } => DelegationVerdict::Secure(evidence.ds.clone()),
            RrsetProof::Unsigned => DelegationVerdict::Bogus(format!(
                "the DS at {} is unsigned, inside the signed zone {parent_zone}",
                evidence.zone
            )),
            RrsetProof::Unsupported(why) => DelegationVerdict::Insecure(why),
            RrsetProof::Bogus(why) => DelegationVerdict::Bogus(format!(
                "the DS at {} did not verify: {why}",
                evidence.zone
            )),
        }
    }

    /// Verify whatever NSEC/NSEC3 records carried a no-DS proof.
    fn verify_denial_records(
        &self,
        evidence: &DelegationEvidence,
        parent_zone: &str,
        parent_keys: &[Dnskey],
    ) -> Result<(), ValidationState> {
        // Rebuild the RRsets from the typed views we kept, and check each one.
        // A proof nobody signed proves nothing.
        let mut checked_any = false;
        for (owner, rtype, rdatas) in denial_rrsets(evidence) {
            match verify_rrset(
                &Rrset::new(&owner, rtype, evidence.class, &rdatas),
                &evidence.rrsigs,
                parent_keys,
                parent_zone,
                self.now,
            ) {
                RrsetProof::Verified { .. } => checked_any = true,
                RrsetProof::Unsupported(_) => return Err(ValidationState::Insecure),
                RrsetProof::Unsigned => {
                    return Err(ValidationState::Bogus(format!(
                        "the denial of a DS at {} is unsigned",
                        evidence.zone
                    )))
                }
                RrsetProof::Bogus(why) => {
                    return Err(ValidationState::Bogus(format!(
                        "the denial of a DS at {} did not verify: {why}",
                        evidence.zone
                    )))
                }
            }
        }
        if checked_any {
            Ok(())
        } else {
            Err(ValidationState::Bogus(format!(
                "nothing signed denies a DS at {}",
                evidence.zone
            )))
        }
    }

    /// Validate every RRset in `records` against the keys established for the
    /// zone that signed it.
    ///
    /// An RRset whose RRSIG names a zone we have no keys for is bogus, not
    /// unsigned: we walked to that zone precisely because it was signed.
    ///
    /// A `Secure` state here is a statement about signatures only. Any RRset
    /// that came from a wildcard is reported in
    /// [`RecordsVerdict::wildcards`] and is not fully validated until its
    /// denial has been checked too.
    pub fn validate_records(&self, records: &[ResourceRecord], keys: &KeyStore) -> RecordsVerdict {
        let rrsigs: Vec<Rrsig> = records.iter().filter_map(Rrsig::from_record).collect();
        let mut validated_any = false;
        let mut wildcards: Vec<WildcardExpansion> = Vec::new();

        for (owner, rtype, class, rdatas) in group_rrsets(records) {
            // Which zone claims to have signed this RRset.
            let signer = rrsigs
                .iter()
                .find(|s| s.owner == owner && s.type_covered == rtype)
                .map(|s| s.signer_name.clone());

            let Some(signer) = signer else {
                return RecordsVerdict::state(ValidationState::Bogus(format!(
                    "{owner} type {rtype} came back unsigned from a signed zone"
                )));
            };
            // A zone may only sign at or below itself.
            if !is_at_or_below(&owner, &signer) {
                return RecordsVerdict::state(ValidationState::Bogus(format!(
                    "{owner} is signed by {signer}, which is not above it"
                )));
            }
            let Some(zone_keys) = keys.get(&signer) else {
                return RecordsVerdict::state(ValidationState::Bogus(format!(
                    "{owner} is signed by {signer}, whose keys were never established"
                )));
            };

            match verify_rrset(
                &Rrset::new(&owner, rtype, class, &rdatas),
                &rrsigs,
                zone_keys,
                &signer,
                self.now,
            ) {
                RrsetProof::Verified { wildcard, .. } => {
                    validated_any = true;
                    if let Some(wildcard) = wildcard {
                        wildcards.push(WildcardExpansion {
                            owner: owner.clone(),
                            wildcard,
                            signer: signer.clone(),
                        });
                    }
                }
                RrsetProof::Unsigned => {
                    return RecordsVerdict::state(ValidationState::Bogus(format!(
                        "{owner} type {rtype} is unsigned"
                    )))
                }
                RrsetProof::Unsupported(_) => {
                    return RecordsVerdict::state(ValidationState::Insecure)
                }
                RrsetProof::Bogus(why) => {
                    return RecordsVerdict::state(ValidationState::Bogus(why))
                }
            }
        }

        let state = if validated_any {
            ValidationState::Secure
        } else {
            // Nothing to check — an empty answer. The caller decides whether a
            // denial-of-existence proof is owed.
            ValidationState::Insecure
        };
        RecordsVerdict { state, wildcards }
    }

    /// Check that each wildcard-expanded RRset comes with a signed denial of the
    /// name it was served at (RFC 4035 §5.3.4).
    ///
    /// `proofs` is where the NSEC/NSEC3 records may be found — the authority
    /// section of the response, plus whatever earlier hops of a CNAME chase
    /// carried. They are re-verified here rather than taken on trust: an NSEC an
    /// attacker appended is exactly as easy to append as the answer it excuses,
    /// and only the zone that signed the answer can deny a name in it.
    pub fn validate_wildcard_proofs(
        &self,
        expansions: &[WildcardExpansion],
        proofs: &[ResourceRecord],
        keys: &KeyStore,
    ) -> ValidationState {
        for expansion in expansions {
            let Some(zone_keys) = keys.get(&expansion.signer) else {
                return ValidationState::Bogus(format!(
                    "{} was expanded from {} by {}, whose keys were never established",
                    expansion.owner, expansion.wildcard, expansion.signer
                ));
            };
            let (nsecs, nsec3s) = self.verified_denials(proofs, &expansion.signer, zone_keys);
            match proves_wildcard_expansion(&expansion.owner, &expansion.wildcard, &nsecs, &nsec3s)
            {
                WildcardVerdict::Proved => {}
                // Not a proof, but not an accusation either: serve it without AD.
                WildcardVerdict::Unjudgeable(_) => return ValidationState::Insecure,
                WildcardVerdict::NotProved(why) => {
                    return ValidationState::Bogus(format!(
                        "{} was answered from the wildcard {} without proof that it has no \
                         records of its own: {why}",
                        expansion.owner, expansion.wildcard
                    ))
                }
            }
        }
        ValidationState::Secure
    }

    /// The NSEC and NSEC3 records in `records` that `zone` really signed.
    ///
    /// One that does not verify is dropped rather than reported: it is not
    /// evidence of anything, and dropping it leaves whatever obligation needed
    /// it unmet — a refusal by the same route, with one error path instead of
    /// two. Each record is verified as an RRset of its own, which NSEC and NSEC3
    /// always are (RFC 4034 §4.1.3 allows exactly one per owner name), so a
    /// forged record spliced in beside a genuine one is discarded on its own
    /// rather than invalidating the record it was meant to hide.
    fn verified_denials(
        &self,
        records: &[ResourceRecord],
        zone: &str,
        keys: &[Dnskey],
    ) -> (Vec<Nsec>, Vec<Nsec3>) {
        let rrsigs: Vec<Rrsig> = records.iter().filter_map(Rrsig::from_record).collect();
        let mut nsecs = Vec::new();
        let mut nsec3s = Vec::new();
        for rr in records {
            let rtype = rr.rdata.rtype;
            if rtype != rt::NSEC && rtype != rt::NSEC3 {
                continue;
            }
            let rdatas = [rr.rdata.clone()];
            if !matches!(
                verify_rrset(
                    &Rrset::new(&rr.name, rtype, rr.class, &rdatas),
                    &rrsigs,
                    keys,
                    zone,
                    self.now,
                ),
                RrsetProof::Verified { .. }
            ) {
                continue;
            }
            if let Some(nsec) = Nsec::from_record(rr) {
                nsecs.push(nsec);
            }
            if let Some(nsec3) = Nsec3::from_record(rr) {
                nsec3s.push(nsec3);
            }
        }
        (nsecs, nsec3s)
    }
}

/// Split records into RRsets by (owner, type, class), skipping the RRSIGs
/// themselves — a signature is not an RRset that needs validating, it is what
/// validates one.
pub fn group_rrsets(records: &[ResourceRecord]) -> Vec<(String, u16, u16, Vec<RecordData>)> {
    let mut sets: Vec<(String, u16, u16, Vec<RecordData>)> = Vec::new();
    for rr in records {
        if rr.rdata.rtype == rt::RRSIG || rr.rdata.rtype == crate::OPT_RECORD_TYPE {
            continue;
        }
        let owner = canonical_name(&rr.name);
        match sets
            .iter_mut()
            .find(|(n, t, c, _)| *n == owner && *t == rr.rdata.rtype && *c == rr.class)
        {
            Some((_, _, _, rdatas)) => rdatas.push(rr.rdata.clone()),
            None => sets.push((owner, rr.rdata.rtype, rr.class, vec![rr.rdata.clone()])),
        }
    }
    sets
}

/// The NSEC/NSEC3 RRsets in a delegation's evidence, in the form
/// [`verify_rrset`] wants.
fn denial_rrsets(evidence: &DelegationEvidence) -> Vec<(String, u16, Vec<RecordData>)> {
    let mut out: Vec<(String, u16, Vec<RecordData>)> = Vec::new();
    for nsec in &evidence.nsecs {
        let rdata = RecordData::from_parsed(&crate::ParsedRecord::NSEC {
            next_domain_name: nsec.next.clone(),
            type_bitmap: nsec.type_bitmap.clone(),
        })
        .expect("an NSEC we parsed must re-encode");
        push_rrset(&mut out, &nsec.owner, rt::NSEC, rdata);
    }
    for nsec3 in &evidence.nsec3s {
        let rdata = RecordData::from_parsed(&crate::ParsedRecord::NSEC3 {
            hash_algorithm: nsec3.hash_algorithm,
            flags: nsec3.flags,
            iterations: nsec3.iterations,
            salt: nsec3.salt.clone(),
            next_hashed_owner: nsec3.next_hashed_owner.clone(),
            type_bitmap: nsec3.type_bitmap.clone(),
        })
        .expect("an NSEC3 we parsed must re-encode");
        push_rrset(&mut out, &nsec3.owner, rt::NSEC3, rdata);
    }
    out
}

fn push_rrset(
    out: &mut Vec<(String, u16, Vec<RecordData>)>,
    owner: &str,
    rtype: u16,
    rdata: RecordData,
) {
    let owner = canonical_name(owner);
    match out.iter_mut().find(|(n, t, _)| *n == owner && *t == rtype) {
        Some((_, _, rdatas)) => rdatas.push(rdata),
        None => out.push((owner, rtype, vec![rdata])),
    }
}

// ---------------------------------------------------------------------------
// CNAME chains
// ---------------------------------------------------------------------------

/// How many CNAMEs an answer may chain through before we stop believing it is a
/// chain. RFC 1034 sets no limit; every implementation picks one, because the
/// alternative is following a loop somebody built on purpose.
pub const MAX_CNAME_CHAIN: usize = 16;

/// What the shape of an answer's CNAME chain turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainShape {
    /// The records form the chain the question asked for, ending at `final_name`.
    Intact { final_name: String },
    /// They do not, and this says how.
    Broken(String),
}

/// Whether an answer section really is the CNAME chain the query asked for.
///
/// **Verifying each RRset is not the same as verifying the chain.** Every record
/// here may carry a perfectly good signature from the zone that owns it, and the
/// collection can still be an answer to a different question: a genuine
/// `a.example.com. CNAME b.example.net.` beside a genuine
/// `something-else.example.net. A 6.6.6.6` is two authentic RRsets and no chain
/// at all. A consumer that takes "the A record in the answer" as the answer has
/// then been handed an address for a name nobody asked about.
///
/// So the shape is checked independently of the signatures: walk from the queried
/// name, follow each CNAME to its target, and require that *every* record in the
/// answer is either a link in that walk or an RRset of the queried type at the
/// name the walk ends on. Anything left over means the answer contains records
/// that are not on the path from the question to its answer.
///
/// This is deliberately not the same check as the resolver's `chain` filter while
/// it fetches. That decides what to *accept* hop by hop and is the reason a
/// stray record rarely reaches here; this decides whether what arrived is
/// coherent, and it holds for an answer that came from anywhere — a forwarder, a
/// cache, a single upstream response.
pub fn cname_chain_shape(qname: &str, qtype: u16, answers: &[ResourceRecord]) -> ChainShape {
    let queried = canonical_name(qname);

    // Index the CNAMEs by owner. More than one CNAME at a name is itself
    // malformed: a CNAME is by definition the only record at its owner
    // (RFC 1034 section 3.6.2), so two of them cannot both be followed.
    let mut cnames: Vec<(String, String)> = Vec::new();
    for rr in answers.iter().filter(|rr| rr.rdata.rtype == rt::CNAME) {
        let Ok(ParsedRecord::CNAME(target)) = rr.rdata.parse() else {
            return ChainShape::Broken(format!("a CNAME at {} does not parse", rr.name));
        };
        let owner = canonical_name(&rr.name);
        if cnames.iter().any(|(o, _)| *o == owner) {
            return ChainShape::Broken(format!(
                "{owner} has more than one CNAME, which cannot be a chain"
            ));
        }
        cnames.push((owner, canonical_name(&target)));
    }

    // A query *for* a CNAME is answered by the CNAME itself rather than by
    // following it (RFC 1034 section 3.6.2), so that question follows nothing and
    // its answer sits at the name asked about.
    let follow = qtype != rt::CNAME;

    // Walk from the question.
    let mut current = queried.clone();
    let mut followed: Vec<String> = Vec::new();
    if follow {
        while let Some((_, target)) = cnames.iter().find(|(owner, _)| *owner == current) {
            if followed.len() >= MAX_CNAME_CHAIN {
                return ChainShape::Broken(format!(
                    "the chain from {queried} is longer than {MAX_CNAME_CHAIN} links"
                ));
            }
            if followed.iter().any(|seen| seen == &current) {
                return ChainShape::Broken(format!("the chain from {queried} loops at {current}"));
            }
            followed.push(current.clone());
            current = target.clone();
        }
    }

    // Everything in the answer must be on that path. A record that is not is
    // either an answer to something else or an attempt to have one taken for
    // this answer.
    for rr in answers {
        if rr.rdata.rtype == rt::RRSIG {
            // A signature is attached to an RRset rather than being one, and the
            // RRset it covers is checked on its own account.
            continue;
        }
        let owner = canonical_name(&rr.name);
        let on_the_path = if rr.rdata.rtype == rt::CNAME {
            // Either a link the walk followed, or — for a query that asked for a
            // CNAME — the answer itself.
            followed.contains(&owner) || (!follow && owner == current)
        } else {
            owner == current
        };
        if !on_the_path {
            return ChainShape::Broken(format!(
                "{owner} type {} is in the answer but not on the path from {queried}",
                rr.rdata.rtype
            ));
        }
    }

    ChainShape::Intact { final_name: current }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::ds_digest;
    use crate::dnssec_denial::build_type_bitmap;
    use crate::dnssec_test_util::{ds_record, TestZone};
    use crate::utils::current_unix_timestamp;
    use crate::{ParsedRecord, ResourceRecord};
    use std::net::Ipv4Addr;

    fn a_record(name: &str, last: u8) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            class: 1,
            ttl: 300,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, last)))
                .unwrap(),
        }
    }

    // -----------------------------------------------------------------
    // Trust anchors
    // -----------------------------------------------------------------

    #[test]
    fn test_builtin_root_anchor_parses() {
        let anchors = TrustAnchors::icann_root();
        let root = anchors.for_zone(".");
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].key_tag, 20326, "ICANN KSK-2017");
        assert_eq!(root[0].algorithm, 8, "RSASHA256");
        assert_eq!(root[0].digest_type, 2, "SHA-256");
        assert_eq!(root[0].digest.len(), 32);
    }

    #[test]
    fn test_anchor_file_formats() {
        let text = "\
                    ; a comment
. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
# another comment
example.test. DS 12345 13 2 ABCDEF0123456789

";
        let anchors = TrustAnchors::parse(text).expect("should parse");
        assert_eq!(anchors.all().len(), 2);
        assert_eq!(anchors.for_zone("example.test.")[0].key_tag, 12345);
        // A trailing dot is not required in the file.
        assert_eq!(anchors.for_zone("EXAMPLE.TEST")[0].algorithm, 13);
    }

    /// A digest split across lines the way IANA publishes it still parses.
    #[test]
    fn test_anchor_digest_may_be_split_by_whitespace() {
        let anchors =
            TrustAnchors::parse(". IN DS 20326 8 2 E06D44B8 0B8F1D39 A95C0B0D 7C65D084 58E88040 9BBC6834 57104237 C7F8EC8D")
                .expect("should parse");
        assert_eq!(anchors.for_zone(".")[0].digest, TrustAnchors::icann_root().for_zone(".")[0].digest);
    }

    /// A typo must stop us rather than silently trust less than intended.
    #[test]
    fn test_bad_anchor_file_is_an_error() {
        assert!(TrustAnchors::parse("").is_err(), "empty file");
        assert!(TrustAnchors::parse("; only comments").is_err());
        assert!(TrustAnchors::parse(". IN DS 20326 8 2").is_err(), "no digest");
        assert!(TrustAnchors::parse(". IN A 192.0.2.1").is_err(), "not a DS");
        assert!(
            TrustAnchors::parse(". IN DS 20326 8 2 NOTHEX!!").is_err(),
            "digest is not hex"
        );
    }

    #[test]
    fn test_deepest_enclosing_anchor_wins() {
        let anchors = TrustAnchors::parse(
            ". IN DS 1 13 2 AABB\n\
             example.test. IN DS 2 13 2 CCDD\n",
        )
        .unwrap();
        assert_eq!(
            anchors.deepest_enclosing("www.example.test.").as_deref(),
            Some("example.test."),
            "a closer anchor beats the root"
        );
        assert_eq!(
            anchors.deepest_enclosing("other.com.").as_deref(),
            Some(".")
        );

        // With no root anchor, a name outside the island has no start point.
        let island = TrustAnchors::parse("example.test. IN DS 2 13 2 CCDD").unwrap();
        assert_eq!(island.deepest_enclosing("other.com."), None);
        assert!(island.deepest_enclosing("a.example.test.").is_some());
    }

    // -----------------------------------------------------------------
    // DNSKEY validation against a DS
    // -----------------------------------------------------------------

    #[test]
    fn test_dnskey_rrset_validates_against_its_ds() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let keys = v
            .validate_dnskeys("example.test.", &zone.dnskey_records(), &[zone.ds(2)])
            .expect("the DNSKEY RRset should validate under its own DS");
        assert_eq!(keys.len(), 2, "trust extends to the ZSK as well as the KSK");
    }

    /// A DS for a key the zone does not publish must not validate anything.
    #[test]
    fn test_dnskey_rrset_rejected_when_the_ds_names_another_key() {
        let zone = TestZone::new("example.test.");
        let stranger = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let err = v
            .validate_dnskeys("example.test.", &zone.dnskey_records(), &[stranger.ds(2)])
            .expect_err("a DS for someone else's key must not validate");
        assert!(err.is_bogus(), "{err:?}");
    }

    /// The attack the DNSKEY signature check exists to stop: an extra key
    /// spliced into the RRset alongside the genuine, DS-vouched one.
    #[test]
    fn test_injected_dnskey_breaks_the_rrset_signature() {
        let zone = TestZone::new("example.test.");
        let attacker = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let mut records = zone.dnskey_records();
        records.insert(
            0,
            ResourceRecord {
                name: "example.test.".into(),
                class: 1,
                ttl: 3600,
                rdata: crate::dnssec_test_util::dnskey_rdata(&attacker.zsk.dnskey("example.test.")),
            },
        );

        let err = v
            .validate_dnskeys("example.test.", &records, &[zone.ds(2)])
            .expect_err("an added key must invalidate the RRset signature");
        assert!(err.is_bogus(), "{err:?}");
    }

    #[test]
    fn test_ds_naming_only_unsupported_algorithms_is_insecure() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        // Algorithm 3 (DSA) is one we deliberately do not implement.
        let mut ds = zone.ds(2);
        ds.algorithm = 3;
        let state = v
            .validate_dnskeys("example.test.", &zone.dnskey_records(), &[ds])
            .expect_err("should not return keys");
        assert_eq!(
            state,
            ValidationState::Insecure,
            "an algorithm we cannot read is not evidence of forgery"
        );
    }

    #[test]
    fn test_signed_parent_with_no_dnskey_at_the_child_is_bogus() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());
        let err = v
            .validate_dnskeys("example.test.", &[], &[zone.ds(2)])
            .expect_err("a DS with no DNSKEY behind it is a broken chain");
        assert!(err.is_bogus(), "{err:?}");
    }

    // -----------------------------------------------------------------
    // Delegations
    // -----------------------------------------------------------------

    /// A parent signing a DS for its child: the ordinary secure delegation.
    #[test]
    fn test_signed_ds_delegation_is_secure() {
        let parent = TestZone::new("test.");
        let child = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let ds_rr = ds_record(&child.ds(2), 3600);
        let sig = parent.sign_records(std::slice::from_ref(&ds_rr));
        let evidence = DelegationEvidence::from_authority("example.test.", &[ds_rr, sig]);

        let verdict = v.validate_delegation(&evidence, "test.", &parent.dnskeys());
        match verdict {
            DelegationVerdict::Secure(ds) => assert_eq!(ds.len(), 1),
            other => panic!("expected a secure delegation, got {other:?}"),
        }
    }

    /// An unsigned DS is an injected DS. The parent zone is signed, so
    /// everything authoritative in it carries a signature.
    #[test]
    fn test_unsigned_ds_is_bogus() {
        let child = TestZone::new("example.test.");
        let parent = TestZone::new("test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let evidence =
            DelegationEvidence::from_authority("example.test.", &[ds_record(&child.ds(2), 3600)]);
        let verdict = v.validate_delegation(&evidence, "test.", &parent.dnskeys());
        assert!(matches!(verdict, DelegationVerdict::Bogus(_)), "{verdict:?}");
    }

    /// A signed NSEC proving there is no DS: the child really is unsigned, and
    /// the walk stops there without calling anything bogus.
    #[test]
    fn test_proven_unsigned_delegation_is_insecure() {
        let parent = TestZone::new("test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let nsec = ResourceRecord {
            name: "example.test.".into(),
            class: 1,
            ttl: 3600,
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC {
                next_domain_name: "zz.test.".into(),
                type_bitmap: build_type_bitmap(&[rt::NS, rt::RRSIG, rt::NSEC]),
            })
            .unwrap(),
        };
        let sig = parent.sign_records(std::slice::from_ref(&nsec));
        let evidence = DelegationEvidence::from_authority("example.test.", &[nsec, sig]);

        let verdict = v.validate_delegation(&evidence, "test.", &parent.dnskeys());
        assert!(
            matches!(verdict, DelegationVerdict::Insecure(_)),
            "{verdict:?}"
        );
    }

    /// The downgrade attack: strip the DS from a referral and offer nothing in
    /// its place. Without a proof, "unsigned" is a claim, not a fact.
    #[test]
    fn test_stripped_ds_with_no_proof_is_bogus() {
        let parent = TestZone::new("test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let evidence = DelegationEvidence::from_authority("example.test.", &[]);
        let verdict = v.validate_delegation(&evidence, "test.", &parent.dnskeys());
        assert!(
            matches!(verdict, DelegationVerdict::Bogus(_)),
            "a missing DS with no denial must not read as unsigned: {verdict:?}"
        );
    }

    /// And an *unsigned* denial is no better than none: the attacker can write
    /// NSEC records too.
    #[test]
    fn test_unsigned_no_ds_proof_is_bogus() {
        let parent = TestZone::new("test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let nsec = ResourceRecord {
            name: "example.test.".into(),
            class: 1,
            ttl: 3600,
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC {
                next_domain_name: "zz.test.".into(),
                type_bitmap: build_type_bitmap(&[rt::NS]),
            })
            .unwrap(),
        };
        let evidence = DelegationEvidence::from_authority("example.test.", &[nsec]);
        let verdict = v.validate_delegation(&evidence, "test.", &parent.dnskeys());
        assert!(matches!(verdict, DelegationVerdict::Bogus(_)), "{verdict:?}");
    }

    // -----------------------------------------------------------------
    // Answers
    // -----------------------------------------------------------------

    #[test]
    fn test_signed_answer_is_secure() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let answer = a_record("www.example.test.", 1);
        let sig = zone.sign_records(std::slice::from_ref(&answer));

        let mut keys = KeyStore::new();
        keys.insert("example.test.".into(), zone.dnskeys());

        let verdict = v.validate_records(&[answer, sig], &keys);
        assert_eq!(verdict.state, ValidationState::Secure);
        assert!(verdict.wildcards.is_empty(), "not a wildcard answer");
    }

    #[test]
    fn test_answer_signed_by_a_zone_we_never_established_is_bogus() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let answer = a_record("www.example.test.", 1);
        let sig = zone.sign_records(std::slice::from_ref(&answer));

        let state = v.validate_records(&[answer, sig], &KeyStore::new()).state;
        assert!(state.is_bogus(), "{state:?}");
    }

    /// A zone may not sign for names outside itself, however good its key is.
    #[test]
    fn test_signature_from_a_zone_above_the_owner_is_rejected() {
        let evil = TestZone::new("evil.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let answer = a_record("www.bank.test.", 6);
        let sig = evil.sign_records(std::slice::from_ref(&answer));

        let mut keys = KeyStore::new();
        keys.insert("evil.test.".into(), evil.dnskeys());

        let state = v.validate_records(&[answer, sig], &keys).state;
        assert!(state.is_bogus(), "{state:?}");
    }

    #[test]
    fn test_unsigned_record_in_a_signed_zone_is_bogus() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let mut keys = KeyStore::new();
        keys.insert("example.test.".into(), zone.dnskeys());

        // A record with no RRSIG beside it, in a zone we know is signed.
        let state = v.validate_records(&[a_record("www.example.test.", 1)], &keys).state;
        assert!(state.is_bogus(), "{state:?}");
    }

    /// Two RRsets, one signed and one not: the answer as a whole is bogus. It
    /// is not enough for *some* of what we return to be authentic.
    #[test]
    fn test_one_unsigned_rrset_taints_the_answer() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let signed = a_record("www.example.test.", 1);
        let sig = zone.sign_records(std::slice::from_ref(&signed));
        let smuggled = ResourceRecord {
            name: "other.example.test.".into(),
            class: 1,
            ttl: 300,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(6, 6, 6, 6))).unwrap(),
        };

        let mut keys = KeyStore::new();
        keys.insert("example.test.".into(), zone.dnskeys());

        let state = v.validate_records(&[signed, sig, smuggled], &keys).state;
        assert!(state.is_bogus(), "{state:?}");
    }

    // -----------------------------------------------------------------
    // Wildcard answers
    // -----------------------------------------------------------------

    /// An NSEC resource record, ready to be signed.
    fn nsec_record(owner: &str, next: &str, types: &[u16]) -> ResourceRecord {
        ResourceRecord {
            name: owner.to_string(),
            class: 1,
            ttl: 300,
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC {
                next_domain_name: next.to_string(),
                type_bitmap: build_type_bitmap(types),
            })
            .unwrap(),
        }
    }

    /// A wildcard-expanded answer verifies, and is reported as owing a proof
    /// rather than being taken as complete.
    #[test]
    fn test_wildcard_answer_is_reported_as_owing_a_proof() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let answer = a_record("a.example.test.", 1);
        let sig = zone.sign_as_wildcard(std::slice::from_ref(&answer), "*.example.test.");

        let mut keys = KeyStore::new();
        keys.insert("example.test.".into(), zone.dnskeys());

        let verdict = v.validate_records(&[answer, sig], &keys);
        assert_eq!(verdict.state, ValidationState::Secure, "the signature is genuine");
        assert_eq!(
            verdict.wildcards.len(),
            1,
            "a verified signature is only half of a wildcard answer"
        );
        assert_eq!(verdict.wildcards[0].owner, "a.example.test.");
        assert_eq!(verdict.wildcards[0].wildcard, "*.example.test.");
        assert_eq!(verdict.wildcards[0].signer, "example.test.");
    }

    /// The whole point: with the signed NSEC the answer is secure; without it,
    /// the same signature is not enough.
    #[test]
    fn test_wildcard_answer_needs_its_nsec() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let answer = a_record("a.example.test.", 1);
        let sig = zone.sign_as_wildcard(std::slice::from_ref(&answer), "*.example.test.");
        let mut keys = KeyStore::new();
        keys.insert("example.test.".into(), zone.dnskeys());
        let expansions = v.validate_records(&[answer, sig], &keys).wildcards;

        // The zone's own NSEC at the wildcard, which covers everything from
        // `*.example.test.` up to `www.example.test.` — `a.example.test.`
        // included, because `*` sorts before every ordinary label.
        let nsec = nsec_record("*.example.test.", "www.example.test.", &[rt::A, rt::RRSIG, rt::NSEC]);
        let nsec_sig = zone.sign_records(std::slice::from_ref(&nsec));

        assert_eq!(
            v.validate_wildcard_proofs(&expansions, &[nsec.clone(), nsec_sig.clone()], &keys),
            ValidationState::Secure
        );

        let state = v.validate_wildcard_proofs(&expansions, &[], &keys);
        assert!(state.is_bogus(), "no proof at all: {state:?}");

        // And an unsigned NSEC is no proof: anyone can write one.
        let state = v.validate_wildcard_proofs(&expansions, &[nsec], &keys);
        assert!(state.is_bogus(), "unsigned proof: {state:?}");
    }

    /// A proof signed by somebody else does not count, even when we hold their
    /// keys — only the zone that expanded the wildcard can say what is in it.
    #[test]
    fn test_wildcard_proof_from_another_zone_is_refused() {
        let zone = TestZone::new("example.test.");
        let stranger = TestZone::new("evil.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let answer = a_record("a.example.test.", 1);
        let sig = zone.sign_as_wildcard(std::slice::from_ref(&answer), "*.example.test.");
        let mut keys = KeyStore::new();
        keys.insert("example.test.".into(), zone.dnskeys());
        keys.insert("evil.test.".into(), stranger.dnskeys());
        let expansions = v.validate_records(&[answer, sig], &keys).wildcards;

        let nsec = nsec_record("*.example.test.", "www.example.test.", &[rt::A, rt::RRSIG, rt::NSEC]);
        let forged = stranger.sign_records(std::slice::from_ref(&nsec));

        let state = v.validate_wildcard_proofs(&expansions, &[nsec, forged], &keys);
        assert!(state.is_bogus(), "{state:?}");
    }

    /// The substitution a wildcard signature makes possible: the RRset and its
    /// RRSIG are genuine and verify at the re-owned name, because that is what
    /// signing a wildcard means. `b.example.test.` exists, so this name's
    /// closest encloser is `b.example.test.` and `*.example.test.` never applied
    /// to it — and the NSEC the attacker has to offer says exactly that.
    #[test]
    fn test_wildcard_answer_re_owned_below_an_existing_name_is_bogus() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let answer = a_record("stolen.b.example.test.", 6);
        let sig = zone.sign_as_wildcard(std::slice::from_ref(&answer), "*.example.test.");
        let mut keys = KeyStore::new();
        keys.insert("example.test.".into(), zone.dnskeys());

        let verdict = v.validate_records(&[answer, sig], &keys);
        assert_eq!(
            verdict.state,
            ValidationState::Secure,
            "the signature really does verify at the re-owned name — that is the problem"
        );

        // The genuine NSEC at `b.example.test.`, which does cover the re-owned
        // name: a name sorts before everything beneath it.
        let nsec = nsec_record("b.example.test.", "c.example.test.", &[rt::A, rt::RRSIG, rt::NSEC]);
        let nsec_sig = zone.sign_records(std::slice::from_ref(&nsec));

        let state = v.validate_wildcard_proofs(&verdict.wildcards, &[nsec, nsec_sig], &keys);
        assert!(
            state.is_bogus(),
            "an expansion below an existing name must not validate: {state:?}"
        );
    }

    /// A record sitting *at* a wildcard is not an expansion of it, even though
    /// the RRSIG's label count is one short of the owner's — the labels field
    /// never counts the `*`. Getting this wrong demands a proof that
    /// `*.example.test.` does not exist, which would break every wildcard-aware
    /// denial, since those carry precisely that record.
    #[test]
    fn test_the_wildcards_own_rrset_is_not_an_expansion() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let at_wildcard = a_record("*.example.test.", 1);
        let sig = zone.sign_records(std::slice::from_ref(&at_wildcard));
        let mut keys = KeyStore::new();
        keys.insert("example.test.".into(), zone.dnskeys());

        let verdict = v.validate_records(&[at_wildcard, sig], &keys);
        assert_eq!(verdict.state, ValidationState::Secure);
        assert!(
            verdict.wildcards.is_empty(),
            "the name asked about is the wildcard itself, which exists"
        );
    }

    /// A DS is computed over the down-cased owner name, so the case a zone
    /// happens to be written in cannot change its digest.
    #[test]
    fn test_ds_digest_is_case_insensitive_in_the_owner() {
        let zone = TestZone::new("example.test.");
        let mixed = zone.ksk.ksk("Example.TEST.");
        let lower = zone.ksk.ksk("example.test.");
        assert_eq!(ds_digest(&mixed, 2).unwrap(), ds_digest(&lower, 2).unwrap());
    }

    #[test]
    fn test_group_rrsets_splits_by_name_and_type_and_skips_signatures() {
        let zone = TestZone::new("example.test.");
        let addresses = vec![a_record("a.example.test.", 1), a_record("a.example.test.", 2)];
        let sig = zone.sign_records(&addresses);

        let mut records = addresses;
        records.push(a_record("b.example.test.", 3));
        records.push(sig);

        let sets = group_rrsets(&records);
        assert_eq!(sets.len(), 2, "two owner names, and the RRSIG is not an RRset");
        assert_eq!(sets[0].3.len(), 2, "two addresses at the first name");
        assert_eq!(sets[1].3.len(), 1);
    }
    // -----------------------------------------------------------------
    // CNAME chains
    // -----------------------------------------------------------------

    fn cname(owner: &str, target: &str) -> ResourceRecord {
        ResourceRecord {
            name: owner.to_string(),
            class: 1,
            ttl: 300,
            rdata: RecordData::from_parsed(&ParsedRecord::CNAME(target.to_string())).unwrap(),
        }
    }

    fn a(owner: &str, addr: &str) -> ResourceRecord {
        ResourceRecord {
            name: owner.to_string(),
            class: 1,
            ttl: 300,
            rdata: RecordData::from_parsed(&ParsedRecord::A(addr.parse().unwrap())).unwrap(),
        }
    }

    fn rrsig_over(owner: &str, covered: u16) -> ResourceRecord {
        ResourceRecord {
            name: owner.to_string(),
            class: 1,
            ttl: 300,
            rdata: RecordData::from_parsed(&ParsedRecord::RRSIG {
                type_covered: covered,
                algorithm: 13,
                labels: 3,
                original_ttl: 300,
                inception: 1,
                expiration: u32::MAX,
                key_tag: 1,
                signer_name: "example.com.".to_string(),
                signature: vec![7; 64],
            })
            .unwrap(),
        }
    }

    #[test]
    fn test_an_ordinary_chain_is_intact() {
        let answers = vec![
            cname("a.example.com.", "b.example.net."),
            rrsig_over("a.example.com.", rt::CNAME),
            cname("b.example.net.", "c.example.org."),
            rrsig_over("b.example.net.", rt::CNAME),
            a("c.example.org.", "192.0.2.1"),
            rrsig_over("c.example.org.", rt::A),
        ];
        assert_eq!(
            cname_chain_shape("a.example.com.", rt::A, &answers),
            ChainShape::Intact {
                final_name: "c.example.org.".to_string()
            }
        );

        // An answer with no CNAME at all is a chain of length zero.
        assert_eq!(
            cname_chain_shape("www.example.com.", rt::A, &[a("www.example.com.", "192.0.2.2")]),
            ChainShape::Intact {
                final_name: "www.example.com.".to_string()
            }
        );
    }

    /// The case the check exists for: two RRsets that are each perfectly
    /// authentic, and together are not an answer to this question. A consumer
    /// reading "the A record in the answer" would take an address for a name
    /// nobody asked about.
    #[test]
    fn test_a_record_off_the_path_breaks_the_chain() {
        let answers = vec![
            cname("a.example.com.", "b.example.net."),
            // The A is for something else entirely.
            a("attacker.example.net.", "6.6.6.6"),
        ];
        let shape = cname_chain_shape("a.example.com.", rt::A, &answers);
        assert!(
            matches!(&shape, ChainShape::Broken(why) if why.contains("not on the path")),
            "got {shape:?}"
        );
    }

    /// The first link has to start at the name that was asked about, or the chain
    /// is somebody else's.
    #[test]
    fn test_a_chain_that_does_not_start_at_the_question_is_broken() {
        let answers = vec![
            cname("other.example.com.", "b.example.net."),
            a("b.example.net.", "192.0.2.1"),
        ];
        let shape = cname_chain_shape("a.example.com.", rt::A, &answers);
        assert!(matches!(shape, ChainShape::Broken(_)), "got {shape:?}");
    }

    /// A missing link is not a shorter chain: the records after the gap are not
    /// reachable from the question.
    #[test]
    fn test_a_missing_link_breaks_the_chain() {
        let answers = vec![
            cname("a.example.com.", "b.example.net."),
            // The CNAME from b to c is absent, so c is unreachable.
            a("c.example.org.", "192.0.2.1"),
        ];
        let shape = cname_chain_shape("a.example.com.", rt::A, &answers);
        assert!(matches!(shape, ChainShape::Broken(_)), "got {shape:?}");
    }

    #[test]
    fn test_a_loop_is_refused() {
        let answers = vec![
            cname("a.example.com.", "b.example.com."),
            cname("b.example.com.", "a.example.com."),
        ];
        let shape = cname_chain_shape("a.example.com.", rt::A, &answers);
        assert!(
            matches!(&shape, ChainShape::Broken(why) if why.contains("loops")),
            "got {shape:?}"
        );
    }

    /// A CNAME is by definition the only record at its owner (RFC 1034 section
    /// 3.6.2), so two of them cannot both be followed — and picking one would be
    /// letting whoever sent them choose.
    #[test]
    fn test_two_cnames_at_one_name_are_refused() {
        let answers = vec![
            cname("a.example.com.", "b.example.net."),
            cname("a.example.com.", "evil.example.net."),
        ];
        let shape = cname_chain_shape("a.example.com.", rt::A, &answers);
        assert!(
            matches!(&shape, ChainShape::Broken(why) if why.contains("more than one CNAME")),
            "got {shape:?}"
        );
    }

    /// A query *for* a CNAME is answered by the CNAME itself rather than by
    /// following it (RFC 1034 section 3.6.2), so the walk must stop at the first
    /// hop — otherwise the answer to the question looks like a record off the path.
    #[test]
    fn test_a_query_for_a_cname_is_answered_by_it() {
        let answers = vec![
            cname("a.example.com.", "b.example.net."),
            rrsig_over("a.example.com.", rt::CNAME),
        ];
        assert_eq!(
            cname_chain_shape("a.example.com.", rt::CNAME, &answers),
            ChainShape::Intact {
                final_name: "a.example.com.".to_string()
            }
        );
    }

    /// Names compare case-insensitively (RFC 4343), and a chain that broke on
    /// capitalisation would break on every answer from a 0x20-randomizing
    /// resolver — which this one is.
    #[test]
    fn test_the_chain_is_case_insensitive() {
        let answers = vec![
            cname("A.ExAmPlE.CoM.", "B.example.NET."),
            a("b.EXAMPLE.net.", "192.0.2.1"),
        ];
        assert!(matches!(
            cname_chain_shape("a.example.com.", rt::A, &answers),
            ChainShape::Intact { .. }
        ));
    }

    /// Bounded, because the alternative is following a chain somebody built to be
    /// followed for ever.
    #[test]
    fn test_a_chain_longer_than_the_limit_is_refused() {
        let mut answers = Vec::new();
        for i in 0..(MAX_CNAME_CHAIN + 2) {
            answers.push(cname(
                &format!("n{i}.example.com."),
                &format!("n{}.example.com.", i + 1),
            ));
        }
        let shape = cname_chain_shape("n0.example.com.", rt::A, &answers);
        assert!(
            matches!(&shape, ChainShape::Broken(why) if why.contains("longer than")),
            "got {shape:?}"
        );
    }
}
