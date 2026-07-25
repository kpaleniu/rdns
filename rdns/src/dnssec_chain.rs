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
use crate::dnssec_denial::{proves_no_ds, Denial, Nsec, Nsec3};
use crate::utils::record_types as rt;
use crate::{RecordData, ResourceRecord};
use anyhow::anyhow;
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
    pub fn parse(text: &str) -> Result<Self, anyhow::Error> {
        let mut anchors = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split(';').next().unwrap_or("");
            let line = line.split('#').next().unwrap_or("");
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            anchors.push(parse_ds_line(line).map_err(|e| {
                anyhow!("trust anchor line {}: {e} in {:?}", lineno + 1, raw.trim())
            })?);
        }
        if anchors.is_empty() {
            return Err(anyhow!("no DS records found"));
        }
        Ok(TrustAnchors { anchors })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, anyhow::Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("reading trust anchors {}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| anyhow!("{}: {e}", path.display()))
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
fn parse_ds_line(line: &str) -> Result<Ds, anyhow::Error> {
    let mut tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 6 {
        return Err(anyhow!("expected at least 6 fields, got {}", tokens.len()));
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
        return Err(anyhow!("expected the DS type keyword, found {:?}", tokens.first()));
    }
    tokens.remove(0);
    if tokens.len() < 4 {
        return Err(anyhow!("DS needs key tag, algorithm, digest type and digest"));
    }

    let key_tag: u16 = tokens[0].parse().map_err(|_| anyhow!("bad key tag {:?}", tokens[0]))?;
    let algorithm: u8 = tokens[1]
        .parse()
        .map_err(|_| anyhow!("bad algorithm {:?}", tokens[1]))?;
    let digest_type: u8 = tokens[2]
        .parse()
        .map_err(|_| anyhow!("bad digest type {:?}", tokens[2]))?;
    // The digest may be split across whitespace, as it is in IANA's own file.
    let hex: String = tokens[3..].concat();
    if !hex.len().is_multiple_of(2) {
        return Err(anyhow!("digest has an odd number of hex characters"));
    }
    let digest = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| anyhow!("digest is not hexadecimal"))?;

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
    pub fn validate_records(&self, records: &[ResourceRecord], keys: &KeyStore) -> ValidationState {
        let rrsigs: Vec<Rrsig> = records.iter().filter_map(Rrsig::from_record).collect();
        let mut validated_any = false;

        for (owner, rtype, class, rdatas) in group_rrsets(records) {
            // Which zone claims to have signed this RRset.
            let signer = rrsigs
                .iter()
                .find(|s| s.owner == owner && s.type_covered == rtype)
                .map(|s| s.signer_name.clone());

            let Some(signer) = signer else {
                return ValidationState::Bogus(format!(
                    "{owner} type {rtype} came back unsigned from a signed zone"
                ));
            };
            // A zone may only sign at or below itself.
            if !is_at_or_below(&owner, &signer) {
                return ValidationState::Bogus(format!(
                    "{owner} is signed by {signer}, which is not above it"
                ));
            }
            let Some(zone_keys) = keys.get(&signer) else {
                return ValidationState::Bogus(format!(
                    "{owner} is signed by {signer}, whose keys were never established"
                ));
            };

            match verify_rrset(
                &Rrset::new(&owner, rtype, class, &rdatas),
                &rrsigs,
                zone_keys,
                &signer,
                self.now,
            ) {
                RrsetProof::Verified { .. } => validated_any = true,
                RrsetProof::Unsigned => {
                    return ValidationState::Bogus(format!("{owner} type {rtype} is unsigned"))
                }
                RrsetProof::Unsupported(_) => return ValidationState::Insecure,
                RrsetProof::Bogus(why) => return ValidationState::Bogus(why),
            }
        }

        if validated_any {
            ValidationState::Secure
        } else {
            // Nothing to check — an empty answer. The caller decides whether a
            // denial-of-existence proof is owed.
            ValidationState::Insecure
        }
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

        assert_eq!(
            v.validate_records(&[answer, sig], &keys),
            ValidationState::Secure
        );
    }

    #[test]
    fn test_answer_signed_by_a_zone_we_never_established_is_bogus() {
        let zone = TestZone::new("example.test.");
        let anchors = TrustAnchors::default();
        let v = ChainValidator::new(&anchors, current_unix_timestamp());

        let answer = a_record("www.example.test.", 1);
        let sig = zone.sign_records(std::slice::from_ref(&answer));

        let state = v.validate_records(&[answer, sig], &KeyStore::new());
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

        let state = v.validate_records(&[answer, sig], &keys);
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
        let state = v.validate_records(&[a_record("www.example.test.", 1)], &keys);
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

        let state = v.validate_records(&[signed, sig, smuggled], &keys);
        assert!(state.is_bogus(), "{state:?}");
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
}
