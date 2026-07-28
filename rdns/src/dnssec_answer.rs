//! What a signed answer carries beyond the records themselves.
//!
//! A signed zone is not a signed *answer*. The signatures sit in the zone
//! beside the data, and until something puts the right ones in the right
//! section of the right reply, a validating client sees an unsigned answer from
//! a zone the parent says is secure — which is not "insecure", it is bogus.
//! This module is the step in between: given the zone and the question, it says
//! which DNSSEC records the reply needs.
//!
//! **Nothing here is optional to a validator, and that is the design
//! constraint.** Three of the four shapes owe a proof rather than a signature:
//!
//! - a wildcard answer owes a denial of the name that was actually asked for,
//!   because the same signature verifies at every name that wildcard reaches
//!   (RFC 4035 §3.1.3) — without the denial, an attacker with one wildcard
//!   answer holds a valid answer for every name under it;
//! - NODATA owes a record *at* the name whose bitmap lacks the type;
//! - NXDOMAIN owes both a denial of the name and a denial of the wildcard that
//!   could otherwise have answered it.
//!
//! Only a plain positive answer is just signatures. [`crate::dnssec_denial`] is
//! the same rules read from the other end, and the tests here check the output
//! with it rather than by inspection.
//!
//! **Nothing is added to an unsigned zone**, whatever the client asked for. The
//! DO bit is a statement about what the client can *understand*, not a demand,
//! and most zones have nothing to send.

use crate::dnssec::{canonical_name, rrsigs_in, Rrsig};
use crate::dnssec_denial::{base32hex_encode, nsec3_hash, Nsec3};
use crate::utils::record_types as rt;
use crate::zone::{NameKind, Zone, ZoneRecord};
use crate::ResourceRecord;

/// The signatures for an answer, and whether that answer came from a wildcard.
#[derive(Debug, Default)]
pub struct AnswerSignatures {
    /// RRSIG records to add to the answer section, owned by the name the client
    /// asked about.
    pub records: Vec<ResourceRecord>,
    /// The wildcard the records were synthesized from, if they were. An answer
    /// with this set is not finished: it still owes [`proof_of_absence`] for the
    /// queried name.
    pub wildcard: Option<String>,
}

/// Whether this zone has signatures to serve at all.
///
/// The apex DNSKEY RRset is the test rather than "are there any RRSIGs",
/// because it is what a validator will come back and ask for. A zone with
/// signatures but no published key cannot be validated by anyone, so serving
/// its signatures only turns an insecure answer into a bogus one.
pub fn is_signed(zone: &Zone) -> bool {
    !zone.query(zone.origin(), rt::DNSKEY).is_empty()
}

/// The RRSIGs covering the answer to `qname`/`qtype`.
///
/// A wildcard's signature is re-owned onto the queried name — which is not a
/// forgery but the protocol: the RRSIG's label count still says the signature
/// was made at the wildcard, and that is what lets a validator reconstruct the
/// name that was really signed (RFC 4035 §5.3.2). Changing the owner and
/// leaving the label count alone is exactly the shape of a genuine wildcard
/// answer.
pub fn answer_signatures(zone: &Zone, qname: &str, qtype: u16) -> AnswerSignatures {
    if !is_signed(zone) {
        return AnswerSignatures::default();
    }
    let qname = canonical_name(qname);
    let mut out = AnswerSignatures::default();
    for record in zone.query(&qname, rt::RRSIG) {
        let Some(sig) = rrsig_of(record) else { continue };
        if sig.type_covered != qtype {
            continue;
        }
        if sig.owner != qname {
            out.wildcard = Some(sig.owner.clone());
        }
        out.records.push(ResourceRecord {
            name: qname.clone(),
            class: record.class,
            ttl: record.ttl,
            rdata: record.rdata.clone(),
        });
    }
    out
}

/// The proof that `qname` does not exist.
///
/// Half of an NXDOMAIN, and the whole of what a wildcard answer owes. Under
/// NSEC that is one record; under NSEC3 it is two, because a hash chain cannot
/// point at a name directly — the proof is "this ancestor exists, and the name
/// one label below it towards the query does not", which is what the closest
/// encloser and the next closer name are (RFC 5155 §7.2.1).
pub fn proof_of_absence(zone: &Zone, qname: &str) -> Vec<ResourceRecord> {
    if !is_signed(zone) {
        return Vec::new();
    }
    let qname = canonical_name(qname);
    let mut out = Vec::new();
    if zone.has_nsec3_chain() {
        let Some(params) = Nsec3Params::of(zone) else {
            return out;
        };
        let Some(encloser) = params.closest_encloser(zone, &qname) else {
            return out;
        };
        push_matching_nsec3(zone, &params, &encloser, &mut out);
        if let Some(next_closer) = child_towards(&qname, &encloser) {
            push_covering_nsec3(zone, &params, &next_closer, &mut out);
        }
    } else if let Some(nsec) = zone.nsec_covering(&qname) {
        push_with_signatures(zone, nsec, &mut out);
    }
    out
}

/// The authority records a negative answer needs beyond the SOA.
///
/// `kind` is the same answer that decided NXDOMAIN against NODATA, and each of
/// its cases owes something different: NODATA owes a record *at* the name saying
/// the type is not among the ones it has, NODATA through a wildcard owes that
/// record at the wildcard plus a denial of the name asked for, and NXDOMAIN owes
/// a denial of the name *and* of the wildcard that could have covered it.
/// Getting that last one wrong is how a validator ends up accepting an NXDOMAIN
/// for a name a wildcard answers.
///
/// It is a [`NameKind`] rather than a bool because the wildcard has to come from
/// the zone. Recomputing it here as "the first label replaced by `*`" was wrong
/// for anything a wildcard reaches more than one label down, and the proof it
/// built was a statement about a name that does not exist.
pub fn negative_proof(zone: &Zone, qname: &str, kind: &NameKind) -> Vec<ResourceRecord> {
    if !is_signed(zone) {
        return Vec::new();
    }
    let qname = canonical_name(qname);
    let mut out = soa_signatures(zone);

    match kind {
        NameKind::NotFound => {
            out.extend(proof_of_absence(zone, &qname));
            out.extend(wildcard_denial(zone, &qname));
        }
        // The ordinary NODATA: the name is there, and the record at it lists
        // the types that are. An empty non-terminal is the same shape — it
        // exists, and the signer puts it in the chain for exactly this
        // (`zone_signer::Layout::chain_names`), so there is a record to point
        // at even though the name has no data of its own.
        NameKind::Exact | NameKind::EmptyNonTerminal => match_at_name(zone, &qname, &mut out),
        // NODATA through a wildcard: the queried name does not exist, a
        // wildcard matched it, and that wildcard has no records of this type.
        // Both halves have to be said — the wildcard's own record for the
        // missing type, and the proof that the queried name is not there in its
        // own right, without which this is indistinguishable from a NODATA
        // about the wildcard name itself.
        NameKind::Wildcard(wildcard) => {
            match_at_name(zone, &canonical_name(wildcard), &mut out);
            out.extend(proof_of_absence(zone, &qname));
        }
    }
    out
}

/// What a referral owes a validating client: the DS RRset with its signature, or
/// the authenticated denial that there is one (RFC 4035 §3.1.4).
///
/// This is the step that keeps the chain of trust connected across a zone cut. A
/// referral carrying no DS and no denial is indistinguishable from one an
/// attacker stripped the DS out of, which is the downgrade attack DNSSEC exists
/// to stop — the child looks unsigned and anything may then be forged in it.
///
/// The NS RRset itself gets **no** signature, and that is not an omission: it is
/// the child's data, and this zone has no authority over it (RFC 4035 §2.2).
pub fn delegation_proof(zone: &Zone, cut: &str) -> Vec<ResourceRecord> {
    if !is_signed(zone) {
        return Vec::new();
    }
    let cut = canonical_name(cut);

    let ds = zone.query(&cut, rt::DS);
    if !ds.is_empty() {
        let mut out: Vec<ResourceRecord> = ds.into_iter().map(to_resource).collect();
        out.extend(signatures_at(zone, &cut, rt::DS));
        return out;
    }

    // No DS: the child is insecure, and a validator will only believe that if it
    // is signed. The record at the cut says so by listing NS and not DS in its
    // bitmap.
    let mut out = Vec::new();
    match_at_name(zone, &cut, &mut out);
    if out.is_empty() && zone.has_nsec3_chain() {
        // Under opt-out an insecure delegation has no NSEC3 of its own
        // (RFC 5155 §7.2.9), so the proof is the closest-encloser pair instead:
        // the covering record says the name falls in a span the chain does not
        // enumerate, which is exactly what opt-out means.
        out.extend(proof_of_absence(zone, &cut));
    }
    out
}

/// The denial of the wildcard that could have answered `qname`, which an
/// NXDOMAIN needs alongside the denial of the name itself (RFC 4035 §5.4).
///
/// The wildcard denied here is `*.<closest encloser>`, and that name is
/// guaranteed not to be in the zone — if it were, the answer would have been a
/// wildcard match rather than an NXDOMAIN. That guarantee lives in
/// [`Zone::name_kind`], and it is load-bearing: `nsec_covering` searches
/// strictly below its argument, so asking it about a name that *is* in the chain
/// returns the record before it, which covers nothing and proves nothing.
fn wildcard_denial(zone: &Zone, qname: &str) -> Vec<ResourceRecord> {
    let mut out = Vec::new();
    if zone.has_nsec3_chain() {
        let Some(params) = Nsec3Params::of(zone) else {
            return out;
        };
        let Some(encloser) = params.closest_encloser(zone, qname) else {
            return out;
        };
        push_covering_nsec3(zone, &params, &format!("*.{encloser}"), &mut out);
    } else {
        let Some(encloser) = nsec_closest_encloser(zone, qname) else {
            return out;
        };
        if let Some(nsec) = zone.nsec_covering(&format!("*.{encloser}")) {
            push_with_signatures(zone, nsec, &mut out);
        }
    }
    out
}

/// The denial record sitting *at* `name`, with its signatures.
fn match_at_name(zone: &Zone, name: &str, out: &mut Vec<ResourceRecord>) {
    if zone.has_nsec3_chain() {
        if let Some(params) = Nsec3Params::of(zone) {
            push_matching_nsec3(zone, &params, name, out);
        }
        return;
    }
    // `query` would fall back to a wildcard, and a wildcard's NSEC says nothing
    // about the name asked for — the records here have to be the literal ones.
    if !zone.holds_name(name) {
        return;
    }
    for record in zone.query(name, rt::NSEC) {
        push_with_signatures(zone, record, out);
    }
}

/// The apex SOA's signatures. The SOA itself is already in the authority
/// section of any negative answer (RFC 2308); unsigned, it is one more record a
/// validator has to reject the answer over.
///
/// The TTL is capped the same way the SOA's is — `min(MINIMUM, the record's own
/// TTL)`, RFC 2308 §3. A signature outliving the record it covers is a cache
/// holding an RRSIG with nothing to check, and the two disagreeing about how
/// long the "no" is good for is what made this worth writing down.
fn soa_signatures(zone: &Zone) -> Vec<ResourceRecord> {
    let origin = zone.origin().to_string();
    let cap = negative_ttl_cap(zone);
    signatures_at(zone, &origin, rt::SOA)
        .into_iter()
        .map(|mut r| {
            r.ttl = r.ttl.min(cap);
            r
        })
        .collect()
}

/// The zone's MINIMUM, as an i32 TTL ceiling.
fn negative_ttl_cap(zone: &Zone) -> i32 {
    zone.query(zone.origin(), rt::SOA)
        .first()
        .and_then(|soa| match soa.rdata.parse() {
            Ok(crate::ParsedRecord::SOA { minimum, .. }) => {
                Some(minimum.min(i32::MAX as u32) as i32)
            }
            _ => None,
        })
        .unwrap_or(0)
}

fn signatures_at(zone: &Zone, name: &str, rtype: u16) -> Vec<ResourceRecord> {
    if !zone.holds_name(name) {
        return Vec::new();
    }
    zone.query(name, rt::RRSIG)
        .into_iter()
        .filter(|r| rrsig_of(r).is_some_and(|s| s.type_covered == rtype))
        .map(to_resource)
        .collect()
}

/// A record and every signature over it.
fn push_with_signatures(zone: &Zone, record: &ZoneRecord, out: &mut Vec<ResourceRecord>) {
    let resource = to_resource(record);
    if out
        .iter()
        .any(|r| r.name == resource.name && r.rdata == resource.rdata)
    {
        // The same NSEC often denies two things at once — a name and the
        // wildcard above it are frequently in the same gap. Sending it twice is
        // legal and pointless; a validator de-duplicates, and the second copy is
        // bytes on an amplification path.
        return;
    }
    let signatures = signatures_at(zone, &record.name, record.rdata.rtype);
    out.push(resource);
    out.extend(signatures);
}

// ---------------------------------------------------------------------------
// NSEC3: the chain is over hashes, so every lookup goes through the parameters
// ---------------------------------------------------------------------------

/// The salt and iteration count this zone's NSEC3 chain was built with.
struct Nsec3Params {
    salt: Vec<u8>,
    iterations: u16,
}

impl Nsec3Params {
    /// Read them off the chain itself rather than off NSEC3PARAM.
    ///
    /// NSEC3PARAM is what tells a *server* which chain to use when a zone is
    /// mid-rollover between two of them (RFC 5155 §4.1), and this server has no
    /// such notion — it has the one chain it was given. Taking the parameters
    /// from a record in that chain cannot disagree with the chain, whereas an
    /// NSEC3PARAM left behind from a previous signing can, and the failure would
    /// be every denial hashing to something no record matches.
    fn of(zone: &Zone) -> Option<Self> {
        zone.any_nsec3()
            .and_then(|r| Nsec3::from_record(&to_resource(r)))
            .map(|n| Nsec3Params {
                salt: n.salt,
                iterations: n.iterations,
            })
    }

    fn hash(&self, name: &str) -> Option<Vec<u8>> {
        nsec3_hash(name, &self.salt, self.iterations).ok()
    }

    fn owner(&self, zone: &Zone, name: &str) -> Option<String> {
        let hash = self.hash(name)?;
        Some(format!(
            "{}.{}",
            base32hex_encode(&hash).to_lowercase(),
            zone.origin()
        ))
    }

    /// The deepest ancestor of `qname` that the chain has a record for.
    ///
    /// Walking up rather than consulting the name index, because under NSEC3 an
    /// empty non-terminal has an NSEC3 and no records of its own — it would be
    /// invisible to a lookup by name, and stopping short of it produces a proof
    /// about the wrong encloser.
    fn closest_encloser(&self, zone: &Zone, qname: &str) -> Option<String> {
        let origin = canonical_name(zone.origin());
        let mut name = canonical_name(qname);
        loop {
            if self
                .owner(zone, &name)
                .is_some_and(|owner| zone.holds_name(&owner))
            {
                return Some(name);
            }
            if name == origin {
                return None;
            }
            name = parent(&name)?;
        }
    }
}

fn push_matching_nsec3(
    zone: &Zone,
    params: &Nsec3Params,
    name: &str,
    out: &mut Vec<ResourceRecord>,
) {
    let Some(owner) = params.owner(zone, name) else {
        return;
    };
    for record in zone.query(&owner, rt::NSEC3) {
        push_with_signatures(zone, record, out);
    }
}

fn push_covering_nsec3(
    zone: &Zone,
    params: &Nsec3Params,
    name: &str,
    out: &mut Vec<ResourceRecord>,
) {
    let Some(hash) = params.hash(name) else {
        return;
    };
    let Some(record) = zone.nsec3_covering(&hash).cloned() else {
        return;
    };
    push_with_signatures(zone, &record, out);
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/// The deepest ancestor of `qname` the zone holds a name for. Under NSEC every
/// name in the chain has a record, empty non-terminals included, so the index
/// answers this directly.
fn nsec_closest_encloser(zone: &Zone, qname: &str) -> Option<String> {
    let origin = canonical_name(zone.origin());
    let mut name = canonical_name(qname);
    loop {
        if zone.holds_name(&name) {
            return Some(name);
        }
        if name == origin {
            return None;
        }
        name = parent(&name)?;
    }
}

/// The name one label below `encloser` on the way to `qname` — the "next
/// closer" name of RFC 5155 §1.3.
fn child_towards(qname: &str, encloser: &str) -> Option<String> {
    let qname = canonical_name(qname);
    let encloser = canonical_name(encloser);
    if qname == encloser {
        return None;
    }
    let mut name = qname;
    loop {
        let up = parent(&name)?;
        if up == encloser {
            return Some(name);
        }
        name = up;
    }
}

fn parent(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.');
    let (_, rest) = trimmed.split_once('.')?;
    Some(canonical_name(rest))
}

fn rrsig_of(record: &ZoneRecord) -> Option<Rrsig> {
    rrsigs_in(&[to_resource(record)]).into_iter().next()
}

fn to_resource(record: &ZoneRecord) -> ResourceRecord {
    ResourceRecord {
        name: record.name.clone(),
        class: record.class,
        ttl: record.ttl,
        rdata: record.rdata.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec::{
        dnskeys_in, verify_rrset, Dnskey, Rrset, RrsetProof, DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE,
    };
    use crate::RecordData;
    use crate::dnssec_denial::{
        nsec3s_in, nsecs_in, proves_nodata, proves_nxdomain, proves_wildcard_expansion, Denial,
        WildcardVerdict,
    };
    use crate::dnssec_key::{SigningAlgorithm, SigningKey};
    use crate::zone::parse_zone_file;
    use crate::zone_signer::{sign_zone, DenialChain, SigningPolicy};

    const NOW: u64 = 1_700_000_000;
    const ORIGIN: &str = "example.com.";

    const ZONE: &str = r#"$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@       IN NS  ns1.example.com.
ns1     IN A   192.0.2.1
www     IN A   192.0.2.10
www     IN AAAA 2001:db8::10
mail    IN MX  10 mail.example.com.
*       IN A   192.0.2.99
deep.a.b IN TXT "down here"
"#;

    fn signed(chain: DenialChain) -> Zone {
        let keys = vec![
            SigningKey::generate(
                SigningAlgorithm::EcdsaP256Sha256,
                ORIGIN,
                DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
            )
            .unwrap(),
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ORIGIN, DNSKEY_FLAG_ZONE)
                .unwrap(),
        ];
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        sign_zone(
            &zone,
            &keys,
            &SigningPolicy::valid_for(NOW, 30 * 86_400).with_chain(chain),
        )
        .unwrap()
    }

    fn keys_of(zone: &Zone) -> Vec<Dnskey> {
        dnskeys_in(
            &zone
                .query(zone.origin(), rt::DNSKEY)
                .into_iter()
                .map(to_resource)
                .collect::<Vec<_>>(),
        )
    }

    /// The answer section rdnsd would build, plus what this module adds.
    fn answer(zone: &Zone, qname: &str, qtype: u16) -> (Vec<RecordData>, AnswerSignatures) {
        let rdatas = zone
            .query(qname, qtype)
            .into_iter()
            .map(|r| r.rdata.clone())
            .collect();
        (rdatas, answer_signatures(zone, qname, qtype))
    }

    /// Judge the answer with the validator, exactly as a client would: the
    /// records as they left, the signatures as they left, nothing from the zone.
    fn judge(zone: &Zone, qname: &str, qtype: u16) -> RrsetProof {
        let (rdatas, sigs) = answer(zone, qname, qtype);
        let rrsigs = crate::dnssec::rrsigs_in(&sigs.records);
        verify_rrset(
            &Rrset::new(qname, qtype, 1, &rdatas),
            &rrsigs,
            &keys_of(zone),
            ORIGIN,
            NOW,
        )
    }

    #[test]
    fn an_ordinary_answer_goes_out_with_the_signature_that_covers_it() {
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            assert!(
                matches!(judge(&zone, "www.example.com.", rt::A), RrsetProof::Verified { .. }),
                "{chain:?}"
            );
            // And only the signature that covers it: an RRSIG over the AAAA at
            // the same name is not evidence about the A, and sending it invites
            // a validator to try the wrong one.
            let (_, sigs) = answer(&zone, "www.example.com.", rt::A);
            assert_eq!(sigs.records.len(), 1, "{chain:?}");
            assert!(sigs.wildcard.is_none());
        }
    }

    #[test]
    fn a_wildcard_answer_carries_its_signature_and_a_denial_of_the_name_asked_for() {
        // The attack this shape exists to stop: one wildcard answer verifies at
        // every name the wildcard reaches, so without a denial of the queried
        // name it is a valid answer for all of them.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            let qname = "anything.example.com.";
            let proof = judge(&zone, qname, rt::A);
            let RrsetProof::Verified {
                wildcard: Some(wildcard),
                ..
            } = proof
            else {
                panic!("{chain:?}: expected a wildcard expansion, got {proof:?}");
            };
            assert_eq!(wildcard, "*.example.com.");

            let (_, sigs) = answer(&zone, qname, rt::A);
            assert_eq!(sigs.wildcard.as_deref(), Some("*.example.com."));
            // The RRSIG goes out owned by the name the client asked about.
            assert!(sigs.records.iter().all(|r| r.name == qname));

            let proof_records = proof_of_absence(&zone, qname);
            assert!(!proof_records.is_empty(), "{chain:?}");
            let verdict = proves_wildcard_expansion(
                qname,
                &wildcard,
                &nsecs_in(&proof_records),
                &nsec3s_in(&proof_records),
            );
            assert!(matches!(verdict, WildcardVerdict::Proved), "{chain:?}: {verdict:?}");
        }
    }

    #[test]
    fn nodata_carries_a_record_at_the_name_denying_the_type() {
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            let records = negative_proof(&zone, "www.example.com.", &zone.name_kind("www.example.com."));
            let denial = proves_nodata(
                "www.example.com.",
                ORIGIN,
                rt::MX,
                &nsecs_in(&records),
                &nsec3s_in(&records),
            );
            assert!(matches!(denial, Denial::Proved), "{chain:?}: {denial:?}");
        }
    }

    #[test]
    fn nodata_through_a_wildcard_says_both_halves() {
        // `anything.example.com.` has no MX. The wildcard is what matched it, so
        // the record denying MX sits at `*.example.com.` — and on its own that
        // is a statement about a name the client never asked about. The denial
        // of the queried name is what ties the two together.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            let records = negative_proof(&zone, "anything.example.com.", &zone.name_kind("anything.example.com."));
            let denial = proves_nodata(
                "anything.example.com.",
                ORIGIN,
                rt::MX,
                &nsecs_in(&records),
                &nsec3s_in(&records),
            );
            assert!(matches!(denial, Denial::Proved), "{chain:?}: {denial:?}");
        }
    }

    #[test]
    fn nxdomain_denies_the_name_and_the_wildcard_that_could_have_answered_it() {
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            // Two labels down, so the apex wildcard cannot reach it — which is
            // what makes this NXDOMAIN rather than a wildcard answer.
            let qname = "gone.a.b.example.com.";
            let records = negative_proof(&zone, qname, &zone.name_kind(qname));
            let denial = proves_nxdomain(qname, ORIGIN, &nsecs_in(&records), &nsec3s_in(&records));
            assert!(matches!(denial, Denial::Proved), "{chain:?}: {denial:?}");
        }
    }

    #[test]
    fn every_denial_record_travels_with_its_own_signature() {
        // A proof is only a proof if it is signed. An unsigned NSEC in the
        // authority section is a record an attacker could have written.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            let records = negative_proof(&zone, "gone.a.b.example.com.", &zone.name_kind("gone.a.b.example.com."));
            let keys = keys_of(&zone);
            let sigs = crate::dnssec::rrsigs_in(&records);

            let mut denials = 0;
            for record in &records {
                if !matches!(record.rdata.rtype, rt::NSEC | rt::NSEC3) {
                    continue;
                }
                denials += 1;
                let rdatas: Vec<RecordData> = records
                    .iter()
                    .filter(|r| r.name == record.name && r.rdata.rtype == record.rdata.rtype)
                    .map(|r| r.rdata.clone())
                    .collect();
                let proof = verify_rrset(
                    &Rrset::new(&record.name, record.rdata.rtype, 1, &rdatas),
                    &sigs,
                    &keys,
                    ORIGIN,
                    NOW,
                );
                assert!(
                    matches!(proof, RrsetProof::Verified { .. }),
                    "{chain:?}: {} is unsigned: {proof:?}",
                    record.name
                );
            }
            assert!(denials > 0, "{chain:?}: no denial records at all");

            // The SOA's signature comes too — rdnsd puts the SOA itself in the
            // authority section of every negative answer, and an unsigned one
            // there is one more record for a validator to reject.
            assert!(
                sigs.iter().any(|s| s.type_covered == rt::SOA),
                "{chain:?}: the SOA went out unsigned"
            );
        }
    }

    #[test]
    fn an_unsigned_zone_gets_nothing_however_the_client_asked() {
        // The DO bit says the client understands DNSSEC, not that the zone owes
        // it anything. Most zones are unsigned and answering one is the normal
        // case, not a failure.
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        assert!(!is_signed(&zone));
        assert!(answer_signatures(&zone, "www.example.com.", rt::A)
            .records
            .is_empty());
        assert!(negative_proof(&zone, "nope.example.com.", &zone.name_kind("nope.example.com.")).is_empty());
        assert!(proof_of_absence(&zone, "nope.example.com.").is_empty());
    }

    #[test]
    fn the_nsec_chain_is_searched_rather_than_scanned() {
        // The covering record is found by range, not by walking the zone. This
        // checks the answer is the right one at both ends of the chain and at
        // the wrap — the three places an ordered lookup gets it wrong.
        let zone = signed(DenialChain::Nsec);
        let covering = |name: &str| {
            let record = zone.nsec_covering(name).expect("a chain to search");
            crate::dnssec_denial::Nsec::from_record(&to_resource(record)).unwrap()
        };
        // Before everything in the zone, which is the wrap-around case: the
        // last NSEC points back at the apex and so covers this.
        assert!(covering("aaa.example.com.").covers("aaa.example.com."));
        // In the middle.
        assert!(covering("nnn.example.com.").covers("nnn.example.com."));
        // After everything.
        assert!(covering("zzz.example.com.").covers("zzz.example.com."));
    }
}
