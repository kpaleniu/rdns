//! Which DNSSEC records a reply owes, given the zone and the question.
//!
//! Only a plain positive answer is just signatures. A wildcard answer owes a
//! denial of the name asked for (RFC 4035 §3.1.3), NODATA a record at the name
//! whose bitmap lacks the type, NXDOMAIN a denial of the name and of the
//! wildcard that could have answered it. [`crate::dnssec_denial`] reads the same
//! rules from the other end and the tests here judge the output with it.
//!
//! An unsigned zone gets nothing, whatever DO says.

use crate::dnssec::canonical_name;
use crate::dnssec_denial::{nsec3_hash_in, nsec3_owner_name, Nsec3, NSEC3_HASH_LEN};
use crate::utils::names_equal;
use crate::utils::record_types as rt;
use crate::zone::{NameKind, Zone, ZoneRecord};
use crate::Qtype;
use crate::ResourceRecord;
use crate::Rtype;
use crate::Ttl;

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
/// The apex DNSKEY RRset, not "are there any RRSIGs": signatures with no
/// published key make an insecure answer bogus rather than validatable.
pub fn is_signed(zone: &Zone) -> bool {
    zone.locate(zone.origin()).has_type(Qtype::of(rt::DNSKEY))
}

/// The RRSIGs covering the answer to `qname`/`qtype`.
///
/// A wildcard's signature is re-owned onto the queried name with its label count
/// left alone: that is what lets a validator reconstruct the name really signed
/// (RFC 4035 §5.3.2).
pub fn answer_signatures(zone: &Zone, qname: &str, qtype: Qtype) -> AnswerSignatures {
    if !is_signed(zone) {
        return AnswerSignatures::default();
    }
    let qname = canonical_name(qname);
    let mut out = AnswerSignatures::default();
    for record in zone.query(&qname, Qtype::of(rt::RRSIG)) {
        let Some(type_covered) = record.rdata.rrsig_type_covered() else {
            continue;
        };
        // `Qtype::matches`, not `== qtype`: no RRSIG covers a QTYPE, so ANY
        // (255) would match nothing and hand back a signed name's data unsigned.
        // The same rule excludes the DNSSEC meta types (RFC 4035 §3.1.1).
        if !qtype.matches(type_covered) {
            continue;
        }
        // An RRSIG's owner is the record's own name, so this is the wildcard
        // test without the parse: `query` fell back to `*.<encloser>`.
        if !names_equal(&record.name, &qname) {
            out.wildcard = Some(canonical_name(&record.name));
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
/// Half of an NXDOMAIN, and the whole of what a wildcard answer owes. One record
/// under NSEC; under NSEC3 a hash chain cannot point at a name, so it is the
/// closest encloser and the next closer name (RFC 5155 §7.2.1).
pub fn proof_of_absence(zone: &Zone, qname: &str) -> Vec<ResourceRecord> {
    if !is_signed(zone) {
        return Vec::new();
    }
    let qname = canonical_name(qname);
    let mut out = Vec::new();
    if zone.has_nsec3_chain() {
        if let Some((chain, encloser)) = Nsec3Chain::and_encloser(zone, &qname) {
            chain.push_absence(zone, &qname, &encloser, &mut out);
        }
    } else if let Some(nsec) = zone.nsec_covering(&qname) {
        push_with_signatures(zone, nsec, &mut out);
    }
    out
}

/// The authority records a negative answer needs beyond the SOA.
///
/// Each case of `kind` owes something different; see the match below.
///
/// A [`NameKind`] rather than a bool because the wildcard has to come from the
/// zone: "the first label replaced by `*`" is wrong for anything a wildcard
/// reaches more than one label down, and denies a name that does not exist.
pub fn negative_proof(zone: &Zone, qname: &str, kind: &NameKind) -> Vec<ResourceRecord> {
    if !is_signed(zone) {
        return Vec::new();
    }
    let qname = canonical_name(qname);
    let mut out = soa_signatures(zone);

    match kind {
        NameKind::NotFound => deny_the_name_and_its_wildcard(zone, &qname, &mut out),
        // NODATA: the record at the name lists the types it has. An empty
        // non-terminal exists too, and the signer gives it a chain entry.
        NameKind::Exact | NameKind::EmptyNonTerminal => match_at_name(zone, &qname, &mut out),
        // NODATA through a wildcard owes both halves: the wildcard's record for
        // the missing type, and the denial of the queried name, without which
        // this reads as a NODATA about the wildcard name itself.
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
/// Neither present, and a referral is indistinguishable from one an attacker
/// stripped the DS out of.
///
/// The NS RRset gets no signature: it is the child's data (RFC 4035 §2.2).
pub fn delegation_proof(zone: &Zone, cut: &str) -> Vec<ResourceRecord> {
    if !is_signed(zone) {
        return Vec::new();
    }
    let cut = canonical_name(cut);

    let ds = zone.query(&cut, Qtype::of(rt::DS));
    if !ds.is_empty() {
        let mut out: Vec<ResourceRecord> = ds.into_iter().map(to_resource).collect();
        out.extend(signatures_at(zone, &cut, rt::DS));
        return out;
    }

    // No DS: the record at the cut says so by listing NS and not DS.
    let mut out = Vec::new();
    match_at_name(zone, &cut, &mut out);
    if out.is_empty() && zone.has_nsec3_chain() {
        // Under opt-out an insecure delegation has no NSEC3 of its own
        // (RFC 5155 §7.2.9), so the closest-encloser pair is the proof.
        out.extend(proof_of_absence(zone, &cut));
    }
    out
}

/// An NXDOMAIN's two halves: `qname` does not exist, and neither does the
/// wildcard that could have answered it (RFC 4035 §5.4).
///
/// One function rather than two calls, because under NSEC3 both proofs hang off
/// the closest encloser and finding it is a hash per label of the QNAME
/// (RFC 5155 §7.2.1) — asked per proof, the walk runs twice for one answer.
///
/// `*.<closest encloser>` is guaranteed absent by [`Zone::name_kind`] — were it
/// present the answer would be a wildcard match — and that is load-bearing:
/// `nsec_covering` searches strictly below its argument, so a name in the chain
/// yields the record before it, which proves nothing.
fn deny_the_name_and_its_wildcard(zone: &Zone, qname: &str, out: &mut Vec<ResourceRecord>) {
    if zone.has_nsec3_chain() {
        if let Some((chain, encloser)) = Nsec3Chain::and_encloser(zone, qname) {
            chain.push_absence(zone, qname, &encloser, out);
            chain.push_wildcard_denial(zone, &encloser, out);
        }
        return;
    }
    if let Some(nsec) = zone.nsec_covering(qname) {
        push_with_signatures(zone, nsec, out);
    }
    if let Some(encloser) = nsec_closest_encloser(zone, qname) {
        if let Some(nsec) = zone.nsec_covering(&format!("*.{encloser}")) {
            push_with_signatures(zone, nsec, out);
        }
    }
}

/// The denial record sitting *at* `name`, with its signatures.
fn match_at_name(zone: &Zone, name: &str, out: &mut Vec<ResourceRecord>) {
    if zone.has_nsec3_chain() {
        if let Some(params) = Nsec3Chain::of(zone) {
            push_matching_nsec3(zone, &params, name, out);
        }
        return;
    }
    // `query` falls back to a wildcard, whose NSEC says nothing about the name
    // asked for; only the literal records will do.
    if !zone.holds_name(name) {
        return;
    }
    for record in zone.query(name, Qtype::of(rt::NSEC)) {
        push_with_signatures(zone, record, out);
    }
}

/// The apex SOA's signatures, capped as the SOA itself is —
/// `min(MINIMUM, the record's own TTL)`, RFC 2308 §3. A signature outliving the
/// record it covers leaves a cache holding an RRSIG with nothing to check.
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

/// The zone's MINIMUM, the ceiling a negative answer's TTLs take (RFC 2308 §3).
fn negative_ttl_cap(zone: &Zone) -> Ttl {
    zone.query(zone.origin(), Qtype::of(rt::SOA))
        .first()
        .and_then(|soa| soa.rdata.soa_minimum())
        .map_or(Ttl::ZERO, Ttl::from_secs)
}

fn signatures_at(zone: &Zone, name: &str, rtype: Rtype) -> Vec<ResourceRecord> {
    if !zone.holds_name(name) {
        return Vec::new();
    }
    zone.query(name, Qtype::of(rt::RRSIG))
        .into_iter()
        .filter(|r| r.rdata.rrsig_type_covered() == Some(rtype))
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
        // One NSEC often denies both a name and the wildcard above it; the
        // second copy is bytes on an amplification path.
        return;
    }
    let signatures = signatures_at(zone, &record.name, record.rdata.rtype());
    out.push(resource);
    out.extend(signatures);
}

/// The salt and iteration count this zone's NSEC3 chain was built with, and the
/// lookups that go through them.
///
/// Not [`crate::dnssec_denial::Nsec3Params`], the borrowed triple one *record*
/// hashes under: this is owned, derived from a whole zone, and answers questions
/// about the chain.
struct Nsec3Chain {
    salt: Vec<u8>,
    iterations: u16,
}

impl Nsec3Chain {
    /// Read off the chain itself, not NSEC3PARAM: this server holds one chain
    /// rather than choosing between rollover chains (RFC 5155 §4.1), and an
    /// NSEC3PARAM left from a previous signing hashes every denial to nothing.
    fn of(zone: &Zone) -> Option<Self> {
        zone.any_nsec3()
            .and_then(|r| Nsec3::from_record(&to_resource(r)))
            .map(|n| Nsec3Chain {
                salt: n.salt,
                iterations: n.iterations,
            })
    }

    fn hash(&self, name: &str) -> Option<[u8; NSEC3_HASH_LEN]> {
        nsec3_hash_in(name, &self.salt, self.iterations).ok()
    }

    fn owner(&self, zone: &Zone, name: &str) -> Option<String> {
        Some(nsec3_owner_name(&self.hash(name)?, zone.origin()))
    }

    /// The chain and the closest encloser of `qname` — what every NSEC3 proof
    /// about that name starts from, derived once.
    fn and_encloser(zone: &Zone, qname: &str) -> Option<(Self, String)> {
        let chain = Self::of(zone)?;
        let encloser = chain.closest_encloser(zone, qname)?;
        Some((chain, encloser))
    }

    /// RFC 5155 §7.2.1: the record matching the closest encloser, and the one
    /// covering the next closer name.
    fn push_absence(
        &self,
        zone: &Zone,
        qname: &str,
        encloser: &str,
        out: &mut Vec<ResourceRecord>,
    ) {
        push_matching_nsec3(zone, self, encloser, out);
        if let Some(next_closer) = child_towards(qname, encloser) {
            push_covering_nsec3(zone, self, &next_closer, out);
        }
    }

    /// The denial of the wildcard at `encloser`.
    fn push_wildcard_denial(&self, zone: &Zone, encloser: &str, out: &mut Vec<ResourceRecord>) {
        push_covering_nsec3(zone, self, &format!("*.{encloser}"), out);
    }

    /// The deepest ancestor of `qname` that the chain has a record for.
    ///
    /// Walked rather than looked up by name: under NSEC3 an empty non-terminal
    /// has an NSEC3 and no records, so the index would miss it and the proof
    /// would name the wrong encloser.
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
    params: &Nsec3Chain,
    name: &str,
    out: &mut Vec<ResourceRecord>,
) {
    let Some(owner) = params.owner(zone, name) else {
        return;
    };
    for record in zone.query(&owner, Qtype::of(rt::NSEC3)) {
        push_with_signatures(zone, record, out);
    }
}

fn push_covering_nsec3(
    zone: &Zone,
    params: &Nsec3Chain,
    name: &str,
    out: &mut Vec<ResourceRecord>,
) {
    let Some(hash) = params.hash(name) else {
        return;
    };
    let Some(record) = zone.nsec3_covering(&hash) else {
        return;
    };
    push_with_signatures(zone, record, out);
}

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
    use crate::dnssec_denial::{
        nsec3s_in, nsecs_in, proves_nodata, proves_nxdomain, proves_wildcard_expansion, Denial,
        WildcardVerdict,
    };
    use crate::dnssec_key::{SigningAlgorithm, SigningKey};
    use crate::zone::parse_zone_file;
    use crate::zone_signer::{sign_zone, DenialChain, SigningPolicy};
    use crate::Class;
    use crate::RecordData;

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
                .query(zone.origin(), Qtype::of(rt::DNSKEY))
                .into_iter()
                .map(to_resource)
                .collect::<Vec<_>>(),
        )
    }

    /// The answer section rdnsd would build, plus what this module adds.
    fn answer(zone: &Zone, qname: &str, qtype: Qtype) -> (Vec<RecordData>, AnswerSignatures) {
        let rdatas = zone
            .query(qname, qtype)
            .into_iter()
            .map(|r| r.rdata.clone())
            .collect();
        (rdatas, answer_signatures(zone, qname, qtype))
    }

    /// Judge the answer with the validator as a client would: what left, not
    /// what the zone holds.
    fn judge(zone: &Zone, qname: &str, qtype: Qtype) -> RrsetProof {
        let (rdatas, sigs) = answer(zone, qname, qtype);
        let rrsigs = crate::dnssec::rrsigs_in(&sigs.records);
        verify_rrset(
            &Rrset::new(qname, Rtype::new(qtype.to_u16()), Class::new(1), &rdatas),
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
                matches!(
                    judge(&zone, "www.example.com.", Qtype::of(rt::A)),
                    RrsetProof::Verified { .. }
                ),
                "{chain:?}"
            );
            // Only the signature that covers it: the AAAA's RRSIG at the same
            // name is not evidence about the A.
            let (_, sigs) = answer(&zone, "www.example.com.", Qtype::of(rt::A));
            assert_eq!(sigs.records.len(), 1, "{chain:?}");
            assert!(sigs.wildcard.is_none());
        }
    }

    #[test]
    fn a_wildcard_answer_carries_its_signature_and_a_denial_of_the_name_asked_for() {
        // One wildcard answer verifies at every name the wildcard reaches, so
        // without the denial it is a valid answer for all of them.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            let qname = "anything.example.com.";
            let proof = judge(&zone, qname, Qtype::of(rt::A));
            let RrsetProof::Verified {
                wildcard: Some(wildcard),
                ..
            } = proof
            else {
                panic!("{chain:?}: expected a wildcard expansion, got {proof:?}");
            };
            assert_eq!(wildcard, "*.example.com.");

            let (_, sigs) = answer(&zone, qname, Qtype::of(rt::A));
            assert_eq!(sigs.wildcard.as_deref(), Some("*.example.com."));
            assert!(sigs.records.iter().all(|r| r.name == qname));

            let proof_records = proof_of_absence(&zone, qname);
            assert!(!proof_records.is_empty(), "{chain:?}");
            let verdict = proves_wildcard_expansion(
                qname,
                &wildcard,
                &nsecs_in(&proof_records),
                &nsec3s_in(&proof_records),
            );
            assert!(
                matches!(verdict, WildcardVerdict::Proved),
                "{chain:?}: {verdict:?}"
            );
        }
    }

    #[test]
    fn nodata_carries_a_record_at_the_name_denying_the_type() {
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            let records = negative_proof(
                &zone,
                "www.example.com.",
                &zone.name_kind("www.example.com."),
            );
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
        // `anything.example.com.` has no MX, so the record denying MX sits at
        // `*.example.com.` — a statement about a name nobody asked about until
        // the denial of the queried name ties the two together.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            let records = negative_proof(
                &zone,
                "anything.example.com.",
                &zone.name_kind("anything.example.com."),
            );
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
            // Two labels down, past the apex wildcard's reach, so NXDOMAIN.
            let qname = "gone.a.b.example.com.";
            let records = negative_proof(&zone, qname, &zone.name_kind(qname));
            let denial = proves_nxdomain(qname, ORIGIN, &nsecs_in(&records), &nsec3s_in(&records));
            assert!(matches!(denial, Denial::Proved), "{chain:?}: {denial:?}");
        }
    }

    #[test]
    fn every_denial_record_travels_with_its_own_signature() {
        // An unsigned NSEC is a record an attacker could have written.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            let records = negative_proof(
                &zone,
                "gone.a.b.example.com.",
                &zone.name_kind("gone.a.b.example.com."),
            );
            let keys = keys_of(&zone);
            let sigs = crate::dnssec::rrsigs_in(&records);

            let mut denials = 0;
            for record in &records {
                if !matches!(record.rdata.rtype(), rt::NSEC | rt::NSEC3) {
                    continue;
                }
                denials += 1;
                let rdatas: Vec<RecordData> = records
                    .iter()
                    .filter(|r| r.name == record.name && r.rdata.rtype() == record.rdata.rtype())
                    .map(|r| r.rdata.clone())
                    .collect();
                let proof = verify_rrset(
                    &Rrset::new(&record.name, record.rdata.rtype(), Class::new(1), &rdatas),
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

            // The SOA is in the authority section of every negative answer, so
            // its signature comes too.
            assert!(
                sigs.iter().any(|s| s.type_covered == rt::SOA),
                "{chain:?}: the SOA went out unsigned"
            );
        }
    }

    #[test]
    fn an_unsigned_zone_gets_nothing_however_the_client_asked() {
        // DO says the client understands DNSSEC, not that the zone owes it
        // anything.
        let zone = parse_zone_file(ZONE, ORIGIN).unwrap();
        assert!(!is_signed(&zone));
        assert!(
            answer_signatures(&zone, "www.example.com.", Qtype::of(rt::A))
                .records
                .is_empty()
        );
        assert!(negative_proof(
            &zone,
            "nope.example.com.",
            &zone.name_kind("nope.example.com.")
        )
        .is_empty());
        assert!(proof_of_absence(&zone, "nope.example.com.").is_empty());
    }

    #[test]
    fn the_nsec_chain_is_searched_rather_than_scanned() {
        // Found by range, not by walking the zone: both ends and the wrap are
        // where an ordered lookup gets it wrong.
        let zone = signed(DenialChain::Nsec);
        let covering = |name: &str| {
            let record = zone.nsec_covering(name).expect("a chain to search");
            crate::dnssec_denial::Nsec::from_record(&to_resource(record)).unwrap()
        };
        // Before everything: the wrap, where the last NSEC points at the apex.
        assert!(covering("aaa.example.com.").covers("aaa.example.com."));
        assert!(covering("nnn.example.com.").covers("nnn.example.com."));
        assert!(covering("zzz.example.com.").covers("zzz.example.com."));
    }
}
