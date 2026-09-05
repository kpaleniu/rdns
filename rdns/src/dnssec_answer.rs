//! Which DNSSEC records a reply owes, given the zone and the question.
//!
//! Only a plain positive answer is just signatures. A wildcard answer owes a
//! denial of the name asked for (RFC 4035 §3.1.3), NODATA a record at the name
//! whose bitmap lacks the type, NXDOMAIN a denial of the name and of the
//! wildcard that could have answered it. [`crate::dnssec_denial`] reads the same
//! rules from the other end and the tests here judge the output with it.
//!
//! An unsigned zone gets nothing, whatever DO says.
//!
//! Every entry point writes into a [`ResponseWriter`] rather than returning
//! records. Nothing here turned out to need synthesizing: a wildcard's RRSIG is
//! re-owned by passing a different name to the writer and a negative answer's
//! TTL cap by passing a different TTL, so no record is built to be copied to the
//! wire. What is left allocating is the names looked up *by* — the folded QNAME,
//! an NSEC3 owner per candidate, `*.<encloser>` — and the lookups' own keys.

use crate::dnssec::canonical_name;
use crate::dnssec_denial::{nsec3_hash_in, nsec3_owner_name, NSEC3_HASH_LEN};
use crate::error::WireError;
use crate::response::{ResponseWriter, Section};
use crate::utils::record_types as rt;
use crate::utils::{names_equal, parent_name};
use crate::zone::{Located, NameKind, Zone, ZoneRecord};
use crate::Qtype;
use crate::Rtype;
use crate::Ttl;

/// Whether this zone has signatures to serve at all.
///
/// The apex DNSKEY RRset, not "are there any RRSIGs": signatures with no
/// published key make an insecure answer bogus rather than validatable.
pub fn is_signed(zone: &Zone) -> bool {
    zone.locate(zone.origin()).has_type(Qtype::of(rt::DNSKEY))
}

/// Write the RRSIGs covering the answer to `qname`/`qtype`.
///
/// True when the answer was synthesized from a wildcard, which means it is not
/// finished: it still owes [`push_proof_of_absence`] for the name asked about.
///
/// A wildcard's signature is re-owned onto the queried name with its label count
/// left alone: that is what lets a validator reconstruct the name really signed
/// (RFC 4035 §5.3.2).
///
/// `at` is the answer's own lookup, handed in rather than repeated: the caller
/// has just read the records out of it (`TODO.md` #25a). `qname` is the name it
/// was located with, canonical, and is what the signatures are echoed under.
pub fn push_answer_signatures(
    at: &Located,
    qname: &str,
    qtype: Qtype,
    w: &mut ResponseWriter,
) -> Result<bool, WireError> {
    if !is_signed(at.zone()) {
        return Ok(false);
    }
    let mut wildcard = false;
    for record in at.of_type(Qtype::of(rt::RRSIG)) {
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
        // test without the parse: `locate` fell back to `*.<encloser>`.
        wildcard |= !names_equal(&record.name, qname);
        w.push(
            Section::Answer,
            qname,
            record.class,
            record.ttl,
            &record.rdata,
        )?;
    }
    Ok(wildcard)
}

/// Write the proof that `qname` does not exist.
///
/// Half of an NXDOMAIN, and the whole of what a wildcard answer owes. One record
/// under NSEC; under NSEC3 a hash chain cannot point at a name, so it is the
/// closest encloser and the next closer name (RFC 5155 §7.2.1).
pub fn push_proof_of_absence(
    zone: &Zone,
    qname: &str,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    if !is_signed(zone) {
        return Ok(());
    }
    let qname = canonical_name(qname);
    absence(zone, &qname, &mut Written::default(), w)
}

/// Write the authority records a negative answer needs beyond the SOA.
///
/// Each case of `kind` owes something different; see the match below.
///
/// A [`NameKind`] rather than a bool because the wildcard has to come from the
/// zone: "the first label replaced by `*`" is wrong for anything a wildcard
/// reaches more than one label down, and denies a name that does not exist.
pub fn push_negative_proof(
    zone: &Zone,
    qname: &str,
    kind: &NameKind,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    if !is_signed(zone) {
        return Ok(());
    }
    let qname = canonical_name(qname);
    let written = &mut Written::default();
    push_soa_signatures(zone, w)?;

    match kind {
        NameKind::NotFound => deny_the_name_and_its_wildcard(zone, &qname, written, w),
        // NODATA: the record at the name lists the types it has. An empty
        // non-terminal exists too, and the signer gives it a chain entry.
        NameKind::Exact | NameKind::EmptyNonTerminal => {
            match_at_name(zone, &qname, written, w).map(drop)
        }
        // NODATA through a wildcard owes both halves: the wildcard's record for
        // the missing type, and the denial of the queried name, without which
        // this reads as a NODATA about the wildcard name itself.
        //
        // `NameKind::Wildcard` carries the name absolute and down-cased, so it
        // needs no folding of its own.
        NameKind::Wildcard(wildcard) => {
            match_at_name(zone, wildcard, written, w)?;
            absence(zone, &qname, written, w)
        }
    }
}

/// Write what a referral owes a validating client: the DS RRset with its
/// signature, or the authenticated denial that there is one (RFC 4035 §3.1.4).
///
/// Neither present, and a referral is indistinguishable from one an attacker
/// stripped the DS out of.
///
/// The NS RRset gets no signature: it is the child's data (RFC 4035 §2.2).
pub fn push_delegation_proof(
    zone: &Zone,
    cut: &str,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    if !is_signed(zone) {
        return Ok(());
    }
    let cut = canonical_name(cut);

    let at = zone.locate(&cut);
    let mut delegated = false;
    for ds in at.of_type(Qtype::of(rt::DS)) {
        delegated = true;
        w.push(Section::Authority, &ds.name, ds.class, ds.ttl, &ds.rdata)?;
    }
    if delegated {
        return push_signatures_at(zone, &cut, rt::DS, None, w);
    }

    // No DS: the record at the cut says so by listing NS and not DS.
    let written = &mut Written::default();
    if !match_at_name(zone, &cut, written, w)? && zone.has_nsec3_chain() {
        // Under opt-out an insecure delegation has no NSEC3 of its own
        // (RFC 5155 §7.2.9), so the closest-encloser pair is the proof.
        absence(zone, &cut, written, w)?;
    }
    Ok(())
}

/// [`push_proof_of_absence`] once the name is folded and the tracker exists, so
/// a caller writing two proofs about one name shares both.
fn absence<'z>(
    zone: &'z Zone,
    qname: &str,
    written: &mut Written<'z>,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    if zone.has_nsec3_chain() {
        if let Some((chain, encloser)) = Nsec3Chain::and_encloser(zone, qname) {
            chain.push_absence(zone, qname, encloser, written, w)?;
        }
    } else if let Some(nsec) = zone.nsec_covering(qname) {
        push_with_signatures(zone, nsec, written, w)?;
    }
    Ok(())
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
fn deny_the_name_and_its_wildcard<'z>(
    zone: &'z Zone,
    qname: &str,
    written: &mut Written<'z>,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    if zone.has_nsec3_chain() {
        if let Some((chain, encloser)) = Nsec3Chain::and_encloser(zone, qname) {
            chain.push_absence(zone, qname, encloser, written, w)?;
            chain.push_wildcard_denial(zone, encloser, written, w)?;
        }
        return Ok(());
    }
    if let Some(nsec) = zone.nsec_covering(qname) {
        push_with_signatures(zone, nsec, written, w)?;
    }
    if let Some(encloser) = nsec_closest_encloser(zone, qname) {
        if let Some(nsec) = zone.nsec_covering(&format!("*.{encloser}")) {
            push_with_signatures(zone, nsec, written, w)?;
        }
    }
    Ok(())
}

/// The denial record sitting *at* `name`, with its signatures. True if there was
/// one.
fn match_at_name<'z>(
    zone: &'z Zone,
    name: &str,
    written: &mut Written<'z>,
    w: &mut ResponseWriter,
) -> Result<bool, WireError> {
    if zone.has_nsec3_chain() {
        let Some(chain) = Nsec3Chain::of(zone) else {
            return Ok(false);
        };
        return chain.push_matching(zone, name, written, w);
    }
    // `locate` falls back to a wildcard, whose NSEC says nothing about the name
    // asked for; only the literal records will do.
    let at = zone.locate(name);
    if !matches!(at.kind(), NameKind::Exact) {
        return Ok(false);
    }
    let mut found = false;
    for record in at.of_type(Qtype::of(rt::NSEC)) {
        found |= push_with_signatures(zone, record, written, w)?;
    }
    Ok(found)
}

/// The apex SOA's signatures, capped as the SOA itself is —
/// `min(MINIMUM, the record's own TTL)`, RFC 2308 §3. A signature outliving the
/// record it covers leaves a cache holding an RRSIG with nothing to check.
fn push_soa_signatures(zone: &Zone, w: &mut ResponseWriter) -> Result<(), WireError> {
    let cap = negative_ttl_cap(zone);
    push_signatures_at(zone, zone.origin(), rt::SOA, Some(cap), w)
}

/// The zone's MINIMUM, the ceiling a negative answer's TTLs take (RFC 2308 §3).
fn negative_ttl_cap(zone: &Zone) -> Ttl {
    zone.locate(zone.origin())
        .of_type(Qtype::of(rt::SOA))
        .next()
        .and_then(|soa| soa.rdata.soa_minimum())
        .map_or(Ttl::ZERO, Ttl::from_secs)
}

/// The RRSIGs at `name` covering `rtype`, each capped at `cap` if there is one.
fn push_signatures_at(
    zone: &Zone,
    name: &str,
    rtype: Rtype,
    cap: Option<Ttl>,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    let at = zone.locate(name);
    // A wildcard's signatures are about the wildcard, not about `name`.
    if !matches!(at.kind(), NameKind::Exact) {
        return Ok(());
    }
    for record in at.of_type(Qtype::of(rt::RRSIG)) {
        if record.rdata.rrsig_type_covered() != Some(rtype) {
            continue;
        }
        let ttl = cap.map_or(record.ttl, |cap| record.ttl.min(cap));
        w.push(
            Section::Authority,
            &record.name,
            record.class,
            ttl,
            &record.rdata,
        )?;
    }
    Ok(())
}

/// A record and every signature over it, unless it has gone out already.
fn push_with_signatures<'z>(
    zone: &'z Zone,
    record: &'z ZoneRecord,
    written: &mut Written<'z>,
    w: &mut ResponseWriter,
) -> Result<bool, WireError> {
    if !written.claim(record) {
        return Ok(false);
    }
    w.push(
        Section::Authority,
        &record.name,
        record.class,
        record.ttl,
        &record.rdata,
    )?;
    push_signatures_at(zone, &record.name, record.rdata.rtype(), None, w)?;
    Ok(true)
}

/// The denial records already written, so one that answers two questions does
/// not go out twice — an NSEC3 covering the next closer name often covers
/// `*.<encloser>` as well, and the second copy is bytes on an amplification
/// path.
///
/// By identity, because these are the zone's own records and "the same record"
/// is the question. Three is what a proof owes at most: RFC 5155 §7.2.1's pair
/// plus the wildcard's. Past that it stops recording rather than growing, so an
/// unforeseen fourth costs bytes and not correctness — hence a `debug_assert`
/// and not a panic on a query path.
#[derive(Default)]
struct Written<'z> {
    seen: [Option<&'z ZoneRecord>; 3],
    filled: usize,
}

impl<'z> Written<'z> {
    /// True if `record` has not been written before, recording it if so.
    fn claim(&mut self, record: &'z ZoneRecord) -> bool {
        if self.seen[..self.filled]
            .iter()
            .any(|seen| seen.is_some_and(|seen| std::ptr::eq(seen, record)))
        {
            return false;
        }
        debug_assert!(
            self.filled < self.seen.len(),
            "a proof owes at most three denial records"
        );
        if let Some(slot) = self.seen.get_mut(self.filled) {
            *slot = Some(record);
            self.filled += 1;
        }
        true
    }
}

/// The salt and iteration count this zone's NSEC3 chain was built with, and the
/// lookups that go through them.
///
/// Not [`crate::dnssec_denial::Nsec3Params`], the borrowed triple one *record*
/// hashes under: this is derived from a whole zone and answers questions about
/// the chain.
struct Nsec3Chain<'a> {
    salt: &'a [u8],
    iterations: u16,
}

impl<'a> Nsec3Chain<'a> {
    /// Read off the chain itself, not NSEC3PARAM: this server holds one chain
    /// rather than choosing between rollover chains (RFC 5155 §4.1), and an
    /// NSEC3PARAM left from a previous signing hashes every denial to nothing.
    ///
    /// Read at its offset rather than parsed: the record is the zone's, so the
    /// salt is borrowed, and a full decode copies the next hashed owner and the
    /// type bitmap that nothing here looks at.
    fn of(zone: &'a Zone) -> Option<Self> {
        let (iterations, salt) = zone.any_nsec3()?.rdata.nsec3_parameters()?;
        Some(Nsec3Chain { salt, iterations })
    }

    fn hash(&self, name: &str) -> Option<[u8; NSEC3_HASH_LEN]> {
        nsec3_hash_in(name, self.salt, self.iterations).ok()
    }

    fn owner(&self, zone: &Zone, name: &str) -> Option<String> {
        Some(nsec3_owner_name(&self.hash(name)?, zone.origin()))
    }

    /// The chain and the closest encloser of `qname` — what every NSEC3 proof
    /// about that name starts from, derived once.
    fn and_encloser<'n>(zone: &'a Zone, qname: &'n str) -> Option<(Self, &'n str)> {
        let chain = Self::of(zone)?;
        let encloser = chain.closest_encloser(zone, qname)?;
        Some((chain, encloser))
    }

    /// RFC 5155 §7.2.1: the record matching the closest encloser, and the one
    /// covering the next closer name.
    fn push_absence<'z>(
        &self,
        zone: &'z Zone,
        qname: &str,
        encloser: &str,
        written: &mut Written<'z>,
        w: &mut ResponseWriter,
    ) -> Result<(), WireError> {
        self.push_matching(zone, encloser, written, w)?;
        if let Some(next_closer) = child_towards(qname, encloser) {
            self.push_covering(zone, next_closer, written, w)?;
        }
        Ok(())
    }

    /// The denial of the wildcard at `encloser`.
    fn push_wildcard_denial<'z>(
        &self,
        zone: &'z Zone,
        encloser: &str,
        written: &mut Written<'z>,
        w: &mut ResponseWriter,
    ) -> Result<(), WireError> {
        self.push_covering(zone, &format!("*.{encloser}"), written, w)
    }

    /// The chain's record *at* `name`, if it has one.
    fn push_matching<'z>(
        &self,
        zone: &'z Zone,
        name: &str,
        written: &mut Written<'z>,
        w: &mut ResponseWriter,
    ) -> Result<bool, WireError> {
        let Some(owner) = self.owner(zone, name) else {
            return Ok(false);
        };
        let mut found = false;
        let at = zone.locate(&owner);
        for record in at.of_type(Qtype::of(rt::NSEC3)) {
            found |= push_with_signatures(zone, record, written, w)?;
        }
        Ok(found)
    }

    /// The chain's record whose span contains `name`.
    fn push_covering<'z>(
        &self,
        zone: &'z Zone,
        name: &str,
        written: &mut Written<'z>,
        w: &mut ResponseWriter,
    ) -> Result<(), WireError> {
        let Some(hash) = self.hash(name) else {
            return Ok(());
        };
        let Some(record) = zone.nsec3_covering(&hash) else {
            return Ok(());
        };
        push_with_signatures(zone, record, written, w).map(drop)
    }

    /// The deepest ancestor of `qname` that the chain has a record for.
    ///
    /// Walked rather than looked up by name: under NSEC3 an empty non-terminal
    /// has an NSEC3 and no records, so the index would miss it and the proof
    /// would name the wrong encloser.
    ///
    /// `qname` must be absolute, which every caller here has already made it —
    /// each ancestor is then a suffix of it rather than a new `String`.
    fn closest_encloser<'n>(&self, zone: &Zone, qname: &'n str) -> Option<&'n str> {
        let mut name = qname;
        loop {
            if self
                .owner(zone, name)
                .is_some_and(|owner| zone.holds_name(&owner))
            {
                return Some(name);
            }
            if names_equal(name, zone.origin()) {
                return None;
            }
            name = parent_name(name)?;
        }
    }
}

/// The deepest ancestor of `qname` the zone holds a name for. Under NSEC every
/// name in the chain has a record, empty non-terminals included, so the index
/// answers this directly.
fn nsec_closest_encloser<'n>(zone: &Zone, qname: &'n str) -> Option<&'n str> {
    let mut name = qname;
    loop {
        if zone.holds_name(name) {
            return Some(name);
        }
        if names_equal(name, zone.origin()) {
            return None;
        }
        name = parent_name(name)?;
    }
}

/// The name one label below `encloser` on the way to `qname` — the "next
/// closer" name of RFC 5155 §1.3.
fn child_towards<'n>(qname: &'n str, encloser: &str) -> Option<&'n str> {
    if names_equal(qname, encloser) {
        return None;
    }
    let mut name = qname;
    loop {
        let up = parent_name(name)?;
        if names_equal(up, encloser) {
            return Some(name);
        }
        name = up;
    }
}

#[cfg(test)]
fn to_resource(record: &ZoneRecord) -> crate::ResourceRecord {
    crate::ResourceRecord {
        name: record.name.clone(),
        class: record.class,
        ttl: record.ttl,
        rdata: record.rdata.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::NameCompressor;
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
    use crate::DnsMessageBuilder;
    use crate::RecordData;
    use crate::ResourceRecord;

    /// The records a proof writes, read back off the wire.
    ///
    /// The entry points write bytes now, so a test that wants to look at
    /// records has to parse them — which is the right way round: our serializer
    /// agreeing with our own record structs proves nothing, and this puts the
    /// reader between the two (`CLAUDE.md` §1). Both sections, because a
    /// signature goes in the answer and a denial in the authority.
    fn written(
        f: impl FnOnce(&mut ResponseWriter) -> Result<(), WireError>,
    ) -> Vec<ResourceRecord> {
        let request = DnsMessageBuilder::new()
            .with_query("example.com.", Qtype::of(rt::SOA))
            .with_id(1)
            .build();
        let mut out = Vec::new();
        let mut compressor = NameCompressor::new();
        // `u16::MAX`: nothing here is about truncation.
        let mut w = ResponseWriter::start(&mut out, &mut compressor, u16::MAX as usize, &request)
            .expect("start a reply");
        f(&mut w).expect("the proof writes");
        w.finish().expect("the reply serializes");
        let reply = crate::DnsMessage::try_from_bytes(&out).expect("and parses back");
        reply.answers.into_iter().chain(reply.authorities).collect()
    }

    fn signatures_for(zone: &Zone, qname: &str, qtype: Qtype) -> (Vec<ResourceRecord>, bool) {
        let mut wildcard = false;
        let records = written(|w| {
            let qname = canonical_name(qname);
            wildcard = push_answer_signatures(&zone.locate(&qname), &qname, qtype, w)?;
            Ok(())
        });
        (records, wildcard)
    }

    fn absence_of(zone: &Zone, qname: &str) -> Vec<ResourceRecord> {
        written(|w| push_proof_of_absence(zone, qname, w))
    }

    fn negative(zone: &Zone, qname: &str, kind: &NameKind) -> Vec<ResourceRecord> {
        written(|w| push_negative_proof(zone, qname, kind, w))
    }

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
    fn answer(zone: &Zone, qname: &str, qtype: Qtype) -> (Vec<RecordData>, Vec<ResourceRecord>) {
        let rdatas = zone
            .query(qname, qtype)
            .into_iter()
            .map(|r| r.rdata.clone())
            .collect();
        (rdatas, signatures_for(zone, qname, qtype).0)
    }

    /// Judge the answer with the validator as a client would: what left, not
    /// what the zone holds.
    fn judge(zone: &Zone, qname: &str, qtype: Qtype) -> RrsetProof {
        let (rdatas, sigs) = answer(zone, qname, qtype);
        let rrsigs = crate::dnssec::rrsigs_in(&sigs);
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
            let (sigs, wildcard) = signatures_for(&zone, "www.example.com.", Qtype::of(rt::A));
            assert_eq!(sigs.len(), 1, "{chain:?}");
            assert!(!wildcard);
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

            // Which wildcard it was is the validator's answer above; what this
            // module reports is only that the answer still owes a denial.
            let (sigs, owes_denial) = signatures_for(&zone, qname, Qtype::of(rt::A));
            assert!(owes_denial, "{chain:?}");
            assert!(sigs.iter().all(|r| r.name == qname));

            let proof_records = absence_of(&zone, qname);
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
            let records = negative(
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
            let records = negative(
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
            let records = negative(&zone, qname, &zone.name_kind(qname));
            let denial = proves_nxdomain(qname, ORIGIN, &nsecs_in(&records), &nsec3s_in(&records));
            assert!(matches!(denial, Denial::Proved), "{chain:?}: {denial:?}");
        }
    }

    #[test]
    fn every_denial_record_travels_with_its_own_signature() {
        // An unsigned NSEC is a record an attacker could have written.
        for chain in [DenialChain::Nsec, DenialChain::nsec3()] {
            let zone = signed(chain.clone());
            let records = negative(
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
        assert!(signatures_for(&zone, "www.example.com.", Qtype::of(rt::A))
            .0
            .is_empty());
        assert!(negative(
            &zone,
            "nope.example.com.",
            &zone.name_kind("nope.example.com.")
        )
        .is_empty());
        assert!(absence_of(&zone, "nope.example.com.").is_empty());
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
