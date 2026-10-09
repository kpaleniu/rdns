//! A **zone answer**: what one zone says to one question — records, a
//! referral, or a no — with the DNSSEC records that reply owes (`CONTEXT.md`).
//!
//! RFC 1034 §4.3.2 for one zone, and the RFC 4035 §3.1 proofs each of its
//! outcomes owes, behind one function. The split from the daemon is here
//! because zone *selection* is server policy — the catalog, replication, a
//! withdrawn secondary — while what a chosen zone says is the RFC's, and an
//! interface that hands the caller the proof table to apply is one the caller
//! can apply wrong. `rdnsd` keeps the request: opcode, EDNS, class, AXFR and
//! IXFR over UDP, the zone lookup, and REFUSED when there is none.
//!
//! The answer is written to the wire as it is found, so sections go out in
//! order, and a helper that owes both an answer and an authority record hands
//! the second back to its caller instead of writing it.

mod dnssec_answer;

use std::borrow::Cow;

use crate::error::WireError;
use crate::name::{dname_redirect, Redirect};
use crate::record_types;
use crate::response::{ResponseWriter, Section};
use crate::zone::{Located, NameKind, Zone, ZoneRecordRef};
use crate::{Class, Name, NameRef, ParsedRecord, Qtype, RecordData, ResponseCode, Ttl};

/// Write what `zone` says to `qname`/`qtype` into `w`: the answer, authority
/// and additional sections, NXDOMAIN or YXDOMAIN where they apply, AA cleared
/// on a referral, and every DNSSEC record the reply owes when `dnssec_ok` and
/// the zone is signed. `qname` is as asked, and its case is echoed (RFC 1034
/// §4.3.3); the header, opcode and EDNS are the caller's.
pub fn write(
    zone: &Zone,
    qname: &Name,
    qtype: Qtype,
    dnssec_ok: bool,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    match resolve_in_zone(zone, qname, qtype) {
        Outcome::Referral { cut } => refer_to_child(zone, cut.as_ref(), dnssec_ok, w),
        Outcome::Answer { chain, name, at } => {
            let owed = add_chain(zone, &chain, dnssec_ok, w)?;
            let target_owed = add_answer(&at, name.as_ref().as_ref(), qtype, dnssec_ok, w)?;
            add_chain_denials(zone, &chain, owed, w)?;
            if target_owed {
                dnssec_answer::push_proof_of_absence(zone, name.as_ref().as_ref(), w)?;
            }
            Ok(())
        }
        Outcome::Negative { chain, name, kind } => {
            let owed = add_chain(zone, &chain, dnssec_ok, w)?;
            add_chain_denials(zone, &chain, owed, w)?;
            add_negative(zone, name.as_ref().as_ref(), &kind, dnssec_ok, w)
        }
        Outcome::ChainLeftZone { chain } => {
            let owed = add_chain(zone, &chain, dnssec_ok, w)?;
            add_chain_denials(zone, &chain, owed, w)
        }
        Outcome::Stopped { chain, rcode } => {
            let owed = add_chain(zone, &chain, dnssec_ok, w)?;
            add_chain_denials(zone, &chain, owed, w)?;
            w.set_rcode(rcode);
            Ok(())
        }
    }
}

/// One redirection followed on the way to an answer.
///
/// Two shapes, because the two carry different things out. A CNAME is a record
/// the zone holds at its own owner name. A DNAME is a record at an *ancestor*
/// of the name asked for, plus a CNAME the server makes up on the spot
/// (RFC 6672 §3.1) — which is why the owner and the name asked about are two
/// fields here and one field for a CNAME.
enum Hop {
    /// A CNAME RRset at `owner`, with its own signature and its own wildcard
    /// denial.
    Cname(Name),
    /// A DNAME redirection. `owner` is where the DNAME is, which is what the
    /// answer carries with its signature; `from` is the name the client asked,
    /// which owns the synthesized CNAME; `to` is the substituted name, or
    /// `None` when the substitution overflowed — RFC 6672 §3.2 step 3C exits
    /// with YXDOMAIN *before* synthesizing a CNAME, and §2.2 still sends the
    /// DNAME "as proof for the YXDOMAIN (value 6) RCODE".
    Dname {
        owner: Name,
        from: Name,
        to: Option<Name>,
        /// The DNAME's own TTL and class, for the CNAME synthesized from it:
        /// "A CNAME RR with Time to Live (TTL) equal to the corresponding
        /// DNAME RR is synthesized" (§3.1). Carried rather than looked up
        /// again — the record was in hand when the redirection was decided
        /// (`TODO.md` #25a).
        ttl: Ttl,
        class: Class,
    },
}

impl Hop {
    /// The name whose RRset goes into the answer section for this hop.
    fn owner(&self) -> NameRef<'_> {
        match self {
            Hop::Cname(owner) => owner.as_ref(),
            Hop::Dname { owner, .. } => owner.as_ref(),
        }
    }
}

/// What RFC 1034 §4.3.2 decided about one question against one zone: a loop with
/// four exits.
/// `name` is what the client asked, in the case it asked in, because that is
/// what an answer echoes (RFC 1034 §4.3.3) and what a DNS-0x20 resolver compares
/// byte for byte. `key` is the same name folded, which is what every lookup
/// wants. Both borrow the question until a CNAME hop makes one of them new.
enum Outcome<'a> {
    /// The zone's authority stops at `cut`: the answer is a referral to the
    /// child, with AA clear (RFC 1035 §4.1.1).
    Referral { cut: Name },
    /// There are records for the question at `name`, reached through the
    /// redirections at `chain` (empty in the ordinary case).
    Answer {
        chain: Vec<Hop>,
        name: Cow<'a, Name>,
        /// The lookup that found them, carried rather than repeated: writing
        /// the records and their signatures would otherwise locate the same
        /// name twice more (`TODO.md` #25a).
        at: Located<'a>,
    },
    /// No records. `name` is the name the "no" is about — the end of the chain
    /// when one was followed — and `kind` decides NXDOMAIN against NODATA.
    Negative {
        chain: Vec<Hop>,
        name: Cow<'a, Name>,
        kind: NameKind,
    },
    /// The chain walked out of this zone: NOERROR with the aliases we hold and
    /// nothing else. Not NXDOMAIN — we know nothing about the target
    /// (RFC 1034 §4.3.2 step 3a).
    ChainLeftZone { chain: Vec<Hop> },
    /// The chain cannot go on. The hops so far still go out — a DNAME that
    /// overflowed is itself the proof for the YXDOMAIN (RFC 6672 §2.2) — and
    /// `rcode` says why it stopped.
    Stopped {
        chain: Vec<Hop>,
        rcode: ResponseCode,
    },
}

/// How many redirections, CNAME and DNAME alike, we follow inside one zone: the
/// visited set stops a cycle, this a chain that never repeats. One ceiling for
/// both, as they chain together (RFC 6672 §2.2).
const MAX_REDIRECTS: usize = 16;

/// Walk RFC 1034 §4.3.2 for one question.
///
/// The four cases are tried at every name in the RFC's order, and the order
/// matters: authority ends here, the name has the data, the name is an alias,
/// the name has no such data. Getting the first one last is how a parent answers
/// NXDOMAIN for a child's names.
fn resolve_in_zone<'a>(zone: &'a Zone, qname: &'a Name, qtype: Qtype) -> Outcome<'a> {
    let mut chain: Vec<Hop> = Vec::new();
    let mut visited: Vec<Name> = Vec::new();
    let mut name: Cow<'a, Name> = Cow::Borrowed(qname);
    // On the stack: a `Vec` here cost a DNS-0x20 query an allocation (#160).
    let mut fold = [0u8; crate::dname::MAX_NAME_LEN];

    for _ in 0..MAX_REDIRECTS {
        // Folded once per name: every `Zone` entry point folds, and an already
        // folded name copies nothing. `name` keeps the asked case for the echo.
        let key = name.as_ref().as_ref().folded_into(&mut fold);

        // The DNAME strictly above (RFC 6672 §2.2, §2.3), asked before the
        // lookup: names below it are occluded (RFC 2136 §7.18).
        let redirect = zone.dname_above(key);

        // A delegation is a referral whatever the type, with two exceptions.
        if let Some(cut) = zone.delegation_for(key) {
            // A DNAME above the cut occludes it, met first (RFC 1034 §4.3.2);
            // only a transferred or updated zone holds both.
            let occluded = redirect.is_some_and(|dname| cut.as_ref().is_at_or_under(dname.name));
            // The DS at the cut is the parent's statement, which the child
            // lacks (RFC 4035 §3.1.4.1).
            let ds_at_the_cut = qtype.is(record_types::DS) && cut == *name;
            if !(occluded || ds_at_the_cut) {
                return if chain.is_empty() {
                    Outcome::Referral { cut }
                } else {
                    // Mid-chain the target is the child's; glue below the cut
                    // is not authoritative.
                    Outcome::ChainLeftZone { chain }
                };
            }
        }

        if let Some(dname) = redirect {
            match redirect_through(dname, name.into_owned(), &mut chain) {
                Ok(next) => {
                    if !in_zone(zone, next.as_ref()) || visited.contains(&next) {
                        return Outcome::ChainLeftZone { chain };
                    }
                    visited.push(next.clone());
                    name = Cow::Owned(next);
                    continue;
                }
                Err(rcode) => return Outcome::Stopped { chain, rcode },
            }
        }

        // One walk for both questions: `locate` already works out the kind, and
        // only whether records exist is asked.
        let located = zone.locate(key);
        if located.has_type(qtype) {
            return Outcome::Answer {
                chain,
                name,
                at: located,
            };
        }
        // A CNAME query is answered by the CNAME, not followed by it.
        if qtype.is(record_types::CNAME) {
            let kind = located.into_kind();
            return Outcome::Negative { chain, name, kind };
        }

        // From the same `located`; only the first CNAME, as RFC 1034 §3.6.2
        // allows one and the loader refuses two.
        let target = located
            .of_type(Qtype::of(record_types::CNAME))
            .next()
            .and_then(|record| match record.rdata.parse() {
                Ok(ParsedRecord::CNAME(target)) => Some(target),
                _ => None,
            });
        let Some(target) = target else {
            let kind = located.into_kind();
            return Outcome::Negative { chain, name, kind };
        };
        chain.push(Hop::Cname(name.into_owned()));
        // `visited` compares as names, which fold as they go — so there is no
        // folded copy of each hop to keep any more.
        if !in_zone(zone, target.as_ref()) || visited.contains(&target) {
            return Outcome::ChainLeftZone { chain };
        }
        visited.push(target.clone());
        name = Cow::Owned(target);
    }
    Outcome::ChainLeftZone { chain }
}

/// Apply one DNAME to the name being sought, recording the hop.
///
/// `Ok` is the substituted name and the chain has grown by one; `Err` is the
/// RCODE to answer with, and the chain still carries the DNAME, which is what
/// RFC 6672 §2.2 sends "as proof for the YXDOMAIN (value 6) RCODE".
fn redirect_through(
    dname: ZoneRecordRef<'_>,
    from: Name,
    chain: &mut Vec<Hop>,
) -> Result<Name, ResponseCode> {
    let Ok(ParsedRecord::DNAME(target)) = dname.rdata.parse() else {
        // An unreadable DNAME still occludes, so SERVFAIL rather than answer
        // from below; unreachable for a loaded zone.
        return Err(ResponseCode::ServerFailure);
    };
    let to = match dname_redirect(from.as_ref(), dname.name, target.as_ref()) {
        Redirect::To(next) => Some(next),
        Redirect::TooLong => None,
        // Unreachable: `Zone::dname_above` found it strictly above. Falling
        // through would answer from occluded data.
        Redirect::NoMatch => return Err(ResponseCode::ServerFailure),
    };
    chain.push(Hop::Dname {
        owner: dname.name.to_owned(),
        from,
        to: to.clone(),
        ttl: dname.ttl,
        class: dname.class,
    });
    // Too long after substitution is YXDOMAIN (RFC 6672 §2.2), the DNAME as
    // proof; this enum spells 6 `DomainExistsForSomeReason`.
    to.ok_or(ResponseCode::DomainExistsForSomeReason)
}

/// Whether a name is at or below this zone's apex. [`NameRef::is_at_or_under`]
/// folds ASCII case as it walks (RFC 4343), so callers need not fold first.
fn in_zone(zone: &Zone, name: NameRef<'_>) -> bool {
    name.is_at_or_under(zone.origin())
}

/// Put the records of `qtype` at `name` into the answer section, with their
/// signatures.
///
/// Echoes `name`, as asked (RFC 1034 §4.3.3), and looks up by `key`; DNS-0x20
/// clients compare the echo. Returns whether a wildcard answered, which still
/// owes a denial of `name` (RFC 4035 §3.1.3), written by the caller.
fn add_answer(
    at: &Located,
    name: NameRef<'_>,
    qtype: Qtype,
    dnssec_ok: bool,
    w: &mut ResponseWriter,
) -> Result<bool, WireError> {
    for record in at.of_type(qtype) {
        w.push(
            Section::Answer,
            name,
            record.class,
            record.ttl,
            record.rdata,
        )?;
    }

    if !dnssec_ok {
        return Ok(false);
    }
    dnssec_answer::push_answer_signatures(at, name, qtype, w)
}

/// The redirections walked to reach the answer, in the order they were
/// followed.
///
/// A CNAME hop is one RRset at its own owner name, with its own signature — and
/// its own wildcard denial when the alias was synthesized. A DNAME hop is the
/// DNAME RRset at an ancestor, with its signature, followed by the CNAME this
/// server synthesizes from it (RFC 6672 §3.1). Returns the hops that owe a
/// wildcard denial, as a bit per index into `chain`.
fn add_chain(
    zone: &Zone,
    chain: &[Hop],
    dnssec_ok: bool,
    w: &mut ResponseWriter,
) -> Result<u32, WireError> {
    const _: () = assert!(MAX_REDIRECTS <= u32::BITS as usize, "one bit per hop");
    let mut owed = 0u32;
    for (i, hop) in chain.iter().enumerate() {
        // No fold here any more: `Zone::locate` folds what its index needs,
        // and the hop's own name is what the answer echoes.
        let qtype = match hop {
            Hop::Cname(_) => Qtype::of(record_types::CNAME),
            Hop::Dname { .. } => Qtype::of(record_types::DNAME),
        };
        if add_answer(&zone.locate(hop.owner()), hop.owner(), qtype, dnssec_ok, w)? {
            owed |= 1 << i;
        }

        // RFC 6672 §3.1: a CNAME with the DNAME's TTL, owned by the QNAME.
        // Never signed (§5.3.1): a validator derives it from the DNAME's RRSIG.
        if let Hop::Dname {
            from,
            to: Some(to),
            ttl,
            class,
            ..
        } = hop
        {
            let rdata = RecordData::from_parsed(&ParsedRecord::CNAME(to.clone()))?;
            w.push(Section::Answer, from.as_ref(), *class, *ttl, rdata.as_ref())?;
        }
    }
    Ok(owed)
}

/// The wildcard denials [`add_chain`] found owing, written once the answer
/// section is closed.
fn add_chain_denials(
    zone: &Zone,
    chain: &[Hop],
    owed: u32,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    if owed == 0 {
        return Ok(());
    }
    for (i, hop) in chain.iter().enumerate() {
        if owed & (1 << i) != 0 {
            dnssec_answer::push_proof_of_absence(zone, hop.owner(), w)?;
        }
    }
    Ok(())
}

/// A negative answer: the rcode, the SOA that says how long it may be cached,
/// and the proof of it when the client can check one.
fn add_negative(
    zone: &Zone,
    name: NameRef<'_>,
    kind: &NameKind,
    dnssec_ok: bool,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    if matches!(kind, NameKind::NotFound) {
        w.set_rcode(ResponseCode::NoSuchDomain);
    }

    // Both kinds of "no" carry the SOA (RFC 2308 §2.1, §2.2), which says how
    // long it may be cached; without it every repeat comes back.
    for soa in zone.query(zone.origin(), Qtype::of(record_types::SOA)) {
        w.push(
            Section::Authority,
            zone.origin(),
            soa.class,
            negative_ttl(soa),
            soa.rdata,
        )?;
    }

    // A signed zone's "no" carries its proof, or a forged NXDOMAIN takes a name
    // away for as long as it is cached.
    if dnssec_ok {
        dnssec_answer::push_negative_proof(zone, name, kind, w)?;
    }
    Ok(())
}

/// How long a negative answer may be cached: `min(SOA MINIMUM, the SOA record's
/// own TTL)` (RFC 2308 §3).
///
/// The record's TTL alone overstates it, and would disagree with the NSEC TTL
/// the signer caps at MINIMUM beside it.
fn negative_ttl(soa: ZoneRecordRef<'_>) -> Ttl {
    match soa.rdata.soa_minimum() {
        Some(minimum) => Ttl::negative_answer(soa.ttl, minimum),
        // An unparseable apex SOA: zero, so the client asks again rather than
        // caching an unbounded "no".
        None => Ttl::ZERO,
    }
}

/// A referral to the child zone: the delegation's NS RRset, its glue, and — for
/// a client that can check it — the DS or the proof there is none.
///
/// AA is clear, which is the whole point. This server hardcoded it true and
/// answered NXDOMAIN for names below a delegation, so per RFC 8020 every
/// resolver cached "the entire subtree does not exist" and the child zone went
/// off the internet for the negative TTL.
fn refer_to_child(
    zone: &Zone,
    cut: NameRef<'_>,
    dnssec_ok: bool,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    w.set_authoritative(false);

    let mut targets: Vec<Name> = Vec::new();
    for ns in zone.query(cut, Qtype::of(record_types::NS)) {
        if let Ok(ParsedRecord::NS(target)) = ns.rdata.parse() {
            targets.push(target);
        }
        w.push(Section::Authority, cut, ns.class, ns.ttl, ns.rdata)?;
    }

    // Before the glue: the additional section cannot be reopened once written
    // to.
    if dnssec_ok {
        dnssec_answer::push_delegation_proof(zone, cut, w)?;
    }

    // In-bailiwick glue only: an address for another zone's name asserts their
    // data, which is what poisoning looks like (RFC 1034 §4.2.1).
    for target in targets {
        if !in_zone(zone, target.as_ref()) {
            continue;
        }
        for rtype in [record_types::A, record_types::AAAA] {
            for glue in zone.query(target.as_ref(), Qtype::of(rtype)) {
                w.push(
                    Section::Additional,
                    target.as_ref(),
                    glue.class,
                    glue.ttl,
                    glue.rdata,
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::NameCompressor;
    use crate::test_records::nm;
    use crate::zone::parse_zone_file;
    use crate::{DnsMessage, DnsMessageBuilder, ResourceRecord, Rtype};

    const ZONE: &str = "$ORIGIN example.com.
$TTL 3600
@        IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@        IN NS  ns1.example.com.
ns1      IN A   192.0.2.1
loop1    IN CNAME loop2.example.com.
loop2    IN CNAME loop1.example.com.
sub      IN NS  ns.sub.example.com.
ns.sub   IN A   192.0.2.20
*.sub    IN A   192.0.2.77
";

    /// What `zone` says to the question, read back off the wire.
    fn answer(zone: &Zone, qname: &str, qtype: Qtype) -> DnsMessage {
        let request = DnsMessageBuilder::new()
            .with_query(nm(qname), qtype)
            .with_id(1)
            .build();
        let mut out = Vec::new();
        let mut compressor = NameCompressor::new();
        let mut w = ResponseWriter::start(&mut out, &mut compressor, u16::MAX as usize, &request)
            .expect("start a reply");
        w.set_authoritative(true);
        write(zone, &nm(qname), qtype, false, &mut w).expect("the answer writes");
        w.finish().expect("the reply serializes");
        DnsMessage::try_from_bytes(&out).expect("and parses back")
    }

    fn of_type(records: &[ResourceRecord], rtype: Rtype) -> usize {
        records.iter().filter(|r| r.rdata.rtype() == rtype).count()
    }

    /// A broken zone must not hang the server. Two aliases pointing at each
    /// other terminate on the visited set, not on the hop limit.
    ///
    /// Here with [`MAX_REDIRECTS`], which it names.
    #[test]
    fn a_cname_loop_terminates() {
        let zone = parse_zone_file(ZONE, "example.com.").expect("the test zone parses");
        let reply = answer(&zone, "loop1.example.com.", Qtype::of(record_types::A));
        assert_eq!(reply.rcode, ResponseCode::Ok);
        assert!(
            of_type(&reply.answers, record_types::CNAME) <= MAX_REDIRECTS,
            "the chain is bounded"
        );
    }

    /// A DNAME pointing at its own owner's ancestor maps a name to itself — RFC
    /// 6672 Table 1's `cyc` row. The visited set ends it, as it ends a CNAME
    /// loop.
    #[test]
    fn a_dname_loop_terminates() {
        let zone_text = "$ORIGIN example.com.\n$TTL 3600\n\
                         @ IN SOA ns1.example.com. admin.example.com. \
                         ( 1 3600 600 604800 300 )\n\
                         @ IN NS ns1.example.com.\n\
                         @ IN DNAME example.com.\n";
        let zone = parse_zone_file(zone_text, "example.com.").expect("the apex DNAME parses");
        let reply = answer(&zone, "cyc.example.com.", Qtype::of(record_types::A));
        assert_eq!(reply.rcode, ResponseCode::Ok);
        assert!(
            of_type(&reply.answers, record_types::CNAME) <= MAX_REDIRECTS,
            "the chain is bounded: {:?}",
            reply.answers
        );
    }

    /// `dnssec_answer::deny_the_name_and_its_wildcard` needs
    /// `*.<closest encloser>` absent, and the guarantor is the order here:
    /// `delegation_for` is asked first (RFC 1034 §4.3.2's first case), so a
    /// name under a cut is a referral even with a wildcard below the cut, and
    /// never reaches a negative proof.
    #[test]
    fn a_wildcard_below_a_cut_is_still_a_referral() {
        let zone = parse_zone_file(ZONE, "example.com.").expect("the test zone parses");
        let qname = nm("nothing.sub.example.com.");
        assert!(matches!(
            resolve_in_zone(&zone, &qname, Qtype::of(record_types::A)),
            Outcome::Referral { .. }
        ));

        let reply = answer(
            &zone,
            "nothing.sub.example.com.",
            Qtype::of(record_types::A),
        );
        assert_eq!(reply.rcode, ResponseCode::Ok, "a referral, not NXDOMAIN");
        assert!(!reply.authoritive, "AA is clear on a referral");
        assert!(reply.answers.is_empty(), "RFC 4592 §2.2.1");
        assert_eq!(of_type(&reply.authorities, record_types::NS), 1);
    }
}
