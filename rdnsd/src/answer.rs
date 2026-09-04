//! Turning a question into an answer: RFC 1034 §4.3.2, and the four cases.
//!
//! Everything here is a synchronous function of the message, the zone map and
//! the metrics — no sockets, no lock guards, nothing `async`.
//!
//! The answer is written to the wire as it is found, through a
//! [`ResponseWriter`], rather than built as a `DnsMessage` and serialized
//! afterwards: an owner `String`, a cloned RDATA and a `Vec` push per record
//! were three of the twelve allocations a query cost (`TODO.md` #27b). The price
//! is that sections go out in order, so a helper that owes both an answer and an
//! authority record hands the second back to its caller instead of writing it.

use std::borrow::Cow;

use rdns::compression::NameCompressor;
use rdns::error::WireError;
use rdns::metrics::{DnsMetrics, LatencyTimer};
use rdns::response::{ResponseWriter, Section};
use rdns::utils::{absolute_lowered, record_types};
use rdns::zone::{Located, NameKind, Zone};
use rdns::Qtype;
use rdns::Ttl;
use rdns::{dnssec_answer, DnsMessage, Edns, OpCode, QueryClass, ResponseCode};

use crate::zones::Zones;
use crate::RDNSD_PAYLOAD_SIZE;

/// Write a DNS response to `msg` into `out`, at most `max_len` octets.
///
/// `out` and `compressor` are the caller's to keep: a worker answering one
/// datagram after another reuses both and the answer costs the allocator
/// nothing. Over `max_len` the reply is an empty TC=1 one (RFC 1035 §4.2.1).
pub(crate) fn write_response(
    msg: &DnsMessage,
    zones: &Zones,
    metrics: &DnsMetrics,
    max_len: usize,
    out: &mut Vec<u8>,
    compressor: &mut NameCompressor,
) -> Result<(), WireError> {
    let timer = LatencyTimer::new();
    let mut w = ResponseWriter::start(out, compressor, max_len, msg)?;
    w.set_authoritative(true);

    // EDNS-level rejections take precedence over any zone lookup: a malformed
    // option list is FORMERR, an EDNS version we don't implement is BADVERS.
    // Both replies carry a bare version-0 OPT — BADVERS is an extended RCODE, so
    // the OPT record is what carries its high bits. `rdnsr` reads the same
    // decision out of `client_edns` (`TODO.md` #30h).
    let client_edns = match rdns::response::client_edns(msg) {
        Ok(edns) => edns,
        Err(rcode) => {
            w.set_rcode(rcode);
            // `with_payload_size` carries no options, so encoding it cannot fail.
            w.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
            return w.finish();
        }
    };

    // DO says the client can make sense of DNSSEC records, so send them
    // (RFC 4035 §3.1.1). Not a demand that the zone be signed.
    let dnssec_ok = client_edns.do_bit();

    // Only QUERY reaches the zone lookup. NOTIFY is answered by the caller,
    // which knows the peer's address; anything else is NOTIMP rather than
    // treated as a lookup (RFC 1035 §4.1.1).
    if msg.opcode != OpCode::Query {
        w.set_rcode(ResponseCode::NotImplemented);
        w.set_authoritative(false);
        // This `return` jumps over the EDNS mirroring at the end of the
        // function, and RFC 6891 §6.1.1 says a response to a request that had an
        // OPT includes one. Some clients remember a missing OPT as a downgrade
        // and never offer EDNS again.
        //
        // `ClientEdns::Present` and `msg.has_edns()` agree here: they differ
        // only for a malformed option list, which answered FORMERR above.
        if let Some(edns) = client_edns.mirror(RDNSD_PAYLOAD_SIZE) {
            w.set_edns(edns);
        }
        return w.finish();
    }

    // RFC 9619 §4: "A DNS message with OPCODE = 0 MUST NOT include a QDCOUNT
    // parameter whose value is greater than 1", and one that does "MUST be
    // treated as an incorrectly formatted message" — FORMERR. There is no answer
    // to give two questions: one RCODE, one AA bit and one set of sections
    // cannot describe two lookups. BIND, NSD, Knot and Unbound all refuse it.
    //
    // QDCOUNT = 0 is left alone; §4 says a firewall "MUST NOT treat messages
    // with OPCODE = 0 and QDCOUNT = 0 as malformed".
    if msg.queries.len() > 1 {
        w.set_rcode(ResponseCode::FormatError);
        w.set_authoritative(false);
    } else if let Some(query) = msg.queries.first() {
        answer_question(query, zones, dnssec_ok, &mut w)?;
    }

    // Count the answer by what it says. REFUSED climbing means a zone went
    // missing, SERVFAIL that one went wrong, NXDOMAIN is ordinary.
    metrics.count_response(w.rcode());
    if w.is_authoritative() {
        metrics.count(&metrics.queries_authoritative);
    }
    metrics.observe_latency_us(timer.elapsed_us());

    // Mirror EDNS0: an OPT record only when the client used EDNS
    // (RFC 6891 §6.1.1), and DO echoed when it was asked for (RFC 3225 §3).
    if let Some(edns) = client_edns.mirror(RDNSD_PAYLOAD_SIZE) {
        w.set_edns(edns);
    }

    w.finish()
}

/// The one question, once the message-level answers are out of the way.
fn answer_question(
    query: &rdns::QuerySection,
    zones: &Zones,
    dnssec_ok: bool,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    // Every zone here is IN, and RFC 1034 §4.3.2 step 1 searches the zones
    // *of the question's class* — so a CH or HS question is the same
    // situation as a zone we do not serve, and REFUSED for the reason at the
    // bottom of this function. QCLASS=ANY (255) matches any class
    // (RFC 1035 §3.2.5), so it is not refused.
    if !matches!(query.qclass, QueryClass::IN | QueryClass::Any) {
        w.set_rcode(ResponseCode::Refused);
        w.set_authoritative(false);
        return Ok(());
    }

    // AXFR is defined over TCP alone (RFC 5936 §4.2), so a UDP request for
    // it is malformed rather than merely refused. The TCP server answers
    // AXFR before reaching here, so this is the UDP path speaking.
    if query.qtype == Qtype::AXFR {
        w.set_rcode(ResponseCode::FormatError);
        return Ok(());
    }

    // An IXFR over UDP is expected. RFC 1995 §2: answer a single SOA of the
    // current version, telling the client to come back over TCP. Done
    // always, rather than only when the increment will not fit — the ACL,
    // TSIG session and message packing all live on the TCP path. The SOA
    // discloses nothing an ordinary SOA query does not.
    if query.qtype == Qtype::IXFR {
        match zones.for_query(&query.qname) {
            Some(zone) => {
                for soa in zone.query(zone.origin(), Qtype::of(record_types::SOA)) {
                    w.push(
                        Section::Answer,
                        zone.origin(),
                        soa.class,
                        soa.ttl,
                        &soa.rdata,
                    )?;
                }
            }
            None => {
                w.set_rcode(ResponseCode::Refused);
                w.set_authoritative(false);
            }
        }
        return Ok(());
    }

    // One fold for the whole question. `Zones::for_query`, the delegation
    // walk and every `Zone` lookup fold their argument themselves and borrow
    // when there is nothing left to fold, so folding once here makes all of
    // them free — a case-randomized query paid for three (`TODO.md` #27a).
    let key = absolute_lowered(&query.qname);
    let Some(zone) = zones.for_query(&key) else {
        // A zone we do not serve is REFUSED, not NXDOMAIN. NXDOMAIN asserts
        // the name exists nowhere, which we have no standing to say, and a
        // resolver caches it (RFC 2308). BIND, NSD and Knot all answer
        // REFUSED here. It matters most for a *withdrawn* zone: an expired
        // secondary answering NXDOMAIN takes its zone off the internet.
        w.set_rcode(ResponseCode::Refused);
        w.set_authoritative(false);
        return Ok(());
    };

    match resolve_in_zone(zone, &query.qname, &key, query.qtype) {
        Outcome::Referral { cut } => refer_to_child(zone, &cut, dnssec_ok, w),
        Outcome::Answer {
            chain,
            name,
            key,
            at,
        } => {
            let owed = add_chain(zone, &chain, dnssec_ok, w)?;
            let target_owed = add_answer(&at, &name, &key, query.qtype, dnssec_ok, w)?;
            add_chain_denials(zone, &chain, owed, w)?;
            if target_owed {
                dnssec_answer::push_proof_of_absence(zone, &key, w)?;
            }
            Ok(())
        }
        Outcome::Negative { chain, name, kind } => {
            let owed = add_chain(zone, &chain, dnssec_ok, w)?;
            add_chain_denials(zone, &chain, owed, w)?;
            add_negative(zone, &name, &kind, dnssec_ok, w)
        }
        Outcome::ChainLeftZone { chain } => {
            let owed = add_chain(zone, &chain, dnssec_ok, w)?;
            add_chain_denials(zone, &chain, owed, w)
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
    Referral { cut: String },
    /// There are records for the question at `name`, reached through the
    /// aliases at `chain` (empty in the ordinary case).
    Answer {
        chain: Vec<String>,
        name: Cow<'a, str>,
        key: Cow<'a, str>,
        /// The lookup that found them, carried rather than repeated: writing
        /// the records and their signatures used to locate the same name twice
        /// more (`TODO.md` #25a).
        at: Located<'a>,
    },
    /// No records. `name` is the name the "no" is about — the end of the chain
    /// when one was followed — and `kind` decides NXDOMAIN against NODATA.
    Negative {
        chain: Vec<String>,
        name: Cow<'a, str>,
        kind: NameKind,
    },
    /// The chain walked out of this zone: NOERROR with the aliases we hold and
    /// nothing else. Not NXDOMAIN — we know nothing about the target
    /// (RFC 1034 §4.3.2 step 3a).
    ChainLeftZone { chain: Vec<String> },
}

/// How many aliases we follow inside one zone. The second bound: the visited set
/// below stops a cycle, this stops a chain that grows without repeating.
pub(crate) const MAX_CNAME_HOPS: usize = 16;

/// Walk RFC 1034 §4.3.2 for one question.
///
/// The four cases are tried at every name in the RFC's order, and the order
/// matters: authority ends here, the name has the data, the name is an alias,
/// the name has no such data. Getting the first one last is how a parent answers
/// NXDOMAIN for a child's names.
/// `qkey` is `qname` folded, which the caller has already paid for: `Zone`'s
/// entry points fold their argument and `ascii_lowered_cow` borrows when there
/// is nothing left to fold, so passing the folded form makes every lookup below
/// free. A case-randomized query folded its name three times before this
/// (`TODO.md` #27a).
fn resolve_in_zone<'a>(zone: &'a Zone, qname: &'a str, qkey: &'a str, qtype: Qtype) -> Outcome<'a> {
    let mut chain: Vec<String> = Vec::new();
    let mut visited: Vec<String> = Vec::new();
    let mut name: Cow<'a, str> = Cow::Borrowed(qname);
    let mut key: Cow<'a, str> = Cow::Borrowed(qkey);

    for _ in 0..MAX_CNAME_HOPS {
        // A delegation is a referral whatever the type, except the DS *at* the
        // cut: that is the parent's own statement about the child, which the
        // child does not hold and could not be asked (RFC 4035 §3.1.4.1).
        if let Some(cut) = zone.delegation_for(&key) {
            let at_the_cut = cut == *key;
            if !(qtype.is(record_types::DS) && at_the_cut) {
                return if chain.is_empty() {
                    Outcome::Referral { cut }
                } else {
                    // Mid-chain the target is the child's name to answer for.
                    // Answering from the glue below the cut would serve occluded
                    // data as authoritative.
                    Outcome::ChainLeftZone { chain }
                };
            }
        }

        // One walk for both questions: `locate` works the kind out to decide
        // whether a wildcard may answer, and asking `name_kind` separately
        // walked the ancestors and folded the name again (`TODO.md` #28b). The
        // records are not collected — this asks only whether there are any
        // (#27c).
        let located = zone.locate(&key);
        if located.has_type(qtype) {
            return Outcome::Answer {
                chain,
                name,
                key,
                at: located,
            };
        }
        // A CNAME query is answered by the CNAME, not followed by it.
        if qtype.is(record_types::CNAME) {
            let kind = located.into_kind();
            return Outcome::Negative { chain, name, kind };
        }

        // From the same `located`: following the alias is a question about the
        // records already found here, not a reason to walk the zone again.
        //
        // Only the first is read: RFC 1034 §3.6.2 allows exactly one CNAME at an
        // owner name, and the parser refuses to load a second, so this is belt
        // to that braces.
        let target = located
            .of_type(Qtype::of(record_types::CNAME))
            .next()
            .and_then(|record| match record.rdata.parse() {
                Ok(rdns::ParsedRecord::CNAME(target)) => Some(target),
                _ => None,
            });
        let Some(target) = target else {
            let kind = located.into_kind();
            return Outcome::Negative { chain, name, kind };
        };
        chain.push(name.into_owned());
        visited.push(key.into_owned());

        // Folded for `visited`, an equality test against folded names; `in_zone`
        // does not need it to be.
        let target_key = absolute_lowered(&target).into_owned();
        if !in_zone(zone, &target_key) || visited.contains(&target_key) {
            return Outcome::ChainLeftZone { chain };
        }
        name = Cow::Owned(target);
        key = Cow::Owned(target_key);
    }
    Outcome::ChainLeftZone { chain }
}

/// Whether a name is at or below this zone's apex. [`rdns::utils::is_at_or_under`]
/// compares case-insensitively itself, so callers need not fold first.
fn in_zone(zone: &Zone, name: &str) -> bool {
    rdns::utils::is_at_or_under(name, zone.origin())
}

/// Put the records of `qtype` at `name` into the answer section, with their
/// signatures.
///
/// Echoes the name asked about, not the stored owner, which may be `@`, relative
/// or a wildcard — the client must see the queried name (RFC 1034 §4.3.3).
/// `name` is echoed and `key` is looked up with: they are the same name, and a
/// DNS-0x20 client compares the echo byte for byte, so the folded form must not
/// reach the wire.
/// Returns whether the answer came through a wildcard and so still owes a
/// denial of the name asked for — an authority record, which the caller writes
/// once every answer record is out (RFC 4035 §3.1.3: the same signature verifies
/// at every name the wildcard reaches, so without the denial one captured answer
/// serves for all).
fn add_answer(
    at: &Located,
    name: &str,
    key: &str,
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
            &record.rdata,
        )?;
    }

    if !dnssec_ok {
        return Ok(false);
    }
    dnssec_answer::push_answer_signatures(at, key, qtype, w)
}

/// The aliases walked to reach the answer, in the order they were followed.
///
/// Each is a CNAME RRset at its own owner name, so it carries its own signature
/// — and its own wildcard denial when the alias was synthesized. Returns the
/// hops that owe one, as a bit per index into `chain`.
fn add_chain(
    zone: &Zone,
    chain: &[String],
    dnssec_ok: bool,
    w: &mut ResponseWriter,
) -> Result<u32, WireError> {
    const _: () = assert!(MAX_CNAME_HOPS <= u32::BITS as usize, "one bit per hop");
    let mut owed = 0u32;
    for (i, at) in chain.iter().enumerate() {
        // Folded here rather than carried: a chain is empty on the ordinary
        // answer, so this pays only where an alias was actually followed.
        let key = absolute_lowered(at);
        if add_answer(
            &zone.locate(&key),
            at,
            &key,
            Qtype::of(record_types::CNAME),
            dnssec_ok,
            w,
        )? {
            owed |= 1 << i;
        }
    }
    Ok(owed)
}

/// The wildcard denials [`add_chain`] found owing, written once the answer
/// section is closed.
fn add_chain_denials(
    zone: &Zone,
    chain: &[String],
    owed: u32,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    if owed == 0 {
        return Ok(());
    }
    for (i, at) in chain.iter().enumerate() {
        if owed & (1 << i) != 0 {
            dnssec_answer::push_proof_of_absence(zone, &absolute_lowered(at), w)?;
        }
    }
    Ok(())
}

/// A negative answer: the rcode, the SOA that says how long it may be cached,
/// and the proof of it when the client can check one.
fn add_negative(
    zone: &Zone,
    name: &str,
    kind: &NameKind,
    dnssec_ok: bool,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    if matches!(kind, NameKind::NotFound) {
        w.set_rcode(ResponseCode::NoSuchDomain);
    }

    // Both kinds of "no" carry the zone's SOA in the authority section
    // (RFC 2308 §2.1 and §2.2). It is not decoration: it is what tells the
    // client, and every resolver in between, how long the answer may be cached.
    // Without it a negative answer is uncacheable, so each repeat of a failing
    // lookup comes back to us.
    for soa in zone.query(zone.origin(), Qtype::of(record_types::SOA)) {
        w.push(
            Section::Authority,
            zone.origin(),
            soa.class,
            negative_ttl(soa),
            &soa.rdata,
        )?;
    }

    // An unsigned "no" is a "no" a resolver has to take on trust, which for a
    // signed zone is the one thing DNSSEC exists to avoid: the proof is what
    // stops a forged NXDOMAIN taking a name off the internet for as long as it
    // stays cached.
    if dnssec_ok {
        dnssec_answer::push_negative_proof(zone, name, kind, w)?;
    }
    Ok(())
}

/// How long a negative answer may be cached: `min(SOA MINIMUM, the SOA record's
/// own TTL)` (RFC 2308 §3).
///
/// The record's own TTL alone is wrong, and wrong in the expensive direction.
/// For the zone shape this repo's own tests use — `$TTL 3600`, `minimum 300` —
/// sending it verbatim advertises every NXDOMAIN and NODATA at 3600 where the
/// RFC says 300, so a record added to fix a typo takes an hour to appear instead
/// of five minutes. It was also internally inconsistent: the signer already caps
/// the NSEC/NSEC3 TTL at MINIMUM (`zone_signer::sign_zone`), so the SOA and the
/// proof beside it in the same section disagreed about how long the "no" was
/// good for.
fn negative_ttl(soa: &rdns::zone::ZoneRecord) -> Ttl {
    match soa.rdata.soa_minimum() {
        Some(minimum) => soa.ttl.min(Ttl::from_secs(minimum)),
        // An apex SOA that will not parse is a zone that should not have loaded.
        // Capping at nothing is the conservative direction: the client asks
        // again rather than caching a "no" we cannot bound.
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
    cut: &str,
    dnssec_ok: bool,
    w: &mut ResponseWriter,
) -> Result<(), WireError> {
    w.set_authoritative(false);

    let mut targets: Vec<String> = Vec::new();
    for ns in zone.query(cut, Qtype::of(record_types::NS)) {
        if let Ok(rdns::ParsedRecord::NS(target)) = ns.rdata.parse() {
            targets.push(target);
        }
        w.push(Section::Authority, cut, ns.class, ns.ttl, &ns.rdata)?;
    }

    // Written here rather than after the glue: both are the same section
    // contents as before, but the additional section cannot be reopened once a
    // record has gone into it.
    if dnssec_ok {
        dnssec_answer::push_delegation_proof(zone, cut, w)?;
    }

    // Glue, and only in-bailiwick glue: an address we hold for a nameserver
    // under this zone is a hint we are entitled to give, while one for a name in
    // somebody else's zone is an assertion about their data. A resolver worth
    // anything discards the latter, and sending it is how cache-poisoning
    // attempts look (RFC 1034 §4.2.1).
    for target in targets {
        // No fold: `is_at_or_under` compares case-insensitively already.
        if !in_zone(zone, &zone.normalize_name(&target)) {
            continue;
        }
        for rtype in [record_types::A, record_types::AAAA] {
            for glue in zone.query(&target, Qtype::of(rtype)) {
                w.push(
                    Section::Additional,
                    &target,
                    glue.class,
                    glue.ttl,
                    &glue.rdata,
                )?;
            }
        }
    }
    Ok(())
}

/// RFC 1034 §4.3.2: the four cases an authoritative answer can be.
///
/// Three of the four were missing here, and the suite was green the whole time
/// because it asserted what the code did — `CLAUDE.md` §1's opening example.
/// Each test below names the wire shape that used to go out.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{make_response, query};
    use rdns::zone::parse_zone_file;
    use rdns::{ResourceRecord, Rtype};

    /// A zone with everything the algorithm has to branch on: an alias, an
    /// alias out of the zone, a two-deep wildcard, a delegation with glue,
    /// and an empty non-terminal.
    const ZONE: &str = r#"$ORIGIN example.com.
$TTL 3600
@        IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@        IN NS  ns1.example.com.
ns1      IN A   192.0.2.1
www      IN CNAME host.example.com.
host     IN A   192.0.2.10
away     IN CNAME elsewhere.test.
loop1    IN CNAME loop2.example.com.
loop2    IN CNAME loop1.example.com.
*        IN A   192.0.2.99
deep.a.b IN TXT "down here"
sub      IN NS  ns.sub.example.com.
sub      IN NS  ns.other.test.
ns.sub   IN A   192.0.2.20
"#;

    fn server() -> Zones {
        let zone = parse_zone_file(ZONE, "example.com.").expect("the test zone parses");
        let mut zones = Zones::default();
        drop(zones.insert(zone));
        zones
    }

    fn ask(qname: &str, qtype: Qtype) -> DnsMessage {
        make_response(&query(qname, qtype, false), &server(), &DnsMetrics::new())
    }

    fn rdatas(records: &[ResourceRecord], rtype: Rtype) -> Vec<&ResourceRecord> {
        records
            .iter()
            .filter(|r| r.rdata.rtype() == rtype)
            .collect()
    }

    /// A resolver randomizes the case of the QNAME and compares the echo byte
    /// for byte; a mismatch is a spoofed answer as far as it is concerned
    /// (DNS-0x20). The answer therefore echoes the name *as asked*, not as the
    /// zone or the lookup key spells it (RFC 1034 §4.3.3, RFC 4343 on why the
    /// lookup may fold and the echo may not).
    ///
    /// Nothing tested this until #27a made the folded key a separate value from
    /// the echoed name — the two had been one string, so no test could tell them
    /// apart. Every other test here asks in lower case, where a regression is
    /// invisible.
    #[test]
    fn a_case_randomized_qname_is_echoed_exactly_as_asked() {
        // `host` is a plain A: `www` in this zone is a CNAME, whose answer
        // section ends at the target's own name and would hide the property.
        // The wildcard case is the second one — synthesis must echo the name
        // asked for, never `*.example.com.` (RFC 4592 §3.3.1).
        for asked in [
            "HoSt.eXaMpLe.CoM.",
            "AnYtHiNg.ExAmPlE.cOm.",
            "HOST.EXAMPLE.COM.",
        ] {
            let response = ask(asked, Qtype::of(record_types::A));
            assert_eq!(response.rcode, ResponseCode::Ok, "{asked}");
            assert_eq!(
                response.queries[0].qname, asked,
                "the question is echoed as asked"
            );
            let answers = rdatas(&response.answers, record_types::A);
            assert_eq!(answers.len(), 1, "{asked}: the same record is found");
            assert_eq!(
                answers[0].name, asked,
                "the owner name is echoed as asked, not folded"
            );
        }
    }

    /// The wire shape that used to go out for every CNAME in every zone this
    /// server loaded: an empty NOERROR with the SOA — "this name has no A
    /// record". `getaddrinfo` fails on it, and BIND and Unbound cache the
    /// NODATA and never follow the alias.
    #[test]
    fn a_cname_is_followed_to_its_target_in_the_same_zone() {
        let response = ask("www.example.com.", Qtype::of(record_types::A));

        assert_eq!(response.rcode, ResponseCode::Ok);
        assert!(response.authoritive);
        let cnames = rdatas(&response.answers, record_types::CNAME);
        assert_eq!(cnames.len(), 1, "the alias itself comes first");
        assert_eq!(cnames[0].name, "www.example.com.");

        let addresses = rdatas(&response.answers, record_types::A);
        assert_eq!(addresses.len(), 1, "and the data it points at");
        assert_eq!(addresses[0].name, "host.example.com.");
        assert!(
            response.authorities.is_empty(),
            "an answer is not a negative answer and owes no SOA"
        );
    }

    /// A chain leaving the zone stops with what we hold. NXDOMAIN here would
    /// be an assertion about a name in somebody else's zone.
    #[test]
    fn a_cname_out_of_the_zone_stops_with_the_partial_chain() {
        let response = ask("away.example.com.", Qtype::of(record_types::A));

        assert_eq!(response.rcode, ResponseCode::Ok, "not NXDOMAIN");
        assert_eq!(rdatas(&response.answers, record_types::CNAME).len(), 1);
        assert!(rdatas(&response.answers, record_types::A).is_empty());
    }

    /// A CNAME query is answered by the CNAME, not followed by it.
    #[test]
    fn a_cname_query_is_not_chased() {
        let response = ask("www.example.com.", Qtype::of(record_types::CNAME));
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rdata.rtype(), record_types::CNAME);
    }

    /// A broken zone must not hang the server. Two aliases pointing at each
    /// other terminate on the visited set, not on the hop limit.
    #[test]
    fn a_cname_loop_terminates() {
        let response = ask("loop1.example.com.", Qtype::of(record_types::A));
        assert_eq!(response.rcode, ResponseCode::Ok);
        assert!(
            rdatas(&response.answers, record_types::CNAME).len() <= MAX_CNAME_HOPS,
            "the chain is bounded"
        );
    }

    /// The referral, and the header bit that makes it one. This used to be an
    /// NXDOMAIN with AA=1, so per RFC 8020 every resolver cached "the
    /// whole subtree does not exist" and the child zone was off the internet
    /// for the negative TTL.
    #[test]
    fn a_name_below_a_delegation_gets_a_referral_not_an_nxdomain() {
        let response = ask("anything.sub.example.com.", Qtype::of(record_types::A));

        assert_eq!(
            response.rcode,
            ResponseCode::Ok,
            "a referral is not an error"
        );
        assert!(
            !response.authoritive,
            "RFC 1035 §4.1.1: AA is clear on a referral — this is the bit that \
             stopped the child zone resolving"
        );
        assert!(response.answers.is_empty());

        let ns = rdatas(&response.authorities, record_types::NS);
        assert_eq!(
            ns.len(),
            2,
            "the child's NS RRset, in the authority section"
        );
        assert!(ns.iter().all(|r| r.name == "sub.example.com."));
        assert!(
            rdatas(&response.authorities, record_types::SOA).is_empty(),
            "a referral carries no SOA — it is not a negative answer"
        );

        // In-bailiwick glue only: an address for `ns.other.test.` would be an
        // assertion about a zone we do not serve.
        let glue = rdatas(&response.additionals, record_types::A);
        assert_eq!(glue.len(), 1, "{:?}", response.additionals);
        assert_eq!(glue[0].name, "ns.sub.example.com.");
    }

    /// The wildcard at the apex must not answer for a name below the cut
    /// (RFC 4592 §2.2.1) — that name belongs to the child.
    #[test]
    fn the_delegation_wins_over_the_wildcard() {
        let response = ask("anything.sub.example.com.", Qtype::of(record_types::A));
        assert!(
            response.answers.is_empty(),
            "the apex wildcard is not this name's source of synthesis"
        );
    }

    /// A query *at* the cut is still a referral, whatever the type — except
    /// the DS, which is the parent's own statement about the child and which
    /// the child could not answer (RFC 4035 §3.1.4.1).
    #[test]
    fn a_ds_at_the_cut_is_answered_by_the_parent() {
        let mut text = ZONE.to_string();
        text.push_str(
            "sub IN DS 12345 13 2 \
             0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\n",
        );
        let zone = parse_zone_file(&text, "example.com.").unwrap();
        let mut zones = Zones::default();
        drop(zones.insert(zone));

        let response = make_response(
            &query("sub.example.com.", Qtype::of(record_types::DS), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert_eq!(rdatas(&response.answers, record_types::DS).len(), 1);
        assert!(response.authoritive, "the DS is the parent's own data");

        // Anything else at the same name is a referral.
        let ns = make_response(
            &query("sub.example.com.", Qtype::of(record_types::NS), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert!(!ns.authoritive);
        assert!(ns.answers.is_empty());
    }

    /// RFC 4592 §3.3.2: synthesis reaches any depth, not one label.
    #[test]
    fn a_wildcard_answers_a_name_more_than_one_label_deep() {
        let response = ask("a.b.c.example.com.", Qtype::of(record_types::A));
        assert_eq!(response.rcode, ResponseCode::Ok);
        let addresses = rdatas(&response.answers, record_types::A);
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].name, "a.b.c.example.com.", "echoed as asked");
    }

    /// RFC 4592 §2.2.2: a name with descendants exists. NXDOMAIN here is the
    /// zone taking *its own* data offline, because an RFC 8020 resolver
    /// extends the denial down to `deep.a.b`.
    #[test]
    fn an_empty_non_terminal_is_nodata_not_nxdomain() {
        let response = ask("a.b.example.com.", Qtype::of(record_types::TXT));
        assert_eq!(response.rcode, ResponseCode::Ok);
        assert!(response.answers.is_empty());
        assert_eq!(rdatas(&response.authorities, record_types::SOA).len(), 1);
    }

    /// RFC 2308 §3: `min(SOA MINIMUM, the SOA record's own TTL)`. The zone
    /// above is the shape this repo's own tests use — `$TTL 3600`,
    /// `minimum 300` — so sending the record's own TTL advertised every "no"
    /// at 3600 where the RFC says 300, cached 12× longer than the operator
    /// asked for.
    #[test]
    fn a_negative_answer_caps_the_soa_ttl_at_minimum() {
        for (qname, qtype, what) in [
            ("a.b.example.com.", record_types::TXT, "NODATA"),
            ("x.a.b.example.com.", record_types::A, "NXDOMAIN"),
        ] {
            let response = ask(qname, Qtype::of(qtype));
            let soa = rdatas(&response.authorities, record_types::SOA);
            assert_eq!(soa.len(), 1, "{what}");
            assert_eq!(
                soa[0].ttl,
                Ttl::from_secs(300),
                "{what}: capped at MINIMUM, not the $TTL"
            );
        }
    }

    /// And the NXDOMAIN that is still an NXDOMAIN, so the fixes above did not
    /// turn every name into a hit: `x.a.b` is below an existing name, so the
    /// apex wildcard is not its source of synthesis and nothing answers.
    #[test]
    fn a_name_nothing_reaches_is_still_nxdomain() {
        let response = ask("x.a.b.example.com.", Qtype::of(record_types::A));
        assert_eq!(response.rcode, ResponseCode::NoSuchDomain);
        assert!(response.authoritive, "we are authoritative for saying no");
        assert_eq!(rdatas(&response.authorities, record_types::SOA).len(), 1);
    }

    /// The class was stored, parsed and then never compared, so a CH
    /// question was answered out of the IN zone — putting `CLASS=CH` in the
    /// echoed question next to `CLASS=IN` records in the answer, a pairing
    /// no resolver can make sense of. RFC 1034 §4.3.2 step 1 searches the
    /// zones *of the question's class*, and there are none.
    ///
    /// REFUSED rather than NXDOMAIN for the reason the rest of this file
    /// gives: NXDOMAIN is an assertion about the DNS that a server holding
    /// nothing in that class has no standing to make, and resolvers cache it.
    #[test]
    fn a_class_this_server_does_not_serve_is_refused() {
        for class in [QueryClass::CH, QueryClass::HS, QueryClass::Other(99)] {
            let mut msg = query("example.com.", Qtype::of(record_types::SOA), false);
            msg.queries[0].qclass = class;
            let response = make_response(&msg, &server(), &DnsMetrics::new());

            assert_eq!(response.rcode, ResponseCode::Refused, "{class:?}");
            assert!(!response.authoritive, "{class:?}");
            assert!(
                response.answers.is_empty(),
                "{class:?}: an IN record must not answer a {class:?} question"
            );
            assert_eq!(
                response.queries[0].qclass, class,
                "{class:?}: the question is echoed as it was asked"
            );
        }
    }

    /// Two questions is FORMERR (RFC 9619 §4), not two answers.
    ///
    /// This server used to loop over the question section and pile every
    /// answer into one message, which has no meaning: there is one RCODE, one
    /// AA bit and one set of sections, so a NOERROR answer and an NXDOMAIN in
    /// the same reply are indistinguishable from an answer and a NODATA. The
    /// last question's outcome simply won. §4 makes it explicit — "A DNS
    /// message with OPCODE = 0 MUST NOT include a QDCOUNT parameter whose
    /// value is greater than 1", to "be treated as an incorrectly formatted
    /// message" — and BIND, NSD, Knot and Unbound all did this already.
    ///
    /// QDCOUNT = 0 stays a plain empty NOERROR: the same section says a
    /// firewall "MUST NOT treat messages with OPCODE = 0 and QDCOUNT = 0 as
    /// malformed".
    #[test]
    fn two_questions_in_one_query_are_a_format_error() {
        let mut msg = query("www.example.com.", Qtype::of(record_types::A), false);
        msg.queries.push(rdns::QuerySection {
            qname: "host.example.com.".to_string(),
            qtype: Qtype::of(record_types::A),
            qclass: QueryClass::IN,
        });
        let response = make_response(&msg, &server(), &DnsMetrics::new());

        assert_eq!(response.rcode, ResponseCode::FormatError);
        assert!(!response.authoritive);
        assert!(response.answers.is_empty(), "neither question is answered");
        assert_eq!(response.queries.len(), 2, "both are echoed back");

        let none = {
            let mut msg = query("www.example.com.", Qtype::of(record_types::A), false);
            msg.queries.clear();
            make_response(&msg, &server(), &DnsMetrics::new())
        };
        assert_eq!(none.rcode, ResponseCode::Ok, "no question is not malformed");
        assert!(none.answers.is_empty());
    }

    /// Choosing a zone folds ASCII case and nothing else (RFC 4343), which
    /// is what the zone index inside it has always done.
    ///
    /// The lookup lower-cased both sides with `str::to_lowercase`
    /// — the full Unicode mapping, which folds U+212A KELVIN SIGN to `k`. A
    /// query for `\u{212A}.example.com.` therefore *selected* the zone
    /// `k.example.com.`, two names that are different bytes on the wire. The
    /// lookup inside then folded ASCII, found nothing, and the answer went
    /// out as NXDOMAIN with AA set — an assertion that a name does not
    /// exist anywhere, made by a server with no standing to make it, and
    /// cached by every resolver that hears it (`CLAUDE.md` §8). REFUSED is
    /// the answer for a name we hold no zone for.
    #[test]
    fn choosing_a_zone_folds_ascii_case_and_nothing_else() {
        let zone = parse_zone_file(
            "$ORIGIN k.example.com.\n\
             $TTL 3600\n\
             @ IN SOA ns1.k.example.com. admin.k.example.com. ( 1 3600 600 604800 300 )\n\
             @ IN NS  ns1.k.example.com.\n",
            "k.example.com.",
        )
        .expect("the test zone parses");
        let mut zones = Zones::default();
        drop(zones.insert(zone));

        let refused = make_response(
            &query("\u{212A}.example.com.", Qtype::of(record_types::SOA), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert_eq!(refused.rcode, ResponseCode::Refused);
        assert!(!refused.authoritive);

        // ASCII case still folds, which is the half that has to keep
        // working: this is the same zone asked for in the other case.
        let answered = make_response(
            &query("K.Example.COM.", Qtype::of(record_types::SOA), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert_eq!(answered.rcode, ResponseCode::Ok);
        assert!(answered.authoritive);
        assert_eq!(rdatas(&answered.answers, record_types::SOA).len(), 1);
    }

    /// A child zone answers for its own names even when its parent is served
    /// here too — the most specific zone wins, which is what the walk finds
    /// first and what the scan's `max_by_key` found by length.
    ///
    /// Preventative, not a regression (§10): both spellings of the lookup get
    /// this right. It is here because the walk is the *only* thing that decides
    /// it now, and a walk that started at the apex instead of the QNAME would
    /// pass every other test in this file.
    #[test]
    fn the_child_zone_answers_for_names_below_the_cut() {
        let parent = parse_zone_file(ZONE, "example.com.").expect("the parent zone parses");
        let child = parse_zone_file(
            "$ORIGIN sub.example.com.\n\
             $TTL 3600\n\
             @   IN SOA ns.sub.example.com. admin.sub.example.com. ( 1 3600 600 604800 300 )\n\
             @   IN NS  ns.sub.example.com.\n\
             ns  IN A   192.0.2.20\n\
             www IN A   192.0.2.21\n",
            "sub.example.com.",
        )
        .expect("the child zone parses");
        let mut zones = Zones::default();
        drop(zones.insert(parent));
        drop(zones.insert(child));

        let from_child = make_response(
            &query("www.sub.example.com.", Qtype::of(record_types::A), false),
            &zones,
            &DnsMetrics::new(),
        );
        // From the parent this name is below a delegation, so a referral with AA
        // clear is what selecting the wrong zone looks like.
        assert!(
            from_child.authoritive,
            "answered from the child, not referred"
        );
        assert_eq!(rdatas(&from_child.answers, record_types::A).len(), 1);

        let from_parent = make_response(
            &query("host.example.com.", Qtype::of(record_types::A), false),
            &zones,
            &DnsMetrics::new(),
        );
        assert!(from_parent.authoritive);
        assert_eq!(rdatas(&from_parent.answers, record_types::A).len(), 1);
    }

    /// QTYPE=ANY is 255, which is a QTYPE and never an RTYPE, so the strict
    /// `record_type_code(&r.rdata) == qtype` matched nothing and an existing
    /// name came back as an empty NOERROR plus the SOA. That is a NODATA for
    /// a name that plainly has data, and it is none of the shapes RFC 8482
    /// §4 permits — not the conventional full answer, not §4.2's synthesized
    /// HINFO, not a single-RRset subset. RFC 1035 §3.2.3 defines it as "all
    /// records", which is the shape taken here.
    #[test]
    fn qtype_any_returns_every_rrset_at_the_name() {
        let response = ask("example.com.", Qtype::of(record_types::ANY));

        assert_eq!(response.rcode, ResponseCode::Ok);
        assert!(response.authoritive);
        assert_eq!(
            rdatas(&response.answers, record_types::SOA).len(),
            1,
            "the apex SOA"
        );
        assert_eq!(
            rdatas(&response.answers, record_types::NS).len(),
            1,
            "and the apex NS beside it, in one answer"
        );
        assert!(
            response.authorities.is_empty(),
            "an answer is not a negative answer and owes no SOA in authority"
        );
    }

    /// A name holding one type still answers with just that type, so the
    /// change did not turn ANY into "everything in the zone".
    #[test]
    fn qtype_any_at_a_single_type_name_returns_only_that_type() {
        let response = ask("host.example.com.", Qtype::of(record_types::ANY));
        assert_eq!(response.rcode, ResponseCode::Ok);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rdata.rtype(), record_types::A);
    }

    /// A CNAME is the only type at its owner (RFC 1034 §3.6.2), so ANY
    /// answers with the alias itself rather than chasing it — the chase is
    /// for a QTYPE the alias does not hold, and ANY holds everything.
    #[test]
    fn qtype_any_at_an_alias_answers_with_the_alias() {
        let response = ask("www.example.com.", Qtype::of(record_types::ANY));
        assert_eq!(response.rcode, ResponseCode::Ok);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(response.answers[0].rdata.rtype(), record_types::CNAME);
        assert_eq!(response.answers[0].name, "www.example.com.");
    }

    /// And a name that does not exist is still NXDOMAIN under ANY: matching
    /// every type must not become matching every name.
    #[test]
    fn qtype_any_at_a_missing_name_is_still_a_negative_answer() {
        let response = ask("x.a.b.example.com.", Qtype::of(record_types::ANY));
        assert_eq!(response.rcode, ResponseCode::NoSuchDomain);
        assert!(response.answers.is_empty());
        assert_eq!(rdatas(&response.authorities, record_types::SOA).len(), 1);
    }

    /// QCLASS=ANY is not an unserved class: RFC 1035 §3.2.5 makes `*` match
    /// any class, and IN is the only class there is here. Refusing it would
    /// be the fix overshooting the bug.
    #[test]
    fn qclass_any_is_answered_from_the_in_zone() {
        let mut msg = query("example.com.", Qtype::of(record_types::SOA), false);
        msg.queries[0].qclass = QueryClass::Any;
        let response = make_response(&msg, &server(), &DnsMetrics::new());

        assert_eq!(response.rcode, ResponseCode::Ok);
        assert!(response.authoritive);
        assert_eq!(rdatas(&response.answers, record_types::SOA).len(), 1);
    }
}
