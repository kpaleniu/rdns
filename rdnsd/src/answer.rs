//! Turning a question into an answer: RFC 1034 §4.3.2, and the four cases.
//!
//! **Everything here is a synchronous function of the message, the zone map and
//! the metrics.** No sockets, no lock guards, nothing `async` — which is what
//! makes this the seam `TODO.md` #20 says to lift first and alone: a move that
//! cannot change what is held across an `.await` cannot change behaviour by
//! accident. `notify_reply` stays in `main`, because it needs `&Secondaries` and
//! the peer address; the transfer and UPDATE paths stay for the stronger version
//! of the same reason.
//!
//! The reason this is worth its own file is not length. It is that the four
//! cases of §4.3.2 — referral, data, alias, no-such-data — are a closed piece of
//! protocol reasoning whose test module names each wire shape it used to get
//! wrong, and reading the two together is how the next person checks them.

use rdns::metrics::{DnsMetrics, LatencyTimer};
use rdns::utils::record_types;
use rdns::zone::{NameKind, Zone};
use rdns::Qtype;
use rdns::Ttl;
use rdns::{
    dnssec_answer, DnsMessage, Edns, OpCode, QueryClass, ResourceRecord, ResponseCode, EDNS_VERSION,
};

use crate::zones::Zones;
use crate::RDNSD_PAYLOAD_SIZE;

/// Build a DNS response for the given query message
///
/// Looks up the zone based on the query name and returns appropriate response
pub(crate) fn make_response(msg: &DnsMessage, zones: &Zones, metrics: &DnsMetrics) -> DnsMessage {
    let timer = LatencyTimer::new();
    let mut response = DnsMessage {
        id: msg.id,
        response: true,
        opcode: msg.opcode,
        authoritive: true,
        truncation: false,
        recursion: msg.recursion,
        recursion_ok: false,
        ad: false,
        cd: msg.cd,
        rcode: ResponseCode::Ok,
        queries: msg.queries.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        edns: None,
    };

    // The client's EDNS parameters, read once for the whole function. This used
    // to be two `msg.edns()` calls sixteen lines apart plus two `has_edns()`
    // scans, and `edns()` builds the option list — a `Vec` and a `Vec<u8>` per
    // option — only for three fields that are not in it (`TODO.md` #9e). A
    // client sending a DNS cookie, which is what BIND and Unbound do by default,
    // paid four allocations per query for a bit.
    //
    // EDNS-level rejections take precedence over any zone lookup: a malformed
    // option list is FORMERR, and an EDNS version we don't implement is BADVERS
    // (RFC 6891 §6.1.3). Both replies carry a bare version-0 OPT — BADVERS is an
    // extended RCODE, so the OPT record is what carries its high bits.
    let client_edns = match msg.edns_header() {
        Ok(edns) => edns,
        Err(_) => {
            response.rcode = ResponseCode::FormatError;
            // `with_payload_size` carries no options, so encoding it cannot fail.
            response.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
            return response;
        }
    };
    if client_edns.is_some_and(|edns| edns.version > EDNS_VERSION) {
        response.rcode = ResponseCode::BadOptVersion;
        response.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
        return response;
    }

    // DO says the client can make sense of DNSSEC records, so send them
    // (RFC 4035 §3.1.1). It is not a request for validation and not a demand
    // that the zone be signed — an unsigned zone answers a DO query exactly as
    // it answers any other, and [`dnssec_answer`] returns nothing for it.
    let dnssec_ok = client_edns.is_some_and(|edns| edns.do_bit);

    // Only QUERY reaches the zone lookup. NOTIFY is answered by the caller,
    // which knows the peer's address; anything else — UPDATE, STATUS, the
    // obsolete IQUERY — is something this server does not implement, and saying
    // so is more useful than treating it as a lookup (RFC 1035 §4.1.1).
    if msg.opcode != OpCode::Query {
        response.rcode = ResponseCode::NotImplemented;
        response.authoritive = false;
        // Mirror the OPT record on the way out. This `return` jumps over the
        // EDNS mirroring at the end of the function, so a NOTIMP used to be the
        // one reply that dropped the client's OPT — and RFC 6891 §6.1.1 says a
        // response to a request that had one includes one. An EDNS client
        // asking with an unsupported opcode got an answer indistinguishable from
        // a server that does not do EDNS at all, which some clients remember as
        // a downgrade and then never offer EDNS to again. `error_bytes` already
        // does this correctly; this path was written separately and drifted
        // (`CLAUDE.md` §7).
        //
        // `client_edns.is_some()` rather than `msg.has_edns()`, and they agree
        // here: the two differ only for an OPT record whose option list is
        // malformed, and that answered FORMERR above without reaching this.
        if client_edns.is_some() {
            let mut edns = Edns::with_payload_size(RDNSD_PAYLOAD_SIZE);
            edns.do_bit = dnssec_ok;
            response.set_edns(edns);
        }
        return response;
    }

    // Process each query
    for query in &msg.queries {
        // The class is part of the question and was never looked at. Every zone
        // this server holds is IN — `zone::parse` refuses any other class in a
        // zone file — so a CH or HS question was answered from the IN zone, and
        // the reply carried `CLASS=CH` in the echoed question beside `CLASS=IN`
        // records in the answer. That pairing is malformed; RFC 1034 §4.3.2's
        // step 1 searches the zones *of the question's class*, and finding none
        // is the same situation as a zone we do not serve.
        //
        // REFUSED rather than NXDOMAIN, for the reason spelled out at the bottom
        // of this loop: NXDOMAIN is an assertion about the DNS that a server
        // holding nothing in that class has no standing to make, and resolvers
        // cache it. QCLASS=ANY (255) is *not* refused — RFC 1035 §3.2.5 makes it
        // match any class, and matching it against the IN zone is exactly right
        // when IN is the only class there is here.
        if !matches!(query.qclass, QueryClass::IN | QueryClass::Any) {
            response.rcode = ResponseCode::Refused;
            response.authoritive = false;
            continue;
        }

        // A transfer over UDP is not a transfer. AXFR is defined over TCP alone
        // (RFC 5936 §4.2) — a whole zone does not fit a datagram and the protocol
        // has no way to say "there is more" — so a UDP request for it is
        // malformed rather than merely refused. The TCP server answers AXFR
        // itself, before ever reaching here, so this is the UDP path speaking.
        if query.qtype == Qtype::AXFR {
            response.rcode = ResponseCode::FormatError;
            continue;
        }

        // An IXFR over UDP is different: it is *expected*, and RFC 1995 §2 gives
        // the answer for one that will not fit in a datagram — a single SOA of
        // the server's current version, which tells the client to come back over
        // TCP. Answering that way always is a deliberate choice rather than a
        // limitation: the ACL, the TSIG session and the multi-message packing all
        // live on the TCP path, and duplicating them here to serve the small
        // subset of increments that fit a datagram would be a second
        // implementation of the interesting parts. The SOA discloses nothing an
        // ordinary SOA query does not, so it needs no ACL of its own.
        if query.qtype == Qtype::IXFR {
            if let Some(zone) = zones.for_query(&query.qname) {
                for soa in zone.query(zone.origin(), Qtype::of(record_types::SOA)) {
                    response.answers.push(ResourceRecord {
                        name: zone.origin().to_string(),
                        class: soa.class,
                        ttl: soa.ttl,
                        rdata: soa.rdata.clone(),
                    });
                }
            } else {
                response.rcode = ResponseCode::Refused;
                response.authoritive = false;
            }
            continue;
        }

        // Find the matching zone for this query
        let zone = zones.for_query(&query.qname);

        if let Some(zone) = zone {
            match resolve_in_zone(zone, &query.qname, query.qtype) {
                Outcome::Referral { cut } => {
                    refer_to_child(zone, &cut, dnssec_ok, &mut response);
                }
                Outcome::Answer { chain, name } => {
                    add_chain(zone, &chain, dnssec_ok, &mut response);
                    add_answer(zone, &name, query.qtype, dnssec_ok, &mut response);
                }
                Outcome::Negative { chain, name, kind } => {
                    add_chain(zone, &chain, dnssec_ok, &mut response);
                    add_negative(zone, &name, &kind, dnssec_ok, &mut response);
                }
                Outcome::ChainLeftZone { chain } => {
                    add_chain(zone, &chain, dnssec_ok, &mut response);
                }
            }
        } else {
            // A zone we do not serve is REFUSED, not NXDOMAIN, and the two are
            // not interchangeable. NXDOMAIN is an assertion *about the DNS* —
            // this name does not exist anywhere — which we have no standing to
            // make about a zone we hold nothing for; a resolver believes it and
            // caches it (RFC 2308), so the lie propagates. REFUSED says the
            // truth, that this server will not answer, and sends the resolver to
            // the other nameservers in the delegation. It is what BIND, NSD and
            // Knot all answer here.
            //
            // This matters more now that a zone can be *withdrawn*: an expired
            // secondary that answered NXDOMAIN would take its zone off the
            // internet for as long as anything cached the answer, which is the
            // opposite of what stopping serving it is for.
            response.rcode = ResponseCode::Refused;
            response.authoritive = false;
        }
    }

    // Count the *answer*, once, by what it actually says.
    //
    // These used to be `increment_cache_hits`/`increment_cache_misses`, on an
    // authoritative server that has no cache — the names were standing in for
    // "found something" and "did not", which is not a question anyone asks of a
    // primary. A rate of SERVFAIL, NXDOMAIN and REFUSED is what an operator
    // pages on, and it is what tells a zone that went missing (REFUSED climbs)
    // from a zone that went wrong (SERVFAIL climbs) from ordinary traffic for
    // names that are not there (NXDOMAIN, which is normal and noisy).
    metrics.count_response(response.rcode);
    if response.authoritive {
        metrics.count(&metrics.queries_authoritative);
    }
    metrics.observe_latency_ms(timer.elapsed_ms());

    // Mirror EDNS0: only include an OPT record when the client used EDNS
    // (RFC 6891 §6.1.1), advertising our own UDP payload size. DO is echoed
    // when it was asked for, which is how the client knows the DNSSEC records
    // it did or did not get were a deliberate answer (RFC 3225 §3).
    if client_edns.is_some() {
        let mut edns = Edns::with_payload_size(RDNSD_PAYLOAD_SIZE);
        edns.do_bit = dnssec_ok;
        response.set_edns(edns);
    }

    response
}

/// What RFC 1034 §4.3.2 decided about one question against one zone.
///
/// The algorithm there is a loop with four exits, and only two of them were ever
/// implemented here: records, or a negative answer. The two that were missing are
/// the ones an ordinary zone cannot be served without — a referral at a
/// delegation, and following an alias.
enum Outcome {
    /// The zone's authority stops at `cut`: the answer is a referral to the
    /// child, with AA **clear** (RFC 1035 §4.1.1).
    Referral { cut: String },
    /// There are records for the question at `name`, reached through the
    /// aliases at `chain` (empty in the ordinary case).
    Answer { chain: Vec<String>, name: String },
    /// No records. `name` is the name the "no" is about — the end of the chain
    /// when one was followed — and `kind` decides NXDOMAIN against NODATA.
    Negative {
        chain: Vec<String>,
        name: String,
        kind: NameKind,
    },
    /// The chain walked out of this zone: NOERROR with the aliases we do hold
    /// and nothing else. **Not** NXDOMAIN — we know nothing about the target,
    /// and saying it does not exist would take it off the internet for as long
    /// as anything cached the answer (RFC 1034 §4.3.2 step 3a).
    ChainLeftZone { chain: Vec<String> },
}

/// How many aliases we will follow inside one zone before giving up.
///
/// A zone with `a CNAME b` and `b CNAME a` is a broken zone, not an attack, but
/// the loop is real and the visited set below is what actually stops it. This is
/// the second bound, for the chain that grows without repeating.
pub(crate) const MAX_CNAME_HOPS: usize = 16;

/// Walk RFC 1034 §4.3.2 for one question.
///
/// The four cases are tried in this order at every name, which is the order the
/// RFC gives and the order that matters: the zone's authority ends here, the
/// name has the data, the name is an alias, the name has no such data. Getting
/// the first one last is how a parent ends up answering NXDOMAIN for a child's
/// names.
fn resolve_in_zone(zone: &Zone, qname: &str, qtype: Qtype) -> Outcome {
    let mut chain: Vec<String> = Vec::new();
    let mut visited: Vec<String> = Vec::new();
    let mut name = qname.to_string();

    for _ in 0..MAX_CNAME_HOPS {
        // A delegation is a referral whatever the type asked for, with one
        // exception: the DS *at* the cut is the parent's own statement about the
        // child, so it is answered here rather than sent downwards — the child
        // does not hold its own DS and could not be asked (RFC 4035 §3.1.4.1).
        if let Some(cut) = zone.delegation_for(&name) {
            let at_the_cut = cut.eq_ignore_ascii_case(&zone.normalize_name(&name));
            if !(qtype.is(record_types::DS) && at_the_cut) {
                return if chain.is_empty() {
                    Outcome::Referral { cut }
                } else {
                    // Mid-chain, the target is the child's name to answer for.
                    // Stopping with what we hold costs the resolver one round
                    // trip and cannot be wrong; answering from the glue below
                    // the cut would serve occluded data as authoritative.
                    Outcome::ChainLeftZone { chain }
                };
            }
        }

        let kind = zone.name_kind(&name);
        if !zone.query(&name, qtype).is_empty() {
            return Outcome::Answer { chain, name };
        }
        // A CNAME query is answered by the CNAME, not followed by it — the
        // alias is the data when the alias is what was asked for.
        if qtype.is(record_types::CNAME) {
            return Outcome::Negative { chain, name, kind };
        }

        let Some(target) = cname_target(zone, &name) else {
            return Outcome::Negative { chain, name, kind };
        };
        chain.push(name.clone());
        visited.push(zone.normalize_name(&name).to_ascii_lowercase());

        // Still folded for `visited`, which is an equality test against a list
        // of folded names; `in_zone` no longer needs it to be.
        let target_key = zone.normalize_name(&target).to_ascii_lowercase();
        if !in_zone(zone, &target_key) || visited.contains(&target_key) {
            return Outcome::ChainLeftZone { chain };
        }
        name = target;
    }
    Outcome::ChainLeftZone { chain }
}

/// The target of the CNAME at `name`, if there is one.
///
/// Only the first is read. RFC 1034 §3.6.2 allows exactly one CNAME at an owner
/// name — a second is a broken zone, and picking one arbitrarily is better than
/// answering with a two-record RRset no client can use. The parser refuses to
/// load the shape at all (see `zone::parse_zone_file`), so this is the belt to
/// that braces.
fn cname_target(zone: &Zone, name: &str) -> Option<String> {
    zone.query(name, Qtype::of(record_types::CNAME))
        .first()
        .and_then(|record| match record.rdata.parse() {
            Ok(rdns::ParsedRecord::CNAME(target)) => Some(target),
            _ => None,
        })
}

/// Whether a name is at or below this zone's apex.
///
/// [`rdns::utils::is_at_or_under`], which is a fourth copy of the same rule this
/// used to be — the same family as the one `zone_signer` was shadowing
/// (`TODO.md` #19b, #19h). The copy allocated `zone.origin().to_ascii_lowercase()`
/// **per call**, on the CNAME-chase and referral-glue paths, and both call sites
/// additionally allocated on the name to feed it something already folded. The
/// shared version compares case-insensitively itself, so neither allocation is
/// needed and the callers hand it the name they already have.
fn in_zone(zone: &Zone, name: &str) -> bool {
    rdns::utils::is_at_or_under(name, zone.origin())
}

/// Put the records of `qtype` at `name` into the answer section, with their
/// signatures.
///
/// The answer echoes the name asked about rather than the stored owner, which
/// may be `@`, relative, or a wildcard — and for a wildcard match the queried
/// name is what the client must see (RFC 1034 §4.3.3).
fn add_answer(zone: &Zone, name: &str, qtype: Qtype, dnssec_ok: bool, response: &mut DnsMessage) {
    for record in zone.query(name, qtype) {
        response.answers.push(ResourceRecord {
            name: name.to_string(),
            class: record.class,
            ttl: record.ttl,
            rdata: record.rdata.clone(),
        });
    }

    if dnssec_ok {
        let signatures = dnssec_answer::answer_signatures(zone, name, qtype);
        // A wildcard answer is not finished when its signature is attached. The
        // same signature verifies at every name that wildcard reaches, so the
        // answer also has to say that the name actually asked for is not in the
        // zone (RFC 4035 §3.1.3) — otherwise one captured answer is a valid
        // answer for all of them.
        if signatures.wildcard.is_some() {
            response
                .authorities
                .extend(dnssec_answer::proof_of_absence(zone, name));
        }
        response.answers.extend(signatures.records);
    }
}

/// The aliases walked to reach the answer, in the order they were followed.
///
/// Each is a CNAME RRset at its own owner name, so it carries its own signature
/// — and its own wildcard denial when the alias was synthesized.
fn add_chain(zone: &Zone, chain: &[String], dnssec_ok: bool, response: &mut DnsMessage) {
    for at in chain {
        add_answer(
            zone,
            at,
            Qtype::of(record_types::CNAME),
            dnssec_ok,
            response,
        );
    }
}

/// A negative answer: the rcode, the SOA that says how long it may be cached,
/// and the proof of it when the client can check one.
fn add_negative(
    zone: &Zone,
    name: &str,
    kind: &NameKind,
    dnssec_ok: bool,
    response: &mut DnsMessage,
) {
    if matches!(kind, NameKind::NotFound) {
        response.rcode = ResponseCode::NoSuchDomain;
    }

    // Both kinds of "no" carry the zone's SOA in the authority section
    // (RFC 2308 §2.1 and §2.2). It is not decoration: it is what tells the
    // client, and every resolver in between, how long the answer may be cached.
    // Without it a negative answer is uncacheable, so each repeat of a failing
    // lookup comes back to us.
    for soa in zone.query(zone.origin(), Qtype::of(record_types::SOA)) {
        response.authorities.push(ResourceRecord {
            name: zone.origin().to_string(),
            class: soa.class,
            ttl: negative_ttl(soa),
            rdata: soa.rdata.clone(),
        });
    }

    // An unsigned "no" is a "no" a resolver has to take on trust, which for a
    // signed zone is the one thing DNSSEC exists to avoid: the proof is what
    // stops a forged NXDOMAIN taking a name off the internet for as long as it
    // stays cached.
    if dnssec_ok {
        response
            .authorities
            .extend(dnssec_answer::negative_proof(zone, name, kind));
    }
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
    match soa.rdata.parse() {
        Ok(rdns::ParsedRecord::SOA { minimum, .. }) => soa.ttl.min(Ttl::from_secs(minimum)),
        // An apex SOA that will not parse is a zone that should not have loaded.
        // Capping at nothing is the conservative direction: the client asks
        // again rather than caching a "no" we cannot bound.
        _ => Ttl::ZERO,
    }
}

/// A referral to the child zone: the delegation's NS RRset, its glue, and — for
/// a client that can check it — the DS or the proof there is none.
///
/// AA is **clear**, which is the whole point. This server hardcoded it true and
/// answered NXDOMAIN for names below a delegation, so per RFC 8020 every
/// resolver cached "the entire subtree does not exist" and the child zone went
/// off the internet for the negative TTL.
fn refer_to_child(zone: &Zone, cut: &str, dnssec_ok: bool, response: &mut DnsMessage) {
    response.authoritive = false;

    let mut targets: Vec<String> = Vec::new();
    for ns in zone.query(cut, Qtype::of(record_types::NS)) {
        if let Ok(rdns::ParsedRecord::NS(target)) = ns.rdata.parse() {
            targets.push(target);
        }
        response.authorities.push(ResourceRecord {
            name: cut.to_string(),
            class: ns.class,
            ttl: ns.ttl,
            rdata: ns.rdata.clone(),
        });
    }

    // Glue, and only in-bailiwick glue: an address we hold for a nameserver
    // under this zone is a hint we are entitled to give, while one for a name in
    // somebody else's zone is an assertion about their data. A resolver worth
    // anything discards the latter, and sending it is how cache-poisoning
    // attempts look (RFC 1034 §4.2.1).
    for target in targets {
        // No fold: `is_at_or_under` compares case-insensitively, so the
        // `to_ascii_lowercase` this used to do per glue target was paying for a
        // guarantee the callee already gives (`TODO.md` #19h).
        if !in_zone(zone, &zone.normalize_name(&target)) {
            continue;
        }
        for rtype in [record_types::A, record_types::AAAA] {
            for glue in zone.query(&target, Qtype::of(rtype)) {
                response.additionals.push(ResourceRecord {
                    name: target.clone(),
                    class: glue.class,
                    ttl: glue.ttl,
                    rdata: glue.rdata.clone(),
                });
            }
        }
    }

    if dnssec_ok {
        response
            .authorities
            .extend(dnssec_answer::delegation_proof(zone, cut));
    }
}

/// **RFC 1034 §4.3.2: the four cases an authoritative answer can be.**
///
/// Three of the four were missing here, and the suite was green the whole time
/// because it asserted what the code did — `CLAUDE.md` §1's opening example.
/// Each test below names the wire shape that used to go out.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::query;
    use rdns::zone::parse_zone_file;
    use rdns::Rtype;

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
    /// NXDOMAIN with **AA=1**, so per RFC 8020 every resolver cached "the
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

    /// Choosing a zone folds ASCII case and nothing else (RFC 4343), which
    /// is what the zone index inside it has always done.
    ///
    /// The lookup lower-cased both sides with `str::to_lowercase`
    /// — the full Unicode mapping, which folds U+212A KELVIN SIGN to `k`. A
    /// query for `\u{212A}.example.com.` therefore *selected* the zone
    /// `k.example.com.`, two names that are different bytes on the wire. The
    /// lookup inside then folded ASCII, found nothing, and the answer went
    /// out as NXDOMAIN **with AA set** — an assertion that a name does not
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
