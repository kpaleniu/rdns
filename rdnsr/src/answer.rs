//! Turning a query into the bytes that answer it: the caches, the answer path
//! and the shaping every reply goes through.
//!
//! No sockets and no listener state — [`handle_query`] takes a datagram and
//! gives back the reply, which is what lets the UDP loop and the TCP handler in
//! [`crate::serve`] be two callers of one function. It is `async` because a
//! recursion is, not because anything here waits on a socket itself.

use std::net::IpAddr;
use std::sync::Arc;

use rdns::dnssec_chain::ValidationState;
use rdns::metrics::LatencyTimer;
use rdns::negative_cache::NegativeCache;
use rdns::nsec_cache::NsecCache;
use rdns::record_types;
use rdns::resolver::Resolver;
use rdns::response::ClientEdns;
use rdns::special_names;
use rdns::validation::Request;
use rdns::Rtype;
use rdns::{
    DnsCache, DnsMessage, Edns, OpCode, QuerySection, ResourceRecord, ResponseCode, OPT_RECORD_TYPE,
};
use rdns_transport::{ServeContext, Transport};

use crate::RDNSR_PAYLOAD_SIZE;

/// What `rdnsr` remembers between queries.
///
/// Three caches with three shapes, which is why they are not one.
///
/// - `answers` maps a question to the records that answered it.
/// - `negatives` maps a question to the *absence* of records (RFC 2308): a
///   different thing, because there are no records to key on and the TTL comes
///   from the SOA rather than from an answer.
/// - `denials` maps a *range* of names to the signed statement that none exist —
///   a lookup neither of the others can express (RFC 8198). Validated material
///   only, so it is empty without `--dnssec-validate`, which is why `negatives`
///   is not redundant with it.
pub(crate) struct Caches {
    answers: DnsCache,
    negatives: NegativeCache,
    denials: NsecCache,
}

impl Caches {
    /// `answers` at 0 is a cache that holds nothing (`DnsCache::put` is a
    /// no-op), which is what `--no-cache` means. `denial_zones` is separately 0
    /// without validation: aggressive use rests on the proofs having been
    /// checked.
    pub(crate) fn new(capacity: usize, denial_zones: usize) -> Caches {
        Caches {
            answers: DnsCache::new(capacity),
            // Negative answers are answers: `--no-cache` means no cache.
            negatives: NegativeCache::new(capacity),
            denials: NsecCache::new(denial_zones),
        }
    }
}

/// What the client asked for and what it can take: everything about a request
/// that shapes the reply once the answer itself is decided.
struct Client {
    edns: ClientEdns,
    /// RFC 6840 §5.8: AD is for a client that asked to be told — DO, or AD set
    /// in the query.
    wants_ad: bool,
    max_len: usize,
}

/// Resolve one datagram: cache lookup, else forward upstream and cache-store.
/// Returns the wire bytes to send back, or `None` if the query was unparseable
/// (in which case we simply drop it, as a resolver should).
pub(crate) async fn handle_query(
    data: Vec<u8>,
    peer: IpAddr,
    now: u64,
    resolver: &Arc<Resolver>,
    caches: &Arc<Caches>,
    ctx: &ServeContext,
    transport: Transport,
) -> Option<Vec<u8>> {
    // Refuse a *response*: a reply parsed as a question and answered with
    // another reply is a packet loop between two servers pointed at each other.
    // `None` is the whole reply, because the peer did not ask anything. The type
    // is what makes the check unskippable — see `rdns::validation::Request`.
    let msg = match Request::from_bytes(&data) {
        Ok(msg) => msg,
        Err(_) => {
            ctx.logger.count_error(peer);
            return None;
        }
    };
    let timer = LatencyTimer::new();
    ctx.metrics.count(&ctx.metrics.queries_received);
    // Per source and per type, for the periodic anomaly warnings — the counters
    // `rdnsd` has kept since #9d and this daemon held and never filled
    // (`TODO.md` #30m). `now` is the caller's: on UDP it is the instant the rate
    // limiter already used.
    ctx.logger
        .log_query(peer, msg.queries.first().map(|q| q.qtype), now);
    if let Some(q) = msg.queries.first() {
        ctx.metrics.track_query_type(q.qtype);
    }

    // NOTIMP is more useful than answering a NOTIFY or an UPDATE with a
    // plausible QUERY-shaped reply the sender will misread (RFC 1035 §4.1.1).
    if msg.opcode != OpCode::Query {
        ctx.record_answer(ResponseCode::NotImplemented, timer);
        return unsupported_opcode(&msg);
    }

    let query = msg.queries.first()?.clone();
    let id = msg.id;
    let recursion = msg.recursion;
    // UDP: 512 unless EDNS0 advertised more. TCP: the length prefix is the only
    // limit, and truncating there strands a client already on the fallback.
    let client_max = match transport {
        Transport::Udp => msg.udp_payload_size() as usize,
        Transport::Tcp => u16::MAX as usize,
    };

    // Before any work on the client's behalf: a malformed option list is
    // FORMERR, an unimplemented EDNS version is BADVERS (RFC 6891 §6.1.3), and
    // both replies carry a bare version-0 OPT. `rdnsd` reads the same decision
    // out of the same function (`TODO.md` #30h).
    let client_edns = match rdns::response::client_edns(&msg) {
        Ok(edns) => edns,
        Err(rcode) => {
            ctx.record_answer(rcode, timer);
            return edns_error(&msg, rcode, client_max);
        }
    };
    // DO means "send me the signatures", AD "tell me whether you checked"; CD
    // means "don't withhold anything on my behalf, I validate myself", which is
    // the message's own bit.
    let client = Client {
        wants_ad: client_edns.do_bit() || msg.ad,
        edns: client_edns,
        max_len: client_max,
    };
    let checking_disabled = msg.cd;

    // RFC 9619 §4: "A DNS message with OPCODE = 0 MUST NOT include a QDCOUNT
    // parameter whose value is greater than 1", and one that does "MUST be
    // treated as an incorrectly formatted message" — one RCODE and one set of
    // sections cannot describe two lookups. `rdnsd` has refused it since #9f;
    // this answered the first question and echoed one, so the reply did not
    // match the request either (`TODO.md` #30r).
    if msg.queries.len() > 1 {
        let resp = build_response(&msg, Vec::new(), ResponseCode::FormatError);
        return finish(resp, false, &client, &query, ctx, timer);
    }

    // Names that must not leave this machine (RFC 6761, 6762, 6303). Before
    // every cache: the table *is* the answer, and consulting anything else means
    // a query going out.
    //
    // Not skipped for CD, unlike the denial cache: CD is a statement about
    // DNSSEC, not a request to be told what a public server thinks `localhost`
    // is.
    if let Some(local) = special_names::lookup(query.qname.as_ref(), query.qtype) {
        let mut resp = build_response(&msg, local.answers, local.rcode);
        resp.authorities = local.authority;
        // DEBUG: one line per query, with the name on it. Logging every query
        // is the operator's decision, not the default's.
        tracing::debug!(qname = %query.qname, why = %local.why, "answered locally");
        // Never authenticated: this was decided by specification rather than
        // validated, and a validating client cannot check the claim itself.
        return finish(resp, false, &client, &query, ctx, timer);
    }

    // Aggressive use of the validated denial cache (RFC 8198). A cached NSEC
    // answers every question in its gap, so it goes before the answer cache: a
    // flood of random names under one zone costs one upstream query, not one per
    // name. Skipped for CD, which asks us not to filter on the client's behalf.
    //
    // The positive half (§5.3) first: a validated wildcard answer is a signed
    // statement about every name the wildcard reaches. The two are mutually
    // exclusive — a cached NXDOMAIN needs the wildcard *denied* — so trying the
    // more specific one first costs nothing.
    if !checking_disabled {
        if let Some(wildcard) = caches
            .denials
            .synthesize_wildcard(query.qname.as_ref(), query.qtype)
        {
            let mut resp = build_response(&msg, wildcard.answers, ResponseCode::Ok);
            resp.authorities = wildcard.authority;
            // A wildcard signature verifies at this name unchanged, so the
            // client can check this for itself.
            return finish(resp, true, &client, &query, ctx, timer);
        }
    }

    if !checking_disabled {
        if let Some(denial) = caches.denials.synthesize(query.qname.as_ref(), query.qtype) {
            ctx.metrics.count(&ctx.metrics.cache_hits);
            let mut resp = build_response(&msg, Vec::new(), denial.rcode);
            resp.authorities = denial.authority;
            // The proofs were validated before storage, so what is derived
            // from them is authentic on the same terms.
            return finish(resp, true, &client, &query, ctx, timer);
        }
    }

    // A cached "no" (RFC 2308), separate from the answer cache only because
    // there are no records to key on. Nothing is synthesized — this is the
    // answer this question got — so a CD client may have it too.
    if let Some(negative) = caches.negatives.get(query.qname.as_ref(), query.qtype) {
        ctx.metrics.count(&ctx.metrics.cache_hits);
        let mut resp = build_response(&msg, Vec::new(), negative.rcode);
        resp.authorities = negative.authority;
        return finish(resp, negative.secure, &client, &query, ctx, timer);
    }

    // Build the response: from cache if we have it, else by resolving.
    let (mut resp, secure) = if let Some((records, secure)) = caches
        .answers
        .get_validated(query.qname.as_ref(), query.qtype)
    {
        ctx.metrics.count(&ctx.metrics.cache_hits);
        (build_response(&msg, records, ResponseCode::Ok), secure)
    } else {
        // Everything above answered from something held; from here the
        // query costs a recursion. This is the line a cache hit rate is
        // drawn on.
        ctx.metrics.count(&ctx.metrics.cache_misses);
        ctx.metrics.count(&ctx.metrics.queries_recursive);
        // Async: each upstream round trip is an await, so this yields the
        // task rather than holding a thread.
        match resolver.resolve_validated(&query).await {
            Ok((mut upstream, state)) => {
                // The resolver used its own random id; the reply must echo
                // the client's and advertise recursion.
                upstream.id = id;
                upstream.response = true;
                upstream.recursion = recursion;
                upstream.recursion_ok = true;

                if let ValidationState::Bogus(ref why) = state {
                    // WARN: an answer that does not validate is an attack
                    // or a broken zone, and both are worth seeing.
                    tracing::warn!(
                        qname = %query.qname,
                        qtype = %query.qtype,
                        "DNSSEC validation failed: {why}"
                    );
                    // Fail closed: the client cannot tell unauthenticated
                    // data from checked data, so serving it launders an
                    // attack into an ordinary reply. CD says the client
                    // checks for itself, and RFC 4035 §3.2.2 requires the
                    // data unfiltered.
                    if !checking_disabled {
                        let resp = build_response(&msg, Vec::new(), ResponseCode::ServerFailure);
                        return finish(resp, false, &client, &query, ctx, timer);
                    }
                }

                let secure = state.is_secure();
                // A bogus answer in the cache is an attack that outlives
                // the query that carried it.
                if !upstream.answers.is_empty() && !state.is_bogus() {
                    caches.answers.put_validated(
                        query.qname.as_ref(),
                        query.qtype,
                        upstream.answers.clone(),
                        secure,
                    );
                }
                // A "no" is an answer; re-resolving it makes a typo storm
                // cost one upstream walk per repeat. The SOA in the
                // authority section says how long it is good for (RFC 2308).
                if !state.is_bogus() {
                    caches
                        .negatives
                        .insert(query.qname.as_ref(), query.qtype, &upstream, secure);
                }
                // A *validated* "no" covers a whole range of names, so it
                // also goes in the denial cache. Only when Secure: an
                // unvalidated NSEC is an attacker's claim about which names
                // do not exist.
                if upstream.answers.is_empty() && secure {
                    caches.denials.insert_validated(&upstream);
                }
                // A validated wildcard answer is the same kind of statement
                // about a range (RFC 8198 §5.3), so it is kept under the
                // wildcard rather than the name asked for.
                if !upstream.answers.is_empty() && secure {
                    caches.denials.insert_validated_wildcard(&upstream);
                }
                (upstream, secure)
            }
            // Say why, then SERVFAIL: lame delegation, budget exhausted
            // and CNAME loop are distinct so they can be read.
            Err(ref e) => {
                // DEBUG: a failed lookup is ordinary, and one line per
                // failure is a flood. The SERVFAIL counter is the alert.
                tracing::debug!(
                    qname = %query.qname,
                    qtype = %query.qtype,
                    "resolve failed: {:#}",
                    e
                );
                (
                    build_response(&msg, Vec::new(), ResponseCode::ServerFailure),
                    false,
                )
            }
        }
    };

    resp.cd = checking_disabled;

    finish(resp, secure, &client, &query, ctx, timer)
}

/// Final shaping common to every reply: the AD bit, OPT mirroring, stripping
/// DNSSEC records a client did not ask for, and the size limit.
///
/// `authenticated` is the caller's half of AD — did *this resolver* check the
/// data (RFC 6840 §5.7) — and whether the client asked to be told (§5.8) is the
/// half every answer path had written out for itself.
fn finish(
    mut resp: DnsMessage,
    authenticated: bool,
    client: &Client,
    query: &QuerySection,
    ctx: &ServeContext,
    timer: LatencyTimer,
) -> Option<Vec<u8>> {
    // Here because this is where every ordinary answer leaves, whatever
    // produced it: cache, denial cache, negative cache or a full recursion.
    ctx.record_answer(resp.rcode, timer);
    resp.ad = authenticated && client.wants_ad;
    // No DO, no DNSSEC records (RFC 4035 §3.2.1). Records asked for by type
    // are a different matter and stay.
    if !client.edns.do_bit() {
        let asked_for = |rtype: Rtype| query.qtype.is(rtype);
        let keep = |rr: &ResourceRecord| match rr.rdata.rtype() {
            record_types::RRSIG | record_types::NSEC | record_types::NSEC3 => false,
            record_types::DNSKEY | record_types::DS => asked_for(rr.rdata.rtype()),
            _ => true,
        };
        resp.answers.retain(keep);
        resp.authorities.retain(keep);
        resp.additionals
            .retain(|rr| rr.rdata.rtype() == OPT_RECORD_TYPE || keep(rr));
    }

    // Only include an OPT record when the client used EDNS (RFC 6891 §6.1.1);
    // otherwise strip any OPT the upstream added so we don't reply with
    // unsolicited EDNS. DO is mirrored, since the signatures the client sees
    // were deliberate.
    if let Some(edns) = client.edns.mirror(RDNSR_PAYLOAD_SIZE) {
        resp.set_edns(edns);
    } else {
        resp.additionals
            .retain(|rr| rr.rdata.rtype() != OPT_RECORD_TYPE);
    }

    // Honor the client's advertised UDP size: truncates (TC=1) if it overflows.
    resp.to_bytes_within(client.max_len).ok()
}

/// An empty error response carrying a version-0 OPT record, for the EDNS-level
/// rejections (FORMERR / BADVERS) that must be signalled before resolving.
fn edns_error(request: &DnsMessage, rcode: ResponseCode, client_max: usize) -> Option<Vec<u8>> {
    let mut resp = build_response(request, Vec::new(), rcode);
    // BADVERS is an extended RCODE, so the OPT record isn't optional here — it
    // carries the code's high bits.
    resp.set_edns(Edns::with_payload_size(RDNSR_PAYLOAD_SIZE));
    resp.to_bytes_within(client_max).ok()
}

/// NOTIMP for an opcode this resolver does not implement.
///
/// The opcode is echoed, not replaced with QUERY (RFC 1035 §4.1.1): a NOTIFY
/// answered with `opcode = QUERY` is a reply its sender cannot match. Same
/// reason [`build_response`] takes one rather than assuming.
///
/// The question is echoed and the OPT record mirrored if the client used EDNS
/// (RFC 6891 §6.1.1) — a reply with no OPT may get us cached as a server that
/// does not do EDNS.
fn unsupported_opcode(msg: &DnsMessage) -> Option<Vec<u8>> {
    let mut resp = build_response(msg, Vec::new(), ResponseCode::NotImplemented);
    if let Some(edns) = ClientEdns::of(msg).mirror(RDNSR_PAYLOAD_SIZE) {
        resp.set_edns(edns);
    }
    resp.to_bytes_within(RDNSR_PAYLOAD_SIZE as usize).ok()
}

/// A reply to `request` carrying `answers`, from whatever produced them.
///
/// The echoed fields are [`DnsMessage::reply_to`]'s, which is where the id, the
/// opcode and the question come from — the opcode because it is the client's,
/// not ours (RFC 1035 §4.1.1). RA is set here because this is a recursive
/// resolver; that is the one policy field every caller agrees on.
///
/// This used to clear CD, against RFC 4035 §3.2.2's "the name server side MUST
/// copy the setting of the CD bit from a query to the corresponding response",
/// and two of the eight call sites set it back by hand (`TODO.md` #30g).
fn build_response(
    request: &DnsMessage,
    answers: Vec<ResourceRecord>,
    rcode: ResponseCode,
) -> DnsMessage {
    let mut resp = DnsMessage::reply_to(request);
    resp.recursion_ok = true;
    resp.rcode = rcode;
    resp.answers = answers;
    resp
}

/// The same answer with TC=1 and no records: what a client over its response
/// budget gets instead of the answer.
///
/// Smaller than the query that asked for it, so useless for amplification, and
/// RFC 1035 §4.2.1 has the client retry over TCP where the handshake proves the
/// source and the budget no longer applies. Silence would leave a legitimate
/// client with a timeout and no idea TCP would work.
///
/// Built by reading our own reply back rather than editing its header in place:
/// one parse, on a path taken only when a source is over budget, and the flags,
/// the echoed question and the OPT record are whatever `to_bytes_within` wrote.
pub(crate) fn truncate_reply(reply: &[u8]) -> Option<Vec<u8>> {
    let mut msg = DnsMessage::try_from_bytes(reply).ok()?;
    msg.truncation = true;
    msg.answers.clear();
    msg.authorities.clear();
    msg.additionals.clear();
    // `to_bytes_within` needs a ceiling; the reply carries no records now, so
    // the classic 512 is more than enough and does not depend on what the
    // client advertised.
    msg.to_bytes_within(rdns::CLASSIC_UDP_SIZE as usize).ok()
}

#[cfg(test)]
mod tests {
    use rdns::clock::current_unix_timestamp;
    use rdns::Qtype;

    use super::*;
    use crate::testutil::*;

    /// AD is two claims at once — this resolver checked the data (RFC 6840
    /// §5.7) and the client asked to be told (§5.8) — so all four combinations
    /// are the rule.
    ///
    /// Not a regression test: the rule was written out at each of the five
    /// answer paths before it was `finish`'s, and every one of them computed
    /// this. What it holds is that there is now one place to get it wrong.
    #[test]
    fn ad_needs_both_an_authenticated_answer_and_a_client_that_asked() {
        let msg = DnsMessage::try_from_bytes(&message(OpCode::Query, false)).expect("parses");
        let query = msg.queries[0].clone();
        for authenticated in [false, true] {
            for asked in [false, true] {
                let client = Client {
                    edns: ClientEdns::of(&msg),
                    wants_ad: asked,
                    max_len: 512,
                };
                let resp = build_response(&msg, Vec::new(), ResponseCode::Ok);
                let bytes = finish(
                    resp,
                    authenticated,
                    &client,
                    &query,
                    &test_shell(),
                    LatencyTimer::new(),
                )
                .expect("a reply this small serializes");
                let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
                assert_eq!(
                    reply.ad,
                    authenticated && asked,
                    "authenticated={authenticated}, asked={asked}"
                );
            }
        }
    }

    /// A reply over the response budget comes back truncated rather than whole:
    /// TC=1 carries no records, so it cannot amplify, and RFC 1035 §4.2.1 has
    /// the client retry over TCP where the handshake proves the address.
    #[test]
    fn a_truncated_reply_carries_no_records_and_keeps_its_question() {
        let request = rdns::DnsMessageBuilder::new()
            .with_id(0x4242)
            .with_query(nm("www.example.com."), Qtype::of(rdns::record_types::A))
            .build();
        let resp = build_response(
            &request,
            vec![ResourceRecord {
                name: nm("www.example.com."),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(60),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                    "192.0.2.1".parse().unwrap(),
                ))
                .unwrap(),
            }],
            ResponseCode::Ok,
        );
        let full = resp.to_bytes_within(4096).expect("serializes");

        let short = truncate_reply(&full).expect("truncates");
        assert!(
            short.len() < full.len(),
            "and is smaller than what it replaces"
        );
        let parsed = DnsMessage::try_from_bytes(&short).expect("a well-formed reply");
        assert!(parsed.truncation, "TC=1");
        assert!(parsed.answers.is_empty(), "carrying no records");
        assert_eq!(parsed.id, 0x4242, "the client can still match it");
        assert_eq!(parsed.queries.len(), 1, "with its question echoed");
    }

    /// NOTIMP is built away from `finish`, so it mirrors the OPT by hand and
    /// used to drop DO with it (RFC 6891 §6.1.1, RFC 3225 §3; `CLAUDE.md` §7).
    #[test]
    fn an_unimplemented_opcode_keeps_the_clients_do_bit() {
        let mut request = rdns::DnsMessageBuilder::new()
            .with_id(0x1234)
            .with_query(nm("example.com."), Qtype::of(rdns::record_types::A))
            .build();
        request.opcode = OpCode::Status;
        let mut edns = rdns::Edns::with_payload_size(1232);
        edns.do_bit = true;
        request.set_edns(edns);

        let bytes = unsupported_opcode(&request).expect("a NOTIMP reply");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("it parses");
        assert_eq!(reply.rcode, ResponseCode::NotImplemented);
        assert!(
            reply
                .edns()
                .expect("an OPT, since the query had one")
                .do_bit
        );
    }

    /// The packet loop: a *response* has a question section too, so two
    /// instances pointed at each other keep answering each other's answers.
    /// Nothing may come back at all.
    #[tokio::test]
    async fn a_response_is_dropped_rather_than_resolved() {
        let (resolver, caches) = context();
        let reply = handle_query(
            message(OpCode::Query, true),
            TEST_PEER,
            current_unix_timestamp(),
            &resolver,
            &caches,
            &test_shell(),
            Transport::Udp,
        )
        .await;
        assert!(
            reply.is_none(),
            "answering a response is how a resolver becomes a packet engine"
        );
    }

    /// NOTIMP, with the opcode unchanged (RFC 1035 §4.1.1): a NOTIFY answered
    /// with `opcode = QUERY` is a reply its sender cannot match.
    #[tokio::test]
    async fn an_unimplemented_opcode_is_notimp_with_the_opcode_echoed() {
        let (resolver, caches) = context();
        for opcode in [OpCode::Notify, OpCode::Update, OpCode::Status] {
            let bytes = handle_query(
                message(opcode, false),
                TEST_PEER,
                current_unix_timestamp(),
                &resolver,
                &caches,
                &test_shell(),
                Transport::Udp,
            )
            .await
            .unwrap_or_else(|| panic!("{opcode:?} should be answered, not dropped"));
            let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");

            assert!(reply.response, "{opcode:?}");
            assert_eq!(reply.rcode, ResponseCode::NotImplemented, "{opcode:?}");
            assert_eq!(reply.opcode, opcode, "the opcode is the client's, not ours");
            assert_eq!(reply.id, 0x1234, "{opcode:?}");
            assert!(
                reply.answers.is_empty(),
                "{opcode:?}: a plausible QUERY-shaped answer is worse than a refusal"
            );
        }
    }

    /// A query for `name` with `queries` questions in it, CD as given.
    fn query_for(name: &str, questions: usize, cd: bool) -> Vec<u8> {
        let mut msg = DnsMessage::try_from_bytes(&message(OpCode::Query, false)).expect("parses");
        msg.cd = cd;
        msg.queries = vec![
            QuerySection {
                qname: nm(name),
                qtype: Qtype::of(record_types::A),
                qclass: rdns::QueryClass::IN,
            };
            questions
        ];
        let mut buf = vec![0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("serialize");
        buf.truncate(n);
        buf
    }

    /// CD comes back as the client set it: RFC 4035 §3.2.2, "The name server
    /// side MUST copy the setting of the CD bit from a query to the
    /// corresponding response". `build_response` cleared it, and two of its
    /// eight call sites set it back by hand — the other six, this one included,
    /// answered a CD client with CD off (`TODO.md` #30g).
    ///
    /// `localhost` because `special_names` answers it from the table
    /// (RFC 6761 §6.3), so the ordinary answer path runs with no upstream.
    ///
    /// Watched failing against the old builder: CD came back clear.
    #[tokio::test]
    async fn the_checking_disabled_bit_is_the_clients() {
        let (resolver, caches) = context();
        for cd in [false, true] {
            let bytes = handle_query(
                query_for("localhost.", 1, cd),
                TEST_PEER,
                current_unix_timestamp(),
                &resolver,
                &caches,
                &test_shell(),
                Transport::Udp,
            )
            .await
            .expect("localhost is answered from the table");
            let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
            assert!(!reply.answers.is_empty(), "the ordinary answer path");
            assert_eq!(reply.cd, cd, "CD is copied, not decided");
        }
    }

    /// RFC 9619 §4: a QUERY carrying more than one question "MUST be treated as
    /// an incorrectly formatted message". `rdnsd` has refused it since #9f;
    /// `rdnsr` answered the first question and echoed one, so the reply did not
    /// even match the request (`TODO.md` #30r).
    ///
    /// Watched failing without the check: NOERROR, one question, `localhost`
    /// answered.
    #[tokio::test]
    async fn two_questions_in_one_query_are_a_format_error() {
        let (resolver, caches) = context();
        let bytes = handle_query(
            query_for("localhost.", 2, false),
            TEST_PEER,
            current_unix_timestamp(),
            &resolver,
            &caches,
            &test_shell(),
            Transport::Udp,
        )
        .await
        .expect("answered, not dropped");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
        assert_eq!(reply.rcode, ResponseCode::FormatError);
        assert!(
            reply.answers.is_empty(),
            "there is no answer to two questions"
        );
    }

    /// The resolver fills the counters the periodic warnings read. It held a
    /// `QueryLogger` and only ever called `log_rate_limited` on it, so
    /// `--anomaly-query-rate` and `--anomaly-source-queries` would have watched
    /// a number that was always zero (`TODO.md` #30m).
    ///
    /// `localhost` so the answer comes from the table and no upstream is
    /// involved (RFC 6761 §6.3).
    #[tokio::test]
    async fn a_query_is_counted_against_the_source_that_sent_it() {
        let (resolver, caches) = context();
        let ctx = test_shell();
        let now = current_unix_timestamp();

        for _ in 0..3 {
            handle_query(
                query_for("localhost.", 1, false),
                TEST_PEER,
                now,
                &resolver,
                &caches,
                &ctx,
                Transport::Udp,
            )
            .await
            .expect("answered from the table");
        }
        // Not a question at all: dropped, and counted as an error rather than
        // as nothing.
        assert!(handle_query(
            vec![0x00, 0x01, 0x00],
            TEST_PEER,
            now,
            &resolver,
            &caches,
            &ctx,
            Transport::Udp,
        )
        .await
        .is_none());

        let stats = ctx.logger.take_stats(now + 60);
        assert_eq!(stats.total_queries, 3);
        assert_eq!(stats.queries_by_ip.get(&TEST_PEER), Some(&3));
        assert_eq!(stats.total_errors, 1);
        assert_eq!(
            stats.queries_by_type.get(&Qtype::of(record_types::A)),
            Some(&3)
        );
    }
}
