//! Turning a query into the bytes that answer it: the caches, the answer path
//! and the shaping every reply goes through.
//!
//! No sockets and no listener state — [`handle_query`] takes a datagram and
//! gives back the reply, which is what lets the UDP loop and the TCP handler in
//! [`crate::serve`] be two callers of one function. It is `async` because a
//! recursion is, not because anything here waits on a socket itself.

use std::net::IpAddr;
use std::sync::Arc;

use rdns::cache::StalePolicy;
use rdns::clock::Clock;
use rdns::dns64::Dns64;
use rdns::dnssec::Bogus;
use rdns::dnssec_chain::ValidationState;
use rdns::ede::InfoCode;
use rdns::error::ResolveError;
use rdns::metrics::LatencyTimer;
use rdns::negative_cache::NegativeCache;
use rdns::nsec_cache::NsecCache;
use rdns::record_types;
use rdns::resolver::{NameserverPolicy, Resolver};
use rdns::response::ClientEdns;
use rdns::rpz::{Action, DelegationPolicy, PolicyStore, PolicyZones, Rewrite};
use rdns::special_names;
use rdns::validation::{Request, Transport};
use rdns::Qtype;
use rdns::Rtype;
use rdns::{
    DnsCache, DnsMessage, Edns, ExtendedError, OpCode, QuerySection, ResourceRecord, ResponseCode,
    OPT_RECORD_TYPE,
};
use rdns_transport::ServeContext;

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
    ///
    /// `stale` reaches the first two and not `denials`: a denial is served
    /// because its signature proves it, and an expired proof proves nothing —
    /// RFC 8198 §5 rests on the validity period the signer chose, which
    /// RFC 8767 has no standing to extend.
    /// `clock` is the daemon's, the one `ServeContext` reads: one process, one
    /// idea of the time, and a test that can move it (`TODO.md` #52).
    pub(crate) fn new(
        capacity: usize,
        denial_zones: usize,
        stale: StalePolicy,
        clock: Clock,
    ) -> Caches {
        Caches {
            answers: DnsCache::with_stale(capacity, stale, clock.clone()),
            // Negative answers are answers: `--no-cache` means no cache.
            negatives: NegativeCache::with_stale(capacity, stale, clock),
            denials: NsecCache::new(denial_zones),
        }
    }

    /// Forget everything held, positive and negative.
    ///
    /// All three, because all three answer without walking a delegation, and
    /// the walk is where a nameserver trigger is asked — a synthesized
    /// NXDOMAIN (RFC 8198) skips it exactly as a cache hit does. The one
    /// caller is the policy reload (`TODO.md` #57); there is no index from a
    /// nameserver to the names it served, so the sweep is the whole cache.
    pub(crate) fn clear(&self) {
        self.answers.clear();
        self.negatives.clear();
        self.denials.clear();
    }
}

/// Everything answering a query needs, in one handle.
///
/// One `Arc` clone per datagram rather than three, and one place to add a piece
/// of state to: the UDP loop and the TCP handler are two callers of one
/// function, and each was cloning the same three fields into every task
/// (`CLAUDE.md` §7). The four encrypted listeners each built their own copy of
/// it, which is the shape `CLAUDE.md` §14 groups into a struct.
pub(crate) struct Resolving {
    pub(crate) resolver: Arc<Resolver>,
    pub(crate) caches: Caches,
    /// The response policy zones, and the files a SIGHUP re-reads them from.
    /// Empty unless `--rpz` named one, and empty costs one `is_empty` a query.
    pub(crate) policy: Arc<PolicyStore>,
    /// Whether a cache hit in the last tenth of its TTL should be re-resolved
    /// once the client's own answer is away (`--prefetch`).
    pub(crate) prefetch: bool,
    /// The NAT64 prefix to synthesize AAAA records into, if any (`--dns64`).
    pub(crate) dns64: Option<Dns64>,
    pub(crate) ctx: Arc<ServeContext>,
}

/// What answering one query produced: the reply, and any work it left behind.
///
/// The second field is the whole reason this is not `Option<Vec<u8>>`. A
/// prefetch must not delay the answer that discovered it, so it is handed back
/// to the socket loop to run *after* the reply is sent — in the same task,
/// which already holds its in-flight permit and its shutdown guard. A task
/// spawned here would hold neither, and `CLAUDE.md` §9 is about what happens to
/// the ones nobody owns.
pub(crate) struct Answered {
    /// The bytes to send back, or `None` to send nothing at all.
    pub(crate) reply: Option<Vec<u8>>,
    /// A question to re-resolve into the cache, now that the client has its
    /// answer.
    pub(crate) refresh: Option<QuerySection>,
}

impl From<Option<Vec<u8>>> for Answered {
    fn from(reply: Option<Vec<u8>>) -> Answered {
        Answered {
            reply,
            refresh: None,
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
    /// Whether an empty answer to this request may be answered with a
    /// synthesized AAAA (RFC 6147).
    ///
    /// A property of the request, decided once rather than at each of the paths
    /// that can produce an empty AAAA answer: DNS64 is configured, the question
    /// is for AAAA, and the client did not set both CD and DO — §5.5 leaves a
    /// client that said it would validate for itself to do its own synthesis.
    dns64: bool,
}

/// Resolve one datagram: cache lookup, else forward upstream and cache-store.
/// Returns the wire bytes to send back, or `None` if the query was unparseable
/// (in which case we simply drop it, as a resolver should).
pub(crate) async fn handle_query(
    data: Vec<u8>,
    peer: IpAddr,
    now: u64,
    serving: &Resolving,
    transport: Transport,
) -> Answered {
    let Resolving {
        resolver,
        caches,
        policy,
        prefetch,
        dns64: _,
        ctx,
    } = serving;
    // One snapshot for one query: a SIGHUP can install a new set part-way
    // through, and a query decided half by each is a rule nobody wrote. The
    // `Arc` also outlives the resolution that the nameserver triggers are
    // borrowed across, where a lock guard could not go (`CLAUDE.md` §9).
    let policy = policy.in_force();
    // Set by the one lookup that can discover it, returned by every path.
    let mut refresh = None;
    // Refuse a *response*: a reply parsed as a question and answered with
    // another reply is a packet loop between two servers pointed at each other.
    // `None` is the whole reply, because the peer did not ask anything. The type
    // is what makes the check unskippable — see `rdns::validation::Request`.
    let msg = match Request::from_bytes(&data) {
        Ok(msg) => msg,
        Err(_) => {
            ctx.logger.count_error(peer);
            return None.into();
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

    // The smaller of what the client said it can take and what this resolver
    // will send, which on TCP is neither (`rdns::UdpSizes::reply_ceiling`).
    // Before the opcode check, because a NOTIMP reply is bounded by it too.
    let client_max = ctx.udp.reply_ceiling(&msg, transport);

    // NOTIMP is more useful than answering a NOTIFY or an UPDATE with a
    // plausible QUERY-shaped reply the sender will misread (RFC 1035 §4.1.1).
    if msg.opcode != OpCode::Query {
        ctx.record_answer(ResponseCode::NotImplemented, timer);
        return unsupported_opcode(&msg, ctx.udp.advertised(), client_max).into();
    }

    // No question at all: nothing to answer and nothing to say about it.
    let Some(query) = msg.queries.first().cloned() else {
        return None.into();
    };
    let id = msg.id;
    let recursion = msg.recursion;

    // Before any work on the client's behalf: a malformed option list is
    // FORMERR, an unimplemented EDNS version is BADVERS (RFC 6891 §6.1.3), and
    // both replies carry a bare version-0 OPT. `rdnsd` reads the same decision
    // out of the same function (`TODO.md` #30h).
    let client_edns = match rdns::response::client_edns(&msg) {
        Ok(edns) => edns,
        Err(rcode) => {
            ctx.record_answer(rcode, timer);
            return edns_error(&msg, rcode, client_max, ctx.udp.advertised()).into();
        }
    };
    // DO means "send me the signatures", AD "tell me whether you checked"; CD
    // means "don't withhold anything on my behalf, I validate myself", which is
    // the message's own bit.
    let checking_disabled = msg.cd;
    let client = Client {
        wants_ad: client_edns.do_bit() || msg.ad,
        dns64: serving.dns64.is_some()
            && query.qtype.is(record_types::AAAA)
            && !(checking_disabled && client_edns.do_bit()),
        edns: client_edns,
        max_len: client_max,
    };

    // RFC 9619 §4: "A DNS message with OPCODE = 0 MUST NOT include a QDCOUNT
    // parameter whose value is greater than 1", and one that does "MUST be
    // treated as an incorrectly formatted message" — one RCODE and one set of
    // sections cannot describe two lookups. `rdnsd` has refused it since #9f;
    // this answered the first question and echoed one, so the reply did not
    // match the request either (`TODO.md` #30r).
    if msg.queries.len() > 1 {
        let resp = build_response(&msg, Vec::new(), ResponseCode::FormatError);
        return finish(resp, false, None, &client, &query, ctx, timer).into();
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
        return finish(resp, false, None, &client, &query, ctx, timer).into();
    }

    // The operator's policy, before every cache and before any resolution: a
    // blocked name must cost no upstream query, and an answer held from before
    // the rule was written must not outlive it.
    //
    // After `special_names` and not before, because that table is a protocol
    // requirement rather than a preference — RFC 6761 §6.3's `localhost` is the
    // loopback address whatever a feed says about it.
    if !policy.is_empty() {
        if let Some(rewrite) = policy.before_query(peer, query.qname.as_ref(), query.qtype) {
            if let Applied::Replied(reply) =
                apply_policy(&msg, rewrite, &client, &query, ctx, timer, transport)
            {
                return reply.into();
            }
        }
    }

    // RFC 6147 §5.3.1: a PTR under `ip6.arpa` for an address inside the NAT64
    // prefix is really a question about the IPv4 address embedded in it. Of the
    // two answers §5.3.1 offers, this is the second — a CNAME into
    // `in-addr.arpa` — because the first means inventing PTR data for a
    // translator this resolver knows nothing about.
    //
    // Before the caches because the question is rewritten, not answered: what is
    // cached is the `in-addr.arpa` name, under its own key.
    if query.qtype.is(record_types::PTR) {
        if let Some(target) = serving
            .dns64
            .as_ref()
            .and_then(|dns64| dns64.reverse_target(query.qname.as_ref()))
        {
            let resp = reverse_dns64(&msg, &query, target, serving).await;
            return finish(resp, false, None, &client, &query, ctx, timer).into();
        }
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
            return finish_dns64(resp, true, None, &client, &query, serving, timer)
                .await
                .into();
        }
    }

    if !checking_disabled {
        if let Some(denial) = caches.denials.synthesize(query.qname.as_ref(), query.qtype) {
            ctx.metrics.count(&ctx.metrics.cache_hits);
            let mut resp = build_response(&msg, Vec::new(), denial.rcode);
            resp.authorities = denial.authority;
            // The proofs were validated before storage, so what is derived
            // from them is authentic on the same terms.
            return finish_dns64(resp, true, None, &client, &query, serving, timer)
                .await
                .into();
        }
    }

    // A cached "no" (RFC 2308), separate from the answer cache only because
    // there are no records to key on. Nothing is synthesized — this is the
    // answer this question got — so a CD client may have it too.
    if let Some(negative) = caches.negatives.get(query.qname.as_ref(), query.qtype) {
        ctx.metrics.count(&ctx.metrics.cache_hits);
        let mut resp = build_response(&msg, Vec::new(), negative.rcode);
        resp.authorities = negative.authority;
        return finish_dns64(resp, negative.secure, None, &client, &query, serving, timer)
            .await
            .into();
    }

    // Build the response: from cache if we have it, else by resolving. The
    // third is RFC 8914's reason, which only the two failing arms have.
    let (mut resp, secure, why) = if let Some(hit) =
        caches
            .answers
            .lookup(query.qname.as_ref(), query.qtype, *prefetch)
    {
        ctx.metrics.count(&ctx.metrics.cache_hits);
        // The cache said this entry is in the last tenth of its TTL and nobody
        // has been asked to refresh it yet. Not here: the client is waiting.
        if hit.refresh {
            refresh = Some(query.clone());
        }
        let (records, secure) = (hit.records, hit.secure);
        (
            build_response(&msg, records, ResponseCode::Ok),
            secure,
            None,
        )
    } else {
        // Everything above answered from something held; from here the
        // query costs a recursion. This is the line a cache hit rate is
        // drawn on.
        ctx.metrics.count(&ctx.metrics.cache_misses);
        ctx.metrics.count(&ctx.metrics.queries_recursive);
        // The nameserver triggers, which can only be asked while the
        // delegation chain is being walked (`rdns::rpz`, `TODO.md` #56).
        // Built only when some zone has one: a feed of QNAME rules pays
        // nothing here.
        let watch = policy
            .watches_delegations()
            .then(|| policy.at_delegations(query.qname.as_ref(), query.qtype));
        // Async: each upstream round trip is an await, so this yields the
        // task rather than holding a thread.
        match resolver
            .resolve_validated(&query, watch.as_ref().map(|w| w as &dyn NameserverPolicy))
            .await
        {
            Ok((mut upstream, state)) => {
                // The resolver used its own random id; the reply must echo
                // the client's and advertise recursion.
                upstream.id = id;
                upstream.response = true;
                upstream.recursion = recursion;
                upstream.recursion_ok = true;

                if let ValidationState::Bogus(ref bogus) = state {
                    // WARN: an answer that does not validate is an attack
                    // or a broken zone, and both are worth seeing.
                    tracing::warn!(
                        qname = %query.qname,
                        qtype = %query.qtype,
                        "DNSSEC validation failed: {bogus}"
                    );
                    // Fail closed: the client cannot tell unauthenticated
                    // data from checked data, so serving it launders an
                    // attack into an ordinary reply. CD says the client
                    // checks for itself, and RFC 4035 §3.2.2 requires the
                    // data unfiltered.
                    if !checking_disabled {
                        let resp = build_response(&msg, Vec::new(), ResponseCode::ServerFailure);
                        return finish(
                            resp,
                            false,
                            Some(bogus_reason(bogus)),
                            &client,
                            &query,
                            ctx,
                            timer,
                        )
                        .into();
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
                (upstream, secure, None)
            }
            // A nameserver trigger matched, so the walk stopped and the
            // policy has the answer. Nothing was cached: the resolution
            // never finished, which is what makes the block hold for the
            // next client as well as this one.
            Err(ResolveError::PolicyStopped) => {
                match watch.as_ref().and_then(DelegationPolicy::matched) {
                    Some(rewrite) => {
                        if let Applied::Replied(reply) =
                            apply_policy(&msg, rewrite, &client, &query, ctx, timer, transport)
                        {
                            return reply.into();
                        }
                        // `Passthru` never stops the walk, and the other five
                        // actions all reply. Unreachable rather than ignorable.
                        unreachable!("a stopped resolution has a reply")
                    }
                    // The policy refused and recorded nothing, which
                    // `DelegationPolicy::allows` does only on a poisoned
                    // lock. SERVFAIL is the honest answer to "blocked, and
                    // the reason was lost".
                    None => (
                        build_response(&msg, Vec::new(), ResponseCode::ServerFailure),
                        false,
                        Some(ResolveError::PolicyStopped.extended_error()),
                    ),
                }
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
                // Only here, and only now: RFC 8767 §4 has the resolver try
                // the authoritative servers and serve what it last knew when
                // that does not work. Everything above answered from something
                // still valid, so this is the one place stale data is right.
                match stale_answer(&msg, caches, &query, ctx) {
                    Some(stale) => stale,
                    None => (
                        build_response(&msg, Vec::new(), ResponseCode::ServerFailure),
                        false,
                        Some(e.extended_error()),
                    ),
                }
            }
        }
    };

    resp.cd = checking_disabled;

    // The address in an answer is a trigger too (`rpz-ip`): a name nobody
    // blocked that resolves into blocked space. After a cache hit as well as
    // after a recursion — the cache holds what the internet said, and the
    // policy is applied to what leaves.
    if !policy.is_empty() && !resp.answers.is_empty() {
        if let Some(rewrite) = policy.on_answer(&resp.answers, query.qname.as_ref(), query.qtype) {
            if let Applied::Replied(reply) =
                apply_policy(&msg, rewrite, &client, &query, ctx, timer, transport)
            {
                return reply.into();
            }
        }
    }

    Answered {
        reply: finish_dns64(resp, secure, why, &client, &query, serving, timer).await,
        refresh,
    }
}

/// [`finish`], with RFC 6147's synthesis in front of it.
///
/// **Every path that can produce an empty AAAA answer ends here**, and the two
/// that must not synthesize end at `finish` instead: a name RFC 6761 answers
/// from the table is not an IPv4 name behind a translator, and a name a policy
/// zone blocked is blocked (`TODO.md` #45a). `CLAUDE.md` §7 is about the
/// opposite mistake — an early return jumping over a shared epilogue — so the
/// split is deliberate and the reason is written at both ends.
///
/// `client.dns64` carries everything about the request that decides this, so
/// nothing here re-derives it.
async fn finish_dns64(
    resp: DnsMessage,
    authenticated: bool,
    why: Option<ExtendedError>,
    client: &Client,
    query: &QuerySection,
    serving: &Resolving,
    timer: LatencyTimer,
) -> Option<Vec<u8>> {
    match synthesized_aaaa(&resp, client, query, serving).await {
        // Never authenticated: these records are this resolver's invention, so
        // AD stays clear whatever the AAAA denial validated as. No Extended DNS
        // Error either — RFC 8914 has no code for a DNS64 answer, and 4
        // (Forged Answer) says "for policy reasons", which this is not.
        Some(synthesized) => finish(synthesized, false, None, client, query, &serving.ctx, timer),
        None => finish(resp, authenticated, why, client, query, &serving.ctx, timer),
    }
}

/// The CNAME into `in-addr.arpa` that answers a reverse query for a synthesized
/// address, and the PTR it leads to (RFC 6147 §5.3.1).
///
/// The CNAME goes out whether or not the PTR resolves: it is true — that
/// `ip6.arpa` name *is* this `in-addr.arpa` name — and a client that follows it
/// itself gets the same answer.
async fn reverse_dns64(
    request: &DnsMessage,
    query: &QuerySection,
    target: rdns::Name,
    serving: &Resolving,
) -> DnsMessage {
    let cname = ResourceRecord {
        name: query.qname.clone(),
        class: rdns::Class::new(1),
        ttl: rdns::Ttl::from_secs(REVERSE_CNAME_TTL),
        rdata: match rdns::RecordData::from_parsed(&rdns::ParsedRecord::CNAME(target.clone())) {
            Ok(rdata) => rdata,
            Err(_) => return build_response(request, Vec::new(), ResponseCode::ServerFailure),
        },
    };
    let ptr = QuerySection {
        qname: target,
        qtype: Qtype::of(record_types::PTR),
        qclass: query.qclass,
    };
    let mut answers = vec![cname];
    if let Some(found) = cached_or_resolve(serving, &ptr).await {
        answers.extend(found);
    }
    build_response(request, answers, ResponseCode::Ok)
}

/// How long the `ip6.arpa` → `in-addr.arpa` CNAME is good for.
///
/// It is derived from the configured prefix rather than from any zone, so there
/// is no authority to take a TTL from; an hour is short enough that changing the
/// prefix takes effect within a shift.
const REVERSE_CNAME_TTL: u32 = 3600;

/// An answer built from the name's A records, for a AAAA question that came
/// back with nothing usable (RFC 6147 §5.1.7).
///
/// `None` — meaning "answer what you have" — for every reason there is not to
/// synthesize: the request is not eligible, the answer already carries a usable
/// AAAA (§5.1.1), the name does not exist (§5.1.2 passes NXDOMAIN through), or
/// the A query found nothing either.
async fn synthesized_aaaa(
    resp: &DnsMessage,
    client: &Client,
    query: &QuerySection,
    serving: &Resolving,
) -> Option<DnsMessage> {
    let dns64 = serving.dns64.as_ref()?;
    if !client.dns64 || resp.rcode == ResponseCode::NoSuchDomain || dns64.answered(&resp.answers) {
        return None;
    }

    // §5.1.7's ceiling: the name has no AAAA, so the SOA that says so bounds
    // how long the invention may live.
    let ttl_cap = resp
        .authorities
        .iter()
        .find(|rr| rr.rdata.rtype() == record_types::SOA)
        .map(|soa| soa.ttl);

    let a = QuerySection {
        qname: query.qname.clone(),
        qtype: Qtype::of(record_types::A),
        qclass: query.qclass,
    };
    let synthesized = dns64.synthesize(&cached_or_resolve(serving, &a).await?, ttl_cap);
    if synthesized.is_empty() {
        return None;
    }
    serving.ctx.metrics.count(&serving.ctx.metrics.synthesized);

    let mut out = resp.clone();
    out.rcode = ResponseCode::Ok;
    out.answers = synthesized;
    // The SOA said there was no AAAA and now there is one; §5.4 assembles the
    // reply from the question and the synthesized answer section alone.
    out.authorities.clear();
    out.additionals.clear();
    Some(out)
}

/// Resolve a question and store what comes back, for the callers that ask on
/// nobody's behalf: a prefetch, and DNS64's A query.
///
/// The answer section, or `None` for a failure or a bogus answer. Not the main
/// answer path's storing, which also has a client to fail closed for, a CD bit
/// to honour and denial proofs to keep; what is shared is what these two need
/// and it is this much (`CLAUDE.md` §7).
async fn resolve_and_store(
    serving: &Resolving,
    query: &QuerySection,
) -> Option<Vec<ResourceRecord>> {
    // Policed like a client's query: an answer a nameserver trigger blocks
    // must not reach the cache by the back door of a prefetch.
    let policy = serving.policy.in_force();
    let watch = policy
        .watches_delegations()
        .then(|| policy.at_delegations(query.qname.as_ref(), query.qtype));
    let Ok((answer, state)) = serving
        .resolver
        .resolve_validated(query, watch.as_ref().map(|w| w as &dyn NameserverPolicy))
        .await
    else {
        return None;
    };
    if state.is_bogus() {
        return None;
    }
    let secure = state.is_secure();
    if !answer.answers.is_empty() {
        serving.caches.answers.put_validated(
            query.qname.as_ref(),
            query.qtype,
            answer.answers.clone(),
            secure,
        );
    }
    // A "no" is an answer, and a name that has gone is exactly what a prefetch
    // should notice before a client does.
    serving
        .caches
        .negatives
        .insert(query.qname.as_ref(), query.qtype, &answer, secure);
    Some(answer.answers)
}

/// [`resolve_and_store`] with the cache tried first — the shape a caller that
/// wants an answer rather than a fresh one needs.
///
/// A cached negative counts: an A query that found nothing is a name with no
/// address of either family, and asking the internet again on every AAAA query
/// for it is how a DNS64 resolver doubles its own traffic.
async fn cached_or_resolve(
    serving: &Resolving,
    query: &QuerySection,
) -> Option<Vec<ResourceRecord>> {
    if let Some(hit) = serving
        .caches
        .answers
        .lookup(query.qname.as_ref(), query.qtype, false)
    {
        return Some(hit.records);
    }
    if serving
        .caches
        .negatives
        .get(query.qname.as_ref(), query.qtype)
        .is_some()
    {
        return None;
    }
    resolve_and_store(serving, query).await
}

/// Re-resolve a name into the cache, after the client that asked for it has its
/// answer (Unbound's `prefetch`).
///
/// Called by the socket loop rather than by [`handle_query`], in the task that
/// has already sent the reply: nothing is waiting on this, and the in-flight
/// permit that task holds is what bounds how many may run at once.
///
/// The result goes through the same storing as an ordinary resolution, because
/// it *is* one — the only difference is that nobody is listening. A failure is
/// left to the entry's own expiry: the name is still in the cache with a tenth
/// of its TTL left, so the next client either finds it or resolves it.
pub(crate) async fn refresh(serving: &Resolving, query: QuerySection) {
    let ctx = &serving.ctx;
    ctx.metrics.count(&ctx.metrics.prefetches);
    if resolve_and_store(serving, &query).await.is_none() {
        // DEBUG: nobody is waiting, and a failure here costs the next client a
        // resolution it would have paid for anyway.
        tracing::debug!(qname = %query.qname, qtype = %query.qtype, "prefetch failed");
    }
}

/// The last thing this resolver knew about `query`, for a resolution that has
/// just failed (RFC 8767).
///
/// Returns what the answer path's own arms return — the response, whether it is
/// authenticated, and the reason to put in the OPT — so the caller has nothing
/// to assemble. `None` when serve-stale is off or nothing usable is held, which
/// is SERVFAIL as before.
///
/// AD survives: `secure` is what validation concluded when the answer was
/// stored, and an expired signature is a validity period rather than a
/// verdict. RFC 8767 §6 notes that a validating stub may reject the answer for
/// exactly that reason, which is its right and not ours to pre-empt.
fn stale_answer(
    request: &DnsMessage,
    caches: &Caches,
    query: &QuerySection,
    ctx: &ServeContext,
) -> Option<(DnsMessage, bool, Option<ExtendedError>)> {
    const WHY_POSITIVE: ExtendedError = ExtendedError::new(
        InfoCode::STALE_ANSWER,
        "the authoritative servers could not be reached",
    );
    const WHY_NEGATIVE: ExtendedError = ExtendedError::new(
        InfoCode::STALE_NXDOMAIN,
        "the authoritative servers could not be reached",
    );

    // A "yes" before a "no": both may be held for one name, and the answer is
    // the more specific thing known about it.
    if let Some((records, secure)) = caches.answers.get_stale(query.qname.as_ref(), query.qtype) {
        ctx.metrics.count(&ctx.metrics.stale_answers);
        // INFO: serving data known to be out of date is a decision the operator
        // turned on, and the line beside the counter is how the decision is
        // seen taking effect.
        tracing::info!(qname = %query.qname, qtype = %query.qtype, "answered from expired cache");
        return Some((
            build_response(request, records, ResponseCode::Ok),
            secure,
            Some(WHY_POSITIVE),
        ));
    }

    let negative = caches
        .negatives
        .get_stale(query.qname.as_ref(), query.qtype)?;
    ctx.metrics.count(&ctx.metrics.stale_answers);
    tracing::info!(qname = %query.qname, qtype = %query.qtype, "answered from expired cache");
    let mut resp = build_response(request, Vec::new(), negative.rcode);
    resp.authorities = negative.authority;
    let why = if negative.rcode == ResponseCode::NoSuchDomain {
        WHY_NEGATIVE
    } else {
        WHY_POSITIVE
    };
    Some((resp, negative.secure, Some(why)))
}

/// What each policy zone holds, by trigger kind.
///
/// Printed at startup and again after every reload, for the reason the rate
/// limiter's policy is: a rewrite is invisible on the wire, so the feed that
/// loaded and the feed the operator meant to load are otherwise the same
/// picture (`CLAUDE.md` §4, §14, `TODO.md` #45a, #56).
pub(crate) fn log_policy(zones: &PolicyZones) {
    for zone in zones.zones() {
        let [qname, client_ip, response_ip, nsdname, nsip] = zone.trigger_counts();
        tracing::info!(
            "policy zone {} ({}): {} records, {qname} qname, {client_ip} client-ip,              {response_ip} response-ip, {nsdname} nsdname, {nsip} nsip",
            zone.origin().to_presentation(),
            zone.policy(),
            zone.records(),
        );
    }
}

/// Re-read every `--rpz` file, and tell the caches what arrived.
///
/// A feed is rewritten under a running resolver — by a cron job, or by an
/// `rdnsd` writing what it transferred — and until this the answer was a
/// restart (`TODO.md` #57).
pub(crate) fn reload_policy(serving: &Resolving) {
    if !serving.policy.is_configured() {
        return;
    }
    match serving.policy.reload() {
        Ok(reloaded) => {
            tracing::info!("policy zones re-read (SIGHUP)");
            log_policy(&reloaded.zones);
            // The one thing a new rule cannot reach on its own. A QNAME or
            // client-IP rule is consulted before every cache and a response-IP
            // rule is applied to what leaves, so both bind the next query
            // whatever is held; a nameserver rule is only asked while a
            // delegation is walked, which a cache hit never does. Conditional,
            // because a reload that emptied the cache every hour would be its
            // own outage.
            if reloaded.delegation_rules_changed {
                serving.caches.clear();
                tracing::info!(
                    "the caches were cleared: a nameserver trigger changed, and nothing held \
                     was offered to it"
                );
            }
        }
        // The previous set is still in force, which is the whole point of
        // saying so: a half-written feed must not lift a block.
        Err(e) => tracing::warn!(
            "could not re-read the policy zones (SIGHUP); the previous ones are still in \
             force: {e}"
        ),
    }
}

/// What a policy match did, since one of the six actions is to do nothing.
enum Applied {
    /// The bytes to send back, or `None` for `rpz-drop`: no reply at all.
    Replied(Option<Vec<u8>>),
    /// Matched and deliberately unchanged — `rpz-passthru`, or `rpz-tcp-only`
    /// on a connection that is already TCP.
    Unchanged,
}

/// Turn a policy match into the reply it calls for (`rdns::rpz`).
///
/// Never authenticated: this answer was decided here, so AD stays clear and a
/// validating client will find the signatures missing — which is the honest
/// outcome and the reason the rewrite is announced with an Extended DNS Error
/// (RFC 8914 §4.16) rather than only in a log nobody downstream reads.
fn apply_policy(
    request: &DnsMessage,
    rewrite: Rewrite,
    client: &Client,
    query: &QuerySection,
    ctx: &ServeContext,
    timer: LatencyTimer,
    transport: Transport,
) -> Applied {
    // RFC 8914 §4.5 draws the line: Forged Answer (4) "should be used when an
    // answer is still provided, not when failure codes are returned instead.
    // See Blocked (15), Censored (16), and Filtered (17) for use when returning
    // other response codes."
    const WHY_DENIED: ExtendedError = ExtendedError::new(
        InfoCode::BLOCKED,
        "this answer is the resolver operator's policy",
    );
    const WHY_FORGED: ExtendedError = ExtendedError::new(
        InfoCode::FORGED_ANSWER,
        "this answer is the resolver operator's policy",
    );
    // INFO, not DEBUG: a name that does not resolve is a support call, and this
    // line is the answer to it. One per rewrite, which is bounded by how much
    // of the traffic the policy covers rather than by the traffic.
    tracing::info!(
        qname = %query.qname,
        qtype = %query.qtype,
        zone = %rewrite.zone,
        trigger = %rewrite.trigger,
        "policy applied"
    );
    let soa = rewrite.soa.into_iter().collect::<Vec<_>>();
    let (answers, rcode) = match rewrite.action {
        // Nothing leaves. Counted, because a query that arrives and produces
        // no answer is otherwise indistinguishable from a lost packet.
        Action::Drop => {
            ctx.metrics.count(&ctx.metrics.policy_drops);
            return Applied::Replied(None);
        }
        Action::Passthru => return Applied::Unchanged,
        // TC=1 sends the client to TCP, where the handshake proves the source;
        // over TCP it has already done that, so there is nothing to ask for.
        Action::TcpOnly => {
            if transport != Transport::Udp {
                return Applied::Unchanged;
            }
            ctx.metrics.count(&ctx.metrics.policy_rewrites);
            let mut resp = build_response(request, Vec::new(), ResponseCode::Ok);
            resp.truncation = true;
            ctx.record_answer(resp.rcode, timer);
            return Applied::Replied(resp.to_bytes_within(client.max_len).ok());
        }
        Action::Nxdomain => (Vec::new(), ResponseCode::NoSuchDomain),
        Action::Nodata => (Vec::new(), ResponseCode::Ok),
        Action::LocalData(records) => (records, ResponseCode::Ok),
    };
    let why = if answers.is_empty() {
        WHY_DENIED
    } else {
        WHY_FORGED
    };
    ctx.metrics.count(&ctx.metrics.policy_rewrites);
    let mut resp = build_response(request, answers, rcode);
    // The policy zone's own SOA, so a negative answer can be cached at all
    // (RFC 2308 §5). Its MINIMUM and its TTL are the two numbers the client
    // needs; which of them wins is §3's rule and the client's to apply.
    if resp.answers.is_empty() {
        resp.authorities = soa;
    }
    Applied::Replied(finish(resp, false, Some(why), client, query, ctx, timer))
}

/// What the client is told about a validation failure: the INFO-CODE the check
/// that failed chose, and one fixed sentence.
///
/// Fixed because [`Bogus::why`] names the zone, the owner and the key tag, and
/// all three came out of an answer a stranger sent — RFC 8914 §2 asks that
/// EXTRA-TEXT leak nothing, and reflecting a remote party's names back to
/// another remote party is the way to do so without noticing. The detail is in
/// the WARN line beside the counter, where the operator reads it.
fn bogus_reason(bogus: &Bogus) -> ExtendedError {
    ExtendedError::new(bogus.code, "this answer did not validate")
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
    why: Option<ExtendedError>,
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
    //
    // `why` rides in that OPT and nowhere else (RFC 8914 §2), which is why it
    // is `mirror_with`'s business rather than a check here — and so is what
    // happens to a reason too long to encode.
    if let Some(edns) = client.edns.mirror_with(ctx.udp.advertised(), why) {
        resp.set_edns(edns);
    } else {
        resp.additionals
            .retain(|rr| rr.rdata.rtype() != OPT_RECORD_TYPE);
    }

    // Honour the ceiling `handle_query` read once: truncates (TC=1) if it
    // overflows.
    resp.to_bytes_within(client.max_len).ok()
}

/// An empty error response carrying a version-0 OPT record, for the EDNS-level
/// rejections (FORMERR / BADVERS) that must be signalled before resolving.
fn edns_error(
    request: &DnsMessage,
    rcode: ResponseCode,
    client_max: usize,
    advertised: u16,
) -> Option<Vec<u8>> {
    let mut resp = build_response(request, Vec::new(), rcode);
    // BADVERS is an extended RCODE, so the OPT record isn't optional here — it
    // carries the code's high bits.
    resp.set_edns(Edns::with_payload_size(advertised));
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
fn unsupported_opcode(msg: &DnsMessage, advertised: u16, max_len: usize) -> Option<Vec<u8>> {
    const WHY: ExtendedError =
        ExtendedError::new(InfoCode::NOT_SUPPORTED, "this opcode is not implemented");
    let mut resp = build_response(msg, Vec::new(), ResponseCode::NotImplemented);
    if let Some(edns) = ClientEdns::of(msg).mirror_with(advertised, Some(WHY)) {
        resp.set_edns(edns);
    }
    resp.to_bytes_within(max_len).ok()
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
    use rdns::rpz::PolicyOverride;
    use rdns::Qtype;

    use rdns::clock::Clock;

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
                    dns64: false,
                };
                let resp = build_response(&msg, Vec::new(), ResponseCode::Ok);
                let bytes = finish(
                    resp,
                    authenticated,
                    None,
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

        let udp = rdns::UdpSizes::default();
        let bytes = unsupported_opcode(
            &request,
            udp.advertised(),
            udp.reply_ceiling(&request, Transport::Udp),
        )
        .expect("a NOTIMP reply");
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
        let serving = context();
        let reply = handle_query(
            message(OpCode::Query, true),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply;
        assert!(
            reply.is_none(),
            "answering a response is how a resolver becomes a packet engine"
        );
    }

    /// NOTIMP, with the opcode unchanged (RFC 1035 §4.1.1): a NOTIFY answered
    /// with `opcode = QUERY` is a reply its sender cannot match.
    #[tokio::test]
    async fn an_unimplemented_opcode_is_notimp_with_the_opcode_echoed() {
        let serving = context();
        for opcode in [OpCode::Notify, OpCode::Update, OpCode::Status] {
            let bytes = handle_query(
                message(opcode, false),
                TEST_PEER,
                current_unix_timestamp(),
                &serving,
                Transport::Udp,
            )
            .await
            .reply
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

    /// The NOTIMP above, to a client that sent an OPT for the reason to ride
    /// in (RFC 8914 §2). Same code `rdnsd` uses for the same refusal, because
    /// it is the same sentence: §4.22, "the requested operation or query is not
    /// supported".
    #[tokio::test]
    async fn an_unimplemented_opcode_says_why_when_the_client_used_edns() {
        let serving = context();
        let mut msg = DnsMessage::try_from_bytes(&message(OpCode::Update, false)).expect("parses");
        msg.set_edns(Edns::with_payload_size(4096));

        let bytes = handle_query(
            msg.to_bytes_within(4096).expect("serialize"),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("an UPDATE is answered, not dropped");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");

        assert_eq!(reply.rcode, ResponseCode::NotImplemented);
        let edns = reply.edns.as_ref().expect("the OPT is mirrored");
        let errors = ExtendedError::all_in(edns).expect("a well-formed option list");
        assert_eq!(
            errors.iter().map(|(code, _)| *code).collect::<Vec<_>>(),
            vec![InfoCode::NOT_SUPPORTED]
        );
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

    /// A handle with a serve-stale window and a clock the test moves: a TTL is
    /// whole seconds, so every other way of reaching expiry is a sleep
    /// (`TODO.md` #52).
    fn serving_stale(seconds: u64) -> (Arc<Resolving>, Clock) {
        timed(StalePolicy::seconds(seconds), false)
    }

    fn timed(stale: StalePolicy, prefetch: bool) -> (Arc<Resolving>, Clock) {
        let clock = Clock::fixed(1_000_000_000);
        let ctx = Arc::new(ServeContext {
            clock: clock.clone(),
            ..(*test_shell()).clone()
        });
        let caches = Caches::new(16, 4, stale, clock.clone());
        (
            Arc::new(Resolving {
                resolver: test_resolver(),
                caches,
                policy: PolicyStore::in_memory(PolicyZones::default()),
                prefetch,
                dns64: None,
                ctx,
            }),
            clock,
        )
    }

    fn a_record(name: &rdns::Name, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.clone(),
            class: rdns::Class::new(1),
            ttl: rdns::Ttl::from_secs(ttl),
            rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(std::net::Ipv4Addr::new(
                192, 0, 2, 10,
            )))
            .expect("encodes"),
        }
    }

    /// RFC 8767, the whole point: the authoritative servers cannot be reached —
    /// the fixture forwards to a port nothing listens on — so the last thing
    /// known goes out instead of SERVFAIL, with the 30-second TTL §4 asks for
    /// and RFC 8914 §4.4's code saying what happened.
    ///
    /// Watched failing with `--serve-stale` off: SERVFAIL, no answers.
    #[tokio::test]
    async fn an_expired_answer_is_served_when_the_resolution_fails() {
        let (serving, clock) = serving_stale(3600);
        let name = nm("example.com.");
        serving.caches.answers.put(
            name.as_ref(),
            Qtype::of(record_types::A),
            vec![a_record(&name, 300)],
        );
        clock.advance(301);

        let query = rdns::DnsMessageBuilder::new()
            .with_id(9)
            .with_query(name.clone(), Qtype::of(record_types::A))
            .with_recursion(true)
            .with_edns(1232, false)
            .build()
            .to_bytes_within(4096)
            .expect("serialize");
        let bytes = handle_query(
            query,
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");

        assert_eq!(reply.rcode, ResponseCode::Ok);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].ttl.as_secs(), 30, "RFC 8767 §4");
        let edns = reply.edns.as_ref().expect("the OPT is mirrored");
        let errors = ExtendedError::all_in(edns).expect("a well-formed option list");
        assert_eq!(
            errors.iter().map(|(code, _)| *code).collect::<Vec<_>>(),
            vec![InfoCode::STALE_ANSWER]
        );
        assert_eq!(
            serving
                .ctx
                .metrics
                .stale_answers
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// Off is the default, and off means the answer is the failure.
    #[tokio::test]
    async fn without_the_flag_a_failed_resolution_is_servfail() {
        let (serving, clock) = timed(StalePolicy::OFF, false);
        let name = nm("example.com.");
        serving.caches.answers.put(
            name.as_ref(),
            Qtype::of(record_types::A),
            vec![a_record(&name, 300)],
        );
        clock.advance(301);
        let bytes = handle_query(
            query_for("example.com.", 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
        assert_eq!(reply.rcode, ResponseCode::ServerFailure);
        assert!(reply.answers.is_empty());
    }

    /// A fresh entry is answered from the cache and never reaches the stale
    /// path: RFC 8767 §4 has the resolver try the authoritative servers first,
    /// so an answer that is still an answer must not be counted as stale.
    #[tokio::test]
    async fn a_live_entry_is_not_a_stale_answer() {
        let (serving, _clock) = serving_stale(3600);
        let name = nm("example.com.");
        serving.caches.answers.put(
            name.as_ref(),
            Qtype::of(record_types::A),
            vec![a_record(&name, 300)],
        );
        let bytes = handle_query(
            query_for("example.com.", 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
        assert_eq!(reply.answers[0].ttl.as_secs(), 300, "its own TTL, not 30");
        assert_eq!(
            serving
                .ctx
                .metrics
                .stale_answers
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// The answer path's half of prefetching: a cache hit in its last tenth
    /// comes back with the question to re-resolve, and the socket loop runs it
    /// after the reply. Nothing here waits for it.
    ///
    /// Watched failing with `prefetch: false`: `refresh` was `None`.
    #[tokio::test]
    async fn a_nearly_expired_cache_hit_asks_for_a_refresh() {
        let (serving, clock) = timed(StalePolicy::OFF, true);
        let name = nm("hot.example.com.");
        serving.caches.answers.put(
            name.as_ref(),
            Qtype::of(record_types::A),
            vec![a_record(&name, 100)],
        );
        // Into the last tenth of the TTL, which is where a prefetch is due.
        clock.advance(95);

        let answered = handle_query(
            query_for("hot.example.com.", 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await;
        let reply = DnsMessage::try_from_bytes(&answered.reply.expect("answered from the cache"))
            .expect("a well-formed reply");
        assert_eq!(reply.answers.len(), 1, "the client is answered first");
        let query = answered.refresh.expect("and the name is due a refresh");
        assert_eq!(query.qname, name);

        // The refresh itself: the upstream is unreachable, so this is about it
        // being counted and returning rather than about what it learns.
        refresh(&serving, query).await;
        assert_eq!(
            serving
                .ctx
                .metrics
                .prefetches
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// Without the switch there is nothing to run, whatever the TTL says.
    #[tokio::test]
    async fn without_the_switch_no_refresh_is_asked_for() {
        let (serving, clock) = timed(StalePolicy::OFF, false);
        let name = nm("hot.example.com.");
        serving.caches.answers.put(
            name.as_ref(),
            Qtype::of(record_types::A),
            vec![a_record(&name, 100)],
        );
        clock.advance(95);
        let answered = handle_query(
            query_for("hot.example.com.", 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await;
        assert!(answered.reply.is_some());
        assert!(answered.refresh.is_none());
    }

    fn with_dns64() -> Arc<Resolving> {
        Arc::new(Resolving {
            resolver: test_resolver(),
            caches: Caches::new(16, 4, StalePolicy::OFF, rdns::clock::Clock::system()),
            policy: PolicyStore::in_memory(PolicyZones::default()),
            prefetch: false,
            dns64: Some(
                rdns::dns64::Dns64::new(rdns::dns64::Nat64Prefix::well_known(), &[])
                    .expect("the Well-Known Prefix"),
            ),
            ctx: test_shell(),
        })
    }

    fn soa(zone: &str) -> ResourceRecord {
        ResourceRecord {
            name: nm(zone),
            class: rdns::Class::new(1),
            ttl: rdns::Ttl::from_secs(60),
            rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::SOA {
                mname: nm("ns.example.com."),
                rname: nm("hostmaster.example.com."),
                serial: rdns::Serial::new(1),
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum: 60,
            })
            .expect("encodes"),
        }
    }

    /// The cached "no" for AAAA that every DNS64 test starts from, plus the A
    /// record synthesis reads.
    fn nodata_aaaa_with_an_a(serving: &Resolving, name: &rdns::Name) {
        let mut denial = DnsMessage::try_from_bytes(&message(OpCode::Query, true)).expect("parses");
        denial.rcode = ResponseCode::Ok;
        denial.answers.clear();
        denial.authorities = vec![soa("example.com.")];
        serving.caches.negatives.insert(
            name.as_ref(),
            Qtype::of(record_types::AAAA),
            &denial,
            false,
        );
        serving.caches.answers.put(
            name.as_ref(),
            Qtype::of(record_types::A),
            vec![ResourceRecord {
                name: name.clone(),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(300),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                    "192.0.2.33".parse().unwrap(),
                ))
                .expect("encodes"),
            }],
        );
    }

    async fn aaaa_reply(serving: &Resolving, name: &str, cd: bool, do_bit: bool) -> DnsMessage {
        let query = rdns::DnsMessageBuilder::new()
            .with_id(5)
            .with_query(nm(name), Qtype::of(record_types::AAAA))
            .with_recursion(true)
            .with_edns(1232, do_bit)
            .build();
        let mut query = query;
        query.cd = cd;
        let bytes = handle_query(
            query.to_bytes_within(4096).expect("serialize"),
            TEST_PEER,
            current_unix_timestamp(),
            serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered");
        DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply")
    }

    /// RFC 6147 §5.1.7 end to end: a name with an A and no AAAA answers with an
    /// address inside the NAT64 prefix, built from RFC 6052 §2.4's own example
    /// pair — 192.0.2.33 under 64:ff9b::/96.
    ///
    /// From the *negative* cache, which is one of the four paths that can
    /// produce an empty AAAA answer: synthesis that only covers a fresh
    /// resolution answers the first client and not the second.
    #[tokio::test]
    async fn a_name_with_no_aaaa_is_answered_from_its_a() {
        let serving = with_dns64();
        let name = nm("v4only.example.com.");
        nodata_aaaa_with_an_a(&serving, &name);

        let reply = aaaa_reply(&serving, "v4only.example.com.", false, false).await;
        assert_eq!(reply.rcode, ResponseCode::Ok);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(
            reply.answers[0].rdata.parse().unwrap(),
            rdns::ParsedRecord::AAAA("64:ff9b::192.0.2.33".parse().unwrap())
        );
        assert_eq!(
            reply.answers[0].ttl.as_secs(),
            60,
            "§5.1.7 caps it at the SOA's TTL"
        );
        assert!(
            reply.authorities.is_empty(),
            "§5.4: the SOA said there was no AAAA and now there is one"
        );
        assert!(!reply.ad, "an invented address is not authentic");
        assert_eq!(
            serving
                .ctx
                .metrics
                .synthesized
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// RFC 6147 §5.5: a client that set both CD and DO said it validates for
    /// itself, so it gets the denial and can synthesize on its own.
    #[tokio::test]
    async fn a_client_that_validates_for_itself_is_not_synthesized_for() {
        let serving = with_dns64();
        let name = nm("v4only.example.com.");
        nodata_aaaa_with_an_a(&serving, &name);

        let reply = aaaa_reply(&serving, "v4only.example.com.", true, true).await;
        assert!(reply.answers.is_empty(), "the empty answer, unchanged");
        assert_eq!(reply.authorities.len(), 1, "and the SOA that says so");
    }

    /// DO alone is not that statement — a stub that asks for signatures is not
    /// a stub that validates — so §5.5's exemption needs CD as well.
    #[tokio::test]
    async fn the_do_bit_alone_does_not_suppress_synthesis() {
        let serving = with_dns64();
        let name = nm("v4only.example.com.");
        nodata_aaaa_with_an_a(&serving, &name);

        let reply = aaaa_reply(&serving, "v4only.example.com.", false, true).await;
        assert_eq!(reply.answers.len(), 1);
    }

    /// §5.1.4: an answer of nothing but IPv4-mapped addresses is an empty
    /// answer, and the client gets something it can route instead.
    #[tokio::test]
    async fn an_answer_of_only_mapped_addresses_is_synthesized_over() {
        let serving = with_dns64();
        let name = nm("mapped.example.com.");
        serving.caches.answers.put(
            name.as_ref(),
            Qtype::of(record_types::AAAA),
            vec![ResourceRecord {
                name: name.clone(),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(300),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::AAAA(
                    "::ffff:192.0.2.33".parse().unwrap(),
                ))
                .expect("encodes"),
            }],
        );
        serving.caches.answers.put(
            name.as_ref(),
            Qtype::of(record_types::A),
            vec![ResourceRecord {
                name: name.clone(),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(300),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                    "192.0.2.33".parse().unwrap(),
                ))
                .expect("encodes"),
            }],
        );

        let reply = aaaa_reply(&serving, "mapped.example.com.", false, false).await;
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(
            reply.answers[0].rdata.parse().unwrap(),
            rdns::ParsedRecord::AAAA("64:ff9b::192.0.2.33".parse().unwrap())
        );
    }

    /// A real AAAA is passed through untouched (§5.1.1).
    #[tokio::test]
    async fn a_name_that_has_an_aaaa_is_left_alone() {
        let serving = with_dns64();
        let name = nm("dual.example.com.");
        serving.caches.answers.put(
            name.as_ref(),
            Qtype::of(record_types::AAAA),
            vec![ResourceRecord {
                name: name.clone(),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(300),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::AAAA(
                    "2001:db8::1".parse().unwrap(),
                ))
                .expect("encodes"),
            }],
        );
        let reply = aaaa_reply(&serving, "dual.example.com.", false, false).await;
        assert_eq!(
            reply.answers[0].rdata.parse().unwrap(),
            rdns::ParsedRecord::AAAA("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            serving
                .ctx
                .metrics
                .synthesized
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// §5.1.2: a name that does not exist has no A to build from either, so
    /// NXDOMAIN passes through rather than becoming a NOERROR with an address
    /// in it.
    #[tokio::test]
    async fn nxdomain_is_not_synthesized_over() {
        let serving = with_dns64();
        let name = nm("gone.example.com.");
        let mut denial = DnsMessage::try_from_bytes(&message(OpCode::Query, true)).expect("parses");
        denial.rcode = ResponseCode::NoSuchDomain;
        denial.answers.clear();
        denial.authorities = vec![soa("example.com.")];
        serving.caches.negatives.insert(
            name.as_ref(),
            Qtype::of(record_types::AAAA),
            &denial,
            false,
        );

        let reply = aaaa_reply(&serving, "gone.example.com.", false, false).await;
        assert_eq!(reply.rcode, ResponseCode::NoSuchDomain);
        assert!(reply.answers.is_empty());
    }

    /// RFC 6147 §5.3.1: a reverse query for an address this resolver invented
    /// is a question about the IPv4 address inside it, answered with the CNAME
    /// §5.3.1's second alternative describes.
    #[tokio::test]
    async fn a_reverse_query_for_a_synthesized_address_is_a_cname() {
        let serving = with_dns64();
        // 64:ff9b::192.0.2.33 = 0064:ff9b:0:0:0:0:c000:0221, one nibble per
        // label, least significant first (RFC 3596 §2.5).
        let nibbles: String = "0064ff9b0000000000000000c0000221"
            .chars()
            .rev()
            .map(|c| format!("{c}."))
            .collect();
        let bytes = handle_query(
            query_for(&format!("{nibbles}ip6.arpa."), 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
        // `query_for` asks for A; the PTR rewrite is about the name, so ask
        // again with the right type through the same path.
        assert_eq!(
            reply.rcode,
            ResponseCode::ServerFailure,
            "an A query is not a PTR query"
        );

        let ptr = rdns::DnsMessageBuilder::new()
            .with_id(6)
            .with_query(
                nm(&format!("{nibbles}ip6.arpa.")),
                Qtype::of(record_types::PTR),
            )
            .with_recursion(true)
            .build()
            .to_bytes_within(4096)
            .expect("serialize");
        let bytes = handle_query(
            ptr,
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
        assert_eq!(reply.rcode, ResponseCode::Ok);
        assert_eq!(reply.answers.len(), 1, "the CNAME, with no PTR behind it");
        assert_eq!(
            reply.answers[0].rdata.parse().unwrap(),
            rdns::ParsedRecord::CNAME(nm("33.2.0.192.in-addr.arpa."))
        );
    }

    /// The whole of #56 end to end: a name nothing in the feed mentions,
    /// delegated to a nameserver the feed does mention, comes back NXDOMAIN.
    ///
    /// The fake root refers and nothing else answers, so the `192.0.2.13` glue
    /// is never reachable — which is also the proof the walk stopped rather
    /// than resolved: an unblocked run of this fixture is a SERVFAIL, as
    /// `passthru_resolves_the_query_as_if_no_rule_matched` shows.
    #[tokio::test]
    async fn a_nameserver_trigger_blocks_a_name_the_feed_never_names() {
        let root = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind a fake root");
        let root_addr = root.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = root.recv_from(&mut buf).await {
                let Ok(query) = DnsMessage::try_from_bytes(&buf[..n]) else {
                    continue;
                };
                let mut resp = DnsMessage::try_from_bytes(&buf[..n]).expect("parses twice");
                resp.response = true;
                resp.queries = query.queries.clone();
                resp.authorities = vec![ResourceRecord {
                    name: nm("example.test."),
                    class: rdns::Class::new(1),
                    ttl: rdns::Ttl::from_secs(3600),
                    rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::NS(nm(
                        "ns.evil.example.com.",
                    )))
                    .expect("encodes"),
                }];
                resp.additionals = vec![ResourceRecord {
                    name: nm("ns.evil.example.com."),
                    class: rdns::Class::new(1),
                    ttl: rdns::Ttl::from_secs(3600),
                    rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                        std::net::Ipv4Addr::new(192, 0, 2, 13),
                    ))
                    .expect("encodes"),
                }];
                let mut out = vec![0u8; 1500];
                if let Ok(len) = resp.to_bytes(&mut out) {
                    let _ = root.send_to(&out[..len], peer).await;
                }
            }
        });

        let resolver = Arc::new(Resolver::new(rdns::resolver::ResolverConfig {
            mode: rdns::resolver::ResolverMode::Recurse,
            root_hints: vec![root_addr],
            server_port: root_addr.port(),
            timeout_ms: 2000,
            ..Default::default()
        }));
        let serving = serving(
            resolver,
            test_shell(),
            policy("ns.evil.example.com.rpz-nsdname IN CNAME .\n"),
        );

        let bytes = handle_query(
            query_for("www.example.test.", 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
        assert_eq!(reply.rcode, ResponseCode::NoSuchDomain);
        assert!(
            serving
                .caches
                .answers
                .lookup(
                    nm("www.example.test.").as_ref(),
                    Qtype::of(record_types::A),
                    false
                )
                .is_none(),
            "a resolution that never finished has nothing to cache"
        );
    }

    /// A policy zone with one rule of each kind this test needs, built in
    /// memory: `PolicyZone::load` is `rdns::rpz`'s to test, and what is under
    /// test here is the answer path around it.
    fn policy(rules: &str) -> PolicyZones {
        let text = format!(
            "$TTL 60\n\
             @ IN SOA ns.rpz.invalid. hostmaster.rpz.invalid. 1 3600 600 86400 60\n{rules}"
        );
        let zone = rdns::zone::parse_zone_file(&text, "rpz.invalid.").expect("the policy parses");
        PolicyZones::from_zones(vec![rdns::rpz::PolicyZone::new(
            zone,
            rdns::rpz::PolicyOverride::Given,
        )
        .expect("indexes")])
    }

    async fn policy_reply(rules: &str, name: &str, transport: Transport) -> Option<DnsMessage> {
        let serving = serving(test_resolver(), test_shell(), policy(rules));
        let bytes = handle_query(
            query_for(name, 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            transport,
        )
        .await
        .reply?;
        Some(DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply"))
    }

    /// The whole point of the feature, end to end: a blocked name is NXDOMAIN
    /// with the policy zone's SOA to cache it by, and no upstream is reached —
    /// the resolver in this fixture forwards to a port nothing listens on, so
    /// an answer at all is proof the query never left.
    #[tokio::test]
    async fn a_blocked_name_is_answered_from_the_policy_and_never_resolved() {
        let reply = policy_reply(
            "evil.example.com IN CNAME .\n",
            "evil.example.com.",
            Transport::Udp,
        )
        .await
        .expect("answered");
        assert_eq!(reply.rcode, ResponseCode::NoSuchDomain);
        assert!(reply.answers.is_empty());
        assert_eq!(
            reply.authorities.len(),
            1,
            "the policy zone's SOA, or the client cannot cache the answer"
        );
        assert!(!reply.ad, "nothing here was authenticated");
    }

    /// RFC 8914 §4.16: the client is told this was policy rather than the
    /// internet, which is the difference between a support call and a shrug.
    #[tokio::test]
    async fn a_rewrite_says_it_was_blocked_when_the_client_used_edns() {
        let serving = serving(
            test_resolver(),
            test_shell(),
            policy("evil.example.com IN CNAME .\n"),
        );
        let query = rdns::DnsMessageBuilder::new()
            .with_id(7)
            .with_query(nm("evil.example.com."), Qtype::of(record_types::A))
            .with_recursion(true)
            .with_edns(1232, false)
            .build()
            .to_bytes_within(4096)
            .expect("serialize");
        let bytes = handle_query(
            query,
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
        let edns = reply.edns.as_ref().expect("the OPT is mirrored");
        let errors = ExtendedError::all_in(edns).expect("a well-formed option list");
        assert_eq!(
            errors.iter().map(|(code, _)| *code).collect::<Vec<_>>(),
            vec![InfoCode::BLOCKED]
        );
    }

    /// Local data answers under the name asked for, and is counted as a
    /// rewrite: a walled garden is the other half of blocking.
    #[tokio::test]
    async fn local_data_answers_the_query_and_is_counted() {
        let serving = serving(
            test_resolver(),
            test_shell(),
            policy("evil.example.com IN A 192.0.2.10\n"),
        );
        let bytes = handle_query(
            query_for("evil.example.com.", 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
        assert_eq!(reply.rcode, ResponseCode::Ok);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].name, nm("evil.example.com."));
        assert_eq!(
            serving
                .ctx
                .metrics
                .policy_rewrites
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// `rpz-drop` sends nothing, and the counter is the only way an operator
    /// tells that from a lost packet.
    #[tokio::test]
    async fn a_dropped_query_is_silent_and_counted() {
        let serving = serving(
            test_resolver(),
            test_shell(),
            policy("evil.example.com IN CNAME rpz-drop.\n"),
        );
        let reply = handle_query(
            query_for("evil.example.com.", 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply;
        assert!(reply.is_none(), "rpz-drop means no reply at all");
        assert_eq!(
            serving
                .ctx
                .metrics
                .policy_drops
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// `rpz-tcp-only` is a statement about UDP: TC=1 sends the client to TCP,
    /// where the handshake proves the source. Over TCP there is nothing left to
    /// ask for, so the query is answered as usual — which here means the
    /// unreachable upstream and SERVFAIL, not a truncated reply.
    #[tokio::test]
    async fn tcp_only_truncates_over_udp_and_does_nothing_over_tcp() {
        let rules = "evil.example.com IN CNAME rpz-tcp-only.\n";
        let over_udp = policy_reply(rules, "evil.example.com.", Transport::Udp)
            .await
            .expect("answered");
        assert!(over_udp.truncation, "TC=1 is the whole of the action");
        assert!(over_udp.answers.is_empty());

        let over_tcp = policy_reply(rules, "evil.example.com.", Transport::Tcp)
            .await
            .expect("answered");
        assert!(!over_tcp.truncation, "the client is already on TCP");
    }

    /// `rpz-passthru` matches and changes nothing, so the query is resolved —
    /// against an upstream that does not answer, which is what SERVFAIL here
    /// means and what tells this apart from a rewrite to NODATA.
    #[tokio::test]
    async fn passthru_resolves_the_query_as_if_no_rule_matched() {
        let reply = policy_reply(
            "evil.example.com IN CNAME rpz-passthru.\n",
            "evil.example.com.",
            Transport::Udp,
        )
        .await
        .expect("answered");
        assert_eq!(reply.rcode, ResponseCode::ServerFailure);
    }

    /// A name in the answer is a trigger too, and the answer this one rewrites
    /// comes out of the cache: the cache holds what the internet said, and the
    /// policy applies to what leaves.
    #[tokio::test]
    async fn a_response_ip_trigger_rewrites_an_answer_served_from_the_cache() {
        let serving = serving(
            test_resolver(),
            test_shell(),
            policy("24.0.2.0.198.rpz-ip IN CNAME .\n"),
        );
        let name = nm("www.example.com.");
        serving.caches.answers.put(
            name.as_ref(),
            Qtype::of(record_types::A),
            vec![ResourceRecord {
                name: name.clone(),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(300),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                    std::net::Ipv4Addr::new(198, 0, 2, 7),
                ))
                .expect("encodes"),
            }],
        );
        let bytes = handle_query(
            query_for("www.example.com.", 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
        assert_eq!(reply.rcode, ResponseCode::NoSuchDomain);
        assert!(
            reply.answers.is_empty(),
            "the address the cache held is what the rule is about"
        );
    }

    /// RFC 6761 §6.3's `localhost` is the loopback address whatever a feed says
    /// about it: the table is a protocol requirement and the policy is a
    /// preference, so the table goes first.
    #[tokio::test]
    async fn the_special_names_table_is_not_overridable_by_policy() {
        let reply = policy_reply("localhost IN CNAME .\n", "localhost.", Transport::Udp)
            .await
            .expect("answered");
        assert_eq!(reply.rcode, ResponseCode::Ok);
        assert_eq!(
            reply.answers.len(),
            1,
            "127.0.0.1, not the policy's NXDOMAIN"
        );
    }

    /// The client's EDNS advertisement is a ceiling this resolver may lower,
    /// not one it has to honour (`TODO.md` #41b).
    ///
    /// A stub advertising 65,535 was given 65,535, so a large cached RRset left
    /// as fragments — which is what every other resolver's `max-udp-size`
    /// exists to prevent. Answered out of the cache so no upstream is involved;
    /// the ceiling is `finish`'s and every answer path goes through it.
    ///
    /// Watched failing against `msg.udp_payload_size()`: 2,093 octets, TC clear.
    #[tokio::test]
    async fn a_udp_reply_is_capped_by_this_resolver_and_not_only_by_the_client() {
        let serving = context();
        let pool = nm("pool.example.com.");
        serving.caches.answers.put(
            pool.as_ref(),
            Qtype::of(record_types::A),
            (0..128u32)
                .map(|i| ResourceRecord {
                    name: pool.clone(),
                    class: rdns::Class::new(1),
                    ttl: rdns::Ttl::from_secs(300),
                    rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                        std::net::Ipv4Addr::new(198, 51, 100, (i % 254 + 1) as u8),
                    ))
                    .expect("encodes"),
                })
                .collect(),
        );

        let greedy = rdns::DnsMessageBuilder::new()
            .with_id(1)
            .with_query(pool.clone(), Qtype::of(record_types::A))
            .with_recursion(true)
            .with_edns(u16::MAX, false)
            .build()
            .to_bytes_within(4096)
            .expect("serialize");

        let cap = serving.ctx.udp.max_response() as usize;
        let bytes = handle_query(
            greedy,
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("answered from the cache");
        assert!(
            bytes.len() <= cap,
            "a {}-octet datagram went out under a {cap}-octet cap",
            bytes.len()
        );
        let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
        assert!(reply.truncation, "and says so, so the client retries");
        assert_eq!(
            reply.edns().expect("an OPT").udp_payload_size,
            serving.ctx.udp.advertised(),
            "the OPT advertises what this resolver was configured with"
        );
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
        let serving = context();
        for cd in [false, true] {
            let bytes = handle_query(
                query_for("localhost.", 1, cd),
                TEST_PEER,
                current_unix_timestamp(),
                &serving,
                Transport::Udp,
            )
            .await
            .reply
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
        let serving = context();
        let bytes = handle_query(
            query_for("localhost.", 2, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
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
        let serving = context();
        let now = current_unix_timestamp();

        for _ in 0..3 {
            handle_query(
                query_for("localhost.", 1, false),
                TEST_PEER,
                now,
                &serving,
                Transport::Udp,
            )
            .await
            .reply
            .expect("answered from the table");
        }
        // Not a question at all: dropped, and counted as an error rather than
        // as nothing.
        assert!(handle_query(
            vec![0x00, 0x01, 0x00],
            TEST_PEER,
            now,
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .is_none());

        let stats = serving.ctx.logger.take_stats(now + 60);
        assert_eq!(stats.total_queries, 3);
        assert_eq!(stats.queries_by_ip.get(&TEST_PEER), Some(&3));
        assert_eq!(stats.total_errors, 1);
        assert_eq!(
            stats.queries_by_type.get(&Qtype::of(record_types::A)),
            Some(&3)
        );
    }

    /// A policy feed with one QNAME rule, and optionally a nameserver rule.
    fn feed(serial: u32, blocked: &str, nsdname: Option<&str>) -> String {
        let mut text = format!(
            "$TTL 60\n\
             @ IN SOA ns.rpz.invalid. hostmaster.rpz.invalid. {serial} 3600 600 86400 60\n\
             @ IN NS localhost.\n\
             {blocked} IN CNAME .\n"
        );
        if let Some(ns) = nsdname {
            text.push_str(&format!("{ns}.rpz-nsdname IN CNAME .\n"));
        }
        text
    }

    /// #57: a feed rewritten under a running resolver reaches the answer path,
    /// which was a restart before.
    ///
    /// The resolver here is unreachable on purpose, so the assertion is also
    /// that the reply cost no resolution: a rule that only arrived at the
    /// reload blocked the name.
    #[tokio::test]
    async fn a_rule_that_arrived_at_a_reload_blocks_the_next_query() {
        let dir = ScratchDir::new("reload-blocks");
        let path = dir.write("feed.zone", &feed(1, "first.example.com", None));
        let store = PolicyStore::load(std::slice::from_ref(&path), PolicyOverride::Given)
            .expect("it loads");
        let serving = serving_policy(store);
        assert!(
            serving
                .policy
                .in_force()
                .before_query(
                    TEST_PEER,
                    nm("second.example.com.").as_ref(),
                    Qtype::of(record_types::A)
                )
                .is_none(),
            "the rule is not in the feed yet"
        );

        std::fs::write(&path, feed(2, "second.example.com", None)).expect("rewrite");
        reload_policy(&serving);

        let reply = handle_query(
            query_for("second.example.com.", 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("the policy answered");
        let reply = DnsMessage::try_from_bytes(&reply).expect("parses");
        assert_eq!(reply.rcode, ResponseCode::NoSuchDomain);
    }

    /// The reload's obligation to the caches, and its limit: an answer held
    /// from before a *nameserver* rule arrived is the one thing that rule
    /// cannot reach, because a cache hit never walks a delegation
    /// (`TODO.md` #56, #57).
    #[tokio::test]
    async fn a_nameserver_rule_that_arrived_at_a_reload_empties_the_caches() {
        let dir = ScratchDir::new("reload-caches");
        let path = dir.write("feed.zone", &feed(1, "first.example.com", None));
        let store = PolicyStore::load(std::slice::from_ref(&path), PolicyOverride::Given)
            .expect("it loads");
        let serving = serving_policy(store);
        let held = nm("held.example.com.");
        let qtype = Qtype::of(record_types::A);
        let cached = || vec![a_record(&held, 3600)];

        // A QNAME rule that moved: what is held is still what the internet
        // said, and the new rule is consulted before the cache anyway.
        serving.caches.answers.put(held.as_ref(), qtype, cached());
        std::fs::write(&path, feed(2, "second.example.com", None)).expect("rewrite");
        reload_policy(&serving);
        assert!(
            serving.caches.answers.get(held.as_ref(), qtype).is_some(),
            "an hourly reload that emptied the cache would be its own outage"
        );

        // A nameserver rule that moved: nothing held was ever offered to it.
        std::fs::write(
            &path,
            feed(3, "second.example.com", Some("ns.evil.example.com")),
        )
        .expect("rewrite");
        reload_policy(&serving);
        assert!(serving.caches.answers.get(held.as_ref(), qtype).is_none());
    }

    /// A half-written feed must not lift a block: the previous set stays in
    /// force and the reload says so (`CLAUDE.md` §4).
    #[tokio::test]
    async fn a_feed_that_will_not_parse_leaves_the_block_in_force() {
        let dir = ScratchDir::new("reload-broken");
        let path = dir.write("feed.zone", &feed(1, "first.example.com", None));
        let store = PolicyStore::load(std::slice::from_ref(&path), PolicyOverride::Given)
            .expect("it loads");
        let serving = serving_policy(store);

        std::fs::write(&path, "this is not a zone file\n").expect("rewrite");
        reload_policy(&serving);

        let reply = handle_query(
            query_for("first.example.com.", 1, false),
            TEST_PEER,
            current_unix_timestamp(),
            &serving,
            Transport::Udp,
        )
        .await
        .reply
        .expect("the policy answered");
        let reply = DnsMessage::try_from_bytes(&reply).expect("parses");
        assert_eq!(reply.rcode, ResponseCode::NoSuchDomain);
    }
}
