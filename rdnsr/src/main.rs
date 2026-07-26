use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rdns::dnssec_chain::{TrustAnchors, ValidationState};
use rdns::resolver::{Resolver, ResolverConfig, ResolverMode};
use rdns::negative_cache::NegativeCache;
use rdns::nsec_cache::NsecCache;
use rdns::utils::record_types;
use rdns::{
    DnsCache, DnsMessage, Edns, OpCode, QuerySection, ResourceRecord, ResponseCode, EDNS_VERSION,
    OPT_RECORD_TYPE,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};

/// UDP payload size rdnsr advertises to clients via EDNS0.
const RDNSR_PAYLOAD_SIZE: u16 = 4096;

/// How long a TCP connection may sit idle between queries before we close it.
/// RFC 7766 §6.2.3 wants connections reused rather than reopened, but an idle
/// one still costs a socket, so this is the compromise the RFC asks for.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long we wait for the rest of a message once its length prefix arrived.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on concurrent TCP connections. Without one, an accept loop that
/// spawns per connection is a free file-descriptor exhaustion vector.
const MAX_TCP_CONNECTIONS: usize = 128;

/// Queries a single connection may have in flight at once. Doubles as the reply
/// channel's depth, so a client that pipelines faster than it reads eventually
/// pushes back on our read loop instead of growing a queue in memory.
const MAX_INFLIGHT_PER_CONNECTION: usize = 16;

/// Zones whose validated denial proofs we keep for aggressive use (RFC 8198).
///
/// Counted in zones rather than records because that is the unit that pays off:
/// one zone's NSEC chain answers for every non-existent name in it, so a
/// thousand zones covers the whole tail of a random-name flood. `NsecCache`
/// bounds the records within each zone separately.
const NSEC_CACHE_ZONES: usize = 1000;

/// What `rdnsr` remembers between queries.
///
/// Three caches with three shapes, which is why they are not one.
///
/// - `answers` maps a question to the records that answered it.
/// - `negatives` maps a question to the *absence* of records (RFC 2308): a
///   different thing, because there are no records to key on and the TTL comes
///   from the SOA rather than from an answer.
/// - `denials` maps a *range* of names to the signed statement that none of them
///   exist — a lookup neither of the others can express, and the whole point of
///   RFC 8198. It holds validated material only, so it is empty unless
///   `--dnssec-validate` is on, which is why `negatives` is not redundant with it.
struct Caches {
    answers: DnsCache,
    negatives: NegativeCache,
    denials: NsecCache,
}

/// Which transport a query arrived on.
///
/// This decides the size limit on the answer: a UDP reply must fit the
/// requestor's advertised payload size, whereas a TCP reply is framed by a
/// 2-byte length and so is bounded only by that field (RFC 6891 §6.2.2 — the
/// EDNS payload size applies to UDP only).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

/// Recursive DNS resolver with caching.
///
/// Unlike the authoritative server (`rdnsd`), `rdnsr` answers by resolving:
/// walking the delegation chain from the root and caching what it learns.
/// Passing `--upstream` switches it to forwarding instead, the way
/// `forwarders`/`forward-zone` does in BIND and Unbound.
///
/// Binds to localhost by default so it is not accidentally exposed as an open
/// resolver (an amplification vector).
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Address to listen on. Defaults to localhost to avoid an open resolver.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value = "53")]
    port: u16,
    /// Forward to this resolver instead of recursing, e.g. 8.8.8.8:53
    /// (repeatable). Passing any `--upstream` switches the resolver from
    /// recursion to forwarding, the way `forwarders`/`forward-zone` does in
    /// BIND and Unbound.
    #[arg(long)]
    upstream: Vec<SocketAddr>,
    /// Root hints file (named.root format) to prime recursion from, replacing
    /// the built-in list. Only used when recursing; ignored with --upstream.
    #[arg(long)]
    root_hints: Option<std::path::PathBuf>,
    /// Maximum number of cached RRsets.
    #[arg(long, default_value = "10000")]
    cache_size: usize,
    /// Disable caching entirely.
    #[arg(long)]
    no_cache: bool,
    /// Validate DNSSEC on resolved answers: walk the chain of trust from a
    /// trust anchor, set AD only on answers that verify, and refuse to serve
    /// ones that fail (SERVFAIL, unless the client sets CD).
    #[arg(long)]
    dnssec_validate: bool,
    /// Trust anchors in DS presentation format, replacing the built-in ICANN
    /// root key. Only used with --dnssec-validate.
    ///
    /// A file rather than a rebuild, because the root KSK rolls over and a
    /// binary compiled before the roll is wrong until it is rebuilt.
    #[arg(long)]
    trust_anchor: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Recursion is the default; naming an upstream is what selects forwarding.
    let mut config = ResolverConfig::default();
    if cli.upstream.is_empty() {
        config.mode = ResolverMode::Recurse;
    } else {
        config.mode = ResolverMode::Forward;
        config.upstream_servers = cli.upstream.clone();
    }

    // Custom root hints only make sense when recursing. Fail loudly on a hints
    // file that yields no addresses — silently falling back to the built-ins
    // would hide a misconfiguration.
    let mut custom_hints = false;
    if let Some(path) = &cli.root_hints {
        if config.mode == ResolverMode::Recurse {
            let text = std::fs::read_to_string(path)
                .map_err(|e| format!("reading root hints {}: {e}", path.display()))?;
            let hints = rdns::resolver::parse_root_hints(&text);
            if hints.is_empty() {
                return Err(format!("no A/AAAA records found in {}", path.display()).into());
            }
            config.root_hints = hints;
            custom_hints = true;
        } else {
            eprintln!("warning: --root-hints is ignored when forwarding (--upstream)");
        }
    }

    // DNSSEC. The built-in ICANN root key is the fallback so a plain
    // --dnssec-validate works out of the box; --trust-anchor overrides it, and
    // is what to reach for when the root KSK rolls.
    let mut dnssec_source = String::new();
    if cli.dnssec_validate {
        let anchors = match &cli.trust_anchor {
            Some(path) => {
                dnssec_source = format!(", DNSSEC validating from {}", path.display());
                TrustAnchors::from_file(path)?
            }
            None => {
                dnssec_source = ", DNSSEC validating from the built-in root anchor".to_string();
                TrustAnchors::icann_root()
            }
        };
        config.dnssec = Some(anchors);
    } else if cli.trust_anchor.is_some() {
        eprintln!("warning: --trust-anchor does nothing without --dnssec-validate");
    }

    let source = match config.mode {
        ResolverMode::Recurse if custom_hints => {
            format!("recursing from {} root hints in {}", config.root_hints.len(), cli.root_hints.as_ref().unwrap().display())
        }
        ResolverMode::Recurse => "recursing from the built-in root hints".to_string(),
        ResolverMode::Forward => format!("forwarding to {:?}", config.upstream_servers),
    };
    let resolver = Arc::new(Resolver::new(config));

    // A zero-capacity cache never stores (DnsCache::put is a no-op at 0), so
    // --no-cache is just a cache sized to hold nothing. The denial cache is
    // sized the same way, and additionally to zero when we are not validating:
    // aggressive use rests entirely on the proofs having been checked, so
    // without validation there is nothing legitimate to put in it.
    let capacity = if cli.no_cache { 0 } else { cli.cache_size };
    let denial_zones = if cli.no_cache || !cli.dnssec_validate {
        0
    } else {
        NSEC_CACHE_ZONES
    };
    let caches = Arc::new(Caches {
        answers: DnsCache::new(capacity),
        // Negative answers share the answer cache's bound: they are answers, and
        // `--no-cache` means no cache.
        negatives: NegativeCache::new(capacity),
        denials: NsecCache::new(denial_zones),
    });

    let addr = format!("{}:{}", cli.host, cli.port);
    // Both transports are mandatory for a resolver: when an answer overflows the
    // client's UDP payload size we reply TC=1, and RFC 1035 §4.2.1 has the client
    // retry the same query over TCP. Without a TCP listener that retry is
    // refused and the query simply fails.
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    let listener = TcpListener::bind(&addr).await?;
    println!(
        "rdnsr listening on {} (UDP+TCP), {}, cache: {}{}",
        addr,
        source,
        if capacity == 0 { "disabled".to_string() } else { format!("{capacity} entries") },
        dnssec_source,
    );

    let udp = tokio::spawn(udp_main(socket, resolver.clone(), caches.clone()));
    let tcp = tokio::spawn(tcp_main(listener, resolver, caches));

    // Neither loop returns in normal operation; whichever fails first takes the
    // process down rather than leaving us serving one transport.
    tokio::select! {
        r = udp => r??,
        r = tcp => r??,
    }
    Ok(())
}

/// Accept datagrams and answer each in its own task.
async fn udp_main(
    socket: Arc<UdpSocket>,
    resolver: Arc<Resolver>,
    caches: Arc<Caches>,
) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let data = buf[..n].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        let caches = caches.clone();
        tokio::spawn(async move {
            if let Some(reply) = handle_query(data, &resolver, &caches, Transport::Udp).await {
                let _ = socket.send_to(&reply, peer).await;
            }
        });
    }
}

/// Accept TCP connections, bounded by [`MAX_TCP_CONNECTIONS`].
async fn tcp_main(
    listener: TcpListener,
    resolver: Arc<Resolver>,
    caches: Arc<Caches>,
) -> Result<(), std::io::Error> {
    let permits = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, _peer) = listener.accept().await?;
        // The semaphore is never closed, so acquiring only fails if we drop it.
        let Ok(permit) = permits.clone().acquire_owned().await else {
            continue;
        };
        let resolver = resolver.clone();
        let caches = caches.clone();
        tokio::spawn(async move {
            serve_connection(stream, resolver, caches).await;
            drop(permit);
        });
    }
}

/// Serve one TCP connection until it goes idle, closes, or misbehaves.
///
/// Each message is framed by a 2-byte big-endian length (RFC 1035 §4.2.2), and a
/// connection may carry any number of queries (RFC 7766 §6.2.1), answered
/// **concurrently** (§6.2.1.1). Concurrency earns its keep here: a cache miss
/// costs an upstream round trip, so answering in lock-step would make every
/// query on a connection wait out the slowest one ahead of it.
async fn serve_connection(
    stream: TcpStream,
    resolver: Arc<Resolver>,
    caches: Arc<Caches>,
) {
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MAX_INFLIGHT_PER_CONNECTION);

    // One task owns the write half. Answers may complete out of order — RFC 7766
    // §6.2.1.1 allows that, and clients match on the transaction id — but two
    // framed messages must never interleave on the wire, so every reply funnels
    // through here.
    let writer_task = tokio::spawn(async move {
        while let Some(framed) = rx.recv().await {
            if writer.write_all(&framed).await.is_err() {
                break;
            }
        }
    });

    let in_flight = Arc::new(Semaphore::new(MAX_INFLIGHT_PER_CONNECTION));

    loop {
        // Between messages the peer may legitimately be idle, so a timeout here
        // is a normal close rather than an error.
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE_TIMEOUT, reader.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            break; // Can't even hold a header; treat as a broken peer.
        }

        // Mid-message the peer has committed to sending `len` bytes, so a stall
        // here gets a much shorter leash than an idle connection does.
        let mut buf = vec![0u8; len];
        match tokio::time::timeout(TCP_READ_TIMEOUT, reader.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }

        // Cap in-flight work per connection: this await is what stops a
        // pipelining client from spawning tasks faster than we retire them.
        let Ok(permit) = in_flight.clone().acquire_owned().await else {
            break;
        };
        let resolver = resolver.clone();
        let caches = caches.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Some(reply) = handle_query(buf, &resolver, &caches, Transport::Tcp).await {
                // Length prefix and message in one buffer, so the writer emits
                // them in a single call.
                let mut framed = Vec::with_capacity(2 + reply.len());
                framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
                framed.extend_from_slice(&reply);
                // A send error means the writer is gone (the peer hung up);
                // there is nowhere left to put the reply.
                let _ = tx.send(framed).await;
            }
            drop(permit);
        });
    }

    // Dropping our sender lets the writer drain the replies still in flight —
    // the clones held by running tasks keep the channel open — and then exit.
    drop(tx);
    let _ = writer_task.await;
}

/// Resolve one datagram: cache lookup, else forward upstream and cache-store.
/// Returns the wire bytes to send back, or `None` if the query was unparseable
/// (in which case we simply drop it, as a resolver should).
async fn handle_query(
    data: Vec<u8>,
    resolver: &Arc<Resolver>,
    caches: &Arc<Caches>,
    transport: Transport,
) -> Option<Vec<u8>> {
    let msg = DnsMessage::try_from_bytes(&data).ok()?;
    let query = msg.queries.first()?.clone();
    let id = msg.id;
    let recursion = msg.recursion;
    // Over UDP: the classic 512, unless the client advertised more via EDNS0.
    // Over TCP: the length prefix is the only limit, and truncating there would
    // strand the client — TCP *is* the fallback it was sent to.
    let client_max = match transport {
        Transport::Udp => msg.udp_payload_size() as usize,
        Transport::Tcp => u16::MAX as usize,
    };

    // Reject bad EDNS before doing any work on the client's behalf: a malformed
    // option list is a FORMERR, and an EDNS version we don't implement is
    // BADVERS (RFC 6891 §6.1.3). Both replies carry a bare version-0 OPT.
    match msg.edns() {
        Err(_) => {
            return edns_error(id, &query, ResponseCode::FormatError, recursion, client_max)
        }
        Ok(Some(edns)) if edns.version > EDNS_VERSION => {
            return edns_error(id, &query, ResponseCode::BadOptVersion, recursion, client_max)
        }
        _ => {}
    }
    let client_uses_edns = msg.has_edns();
    // What the client asked for, DNSSEC-wise. DO means "send me the signatures";
    // CD means "don't withhold anything on my behalf, I validate myself".
    let client_wants_dnssec = msg.edns().ok().flatten().is_some_and(|e| e.do_bit);
    let checking_disabled = msg.cd;

    // Aggressive use of the validated denial cache (RFC 8198). A cached NSEC
    // does not answer one question, it answers every question in its gap, so
    // this is checked before the answer cache: a flood of random names under one
    // zone costs a single upstream query rather than one per name.
    //
    // A client with CD set has asked us not to filter on its behalf, and an
    // answer we invented from cached proofs is exactly that, so it goes
    // upstream instead.
    if !checking_disabled {
        if let Some(denial) = caches.denials.synthesize(&query.qname, query.qtype) {
            let mut resp = build_response(id, &query, Vec::new(), denial.rcode, recursion);
            resp.authorities = denial.authority;
            // The proofs were validated before they were stored, so the answer
            // derived from them is authentic on the same terms as the original.
            resp.ad = client_wants_dnssec || msg.ad;
            return finish(resp, client_uses_edns, client_wants_dnssec, &query, client_max);
        }
    }

    // A cached "no" (RFC 2308). Checked alongside the answer cache because it
    // answers the same question the same way — the only reason it is a separate
    // cache is that there are no records to key on. Unlike the denial cache
    // above, nothing here is synthesized: this is the answer this question got,
    // so a CD client may have it too.
    if let Some(negative) = caches.negatives.get(&query.qname, query.qtype) {
        let mut resp = build_response(id, &query, Vec::new(), negative.rcode, recursion);
        resp.authorities = negative.authority;
        resp.ad = negative.secure && (client_wants_dnssec || msg.ad);
        resp.cd = checking_disabled;
        return finish(resp, client_uses_edns, client_wants_dnssec, &query, client_max);
    }

    // Build the response: from cache if we have it, else by resolving.
    let (mut resp, secure) = if let Some((records, secure)) =
        caches.answers.get_validated(&query.qname, query.qtype)
    {
        (
            build_response(id, &query, records, ResponseCode::Ok, recursion),
            secure,
        )
    } else {
        // Resolver::resolve_validated is async — each upstream round trip is an
        // await, so this yields the task rather than holding a thread.
        match resolver.resolve_validated(&query).await {
            Ok((mut upstream, state)) => {
                // The resolver used its own random transaction id; the reply
                // must echo the client's id and advertise recursion.
                upstream.id = id;
                upstream.response = true;
                upstream.recursion = recursion;
                upstream.recursion_ok = true;

                if let ValidationState::Bogus(ref why) = state {
                    eprintln!(
                        "resolve {} type {}: DNSSEC validation failed: {why}",
                        query.qname, query.qtype
                    );
                    // Fail closed. Data we know we cannot authenticate is worse
                    // than no data: the client has no way to tell it apart from
                    // an answer that was checked, so serving it launders an
                    // attack into an ordinary-looking reply. A client that sets
                    // CD has said it will do its own checking, and RFC 4035
                    // §3.2.2 requires we hand the data over unfiltered.
                    if !checking_disabled {
                        let resp = build_response(
                            id,
                            &query,
                            Vec::new(),
                            ResponseCode::ServerFailure,
                            recursion,
                        );
                        return finish(
                            resp,
                            client_uses_edns,
                            client_wants_dnssec,
                            &query,
                            client_max,
                        );
                    }
                }

                let secure = state.is_secure();
                // Never store an answer as validated that was not, and never
                // store one at all if it failed: a bogus answer in the cache is
                // an attack that outlives the query that carried it.
                if !upstream.answers.is_empty() && !state.is_bogus() {
                    caches.answers.put_validated(
                        &query.qname,
                        query.qtype,
                        upstream.answers.clone(),
                        secure,
                    );
                }
                // A "no" is an answer, and re-resolving it every time is what
                // made a typo storm cost one upstream walk per repeat. RFC 2308:
                // the SOA in the authority section says how long it is good for.
                if !state.is_bogus() {
                    caches
                        .negatives
                        .insert(&query.qname, query.qtype, &upstream, secure);
                }
                // A *validated* "no" is worth more than the question that
                // produced it — the NSEC covers a whole range of names — so it
                // also goes into the denial cache. Only when Secure: aggressive
                // use rests entirely on the proof having been checked, and an
                // unvalidated NSEC is an attacker's claim about which names do
                // not exist.
                if upstream.answers.is_empty() && secure {
                    caches.denials.insert_validated(&upstream);
                }
                (upstream, secure)
            }
            // Resolution failed: say why, then SERVFAIL. A resolver that turns
            // every failure into a bare SERVFAIL is undiagnosable from the
            // outside, and the reasons here are specific — lame delegation,
            // budget exhausted, CNAME loop — precisely so they can be read.
            Err(ref e) => {
                eprintln!(
                    "resolve {} type {} failed: {:#}",
                    query.qname, query.qtype, e
                );
                (
                    build_response(id, &query, Vec::new(), ResponseCode::ServerFailure, recursion),
                    false,
                )
            }
        }
    };

    // The AD bit goes on only for an answer we actually authenticated, and only
    // for a client that asked about it (RFC 6840 §5.8) — to anyone else it is
    // noise, and to a client behind an untrusted link it is not evidence of
    // anything anyway.
    resp.ad = secure && (client_wants_dnssec || msg.ad);
    resp.cd = checking_disabled;

    finish(resp, client_uses_edns, client_wants_dnssec, &query, client_max)
}

/// Final shaping common to every reply: OPT mirroring, stripping DNSSEC records
/// a client did not ask for, and the size limit.
fn finish(
    mut resp: DnsMessage,
    client_uses_edns: bool,
    client_wants_dnssec: bool,
    query: &QuerySection,
    client_max: usize,
) -> Option<Vec<u8>> {
    // A client that did not set DO gets no DNSSEC records (RFC 4035 §3.2.1) —
    // it did not ask for them, they are large, and it has no use for them.
    // Records it asked for by type are a different matter and stay.
    if !client_wants_dnssec {
        let asked_for = |rtype: u16| query.qtype == rtype;
        let keep = |rr: &ResourceRecord| match rr.rdata.rtype {
            record_types::RRSIG | record_types::NSEC | record_types::NSEC3 => false,
            record_types::DNSKEY | record_types::DS => asked_for(rr.rdata.rtype),
            _ => true,
        };
        resp.answers.retain(keep);
        resp.authorities.retain(keep);
        resp.additionals
            .retain(|rr| rr.rdata.rtype == OPT_RECORD_TYPE || keep(rr));
    }

    // Only include an OPT record when the client used EDNS (RFC 6891 §6.1.1);
    // otherwise strip any OPT the upstream added so we don't reply with
    // unsolicited EDNS.
    if client_uses_edns {
        let mut edns = Edns::with_payload_size(RDNSR_PAYLOAD_SIZE);
        // Mirror DO back: it tells the client the signatures it sees were
        // deliberate rather than leftovers.
        edns.do_bit = client_wants_dnssec;
        resp.set_edns(edns).ok()?;
    } else {
        resp.additionals.retain(|rr| rr.rdata.rtype != OPT_RECORD_TYPE);
    }

    // Honor the client's advertised UDP size: truncates (TC=1) if it overflows.
    resp.to_bytes_within(client_max).ok()
}

/// An empty error response carrying a version-0 OPT record, for the EDNS-level
/// rejections (FORMERR / BADVERS) that must be signalled before resolving.
fn edns_error(
    id: u16,
    query: &QuerySection,
    rcode: ResponseCode,
    recursion: bool,
    client_max: usize,
) -> Option<Vec<u8>> {
    let mut resp = build_response(id, query, Vec::new(), rcode, recursion);
    // BADVERS is an extended RCODE, so the OPT record isn't optional here — it
    // carries the code's high bits.
    resp.set_edns(Edns::with_payload_size(RDNSR_PAYLOAD_SIZE)).ok()?;
    resp.to_bytes_within(client_max).ok()
}

/// Build a minimal response message echoing the question section.
fn build_response(
    id: u16,
    query: &QuerySection,
    answers: Vec<ResourceRecord>,
    rcode: ResponseCode,
    recursion: bool,
) -> DnsMessage {
    DnsMessage {
        id,
        response: true,
        opcode: OpCode::Query,
        authoritive: false,
        truncation: false,
        recursion,
        recursion_ok: true,
        ad: false,
        cd: false,
        rcode,
        queries: vec![query.clone()],
        answers,
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}
