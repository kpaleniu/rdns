use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use clap::Parser;
use rdns::dnssec_chain::{TrustAnchors, ValidationState};
use rdns::logging::LogLevel;
use rdns::negative_cache::NegativeCache;
use rdns::nsec_cache::NsecCache;
use rdns::resolver::{Resolver, ResolverConfig, ResolverMode, SharedAnchors};
use rdns::rfc5011::{self, AnchorChange, ManagedAnchors};
use rdns::shutdown::{stop_signal, Busy, Shutdown, Stop};
use rdns::special_names;
use rdns::utils::current_unix_timestamp;
use rdns::utils::record_types;
use rdns::utils::{recv_error_is_transient, UDP_RECEIVE_BUFFER};
use rdns::{
    DnsCache, DnsMessage, Edns, OpCode, QuerySection, ResourceRecord, ResponseCode, EDNS_VERSION,
    OPT_RECORD_TYPE,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

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
#[command(version = rdns::VERSION, about, long_about = None)]
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
    /// A *managed* trust anchor file, followed and rewritten as keys roll
    /// (RFC 5011). Only used with --dnssec-validate.
    ///
    /// The difference from `--trust-anchor` is who owns the file. That one is
    /// read and never touched: the operator's decision, and a key roll means
    /// editing it. This one is read *and written*: the resolver watches the
    /// zone's own signed DNSKEY RRset, adopts a new key once it has been
    /// published continuously for 30 days, and drops one the zone revokes with a
    /// signature from that same key. It is the difference between a root KSK roll
    /// being an outage and being something that already happened.
    ///
    /// Created from the anchors in force when it does not exist yet, so pointing
    /// at a new path is enough to start.
    #[arg(long)]
    auto_trust_anchor: Option<std::path::PathBuf>,
    /// How much to say: error, warn, info, debug or trace.
    ///
    /// `info` by default, and nothing per-query is above `debug` — the same
    /// flag, levels and default as `rdnsd`. `RUST_LOG` overrides it when set, so
    /// a resolver that is already misbehaving can be turned up without a restart
    /// into new flags.
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: LogLevel,
    /// Errors only. The same as `--log-level error`, and refused with it.
    #[arg(long, conflicts_with = "log_level")]
    quiet: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Before anything that might have something to say — and through the same
    // initialiser `rdnsd` uses, so the two daemons cannot end up formatting or
    // filtering differently (`CLAUDE.md` §7).
    rdns::logging::init(if cli.quiet {
        LogLevel::Error
    } else {
        cli.log_level
    });

    // Created before anything is spawned: the RFC 5011 anchor manager starts
    // before the listeners do, and it owns the only durable state this process
    // writes.
    let shutdown = Shutdown::new();

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
                .with_context(|| format!("reading root hints {}", path.display()))?;
            let hints = rdns::resolver::parse_root_hints(&text);
            if hints.is_empty() {
                return Err(anyhow!("no A/AAAA records found in {}", path.display()));
            }
            config.root_hints = hints;
            custom_hints = true;
        } else {
            tracing::warn!("--root-hints is ignored when forwarding (--upstream)");
        }
    }

    // DNSSEC. The built-in ICANN root key is the fallback so a plain
    // --dnssec-validate works out of the box; --trust-anchor overrides it, and
    // is what to reach for when the root KSK rolls.
    let mut dnssec_source = String::new();
    let mut managed: Option<(std::path::PathBuf, ManagedAnchors)> = None;
    let mut shared_anchors: Option<SharedAnchors> = None;
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
        // A managed file, if there is one, supersedes what we just loaded: it is
        // the record of what has been *learned* since, and starting from the
        // configured anchors again would throw away a hold-down that may be 29
        // days old.
        managed = match &cli.auto_trust_anchor {
            Some(path) => {
                let anchors =
                    ManagedAnchors::load_or_seed(path, &anchors, current_unix_timestamp())?;
                // Write it out now if it is not there yet, rather than at the
                // first change. An operator who points at a new path should be
                // able to look at the file and see what is trusted, and a
                // resolver that only writes when something happens leaves them
                // wondering for a month whether any of this is on.
                if !path.exists() {
                    anchors.save(path)?;
                    tracing::info!(
                        file = %path.display(),
                        "trust anchors: wrote the anchors in force"
                    );
                }
                dnssec_source = format!(", DNSSEC validating from {} (RFC 5011)", path.display());
                Some((path.clone(), anchors))
            }
            None => None,
        };
        let in_force = match &managed {
            Some((_, managed)) => managed.trust_anchors(),
            None => anchors,
        };
        shared_anchors = Some(SharedAnchors::new(in_force));
        config.dnssec = shared_anchors.clone();
    } else if cli.trust_anchor.is_some() || cli.auto_trust_anchor.is_some() {
        tracing::warn!(
            "--trust-anchor and --auto-trust-anchor do nothing without --dnssec-validate"
        );
    }

    let source = match config.mode {
        ResolverMode::Recurse if custom_hints => {
            format!(
                "recursing from {} root hints in {}",
                config.root_hints.len(),
                cli.root_hints.as_ref().unwrap().display()
            )
        }
        ResolverMode::Recurse => "recursing from the built-in root hints".to_string(),
        ResolverMode::Forward => format!("forwarding to {:?}", config.upstream_servers),
    };
    let resolver = Arc::new(Resolver::new(config));

    // Following the anchors is a task of its own: it resolves, which means it
    // needs the resolver, which means it cannot be part of building one.
    if let (Some((path, anchors)), Some(shared)) = (managed, shared_anchors) {
        spawn_anchor_manager(
            resolver.clone(),
            shared,
            anchors,
            path,
            shutdown.stop_handle(),
            shutdown.busy(),
        );
    }

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
    tracing::info!(
        "rdnsr listening on {} (UDP+TCP), {}, cache: {}{}",
        addr,
        source,
        if capacity == 0 {
            "disabled".to_string()
        } else {
            format!("{capacity} entries")
        },
        dnssec_source,
    );

    // A `JoinSet` rather than two `JoinHandle`s in a `select!`, which dropped
    // the loser — and dropping a `JoinHandle` detaches the task rather than
    // cancelling it, so `main` returned with the other transport still reading
    // and replies still queued in a per-connection `mpsc`. `join_next` is
    // cancel-safe, so first-one-wins keeps both tasks owned and joinable.
    let mut loops = JoinSet::new();
    loops.spawn(udp_main(
        socket,
        resolver.clone(),
        caches.clone(),
        shutdown.stop_handle(),
        shutdown.busy(),
    ));
    loops.spawn(tcp_main(
        listener,
        resolver,
        caches,
        shutdown.stop_handle(),
        shutdown.busy(),
    ));

    // Neither loop returns in normal operation; whichever ends first ends the
    // process rather than leaving us serving one transport — cooperatively now.
    let mut failure: Option<anyhow::Error> = None;
    tokio::select! {
        joined = loops.join_next() => {
            failure = joined.and_then(listener_failure);
        }
        signal = stop_signal() => {
            tracing::info!("{signal} received, shutting down");
        }
    }

    shutdown.begin();
    while let Some(joined) = loops.join_next().await {
        if failure.is_none() {
            failure = listener_failure(joined);
        }
    }

    // What is left running is a resolution the client is still waiting on, or
    // the RFC 5011 manager part-way through rewriting the anchor file — which
    // is the one piece of durable state this process owns.
    shutdown.drain_reporting().await;

    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// How a finished listener task is reported. A cancelled task is not a failure:
/// it is a task that was told to stop.
fn listener_failure(
    joined: Result<Result<(), std::io::Error>, tokio::task::JoinError>,
) -> Option<anyhow::Error> {
    match joined {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(anyhow::Error::from(e).context("a listener stopped")),
        Err(e) if e.is_cancelled() => None,
        Err(e) => Some(anyhow::anyhow!("a listener task panicked: {e}")),
    }
}

/// Accept datagrams and answer each in its own task.
/// Follow the managed zones' DNSKEY RRsets and keep the anchors in step
/// (RFC 5011).
///
/// One task, not one per zone: the zones share a file, and one writer per file
/// is the rule everything else here obeys too.
fn spawn_anchor_manager(
    resolver: Arc<Resolver>,
    anchors: SharedAnchors,
    mut managed: ManagedAnchors,
    path: std::path::PathBuf,
    stop: Stop,
    busy: Busy,
) {
    tokio::spawn(async move {
        // A first probe soon after start rather than immediately: a resolver
        // that cannot answer its own first query yet would just spend a retry.
        let mut wait = Duration::from_secs(60);
        loop {
            // No `Busy` across the sleep, which is hours long — only across the
            // probe-and-save below, where the file is actually rewritten.
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = stop.wait() => return,
            }
            let _busy = busy.clone();
            wait = Duration::from_secs(rfc5011::retry_interval(0, 0));

            let mut changed = false;
            let mut soonest = u64::MAX;
            for zone in managed.zones() {
                match probe_zone(&resolver, &zone).await {
                    Ok(probe) => {
                        let changes = managed.observe(
                            &zone,
                            &probe.keys,
                            &probe.self_signers,
                            current_unix_timestamp(),
                        );
                        for change in &changes {
                            report(change);
                        }
                        changed |= !changes.is_empty();
                        soonest = soonest.min(rfc5011::query_interval(
                            probe.original_ttl,
                            probe.signature_remaining,
                        ));
                    }
                    Err(e) => tracing::warn!(%zone, "trust anchors: {e}"),
                }
            }

            if changed {
                // The live anchor set moves with the file, in that order: a
                // resolver validating against keys it has not recorded would
                // forget them on restart, which is the failure this file exists
                // to prevent.
                match managed.save(&path) {
                    Ok(()) => anchors.replace(managed.trust_anchors()),
                    Err(e) => tracing::error!(
                        "trust anchors: {e} — keeping the previous set rather than \
                         validating against keys we could not write down"
                    ),
                }
            }
            if soonest != u64::MAX {
                wait = Duration::from_secs(soonest);
            }
        }
    });
}

/// What one DNSKEY probe learned.
struct AnchorProbe {
    keys: Vec<rdns::dnssec::Dnskey>,
    /// Those of them that signed the RRset — what a revocation rests on.
    self_signers: Vec<rdns::dnssec::Dnskey>,
    original_ttl: u32,
    signature_remaining: u64,
}

/// Resolve a zone's DNSKEY RRset, insisting it validated.
///
/// **Secure or nothing.** An Insecure or Indeterminate answer for a zone we hold
/// an anchor for is not a zone that went unsigned, it is an answer we could not
/// tie to the anchor — and adopting keys from one would be adopting whatever
/// answered. This is the precondition `ManagedAnchors::observe` documents and
/// cannot check for itself.
async fn probe_zone(resolver: &Resolver, zone: &str) -> anyhow::Result<AnchorProbe> {
    let query = QuerySection {
        qname: zone.to_string(),
        qtype: record_types::DNSKEY,
        qclass: rdns::QueryClass::IN,
    };
    let (response, state) = resolver
        .resolve_validated(&query)
        .await
        .context("resolving DNSKEY")?;

    if state != ValidationState::Secure {
        return Err(anyhow!(
            "the DNSKEY RRset did not validate ({state:?}) — not adopting anything from it"
        ));
    }

    let now = current_unix_timestamp();
    let keys: Vec<rdns::dnssec::Dnskey> = response
        .answers
        .iter()
        .filter_map(rdns::dnssec::Dnskey::from_record)
        .collect();
    if keys.is_empty() {
        return Err(anyhow!("a validated answer with no DNSKEY in it"));
    }

    // The timers come from the RRSIG that covers the set: how long the zone said
    // to cache it, and how long its signature has left.
    let (original_ttl, signature_remaining) = response
        .answers
        .iter()
        .filter_map(rdns::dnssec::Rrsig::from_record)
        .filter(|sig| sig.type_covered == record_types::DNSKEY)
        .map(|sig| {
            (
                sig.original_ttl,
                (sig.expiration as u64).saturating_sub(now),
            )
        })
        .max_by_key(|(_, remaining)| *remaining)
        .unwrap_or((0, 0));

    Ok(AnchorProbe {
        self_signers: rfc5011::self_signers(zone, &response.answers, now),
        keys,
        original_ttl,
        signature_remaining,
    })
}

/// Say what happened. A trust anchor moving is the rarest event this resolver
/// has and the one an operator most wants to find in a log afterwards.
/// INFO throughout, and INFO deliberately: a trust anchor changing is rare, it
/// is the thing an operator reconstructs a DNSSEC incident from afterwards, and
/// there is no volume in it — a key rolls over months. `--quiet` still silences
/// it, which is the operator saying they do not want it.
fn report(change: &AnchorChange) {
    match change {
        AnchorChange::Pending { zone, key_tag } => tracing::info!(
            %zone,
            key_tag,
            "trust anchors: new key — trusted in {} days if it stays",
            rfc5011::ADD_HOLD_DOWN / 86_400
        ),
        AnchorChange::Trusted { zone, key_tag } => {
            tracing::info!(%zone, key_tag, "trust anchors: key is now a trust anchor")
        }
        AnchorChange::Withdrawn { zone, key_tag } => tracing::info!(
            %zone,
            key_tag,
            "trust anchors: key went away before its hold-down elapsed"
        ),
        AnchorChange::Absent { zone, key_tag } => tracing::info!(
            %zone,
            key_tag,
            "trust anchors: key is no longer published, but is still trusted \
             (revocation is how a key is retired)"
        ),
        AnchorChange::Returned { zone, key_tag } => {
            tracing::info!(%zone, key_tag, "trust anchors: key is published again")
        }
        AnchorChange::Revoked { zone, key_tag } => tracing::info!(
            %zone,
            key_tag,
            "trust anchors: key REVOKED itself — no longer a trust anchor"
        ),
        AnchorChange::Forgotten { zone, key_tag } => {
            tracing::info!(%zone, key_tag, "trust anchors: key is forgotten")
        }
    }
}

async fn udp_main(
    socket: Arc<UdpSocket>,
    resolver: Arc<Resolver>,
    caches: Arc<Caches>,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    // Sized for any datagram a client may send, not for the payload size we
    // advertise: on Windows an oversized datagram fails the receive rather than
    // truncating, and a failed receive ends this loop and the process with it.
    let mut buf = vec![0u8; UDP_RECEIVE_BUFFER];
    loop {
        // Stop receiving on shutdown. `recv_from` is cancel-safe, so a datagram
        // is either fully received or not received at all.
        let received = tokio::select! {
            r = socket.recv_from(&mut buf) => r,
            _ = stop.wait() => return Ok(()),
        };
        let (n, peer) = match received {
            Ok(received) => received,
            // An ICMP report about a datagram we already sent, or a datagram
            // that did not fit — neither says anything about this socket, and
            // both used to end the loop. See `recv_error_is_transient`, which
            // this shares with `rdnsd` precisely because the two copies had
            // already drifted.
            Err(e) if recv_error_is_transient(&e) => continue,
            Err(e) => return Err(e),
        };
        let data = buf[..n].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        let caches = caches.clone();
        // A recursive answer can take seconds and the client is already waiting
        // on it, so it is worth the drain rather than being dropped.
        let busy = busy.clone();
        tokio::spawn(async move {
            let _busy = busy;
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
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    let permits = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        // Stop accepting on shutdown; connections already open drain in their
        // own tasks below. `accept` is cancel-safe, so a connection lost to this
        // race stays in the kernel backlog rather than being half-taken.
        let (stream, _peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = stop.wait() => return Ok(()),
        };
        // The semaphore is never closed, so acquiring only fails if we drop it.
        let Ok(permit) = permits.clone().acquire_owned().await else {
            continue;
        };
        let resolver = resolver.clone();
        let caches = caches.clone();
        let stop = stop.clone();
        let busy = busy.clone();
        tokio::spawn(async move {
            serve_connection(stream, resolver, caches, stop).await;
            drop(permit);
            drop(busy);
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
    stop: Stop,
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
        // is a normal close rather than an error — and so is a shutdown, which
        // ends the connection at the cheapest possible moment: the peer has
        // committed to nothing, so it costs one reconnect and no answer.
        let mut len_buf = [0u8; 2];
        let read = tokio::select! {
            r = tokio::time::timeout(TCP_IDLE_TIMEOUT, reader.read_exact(&mut len_buf)) => r,
            _ = stop.wait() => break,
        };
        match read {
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

    // A *response* is not a query, and answering one is how a resolver becomes a
    // packet engine. `handle_query` used to go straight to `queries.first()`,
    // which a response also has — so two instances pointed at each other, or one
    // spoofed datagram with a forged source, is a self-sustaining loop between
    // them: each reply is parsed as a question and answered with another reply.
    // There is nothing to send back here, because the peer did not ask anything.
    if msg.response {
        return None;
    }

    // Every opcode but QUERY is something this resolver does not implement, and
    // saying so is more useful than answering a NOTIFY or an UPDATE with a
    // plausible QUERY-shaped reply the sender will misread (RFC 1035 §4.1.1).
    if msg.opcode != OpCode::Query {
        return unsupported_opcode(&msg);
    }

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
        Err(_) => return edns_error(id, &query, ResponseCode::FormatError, recursion, client_max),
        Ok(Some(edns)) if edns.version > EDNS_VERSION => {
            return edns_error(
                id,
                &query,
                ResponseCode::BadOptVersion,
                recursion,
                client_max,
            )
        }
        _ => {}
    }
    let client_uses_edns = msg.has_edns();
    // What the client asked for, DNSSEC-wise. DO means "send me the signatures";
    // CD means "don't withhold anything on my behalf, I validate myself".
    let client_wants_dnssec = msg.edns().ok().flatten().is_some_and(|e| e.do_bit);
    let checking_disabled = msg.cd;

    // Names that must not leave this machine (RFC 6761, 6762, 6303). First,
    // before every cache and before any resolution: for these the table *is* the
    // answer, and consulting anything else would mean a query going out.
    //
    // Not skipped for a client with CD set, unlike the denial cache. CD says "do
    // not withhold an answer on my behalf because it failed validation", which is
    // a statement about DNSSEC; it is not a request to be told what a public
    // server thinks `localhost` is.
    if let Some(local) = special_names::lookup(&query.qname, query.qtype) {
        let mut resp = build_response(
            id,
            OpCode::Query,
            &query,
            local.answers,
            local.rcode,
            recursion,
        );
        resp.authorities = local.authority;
        // Never AD: nothing here was validated, it was decided by specification.
        // Claiming otherwise would be the one lie a validating client cannot
        // check for itself.
        resp.ad = false;
        resp.cd = checking_disabled;
        // DEBUG: this is one line per query, with the name asked for on it.
        // Unconditional query logging is a decision an operator makes, not one a
        // default makes for them — see `TODO.md` #9d on what the deleted
        // telemetry module used to do here.
        tracing::debug!(qname = %query.qname, why = %local.why, "answered locally");
        return finish(
            resp,
            client_uses_edns,
            client_wants_dnssec,
            &query,
            client_max,
        );
    }

    // Aggressive use of the validated denial cache (RFC 8198). A cached NSEC
    // does not answer one question, it answers every question in its gap, so
    // this is checked before the answer cache: a flood of random names under one
    // zone costs a single upstream query rather than one per name.
    //
    // A client with CD set has asked us not to filter on its behalf, and an
    // answer we invented from cached proofs is exactly that, so it goes
    // upstream instead.
    // The positive half of RFC 8198 (§5.3): a validated wildcard answer is a
    // signed statement about every name that wildcard reaches, so a name nobody
    // has asked about yet can be answered from it. Checked before the negative
    // synthesis because the two are mutually exclusive by construction — a
    // cached NXDOMAIN needs the wildcard *denied*, so it cannot fire for a name a
    // wildcard governs — and this way the cheaper, more specific answer is tried
    // first.
    if !checking_disabled {
        if let Some(wildcard) = caches
            .denials
            .synthesize_wildcard(&query.qname, query.qtype)
        {
            let mut resp = build_response(
                id,
                OpCode::Query,
                &query,
                wildcard.answers,
                ResponseCode::Ok,
                recursion,
            );
            resp.authorities = wildcard.authority;
            // The wildcard's own signature verifies at this name unchanged —
            // that is what a wildcard signature means — so this is as validated
            // as the answer it came from, and the client can check it itself.
            resp.ad = client_wants_dnssec || msg.ad;
            return finish(
                resp,
                client_uses_edns,
                client_wants_dnssec,
                &query,
                client_max,
            );
        }
    }

    if !checking_disabled {
        if let Some(denial) = caches.denials.synthesize(&query.qname, query.qtype) {
            let mut resp = build_response(
                id,
                OpCode::Query,
                &query,
                Vec::new(),
                denial.rcode,
                recursion,
            );
            resp.authorities = denial.authority;
            // The proofs were validated before they were stored, so the answer
            // derived from them is authentic on the same terms as the original.
            resp.ad = client_wants_dnssec || msg.ad;
            return finish(
                resp,
                client_uses_edns,
                client_wants_dnssec,
                &query,
                client_max,
            );
        }
    }

    // A cached "no" (RFC 2308). Checked alongside the answer cache because it
    // answers the same question the same way — the only reason it is a separate
    // cache is that there are no records to key on. Unlike the denial cache
    // above, nothing here is synthesized: this is the answer this question got,
    // so a CD client may have it too.
    if let Some(negative) = caches.negatives.get(&query.qname, query.qtype) {
        let mut resp = build_response(
            id,
            OpCode::Query,
            &query,
            Vec::new(),
            negative.rcode,
            recursion,
        );
        resp.authorities = negative.authority;
        resp.ad = negative.secure && (client_wants_dnssec || msg.ad);
        resp.cd = checking_disabled;
        return finish(
            resp,
            client_uses_edns,
            client_wants_dnssec,
            &query,
            client_max,
        );
    }

    // Build the response: from cache if we have it, else by resolving.
    let (mut resp, secure) =
        if let Some((records, secure)) = caches.answers.get_validated(&query.qname, query.qtype) {
            (
                build_response(
                    id,
                    OpCode::Query,
                    &query,
                    records,
                    ResponseCode::Ok,
                    recursion,
                ),
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
                        // WARN, not DEBUG: an answer that does not validate is
                        // either an attack or a broken zone, and both are worth
                        // seeing without turning anything up.
                        tracing::warn!(
                            qname = %query.qname,
                            qtype = query.qtype,
                            "DNSSEC validation failed: {why}"
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
                                OpCode::Query,
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
                    // And a validated *positive* answer that came from a wildcard is
                    // the same kind of statement about a range of names (RFC 8198
                    // §5.3), so it is kept too — under the wildcard rather than under
                    // the name that happened to be asked for. Only when Secure, for
                    // exactly the same reason.
                    if !upstream.answers.is_empty() && secure {
                        caches.denials.insert_validated_wildcard(&upstream);
                    }
                    (upstream, secure)
                }
                // Resolution failed: say why, then SERVFAIL. A resolver that turns
                // every failure into a bare SERVFAIL is undiagnosable from the
                // outside, and the reasons here are specific — lame delegation,
                // budget exhausted, CNAME loop — precisely so they can be read.
                Err(ref e) => {
                    // DEBUG: a lookup that fails is ordinary — a typo, a dead
                    // nameserver, a client asking for something that is not
                    // there — and one line per failed query is the flood the
                    // level exists to stop. The SERVFAIL counter is what an
                    // operator alerts on.
                    tracing::debug!(
                        qname = %query.qname,
                        qtype = query.qtype,
                        "resolve failed: {:#}",
                        e
                    );
                    (
                        build_response(
                            id,
                            OpCode::Query,
                            &query,
                            Vec::new(),
                            ResponseCode::ServerFailure,
                            recursion,
                        ),
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

    finish(
        resp,
        client_uses_edns,
        client_wants_dnssec,
        &query,
        client_max,
    )
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
        resp.additionals
            .retain(|rr| rr.rdata.rtype != OPT_RECORD_TYPE);
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
    let mut resp = build_response(id, OpCode::Query, query, Vec::new(), rcode, recursion);
    // BADVERS is an extended RCODE, so the OPT record isn't optional here — it
    // carries the code's high bits.
    resp.set_edns(Edns::with_payload_size(RDNSR_PAYLOAD_SIZE))
        .ok()?;
    resp.to_bytes_within(client_max).ok()
}

/// NOTIMP for an opcode this resolver does not implement.
///
/// The opcode is **echoed**, not replaced with QUERY: RFC 1035 §4.1.1 says it is
/// "set by the originator of a query and copied into the response", and a NOTIFY
/// answered with `opcode = QUERY` is a reply its sender cannot match to what it
/// asked. That is the same reason [`build_response`] takes one rather than
/// assuming.
///
/// The question section is echoed if there was one, and the OPT record mirrored
/// if the client used EDNS (RFC 6891 §6.1.1) — an EDNS client that gets a reply
/// with no OPT may cache us as a server that does not do EDNS, which is a
/// downgrade earned by an unrelated mistake.
fn unsupported_opcode(msg: &DnsMessage) -> Option<Vec<u8>> {
    let mut resp = DnsMessage {
        id: msg.id,
        response: true,
        opcode: msg.opcode,
        authoritive: false,
        truncation: false,
        recursion: msg.recursion,
        recursion_ok: true,
        ad: false,
        cd: msg.cd,
        rcode: ResponseCode::NotImplemented,
        queries: msg.queries.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    if msg.has_edns() {
        resp.set_edns(Edns::with_payload_size(RDNSR_PAYLOAD_SIZE))
            .ok()?;
    }
    resp.to_bytes_within(RDNSR_PAYLOAD_SIZE as usize).ok()
}

/// Build a minimal response message echoing the question section.
///
/// `opcode` is a parameter because it is the client's, not ours (RFC 1035
/// §4.1.1). Every caller here passes QUERY and is right to — `handle_query`
/// refuses anything else before reaching them — but hardcoding it is what made
/// the missing opcode check invisible.
fn build_response(
    id: u16,
    opcode: OpCode,
    query: &QuerySection,
    answers: Vec<ResourceRecord>,
    rcode: ResponseCode,
    recursion: bool,
) -> DnsMessage {
    DnsMessage {
        id,
        response: true,
        opcode,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver that will never be reached: every test below is about a packet
    /// rejected before any resolution is attempted.
    fn context() -> (Arc<Resolver>, Arc<Caches>) {
        let config = ResolverConfig {
            mode: ResolverMode::Forward,
            // Nothing here ever reaches an upstream: every test below is about a
            // packet rejected before resolution is attempted.
            upstream_servers: vec!["127.0.0.1:1".parse().unwrap()],
            ..Default::default()
        };
        (
            Arc::new(Resolver::new(config)),
            Arc::new(Caches {
                answers: DnsCache::new(16),
                negatives: NegativeCache::new(16),
                denials: NsecCache::new(4),
            }),
        )
    }

    fn message(opcode: OpCode, response: bool) -> Vec<u8> {
        let msg = DnsMessage {
            id: 0x1234,
            response,
            opcode,
            authoritive: false,
            truncation: false,
            recursion: true,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: "example.com.".to_string(),
                qtype: record_types::A,
                qclass: rdns::QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let mut buf = vec![0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("serialize");
        buf.truncate(n);
        buf
    }

    /// The packet loop. `handle_query` went straight to `queries.first()`, which
    /// a *response* also has — so two instances pointed at each other, or one
    /// spoofed datagram with a forged source, kept answering each other's
    /// answers for as long as both were up.
    ///
    /// There is nothing to reply with here, so the test is that nothing comes
    /// back at all.
    #[tokio::test]
    async fn a_response_is_dropped_rather_than_resolved() {
        let (resolver, caches) = context();
        let reply = handle_query(
            message(OpCode::Query, true),
            &resolver,
            &caches,
            Transport::Udp,
        )
        .await;
        assert!(
            reply.is_none(),
            "answering a response is how a resolver becomes a packet engine"
        );
    }

    /// An opcode this resolver does not implement is NOTIMP, and the opcode
    /// comes back unchanged — RFC 1035 §4.1.1 says it is "copied into the
    /// response". A NOTIFY answered with `opcode = QUERY` is a reply its sender
    /// cannot match to what it asked.
    #[tokio::test]
    async fn an_unimplemented_opcode_is_notimp_with_the_opcode_echoed() {
        let (resolver, caches) = context();
        for opcode in [OpCode::Notify, OpCode::Update, OpCode::Status] {
            let bytes = handle_query(message(opcode, false), &resolver, &caches, Transport::Udp)
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
}
