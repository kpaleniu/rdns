use rdns::Rtype;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use clap::Parser;
use rdns::dnssec_chain::{TrustAnchors, ValidationState};
use rdns::logging::{watch_anomalies, AnomalyThresholds, LogLevel, QueryLogger};
use rdns::metrics::{DnsMetrics, LatencyTimer};
use rdns::metrics_server;
use rdns::negative_cache::NegativeCache;
use rdns::nsec_cache::NsecCache;
use rdns::readiness::Readiness;
use rdns::resolver::{Resolver, ResolverConfig, ResolverMode, SharedAnchors};
use rdns::response::ClientEdns;
use rdns::rfc5011::{self, AnchorChange, ManagedAnchors};
use rdns::security::{RateLimitConfig, RateLimiter, ResponseLimiter, ResponseVerdict, TransferAcl};
use rdns::shutdown::{Busy, Shutdown, Stop};
use rdns::special_names;
use rdns::utils::current_unix_timestamp;
use rdns::utils::record_types;
use rdns::utils::{recv_error_is_transient, UDP_RECEIVE_BUFFER};
use rdns::validation::{AdmissionCheck, Request};
use rdns::{
    DnsCache, DnsMessage, Edns, OpCode, Qtype, QuerySection, ResourceRecord, ResponseCode,
    OPT_RECORD_TYPE,
};
use rdns_transport::{tcp, ServeContext, Transport, TransportLimits};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;

/// UDP payload size rdnsr advertises to clients via EDNS0.
const RDNSR_PAYLOAD_SIZE: u16 = 4096;

/// UDP queries this resolver will have in flight at once, when nothing says
/// otherwise.
///
/// Not `rdnsd`'s worker count. There, answering is microseconds out of memory;
/// here one query is a recursion — several round trips, seconds of it, almost
/// all spent waiting. So it stays a task per datagram, and this bounds how many
/// may exist.
///
/// 1024 because a task waiting on the network is ~1.5 KB, so the ceiling costs
/// ~1.5 MB fully occupied, and a resolver with a thousand queries outstanding is
/// either very busy or under attack — shedding answers both.
const MAX_INFLIGHT_UDP: usize = 1024;

/// Zones whose validated denial proofs we keep for aggressive use (RFC 8198).
///
/// Zones, not records: one zone's NSEC chain answers for every non-existent
/// name in it. `NsecCache` bounds the records within each zone separately.
const NSEC_CACHE_ZONES: usize = 1000;

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
struct Caches {
    answers: DnsCache,
    negatives: NegativeCache,
    denials: NsecCache,
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
    /// Who owns the file is the difference from `--trust-anchor`, which is read
    /// and never touched. This one is read *and written*: the resolver watches
    /// the zone's signed DNSKEY RRset, adopts a key published continuously for
    /// 30 days, and drops one the zone revokes with a signature from that same
    /// key.
    ///
    /// Created from the anchors in force when it does not exist, so pointing at
    /// a new path is enough to start.
    #[arg(long)]
    auto_trust_anchor: Option<std::path::PathBuf>,
    /// How much to say: error, warn, info, debug or trace.
    ///
    /// Nothing per-query is above `debug`. `RUST_LOG` overrides it, so a
    /// misbehaving resolver can be turned up without a restart into new flags.
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: LogLevel,
    /// Errors only. The same as `--log-level error`, and refused with it.
    #[arg(long, conflicts_with = "log_level")]
    quiet: bool,
    /// How many UDP queries may be in flight at once. Over the ceiling, further
    /// datagrams are dropped.
    ///
    /// No off switch, unlike `--query-rate 0`: a recursion holds its task for
    /// seconds, so unbounded means a flood of one-datagram queries spawns tasks
    /// faster than they retire. 0 is floored to 1, so a mistyped flag is wrong
    /// and not fatal.
    ///
    /// Dropping is silent: a reply to a spoofed source is what an amplifier
    /// sends.
    #[arg(long, value_name = "QUERIES", default_value_t = MAX_INFLIGHT_UDP)]
    max_inflight_udp: usize,
    /// Queries per second, per client address. 0 turns the limit off.
    ///
    /// 200 where `rdnsd`'s is 1000: an authoritative server's clients are
    /// resolvers, and one resolver behind one address legitimately asks orders
    /// of magnitude more than one person does.
    #[arg(long, value_name = "QUERIES_PER_SEC", default_value = "200")]
    query_rate: u32,
    /// How many queries may arrive at once before `--query-rate` applies.
    ///
    /// A DNS client sends its queries in bursts by nature — one page load is
    /// dozens of names at once — so a limiter with no burst allowance drops
    /// traffic that is not a flood at all.
    #[arg(long, value_name = "QUERIES", default_value = "100")]
    query_burst: u32,
    /// An address or CIDR prefix the query rate limit does not apply to,
    /// repeatable.
    ///
    /// For a monitoring probe whose whole job is to query more often than a
    /// client would, and for a forwarder in front of this one. Without it the
    /// only way to spare a known-good source is to raise the limit for everybody.
    #[arg(long, value_name = "ADDR|CIDR")]
    query_rate_exempt: Vec<String>,
    /// How often to report what the last interval's traffic looked like, in
    /// seconds. 0 turns the anomaly warnings off.
    ///
    /// Every threshold below is per interval, so this is also the unit they are
    /// read in: `--anomaly-source-queries 100` at the default is a hundred
    /// queries a minute from one address.
    #[arg(long, value_name = "SECONDS", default_value = "60")]
    anomaly_interval: u64,
    /// Warn above this query rate, averaged over `--anomaly-interval`. 0 is off.
    #[arg(long, value_name = "QUERIES_PER_SEC", default_value = "50")]
    anomaly_query_rate: f64,
    /// Warn when more than this percentage of an interval's queries failed.
    /// 0 is off.
    #[arg(long, value_name = "PERCENT", default_value = "10")]
    anomaly_error_percent: f64,
    /// Warn about a source that sent more than this many queries in one
    /// interval. 0 is off.
    ///
    /// A log line, not a metric: naming the address is the point, and an
    /// address is exactly what a Prometheus label must not be — the cardinality
    /// is the client's to choose.
    #[arg(long, value_name = "QUERIES", default_value = "100")]
    anomaly_source_queries: u64,
    /// Warn about a source the rate limiter refused more than this many times
    /// in one interval. 0 is off.
    #[arg(long, value_name = "REFUSALS", default_value = "5")]
    anomaly_source_refusals: u64,
    /// Response bytes per second, per client address. 0 turns the budget off.
    ///
    /// A resolver needs this more than an authoritative server does: a 30-byte
    /// query can produce a 4 KB validated answer, which `--dnssec-validate`
    /// makes ordinary. Meters what leaves, since that is what an amplification
    /// attack is made of, and UDP only — a TCP query completed a handshake, so
    /// there is nobody to reflect at.
    #[arg(long, value_name = "BYTES_PER_SEC", default_value = "8192")]
    response_rate: u32,
    /// Serve Prometheus metrics and a liveness probe on this address.
    ///
    /// No meaningful `/readyz`: a resolver has nothing to wait for, so it
    /// answers ready as soon as it is up. `metrics_server` serves the route
    /// because it is shared with `rdnsd`.
    #[arg(long, value_name = "ADDR:PORT")]
    metrics_listen: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Before anything with something to say, and through the same initialiser
    // `rdnsd` uses so the two cannot format or filter differently.
    rdns::logging::init(if cli.quiet {
        LogLevel::Error
    } else {
        cli.log_level
    });

    // Before anything is spawned: it owns the only durable state this process
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

    // Fail loudly on a hints file that yields no addresses; falling back to
    // the built-ins would hide the misconfiguration.
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

    // The built-in ICANN root key is the fallback so plain --dnssec-validate
    // works; --trust-anchor overrides it when the root KSK rolls.
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
        // A managed file supersedes the configured anchors: it records what
        // has been *learned* since, including a hold-down 29 days old.
        managed = match &cli.auto_trust_anchor {
            Some(path) => {
                let anchors =
                    ManagedAnchors::load_or_seed(path, &anchors, current_unix_timestamp())?;
                // Now rather than at the first change, so an operator who
                // points at a new path can see what is trusted without waiting
                // a month for something to happen.
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

    // A task of its own: following the anchors resolves, so it needs the
    // resolver and cannot be part of building one.
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

    // `DnsCache::put` is a no-op at 0, so --no-cache is a cache sized to hold
    // nothing. The denial cache is zero without validation too: aggressive use
    // rests on the proofs having been checked.
    let capacity = if cli.no_cache { 0 } else { cli.cache_size };
    let denial_zones = if cli.no_cache || !cli.dnssec_validate {
        0
    } else {
        NSEC_CACHE_ZONES
    };
    let caches = Arc::new(Caches {
        answers: DnsCache::new(capacity),
        // Negative answers are answers: `--no-cache` means no cache.
        negatives: NegativeCache::new(capacity),
        denials: NsecCache::new(denial_zones),
    });

    let addr = format!("{}:{}", cli.host, cli.port);
    // Both transports are mandatory: an answer over the client's UDP payload
    // size gets TC=1, and RFC 1035 §4.2.1 has the client retry over TCP.
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    let listener = TcpListener::bind(&addr).await?;
    // Bound before anything is announced, so a typo in `--metrics-listen`
    // stops the start rather than losing the observability silently.
    let metrics_listener = match &cli.metrics_listen {
        Some(spec) => Some(
            TcpListener::bind(spec)
                .await
                .with_context(|| format!("--metrics-listen {spec}"))?,
        ),
        None => None,
    };

    let query_limit = RateLimitConfig::per_second(cli.query_rate, cli.query_burst).exempting(
        TransferAcl::parse_named(&cli.query_rate_exempt, "--query-rate-exempt")?,
    );
    let ctx = Arc::new(ServeContext {
        limiter: Arc::new(RateLimiter::new(query_limit)),
        responses: Arc::new(ResponseLimiter::per_second(cli.response_rate)),
        metrics: Arc::new(DnsMetrics::new()),
        logger: Arc::new(QueryLogger::new()),
        validator: Arc::new(AdmissionCheck::with_defaults()),
    });
    tracing::info!(
        "rdnsr listening on {} (UDP+TCP), {}, cache: {}{}, UDP in flight: {}",
        addr,
        source,
        if capacity == 0 {
            "disabled".to_string()
        } else {
            format!("{capacity} entries")
        },
        dnssec_source,
        // Printed because the drops it causes are silent.
        cli.max_inflight_udp.max(1),
    );
    // And the two limits, for the same reason: both drop in silence, so an
    // operator who cannot see the policy blames the network.
    let anomaly_interval = Duration::from_secs(cli.anomaly_interval);
    let anomaly_thresholds = AnomalyThresholds {
        queries_per_second: cli.anomaly_query_rate,
        error_percent: cli.anomaly_error_percent,
        queries_per_source: cli.anomaly_source_queries,
        refusals_per_source: cli.anomaly_source_refusals,
    };
    tracing::info!(
        "query rate: {}, response budget: {}, metrics: {}, anomaly warnings: {}",
        if cli.query_rate == 0 {
            "unlimited (--query-rate 0)".to_string()
        } else {
            format!(
                "{}/s per client, burst {}{}",
                cli.query_rate,
                cli.query_burst,
                if cli.query_rate_exempt.is_empty() {
                    String::new()
                } else {
                    format!(", {} exempt", cli.query_rate_exempt.len())
                }
            )
        },
        if cli.response_rate == 0 {
            "off (--response-rate 0)".to_string()
        } else {
            format!("{} bytes/s per client", cli.response_rate)
        },
        match &cli.metrics_listen {
            Some(spec) => format!("{spec}/metrics"),
            None => "off (--metrics-listen)".to_string(),
        },
        if anomaly_interval.is_zero() {
            "off (--anomaly-interval 0)".to_string()
        } else {
            format!(
                "every {}s (>{} q/s, >{}% errors, >{} q/source, >{} refusals/source)",
                anomaly_interval.as_secs(),
                anomaly_thresholds.queries_per_second,
                anomaly_thresholds.error_percent,
                anomaly_thresholds.queries_per_source,
                anomaly_thresholds.refusals_per_source
            )
        },
    );

    // A `JoinSet` rather than two `JoinHandle`s in a `select!`: dropping the
    // loser detaches the task rather than cancelling it, so `main` returns with
    // the other transport still reading
    // and replies still queued in a per-connection `mpsc`. `join_next` is
    // cancel-safe, so first-one-wins keeps both tasks owned and joinable.
    // Outside the `JoinSet`: that set ends the process when its first task ends,
    // and this one ends on the stop signal by design. Joined after the drain, so
    // it is not a detached task (`CLAUDE.md` §9).
    let anomalies = tokio::spawn(watch_anomalies(
        ctx.logger.clone(),
        anomaly_thresholds,
        anomaly_interval,
        shutdown.stop_handle(),
    ));

    let mut loops = JoinSet::new();
    loops.spawn(udp_main(
        socket,
        resolver.clone(),
        caches.clone(),
        ctx.clone(),
        cli.max_inflight_udp,
        shutdown.stop_handle(),
        shutdown.busy(),
    ));
    // Per connection, not per message: a resolver's clients open a connection
    // and ask a few things (`TODO.md` #30e).
    loops.spawn(tcp::serve(
        listener,
        Arc::new(Resolving {
            resolver,
            caches,
            ctx: ctx.clone(),
        }),
        TransportLimits::default(),
        tcp::RateLimit::PerConnection,
        shutdown.stop_handle(),
        shutdown.busy(),
    ));
    // A listener like the others: if it dies, the process does. Metrics that
    // silently stopped are worse than a resolver that is plainly down.
    if let Some(metrics_listener) = metrics_listener {
        // Both handles taken *here*, not before the `if`: a `Busy` clone that
        // nothing moves into a task is one `main` holds for the life of the
        // process, so the drain never reaches zero and every shutdown waits out
        // its whole budget before exiting — which is what this daemon did with
        // no `--metrics-listen`, which is the default.
        let (stop, busy) = (shutdown.stop_handle(), shutdown.busy());
        loops.spawn(async move {
            metrics_server::serve(
                metrics_listener,
                ctx.metrics.clone(),
                // Nothing to wait for: a resolver is ready as soon as it is
                // up.
                Readiness::ready(),
                stop,
                busy,
            )
            .await
        });
    }

    // Whichever listener ends first ends the process rather than leaving one
    // transport served; what the drain then waits for here is a resolution a
    // client is waiting on, or the RFC 5011 manager part-way through rewriting
    // the anchor file.
    rdns_transport::serve_until_stopped(loops, anomalies, shutdown).await
}

/// Follow the managed zones' DNSKEY RRsets and keep the anchors in step
/// (RFC 5011).
///
/// One task, not one per zone: the zones share a file, and one file wants one
/// writer.
fn spawn_anchor_manager(
    resolver: Arc<Resolver>,
    anchors: SharedAnchors,
    mut managed: ManagedAnchors,
    path: std::path::PathBuf,
    stop: Stop,
    busy: Busy,
) {
    tokio::spawn(async move {
        // Soon after start, not immediately: a resolver that cannot answer
        // its own first query would spend a retry.
        let mut wait = Duration::from_secs(60);
        loop {
            // No `Busy` across the sleep, which is hours long — only across
            // the probe-and-save, where the file is rewritten.
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
                        let Ok(zone_name) = rdns::Name::from_presentation(&zone) else {
                            continue;
                        };
                        let changes = managed.observe(
                            zone_name.as_ref(),
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
                // File first: validating against keys not yet recorded would
                // forget them on restart.
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
/// Secure or nothing. Insecure or Indeterminate for a zone we hold an anchor
/// for is not a zone gone unsigned but an answer we could not tie to the anchor,
/// and adopting keys from one adopts whatever answered. `ManagedAnchors::observe`
/// requires this and cannot check it itself.
async fn probe_zone(resolver: &Resolver, zone: &str) -> anyhow::Result<AnchorProbe> {
    let query = QuerySection {
        qname: rdns::Name::from_presentation(zone)
            .with_context(|| format!("{zone:?} is not a domain name"))?,
        qtype: Qtype::of(record_types::DNSKEY),
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

    // From the RRSIG covering the set: how long to cache it, and how long the
    // signature has left.
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
        self_signers: rfc5011::self_signers(query.qname.as_ref(), &response.answers, now),
        keys,
        original_ttl,
        signature_remaining,
    })
}

/// INFO throughout: a key rolls over months, so there is no volume in it, and
/// it is what an operator reconstructs a DNSSEC incident from.
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
fn truncate_reply(reply: &[u8]) -> Option<Vec<u8>> {
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

/// Receive datagrams and resolve each in its own task, up to `max_inflight`.
///
/// The permit is taken *before* the packet is copied and the task created — see
/// [`MAX_INFLIGHT_UDP`] for why a resolver spawns per datagram at all.
/// `try_acquire`, not `acquire`: waiting would move the queue from the kernel's
/// receive buffer into a pile of tasks holding copies. For UDP, shedding is the
/// back-pressure.
async fn udp_main(
    socket: Arc<UdpSocket>,
    resolver: Arc<Resolver>,
    caches: Arc<Caches>,
    ctx: Arc<ServeContext>,
    max_inflight: usize,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    // Floored, not refused: nobody means "answer nothing".
    let in_flight = Arc::new(Semaphore::new(max_inflight.max(1)));
    // Sized for any datagram a client may send, not the payload size we
    // advertise: on Windows an oversized one fails the receive rather than
    // truncating, and a failed receive ends this loop.
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
            // An ICMP report about a datagram already sent, or one that did
            // not fit: neither says anything about this socket. Shared with
            // `rdnsd` — see `recv_error_is_transient`.
            Err(e) if recv_error_is_transient(&e) => continue,
            Err(e) => return Err(e),
        };
        // First, because it is the cheapest rejection and the one a flood
        // should hit: a hash lookup and a token, before the packet is looked
        // at. Dropping is silent, which is why the policy is printed at startup
        // and counted here.
        //
        // One read for the limiter and the query log, which happen within
        // microseconds of each other; the response budget reads its own, since a
        // recursion sits in between (`TODO.md` #28a).
        let now = current_unix_timestamp();
        if !ctx.allow_source(peer.ip(), now) {
            continue;
        }
        // Then the structural checks, on bytes nothing has trusted yet.
        if !ctx.accept_packet(peer.ip(), &buf[..n], Transport::Udp) {
            continue;
        }
        // Before the copy, the clones and the task: at the ceiling a datagram
        // costs one comparison. The semaphore is never closed, so the only
        // failure is "full".
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            tracing::debug!(%peer, "dropped: {max_inflight} UDP queries already in flight");
            ctx.metrics.count(&ctx.metrics.queries_dropped);
            continue;
        };
        let data = buf[..n].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        let caches = caches.clone();
        // A recursion takes seconds and the client is already waiting, so it
        // is worth the drain.
        let busy = busy.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _busy = busy;
            let _permit = permit;
            if let Some(reply) = handle_query(
                data,
                peer.ip(),
                now,
                &resolver,
                &caches,
                &ctx,
                Transport::Udp,
            )
            .await
            {
                // Charge the response, not the query. Over budget, TC=1 is
                // the useful refusal: no records to amplify, and a real client
                // retries over TCP where the handshake proves who it is.
                // Its own clock read, not the one the limiter used above: a
                // recursive resolution sits in between and can take seconds, so
                // sharing that instant would deny the bucket the refill the wait
                // earned it.
                match ctx.admit_response(peer.ip(), reply.len(), current_unix_timestamp()) {
                    ResponseVerdict::Send => {
                        let _ = socket.send_to(&reply, peer).await;
                    }
                    ResponseVerdict::Truncate => {
                        if let Some(short) = truncate_reply(&reply) {
                            let _ = socket.send_to(&short, peer).await;
                        }
                    }
                    ResponseVerdict::Drop => {}
                }
            }
        });
    }
}

/// What answers a query on this resolver, for the shared TCP transport.
///
/// The three handles `handle_query` needs, in one place so the transport can
/// hold them: it is generic over the handler and knows nothing about resolving.
struct Resolving {
    resolver: Arc<Resolver>,
    caches: Arc<Caches>,
    ctx: Arc<ServeContext>,
}

impl tcp::Handler for Resolving {
    fn context(&self) -> &ServeContext {
        &self.ctx
    }

    /// One reply or none, into a sink that can carry several — a resolver never
    /// sends more than one, and the shape is `rdnsd`'s AXFR's (`TODO.md` #30a).
    async fn handle(
        &self,
        packet: Vec<u8>,
        peer: SocketAddr,
        now: u64,
        out: mpsc::Sender<tcp::Reply>,
    ) {
        if let Some(reply) = handle_query(
            packet,
            peer.ip(),
            now,
            &self.resolver,
            &self.caches,
            &self.ctx,
            Transport::Tcp,
        )
        .await
        {
            tcp::send_framed(&out, &reply).await;
        }
    }
}

/// Resolve one datagram: cache lookup, else forward upstream and cache-store.
/// Returns the wire bytes to send back, or `None` if the query was unparseable
/// (in which case we simply drop it, as a resolver should).
async fn handle_query(
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
    // DO means "send me the signatures"; CD means "don't withhold anything on
    // my behalf, I validate myself", which is the message's own bit.
    let client_wants_dnssec = client_edns.do_bit();
    let checking_disabled = msg.cd;

    // RFC 9619 §4: "A DNS message with OPCODE = 0 MUST NOT include a QDCOUNT
    // parameter whose value is greater than 1", and one that does "MUST be
    // treated as an incorrectly formatted message" — one RCODE and one set of
    // sections cannot describe two lookups. `rdnsd` has refused it since #9f;
    // this answered the first question and echoed one, so the reply did not
    // match the request either (`TODO.md` #30r).
    if msg.queries.len() > 1 {
        let resp = build_response(&msg, Vec::new(), ResponseCode::FormatError);
        return finish(resp, client_edns, &query, client_max, ctx, timer);
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
        // Never AD: this was decided by specification, not validated, and a
        // validating client cannot check the claim for itself.
        resp.ad = false;
        // DEBUG: one line per query, with the name on it. Logging every query
        // is the operator's decision, not the default's.
        tracing::debug!(qname = %query.qname, why = %local.why, "answered locally");
        return finish(resp, client_edns, &query, client_max, ctx, timer);
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
            .synthesize_wildcard(&query.qname.as_ref().to_presentation(), query.qtype)
        {
            let mut resp = build_response(&msg, wildcard.answers, ResponseCode::Ok);
            resp.authorities = wildcard.authority;
            // A wildcard signature verifies at this name unchanged, so the
            // client can check this for itself.
            resp.ad = client_wants_dnssec || msg.ad;
            return finish(resp, client_edns, &query, client_max, ctx, timer);
        }
    }

    if !checking_disabled {
        if let Some(denial) = caches
            .denials
            .synthesize(&query.qname.as_ref().to_presentation(), query.qtype)
        {
            ctx.metrics.count(&ctx.metrics.cache_hits);
            let mut resp = build_response(&msg, Vec::new(), denial.rcode);
            resp.authorities = denial.authority;
            // The proofs were validated before storage, so what is derived
            // from them is authentic on the same terms.
            resp.ad = client_wants_dnssec || msg.ad;
            return finish(resp, client_edns, &query, client_max, ctx, timer);
        }
    }

    // A cached "no" (RFC 2308), separate from the answer cache only because
    // there are no records to key on. Nothing is synthesized — this is the
    // answer this question got — so a CD client may have it too.
    if let Some(negative) = caches
        .negatives
        .get(&query.qname.as_ref().to_presentation(), query.qtype)
    {
        ctx.metrics.count(&ctx.metrics.cache_hits);
        let mut resp = build_response(&msg, Vec::new(), negative.rcode);
        resp.authorities = negative.authority;
        resp.ad = negative.secure && (client_wants_dnssec || msg.ad);
        return finish(resp, client_edns, &query, client_max, ctx, timer);
    }

    // Build the response: from cache if we have it, else by resolving.
    let (mut resp, secure) = if let Some((records, secure)) = caches
        .answers
        .get_validated(&query.qname.as_ref().to_presentation(), query.qtype)
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
                        return finish(resp, client_edns, &query, client_max, ctx, timer);
                    }
                }

                let secure = state.is_secure();
                // A bogus answer in the cache is an attack that outlives
                // the query that carried it.
                if !upstream.answers.is_empty() && !state.is_bogus() {
                    caches.answers.put_validated(
                        &query.qname.as_ref().to_presentation(),
                        query.qtype,
                        upstream.answers.clone(),
                        secure,
                    );
                }
                // A "no" is an answer; re-resolving it makes a typo storm
                // cost one upstream walk per repeat. The SOA in the
                // authority section says how long it is good for (RFC 2308).
                if !state.is_bogus() {
                    caches.negatives.insert(
                        &query.qname.as_ref().to_presentation(),
                        query.qtype,
                        &upstream,
                        secure,
                    );
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

    // AD only for an answer actually authenticated, and only for a client that
    // asked (RFC 6840 §5.8).
    resp.ad = secure && (client_wants_dnssec || msg.ad);
    resp.cd = checking_disabled;

    finish(resp, client_edns, &query, client_max, ctx, timer)
}

/// Final shaping common to every reply: OPT mirroring, stripping DNSSEC records
/// a client did not ask for, and the size limit.
fn finish(
    mut resp: DnsMessage,
    client_edns: ClientEdns,
    query: &QuerySection,
    client_max: usize,
    ctx: &ServeContext,
    timer: LatencyTimer,
) -> Option<Vec<u8>> {
    // Here because this is where every ordinary answer leaves, whatever
    // produced it: cache, denial cache, negative cache or a full recursion.
    ctx.record_answer(resp.rcode, timer);
    // No DO, no DNSSEC records (RFC 4035 §3.2.1). Records asked for by type
    // are a different matter and stay.
    if !client_edns.do_bit() {
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
    if let Some(edns) = client_edns.mirror(RDNSR_PAYLOAD_SIZE) {
        resp.set_edns(edns);
    } else {
        resp.additionals
            .retain(|rr| rr.rdata.rtype() != OPT_RECORD_TYPE);
    }

    // Honor the client's advertised UDP size: truncates (TC=1) if it overflows.
    resp.to_bytes_within(client_max).ok()
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
    if msg.has_edns() {
        resp.set_edns(Edns::with_payload_size(RDNSR_PAYLOAD_SIZE));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A name from a literal, for tests only: `Name` is fallible to build and a
    /// test that writes a bad one should fail loudly at that line.
    #[allow(dead_code)]
    fn nm(text: &str) -> rdns::Name {
        text.parse().expect("a test name parses")
    }

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// Never reached: every test below is about a packet rejected before any
    /// resolution is attempted.
    /// A source over its query rate is dropped, and the drop is counted. Both
    /// halves: silence is right, because a reply to a spoofed source is what an
    /// amplifier sends, which is exactly why the counter has to exist.
    ///
    /// Watched failing without the limiter check: all four datagrams answered,
    /// `rate_limited` at 0.
    #[tokio::test]
    async fn a_source_over_its_query_rate_is_dropped_and_counted() {
        let (resolver, caches) = context();

        // One per second, burst of one: the second datagram in a burst is over
        // the limit whatever the clock does.
        let ctx = Arc::new(ServeContext {
            limiter: Arc::new(RateLimiter::new(RateLimitConfig::per_second(1, 1))),
            responses: Arc::new(ResponseLimiter::disabled()),
            metrics: Arc::new(DnsMetrics::new()),
            logger: Arc::new(QueryLogger::new()),
            validator: Arc::new(AdmissionCheck::with_defaults()),
        });
        let metrics = ctx.metrics.clone();

        let shutdown = Shutdown::new();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let addr = socket.local_addr().expect("addr");
        let server = tokio::spawn(udp_main(
            socket,
            resolver,
            caches,
            ctx,
            16,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
        for _ in 0..4 {
            client
                .send_to(&message(OpCode::Query, false), addr)
                .await
                .expect("send");
        }
        // Long enough for the loop to have taken all four off the socket.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            metrics.rate_limited.load(std::sync::atomic::Ordering::Relaxed) >= 3,
            "three of four datagrams are over a burst of one, and each drop is              counted: {}",
            metrics.rate_limited.load(std::sync::atomic::Ordering::Relaxed)
        );

        shutdown.begin();
        let _ = server.await;
    }

    /// The escape hatch, for a monitoring probe whose job is to query more
    /// often than a client would.
    #[test]
    fn an_exempt_source_is_not_rate_limited() {
        let limiter = RateLimiter::new(
            RateLimitConfig::per_second(1, 1)
                .exempting(TransferAcl::parse_named(&["127.0.0.1".to_string()], "--test").unwrap()),
        );
        let exempt: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let other: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..10 {
            assert!(
                limiter.should_allow(exempt, current_unix_timestamp()),
                "an exempt source never trips"
            );
        }
        assert!(limiter.should_allow(other, current_unix_timestamp()));
        assert!(
            !limiter.should_allow(other, current_unix_timestamp()),
            "and a source that is not exempt still does"
        );
    }

    /// A reply over the response budget comes back truncated rather than whole:
    /// TC=1 carries no records, so it cannot amplify, and RFC 1035 §4.2.1 has
    /// the client retry over TCP where the handshake proves the address.
    #[test]
    fn a_truncated_reply_carries_no_records_and_keeps_its_question() {
        let request = rdns::DnsMessageBuilder::new()
            .with_id(0x4242)
            .with_query(
                nm("www.example.com."),
                Qtype::of(rdns::utils::record_types::A),
            )
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

    /// Whose queries these are, where the test does not care.
    const TEST_PEER: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7));

    /// A ctx with every limit off, so a test measures the thing it names and
    /// not the rate limiter.
    fn test_shell() -> Arc<ServeContext> {
        Arc::new(ServeContext {
            limiter: Arc::new(RateLimiter::new(RateLimitConfig::per_second(0, 0))),
            responses: Arc::new(ResponseLimiter::disabled()),
            metrics: Arc::new(DnsMetrics::new()),
            logger: Arc::new(QueryLogger::new()),
            validator: Arc::new(AdmissionCheck::with_defaults()),
        })
    }

    fn context() -> (Arc<Resolver>, Arc<Caches>) {
        let config = ResolverConfig {
            mode: ResolverMode::Forward,
            // Nothing here reaches an upstream.
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
                qname: nm("example.com."),
                qtype: Qtype::of(record_types::A),
                qclass: rdns::QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        };
        let mut buf = vec![0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("serialize");
        buf.truncate(n);
        buf
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

    /// An UPDATE carrying `additionals` additional records, which
    /// `handle_query` answers NOTIMP out of the message alone. Five is one over
    /// `AdmissionCheck`'s cap for a request.
    fn update_with_additionals(id: u16, additionals: usize) -> Vec<u8> {
        let mut msg = DnsMessage::try_from_bytes(&message(OpCode::Update, false)).expect("parses");
        msg.id = id;
        msg.additionals = vec![
            ResourceRecord {
                name: nm("example.com."),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(60),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                    "192.0.2.1".parse().unwrap(),
                ))
                .unwrap(),
            };
            additionals
        ];
        let mut buf = vec![0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("serialize");
        buf.truncate(n);
        buf
    }

    /// The admission check runs on TCP as well. It ran on one of the two
    /// transports (`TODO.md` #30q), so the 16 KiB ceiling, the QDCOUNT cap and
    /// the per-section counts all stopped at the UDP loop.
    ///
    /// Provoked with the additional-count cap because it is the cheapest of
    /// those rules to build; the check is one call, so any rule of it firing is
    /// the whole check running. Both messages are UPDATEs, answered from the
    /// message alone — no cache, no upstream — so a missing reply is a drop
    /// rather than a timeout somewhere else, and the second one is what says
    /// the connection survived the first.
    ///
    /// Watched failing with the check removed: the reply carried 0xBAD1.
    #[tokio::test]
    async fn a_tcp_message_over_the_admission_caps_is_dropped_and_the_connection_kept() {
        let (resolver, caches) = context();
        let ctx = test_shell();
        let metrics = ctx.metrics.clone();

        let shutdown = Shutdown::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(tcp::serve(
            listener,
            Arc::new(Resolving {
                resolver,
                caches,
                ctx,
            }),
            TransportLimits::default(),
            tcp::RateLimit::PerConnection,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let mut client = TcpStream::connect(addr).await.expect("connect");
        for message in [
            update_with_additionals(0xBAD1, 5),
            update_with_additionals(0x600D, 1),
        ] {
            client
                .write_all(&rdns::framed(&message).expect("frames"))
                .await
                .expect("send");
        }

        let mut prefix = [0u8; 2];
        client.read_exact(&mut prefix).await.expect("one reply");
        let mut reply = vec![0u8; u16::from_be_bytes(prefix) as usize];
        client.read_exact(&mut reply).await.expect("its body");
        let reply = DnsMessage::try_from_bytes(&reply).expect("a well-formed reply");
        assert_eq!(
            reply.id, 0x600D,
            "0xBAD1 is over the cap and must not be answered"
        );
        assert_eq!(reply.rcode, ResponseCode::NotImplemented);
        assert_eq!(
            metrics
                .validation_errors
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "and the drop is counted, since it is silent on the wire"
        );

        shutdown.begin();
        let _ = server.await;
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

    /// A datagram arriving with the in-flight ceiling already reached is
    /// dropped, and dropped *before* it is copied and given a task.
    ///
    /// Neither half is a race. Forwarding to an upstream that never answers
    /// holds the only permit for the whole test, and the black hole *receiving*
    /// that query is the proof it does. The second datagram is an UPDATE, which
    /// `handle_query` answers with NOTIMP out of the message alone — no cache,
    /// no network — so "no reply" means dropped at the door.
    ///
    /// Watched failing with the `try_acquire_owned` removed: the NOTIMP came
    /// straight back.
    #[tokio::test]
    async fn a_datagram_over_the_in_flight_ceiling_is_dropped() {
        let black_hole = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let upstream = black_hole.local_addr().expect("addr");
        let resolver = Arc::new(Resolver::new(ResolverConfig {
            mode: ResolverMode::Forward,
            upstream_servers: vec![upstream],
            // Long enough that the first query is still outstanding at the
            // end of the test.
            timeout_ms: 30_000,
            ..Default::default()
        }));
        let (_, caches) = context();

        let shutdown = Shutdown::new();
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let addr = socket.local_addr().expect("addr");
        let server = tokio::spawn(udp_main(
            socket,
            resolver,
            caches,
            test_shell(),
            1,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
        client
            .send_to(&message(OpCode::Query, false), addr)
            .await
            .expect("send the query that takes the permit");
        // The forwarded query landing here is what makes the permit
        // definitely held rather than probably held.
        let mut buf = vec![0u8; 512];
        black_hole
            .recv_from(&mut buf)
            .await
            .expect("the query was forwarded, so the permit is taken");

        client
            .send_to(&message(OpCode::Update, false), addr)
            .await
            .expect("send the query that must be dropped");
        let waited = tokio::time::timeout(Duration::from_millis(500), client.recv_from(&mut buf))
            .await
            .is_ok();
        assert!(
            !waited,
            "a NOTIMP came back, so the datagram was answered rather than shed — \
             it costs microseconds to build, and half a second is a thousand times that"
        );

        shutdown.begin();
        // The worker is parked in `recv_from`, which the stop cancels. The
        // resolving task is what the drain is for; this test does not wait out
        // its thirty seconds.
        let _ = server.await;
    }
}
