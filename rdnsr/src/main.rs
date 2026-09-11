//! `rdnsr` — the recursive resolver: UDP and TCP on one port, bound to
//! localhost by default, because an open resolver is somebody else's
//! amplifier.
//!
//! This root is the CLI and the startup order, and nothing else: the three
//! modules under it are [`anchors`] (the trust anchors and RFC 5011's rolling),
//! [`answer`] (a datagram in, the reply out — no sockets) and [`serve`] (the two
//! socket loops and the shutdown). One `Resolver` with a mode rather than two
//! programs; the reasoning is `TODO.md`'s "Architecture: the resolver".

mod anchors;
mod answer;
mod serve;
#[cfg(test)]
mod testutil;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use clap::Parser;
use rdns::clock::current_unix_timestamp;
use rdns::dnssec_chain::TrustAnchors;
use rdns::logging::{watch_anomalies, AnomalyThresholds, LogLevel, QueryLogger};
use rdns::metrics::DnsMetrics;
use rdns::metrics_server;
use rdns::readiness::Readiness;
use rdns::resolver::{Resolver, ResolverConfig, ResolverMode, SharedAnchors};
use rdns::rfc5011::ManagedAnchors;
use rdns::security::{RateLimitConfig, RateLimiter, ResponseLimiter, TransferAcl};
use rdns::shutdown::Shutdown;
use rdns::validation::{AdmissionCheck, AdmissionLimits};
use rdns::UdpSizes;
use rdns_transport::{tcp, ServeContext, TransportLimits};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;

use crate::anchors::spawn_anchor_manager;
use crate::answer::Caches;
use crate::serve::{udp_main, Resolving};

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
    /// Largest UDP request accepted, in octets.
    ///
    /// Floored at the payload size this resolver advertises it can reassemble
    /// (RFC 6891 §6.2.4): refusing under what was advertised is a promise broken
    /// in silence (`TODO.md` #40f). A client's padded query (RFC 8467) is the
    /// request here that grows, where `rdnsd`'s is a signed UPDATE.
    #[arg(long, value_name = "OCTETS", default_value = "4096")]
    max_udp_request: u16,
    /// Largest TCP request accepted, in octets. Not a protocol limit — the
    /// length prefix allows 65,535 — but a query has no reason to be large.
    #[arg(long, value_name = "OCTETS", default_value = "16384")]
    max_tcp_request: u16,
    /// UDP payload size advertised to clients in every reply's OPT, in octets.
    ///
    /// What this resolver says it can reassemble (RFC 6891 §6.2.3), in both
    /// directions: to its clients in every reply's OPT, and to the authoritative
    /// servers it asks. One number because it is a fact about this host's stack
    /// rather than about who is being told, which is how Unbound's
    /// `edns-buffer-size` reads. It also floors `--max-udp-request`.
    ///
    /// 1232 is the default of BIND's `edns-udp-size`, Knot's `udp-max-payload`,
    /// NSD's `ipv4-edns-size` and Unbound's `edns-buffer-size` after DNS Flag
    /// Day 2020. Not the size an upstream answer is read into, which is
    /// separate since `TODO.md` #41c. Floored at 512.
    #[arg(long, value_name = "OCTETS", default_value = "1232")]
    udp_payload_size: u16,
    /// Largest UDP reply this resolver will send, in octets.
    ///
    /// The client's own advertisement is honoured only down to this: above it
    /// the reply fragments, and a fragment is what middleboxes drop. Over the
    /// cap the reply is an empty TC=1 and the client asks again over TCP, which
    /// is never capped. 65535 is "whatever the client asked for"; floored at
    /// 512.
    #[arg(long, value_name = "OCTETS", default_value = "1232")]
    max_udp_response: u16,
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

    // What this host can reassemble and the largest datagram it will send. One
    // advertisement, in both directions: the number is a fact about this stack,
    // not about who is being told, which is how Unbound's `edns-buffer-size`
    // reads too (`TODO.md` #41c).
    let udp = UdpSizes::new(cli.udp_payload_size, cli.max_udp_response);

    // Recursion is the default; naming an upstream is what selects forwarding.
    let mut config = ResolverConfig {
        udp_payload_size: udp.advertised(),
        ..ResolverConfig::default()
    };
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

    // What the two flags mean for each cache is `Caches::new`'s to say.
    let capacity = if cli.no_cache { 0 } else { cli.cache_size };
    let denial_zones = if cli.no_cache || !cli.dnssec_validate {
        0
    } else {
        NSEC_CACHE_ZONES
    };
    let caches = Arc::new(Caches::new(capacity, denial_zones));

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
    // Floored at what this resolver advertises, for the reason
    // `--max-udp-request` gives: the advertisement is a promise.
    let admission = AdmissionLimits::new(
        cli.max_udp_request.max(udp.advertised()) as usize,
        cli.max_tcp_request as usize,
    );
    let ctx = Arc::new(ServeContext {
        udp,
        limiter: Arc::new(RateLimiter::new(query_limit)),
        responses: Arc::new(ResponseLimiter::per_second(cli.response_rate)),
        metrics: Arc::new(DnsMetrics::new()),
        logger: Arc::new(QueryLogger::new()),
        validator: Arc::new(AdmissionCheck::new(admission.clone())),
    });
    tracing::info!(
        "rdnsr listening on {} (UDP+TCP), {}, cache: {}{}, \
         UDP reply cap: {}B (advertising {}B), UDP in flight: {}",
        addr,
        source,
        if capacity == 0 {
            "disabled".to_string()
        } else {
            format!("{capacity} entries")
        },
        dnssec_source,
        udp.max_response(),
        udp.advertised(),
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
    let (udp_cap, tcp_cap) = admission.caps();
    tracing::info!(
        "query rate: {}, response budget: {}, request cap: {udp_cap}B UDP / {tcp_cap}B TCP,          metrics: {}, anomaly warnings: {}",
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
