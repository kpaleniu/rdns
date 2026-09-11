//! `rdnsd` — the authoritative server: UDP and TCP from one process.
//!
//! One process because anything that writes state — a fetched zone, a refresh
//! timestamp, a journal — needs a single owner.
//!
//! What stays in this root is the shell around the answering: the CLI, startup's
//! order (config, secrets, zones, signing, verification, then a socket), the two
//! socket loops, the reload and maintenance timers, and NOTIFY going *out*. What
//! #20 and #38d lifted out of it, one seam per commit, is [`zones`] (where a zone
//! comes from and how it is swapped in), [`replication`] (being a secondary),
//! [`dispatch`] (one request in, its reply on the wire), [`answer`] (what a name
//! deserves, with no sockets in it), [`config`] and — Unix only, so spelled rather
//! than linked — `control`.
//!
//! Every listening socket this binary binds is bound here or in `control`, and
//! nothing below them decides to exit. A change about *what an answer is* belongs
//! two modules down.

mod answer;
mod config;
/// Control socket. Needs a Unix domain socket, so Unix only.
#[cfg(unix)]
mod control;
/// Answering one request, on either transport.
mod dispatch;
mod replication;
#[cfg(test)]
mod testutil;
mod zones;

use replication::{
    parse_secondary_specs, spawn_secondaries, withdraw_unvouched_zones, ReplicationContext,
    Secondaries,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zones::{
    discard_orphan_journals, install_all_zones, load_zones_from_source, note_serials,
    restore_journals, validate_zone_source, verify_zones, ZoneContext, ZoneMap, ZoneSigning,
    ZoneSource, Zones,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rdns::compression::NameCompressor;
use rdns::{
    dnssec::{DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE},
    dnssec_key::{SigningAlgorithm, SigningKey},
    dnssec_validation_mode::DnssecValidator,
    ixfr::DeltaLog,
    journal::Journal,
    logging::{watch_anomalies, AnomalyThresholds, LogLevel, QueryLogger},
    metrics::DnsMetrics,
    metrics_server, notify,
    readiness::Readiness,
    secondary::{state_file_path, MasterSpec, StateFile},
    security::{RateLimitConfig, RateLimiter, ResponseLimiter, TransferAcl},
    shutdown::{Busy, Lifecycle, Shutdown, Stop},
    socket::bind_addr_for,
    tsig::{self, TsigKeyring},
    validation::{AdmissionCheck, Transport},
    zone::Zone,
    DnsMessage, ResourceRecord, Serial,
};
use rdns::{Name, NameRef};
// Test-only since `TODO.md` #38d moved the transfer and UPDATE answering, which
// were the non-test callers, into `dispatch`.
#[cfg(test)]
use rdns::{clock::current_unix_timestamp, zone::parse_zone_file_at};
use rdns_transport::tcp;
use rdns_transport::{recv_error_is_transient, ServeContext, TransportLimits, UDP_RECEIVE_BUFFER};

/// UDP payload size rdnsd advertises to clients via EDNS0.
const RDNSD_PAYLOAD_SIZE: u16 = 4096;

/// Default for `--udp-workers`: the machine's parallelism, clamped to 2..=32.
///
/// A worker spends microseconds of CPU per datagram, so useful parallelism is
/// the machine's; past 32 this buys receive buffers ([`UDP_RECEIVE_BUFFER`]
/// each) rather than throughput. `available_parallelism` and not `num_cpus`:
/// std, and it respects cgroup quotas and affinity masks.
pub(crate) fn default_udp_workers() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(2)
        .clamp(2, 32)
}

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinSet;

#[cfg(unix)]
use tokio::signal::unix::{signal, Signal, SignalKind};

// Both macros are re-exported with `pub(crate) use` rather than left to
// `macro_rules!`'s textual scoping, which would force `mod dispatch;` below this
// point; `#[macro_export]` would widen them to the crate's public surface
// instead (`TODO.md` #39d).

/// A peer sent something we could not use: a malformed packet, a truncated TCP
/// message, a response arriving at a listening socket.
///
/// DEBUG on purpose: these are the paths a flood goes through, so the message
/// must not be formatted unless somebody asked for it. The default signal is
/// the counter (`dns_errors_total`).
macro_rules! bad_request {
    ($logger:expr, $ip:expr, $($arg:tt)*) => {{
        $logger.count_error($ip);
        tracing::debug!(peer = %$ip, $($arg)*);
    }};
}
pub(crate) use bad_request;

/// A refusal we decided on, or a failure that is ours.
///
/// WARN, because unlike [`bad_request`] none of these is attacker-triggerable
/// in volume. Both macros count, so `total_errors` means "requests that did not
/// get a normal answer" whichever level is in force.
macro_rules! serving_error {
    ($logger:expr, $ip:expr, $($arg:tt)*) => {{
        $logger.count_error($ip);
        tracing::warn!(peer = %$ip, $($arg)*);
    }};
}
pub(crate) use serving_error;

use dispatch::Wire;

/// Authoritative DNS server.
///
/// UDP and TCP from one process: anything that writes state (a fetched zone, a
/// refresh timestamp) needs a single owner.
#[derive(Parser)]
#[command(version = rdns::VERSION, about, long_about = None)]
struct Cli {
    /// Address to listen on, for both transports.
    #[arg(long, default_value = "0.0.0.0", conflicts_with = "config")]
    host: String,
    /// Port to listen on, for both transports.
    #[arg(long, default_value = "53", conflicts_with = "config")]
    port: u16,
    /// A single zone file. The origin comes from the file name.
    #[arg(long, conflicts_with = "config")]
    zone_file: Option<String>,
    /// A directory of `.zone` files.
    #[arg(long, conflicts_with = "config")]
    zone_dir: Option<String>,
    /// Who may request a zone transfer: an address or CIDR prefix, repeatable.
    ///
    /// Nobody, unless this says otherwise. TCP only, because AXFR is defined
    /// over TCP alone (RFC 5936 §4.2).
    #[arg(long, value_name = "ADDR|CIDR", conflicts_with = "config")]
    allow_transfer: Vec<String>,
    /// A TSIG key, `[algorithm:]name:base64secret`, repeatable.
    ///
    /// A request signed with a key named here may transfer a zone whatever its
    /// source address, and any signed request gets a signed answer (RFC 8945).
    /// The algorithm defaults to hmac-sha256.
    #[arg(long, value_name = "[ALG:]NAME:SECRET", conflicts_with = "config")]
    tsig_key: Vec<String>,
    /// A secondary to notify when a zone changes: `addr[:port]`, repeatable.
    ///
    /// Sent on zone load — startup and SIGHUP — for every zone whose serial
    /// moved forward (RFC 1996).
    #[arg(long, value_name = "ADDR[:PORT]", conflicts_with = "config")]
    also_notify: Vec<String>,
    /// A zone to replicate: `zone@master[:port][#tsig-key-name]`, repeatable.
    ///
    /// Makes this server a secondary for that zone: SOA on the zone's REFRESH
    /// timer, transfer when the serial moved, stop serving once EXPIRE passes
    /// without contact. Repeat with the same zone for more than one master.
    /// Requires `--zone-dir`, where the fetched file lands.
    #[arg(
        long,
        value_name = "ZONE@MASTER[:PORT][#KEY]",
        conflicts_with = "config"
    )]
    secondary: Vec<String>,
    /// A directory of `.rdnskey` signing keys.
    ///
    /// A zone whose apex matches a key here is signed in memory as it loads.
    /// The zone file is never rewritten: a resigning timer racing an editor for
    /// one file is a way to lose a zone.
    #[arg(long, value_name = "DIR", conflicts_with = "config")]
    signing_key_dir: Option<PathBuf>,
    /// How long a generated signature is good for, in days.
    ///
    /// Signatures are made at load, so this also says how often the zone has to
    /// be reloaded — hence the long default.
    #[arg(
        long,
        value_name = "DAYS",
        default_value = "30",
        conflicts_with = "config"
    )]
    signature_validity: u32,
    /// Deny names with NSEC3 (RFC 5155) rather than NSEC.
    ///
    /// No salt, no extra iterations (RFC 9276 §3.1).
    #[arg(long, conflicts_with = "config")]
    nsec3: bool,
    /// Leave insecure delegations out of the NSEC3 chain (RFC 5155 §6).
    ///
    /// For a zone with many unsigned children. The cost is that a denial
    /// covering an opted-out span proves less.
    #[arg(long, requires = "nsec3", conflicts_with = "config")]
    nsec3_opt_out: bool,
    /// Generate a key-signing and a zone-signing key for ZONE, print the DS
    /// record to give the parent, and exit.
    ///
    /// Writes both into `--signing-key-dir`, which must exist. Serves nothing.
    #[arg(long, value_name = "ZONE", requires = "signing_key_dir")]
    generate_keys: Option<String>,
    /// The algorithm `--generate-keys` uses: a number or a mnemonic.
    #[arg(long, value_name = "ALG", default_value = "ECDSAP256SHA256")]
    key_algorithm: String,
    /// Refuse to serve a zone that is not signed, or whose signatures do not
    /// verify.
    ///
    /// Off by default: a server may hold a mix, and most zones are unsigned.
    #[arg(long, conflicts_with = "config")]
    require_signed: bool,
    /// Serve the zones that loaded even if others in --zone-dir failed to parse.
    ///
    /// Off by default: one typo plus a deploy SIGHUP is otherwise a lame
    /// delegation nothing alerts on. The flag exists because a secondary
    /// holding 40 zones would rather serve 39 than none — but as a decision.
    #[arg(long, conflicts_with = "config")]
    allow_partial_load: bool,
    /// Response bytes per second, per client address. 0 turns the budget off.
    ///
    /// Meters what leaves, which is what an amplification attack is made of.
    /// UDP only: a TCP query completed a handshake, so there is nobody to
    /// reflect at.
    #[arg(
        long,
        value_name = "BYTES_PER_SEC",
        default_value = "8192",
        conflicts_with = "config"
    )]
    response_rate: u32,
    /// Queries per second, per client address. 0 turns the limit off.
    ///
    /// Over the limit is dropped silently, so the number has to be generous:
    /// `rdnsd`'s clients are resolvers, not end users. A backstop against a
    /// flood, not a quota.
    #[arg(
        long,
        value_name = "QUERIES_PER_SEC",
        default_value = "1000",
        conflicts_with = "config"
    )]
    query_rate: u32,
    /// How many queries may arrive at once before `--query-rate` applies.
    ///
    /// DNS traffic is bursty by nature; no burst allowance drops traffic that
    /// is not a flood.
    #[arg(
        long,
        value_name = "QUERIES",
        default_value = "200",
        conflicts_with = "config"
    )]
    query_burst: u32,
    /// An address or CIDR prefix the query rate limit does not apply to,
    /// repeatable.
    ///
    /// For your own resolvers and monitoring probes; the alternative is raising
    /// the limit for everybody.
    #[arg(long, value_name = "ADDR|CIDR", conflicts_with = "config")]
    query_rate_exempt: Vec<String>,
    /// How often to report what the last interval's traffic looked like, in
    /// seconds. 0 turns the anomaly warnings off.
    ///
    /// Every threshold below is per interval, so this is also the unit they are
    /// read in: `--anomaly-source-queries 100` at the default is a hundred
    /// queries a minute from one address.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value = "60",
        conflicts_with = "config"
    )]
    anomaly_interval: u64,
    /// Warn above this query rate, averaged over `--anomaly-interval`. 0 is off.
    #[arg(
        long,
        value_name = "QUERIES_PER_SEC",
        default_value = "50",
        conflicts_with = "config"
    )]
    anomaly_query_rate: f64,
    /// Warn when more than this percentage of an interval's queries failed.
    /// 0 is off.
    #[arg(
        long,
        value_name = "PERCENT",
        default_value = "10",
        conflicts_with = "config"
    )]
    anomaly_error_percent: f64,
    /// Warn about a source that sent more than this many queries in one
    /// interval. 0 is off.
    ///
    /// A log line, not a metric: naming the address is the point, and an
    /// address is exactly what a Prometheus label must not be — the cardinality
    /// is the client's to choose.
    #[arg(
        long,
        value_name = "QUERIES",
        default_value = "100",
        conflicts_with = "config"
    )]
    anomaly_source_queries: u64,
    /// Warn about a source the rate limiter refused more than this many times
    /// in one interval. 0 is off.
    #[arg(
        long,
        value_name = "REFUSALS",
        default_value = "5",
        conflicts_with = "config"
    )]
    anomaly_source_refusals: u64,
    /// How many UDP datagrams may be answered at once.
    ///
    /// That many identical tasks share the socket and answer inline, rather
    /// than one task spawned per datagram (1,536 bytes each, before anything
    /// decided to keep the packet). Raising it does not make a busy server
    /// faster; it buys memory (a 64 KB receive buffer per worker). Beyond the
    /// workers, datagrams queue in the socket buffer and the kernel drops the
    /// overflow, which is the correct back-pressure for UDP.
    #[arg(
        long,
        value_name = "TASKS",
        default_value_t = default_udp_workers(),
        conflicts_with = "config"
    )]
    udp_workers: usize,
    /// Serve Prometheus metrics and a liveness probe on this address.
    ///
    /// `GET /metrics` is the scrape, `GET /healthz` says the process is
    /// running. No TLS and no auth: bind it on loopback or a management
    /// address.
    #[arg(long, value_name = "ADDR:PORT", conflicts_with = "config")]
    metrics_listen: Option<String>,
    /// Answer `rdnsctl` on this Unix socket: `status`, `reload`, `dump <zone>`.
    ///
    /// Filesystem permissions are the authentication: the socket is mode 0600,
    /// so the server's user and root. That is also why these commands are not
    /// on `--metrics-listen`, where `reload` would be a POST with no
    /// credential. Unix only — `tokio` has no `UnixListener` on Windows, so
    /// this is refused there at startup rather than ignored.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    control_socket: Option<PathBuf>,
    /// Read the settings from a TOML file instead of from flags.
    ///
    /// Exclusive of the flags it would set: `--config` with `--port` is an
    /// error, not a precedence rule. Both values are valid, so the failure
    /// would be silent.
    ///
    /// The file can express two things a flag cannot: a TSIG secret in a file of
    /// its own (so it is in neither `argv` nor the config), and per-zone signing
    /// settings.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Validate the configuration and exit without binding a socket.
    ///
    /// Reads the config, the TSIG secrets and the signing keys, and checks
    /// everything knowable without the network. Exit 0 means it would start.
    #[arg(long, requires = "config")]
    check_config: bool,
    /// How much to say: error, warn, info, debug or trace.
    ///
    /// Nothing per-packet is above `debug`: a malformed packet is not an
    /// operator-actionable event, and at 50k pps that is 50k lines a second.
    /// `RUST_LOG` overrides this when set.
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: LogLevel,
    /// Errors only. The same as `--log-level error`, and refused with it.
    #[arg(long, conflicts_with = "log_level")]
    quiet: bool,
}

/// Everything both transports answer from. One per process, so a connection or
/// datagram task clones a single `Arc`.
///
/// Shared across transports on purpose: a client's rate limit must not reset
/// because it switched transport, and the metrics are one server's.
struct Server {
    zone_map: Arc<RwLock<Zones>>,
    /// The limiter, the response budget, the validator, the logger and the
    /// metrics — the five handles serving a request needs that are not the
    /// answer. `rdnsr` held the same five as its `Shell`, which is how the
    /// admission sequence came to be written twice (`TODO.md` #30e, #32).
    ctx: ServeContext,
    /// Who may ask for a zone transfer. Empty by default, which refuses everyone.
    transfer_acl: Arc<TransferAcl>,
    tsig_keys: Arc<TsigKeyring>,
    /// The zones we replicate, so a NOTIFY can be told from a plausible one.
    secondaries: Secondaries,
    /// Per-zone change history, so an IXFR can answer with the difference.
    /// Derived from the zone map, so the two are only updated together.
    deltas: Arc<RwLock<DeltaLog>>,
    /// `None` on a server with no writable zone source: every UPDATE refused.
    updates: Arc<UpdateHandling>,
    journal: Option<Arc<Journal>>,
}

/// What answering a dynamic UPDATE (RFC 2136) needs beyond what a query needs.
///
/// The update must reach the *file*, not just the map: the re-signing timer
/// reloads every zone from its file (see [`ZoneSigning::resign_interval`]), so
/// an in-memory-only edit is discarded within one re-signing interval with
/// nothing logged. The flow is apply to the zone as the file has it, write the
/// file, sign the result, install that.
struct UpdateHandling {
    /// `None` when the server has no source it may write — a secondary's
    /// replicated zones are the master's copy.
    source: Option<ZoneSource>,
    /// So the installed version is signed the way a loaded one would be.
    signing: Option<Arc<ZoneSigning>>,
    /// Serializes the read-modify-write, which RFC 2136 §3.7 requires.
    ///
    /// One lock for all zones rather than one per zone: two concurrent UPDATEs
    /// is not a workload this has. Held across file I/O and a signing run, so
    /// `tokio::Mutex` and not a `std` one.
    applying: tokio::sync::Mutex<()>,
}

impl UpdateHandling {
    /// A server that refuses every UPDATE.
    ///
    /// `#[cfg(test)]`: `serve` always has a zone source. The `None` case still
    /// drives the refusal branch in `answer_update`.
    #[cfg(test)]
    fn disabled() -> Self {
        UpdateHandling {
            source: None,
            signing: None,
            applying: tokio::sync::Mutex::new(()),
        }
    }
}

/// The policy knobs `serve` applies.
///
/// A struct rather than more positional parameters: two `u32`s and two
/// address-shaped things are one edit away from being swapped silently.
struct ServePolicy {
    transfer_acl: TransferAcl,
    tsig_keys: TsigKeyring,
    /// Bytes per second per client, for UDP replies. 0 is off.
    response_rate: u32,
    /// Queries per second per client, with its burst and exemptions.
    query_limit: RateLimitConfig,
    /// How often the anomaly warnings run, and what they warn about. Zero
    /// interval is off.
    anomalies: (Duration, AnomalyThresholds),
    /// How many UDP datagrams may be answered at once. Floored at 1 in `serve`.
    udp_workers: usize,
    /// Where to serve Prometheus metrics, if anywhere.
    metrics_listen: Option<String>,
    /// Whether every zone this server answers for is in the map yet, for
    /// `/readyz` on that same listener.
    readiness: Readiness,
    /// What a dynamic UPDATE needs; refuses everything when unconfigured.
    updates: Arc<UpdateHandling>,
    /// Where the delta log is persisted, if anywhere.
    journal: Option<Arc<Journal>>,
    /// The control socket, and what a `reload` on it pokes.
    control: ControlPolicy,
}

/// Where the control socket lives and how it asks for a reload.
#[cfg_attr(not(unix), allow(dead_code))]
struct ControlPolicy {
    socket: Option<PathBuf>,
    reloads: mpsc::Sender<ReloadTrigger>,
    /// Zones this server replicates, so `status` says `secondary` from
    /// configuration rather than guessing from an absent timestamp, which a
    /// primary also has.
    replicated: Vec<String>,
    /// For `status`'s uptime. Taken in `main`, not here: loading and signing
    /// every zone happens before `serve` and is the bulk of a big start.
    started: Instant,
}

/// Bind both transports and serve them from one process.
async fn serve(
    addr: &str,
    zone_map: Arc<RwLock<Zones>>,
    policy: ServePolicy,
    secondaries: Secondaries,
    deltas: Arc<RwLock<DeltaLog>>,
    shutdown: Shutdown,
    metrics: Arc<DnsMetrics>,
) -> Result<()> {
    let ServePolicy {
        transfer_acl,
        tsig_keys,
        response_rate,
        query_limit,
        anomalies: (anomaly_interval, anomaly_thresholds),
        udp_workers,
        metrics_listen,
        readiness,
        updates,
        journal,
        control,
    } = policy;
    // Floored, not refused: `--udp-workers 0` would bind the socket and answer
    // nothing on it. A mistyped knob should be wrong, not fatal.
    let udp_workers = udp_workers.max(1);
    let transfers = if transfer_acl.is_empty() && tsig_keys.is_empty() {
        "refused (no --allow-transfer, no --tsig-key)".to_string()
    } else {
        // Per-key scope spelled out, not counted: an unscoped key transfers
        // every zone, and that has to be visible without reading the config.
        format!(
            "allowed for {} address rule(s) and {} key(s){}",
            transfer_acl.len(),
            tsig_keys.len(),
            if tsig_keys.is_empty() {
                String::new()
            } else {
                format!(" [{}]", tsig_keys.describe())
            }
        )
    };
    let budget = if response_rate == 0 {
        "off".to_string()
    } else {
        format!("{response_rate} bytes/s per client")
    };
    // Printed at startup: over-limit queries are dropped silently — replying to
    // a spoofed source is what an amplifier does — so the number has to be
    // visible somewhere else.
    let query_limit_note = if query_limit.tokens_per_window == 0 {
        "off".to_string()
    } else {
        format!(
            "{} q/s per client, burst {}{}",
            query_limit.tokens_per_window,
            query_limit.burst_size,
            if query_limit.exempt.is_empty() {
                String::new()
            } else {
                format!(", {} exempt rule(s)", query_limit.exempt.len())
            }
        )
    };

    // The same reason the two above are printed: these thresholds decide what an
    // operator is told about a flood, and a check that is off has to say so.
    let anomaly_note = if anomaly_interval.is_zero() {
        "off".to_string()
    } else {
        format!(
            "every {}s (>{} q/s, >{}% errors, >{} q/source, >{} refusals/source)",
            anomaly_interval.as_secs(),
            anomaly_thresholds.queries_per_second,
            anomaly_thresholds.error_percent,
            anomaly_thresholds.queries_per_source,
            anomaly_thresholds.refusals_per_source
        )
    };

    // Bind everything before announcing anything, so a port conflict fails here
    // rather than after one transport is up. The metrics listener included: a
    // typo in `--metrics-listen` must stop the start, not silently disable it.
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    let listener = TcpListener::bind(addr).await?;
    let metrics_listener = match &metrics_listen {
        Some(spec) => Some(
            TcpListener::bind(spec)
                .await
                .with_context(|| format!("--metrics-listen {spec}"))?,
        ),
        None => None,
    };
    // Same rule for the control socket: a path that cannot be bound stops the
    // start.
    #[cfg(unix)]
    let control_listener = match &control.socket {
        Some(path) => Some(control::bind(path)?),
        None => None,
    };

    let server = Arc::new(Server {
        zone_map,
        ctx: ServeContext {
            limiter: Arc::new(RateLimiter::new(query_limit)),
            responses: Arc::new(ResponseLimiter::per_second(response_rate)),
            validator: Arc::new(AdmissionCheck::with_defaults()),
            logger: Arc::new(QueryLogger::new()),
            metrics,
        },
        transfer_acl: Arc::new(transfer_acl),
        tsig_keys: Arc::new(tsig_keys),
        secondaries,
        deltas,
        updates,
        journal,
    });
    // The effective policy, at the default level: a control nobody can observe
    // is a control nobody can debug.
    tracing::info!(
        "rdnsd listening on {addr} (UDP+TCP), zone transfer: {transfers}, \
         response budget: {budget}, query rate: {query_limit_note}, \
         UDP workers: {udp_workers}, anomaly warnings: {anomaly_note}, \
         TSIG keys: {}, metrics: {}, control: {}",
        server.tsig_keys.len(),
        match &metrics_listen {
            Some(spec) => format!("{spec}/metrics"),
            None => "off (--metrics-listen)".to_string(),
        },
        match &control.socket {
            Some(path) => format!("{} (mode 0600)", path.display()),
            None => "off (--control-socket)".to_string(),
        }
    );
    // Listening is not serving: the sockets are up and some zones are not, which
    // is invisible from outside unless `/readyz` is reachable.
    let still_waiting = readiness.pending();
    if !still_waiting.is_empty() {
        tracing::info!(
            "not ready: {} zone(s) awaiting a first transfer [{}]{}",
            still_waiting.len(),
            still_waiting.join(" "),
            match &metrics_listen {
                Some(spec) => format!(" — {spec}/readyz answers 503 until they arrive"),
                None => " — with no --metrics-listen, nothing can probe for it".to_string(),
            }
        );
    }

    // Not in the `JoinSet` below: that set's rule is "the first task to end ends
    // the process", and this one ends on the stop signal by design. Joined after
    // the drain instead, so it is not a detached task (`CLAUDE.md` §9).
    let anomalies = tokio::spawn(watch_anomalies(
        server.ctx.logger.clone(),
        anomaly_thresholds,
        anomaly_interval,
        shutdown.stop_handle(),
    ));

    // `JoinSet`, not two `JoinHandle`s in a `select!`: dropping a `JoinHandle`
    // detaches the task rather than cancelling it. `join_next` is cancel-safe
    // and leaves both tasks owned.
    let mut loops = JoinSet::new();
    // Workers are peers: each receives from the shared socket and answers
    // inline, so the first to stop for a reason other than the signal ends the
    // process, as for the accept loops.
    for _ in 0..udp_workers {
        loops.spawn(udp_loop(
            socket.clone(),
            server.clone(),
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
    }
    // Per message, not per connection: this server's clients are resolvers, and
    // they pipeline (`TODO.md` #30e).
    loops.spawn(tcp::serve(
        listener,
        server.clone(),
        TransportLimits::default(),
        tcp::RateLimit::PerMessage,
        shutdown.stop_handle(),
        shutdown.busy(),
    ));
    // A listener like the others: if it dies, the process does. A server whose
    // metrics stopped is one nobody is watching.
    if let Some(metrics_listener) = metrics_listener {
        loops.spawn(metrics_server::serve(
            metrics_listener,
            server.ctx.metrics.clone(),
            readiness,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
    }
    // And the control socket, for the same reason.
    #[cfg(unix)]
    if let Some(control_listener) = control_listener {
        let ControlPolicy {
            socket,
            reloads,
            replicated,
            started,
        } = control;
        loops.spawn(control::serve(
            control_listener,
            socket.expect("a listener implies a path"),
            Arc::new(control::Control {
                served: ZoneContext {
                    zone_map: server.zone_map.clone(),
                    deltas: server.deltas.clone(),
                    metrics: server.ctx.metrics.clone(),
                    journal: server.journal.clone(),
                },
                replicated,
                reloads,
                started,
                listen: addr.to_string(),
            }),
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
    }

    // Whichever listener ends first ends the process: answering on one transport
    // and not the other is worse than being plainly down. The drain then waits
    // for an AXFR already on the wire, which a client cannot tell from a
    // complete one if it is cut.
    rdns_transport::serve_until_stopped(loops, anomalies, shutdown).await
}

/// A name in absolute form, so it can be compared with a zone origin.
///
/// [`rdns::text_names::absolute`] under this module's name for it. Returns a `Cow` so
/// the common case — a name off the wire, already absolute — borrows.
fn absolute_name(name: &str) -> std::borrow::Cow<'_, str> {
    rdns::text_names::absolute(name)
}

/// Receive datagrams and answer them, as one of `--udp-workers` identical tasks
/// sharing the socket.
///
/// No task per datagram: a fixed pool bounds concurrency before the packet is
/// copied, and the overflow queues in the socket receive buffer where the kernel
/// drops and counts it. A spawn per datagram cost 1,536 bytes, 46% of everything
/// a query allocated. Costs one 64 KB receive buffer per worker — see
/// [`default_udp_workers`].
///
/// This loop must not block: a worker stuck here is a worker not receiving.
///
/// A panic while answering ends the worker, and `serve` then ends the process.
async fn udp_loop(
    socket: Arc<UdpSocket>,
    server: Arc<Server>,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    let mut buf = vec![0; UDP_RECEIVE_BUFFER];
    let mut scratch = Scratch::default();

    loop {
        // `recv_from` is cancel-safe: a datagram is either fully received or not
        // received at all, so losing this race drops nothing.
        let received = tokio::select! {
            r = socket.recv_from(&mut buf) => r,
            _ = stop.wait() => return Ok(()),
        };
        let (size, peer) = match received {
            Ok(received) => received,
            Err(e) if recv_error_is_transient(&e) => continue,
            Err(e) => return Err(e),
        };
        let packet = &buf[..size];

        // One clock read per datagram, shared by the limiter, the logger, the
        // TSIG check and the response budget — each used to fetch its own, at
        // 24-26 ns a call (`TODO.md` #28a).
        let now = tsig::now();

        // Both are decisions to do nothing, so they run on `&buf[..size]` with
        // nothing copied and nothing spawned.
        if !server.ctx.allow_source(peer.ip(), now) {
            continue;
        }
        if !server.ctx.accept_packet(peer.ip(), packet, Transport::Udp) {
            continue;
        }

        // Claims the drain until this answer is on the wire and no longer: a
        // claim held across the loop would keep the drain open for the whole
        // budget.
        let _busy = busy.clone();
        server
            .answer(
                packet,
                peer,
                now,
                &Wire::Datagram(&socket, peer),
                &mut scratch,
            )
            .await;
    }
}

/// What one UDP worker reuses from datagram to datagram.
///
/// Three pieces of per-message state that a task-per-datagram server pays for
/// every time and a fixed pool pays for once: the reply buffer, which settles at
/// the largest EDNS payload size this worker has been asked for; the name
/// compressor, whose two allocations are per message (`TODO.md` #27b); and the
/// folded lookup key, which a case-randomized QNAME needs somewhere that
/// outlives the question (#27a).
///
/// One struct because they are one thing — the scratch space — and because
/// three more parameters on `answer_datagram` is what clippy's argument limit is
/// for (`CLAUDE.md` §14).
#[derive(Default)]
struct Scratch {
    out: Vec<u8>,
    compressor: NameCompressor,
    key: String,
}

/// What a reload has to redo: everything between reading the files and being
/// ready to answer from them.
///
/// Only SIGHUP reloads, so on a platform without signals this is carried and
/// never used — the same shape the signal handler itself has.
#[derive(Clone)]
#[cfg_attr(not(unix), allow(dead_code))]
struct Reloading {
    replicating: bool,
    allow_partial: bool,
    /// The zones we replicate, and the directory their state sidecar lives in.
    /// A reload re-reads every `.zone` file from disk, so it can resurrect a zone
    /// that was withdrawn for EXPIRE — these are what let it be withdrawn again.
    /// Empty for a server that is nobody's secondary.
    secondaries: Vec<MasterSpec>,
    zone_dir: Option<PathBuf>,
    signing: Option<Arc<ZoneSigning>>,
    validator: Arc<DnssecValidator>,
}

#[cfg_attr(not(unix), allow(dead_code))]
impl Reloading {
    /// Read the zones again and put them through signing and checking, or say
    /// why not.
    ///
    /// Nothing is installed unless the whole set comes through: a reload that
    /// replaced half the zones and gave up would serve a mixture of two
    /// versions, and the half that failed is the half needing attention.
    ///
    /// On a blocking thread, all of it. Every step blocks — `read_dir`, a parse
    /// per zone, an ECDSA signing run over every RRset of every signed zone,
    /// then verification — and both callers run while the listeners are live, so
    /// on the runtime this is a worker out of service with queries behind it.
    async fn load(&self, source: &ZoneSource) -> Result<ZoneMap> {
        let reloading = self.clone();
        let source = source.clone();
        tokio::task::spawn_blocking(move || reloading.load_blocking(&source))
            .await
            .context("the zone-loading task")?
    }

    /// The blocking half of [`Reloading::load`], and named so at the call site.
    fn load_blocking(&self, source: &ZoneSource) -> Result<ZoneMap> {
        let mut zones = load_zones_from_source(source, self.replicating, self.allow_partial)?;
        if let Some(signing) = &self.signing {
            signing.apply(&mut zones)?;
        }
        verify_zones(&zones, &self.validator)?;
        Ok(zones)
    }

    /// Re-apply EXPIRE to what was just installed.
    ///
    /// Separate from [`Reloading::load`] because it has to run *after*
    /// `install_all_zones`: the question is about the zones now being served, and
    /// until they are installed there is nothing to withdraw.
    async fn withdraw_unvouched(&self, served: &ZoneContext) {
        let Some(zone_dir) = &self.zone_dir else {
            return;
        };
        if self.secondaries.is_empty() {
            return;
        }
        withdraw_unvouched_zones(&self.secondaries, served, zone_dir).await;
    }
}

/// Why a reload is happening, and who — if anyone — is waiting to be told how
/// it went.
///
/// A carrier for the reply channel as much as a label. `reload_once` already
/// takes seven arguments, which is where clippy stops counting for the reason
/// `CLAUDE.md` §14 gives, so the channel rides with the reason it exists for
/// rather than becoming an eighth.
enum ReloadTrigger {
    /// SIGHUP. Nobody is waiting; the log is the report.
    #[cfg_attr(not(unix), allow(dead_code))]
    Signal,
    /// The signature-validity timer came round.
    Timer,
    /// `rdnsctl reload`, with the channel the outcome goes back down. `Ok` is
    /// the number of zones installed.
    #[cfg_attr(not(unix), allow(dead_code))]
    Control(tokio::sync::oneshot::Sender<Result<usize, String>>),
}

impl ReloadTrigger {
    /// What the log line says this reload was for.
    fn why(&self) -> &'static str {
        match self {
            ReloadTrigger::Signal => "SIGHUP",
            ReloadTrigger::Timer => "signature refresh",
            ReloadTrigger::Control(_) => "control socket",
        }
    }
}

/// One reload, installed and announced. What SIGHUP, the re-signing timer and
/// the control socket all do, so that they cannot drift apart (`CLAUDE.md` §7).
///
/// Returns the announced-serial state to carry into the next round.
async fn reload_once(
    reloading: &Reloading,
    source: &ZoneSource,
    served: &ZoneContext,
    notify_targets: &[SocketAddr],
    announced: Vec<(Name, Serial)>,
    busy: &Busy,
    trigger: ReloadTrigger,
) -> Vec<(Name, Serial)> {
    let why = trigger.why();
    let (announced, outcome) = match reloading.load(source).await {
        Ok(new_zones) => {
            let loaded = new_zones.len();
            // A reload is a version step like any other: the difference from
            // what we were serving is what an IXFR will answer with, and this is
            // the only moment both versions exist.
            install_all_zones(served, new_zones).await;
            // A reload re-reads the files, so a zone withdrawn for EXPIRE is
            // back in the map at this point. Judge it again before anything is
            // announced or answered.
            reloading.withdraw_unvouched(served).await;
            tracing::info!("zones reloaded ({why})");
            // The point of reloading is that something changed — new data, or at
            // minimum new signatures and a new serial — so this is exactly when a
            // secondary wants to hear about it.
            (
                announce_zones(&served.zone_map, &announced, notify_targets, busy).await,
                Ok(loaded),
            )
        }
        Err(e) => {
            // The zones already loaded keep answering. A reload that failed is a
            // file that changed for the worse, and the version in memory is the
            // last one known good.
            tracing::error!("failed to reload zones ({why}): {e}");
            // `{e:#}` rather than `{e}`: `anyhow`'s `Display` prints only the
            // outermost context, and the operator holding the terminal wants
            // the whole chain — "the zone-loading task: example.com.zone:12:
            // ..." — not just its first clause. The log line above keeps the
            // short form because a log line is scanned rather than read.
            (announced, Err(format!("{e:#}")))
        }
    };
    // Whoever asked hears how it went. A dropped receiver is an `rdnsctl` that
    // gave up waiting, which is not this task's problem — the reload happened
    // either way and the log has it.
    if let ReloadTrigger::Control(reply) = trigger {
        let _ = reply.send(outcome);
    }
    announced
}

/// Keep the zones current: reload on SIGHUP or on the control socket, and
/// re-sign on a timer.
///
/// One task. The re-signing timer works by *reloading* (see
/// [`ZoneSigning::resign_interval`]), so it and SIGHUP are the same operation on
/// two triggers, and `rdnsctl reload` is a third. Two tasks would mean two
/// reloads running at once, each installing a different snapshot of the files
/// and holding its own idea of which serials have been announced.
///
/// It holds a [`Busy`] and exits on [`Stop`]: a reload part-way through
/// installing zones is work the drain should wait for, and a task that never
/// exits while holding a `Busy` spends the whole budget every shutdown.
fn spawn_zone_maintenance(
    served: ZoneContext,
    source: ZoneSource,
    notify_targets: Vec<SocketAddr>,
    announced: Vec<(Name, Serial)>,
    reloading: Reloading,
    lifecycle: Lifecycle,
) -> mpsc::Sender<ReloadTrigger> {
    let Lifecycle { stop, busy } = lifecycle;
    // `None` when nothing is signed: a server with no keys has nothing to
    // re-sign, and a timer that fired anyway would reload the zones on a
    // schedule nobody asked for.
    let resign_every = reloading.signing.as_ref().map(|s| s.resign_interval());
    if let Some(every) = resign_every {
        tracing::info!(
            "re-signing every {}h, a third of the {}-day signature validity",
            every.as_secs() / 3600,
            reloading
                .signing
                .as_ref()
                .map(|s| s.validity_days())
                .unwrap_or(0),
        );
    }

    // Depth 1: a reload is the whole zone set, so a queue of them is a queue of
    // identical work. The second `rdnsctl reload` to arrive while one is running
    // waits for a slot rather than being dropped, and there is nothing to gain
    // from letting a third pile up behind it.
    let (requests, mut receiver) = mpsc::channel(1);
    // The task keeps a sender of its own, so `recv` parks forever when nothing
    // is asking rather than returning `None` the moment the control socket is
    // not configured. A `None` branch here would be a busy loop or a dead arm,
    // and neither is worth having when one clone removes the question.
    let keepalive = requests.clone();

    tokio::spawn(async move {
        let _busy = busy;
        let _keepalive = keepalive;
        let mut announced = announced;
        let mut signals = signal_stream();
        loop {
            // Whichever comes first. A trigger that arrives during shutdown is
            // ignored: reloading zones we are about to stop serving is work for
            // nobody.
            //
            // `recv` on the request channel is cancel-safe, so losing this race
            // leaves the request queued rather than dropping it — and a request
            // that loses to the stop is one whose sender is about to be told the
            // server stopped, which is true.
            let trigger = tokio::select! {
                reloaded = next_reload_signal(&mut signals) => {
                    if !reloaded {
                        break;
                    }
                    ReloadTrigger::Signal
                }
                // `None` is unreachable while `_keepalive` is alive, and it is
                // alive for exactly as long as this loop.
                Some(trigger) = receiver.recv() => trigger,
                _ = sleep_for(resign_every) => ReloadTrigger::Timer,
                _ = stop.wait() => break,
            };
            announced = reload_once(
                &reloading,
                &source,
                &served,
                &notify_targets,
                announced,
                &_busy,
                trigger,
            )
            .await;
        }
    });

    requests
}

/// Sleep for `every`, or forever when there is nothing to wait for.
///
/// `pending()` rather than a long sleep, so an unsigned server's maintenance task
/// costs one parked future rather than waking up to do nothing.
async fn sleep_for(every: Option<Duration>) {
    match every {
        Some(every) => tokio::time::sleep(every).await,
        None => std::future::pending().await,
    }
}

/// `tokio`'s own signal support rather than `signal-hook-tokio`, for the same
/// reason `rdns::shutdown` uses it: it is already here, it needs no dependency,
/// and one mechanism for every signal this process handles beats two.
///
/// `signals.next()` needs a `StreamExt` in scope to resolve to `Stream::next`;
/// without one it resolves to `Iterator::next` and fails the trait bound — which
/// no amount of building on Windows shows, since the module is `#[cfg(unix)]`.
#[cfg(unix)]
fn signal_stream() -> Option<Signal> {
    match signal(SignalKind::hangup()) {
        Ok(signals) => Some(signals),
        Err(e) => {
            // The re-signing timer still works, which is the half with teeth.
            tracing::error!("could not listen for SIGHUP ({e}); zones will not reload on signal");
            None
        }
    }
}

/// Whether a reload was asked for. `false` means the signal source ended and the
/// loop should stop watching it.
#[cfg(unix)]
async fn next_reload_signal(signals: &mut Option<Signal>) -> bool {
    match signals {
        Some(signals) => signals.recv().await.is_some(),
        // No signal source, but the timer may still fire — so park here rather
        // than ending the loop.
        None => std::future::pending().await,
    }
}

/// Windows has no SIGHUP, so only the timer triggers a reload here.
#[cfg(not(unix))]
fn signal_stream() -> Option<()> {
    None
}

#[cfg(not(unix))]
async fn next_reload_signal(_signals: &mut Option<()>) -> bool {
    std::future::pending().await
}

/// `addr` or `addr:port` for a secondary, defaulting to port 53.
///
/// A bare IPv6 address has colons of its own, so `[::1]:5353` is the only
/// unambiguous way to give one a port — which is what `SocketAddr` already
/// parses, so the shape is the familiar one rather than a new convention.
fn parse_notify_targets(specs: &[String]) -> Result<Vec<SocketAddr>> {
    let mut targets = Vec::new();
    for spec in specs {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        if let Ok(addr) = spec.parse::<SocketAddr>() {
            targets.push(addr);
            continue;
        }
        match spec.parse::<IpAddr>() {
            Ok(ip) => targets.push(SocketAddr::new(ip, 53)),
            Err(e) => {
                return Err(anyhow!(
                    "--also-notify {spec:?} is not an address or address:port: {e}"
                ))
            }
        }
    }
    Ok(targets)
}

/// Tell every secondary about the zones whose serial moved since `announced`,
/// and return the serials now announced.
///
/// Called after each load. A zone whose serial did not move is not news, and one
/// that went backwards is not either — a secondary compares serials and would
/// ignore it, so sending would be noise.
async fn announce_zones(
    zone_map: &Arc<RwLock<Zones>>,
    announced: &[(Name, Serial)],
    targets: &[SocketAddr],
    busy: &Busy,
) -> Vec<(Name, Serial)> {
    let (current, pending) = {
        let zones = zone_map.read().await;
        let all: Vec<&Zone> = zones.values().map(Arc::as_ref).collect();
        let current = notify::zone_serials(&all);
        let changed = notify::changed_zones(announced, &current);
        // Build the messages under the lock, send them outside it: a NOTIFY that
        // goes unanswered takes seconds to retry, and holding the zone map that
        // long would block a reload behind the network.
        let pending: Vec<(Name, Serial, Option<rdns::ResourceRecord>)> = changed
            .iter()
            .filter_map(|(name, serial)| {
                zones
                    .get(&*name.as_ref().folded())
                    .map(|zone| (name.clone(), *serial, zone.apex_soa_record()))
            })
            .collect();
        (current, pending)
    };

    if targets.is_empty() || pending.is_empty() {
        return current;
    }
    for (zone, serial, soa) in pending {
        for target in targets {
            let target = *target;
            let zone = zone.clone();
            let soa = soa.clone();
            // Fire-and-forget, but not unaccounted-for: a NOTIFY dropped at
            // shutdown is a secondary that waits out a whole REFRESH before it
            // learns of a change we already knew about, so the drain covers it.
            let busy = busy.clone();
            tokio::spawn(async move {
                let _busy = busy;
                send_notify(zone.as_ref(), serial, soa, target).await;
            });
        }
    }
    current
}

/// Tell the configured secondaries that a zone *we* replicate has moved.
///
/// RFC 1996 §3.2's "master" is whoever serves the zone to someone, which a
/// secondary in the middle of a tree is. Without this, `announce_zones` covers
/// only the moments a *primary* learns of a change — startup and SIGHUP — while a
/// secondary learns of one by transferring it and says nothing, so the first
/// level of a tree updates at once and every level below it waits out a refresh
/// timer.
///
/// Spawned rather than awaited for the same reason the primary's announcements
/// are: an unanswered NOTIFY takes seconds to give up on, and a refresh should
/// not be held behind the network to tell somebody about work it has finished.
fn announce_transfer(
    zone: NameRef<'_>,
    serial: Serial,
    soa: Option<ResourceRecord>,
    targets: &[SocketAddr],
    busy: &Busy,
) {
    for target in targets {
        let (zone, soa, target) = (zone.to_owned(), soa.clone(), *target);
        // Accounted for by the drain, like the primary's announcements: a NOTIFY
        // dropped at shutdown costs the level below us a whole REFRESH before it
        // learns of a change that has already reached us.
        let busy = busy.clone();
        tokio::spawn(async move {
            let _busy = busy;
            send_notify(zone.as_ref(), serial, soa, target).await;
        });
    }
}

/// Send one NOTIFY, retrying until it is acknowledged (RFC 1996 §3.6).
///
/// Any rcode is an acknowledgement: a secondary answering NOTAUTH has still
/// received the message, and repeating it would not change its mind. Giving up
/// after [`notify::NOTIFY_ATTEMPTS`] is safe because the secondary's refresh timer
/// is the backstop this is an optimisation over.
async fn send_notify(
    zone: NameRef<'_>,
    serial: Serial,
    soa: Option<rdns::ResourceRecord>,
    target: SocketAddr,
) {
    let Ok(socket) = UdpSocket::bind(bind_addr_for(target)).await else {
        tracing::warn!("NOTIFY {zone} to {target}: could not open a socket");
        return;
    };

    let mut wait = Duration::from_secs(notify::NOTIFY_RETRY_SECS);
    for attempt in 1..=notify::NOTIFY_ATTEMPTS {
        let id = rdns::rand_id();
        let msg = notify::notify_request(zone, soa.clone(), id);
        let mut buf = vec![0u8; 512];
        let Ok(len) = msg.to_bytes(&mut buf) else {
            tracing::warn!("NOTIFY {zone}: could not serialize");
            return;
        };
        if socket.send_to(&buf[..len], target).await.is_err() {
            tracing::warn!("NOTIFY {zone} to {target}: send failed");
            return;
        }

        let mut reply = vec![0u8; 512];
        // Something answered, but not this? Treat it as no answer rather than as
        // an acknowledgement: an off-path reply should not be able to silence a
        // notification.
        if let Ok(Ok((n, _))) = tokio::time::timeout(wait, socket.recv_from(&mut reply)).await {
            if let Ok(parsed) = DnsMessage::try_from_bytes(&reply[..n]) {
                if notify::acknowledges(&parsed, id) {
                    tracing::info!(
                        "NOTIFY {zone} serial {serial} to {target}: acknowledged ({:?})",
                        parsed.rcode
                    );
                    return;
                }
            }
        }
        if attempt < notify::NOTIFY_ATTEMPTS {
            wait *= 2;
        }
    }
    tracing::warn!(
        "NOTIFY {zone} serial {serial} to {target}: no acknowledgement after {} attempts",
        notify::NOTIFY_ATTEMPTS
    );
}

/// DHAT's allocator shim, only under `--features dhat-heap`.
///
/// It records a backtrace per allocation, which dominates everything — so a
/// build with this on answers *how many* and *how big* and says nothing useful
/// about *how fast*. Never read a timing number from one.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[tokio::main]
async fn main() -> Result<()> {
    // Held to the end of `main`, because the profiler writes `dhat-heap.json`
    // on `Drop` — a daemon that never returns from `main` never writes one at
    // all, which is why this item waited on graceful shutdown. Binding it in
    // `serve` instead would drop it before the drain and report short.
    #[cfg(feature = "dhat-heap")]
    let _dhat = dhat::Profiler::new_heap();

    // The first thing, so `status`'s uptime covers the zone load rather than
    // starting once the sockets are bound. On a server with forty signed zones
    // the load *is* the start.
    let started = Instant::now();

    let mut cli = Cli::parse();

    // Before anything that might have something to say. `--quiet` is the same
    // as `--log-level error`; clap refuses the two together, so this is a
    // rename and not a precedence rule (`CLAUDE.md` §15).
    rdns::logging::init(if cli.quiet {
        rdns::logging::LogLevel::Error
    } else {
        cli.log_level
    });

    // A config file supplies the same settings the flags do, plus the two things
    // a flag cannot express — a secret in its own file, and per-zone settings.
    // It *replaces* the flags rather than layering over them; see `config` for
    // why that is an error rather than a precedence rule.
    let per_zone = match cli.config.clone() {
        Some(path) => {
            let config = config::Config::load(&path)?;
            let per_zone = config.apply(&mut cli)?;
            tracing::info!("configured from {}", path.display());
            per_zone
        }
        None => config::PerZone::default(),
    };
    let cli = cli;

    // Key generation is a mode, not a server option: nothing is served, and it
    // happens once per zone before anything else can.
    if let Some(zone) = &cli.generate_keys {
        let dir = cli
            .signing_key_dir
            .as_deref()
            .ok_or_else(|| anyhow!("--generate-keys needs --signing-key-dir"))?;
        return generate_keys(zone, dir, &cli.key_algorithm);
    }

    validate_cli_args(&cli.host, cli.port)?;
    // Refused rather than ignored, and refused *here* so `--check-config` says
    // so too. A setting the operator believes is in force and is not is the
    // whole failure `deny_unknown_fields` exists to prevent, and silently
    // dropping a flag we parsed would be that failure with our name on it.
    #[cfg(not(unix))]
    if cli.control_socket.is_some() {
        return Err(anyhow!(
            "--control-socket needs a Unix domain socket, and neither std nor \
             tokio exposes one on Windows — the flag is parsed everywhere so a \
             config file written on Linux is not a syntax error here, but it \
             cannot be honoured"
        ));
    }

    // Created here rather than in `serve`, because the things that need to be
    // drained start before the listeners do: the startup NOTIFY burst, and every
    // secondary's refresh task. A `Shutdown` created at the point the sockets
    // bind would leave both of those outside the only mechanism that waits for
    // them.
    let shutdown = Shutdown::new();
    // Created here for the same reason as `shutdown`: the facts it records —
    // which serial is served, when a zone last transferred — start being true
    // before the listeners exist, at the initial zone load.
    let metrics = Arc::new(DnsMetrics::new());
    // A typo in either list stops the server rather than quietly narrowing it —
    // or, worse, being read as something wider.
    let transfer_acl = TransferAcl::parse(&cli.allow_transfer)?;
    let tsig_keys = TsigKeyring::parse(&cli.tsig_key)?;
    let notify_targets = parse_notify_targets(&cli.also_notify)?;
    let query_limit = RateLimitConfig::per_second(cli.query_rate, cli.query_burst).exempting(
        TransferAcl::parse_named(&cli.query_rate_exempt, "--query-rate-exempt")?,
    );

    let secondary_specs = parse_secondary_specs(&cli.secondary)?;

    let replicating = !secondary_specs.is_empty();
    // Read before the source is taken apart, which consumes the two path
    // fields.
    let signing = ZoneSigning::load(&cli, &per_zone.signing)?.map(Arc::new);
    let source = if per_zone.files.is_empty() {
        validate_zone_source(cli.zone_file, cli.zone_dir, replicating)?
    } else {
        // Zones that named their own files. `Config::apply` has already refused
        // this combined with `zone-dir`, and `Config::check` has refused a
        // secondary zone with no directory to write to.
        for path in per_zone.files.values() {
            if !Path::new(path).exists() {
                return Err(anyhow!("Zone file not found: {path}"));
            }
        }
        ZoneSource::Files(
            per_zone
                .files
                .iter()
                .map(|(origin, path)| (origin.clone(), path.clone()))
                .collect(),
        )
    };
    // Blocking, and deliberately left on this thread: startup has no listeners
    // bound yet and nothing to answer, so there is no worker to take out of
    // service. The reload path is the one that needs `spawn_blocking`.
    let mut zones = load_zones_from_source(&source, replicating, cli.allow_partial_load)?;

    // Signing happens between loading and serving, and so does checking the
    // result: verifying what we just produced is what catches a canonicalization
    // bug here rather than at every validator on the internet.
    if let Some(signing) = &signing {
        signing.apply(&mut zones)?;
    }
    let mut validator = DnssecValidator::new(cli.require_signed || signing.is_some());
    validator.set_require_signed(cli.require_signed);
    let validator = Arc::new(validator);
    verify_zones(&zones, &validator)?;

    // The dry run exits here, and *here* specifically: everything above is
    // everything that can be known without touching the network. The config
    // parsed, the TSIG secrets were read and their permissions checked, the ACLs
    // and master specs parsed, every zone file loaded and was signed, and every
    // signature verified. What is left is binding sockets and starting timers.
    //
    // A shallower check — parse the TOML and stop — would pass for the failures
    // that actually break a deploy: a zone with a typo in it, a key file that got
    // chmodded, a zone whose signatures do not verify.
    if cli.check_config {
        // `println!`, not `tracing`: this is `--check-config`'s answer on
        // stdout, not a log line. A deploy script reads it, and `--quiet` must
        // not be able to take away the output of a command whose entire job is
        // to produce it.
        println!(
            "configuration is valid: {} zone(s), {} TSIG key(s), signing {}",
            zones.len(),
            cli.tsig_key.len(),
            match &signing {
                Some(s) => format!("{} zone(s)", s.signed_zone_count(&zones)),
                None => "disabled".to_string(),
            }
        );
        return Ok(());
    }

    note_serials(&metrics, &zones);
    let zone_map = Arc::new(RwLock::new(Zones::new(zones)));
    // Empty at startup by design: the deltas are between versions *this process*
    // has held, and a zone read from disk has no previous version here. Every
    // secondary asking for an increment across a restart gets a full transfer
    // instead, which RFC 1995 §4 permits unconditionally and which corrects
    // itself at the next change. See "Architecture: incremental transfer".
    let deltas = Arc::new(RwLock::new(DeltaLog::new()));
    // Where those steps are persisted, so the paragraph above stops being true
    // across a restart. Only a directory-shaped source has somewhere to put it:
    // `--zone-file` names one file and writing a journal beside it would put a
    // file into a directory the operator did not give us.
    let journal = match &source {
        ZoneSource::Directory(dir) => Some(Arc::new(Journal::new(PathBuf::from(dir)))),
        ZoneSource::SingleFile(_) | ZoneSource::Files(_) => None,
    };
    // The four that are only ever updated together. See [`ZoneContext`].
    let served = ZoneContext {
        zone_map: zone_map.clone(),
        deltas: deltas.clone(),
        metrics: metrics.clone(),
        journal: journal.clone(),
    };
    if let Some(journal) = &journal {
        restore_journals(journal, &zone_map, &deltas).await;
        // A separate walk because it is a separate question: the restore asks
        // what each zone's journal says, this asks which journals are no zone's
        // (`CLAUDE.md` §4).
        discard_orphan_journals(journal, &zone_map).await;
    }
    let addr = format!("{}:{}", cli.host, cli.port);

    // Before anything is served: a replicated zone whose copy on disk went out
    // of contact past its EXPIRE is not ours to answer for, however recently the
    // process started.
    let mut reload_secondaries: Vec<MasterSpec> = Vec::new();
    let mut reload_zone_dir: Option<PathBuf> = None;
    // Filled in below for a secondary. A primary's is empty and it is ready as
    // soon as it is alive: every zone it serves was loaded, signed and verified
    // above, and a failure in any of that stopped the start rather than reaching
    // here.
    let mut readiness = Readiness::ready();
    let secondaries = if secondary_specs.is_empty() {
        Arc::new(HashMap::new())
    } else {
        let ZoneSource::Directory(dir) = &source else {
            // `validate_zone_source` has already refused this combination; this
            // is the compiler being told so.
            return Err(anyhow!("--secondary requires --zone-dir"));
        };
        let zone_dir = PathBuf::from(dir);
        withdraw_unvouched_zones(&secondary_specs, &served, &zone_dir).await;
        reload_secondaries = secondary_specs.clone();
        reload_zone_dir = Some(zone_dir.clone());

        // What we are configured to answer for but do not hold — asked *after*
        // the withdrawal above, because a zone read off disk whose age cannot be
        // vouched for has just stopped being served and is exactly what this has
        // to wait for. Built before the refresh tasks start, so an arrival can
        // never be reported to a `Readiness` that does not exist yet.
        readiness = {
            let zones = zone_map.read().await;
            Readiness::waiting_for(
                secondary_specs
                    .iter()
                    .filter(|spec| zones.matching(spec.zone.as_ref()).is_none())
                    .map(|spec| spec.zone.as_ref().to_presentation()),
            )
        };

        let replication = ReplicationContext {
            served: served.clone(),
            state: Arc::new(Mutex::new(StateFile::load(&state_file_path(&zone_dir)))),
            zone_dir,
            notify_targets: notify_targets.clone(),
            readiness: readiness.clone(),
        };
        spawn_secondaries(
            secondary_specs,
            &tsig_keys,
            replication,
            shutdown.lifecycle(),
        )?
    };

    // A zone that has just been loaded is news to every secondary, which is why
    // this runs at startup and not only on reload.
    let announced = announce_zones(&zone_map, &[], &notify_targets, &shutdown.busy()).await;

    // Which zones are replicated, before `reload_secondaries` is moved into
    // `Reloading`. `status` reports the role from the configuration rather than
    // inferring it from an absent last-contact time, which a primary also has.
    let replicated: Vec<String> = reload_secondaries
        .iter()
        .map(|spec| spec.zone.as_ref().to_presentation())
        .collect();

    // What a dynamic UPDATE needs, taken before `source` and `signing` are moved
    // into the maintenance task. It holds the same two things that task does, on
    // purpose: an UPDATE is a zone-file edit followed by the load path, so it has
    // to read and sign exactly the way a reload does or the two will disagree
    // about what the zone is.
    let updates = Arc::new(UpdateHandling {
        source: Some(source.clone()),
        signing: signing.clone(),
        applying: tokio::sync::Mutex::new(()),
    });

    // Reload on SIGHUP or on the control socket, and re-sign on the signature
    // timer. The sender it hands back is how `rdnsctl reload` reaches the same
    // loop rather than becoming a second implementation of a reload.
    let reloads = spawn_zone_maintenance(
        served.clone(),
        source,
        notify_targets,
        announced,
        Reloading {
            replicating,
            allow_partial: cli.allow_partial_load,
            secondaries: reload_secondaries,
            zone_dir: reload_zone_dir,
            signing,
            validator,
        },
        shutdown.lifecycle(),
    );

    serve(
        &addr,
        zone_map,
        ServePolicy {
            transfer_acl,
            tsig_keys,
            response_rate: cli.response_rate,
            query_limit,
            anomalies: (
                Duration::from_secs(cli.anomaly_interval),
                AnomalyThresholds {
                    queries_per_second: cli.anomaly_query_rate,
                    error_percent: cli.anomaly_error_percent,
                    queries_per_source: cli.anomaly_source_queries,
                    refusals_per_source: cli.anomaly_source_refusals,
                },
            ),
            udp_workers: cli.udp_workers,
            metrics_listen: cli.metrics_listen,
            readiness,
            updates,
            journal,
            control: ControlPolicy {
                socket: cli.control_socket,
                reloads,
                replicated,
                started,
            },
        },
        secondaries,
        deltas,
        shutdown,
        metrics,
    )
    .await
}

fn validate_cli_args(host: &str, port: u16) -> Result<()> {
    // Port must be 1-65535 (0 is reserved)
    if port == 0 {
        return Err(anyhow!("Port must be in range 1-65535"));
    }

    // Host must be valid IP or hostname (basic validation)
    // This is a simple check; more complex validation could parse as IP
    if host.is_empty() {
        return Err(anyhow!("Host cannot be empty"));
    }

    // Very basic hostname/IP validation - just check for invalid characters
    // Valid hostnames: alphanumeric, dots, hyphens, colons (for IPv6)
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '%')
    {
        return Err(anyhow!("Invalid host format: {host}"));
    }

    Ok(())
}

/// Make a key-signing and a zone-signing key for `zone`, and say what to give
/// the parent.
///
/// Two keys rather than one because that is what lets the data key roll without
/// the parent being involved: only the key-signing key is digested into the DS,
/// so the zone-signing key can be replaced whenever, while replacing the other
/// means a conversation with the registrar.
fn generate_keys(zone: &str, dir: &Path, algorithm: &str) -> Result<()> {
    let algorithm = SigningAlgorithm::parse(algorithm)?;
    let zone = if zone.ends_with('.') {
        zone.to_string()
    } else {
        format!("{zone}.")
    };

    let ksk = SigningKey::generate(algorithm, &zone, DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP)?;
    let zsk = SigningKey::generate(algorithm, &zone, DNSKEY_FLAG_ZONE)?;
    for key in [&ksk, &zsk] {
        let path = key.write_to_dir(dir)?;
        // Also stdout on purpose, for the same reason as `--check-config`:
        // `--generate-keys` exists to print a DS record somebody pastes into a
        // registrar form, and that is output, not logging.
        println!("Wrote {}", path.display());
    }

    // SHA-256, which RFC 8624 §3.3 is the only digest that is both mandatory to
    // implement and not deprecated.
    let ds = ksk.ds(2)?;
    println!("\nGive the parent zone this DS record:\n");
    println!(
        "{} IN DS {} {} {} {}",
        ds.owner,
        ds.key_tag,
        ds.algorithm,
        ds.digest_type,
        ds.digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    );
    println!(
        "\nUntil it is published, {zone} is signed but insecure: a validator has no way to \
         reach these keys."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::{expire_if_out_of_contact, refresh_once};
    use crate::testutil::{make_response, nm, query, zkey, ScratchDir};
    use crate::zones::{enumerate_zone_files, plan_reload, zone_key};
    use rdns::record_types;
    use rdns::secondary::{zone_file_path, RefreshTimers, TransferState};
    use rdns::tsig::{TsigAlgorithm, TsigKey};
    use rdns::zone_signer::{sign_zone, DenialChain, SigningPolicy};
    use rdns::Class;
    use rdns::QueryClass;
    use rdns::{OpCode, Qtype, ResponseCode, Ttl};
    use rdns_transport::tcp::Reply;
    use std::collections::BTreeMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// `Server::answer` collected, for tests wanting the whole reply in hand.
    /// It sends rather than returns so a transfer need not exist all at once;
    /// nothing in a test fills the channel before it is drained here.
    async fn answered(server: &Server, packet: &[u8], peer: SocketAddr) -> Vec<Vec<u8>> {
        let (tx, mut rx) = mpsc::channel::<Reply>(1024);
        server
            .answer(
                packet,
                peer,
                tsig::now(),
                &Wire::Framed(&tx),
                &mut Scratch::default(),
            )
            .await;
        drop(tx);
        let mut replies = Vec::new();
        while let Some(Reply::Frame(framed)) = rx.recv().await {
            replies.push(framed);
        }
        replies
    }

    /// A suppressed log line must not build its message.
    ///
    /// This is the half of the malformed-packet finding that a level alone does
    /// not fix. The old call site was
    /// `log_error(ip, &format!("invalid query: {}", ...))` — the `format!` runs,
    /// and the `String` is allocated, before `log_error` is even entered, so
    /// turning the logging off would still have paid for every message at 50k
    /// pps. `tracing`'s macros do not evaluate their arguments unless a
    /// subscriber is interested, and `bad_request!` is a thin wrapper over one.
    ///
    /// The counter is asserted in the same test on purpose: an error that stops
    /// being *counted* when the level is turned down would make `total_errors`
    /// mean "errors we happened to log", and every graph built on it wrong.
    #[test]
    fn a_suppressed_bad_request_costs_nothing_to_format_and_is_still_counted() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Counts how many times something asked it to render.
        struct CountsFormats(Arc<AtomicUsize>);
        impl std::fmt::Display for CountsFormats {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fetch_add(1, Ordering::SeqCst);
                f.write_str("the reason a packet was rejected")
            }
        }

        let logger = QueryLogger::new();
        let ip: IpAddr = "198.51.100.7".parse().expect("a documentation address");
        let formats = Arc::new(AtomicUsize::new(0));

        // At WARN, the DEBUG line is not emitted — and not built.
        let quiet = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .finish();
        tracing::subscriber::with_default(quiet, || {
            bad_request!(
                logger,
                ip,
                "invalid query: {}",
                CountsFormats(formats.clone())
            );
        });
        assert_eq!(
            formats.load(Ordering::SeqCst),
            0,
            "the message was built for a line nobody wanted"
        );
        assert_eq!(
            logger.get_stats().total_errors,
            1,
            "but the error still counted: the metric is not a function of the log level"
        );

        // At DEBUG it is emitted, which is what makes the assertion above mean
        // something rather than testing a macro that does nothing.
        let verbose = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        tracing::subscriber::with_default(verbose, || {
            bad_request!(
                logger,
                ip,
                "invalid query: {}",
                CountsFormats(formats.clone())
            );
        });
        assert_eq!(
            formats.load(Ordering::SeqCst),
            1,
            "the message was not built for a line that was asked for"
        );
        assert_eq!(logger.get_stats().total_errors, 2);
    }

    #[test]
    fn test_validate_cli_args_valid() {
        // Test CLI argument validation with valid args
        let result = validate_cli_args("0.0.0.0", 53);
        assert!(result.is_ok(), "Valid host and port should pass validation");
    }

    #[test]
    fn test_validate_cli_args_invalid_port_too_high() {
        // Test CLI argument validation with port > 65535
        // Since port is u16, we can only test with maximum valid value
        // This test documents the port range constraint
        let result = validate_cli_args("0.0.0.0", 65535);
        assert!(result.is_ok(), "Max port (65535) should pass validation");
    }

    #[test]
    fn test_validate_cli_args_invalid_port_zero() {
        // Test CLI argument validation with port 0
        let result = validate_cli_args("0.0.0.0", 0);
        assert!(result.is_err(), "Port 0 should fail validation");
    }

    #[test]
    fn test_validate_cli_args_localhost() {
        // Test CLI argument validation with localhost (valid for local dev)
        let result = validate_cli_args("127.0.0.1", 5353);
        assert!(
            result.is_ok(),
            "Localhost with custom port should pass validation"
        );
    }

    #[test]
    fn test_validate_cli_args_custom_host() {
        // Test CLI argument validation with custom host
        let result = validate_cli_args("192.168.1.1", 8053);
        assert!(
            result.is_ok(),
            "Custom host and port should pass validation"
        );
    }

    #[test]
    fn test_validate_cli_args_ipv6() {
        // Test CLI argument validation with IPv6 address (without brackets for validation)
        let result = validate_cli_args("::1", 53);
        assert!(result.is_ok(), "IPv6 address should pass validation");
    }

    #[test]
    fn test_validate_zone_source_file_present() {
        // Test zone source validation error when file doesn't exist
        // This documents that validate_zone_source checks file existence
        let result = validate_zone_source(Some("nonexistent.zone".to_string()), None, false);
        assert!(result.is_err(), "Non-existent file should fail validation");
    }

    #[test]
    fn test_validate_zone_source_dir_present() {
        // Test zone source validation error when directory doesn't exist
        // This documents that validate_zone_source checks directory existence
        let result = validate_zone_source(None, Some("/nonexistent/path".to_string()), false);
        assert!(
            result.is_err(),
            "Non-existent directory should fail validation"
        );
    }

    #[test]
    fn test_validate_zone_source_both_present_error() {
        // Test zone source validation rejects when both file and dir provided
        let result = validate_zone_source(
            Some("test.zone".to_string()),
            Some("/etc/dns".to_string()),
            false,
        );
        assert!(
            result.is_err(),
            "Should reject when both file and dir specified"
        );
    }

    #[test]
    fn test_validate_zone_source_neither_present_error() {
        // Test zone source validation rejects when neither file nor dir provided
        let result = validate_zone_source(None, None, false);
        assert!(
            result.is_err(),
            "Should reject when neither file nor dir specified"
        );
    }

    // The secondary role

    /// A transferred zone has to be written somewhere, and one file is not a
    /// place to put zones whose names we may not have seen yet.
    #[test]
    fn test_secondary_requires_a_zone_directory() {
        let Err(err) = validate_zone_source(Some("test.zone".to_string()), None, true) else {
            panic!("--secondary with only --zone-file should be refused");
        };
        assert!(err.to_string().contains("--zone-dir"), "got: {err}");
    }

    #[test]
    fn test_secondary_specs_are_parsed_or_refused() {
        let specs = parse_secondary_specs(&[
            "example.com@127.0.0.1:5353".to_string(),
            "  ".to_string(), // an empty repetition is not a zone
        ])
        .expect("parse");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].zone, nm("example.com."));

        let err = parse_secondary_specs(&["nonsense".to_string()])
            .unwrap_err()
            .to_string();
        assert!(
            err.to_string().contains("--secondary"),
            "the error names the flag: {err}"
        );
    }

    /// A [`ZoneContext`] over the given map and log, with throwaway gauges — for
    /// tests about installing and withdrawing zones rather than about metrics.
    fn served(zone_map: &Arc<RwLock<Zones>>, deltas: &Arc<RwLock<DeltaLog>>) -> ZoneContext {
        ZoneContext {
            zone_map: zone_map.clone(),
            deltas: deltas.clone(),
            metrics: Arc::new(DnsMetrics::new()),
            journal: None,
        }
    }

    /// A `Shutdown` that is never triggered and never dropped, for tests that
    /// need the handles but not the behaviour.
    ///
    /// Leaked on purpose. Dropping the `Shutdown` closes the `watch` channel,
    /// which makes every `Stop::wait` resolve *immediately* — so a test holding
    /// only a `Stop` would find its connections closing the moment they opened,
    /// and would be testing shutdown rather than whatever it meant to test.
    fn test_shutdown() -> &'static Shutdown {
        use std::sync::OnceLock;
        static SHUTDOWN: OnceLock<Shutdown> = OnceLock::new();
        SHUTDOWN.get_or_init(Shutdown::new)
    }

    /// A `Server` holding one zone and nothing else surprising: no rate limit
    /// worth hitting, no response budget, no keys.
    ///
    /// Up here rather than in `mod shutdown`, where it started, because the UDP
    /// tests want the same thing and a second copy is how two of them come to
    /// disagree about what a default server is (`CLAUDE.md` §7).
    /// Every limit off and throwaway counters: a test about answering must not
    /// also be a test of the rate limiter.
    fn test_context() -> ServeContext {
        ServeContext {
            limiter: Arc::new(RateLimiter::with_defaults()),
            responses: Arc::new(ResponseLimiter::disabled()),
            validator: Arc::new(AdmissionCheck::with_defaults()),
            logger: Arc::new(QueryLogger::new()),
            metrics: Arc::new(DnsMetrics::new()),
        }
    }

    fn server_with(zone: Zone) -> Arc<Server> {
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
        Arc::new(Server {
            zone_map: Arc::new(RwLock::new(Zones::new(zones))),
            ctx: test_context(),
            journal: None,
            transfer_acl: Arc::new(TransferAcl::parse(&["127.0.0.1".to_string()]).expect("acl")),
            tsig_keys: Arc::new(TsigKeyring::new(Vec::new())),
            secondaries: Arc::new(HashMap::new()),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
            updates: Arc::new(UpdateHandling::disabled()),
        })
    }

    // The UDP worker pool

    mod udp {
        use super::*;

        fn one_record_zone() -> Zone {
            rdns::zone::parse_zone_file(
                "$ORIGIN example.com.\n\
                 $TTL 3600\n\
                 @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                 @   IN NS  ns1.example.com.\n\
                 ns1 IN A   192.0.2.1\n\
                 www IN A   192.0.2.9\n",
                "example.com.",
            )
            .expect("the zone parses")
        }

        fn a_query() -> Vec<u8> {
            query("www.example.com.", Qtype::of(record_types::A), false)
                .to_bytes_within(4096)
                .expect("serialize the query")
        }

        /// A transfer asked for over UDP is not streamed, and that is now a
        /// branch rather than a position.
        ///
        /// Until one dispatcher replaced two (`TODO.md` #39b), "AXFR never
        /// reaches `write_response` over TCP" was true because the TCP function
        /// answered it earlier — `answer.rs`'s comment says exactly that, "so
        /// this is the UDP path speaking". One function for both transports makes
        /// the streaming branch reachable from a datagram, so the rule is a
        /// `match` on `Wire` and this is what holds it: AXFR is FORMERR because
        /// it is defined over TCP alone (RFC 5936 §4.2), and an IXFR is answered
        /// with a single SOA of the current version, which tells the client to
        /// come back over TCP (RFC 1995 §2).
        ///
        /// Nothing covered either rule before. Watched failing against a gate
        /// that trusts the caller: dropping the `Wire::Framed` guard streams the
        /// zone into the datagram path, and both assertions go.
        #[tokio::test]
        async fn a_transfer_over_udp_is_answered_rather_than_streamed() {
            let server = server_with(one_record_zone());
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
            let peer = client.local_addr().expect("addr");

            for (qtype, rcode, answers) in [
                (Qtype::AXFR, ResponseCode::FormatError, 0),
                (Qtype::IXFR, ResponseCode::Ok, 1),
            ] {
                let packet = query("example.com.", qtype, false)
                    .to_bytes_within(4096)
                    .expect("serialize");
                let mut scratch = Scratch::default();
                server
                    .answer(
                        &packet,
                        peer,
                        tsig::now(),
                        &Wire::Datagram(&socket, peer),
                        &mut scratch,
                    )
                    .await;

                let reply = DnsMessage::try_from_bytes(&scratch.out).expect("one parseable reply");
                assert_eq!(reply.rcode, rcode, "{qtype:?} over UDP");
                assert_eq!(
                    reply.answers.len(),
                    answers,
                    "{qtype:?} over UDP: the answer section"
                );
            }
        }

        /// A request that fails its TSIG check is still a request that arrived.
        ///
        /// The two dispatchers had drifted (`TODO.md` #39a): the TCP path counts
        /// `queries_received` and the query type before the TSIG check and this
        /// one counted them after, so a rejected request was a received query on
        /// one transport and not on the other. The exported name is
        /// `dns_queries_received_total`, "Total DNS queries received", and a
        /// request whose MAC does not verify arrived (`CLAUDE.md` §14: a
        /// counter's name is a claim about what it counts).
        ///
        /// Both transports in one test, because the claim is that they agree —
        /// which is what makes it a test of the *counter* and not of the copy
        /// #39b will delete. Watched failing against the old order: the UDP half
        /// read 0.
        #[tokio::test]
        async fn a_rejected_tsig_is_a_received_query_on_both_transports() {
            use std::sync::atomic::Ordering;

            // A key the server does not hold, so `check_request` rejects with
            // BADKEY before anything can answer.
            let stranger = TsigKey::new(
                "stranger.key.",
                TsigAlgorithm::HmacSha256,
                b"0123456789012345678901234567890123456789".to_vec(),
            );
            let now = tsig::now();
            let signed = tsig::sign_request(a_query(), &stranger, now).expect("sign the query");

            let over_tcp = server_with(one_record_zone());
            let peer: SocketAddr = "127.0.0.1:5399".parse().expect("a peer address");
            let replies = answered(&over_tcp, &signed, peer).await;
            assert_eq!(replies.len(), 1, "a rejection is still answered, signed");

            let over_udp = server_with(one_record_zone());
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
            let mut scratch = Scratch::default();
            over_udp
                .answer(
                    &signed,
                    client.local_addr().expect("addr"),
                    now,
                    &Wire::Datagram(&socket, client.local_addr().expect("addr")),
                    &mut scratch,
                )
                .await;

            for (transport, server) in [("TCP", &over_tcp), ("UDP", &over_udp)] {
                assert_eq!(
                    server.ctx.metrics.queries_received.load(Ordering::Relaxed),
                    1,
                    "{transport} did not count a TSIG-rejected request as received"
                );
                assert_eq!(
                    server.ctx.metrics.queries_type_a.load(Ordering::Relaxed),
                    1,
                    "{transport} did not track the query type of a rejected request"
                );
            }
        }

        /// The pool answers, which is the part a refactor of the answer path has
        /// to establish before anything else about it is interesting.
        ///
        /// Drives the real `udp_loop` over a real socket rather than calling the
        /// answering code directly: the whole change is *where* the work happens
        /// relative to the receive, so a test that skipped the loop would skip
        /// the change.
        #[tokio::test]
        async fn a_worker_answers_a_datagram_it_received() {
            let shutdown = Shutdown::new();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
            let server_addr = socket.local_addr().expect("addr");
            let worker = tokio::spawn(udp_loop(
                socket,
                server_with(one_record_zone()),
                shutdown.stop_handle(),
                shutdown.busy(),
            ));

            let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
            client.send_to(&a_query(), server_addr).await.expect("send");
            let mut buf = vec![0u8; 4096];
            let (n, _) = client.recv_from(&mut buf).await.expect("an answer");
            let reply = DnsMessage::try_from_bytes(&buf[..n]).expect("a parseable answer");

            assert!(reply.response && reply.authoritive);
            assert_eq!(reply.rcode, ResponseCode::Ok);
            assert_eq!(reply.answers.len(), 1, "the A record for www");

            shutdown.begin();
            worker
                .await
                .expect("the worker joins")
                .expect("no io error");
        }

        /// A response sent to the UDP port must not be answered.
        ///
        /// `CLAUDE.md` §8: "A response is not a question. Test QR before doing
        /// anything with a packet that arrived at a listening socket, on both
        /// daemons. Two servers pointed at each other, or one spoofed
        /// datagram, is otherwise a packet loop neither end can see."
        ///
        /// UDP is the transport where a spoofed source and a packet loop
        /// matter. Both paths go through `rdns::validation::Request`, the only
        /// way to get a message out of a packet here, which refuses QR=1
        /// itself; this test says what the behaviour is.
        #[tokio::test]
        async fn a_response_to_the_udp_port_is_not_answered() {
            let server = server_with(one_record_zone());
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
            let peer = client.local_addr().expect("addr");

            let mut msg = query("www.example.com.", Qtype::of(record_types::A), false);
            msg.response = true; // QR=1: this is somebody's answer, not a question.
            let packet = msg.to_bytes_within(4096).expect("serialize");

            let mut scratch = Scratch::default();
            server
                .answer(
                    &packet,
                    peer,
                    tsig::now(),
                    &Wire::Datagram(&socket, peer),
                    &mut scratch,
                )
                .await;

            assert!(
                scratch.out.is_empty(),
                "a QR=1 datagram was answered; two such servers pointed at each \
                 other are a packet loop"
            );
        }

        /// The response buffer is the worker's, not the datagram's.
        ///
        /// What this is a regression for, since it cannot fail against the
        /// old code — the old code had no buffer to reuse, because a task per
        /// datagram has nowhere to keep one between datagrams. It fails against
        /// anyone putting `to_bytes_within` back in `answer_datagram`: swapping
        /// the two lines makes the second answer allocate afresh and the pointer
        /// move. Confirmed by doing exactly that.
        ///
        /// Asserted on the pointer and the capacity rather than on a timing,
        /// which is the same reason `a_small_response_does_not_carry_a_64k_buffer`
        /// asserts on capacity: both are exact and neither cares what else is
        /// running (`CLAUDE.md` §10).
        #[tokio::test]
        async fn answering_a_second_datagram_reuses_the_first_one_s_buffer() {
            let server = server_with(one_record_zone());
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
            let peer = client.local_addr().expect("addr");
            let packet = a_query();
            let mut scratch = Scratch::default();

            server
                .answer(
                    &packet,
                    peer,
                    tsig::now(),
                    &Wire::Datagram(&socket, peer),
                    &mut scratch,
                )
                .await;
            let (address, capacity) = (scratch.out.as_ptr(), scratch.out.capacity());
            assert!(!scratch.out.is_empty(), "the first answer was serialized");

            server
                .answer(
                    &packet,
                    peer,
                    tsig::now(),
                    &Wire::Datagram(&socket, peer),
                    &mut scratch,
                )
                .await;
            assert_eq!(
                scratch.out.as_ptr(),
                address,
                "the second answer reallocated: it is not reusing the buffer"
            );
            assert_eq!(scratch.out.capacity(), capacity);

            // Both were sent, so the reuse is of a buffer that really carried an
            // answer to the wire and not of one left over from a failure.
            let mut buf = vec![0u8; 4096];
            for _ in 0..2 {
                let (n, _) = client.recv_from(&mut buf).await.expect("an answer");
                assert_eq!(
                    DnsMessage::try_from_bytes(&buf[..n])
                        .expect("parseable")
                        .answers
                        .len(),
                    1
                );
            }
        }

        /// The default is the machine's parallelism, clamped at both ends — see
        /// [`default_udp_workers`] for why each end is where it is. A default of
        /// zero would bind the UDP socket and answer nothing on it.
        #[test]
        fn the_default_worker_count_is_within_its_clamp() {
            let workers = default_udp_workers();
            assert!(
                (2..=32).contains(&workers),
                "{workers} is outside the clamp the default promises"
            );
        }
    }

    // Graceful shutdown

    mod shutdown {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        /// A zone big enough that its AXFR spans many messages, so a transfer is
        /// reliably still in flight when the stop arrives. One message would make
        /// this test pass for the wrong reason.
        fn big_zone() -> Zone {
            let mut text = String::from(
                "$ORIGIN example.com.\n\
                 $TTL 3600\n\
                 @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                 @   IN NS  ns1.example.com.\n\
                 ns1 IN A   192.0.2.1\n",
            );
            for i in 0..4000 {
                text.push_str(&format!(
                    "host{i} IN A 10.{}.{}.{}\n",
                    (i >> 16) & 255,
                    (i >> 8) & 255,
                    i & 255
                ));
            }
            rdns::zone::parse_zone_file(&text, "example.com.").expect("the big zone parses")
        }

        /// Read one length-prefixed message.
        async fn read_message(stream: &mut TcpStream) -> Option<DnsMessage> {
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.ok()?;
            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).await.ok()?;
            DnsMessage::try_from_bytes(&body).ok()
        }

        async fn send_axfr_request(stream: &mut TcpStream) {
            let msg = query("example.com.", Qtype::of(record_types::AXFR), false);
            let bytes = msg.to_bytes_within(u16::MAX as usize).expect("serialize");
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            stream.write_all(&framed).await.expect("send the request");
        }

        /// The harm the whole item is about: `systemctl stop` used to cut an
        /// in-flight AXFR mid-stream, and the client cannot tell a truncated
        /// transfer from a complete one — it sees records, then silence, and a
        /// secondary that believes it holds a zone it holds half of.
        ///
        /// Drives the real `tcp_loop` and the real `serve_connection`, and stops
        /// the server after the first message of a multi-message transfer has
        /// arrived — so the stop is unambiguously mid-transfer.
        #[tokio::test]
        async fn a_transfer_in_flight_survives_the_stop() {
            let shutdown = Shutdown::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let loop_handle = tokio::spawn(tcp::serve(
                listener,
                server_with(big_zone()),
                TransportLimits::default(),
                tcp::RateLimit::PerMessage,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));

            let mut stream = TcpStream::connect(addr).await.expect("connect");
            send_axfr_request(&mut stream).await;

            // One message in: the transfer has begun and is not finished.
            let first = read_message(&mut stream).await.expect("the first message");
            assert!(!first.answers.is_empty());

            shutdown.begin();

            // Everything else must still arrive, ending with the closing SOA
            // that RFC 5936 §2.2 uses to bracket a transfer — which is exactly
            // the thing a cut connection withholds.
            let mut records = first.answers.len();
            let mut messages = 1;
            while let Some(msg) = read_message(&mut stream).await {
                records += msg.answers.len();
                messages += 1;
                let closed = msg
                    .answers
                    .last()
                    .is_some_and(|rr| rr.rdata.rtype() == record_types::SOA);
                if closed {
                    break;
                }
            }
            assert!(
                messages > 1,
                "the zone must not fit in one message or this proves nothing"
            );
            // 4000 hosts + SOA + NS + ns1 + the closing SOA.
            assert_eq!(
                records, 4004,
                "the transfer arrived short after {messages} messages"
            );

            // And the loop stopped accepting, so the drain can complete.
            let _ = tokio::time::timeout(Duration::from_secs(5), loop_handle)
                .await
                .expect("the accept loop must return on stop");
            assert!(
                shutdown.drain(Duration::from_secs(5)).await,
                "the drain must complete once the transfer is done"
            );
        }

        /// The other half: once stopped, nothing new is taken on. A connection
        /// opened after the signal gets no answer — the loop has returned, so the
        /// kernel's backlog holds the socket and the peer's retry goes to whatever
        /// replaces us.
        #[tokio::test]
        async fn nothing_new_is_accepted_after_the_stop() {
            let shutdown = Shutdown::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let loop_handle = tokio::spawn(tcp::serve(
                listener,
                server_with(big_zone()),
                TransportLimits::default(),
                tcp::RateLimit::PerMessage,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));

            shutdown.begin();
            let _ = tokio::time::timeout(Duration::from_secs(5), loop_handle)
                .await
                .expect("the accept loop must return on stop");

            // The listener is dropped with the loop, so this either fails to
            // connect or connects and is never answered. Both are "not served";
            // what must not happen is a reply.
            if let Ok(Ok(mut stream)) =
                tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(addr)).await
            {
                send_axfr_request(&mut stream).await;
                let answered =
                    tokio::time::timeout(Duration::from_secs(1), read_message(&mut stream)).await;
                assert!(
                    !matches!(answered, Ok(Some(_))),
                    "a stopped server answered a query it accepted after stopping"
                );
            }

            assert!(shutdown.drain(Duration::from_secs(5)).await);
        }

        /// A connection sitting idle between queries closes on the stop rather
        /// than holding the drain for its full idle timeout. This is the case
        /// that decides whether a shutdown takes milliseconds or the whole
        /// budget, since a resolver keeps connections open by design (RFC 7766
        /// §6.2.3) and most of them are idle at any moment.
        #[tokio::test]
        async fn an_idle_connection_does_not_hold_the_drain() {
            let shutdown = Shutdown::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(tcp::serve(
                listener,
                server_with(big_zone()),
                TransportLimits::default(),
                tcp::RateLimit::PerMessage,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));

            // Connect, ask one question, read the answer, then go quiet — which
            // is what a pooled connection does for most of its life.
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            let msg = query("example.com.", Qtype::of(record_types::SOA), false);
            let bytes = msg.to_bytes_within(u16::MAX as usize).expect("serialize");
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            stream.write_all(&framed).await.expect("send");
            read_message(&mut stream).await.expect("answer");

            shutdown.begin();

            // TCP_IDLE_TIMEOUT is ten seconds; this budget is well under it, so
            // passing means the connection observed the stop rather than timing
            // out. Keep the client end alive so nothing else can close it.
            let drained = shutdown.drain(Duration::from_secs(3)).await;
            drop(stream);
            assert!(
                drained,
                "an idle connection held the drain for its idle timeout"
            );
        }
    }

    // Who a TSIG key authorizes

    mod transfer_authorization {
        use super::*;
        use rdns::tsig::{TsigAlgorithm, TsigKey, TsigKeyring};

        fn key(zones: &[&str]) -> TsigKey {
            TsigKey::new(
                "partner.key.",
                TsigAlgorithm::HmacSha256,
                b"0123456789012345678901234567890123456789".to_vec(),
            )
            .for_zones(zones.iter().copied())
        }

        /// A primary holding both zones, with an empty ACL — so the key is the
        /// only thing that can authorize a transfer, which is the situation the
        /// bug was about.
        async fn primary_with(key: TsigKey) -> SocketAddr {
            let zone = rdns::zone::parse_zone_file(
                "$ORIGIN example.com.\n\
                 $TTL 3600\n\
                 @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                 @   IN NS  ns1.example.com.\n\
                 ns1 IN A   192.0.2.1\n",
                "example.com.",
            )
            .expect("parse");
            spawn_primary_with_keys(zone, &[], DeltaLog::new(), TsigKeyring::new(vec![key])).await
        }

        /// The bug: `answer_transfer` asked only whether a session *existed*, so
        /// any key in the keyring transferred any zone and bypassed
        /// `--allow-transfer` entirely. Hand a per-customer key to one partner and
        /// you handed them every zone on the server.
        #[tokio::test]
        async fn a_key_scoped_to_another_zone_cannot_transfer_this_one() {
            let scoped = key(&["other.test."]);
            let master = primary_with(scoped.clone()).await;

            let err = rdns::xfr::fetch_zone(master, nm("example.com.").as_ref(), Some(&scoped))
                .await
                .expect_err("a key scoped to other.test. must not transfer example.com.");
            // REFUSED, and reported as a refusal rather than as a bad signature:
            // the peer proved who it is and the answer is still no.
            assert!(
                err.to_string().contains("Refused"),
                "want a refusal, got: {err}"
            );
        }

        /// The control. Narrowing must not break the case it exists to serve.
        #[tokio::test]
        async fn a_key_scoped_to_this_zone_transfers_it() {
            let scoped = key(&["example.com."]);
            let master = primary_with(scoped.clone()).await;

            let zone = rdns::xfr::fetch_zone(master, nm("example.com.").as_ref(), Some(&scoped))
                .await
                .expect("a key naming this zone must transfer it");
            assert_eq!(zone.serial(), Some(Serial::new(1)));
        }

        /// Case-insensitively, and with or without the trailing dot — a zone name
        /// is a domain name, and every other comparison in this codebase folds
        /// ASCII case (RFC 4343). An operator who wrote `EXAMPLE.COM` in a flag
        /// must not get a silent refusal at 3am.
        #[tokio::test]
        async fn the_zone_list_is_matched_as_a_domain_name() {
            let scoped = key(&["EXAMPLE.com"]);
            let master = primary_with(scoped.clone()).await;

            let zone = rdns::xfr::fetch_zone(master, nm("example.com.").as_ref(), Some(&scoped))
                .await
                .expect("case and the trailing dot must not decide authorization");
            assert_eq!(zone.serial(), Some(Serial::new(1)));
        }

        /// The preserved default, stated as a test so that changing it is a
        /// deliberate act rather than a side effect. A key with no zone list still
        /// transfers everything: making it deny instead would mean upgrading the
        /// binary silently stops every transfer on a working deployment.
        #[tokio::test]
        async fn a_key_with_no_zone_list_still_transfers_everything() {
            let unscoped = key(&[]);
            let master = primary_with(unscoped.clone()).await;

            let zone = rdns::xfr::fetch_zone(master, nm("example.com.").as_ref(), Some(&unscoped))
                .await
                .expect("an unscoped key is unrestricted, as it always was");
            assert_eq!(zone.serial(), Some(Serial::new(1)));
        }
    }

    /// A primary on a loopback port, answering with `rdnsd`'s own AXFR path.
    ///
    /// Deliberately the real thing rather than a stub: `Server::serve_connection`
    /// is what a live `rdnsd` answers a transfer with, ACL and all, so what this
    /// exercises is the two halves of this codebase against each other rather
    /// than the secondary against a convenient fiction.
    async fn spawn_primary(zone_text: &str) -> SocketAddr {
        spawn_primary_with_acl(zone_text, &["127.0.0.1".to_string()]).await
    }

    /// A primary serving `new_text` that remembers the step from `old_text` —
    /// what a real one holds after a reload, and what lets it answer an IXFR.
    async fn spawn_primary_with_history(old_text: &str, new_text: &str) -> SocketAddr {
        let old =
            rdns::zone::parse_zone_file(old_text, "example.com.").expect("parse the old zone");
        let new =
            rdns::zone::parse_zone_file(new_text, "example.com.").expect("parse the new zone");
        let mut log = DeltaLog::new();
        log.note_change(Some(&old), &new);
        spawn_primary_inner(new, &["127.0.0.1".to_string()], log).await
    }

    async fn spawn_primary_with_acl(zone_text: &str, acl: &[String]) -> SocketAddr {
        let zone = rdns::zone::parse_zone_file(zone_text, "example.com.").expect("parse the zone");
        spawn_primary_inner(zone, acl, DeltaLog::new()).await
    }

    async fn spawn_primary_inner(zone: Zone, acl: &[String], log: DeltaLog) -> SocketAddr {
        spawn_primary_with_keys(zone, acl, log, TsigKeyring::new(Vec::new())).await
    }

    /// A primary that knows some TSIG keys, for the authorization tests. The ACL
    /// is deliberately empty in those, so the key is the *only* thing that can
    /// grant a transfer.
    async fn spawn_primary_with_keys(
        zone: Zone,
        acl: &[String],
        log: DeltaLog,
        keys: TsigKeyring,
    ) -> SocketAddr {
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));

        let server = Arc::new(Server {
            zone_map: Arc::new(RwLock::new(Zones::new(zones))),
            ctx: test_context(),
            transfer_acl: Arc::new(TransferAcl::parse(acl).expect("acl")),
            tsig_keys: Arc::new(keys),
            secondaries: Arc::new(HashMap::new()),
            deltas: Arc::new(RwLock::new(log)),
            updates: Arc::new(UpdateHandling::disabled()),
            journal: None,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                tokio::spawn(tcp::serve_one(
                    stream,
                    peer,
                    server.clone(),
                    TransportLimits::default(),
                    tcp::RateLimit::PerMessage,
                    test_shutdown().stop_handle(),
                ));
            }
        });
        addr
    }

    // Dynamic UPDATE, end to end (RFC 2136)

    /// The zone every UPDATE test starts from.
    const UPDATE_ZONE: &str = "$ORIGIN example.com.\n\
         $TTL 3600\n\
         @    IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
         @    IN NS  ns1.example.com.\n\
         ns1  IN A   192.0.2.1\n\
         www  IN A   192.0.2.10\n";

    fn update_key(zones: rdns::tsig::UpdatePolicy) -> TsigKey {
        TsigKey::new("dhcp.key.", TsigAlgorithm::HmacSha256, vec![7u8; 32]).for_updates(zones)
    }

    /// A server serving `example.com.` out of a real directory it can write.
    async fn spawn_updatable(dir: &Path, key: TsigKey) -> SocketAddr {
        spawn_updatable_with_journal(dir, key, None).await
    }

    async fn spawn_updatable_with_journal(
        dir: &Path,
        key: TsigKey,
        journal: Option<Arc<rdns::journal::Journal>>,
    ) -> SocketAddr {
        std::fs::write(dir.join("example.com.zone"), UPDATE_ZONE).expect("write the zone file");
        let source = ZoneSource::Directory(dir.to_string_lossy().to_string());
        let zones = load_zones_from_source(&source, false, false).expect("load");

        let server = Arc::new(Server {
            zone_map: Arc::new(RwLock::new(Zones::new(zones))),
            ctx: test_context(),
            transfer_acl: Arc::new(TransferAcl::parse(&[]).expect("acl")),
            tsig_keys: Arc::new(TsigKeyring::new(vec![key])),
            secondaries: Arc::new(HashMap::new()),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
            updates: Arc::new(UpdateHandling {
                source: Some(source),
                signing: None,
                applying: tokio::sync::Mutex::new(()),
            }),
            journal,
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                tokio::spawn(tcp::serve_one(
                    stream,
                    peer,
                    server.clone(),
                    TransportLimits::default(),
                    tcp::RateLimit::PerMessage,
                    test_shutdown().stop_handle(),
                ));
            }
        });
        addr
    }

    /// An UPDATE message adding `name` with one A record, or whatever `changes`
    /// says.
    fn update_message(zone: &str, changes: Vec<ResourceRecord>) -> DnsMessage {
        DnsMessage {
            id: 0x2136,
            response: false,
            opcode: OpCode::Update,
            authoritive: false,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![rdns::QuerySection {
                qname: nm(zone),
                qtype: Qtype::of(record_types::SOA),
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: changes,
            additionals: Vec::new(),
            edns: None,
        }
    }

    fn a_record(name: &str, addr: &str) -> ResourceRecord {
        ResourceRecord {
            name: nm(name),
            class: rdns::Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                addr.parse().expect("an address"),
            ))
            .expect("encodes"),
        }
    }

    /// Send one message over TCP and read one reply.
    async fn round_trip(addr: SocketAddr, bytes: Vec<u8>) -> DnsMessage {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(&rdns::framed(&bytes).expect("the test message frames"))
            .await
            .expect("write");
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.expect("length prefix");
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut buf).await.expect("body");
        DnsMessage::try_from_bytes(&buf).expect("a reply")
    }

    /// An UPDATE reaches the zone file, not just the zone map.
    ///
    /// This is the assertion the whole design turns on, and it is why write-back
    /// is a precondition rather than a follow-on: the re-signing timer reloads
    /// every zone from its file (`ZoneSigning::resign_interval` explains why it
    /// must), so a change that lived only in memory would be discarded within one
    /// interval, silently, having told the client it succeeded. Asserting on the
    /// map alone would pass against exactly that bug.
    ///
    /// Watched failing against a handler that installed the new zone without
    /// writing the file: the map assertion passed, the file assertion did not.
    #[tokio::test]
    async fn an_update_is_applied_persisted_and_served() {
        let dir = ScratchDir::new("update-applied");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let addr = spawn_updatable(dir.path(), key.clone()).await;

        let message = update_message(
            "example.com.",
            vec![a_record("new.example.com.", "192.0.2.50")],
        );
        let bytes = message.to_bytes_within(4096).expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, &key, tsig::now()).expect("sign");
        let reply = round_trip(addr, signed).await;

        assert_eq!(reply.rcode, ResponseCode::Ok, "RFC 2136 §3.4.2.5");
        assert_eq!(reply.opcode, OpCode::Update, "the opcode is echoed");

        // Served: asked over the same socket, so this is the zone map answering
        // and not an inspection of internals.
        let asked = round_trip(
            addr,
            query("new.example.com.", Qtype::of(record_types::A), false)
                .to_bytes_within(4096)
                .expect("serialize"),
        )
        .await;
        assert_eq!(asked.rcode, ResponseCode::Ok);
        assert_eq!(
            asked.answers.len(),
            1,
            "the new record is being served: {:?}",
            asked.answers
        );

        // The file, which is the half that survives a reload.
        let written = std::fs::read_to_string(dir.join("example.com.zone")).expect("read back");
        assert!(
            written.contains("new.example.com."),
            "the record reached the file:\n{written}"
        );

        // And it reads back as a zone with the record and a moved serial, rather
        // than merely containing the right substring.
        let reloaded = rdns::zone::parse_zone_file(&written, "example.com.").expect("reparses");
        assert_eq!(
            reloaded
                .query(nm("new.example.com.").as_ref(), Qtype::of(record_types::A))
                .len(),
            1
        );
        assert_eq!(
            reloaded.serial(),
            Some(Serial::new(2)),
            "RFC 2136 §3.6: the serial moved with the contents"
        );
    }

    /// The three refusals, each with the code RFC 2136 gives it.
    ///
    /// They are not interchangeable and that is the point: NOTAUTH says "not my
    /// zone" (§3.1.1) and REFUSED says "not you" (§3.3), and a client uses the
    /// difference to decide whether to look for a different server or a
    /// different key.
    #[tokio::test]
    async fn an_unauthorized_update_is_refused_and_an_unknown_zone_is_notauth() {
        let dir = ScratchDir::new("update-refused");
        // Scoped to a zone this server does not serve, so the key is valid and
        // grants nothing here.
        let key = update_key(rdns::tsig::UpdatePolicy::Zones(vec![
            "elsewhere.test.".to_string()
        ]));
        let addr = spawn_updatable(dir.path(), key.clone()).await;
        let changes = vec![a_record("new.example.com.", "192.0.2.50")];

        // Unsigned: an UPDATE has no address-based path in, by design.
        let unsigned = update_message("example.com.", changes.clone())
            .to_bytes_within(4096)
            .expect("serialize");
        assert_eq!(
            round_trip(addr, unsigned).await.rcode,
            ResponseCode::Refused,
            "§3.3: an unsigned UPDATE has no credential"
        );

        // Signed with a key scoped to another zone.
        let bytes = update_message("example.com.", changes)
            .to_bytes_within(4096)
            .expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, &key, tsig::now()).expect("sign");
        assert_eq!(
            round_trip(addr, signed).await.rcode,
            ResponseCode::Refused,
            "§3.3: the key may not rewrite this zone"
        );

        // A zone this server is not authoritative for is NOTAUTH, not REFUSED —
        // the opposite of the query path's rule (`CLAUDE.md` §8).
        let elsewhere = update_message(
            "elsewhere.test.",
            vec![a_record("new.elsewhere.test.", "192.0.2.50")],
        )
        .to_bytes_within(4096)
        .expect("serialize");
        let signed = rdns::tsig::sign_request(elsewhere, &key, tsig::now()).expect("sign");
        assert_eq!(
            round_trip(addr, signed).await.rcode,
            ResponseCode::NotAuthorized,
            "§3.1.1: not one of this server's authority zones"
        );

        // Nothing was written on any of the three paths.
        let written = std::fs::read_to_string(dir.join("example.com.zone")).expect("read back");
        assert!(
            !written.contains("new.example.com."),
            "a refused UPDATE changes nothing:\n{written}"
        );
    }

    /// A server with no writable zone source refuses an UPDATE rather than
    /// applying it to memory alone.
    ///
    /// The distinction this protects is the one in [`UpdateHandling`]'s docs: an
    /// in-memory-only change is discarded by the next reload or re-signing run,
    /// silently, after the client was told it succeeded. Refusing is the honest
    /// answer, and it is the branch that exists because the field is an `Option`.
    #[tokio::test]
    async fn an_update_is_refused_without_a_writable_source() {
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let zone = rdns::zone::parse_zone_file(UPDATE_ZONE, "example.com.").expect("parse");
        let addr = spawn_primary_with_keys(
            zone,
            &[],
            DeltaLog::new(),
            TsigKeyring::new(vec![key.clone()]),
        )
        .await;

        let bytes = update_message(
            "example.com.",
            vec![a_record("new.example.com.", "192.0.2.50")],
        )
        .to_bytes_within(4096)
        .expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, &key, tsig::now()).expect("sign");
        assert_eq!(
            round_trip(addr, signed).await.rcode,
            ResponseCode::Refused,
            "a key that grants everything still cannot write a zone we cannot persist"
        );
    }

    /// An UPDATE leaves a journal, and the journal answers an IXFR from
    /// before it.
    ///
    /// Asserting on the file alone would not show it: what matters is that a
    /// *fresh* `DeltaLog`, as after a restart, can chain from the serial a
    /// secondary held beforehand. Anything less is a file that exists rather
    /// than a history that works.
    ///
    /// Watched failing with the journal write removed from `install_zone`:
    /// the update still applied and was still served, and `Journal::load` came
    /// back empty, so `chain_from` had nothing to answer with — which is
    /// precisely the pre-journal behaviour it is meant to replace.
    #[tokio::test]
    async fn an_update_leaves_a_journal_that_survives_the_process() {
        let dir = ScratchDir::new("update-journal");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let journal = Arc::new(rdns::journal::Journal::new(dir.path().to_path_buf()));
        let addr =
            spawn_updatable_with_journal(dir.path(), key.clone(), Some(journal.clone())).await;

        for (n, addr_text) in [(1u8, "192.0.2.51"), (2, "192.0.2.52")] {
            let bytes = update_message(
                "example.com.",
                vec![a_record(&format!("host{n}.example.com."), addr_text)],
            )
            .to_bytes_within(4096)
            .expect("serialize");
            let signed = rdns::tsig::sign_request(bytes, &key, tsig::now()).expect("sign");
            assert_eq!(round_trip(addr, signed).await.rcode, ResponseCode::Ok);
        }

        // A new process would see exactly this: the file, and nothing in memory.
        let restored = journal
            .load(nm("example.com.").as_ref())
            .expect("the journal reads back");
        assert_eq!(restored.len(), 2, "one step per update");
        assert_eq!(restored[0].from_serial, Serial::new(1), "the zone's serial");
        assert_eq!(restored[1].to_serial, Serial::new(3), "after two bumps");

        let mut log = DeltaLog::new();
        log.restore(nm("example.com.").as_ref(), restored);
        let chain = log
            .chain_from(nm("example.com.").as_ref(), Serial::new(1))
            .expect("a secondary at the pre-update serial can still be caught up");
        assert_eq!(chain.len(), 2);
        assert!(
            chain
                .iter()
                .flat_map(|d| d.added.iter())
                .any(|r| r.name == nm("host1.example.com.")),
            "and the records it was missing are in it"
        );
    }

    /// A prerequisite that does not hold stops the update, with its own RCODE
    /// (§3.2) and with the zone untouched — which is what makes an UPDATE a
    /// transaction rather than a sequence of edits.
    #[tokio::test]
    async fn a_failed_prerequisite_leaves_the_zone_alone() {
        let dir = ScratchDir::new("update-prereq");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let addr = spawn_updatable(dir.path(), key.clone()).await;

        let mut message = update_message(
            "example.com.",
            vec![a_record("new.example.com.", "192.0.2.50")],
        );
        // §2.4.3 CLASS=NONE: "no RRset of this type exists at this name" — and
        // `www` has an A, so it does not hold.
        message.answers = vec![ResourceRecord {
            name: nm("www.example.com."),
            class: rdns::Class::new(254),
            ttl: Ttl::ZERO,
            rdata: rdns::RecordData::new(record_types::A, Vec::new()).expect("bare"),
        }];
        let bytes = message.to_bytes_within(4096).expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, &key, tsig::now()).expect("sign");

        assert_eq!(
            round_trip(addr, signed).await.rcode,
            ResponseCode::ResourceRecordSetExistsForSomeReason,
            "§3.2.2 YXRRSET, not a generic failure"
        );
        let written = std::fs::read_to_string(dir.join("example.com.zone")).expect("read back");
        assert!(!written.contains("new.example.com."), "{written}");
        let reloaded = rdns::zone::parse_zone_file(&written, "example.com.").expect("reparses");
        assert_eq!(
            reloaded.serial(),
            Some(Serial::new(1)),
            "and the serial did not move either"
        );
    }

    /// The replication context a refresh runs in, over a scratch directory.
    fn replication(dir: &ScratchDir, notify_targets: Vec<SocketAddr>) -> ReplicationContext {
        ReplicationContext {
            served: ZoneContext {
                zone_map: Arc::new(RwLock::new(Zones::default())),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
                metrics: Arc::new(DnsMetrics::new()),
                journal: None,
            },
            state: Arc::new(Mutex::new(StateFile::load(&state_file_path(dir.path())))),
            zone_dir: dir.path().to_path_buf(),
            notify_targets,
            // Nothing here probes `/readyz`; `readiness::tests` is where the
            // latch itself is checked.
            readiness: Readiness::ready(),
        }
    }

    fn zone_text(serial: u32) -> String {
        format!(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. {serial} 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.2\n"
        )
    }

    /// The whole of step 3 in one test: a zone this server has never seen is
    /// fetched, served, written down, and remembered.
    #[tokio::test]
    async fn test_a_secondary_fetches_serves_and_persists_a_zone() {
        let dir = ScratchDir::new("fetch");
        let master = spawn_primary(&zone_text(7)).await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
        };
        let r = replication(&dir, Vec::new());

        let outcome = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("refresh");
        assert!(outcome.contains("transferred serial 7"), "got: {outcome}");

        // Served from memory...
        let zones = r.served.zone_map.read().await;
        let held = zones
            .get(nm("example.com.").as_ref().folded().as_ref())
            .expect("the zone is now served");
        assert_eq!(held.serial(), Some(Serial::new(7)));
        assert_eq!(
            held.query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A))
                .len(),
            1
        );
        drop(zones);

        // ...written to disk, in the form the ordinary load path reads...
        let path = zone_file_path(dir.path(), "example.com.");
        let reloaded = parse_zone_file_at(&path, "example.com.").expect("reload from disk");
        assert_eq!(reloaded.serial(), Some(Serial::new(7)));
        assert_eq!(reloaded.records().len(), 4);

        // ...and remembered, so a restart knows when contact was last made.
        let entry = r
            .state
            .lock()
            .unwrap()
            .get("example.com.", master)
            .cloned()
            .expect("state recorded");
        assert_eq!(entry.serial, Serial::new(7));
        assert!(entry.refreshed_at > 0);

        // ...*on disk*, and not only in the copy held in memory. The assertion
        // above passes whether or not the sidecar was ever written, which is
        // exactly what a restart depends on — and the half a refactor of the
        // write path can break in silence. `record_state` updates under the
        // mutex and writes after dropping it, so "the entry is there" and "the
        // file has it" became two separate claims.
        let on_disk = StateFile::load(&state_file_path(dir.path()))
            .get("example.com.", master)
            .cloned()
            .expect("the sidecar on disk has the entry, not just the copy in memory");
        assert_eq!(on_disk.serial, Serial::new(7));
        assert_eq!(on_disk.refreshed_at, entry.refreshed_at);
    }

    /// The serial comparison is the point of the SOA probe: an unchanged zone
    /// must not be transferred again, or every refresh interval would move the
    /// whole zone for nothing.
    #[tokio::test]
    async fn test_an_unchanged_serial_is_not_transferred_again() {
        let dir = ScratchDir::new("unchanged");
        let master = spawn_primary(&zone_text(7)).await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
        };
        let r = replication(&dir, Vec::new());

        refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("first refresh");
        let second = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("second refresh");

        assert!(second.contains("current"), "got: {second}");
        assert_eq!(
            r.served
                .zone_map
                .read()
                .await
                .get(zkey("example.com.").as_slice())
                .unwrap()
                .serial(),
            Some(Serial::new(7))
        );
    }

    /// And a serial that moved forward *is* transferred, replacing the zone
    /// wholesale rather than merging into it.
    #[tokio::test]
    async fn test_a_bumped_serial_replaces_the_zone() {
        let dir = ScratchDir::new("bumped");
        let spec_zone = "example.com.".to_string();
        let r = replication(&dir, Vec::new());

        let old = spawn_primary(&zone_text(7)).await;
        refresh_once(
            &MasterSpec {
                zone: nm(&spec_zone.clone()),
                master: old,
                key_name: None,
            },
            None,
            &r,
            &test_shutdown().busy(),
        )
        .await
        .expect("first");

        // A primary whose zone has moved on — and lost a record, which is what
        // proves the zone is replaced rather than added to.
        let new = spawn_primary(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n",
        )
        .await;
        let outcome = refresh_once(
            &MasterSpec {
                zone: nm(&spec_zone),
                master: new,
                key_name: None,
            },
            None,
            &r,
            &test_shutdown().busy(),
        )
        .await
        .expect("second");

        assert!(outcome.contains("serial 7 -> 8"), "got: {outcome}");
        let zones = r.served.zone_map.read().await;
        let held = zones.get(zkey("example.com.").as_slice()).unwrap();
        assert_eq!(held.serial(), Some(Serial::new(8)));
        assert!(
            held.query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A))
                .is_empty(),
            "a record the new zone does not have must be gone, not merged"
        );
    }

    /// EXPIRE is the timer with teeth: out of contact past it, the zone stops
    /// being served rather than being answered for with stale data and AA set.
    #[tokio::test]
    async fn test_a_zone_out_of_contact_past_expire_is_withdrawn() {
        let dir = ScratchDir::new("expire");
        let master = "127.0.0.1:1"
            .parse()
            .expect("an address nothing answers on");
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
        };

        let zone = rdns::zone::parse_zone_file(&zone_text(7), "example.com.").expect("zone");
        let timers = RefreshTimers::from_zone(&zone).expect("timers");
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
        let zone_map = Arc::new(RwLock::new(Zones::new(zones)));

        let mut state_file = StateFile::load(&state_file_path(dir.path()));
        // Contact was made, a very long time ago.
        state_file
            .record(TransferState {
                zone: "example.com.".to_string(),
                serial: Serial::new(7),
                refreshed_at: current_unix_timestamp() - timers.expire - 1,
                master,
            })
            .expect("record");
        let state = Arc::new(Mutex::new(state_file));

        let r = ReplicationContext {
            served: ZoneContext {
                zone_map: zone_map.clone(),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
                metrics: Arc::new(DnsMetrics::new()),
                journal: None,
            },
            state: state.clone(),
            zone_dir: dir.path().to_path_buf(),
            notify_targets: Vec::new(),
            readiness: Readiness::ready(),
        };
        expire_if_out_of_contact(&spec, &r, current_unix_timestamp(), timers).await;
        assert!(
            zone_map.read().await.is_empty(),
            "an expired zone is no longer served"
        );

        // And the state line survives, so a restart still knows it is expired
        // rather than reading "nothing known" as "fetch and serve".
        assert!(state.lock().unwrap().get("example.com.", master).is_some());
    }

    /// Within EXPIRE, a failure to reach the master changes nothing: that is the
    /// whole point of having three timers rather than one.
    #[tokio::test]
    async fn test_a_recent_failure_does_not_withdraw_the_zone() {
        let dir = ScratchDir::new("still-good");
        let master = "127.0.0.1:1".parse().unwrap();
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
        };

        let zone = rdns::zone::parse_zone_file(&zone_text(7), "example.com.").expect("zone");
        let timers = RefreshTimers::from_zone(&zone).expect("timers");
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
        let zone_map = Arc::new(RwLock::new(Zones::new(zones)));

        let mut state_file = StateFile::load(&state_file_path(dir.path()));
        state_file
            .record(TransferState {
                zone: "example.com.".to_string(),
                serial: Serial::new(7),
                refreshed_at: current_unix_timestamp() - 60,
                master,
            })
            .expect("record");
        let state = Arc::new(Mutex::new(state_file));

        let r = ReplicationContext {
            served: ZoneContext {
                zone_map: zone_map.clone(),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
                metrics: Arc::new(DnsMetrics::new()),
                journal: None,
            },
            state: state.clone(),
            zone_dir: dir.path().to_path_buf(),
            notify_targets: Vec::new(),
            readiness: Readiness::ready(),
        };
        expire_if_out_of_contact(&spec, &r, current_unix_timestamp(), timers).await;
        assert_eq!(zone_map.read().await.len(), 1, "still served");
    }

    /// A refresh against a master that remembers the change moves only the
    /// difference — and lands on the same zone a full transfer would have.
    ///
    /// The equality is the assertion that matters: an incremental transfer that
    /// produces a *nearly* right zone is the failure mode this whole path has,
    /// and no serial comparison afterwards would ever notice it.
    #[tokio::test]
    async fn test_a_refresh_takes_the_increment_when_the_master_has_one() {
        let dir = ScratchDir::new("ixfr-in");
        let old_text = zone_text(7);
        let new_text = "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.250\n\
             extra IN TXT \"added in version 8\"\n";

        let r = replication(&dir, Vec::new());

        // Start from version 7, fetched in full because we hold nothing yet.
        let first = spawn_primary(&old_text).await;
        let spec = |master| MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
        };
        refresh_once(&spec(first), None, &r, &test_shutdown().busy())
            .await
            .expect("initial transfer");

        // Now a master that knows how to get from 7 to 8.
        let master = spawn_primary_with_history(&old_text, new_text).await;
        let outcome = refresh_once(&spec(master), None, &r, &test_shutdown().busy())
            .await
            .expect("incremental refresh");
        assert!(
            outcome.contains("1 incremental step(s)"),
            "expected an increment, got: {outcome}"
        );

        let zones = r.served.zone_map.read().await;
        let held = zones
            .get(zkey("example.com.").as_slice())
            .expect("still served");
        assert_eq!(held.serial(), Some(Serial::new(8)));
        assert_eq!(
            held.query(
                nm("extra.example.com.").as_ref(),
                Qtype::of(record_types::TXT)
            )
            .len(),
            1
        );
        assert!(
            held.query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A))
                .iter()
                .all(|r| r
                    .rdata
                    .parse()
                    .map(
                        |p| matches!(p, rdns::ParsedRecord::A(a) if a.octets() == [192, 0, 2, 250])
                    )
                    .unwrap_or(false)),
            "the old address must be gone, not merged"
        );

        // Record for record, the zone the master serves.
        let expected = rdns::zone::parse_zone_file(new_text, "example.com.").unwrap();
        let key = |z: &Zone| {
            let mut rows: Vec<_> = z
                .records()
                .iter()
                .map(|r| {
                    (
                        r.name.as_ref().to_folded().to_string(),
                        r.ttl,
                        r.rdata.clone(),
                    )
                })
                .collect();
            rows.sort_by_key(|r| (r.0.clone(), r.2.rtype()));
            rows
        };
        assert_eq!(
            key(held),
            key(&expected),
            "the increment reproduced the zone"
        );
    }

    /// A secondary that takes a transfer tells its own secondaries at once.
    ///
    /// Without this, only a *primary* ever announces — at startup and on SIGHUP —
    /// so the first level of a replication tree updates immediately and every
    /// level below it waits out a refresh timer. RFC 1996 §3.2's "master" is
    /// whoever serves the zone to someone, which a secondary in the middle is.
    #[tokio::test]
    async fn test_a_secondary_announces_what_it_transferred() {
        let dir = ScratchDir::new("announce");
        let master = spawn_primary(&zone_text(11)).await;

        // A socket standing in for a downstream secondary, so the NOTIFY is
        // caught on the wire rather than inferred from a log line.
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");

        let r = replication(&dir, vec![target]);
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
        };

        refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("transfer");

        let mut buf = vec![0u8; 4096];
        let (n, _from) =
            tokio::time::timeout(Duration::from_secs(5), downstream.recv_from(&mut buf))
                .await
                .expect("a NOTIFY should arrive")
                .expect("recv");

        let msg = DnsMessage::try_from_bytes(&buf[..n]).expect("parse the NOTIFY");
        assert_eq!(msg.opcode, OpCode::Notify, "a NOTIFY, not a query");
        assert!(!msg.response);
        assert_eq!(
            notify::notified_zone(&msg),
            Some(nm("example.com.")),
            "for the zone that moved"
        );
        assert_eq!(
            notify::notified_serial(&msg),
            Some(Serial::new(11)),
            "carrying the serial we just transferred, so the downstream \
             secondary need not ask"
        );
    }

    /// Nothing is announced when nothing moved: a refresh that confirms the
    /// serial is unchanged is not news, and telling anyone would cost them a
    /// pointless SOA probe every refresh interval.
    #[tokio::test]
    async fn test_an_unchanged_refresh_announces_nothing() {
        let dir = ScratchDir::new("announce-quiet");
        let master = spawn_primary(&zone_text(11)).await;
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");

        let r = replication(&dir, vec![target]);
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
        };

        // The first transfer announces; drain it.
        refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("transfer");
        let mut buf = vec![0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(5), downstream.recv_from(&mut buf))
            .await
            .expect("the first NOTIFY");

        // The second finds the same serial and must say nothing.
        let outcome = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("second refresh");
        assert!(outcome.contains("current"), "got: {outcome}");
        assert!(
            tokio::time::timeout(Duration::from_millis(500), downstream.recv_from(&mut buf))
                .await
                .is_err(),
            "an unchanged zone is not news"
        );
    }

    /// A secondary that receives a change can answer an IXFR for it — which is
    /// what makes one of these an interior node of a replication tree rather than
    /// a leaf. The delta only exists if the swap recorded it, so this is really a
    /// test that the zone map and the delta log move together.
    #[tokio::test]
    async fn test_a_transferred_change_becomes_an_increment_we_can_serve() {
        let dir = ScratchDir::new("ixfr-out");
        let r = replication(&dir, Vec::new());
        let spec = |master| MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
        };

        let first = spawn_primary(&zone_text(7)).await;
        refresh_once(&spec(first), None, &r, &test_shutdown().busy())
            .await
            .expect("first transfer");
        assert_eq!(
            r.served
                .deltas
                .read()
                .await
                .len(nm("example.com.").as_ref()),
            0,
            "a first fetch has no previous version to differ from"
        );

        let second = spawn_primary(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.250\n",
        )
        .await;
        refresh_once(&spec(second), None, &r, &test_shutdown().busy())
            .await
            .expect("second transfer");

        let log = r.served.deltas.read().await;
        assert_eq!(
            log.len(nm("example.com.").as_ref()),
            1,
            "the change was recorded"
        );
        let chain = log
            .chain_from(nm("example.com.").as_ref(), Serial::new(7))
            .expect("a chain from 7");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].to_serial, Serial::new(8));
        // www's address changed: one deletion, one addition.
        assert_eq!(chain[0].deleted.len(), 1);
        assert_eq!(chain[0].added.len(), 1);
    }

    /// A reload is a version step too, and a zone that leaves the configuration
    /// takes its history with it — we cannot offer increments of a zone we no
    /// longer serve.
    #[tokio::test]
    async fn test_a_reload_records_its_changes_and_forgets_removed_zones() {
        let zone_map = Arc::new(RwLock::new(Zones::default()));
        let deltas = Arc::new(RwLock::new(DeltaLog::new()));
        let parse = |text: &str, origin: &str| {
            rdns::zone::parse_zone_file(text, origin).expect("zone should parse")
        };

        let v7 = parse(&zone_text(7), "example.com.");
        let other = parse(
            "@ IN SOA ns1.other.test. admin.other.test. 1 3600 1800 604800 86400\n\
             @ IN NS ns1.other.test.\n",
            "other.test.",
        );
        let mut initial = HashMap::new();
        initial.insert(zone_key(&v7), std::sync::Arc::new(v7));
        initial.insert(zone_key(&other), std::sync::Arc::new(other));
        install_all_zones(&served(&zone_map, &deltas), initial).await;
        assert!(deltas.read().await.is_empty(), "nothing to differ from yet");

        // example.com. moves on; other.test. is dropped from the configuration.
        let v8 = parse(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.222\n",
            "example.com.",
        );
        let mut reloaded = HashMap::new();
        reloaded.insert(zone_key(&v8), std::sync::Arc::new(v8));
        install_all_zones(&served(&zone_map, &deltas), reloaded).await;

        let log = deltas.read().await;
        assert_eq!(
            log.len(nm("example.com.").as_ref()),
            1,
            "the reload is a version step"
        );
        assert_eq!(
            log.len(nm("other.test.").as_ref()),
            0,
            "a zone we no longer serve"
        );
        assert_eq!(zone_map.read().await.len(), 1);
    }

    /// A reload must not block every query for the length of its diffs:
    /// `ixfr::diff` runs under the read lock, and only the swap under the write
    /// lock.
    ///
    /// Self-calibrating: time one unlocked diff, then require a contiguous
    /// window at least half that long inside the reload in which a reader could
    /// have been admitted. Such a window exists only if the diff ran under a
    /// shared lock, and a slower box stretches baseline and window together. 90%
    /// of the reload with the split, 9% with the diff under the write lock.
    ///
    /// Not a ratio of `try_read` samples: `tokio::sync::RwLock` is fair, so
    /// `try_read` fails while a writer is merely queued, which measures wake
    /// latency against a denominator that is the sampler's spin rate.
    ///
    /// Multi-threaded, because the diff has no `.await`: on one thread the
    /// reload finishes before the reader is polled and the test passes against
    /// both versions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reload_does_not_hold_the_write_lock_across_its_diffs() {
        // Every record differs between the two versions, so nothing cancels out
        // and the diff does the most work it can — which is the work that used
        // to happen with every query waiting on it.
        const RECORDS: u32 = 6000;
        let version = |serial: u32, tail: u8| {
            let mut text = format!(
                "$TTL 3600\n\
                 @    IN SOA ns1.example.com. admin.example.com. {serial} 3600 1800 604800 86400\n\
                 @    IN NS  ns1.example.com.\n"
            );
            for i in 0..RECORDS {
                text.push_str(&format!("h{i} IN A 10.{}.{}.{tail}\n", i / 256, i % 256));
            }
            rdns::zone::parse_zone_file(&text, "example.com.").expect("zone should parse")
        };

        let v1 = version(1, 1);
        let v2 = version(2, 2);

        // Observing this is a race, and losing it is not a failure. If this
        // task is descheduled between spawning the reload and starting to
        // sample, the whole reload can be over before the first probe — there is
        // then nothing to measure and no verdict to give either way. On a
        // machine pinned to two cores with the rest of the suite running, about
        // one attempt in four saw nothing at all. So the *observation* is
        // retried, and only never managing to observe anything is a failure.
        // Each attempt gets its own map and log, so a retry cannot inherit
        // anything from the one before it.
        let mut observed = None;
        for _ in 0..16 {
            let zone_map = Arc::new(RwLock::new(Zones::default()));
            let deltas = Arc::new(RwLock::new(DeltaLog::new()));
            let mut initial = HashMap::new();
            initial.insert(zone_key(&v1), std::sync::Arc::new(v1.clone()));
            install_all_zones(&served(&zone_map, &deltas), initial).await;

            // What one diff costs on this machine right now, with no locks and
            // nothing else running: the yardstick the window below is measured
            // against. Timed here rather than assumed, because it is what makes
            // the assertion portable — CI's runner is several times slower than
            // this one and the comparison has to survive that.
            let mut baseline_zones = HashMap::new();
            baseline_zones.insert(zone_key(&v2), std::sync::Arc::new(v2.clone()));
            let baseline = {
                let zones = zone_map.read().await;
                let started = std::time::Instant::now();
                let plan = plan_reload(&zones, &baseline_zones);
                let elapsed = started.elapsed();
                std::hint::black_box(&plan);
                elapsed
            };

            let mut reloaded = HashMap::new();
            reloaded.insert(zone_key(&v2), std::sync::Arc::new(v2.clone()));
            let reloading = served(&zone_map, &deltas);
            let reload = tokio::spawn(async move {
                install_all_zones(&reloading, reloaded).await;
            });

            // Sample continuously for as long as the reload runs, rather than
            // asking once after a fixed delay: a single probe times out against
            // how long the diff happens to take on this machine, and a probe
            // that arrives after the reload has finished measures nothing.
            // Every sample is one query's worth of "could I have been answered
            // right now?".
            //
            // What is kept is the longest *contiguous stretch of time* over
            // which every sample was admitted. A stretch, rather than a count or
            // a fraction: the count depends on how often this loop gets
            // scheduled, and the fraction has the writer's wake latency in its
            // denominator. A stretch of wall-clock time has neither in it. Gaps
            // in sampling cannot shorten one either — only a refusal ends a
            // stretch — so a starved sampler measures the same window as an idle
            // one.
            let mut attempts = 0u32;
            let started = std::time::Instant::now();
            let mut stretch_began = started;
            let mut longest = std::time::Duration::ZERO;
            let mut admitted = true;
            while !reload.is_finished() {
                attempts += 1;
                let now = std::time::Instant::now();
                if zone_map.try_read().is_err() {
                    if admitted {
                        longest = longest.max(now - stretch_began);
                        admitted = false;
                    }
                } else if !admitted {
                    stretch_began = now;
                    admitted = true;
                }
                tokio::task::yield_now().await;
            }
            if admitted {
                longest = longest.max(std::time::Instant::now() - stretch_began);
            }
            reload.await.expect("the reload finished");

            assert_eq!(
                deltas.read().await.len(nm("example.com.").as_ref()),
                1,
                "the version step is recorded whether or not this attempt saw \
                 anything"
            );
            if attempts > 100 {
                observed = Some((longest, baseline, attempts));
                break;
            }
        }

        let Some((longest, baseline, attempts)) = observed else {
            panic!(
                "sixteen attempts and not one of them sampled the reload while it \
                 was running — this proves nothing either way, so it is a broken \
                 measurement rather than a broken lock discipline"
            );
        };

        // Half the baseline, which is a factor of five clear of both measured
        // shapes: the window is ~90% of a reload with the split and ~9% without
        // it, and the reload is a little longer than one diff. Halving leaves
        // room for the diff inside the reload to run slower than the unlocked
        // baseline — it is competing with this sampler, after all — without
        // leaving room for the old behaviour to pass.
        assert!(
            longest * 2 > baseline,
            "over {attempts} samples the longest window in which a reader could be \
             admitted was {longest:?}, against a {baseline:?} diff on this machine: \
             the diff is being held under the write lock again"
        );
    }

    /// An IXFR is gated by the same ACL as an AXFR, and it has to be: it may
    /// *answer* with the whole zone (RFC 1995 §4), so a policy that let it
    /// through would be no policy at all. The default is to refuse everyone, and
    /// this is the test that a new transfer type did not quietly escape it.
    #[tokio::test]
    async fn test_an_ixfr_is_refused_by_the_same_default_that_refuses_an_axfr() {
        let master = spawn_primary_with_acl(&zone_text(7), &[]).await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
        };
        let dir = ScratchDir::new("refused");
        let r = replication(&dir, Vec::new());

        // The AXFR our own client makes is refused, which is the baseline.
        let err = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Refused"), "got: {err}");

        // And so is an IXFR, over the same connection path.
        let request = {
            let mut msg = rdns::xfr::axfr_request(nm("example.com.").as_ref(), 0x33);
            msg.queries[0].qtype = Qtype::of(record_types::IXFR);
            msg
        };
        let mut buf = vec![0u8; 512];
        let n = request.to_bytes(&mut buf).expect("serialize");
        let mut framed = (n as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&buf[..n]);

        let mut stream = TcpStream::connect(master).await.expect("connect");
        stream.write_all(&framed).await.expect("send");
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.expect("length");
        let mut packet = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut packet).await.expect("reply");

        let reply = DnsMessage::try_from_bytes(&packet).expect("parse");
        assert_eq!(reply.rcode, ResponseCode::Refused);
        assert!(reply.answers.is_empty(), "a refusal carries no zone");
    }

    // Loading a directory of zones: three questions, three answers

    mod loading {
        use super::*;

        const GOOD: &str = "@ IN SOA ns1.example.com. admin.example.com. \
                            1 3600 600 604800 300\n@ IN NS ns1.example.com.\n";
        const BROKEN: &str = "@ IN SOA ns1.broken.test. admin.broken.test. \
                              1 3600 600 604800 300\nwww IN A not-an-address\n";

        fn dir_with(tag: &str, files: &[(&str, &str)]) -> ScratchDir {
            let dir = ScratchDir::new(tag);
            for (name, text) in files {
                std::fs::write(dir.join(name), text).expect("write zone");
            }
            dir
        }

        /// One bad file out of three used to be a line on stderr, exit code 0, and
        /// that zone answering REFUSED — indistinguishable from a zone nobody
        /// configured. It also defeated the all-or-nothing invariant
        /// `Reloading::load`'s own doc comment claims, because `install_all_zones`
        /// then installed the survivors wholesale: a broken file plus a deploy
        /// SIGHUP took a *previously working* zone off the air.
        #[tokio::test]
        async fn a_zone_file_that_fails_to_parse_fails_the_load() {
            let dir = dir_with(
                "partial",
                &[
                    ("example.com.zone", GOOD),
                    ("other.test.zone", GOOD),
                    ("broken.test.zone", BROKEN),
                ],
            );
            let source = ZoneSource::Directory(dir.path().to_string_lossy().to_string());

            let err = load_zones_from_source(&source, false, false)
                .expect_err("a broken zone file must not pass for a configuration choice")
                .to_string();
            assert!(
                err.to_string().contains("1 of 3"),
                "say how many of how many, so the scale is visible: {err}"
            );
            assert!(
                err.to_string().contains("--allow-partial-load"),
                "and say what to do about it: {err}"
            );
        }

        /// The escape hatch, because the behaviour is defensible when the
        /// alternative is worse — 39 of 40 zones beats none. It just has to be a
        /// decision rather than what happens when nobody looked.
        #[tokio::test]
        async fn allow_partial_load_serves_what_parsed() {
            let dir = dir_with(
                "partial-ok",
                &[("example.com.zone", GOOD), ("broken.test.zone", BROKEN)],
            );
            let source = ZoneSource::Directory(dir.path().to_string_lossy().to_string());

            let zones = load_zones_from_source(&source, false, true)
                .expect("the flag is an explicit choice to serve a partial set");
            assert_eq!(zones.len(), 1);
            assert!(zones.contains_key(zkey("example.com.").as_slice()));
        }

        /// A secondary's first start has nothing on disk yet, and refusing to run
        /// until a zone arrives would mean it never could.
        ///
        /// This is a regression test for a fix, not for the original bug.
        /// Removing the `unwrap_or_default()` that turned an unreadable directory
        /// into `Ok(empty)` also removed the only thing making an *empty*
        /// directory work, because `enumerate_zone_files` returned
        /// `Err("No .zone files found")` for one — and the commit that removed it
        /// claimed the opposite. Nothing caught it, because nothing tested a
        /// secondary starting from an empty directory. The emptiness check now
        /// lives in `load_zones_from_source`, which is the only place that knows
        /// whether the caller is a secondary.
        #[tokio::test]
        async fn a_secondary_may_start_with_an_empty_zone_directory() {
            let dir = dir_with("empty-secondary", &[]);
            let source = ZoneSource::Directory(dir.path().to_string_lossy().to_string());

            let zones = load_zones_from_source(&source, true, false)
                .expect("a secondary starts before its first transfer");
            assert!(zones.is_empty());

            // A primary with an empty --zone-dir is a typo in the path, and
            // serving nothing is not what was asked for.
            assert!(load_zones_from_source(&source, false, false).is_err());
        }

        /// The zone a secondary replicates, with an EXPIRE of one hour so the
        /// arithmetic in the tests below is legible.
        const REPLICATED: &str = "@ IN SOA ns1.example.com. admin.example.com. \
                                  7 3600 600 3600 300\n@ IN NS ns1.example.com.\n";

        /// A secondary mid-life: a zone dir, the spec it replicates under, and
        /// the two maps a withdrawal touches.
        struct Replica {
            dir: ScratchDir,
            specs: Vec<MasterSpec>,
            zone_map: Arc<RwLock<Zones>>,
            deltas: Arc<RwLock<DeltaLog>>,
        }

        fn replicated_setup(tag: &str) -> Replica {
            let dir = ScratchDir::new(tag);
            let zone = rdns::zone::parse_zone_file(REPLICATED, "example.com.").expect("zone");
            let mut zones = HashMap::new();
            zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
            let specs = vec![MasterSpec {
                zone: nm("example.com."),
                master: "192.0.2.1:53".parse().unwrap(),
                key_name: None,
            }];
            Replica {
                dir,
                specs,
                zone_map: Arc::new(RwLock::new(Zones::new(zones))),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
            }
        }

        fn record_contact(dir: &ScratchDir, master: &str, refreshed_at: u64) {
            let mut state = StateFile::load(&state_file_path(dir.path()));
            state
                .record(TransferState {
                    zone: "example.com.".to_string(),
                    serial: Serial::new(7),
                    refreshed_at,
                    master: master.parse().unwrap(),
                })
                .expect("write the sidecar");
        }

        /// Expiry that lasts only until the next deploy is not expiry.
        ///
        /// `expire_stale_zones_at_startup` ran from `main` and nowhere else, while
        /// `Reloading::load` re-reads every `.zone` file from disk without
        /// consulting the sidecar. A zone correctly withdrawn because its primary
        /// had been unreachable for a week came straight back on SIGHUP and was
        /// served with AA set — which is precisely the "permanently wrong
        /// answers nobody can see are wrong" the withdrawal code's own comment
        /// says it exists to prevent.
        #[tokio::test]
        async fn a_reload_does_not_resurrect_a_zone_that_expired() {
            let Replica {
                dir,
                specs,
                zone_map,
                deltas,
            } = replicated_setup("expire-reload");
            // Last contact two hours ago, against an EXPIRE of one.
            record_contact(&dir, "192.0.2.1:53", current_unix_timestamp() - 7200);

            withdraw_unvouched_zones(&specs, &served(&zone_map, &deltas), dir.path()).await;
            assert!(
                zone_map.read().await.is_empty(),
                "out of contact past EXPIRE is not ours to answer for"
            );

            // Now the reload: the file is still on disk, so it comes back.
            let zone = rdns::zone::parse_zone_file(REPLICATED, "example.com.").unwrap();
            let mut reloaded = HashMap::new();
            reloaded.insert(zone_key(&zone), std::sync::Arc::new(zone));
            install_all_zones(&served(&zone_map, &deltas), reloaded).await;
            assert_eq!(zone_map.read().await.len(), 1, "a reload re-reads the file");

            // ...and must be withdrawn again, which is the whole finding.
            withdraw_unvouched_zones(&specs, &served(&zone_map, &deltas), dir.path()).await;
            assert!(
                zone_map.read().await.is_empty(),
                "a SIGHUP is not new contact with the master"
            );
        }

        /// The other half: no record of contact at all.
        ///
        /// `StateFile::load` returns empty rather than failing — right for a
        /// cache, wrong for expiry, because forgetting the last-contact time *is*
        /// the difference between withdrawn and served. A missing or unreadable
        /// sidecar used to mean the stale copy on disk was served authoritatively
        /// from a cold start. Unknown age has to read as "do not serve": the zone
        /// comes back at the first successful transfer, which is what makes it
        /// ours to answer for in the first place.
        #[tokio::test]
        async fn a_zone_with_no_record_of_transfer_is_not_served() {
            let Replica {
                dir,
                specs,
                zone_map,
                deltas,
            } = replicated_setup("expire-nostate");
            assert!(!state_file_path(dir.path()).exists(), "no sidecar at all");

            withdraw_unvouched_zones(&specs, &served(&zone_map, &deltas), dir.path()).await;
            assert!(zone_map.read().await.is_empty());
        }

        /// A sidecar entry for a *different* master is not evidence about this
        /// one, and lands in the same place.
        #[tokio::test]
        async fn a_record_for_another_master_does_not_vouch_for_this_one() {
            let Replica {
                dir,
                specs,
                zone_map,
                deltas,
            } = replicated_setup("expire-othermaster");
            record_contact(&dir, "192.0.2.99:53", current_unix_timestamp());

            withdraw_unvouched_zones(&specs, &served(&zone_map, &deltas), dir.path()).await;
            assert!(zone_map.read().await.is_empty());
        }

        /// And the control, because the check has to be narrow: a zone in contact
        /// keeps being served, reload or no reload.
        #[tokio::test]
        async fn a_zone_in_contact_with_its_master_keeps_being_served() {
            let Replica {
                dir,
                specs,
                zone_map,
                deltas,
            } = replicated_setup("expire-fresh");
            record_contact(&dir, "192.0.2.1:53", current_unix_timestamp());

            withdraw_unvouched_zones(&specs, &served(&zone_map, &deltas), dir.path()).await;
            assert_eq!(zone_map.read().await.len(), 1);
        }

        /// A directory that cannot be read is fatal either way — this is the
        /// original #9c finding, and `--allow-partial-load` must not weaken it.
        /// "Some files failed to parse" and "the directory is not there" are
        /// different questions, and only the first one has a flag.
        #[tokio::test]
        async fn an_unreadable_directory_is_fatal_even_with_partial_load() {
            let missing = ZoneSource::Directory("no-such-directory-anywhere".to_string());
            for allow_partial in [false, true] {
                assert!(
                    load_zones_from_source(&missing, true, allow_partial).is_err(),
                    "allow_partial={allow_partial}: an I/O error is not a parse failure"
                );
            }
        }

        /// A reload must not take the runtime worker with it.
        ///
        /// Every step of a load blocks — `read_dir`, a parse per zone, an ECDSA
        /// signing run, verification — and it runs while both listeners are
        /// live.
        ///
        /// One worker thread, so the question has a yes-or-no answer instead of
        /// a ratio: if the load blocks the runtime, the ticker below is not
        /// polled once while it runs.
        ///
        /// The load has to be inside a spawned task. `#[tokio::test]` runs the
        /// body on the calling thread via `block_on`, so a blocking call there
        /// never occupies the worker it is supposed to be starving — the body is
        /// the observer.
        #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
        async fn a_reload_does_not_block_the_runtime_it_was_called_from() {
            // Enough parsing to take real time — the point is that whatever it
            // costs, it is not charged to the runtime.
            let mut records = String::new();
            for i in 0..4000 {
                records.push_str(&format!("h{i} IN A 10.{}.{}.1\n", i / 256, i % 256));
            }
            let dir = ScratchDir::new("reload-blocking");
            for zone in ["a", "b", "c", "d"] {
                let text = format!(
                    "@ IN SOA ns1.{zone}.test. admin.{zone}.test. 1 3600 600 604800 300\n\
                     @ IN NS ns1.{zone}.test.\n{records}"
                );
                std::fs::write(dir.join(format!("{zone}.test.zone")), text).expect("write");
            }

            let reloading = Reloading {
                replicating: false,
                allow_partial: false,
                secondaries: Vec::new(),
                zone_dir: Some(dir.path().to_path_buf()),
                signing: None,
                validator: Arc::new(DnssecValidator::new(false)),
            };
            let source = ZoneSource::Directory(dir.path().to_string_lossy().to_string());

            // Anything at all that wants the runtime while the reload runs — one
            // query's worth of "was I polled?".
            use std::sync::atomic::{AtomicU64, Ordering};
            let ticks = Arc::new(AtomicU64::new(0));
            let counting = ticks.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counting.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });

            // The loader announces itself and then does the work, so the count
            // is taken across the load and not across the scheduling that
            // preceded it.
            let (started, has_started) = tokio::sync::oneshot::channel();
            let loader = tokio::spawn(async move {
                let _ = started.send(());
                reloading.load(&source).await
            });
            has_started.await.expect("the loader started");
            let before = ticks.load(Ordering::Relaxed);

            let zones = loader.await.expect("the loading task").expect("zones load");
            let during = ticks.load(Ordering::Relaxed) - before;
            ticker.abort();

            assert_eq!(zones.len(), 4, "and it actually loaded them");
            assert!(
                during > 0,
                "nothing else on the runtime was polled during the reload — the \
                 parse and sign are back on the worker"
            );
        }
    }

    /// A *response* arriving at the server port is dropped, not answered.
    ///
    /// `AdmissionCheck` deliberately accepts QR=1 — it is used on both
    /// directions of the wire — so nothing between the socket and the zone lookup
    /// tested it, and `make_response` would happily build a reply to a reply. Two
    /// servers pointed at each other, or one spoofed datagram with a forged
    /// source, is then a packet loop that neither end can see is one.
    #[tokio::test]
    async fn a_response_sent_to_the_server_port_is_dropped() {
        let zone = rdns::zone::parse_zone_file(
            "@ IN SOA ns1.example.com. admin.example.com. 1 3600 600 604800 300\n\
             @ IN NS ns1.example.com.\n\
             ns1 IN A 192.0.2.1\n",
            "example.com.",
        )
        .expect("parse the zone");
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
        let server = Server {
            zone_map: Arc::new(RwLock::new(Zones::new(zones))),
            ctx: test_context(),
            journal: None,
            transfer_acl: Arc::new(TransferAcl::parse(&[]).expect("acl")),
            tsig_keys: Arc::new(TsigKeyring::new(Vec::new())),
            secondaries: Arc::new(HashMap::new()),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
            updates: Arc::new(UpdateHandling::disabled()),
        };
        let peer: SocketAddr = "192.0.2.9:5353".parse().unwrap();

        let wire = |msg: &DnsMessage| {
            let mut buf = vec![0u8; 512];
            let n = msg.to_bytes(&mut buf).expect("serialize");
            buf.truncate(n);
            buf
        };

        // The control: the same question, asked as a question, is answered.
        let mut question = query("ns1.example.com.", Qtype::of(record_types::A), false);
        assert!(
            !answered(&server, &wire(&question), peer).await.is_empty(),
            "a real query must still be answered — the check has to be narrow"
        );

        // The same bytes with QR set are a response, and get nothing back.
        question.response = true;
        assert!(
            answered(&server, &wire(&question), peer).await.is_empty(),
            "a response is not a question, and replying to one is a packet loop"
        );
    }

    // RFC 1034 §4.3.2's four cases live in `answer.rs`, with the code they test.

    // Signing, and answering a client that can read the result

    mod dnssec {
        use super::*;
        use rdns::dnssec::{dnskeys_in, rrsigs_in, verify_rrset, Dnskey, Rrset, RrsetProof};
        use rdns::dnssec_denial::{
            nsec3s_in, nsecs_in, proves_no_ds, proves_nxdomain, proves_wildcard_expansion, Denial,
            WildcardVerdict,
        };
        use rdns::zone::parse_zone_file;
        use rdns::RecordData;

        const SIGNED_ZONE: &str = r#"$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@   IN NS  ns1.example.com.
ns1 IN A   192.0.2.1
www IN A   192.0.2.10
deep.a.b IN TXT "down here"
"#;

        /// A server holding one signed zone, and the keys it was signed with.
        fn signed_server(nsec3: bool) -> (Zones, Vec<SigningKey>) {
            let keys = vec![
                SigningKey::generate(
                    SigningAlgorithm::EcdsaP256Sha256,
                    "example.com.",
                    DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
                )
                .unwrap(),
                SigningKey::generate(
                    SigningAlgorithm::EcdsaP256Sha256,
                    "example.com.",
                    DNSKEY_FLAG_ZONE,
                )
                .unwrap(),
            ];
            let policy = SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400)
                .with_chain(if nsec3 {
                    DenialChain::nsec3()
                } else {
                    DenialChain::Nsec
                });
            let zone = sign_zone(
                &parse_zone_file(SIGNED_ZONE, "example.com.").unwrap(),
                &keys,
                &policy,
            )
            .unwrap();
            let mut zones = Zones::default();
            drop(zones.insert(zone));
            (zones, keys)
        }

        fn keys_of(zones: &Zones) -> Vec<Dnskey> {
            let zone = &zones[zkey("example.com.").as_slice()];
            dnskeys_in(
                &zone
                    .query(nm("example.com.").as_ref(), Qtype::of(record_types::DNSKEY))
                    .into_iter()
                    .map(|r| ResourceRecord {
                        name: r.name.clone(),
                        class: r.class,
                        ttl: r.ttl,
                        rdata: r.rdata.clone(),
                    })
                    .collect::<Vec<_>>(),
            )
        }

        /// A zone with a wildcard and both kinds of delegation, which is what the
        /// referral and deep-synthesis proofs need and what `SIGNED_ZONE` above
        /// deliberately does not have — a wildcard at the apex would turn its
        /// NXDOMAIN tests into wildcard answers.
        const DELEGATING_ZONE: &str = r#"$ORIGIN example.com.
$TTL 3600
@         IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@         IN NS  ns1.example.com.
ns1       IN A   192.0.2.1
*         IN A   192.0.2.99
secure    IN NS  ns.secure.example.com.
secure    IN DS  12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns.secure IN A   192.0.2.20
plain     IN NS  ns.plain.example.com.
ns.plain  IN A   192.0.2.30
"#;

        fn signed_zones(text: &str, nsec3: bool) -> (Zones, Vec<SigningKey>) {
            let keys = vec![
                SigningKey::generate(
                    SigningAlgorithm::EcdsaP256Sha256,
                    "example.com.",
                    DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
                )
                .unwrap(),
                SigningKey::generate(
                    SigningAlgorithm::EcdsaP256Sha256,
                    "example.com.",
                    DNSKEY_FLAG_ZONE,
                )
                .unwrap(),
            ];
            let policy = SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400)
                .with_chain(if nsec3 {
                    DenialChain::nsec3()
                } else {
                    DenialChain::Nsec
                });
            let zone = sign_zone(
                &parse_zone_file(text, "example.com.").unwrap(),
                &keys,
                &policy,
            )
            .unwrap();
            let mut zones = Zones::default();
            drop(zones.insert(zone));
            (zones, keys)
        }

        /// The failure this is the regression test for: a signed zone with a
        /// wildcard SERVFAILed at every validator for every non-existent name two
        /// or more labels deep. The synthesis reached one label, so a deeper
        /// name became an NXDOMAIN — and then the wildcard denial asked the chain
        /// to cover `*.example.com.`, a name that is *in* the chain, so nothing
        /// covered it and the proof came back unproved. Failing closed is worse
        /// than failing open here: the zone was unusable rather than merely
        /// wrong.
        #[test]
        fn a_deep_wildcard_answer_verifies_and_proves_its_own_expansion() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(DELEGATING_ZONE, nsec3);
                let qname = "x.y.z.example.com.";
                let response = make_response(
                    &query(qname, Qtype::of(record_types::A), true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert_eq!(response.rcode, ResponseCode::Ok, "nsec3={nsec3}");
                let rdatas: Vec<RecordData> = response
                    .answers
                    .iter()
                    .filter(|r| r.rdata.rtype() == record_types::A)
                    .map(|r| r.rdata.clone())
                    .collect();
                assert_eq!(rdatas.len(), 1, "nsec3={nsec3}: no wildcard answer");

                let proof = verify_rrset(
                    &Rrset::new(nm(qname).as_ref(), record_types::A, Class::new(1), &rdatas),
                    &rrsigs_in(&response.answers),
                    &keys_of(&zones),
                    nm("example.com.").as_ref(),
                    current_unix_timestamp(),
                );
                let RrsetProof::Verified {
                    wildcard: Some(wildcard),
                    ..
                } = proof
                else {
                    panic!("nsec3={nsec3}: expected a wildcard expansion, got {proof:?}");
                };
                assert_eq!(wildcard, nm("*.example.com."));

                // And the denial it owes: without it one captured answer is a
                // valid answer for every name the wildcard reaches
                // (RFC 4035 §3.1.3).
                let verdict = proves_wildcard_expansion(
                    nm(qname).as_ref(),
                    wildcard.as_ref(),
                    &nsecs_in(&response.authorities),
                    &nsec3s_in(&response.authorities),
                );
                assert!(
                    matches!(verdict, WildcardVerdict::Proved),
                    "nsec3={nsec3}: {verdict:?}"
                );
            }
        }

        /// An ANY answer from a signed zone owes a signature over every
        /// RRset it returns, and the filter that finds them was
        /// `sig.type_covered != qtype` — which matches nothing for QTYPE 255,
        /// because no RRSIG covers a QTYPE. Left alone, making ANY return every
        /// type would have handed a validator the whole of a signed name's data
        /// with no signatures on it at all: bogus, not merely unsigned, and a
        /// SERVFAIL for the name.
        ///
        /// Judged with `verify_rrset` — the same code that judges a real zone
        /// off the internet — rather than by counting RRSIG records, because a
        /// signature that is present and does not verify passes a count
        /// (`CLAUDE.md` §1).
        #[test]
        fn an_any_answer_from_a_signed_zone_is_signed_rrset_by_rrset() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(SIGNED_ZONE, nsec3);
                let response = make_response(
                    &query("example.com.", Qtype::of(record_types::ANY), true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert_eq!(response.rcode, ResponseCode::Ok, "nsec3={nsec3}");

                // Every type the apex actually holds must be in the answer, and
                // the DNSSEC meta types must not: RFC 4035 §3.1.1 keeps NSEC and
                // the signatures out of the answer section, and an NSEC there
                // would also make an empty non-terminal look like data.
                for rtype in [record_types::SOA, record_types::NS, record_types::DNSKEY] {
                    assert!(
                        response.answers.iter().any(|r| r.rdata.rtype() == rtype),
                        "nsec3={nsec3}: type {rtype} missing from the ANY answer"
                    );
                }
                assert!(
                    !response.answers.iter().any(|r| matches!(
                        r.rdata.rtype(),
                        record_types::NSEC | record_types::NSEC3
                    )),
                    "nsec3={nsec3}: a denial record is not answer-section data"
                );

                // Then the part that matters: each RRset, against the zone's own
                // keys.
                let signatures = rrsigs_in(&response.answers);
                let keys = keys_of(&zones);
                for rtype in [record_types::SOA, record_types::NS, record_types::DNSKEY] {
                    let rdatas: Vec<RecordData> = response
                        .answers
                        .iter()
                        .filter(|r| r.rdata.rtype() == rtype)
                        .map(|r| r.rdata.clone())
                        .collect();
                    let proof = verify_rrset(
                        &Rrset::new(nm("example.com.").as_ref(), rtype, Class::new(1), &rdatas),
                        &signatures,
                        &keys,
                        nm("example.com.").as_ref(),
                        current_unix_timestamp(),
                    );
                    assert!(
                        matches!(proof, RrsetProof::Verified { .. }),
                        "nsec3={nsec3}: type {rtype} in an ANY answer: {proof:?}"
                    );
                }
            }
        }

        /// And without DO, an ANY answer carries the data and nothing else — the
        /// signatures are not volunteered to a client that did not ask for them
        /// (RFC 4035 §3.1.1), which is the other half of the same rule.
        #[test]
        fn an_any_answer_without_do_carries_no_dnssec_records() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(SIGNED_ZONE, nsec3);
                let response = make_response(
                    &query("example.com.", Qtype::of(record_types::ANY), false),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert_eq!(response.rcode, ResponseCode::Ok, "nsec3={nsec3}");
                assert!(
                    !response.answers.iter().any(|r| matches!(
                        r.rdata.rtype(),
                        record_types::RRSIG | record_types::NSEC | record_types::NSEC3
                    )),
                    "nsec3={nsec3}: DNSSEC records went out to a client that did not set DO"
                );
                assert!(
                    response
                        .answers
                        .iter()
                        .any(|r| r.rdata.rtype() == record_types::SOA),
                    "nsec3={nsec3}: but the zone's own data is still there"
                );
            }
        }

        /// A secure delegation hands down the DS and its signature, and the NS
        /// RRset goes out unsigned — it is the child's data (RFC 4035 §2.2).
        #[test]
        fn a_secure_referral_carries_the_ds_and_leaves_the_ns_rrset_unsigned() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(DELEGATING_ZONE, nsec3);
                let response = make_response(
                    &query("host.secure.example.com.", Qtype::of(record_types::A), true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert!(!response.authoritive, "nsec3={nsec3}");
                let ds: Vec<RecordData> = response
                    .authorities
                    .iter()
                    .filter(|r| r.rdata.rtype() == record_types::DS)
                    .map(|r| r.rdata.clone())
                    .collect();
                assert_eq!(
                    ds.len(),
                    1,
                    "nsec3={nsec3}: the DS is what continues the chain"
                );

                let sigs = rrsigs_in(&response.authorities);
                let proof = verify_rrset(
                    &Rrset::new(
                        nm("secure.example.com.").as_ref(),
                        record_types::DS,
                        Class::new(1),
                        &ds,
                    ),
                    &sigs,
                    &keys_of(&zones),
                    nm("example.com.").as_ref(),
                    current_unix_timestamp(),
                );
                assert!(
                    matches!(proof, RrsetProof::Verified { .. }),
                    "nsec3={nsec3}: an unsigned DS proves nothing: {proof:?}"
                );
                assert!(
                    !sigs.iter().any(|s| s.type_covered == record_types::NS),
                    "nsec3={nsec3}: the delegation's NS RRset must not be signed — every \
                     validator ignores the signature and the type shows up in the parent's \
                     bitmap as one that is not there"
                );
            }
        }

        /// An insecure delegation is the other half, and the more dangerous one:
        /// "there is no DS here" has to be *proved*, or stripping the DS is a
        /// downgrade to insecure and anything in the child may then be forged.
        #[test]
        fn an_insecure_referral_carries_a_signed_denial_of_the_ds() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_zones(DELEGATING_ZONE, nsec3);
                let response = make_response(
                    &query("host.plain.example.com.", Qtype::of(record_types::A), true),
                    &zones,
                    &DnsMetrics::new(),
                );

                assert!(!response.authoritive, "nsec3={nsec3}");
                assert!(
                    !response
                        .authorities
                        .iter()
                        .any(|r| r.rdata.rtype() == record_types::DS),
                    "nsec3={nsec3}: this child is not signed"
                );
                let denial = proves_no_ds(
                    nm("plain.example.com.").as_ref(),
                    &nsecs_in(&response.authorities),
                    &nsec3s_in(&response.authorities),
                );
                assert!(
                    matches!(denial, Denial::Proved),
                    "nsec3={nsec3}: {denial:?}"
                );
            }
        }

        #[test]
        fn a_do_query_gets_an_answer_a_validator_accepts() {
            let (zones, _keys) = signed_server(false);
            let metrics = DnsMetrics::new();
            let response = make_response(
                &query("www.example.com.", Qtype::of(record_types::A), true),
                &zones,
                &metrics,
            );

            // Judge it the way a client would: only what came back.
            let rdatas: Vec<RecordData> = response
                .answers
                .iter()
                .filter(|r| r.rdata.rtype() == record_types::A)
                .map(|r| r.rdata.clone())
                .collect();
            let proof = verify_rrset(
                &Rrset::new(
                    nm("www.example.com.").as_ref(),
                    record_types::A,
                    Class::new(1),
                    &rdatas,
                ),
                &rrsigs_in(&response.answers),
                &keys_of(&zones),
                nm("example.com.").as_ref(),
                current_unix_timestamp(),
            );
            assert!(matches!(proof, RrsetProof::Verified { .. }), "{proof:?}");
        }

        #[test]
        fn a_do_query_for_a_name_that_is_not_there_gets_the_proof() {
            for nsec3 in [false, true] {
                let (zones, _keys) = signed_server(nsec3);
                let metrics = DnsMetrics::new();
                let response = make_response(
                    &query("gone.a.b.example.com.", Qtype::of(record_types::A), true),
                    &zones,
                    &metrics,
                );
                assert_eq!(response.rcode, ResponseCode::NoSuchDomain);

                let denial = proves_nxdomain(
                    nm("gone.a.b.example.com.").as_ref(),
                    nm("example.com.").as_ref(),
                    &nsecs_in(&response.authorities),
                    &nsec3s_in(&response.authorities),
                );
                assert!(
                    matches!(denial, Denial::Proved),
                    "nsec3={nsec3}: {denial:?}"
                );
            }
        }

        #[test]
        fn a_client_that_did_not_ask_gets_no_dnssec_records() {
            // The DO bit is what says the client can read them. Sending them
            // anyway is bytes on an amplification path for a client that will
            // ignore them, and a response that may no longer fit a datagram.
            let (zones, _keys) = signed_server(false);
            let metrics = DnsMetrics::new();

            let answer = make_response(
                &query("www.example.com.", Qtype::of(record_types::A), false),
                &zones,
                &metrics,
            );
            assert!(rrsigs_in(&answer.answers).is_empty());
            assert!(!answer.edns().unwrap().do_bit);

            let denial = make_response(
                &query("nope.example.com.", Qtype::of(record_types::A), false),
                &zones,
                &metrics,
            );
            assert!(nsecs_in(&denial.authorities).is_empty());
            // The SOA is still there: a negative answer has always carried one
            // (RFC 2308), signed zone or not.
            assert!(denial
                .authorities
                .iter()
                .any(|r| r.rdata.rtype() == record_types::SOA));
        }

        #[test]
        fn the_do_bit_comes_back_set() {
            // RFC 3225 §3. Without it the client cannot tell an answer with no
            // DNSSEC records from a server that dropped them.
            let (zones, _keys) = signed_server(false);
            let metrics = DnsMetrics::new();
            let response = make_response(
                &query("www.example.com.", Qtype::of(record_types::A), true),
                &zones,
                &metrics,
            );
            assert!(response.edns().unwrap().do_bit);
        }

        #[test]
        fn an_unsigned_zone_answers_a_do_query_the_way_it_answers_any_other() {
            let mut zones = Zones::default();
            drop(zones.insert(parse_zone_file(SIGNED_ZONE, "example.com.").unwrap()));
            let metrics = DnsMetrics::new();

            let response = make_response(
                &query("www.example.com.", Qtype::of(record_types::A), true),
                &zones,
                &metrics,
            );
            assert_eq!(response.answers.len(), 1);
            assert!(rrsigs_in(&response.answers).is_empty());
        }

        #[test]
        fn keys_are_generated_loaded_and_used_without_anything_in_between() {
            // The whole operator path in one test: make the keys, point the
            // server at the directory, and have what it serves verify. Each
            // step is checked elsewhere; what this catches is the two ends not
            // meeting — a key written under a name the loader does not look
            // for, or loaded for a zone whose origin is spelled differently.
            let dir = ScratchDir::new("signing");
            generate_keys("example.com", dir.path(), "ECDSAP256SHA256").expect("generate");

            let zone_path = dir.join("example.com.zone");
            std::fs::write(&zone_path, SIGNED_ZONE).unwrap();

            let cli = Cli::parse_from([
                "rdnsd",
                "--zone-dir",
                dir.path().to_str().unwrap(),
                "--signing-key-dir",
                dir.path().to_str().unwrap(),
            ]);
            let signing = ZoneSigning::load(&cli, &BTreeMap::new())
                .expect("load keys")
                .expect("configured");

            let mut zones =
                enumerate_zone_files(dir.path().to_str().unwrap(), false).expect("zones");
            signing.apply(&mut zones).expect("sign");

            // Checked with the same validator the server runs before serving.
            let mut validator = DnssecValidator::new(true);
            validator.set_require_signed(true);
            verify_zones(&zones, &validator).expect("the zone we just signed verifies");

            let zones = Zones::new(zones);
            let metrics = DnsMetrics::new();
            let response = make_response(
                &query("www.example.com.", Qtype::of(record_types::A), true),
                &zones,
                &metrics,
            );
            assert_eq!(rrsigs_in(&response.answers).len(), 1);
        }

        #[test]
        fn require_signed_refuses_an_unsigned_zone_rather_than_serving_it() {
            let zone = parse_zone_file(SIGNED_ZONE, "example.com.").unwrap();
            let mut zones = HashMap::new();
            zones.insert(zone_key(&zone), std::sync::Arc::new(zone));

            let mut validator = DnssecValidator::new(true);
            validator.set_require_signed(true);
            let err = verify_zones(&zones, &validator).unwrap_err();
            assert!(err.to_string().contains("not signed"), "{err}");

            // And without the assertion, the same zone is fine: most zones are
            // unsigned and serving them is the normal case.
            let permissive = DnssecValidator::new(true);
            assert!(verify_zones(&zones, &permissive).is_ok());
        }

        #[test]
        fn a_signature_that_stopped_matching_its_records_stops_the_server() {
            // The failure this check exists for: the zone file was edited and
            // the signatures were not renewed, so what goes out is signed data
            // that no longer says what the signature says it says.
            let (mut zones, _keys) = signed_server(false);
            let edited = {
                let zone = zones
                    .matching(nm("example.com.").as_ref())
                    .expect("the signed zone");
                let mut edited = Zone::new(nm(&zone.origin().to_string()));
                for record in zone.records() {
                    let mut record = record.clone();
                    if record.name == nm("www.example.com.")
                        && record.rdata.rtype() == record_types::A
                    {
                        record.rdata = RecordData::from_parsed(&rdns::ParsedRecord::A(
                            "198.51.100.9".parse().unwrap(),
                        ))
                        .unwrap();
                    }
                    edited.add_record(record);
                }
                edited
            };
            drop(zones.insert(edited));

            let validator = DnssecValidator::new(true);
            let err = verify_zones(&zones, &validator).unwrap_err();
            assert!(err.to_string().contains("does not verify"), "{err}");
        }
    }
}
