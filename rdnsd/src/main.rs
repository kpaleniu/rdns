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
/// Consuming catalog zones: what `--catalog` provisions (RFC 9432).
mod catalog;
mod config;
/// Control socket. Needs a Unix domain socket, so Unix only.
#[cfg(unix)]
mod control;
/// Answering one request, on either transport.
mod dispatch;
mod dnstap;
mod replication;
/// What a signed answer weighs, for `TODO.md` #41's choice of ceiling.
#[cfg(test)]
mod response_size;
#[cfg(test)]
mod testutil;
mod zones;

use catalog::{parse_catalog_specs, Catalogs};
use replication::{
    parse_secondary_specs, resolve_key, spawn_secondaries, withdraw_unvouched_zones,
    ReplicationContext, Secondaries,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zones::{
    discard_orphan_journals, install_all_zones, load_zones_from_source, note_serials,
    restore_journals, validate_zone_source, verify_zones, ProvenSigning, SigningRun, ZoneContext,
    ZoneMap, ZoneSigning, ZoneSource, Zones,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rdns::clock::Clock;
use rdns::compression::NameCompressor;
use rdns::tls_identity::TlsIdentity;
use rdns::xot::XotTrust;
use rdns::{
    dnssec::{DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE},
    dnssec_key::{SigningAlgorithm, SigningKey},
    dnssec_validation_mode::DnssecValidator,
    ixfr::DeltaLog,
    journal::Journal,
    logging::{watch_anomalies, AnomalyThresholds, LogLevel, QueryLogger},
    metrics::DnsMetrics,
    notify::{self, NotifyOutcome, NotifyPeer, NotifyPolicy},
    readiness::Readiness,
    secondary::{state_file_path, StateFile},
    security::{RateLimitConfig, RateLimiter, ResponseLimiter, TransferAcl},
    shutdown::{next_reload, reload_signal, Busy, Lifecycle, Shutdown, Stop},
    socket::bind_addr_for,
    tsig::{self, TsigKeyring},
    validation::{AdmissionCheck, AdmissionLimits, Transport},
    zone::Zone,
    DnsMessage, ResourceRecord, Serial,
};
use rdns::{Name, NameRef, UdpSizes};
// Test-only since `TODO.md` #38d moved the transfer and UPDATE answering, which
// were the non-test callers, into `dispatch`.
#[cfg(test)]
use rdns::{clock::current_unix_timestamp, zone::parse_zone_file_at};
use rdns_transport::https;
use rdns_transport::metrics_server;
use rdns_transport::quic;
use rdns_transport::tcp;
use rdns_transport::tls::{self, CertificateStore};
use rdns_transport::{recv_error_is_transient, ServeContext, TransportLimits, UDP_RECEIVE_BUFFER};

/// The request caps `--max-udp-request` and `--max-tcp-request` ask for, with the
/// one floor this daemon adds to [`AdmissionLimits::new`]'s.
///
/// The UDP cap may not go below `--udp-payload-size`. That number is in every
/// reply's OPT as what this server can reassemble (RFC 6891 §6.2.4), so a lower
/// cap makes the advertisement a promise the server breaks — and breaks it in
/// silence, which is exactly what `TODO.md` #40f found. Above it is the
/// operator's business: accepting more than was advertised misleads nobody.
fn admission_limits(udp: UdpSizes, max_udp: u16, max_tcp: u16) -> AdmissionLimits {
    AdmissionLimits::new(max_udp.max(udp.advertised()) as usize, max_tcp as usize)
}

// The daemon's defaults, in one place because each is spelled twice: `Cli`
// takes them through `default_value_t` and the config file's `[server]` and
// `[signing]` tables through `#[serde(default = "crate::...")]`. Sixteen had a
// literal on each side and nothing comparing them (`TODO.md` #63e);
// `default_udp_workers` is the one that did not, and is the shape.
//
// Here and not in `config`, because a flag's default is the daemon's and the
// file inherits it — and an item private in the crate root is visible to every
// module under it, which is all `config` needs (`CLAUDE.md` §17).

fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    53
}
fn default_response_rate() -> u32 {
    8192
}
fn default_query_rate() -> u32 {
    1000
}
fn default_query_burst() -> u32 {
    200
}
fn default_max_udp_request() -> u16 {
    4096
}
fn default_max_tcp_request() -> u16 {
    16 * 1024
}
fn default_udp_payload_size() -> u16 {
    rdns::FLAG_DAY_UDP_SIZE
}
fn default_max_udp_response() -> u16 {
    rdns::FLAG_DAY_UDP_SIZE
}
fn default_anomaly_interval() -> u64 {
    60
}
fn default_anomaly_query_rate() -> f64 {
    50.0
}
fn default_anomaly_error_percent() -> f64 {
    10.0
}
fn default_anomaly_source_queries() -> u64 {
    100
}
fn default_anomaly_source_refusals() -> u64 {
    5
}
fn default_dnstap_max_bytes() -> u64 {
    1_073_741_824
}
fn default_validity_days() -> u32 {
    30
}

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
    #[arg(long, default_value_t = default_host(), conflicts_with = "config")]
    host: String,
    /// Port to listen on, for both transports.
    #[arg(long, default_value_t = default_port(), conflicts_with = "config")]
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
    /// A catalog zone to consume: `zone@master[:port][#tsig-key-name]`,
    /// repeatable.
    ///
    /// The catalog is replicated like any other zone, and the zones it lists
    /// (RFC 9432) are then served as secondaries of the same master, signed
    /// with the same key. A zone the catalog stops listing stops being served
    /// and its file is deleted. Requires `--zone-dir`.
    #[arg(
        long,
        value_name = "ZONE@MASTER[:PORT][#KEY]",
        conflicts_with = "config"
    )]
    catalog: Vec<String>,
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
        default_value_t = default_validity_days(),
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
        default_value_t = default_response_rate(),
        conflicts_with = "config"
    )]
    response_rate: u32,
    /// Largest UDP request accepted, in octets.
    ///
    /// Floored at the payload size this server advertises it can reassemble
    /// (RFC 6891 §6.2.4), because that advertisement is a promise: refusing
    /// under it is how a client that believed us got silence, which is what this
    /// default being 512 did (`TODO.md` #40f). Raise it for a deployment whose
    /// signed UPDATEs are large — a 2,048-bit DKIM key rotation weighs 566
    /// octets with its TSIG, measured in
    /// `rdns/examples/request_size_probe.rs`. Over the cap is dropped in
    /// silence, so the effective value is in the startup line.
    #[arg(
        long,
        value_name = "OCTETS",
        default_value_t = default_max_udp_request(),
        conflicts_with = "config"
    )]
    max_udp_request: u16,
    /// UDP payload size advertised in every reply's OPT, in octets.
    ///
    /// What this server says it can reassemble (RFC 6891 §6.2.4), which is why
    /// it also floors `--max-udp-request`. 1232 is where BIND
    /// (`edns-udp-size`), Knot (`udp-max-payload`), NSD (`ipv4-edns-size`) and
    /// Unbound (`edns-buffer-size`) all landed after DNS Flag Day 2020. Floored
    /// at 512.
    #[arg(
        long,
        value_name = "OCTETS",
        default_value_t = default_udp_payload_size(),
        conflicts_with = "config"
    )]
    udp_payload_size: u16,
    /// Largest UDP reply this server will send, in octets.
    ///
    /// The client's own advertisement is honoured only down to this — a client
    /// asking for 65,535 got exactly that before `TODO.md` #41b, so a large
    /// signed answer left as ~45 IP fragments. Over it the reply is an empty
    /// TC=1 and the client asks again over TCP, which is never capped. What a
    /// signed answer off these zones weighs is measured in
    /// `rdnsd/src/response_size.rs`. 65535 is "whatever the client asked for";
    /// floored at 512.
    #[arg(
        long,
        value_name = "OCTETS",
        default_value_t = default_max_udp_response(),
        conflicts_with = "config"
    )]
    max_udp_response: u16,
    /// Largest TCP request accepted, in octets.
    ///
    /// Not a protocol limit — the length prefix allows 65,535 — but a request
    /// has no legitimate reason to be large, and a bulk UPDATE is the one that
    /// might be. Floored at 512.
    #[arg(
        long,
        value_name = "OCTETS",
        default_value_t = default_max_tcp_request(),
        conflicts_with = "config"
    )]
    max_tcp_request: u16,
    /// Queries per second, per client address. 0 turns the limit off.
    ///
    /// Over the limit is dropped silently, so the number has to be generous:
    /// `rdnsd`'s clients are resolvers, not end users. A backstop against a
    /// flood, not a quota.
    #[arg(
        long,
        value_name = "QUERIES_PER_SEC",
        default_value_t = default_query_rate(),
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
        default_value_t = default_query_burst(),
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
        default_value_t = default_anomaly_interval(),
        conflicts_with = "config"
    )]
    anomaly_interval: u64,
    /// Warn above this query rate, averaged over `--anomaly-interval`. 0 is off.
    #[arg(
        long,
        value_name = "QUERIES_PER_SEC",
        default_value_t = default_anomaly_query_rate(),
        conflicts_with = "config"
    )]
    anomaly_query_rate: f64,
    /// Warn when more than this percentage of an interval's queries failed.
    /// 0 is off.
    #[arg(
        long,
        value_name = "PERCENT",
        default_value_t = default_anomaly_error_percent(),
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
        default_value_t = default_anomaly_source_queries(),
        conflicts_with = "config"
    )]
    anomaly_source_queries: u64,
    /// Warn about a source the rate limiter refused more than this many times
    /// in one interval. 0 is off.
    #[arg(
        long,
        value_name = "REFUSALS",
        default_value_t = default_anomaly_source_refusals(),
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
    /// Also answer DNS over TLS here (RFC 7858). Needs --tls-cert and --tls-key.
    ///
    /// 853 is the assigned port. This is in addition to the plain UDP and TCP
    /// listeners on --port, not instead of them: a server that answered only
    /// over TLS could not be used by the resolvers that make up an
    /// authoritative server's clients.
    #[arg(long, value_name = "ADDR:PORT", conflicts_with = "config")]
    tls_listen: Option<String>,
    /// Also answer DNS over QUIC here (RFC 9250). Needs --tls-cert and --tls-key.
    ///
    /// 853 as well, and the two do not collide: DoT is TCP and DoQ is UDP, so an
    /// operator serving both writes the same number twice. The certificate is
    /// the same one, from the same store, reloaded by the same SIGHUP.
    #[arg(long, value_name = "ADDR:PORT", conflicts_with = "config")]
    quic_listen: Option<String>,
    /// Also answer DNS over HTTPS here (RFC 8484). Needs --tls-cert and --tls-key.
    ///
    /// 443 is the port, because DoH is meant to look like other HTTPS traffic
    /// and a port of its own would undo that.
    #[arg(long, value_name = "ADDR:PORT", conflicts_with = "config")]
    https_listen: Option<String>,
    /// The path --https-listen answers on. RFC 8484 makes this a template
    /// rather than a constant; /dns-query is what every deployment uses.
    #[arg(
        long,
        value_name = "PATH",
        default_value = rdns_transport::https::DEFAULT_PATH,
        conflicts_with = "config"
    )]
    https_path: String,
    /// The PEM certificate chain --tls-listen and --quic-listen present. Leaf
    /// first.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    tls_cert: Option<PathBuf>,
    /// The PEM private key for --tls-cert.
    ///
    /// Refused if it is readable by its group or by everybody, the same check
    /// the DNSSEC keys and a TSIG `secret-file` get. Unix only; Windows has no
    /// equivalent.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    tls_key: Option<PathBuf>,
    /// PEM trust anchors for zone transfers this server *fetches* over TLS
    /// (RFC 9103), which is what `--secondary ...+tls=name` asks for.
    ///
    /// Nothing here is a default: the anchors are whoever issues the
    /// certificates of the masters this server replicates from, which for a
    /// primary and its own secondaries is usually a private CA. A master
    /// holding a publicly issued certificate means pointing this at the
    /// system bundle, which is a PEM file like any other.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    transfer_tls_ca: Option<PathBuf>,
    /// PEM certificate chain this server presents to a master that asks for one
    /// (RFC 9103 §7.5's mutual TLS).
    ///
    /// Optional, and needed only when the master is configured to demand it —
    /// §7.5's other method is the address ACL plus TSIG, which every peer here
    /// speaks. Offered only if the master asks: a certificate configured for a
    /// master that never sends a CertificateRequest is never sent, so the
    /// startup banner says one is loaded rather than that mTLS is in force.
    #[arg(
        long,
        value_name = "PATH",
        requires = "transfer_tls_key",
        conflicts_with = "config"
    )]
    transfer_tls_cert: Option<PathBuf>,
    /// The PEM private key for --transfer-tls-cert.
    ///
    /// Refused if it is readable by its group or by everybody, the same check
    /// --tls-key gets. Unix only; Windows has no equivalent.
    #[arg(
        long,
        value_name = "PATH",
        requires = "transfer_tls_cert",
        conflicts_with = "config"
    )]
    transfer_tls_key: Option<PathBuf>,
    /// Refuse a zone transfer that did not arrive over an encrypted transport.
    ///
    /// The other half of RFC 9103: §11 says an individual transfer "is not
    /// considered protected by XoT unless both the client and server are
    /// configured to use only XoT", and this is the server's half of that.
    /// Needs a listener a transfer can arrive on — --tls-listen, --quic-listen
    /// or --https-listen — or every transfer is refused.
    #[arg(long, conflicts_with = "config")]
    transfer_tls_only: bool,
    /// Stream every answered request to a dnstap collector.
    ///
    /// `tcp:<addr:port>` for a collector, `file:<path>` for a capture `dnstap
    /// -r` reads. The scheme is not optional: a path and an address are both
    /// plausible bare, and guessing is how an operator gets the other one.
    ///
    /// This is the query *stream*, not the query log — the log deliberately
    /// says nothing per packet above DEBUG, which is why a pipeline needs its
    /// own output. The queue between the answer path and the sink is bounded
    /// and drops rather than blocking: `dns_dnstap_dropped_total` is the
    /// shortfall, and a collector that stops reading must not become an outage.
    ///
    /// No Unix socket, which is dnstap's usual transport: `tokio` has no
    /// `UnixStream` on Windows and a cfg-gated sink is a module that stops
    /// compiling on one platform behind a green suite. TCP is portable and does
    /// the same job.
    #[arg(
        long,
        value_name = "tcp:ADDR:PORT|file:PATH",
        conflicts_with = "config"
    )]
    dnstap: Option<String>,
    /// Stop writing a dnstap *file* after this many octets. 0 is no limit.
    ///
    /// A capture file is not rotated and not reopened, so without a bound it is
    /// a way to fill a disk and take the server down with it. Reaching the
    /// bound stops the writing, warns once, and counts every further payload as
    /// dropped. Ignored for a `tcp:` target, where the collector owns the
    /// storage.
    ///
    /// The config file's `server.dnstap-max-bytes` is the same setting, and
    /// takes its default from the same [`default_dnstap_max_bytes`].
    #[arg(
        long,
        value_name = "OCTETS",
        default_value_t = default_dnstap_max_bytes(),
        conflicts_with = "config"
    )]
    dnstap_max_bytes: u64,
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
    /// Refuse a transfer that did not arrive over TLS 1.3 (RFC 9103 §11,
    /// `--transfer-tls-only`). Beside the ACL because it is the other half of
    /// the same question — the ACL says who may ask, this says on what.
    transfer_tls_only: bool,
    tsig_keys: Arc<TsigKeyring>,
    /// The zones we replicate, so a NOTIFY can be told from a plausible one.
    secondaries: Arc<Secondaries>,
    /// Per-zone change history, so an IXFR can answer with the difference.
    /// Derived from the zone map, so the two are only updated together.
    deltas: Arc<RwLock<DeltaLog>>,
    /// `None` on a server with no writable zone source: every UPDATE refused.
    updates: Arc<UpdateHandling>,
    journal: Option<Arc<Journal>>,
    /// Where the query stream goes, or `None` when `--dnstap` was not given.
    /// See [`crate::dnstap`] for why the queue behind it drops.
    dnstap: Option<crate::dnstap::Sink>,
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
    /// Refuse a zone transfer that did not arrive encrypted (RFC 9103 §11).
    transfer_tls_only: bool,
    tsig_keys: TsigKeyring,
    /// Bytes per second per client, for UDP replies. 0 is off.
    response_rate: u32,
    /// Queries per second per client, with its burst and exemptions.
    query_limit: RateLimitConfig,
    /// The largest request each transport accepts.
    admission: AdmissionLimits,
    /// What every reply's OPT advertises, and the largest datagram this server
    /// will send.
    udp: UdpSizes,
    /// How often the anomaly warnings run, and what they warn about. Zero
    /// interval is off.
    anomalies: (Duration, AnomalyThresholds),
    /// How many UDP datagrams may be answered at once. Floored at 1 in `serve`.
    udp_workers: usize,
    /// Where to serve Prometheus metrics, if anywhere.
    metrics_listen: Option<String>,
    /// Where to answer DNS over TLS, and with what. `None` is off.
    tls: Option<TlsPolicy>,
    /// Whether every zone this server answers for is in the map yet, for
    /// `/readyz` on that same listener.
    readiness: Readiness,
    /// What a dynamic UPDATE needs; refuses everything when unconfigured.
    updates: Arc<UpdateHandling>,
    /// Where the delta log is persisted, if anywhere.
    journal: Option<Arc<Journal>>,
    /// Where the query stream goes, and what a capture file may weigh.
    dnstap: Option<(crate::dnstap::Target, u64)>,
    /// The control socket, and what a `reload` on it pokes.
    control: ControlPolicy,
}

/// `Dnstap.identity`: this host, as the environment names it.
///
/// `HOSTNAME` then `COMPUTERNAME`, and empty if neither is set — which the
/// encoder omits rather than writing as an empty string. `std` has no portable
/// way to ask the OS and a crate for one field of one optional output is not a
/// dependency this earns (`CLAUDE.md` §14). An operator who needs a particular
/// identity sets the variable, which is where a service manager already puts it.
fn hostname_bytes() -> Vec<u8> {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .map(String::into_bytes)
        .unwrap_or_default()
}

/// "853 (DoT), 853 (DoQ)", or whichever of the two is configured.
fn describe_encrypted(policy: &TlsPolicy) -> String {
    let mut parts = Vec::new();
    if let Some(addr) = &policy.dot {
        parts.push(format!("{addr} DoT"));
    }
    if let Some(addr) = &policy.doq {
        parts.push(format!("{addr} DoQ"));
    }
    if let Some((addr, path)) = &policy.doh {
        parts.push(format!("{addr}{path} DoH"));
    }
    parts.join(", ")
}

/// A DoT listener: the address, and the certificate it presents.
///
/// The store is shared with the reload path, so a renewed certificate is picked
/// up by `rdnsctl reload` or a SIGHUP rather than by a restart (`TODO.md` #42a).
struct TlsPolicy {
    /// Where to answer DNS over TLS, if anywhere.
    dot: Option<String>,
    /// Where to answer DNS over QUIC, if anywhere.
    doq: Option<String>,
    /// Where to answer DNS over HTTPS, and on what path.
    doh: Option<(String, String)>,
    /// One store for both, so a renewal reaches both listeners. Two stores over
    /// the same two files would be a certificate that expires on one port.
    store: Arc<CertificateStore>,
}

/// Where the control socket lives and how it asks for a reload.
#[cfg_attr(not(unix), allow(dead_code))]
struct ControlPolicy {
    socket: Option<PathBuf>,
    reloads: mpsc::Sender<ReloadTrigger>,
    /// Zones this server replicates, so `status` says `secondary` from what is
    /// being replicated rather than guessing from an absent timestamp, which a
    /// primary also has. The live registry, because a catalog's members are
    /// replicated and arrive after startup (`TODO.md` #44a).
    secondaries: Arc<Secondaries>,
    /// The catalogs this server consumes, so `status` can name the catalog a
    /// zone came from and `catalog` can report what one holds — refusals
    /// included, which have no zone and so no row in `status`
    /// (`TODO.md` #49).
    catalogs: Arc<crate::catalog::Catalogs>,
    /// For `status`'s uptime. Taken in `main`, not here: loading and signing
    /// every zone happens before `serve` and is the bulk of a big start.
    started: Instant,
}

/// Bind both transports and serve them from one process.
async fn serve(
    addr: &str,
    zone_map: Arc<RwLock<Zones>>,
    policy: ServePolicy,
    secondaries: Arc<Secondaries>,
    deltas: Arc<RwLock<DeltaLog>>,
    shutdown: Shutdown,
    metrics: Arc<DnsMetrics>,
) -> Result<()> {
    let ServePolicy {
        transfer_acl,
        transfer_tls_only,
        tsig_keys,
        response_rate,
        query_limit,
        admission,
        udp,
        anomalies: (anomaly_interval, anomaly_thresholds),
        udp_workers,
        metrics_listen,
        tls,
        readiness,
        updates,
        journal,
        dnstap,
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
    // Appended rather than folded in: `--transfer-tls-only` narrows whatever
    // the line above says, and an operator reading "allowed for 2 address
    // rule(s)" should not have to know the flag exists to find out that none of
    // them applies over plain TCP (RFC 9103 §11, `CLAUDE.md` §14).
    let transfers = if transfer_tls_only {
        format!("{transfers}, over TLS 1.3 only (--transfer-tls-only)")
    } else {
        transfers
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

    // And the same reason again: over the admission cap is dropped in silence, so
    // the startup line is the only place an operator learns the number.
    let (udp_cap, tcp_cap) = admission.caps();

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
    // And the TLS listener, for the same reason the metrics one is bound here:
    // a port conflict on 853 must stop the start rather than leave a server
    // running that a DoT client cannot reach and nothing reports.
    let tls_listener = match tls.as_ref().and_then(|p| p.dot.as_ref().map(|a| (p, a))) {
        Some((policy, addr)) => Some((
            TcpListener::bind(addr)
                .await
                .with_context(|| format!("--tls-listen {addr}"))?,
            tls::server_config(policy.store.clone())?,
        )),
        None => None,
    };
    let https_listener = match tls.as_ref().and_then(|p| p.doh.as_ref().map(|d| (p, d))) {
        Some((policy, (addr, path))) => Some((
            TcpListener::bind(addr)
                .await
                .with_context(|| format!("--https-listen {addr}"))?,
            https::endpoint(policy.store.clone(), path),
        )),
        None => None,
    };
    // quinn binds its own UDP socket, so this is the same "fail here, not after
    // one transport is up" rule applied to a different kind of listener.
    let quic_endpoint = match tls.as_ref().and_then(|p| p.doq.as_ref().map(|a| (p, a))) {
        Some((policy, addr)) => Some(
            quinn::Endpoint::server(
                quic::server_config(policy.store.clone(), TransportLimits::default())?,
                addr.parse()
                    .with_context(|| format!("--quic-listen {addr} is not an address:port"))?,
            )
            .with_context(|| format!("--quic-listen {addr}"))?,
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

    // Before the sockets, with the other things that must fail at startup: a
    // collector that is not listening, or a capture path that cannot be
    // written, is a misconfiguration and not a stream that quietly never
    // appears (`CLAUDE.md` §4).
    let dnstap = match &dnstap {
        Some((target, max_bytes)) => Some(
            crate::dnstap::Sink::spawn(
                target,
                *max_bytes,
                hostname_bytes(),
                format!("rdnsd {}", env!("CARGO_PKG_VERSION")).into_bytes(),
                (*metrics).clone(),
                shutdown.stop_handle(),
            )
            .await?,
        ),
        None => None,
    };

    let server = Arc::new(Server {
        zone_map,
        ctx: ServeContext {
            limiter: Arc::new(RateLimiter::new(query_limit)),
            responses: Arc::new(ResponseLimiter::per_second(response_rate)),
            validator: Arc::new(AdmissionCheck::new(admission.clone())),
            logger: Arc::new(QueryLogger::new()),
            metrics,
            udp,
            clock: Clock::system(),
        },
        transfer_acl: Arc::new(transfer_acl),
        transfer_tls_only,
        tsig_keys: Arc::new(tsig_keys),
        secondaries,
        deltas,
        updates,
        journal,
        dnstap,
    });
    // The effective policy, at the default level: a control nobody can observe
    // is a control nobody can debug.
    tracing::info!(
        "rdnsd listening on {addr} (UDP+TCP), zone transfer: {transfers}, \
         response budget: {budget}, query rate: {query_limit_note}, \
         request cap: {udp_cap}B UDP / {tcp_cap}B TCP, \
         UDP reply cap: {reply_cap}B (advertising {advertised}B), \
         UDP workers: {udp_workers}, anomaly warnings: {anomaly_note}, \
         TSIG keys: {}, encrypted: {}, metrics: {}, control: {}",
        server.tsig_keys.len(),
        match &tls {
            Some(policy) => {
                let (cert, key) = policy.store.paths();
                format!(
                    "{} (cert {}, key {})",
                    describe_encrypted(policy),
                    cert.display(),
                    key.display()
                )
            }
            None => "off (--tls-listen, --quic-listen)".to_string(),
        },
        match &metrics_listen {
            Some(spec) => format!("{spec}/metrics"),
            None => "off (--metrics-listen)".to_string(),
        },
        match &control.socket {
            Some(path) => format!("{} (mode 0600)", path.display()),
            None => "off (--control-socket)".to_string(),
        },
        reply_cap = udp.max_response(),
        advertised = udp.advertised(),
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
    // Same admission and the same rate rule as the plain TCP loop above: what
    // TLS changes is who can read the connection, not what this server will
    // answer on it.
    if let Some((tls_listener, config)) = tls_listener {
        loops.spawn(tls::serve(
            tls_listener,
            config,
            server.clone(),
            TransportLimits::default(),
            tcp::RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
    }
    if let Some(endpoint) = quic_endpoint {
        loops.spawn(quic::serve(
            endpoint,
            server.clone(),
            TransportLimits::default(),
            tcp::RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
    }
    if let Some((https_listener, endpoint)) = https_listener {
        loops.spawn(https::serve(
            https_listener,
            endpoint,
            server.clone(),
            TransportLimits::default(),
            tcp::RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
    }
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
            secondaries,
            catalogs,
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
                secondaries,
                catalogs,
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
    ///
    /// The live registry rather than the `--secondary` specs: a catalog's
    /// members are replicated zones whose files are in the same directory, and
    /// a list fixed at startup would let a reload serve one of those with AA set
    /// however long its master had been unreachable (`TODO.md` #44a).
    secondaries: Arc<Secondaries>,
    zone_dir: Option<PathBuf>,
    signing: Option<Arc<ZoneSigning>>,
    validator: Arc<DnssecValidator>,
    /// Shared with the startup pass, which is the run that proves most of it:
    /// a reload that re-signs a zone with the same keys has nothing new to
    /// check (`TODO.md` #53).
    proved: ProvenSigning,
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
    async fn load(&self, source: &ZoneSource, previous: Option<ZoneMap>) -> Result<ZoneMap> {
        let reloading = self.clone();
        let source = source.clone();
        tokio::task::spawn_blocking(move || reloading.load_blocking(&source, previous.as_ref()))
            .await
            .context("the zone-loading task")?
    }

    /// The blocking half of [`Reloading::load`], and named so at the call site.
    fn load_blocking(&self, source: &ZoneSource, previous: Option<&ZoneMap>) -> Result<ZoneMap> {
        let mut zones = load_zones_from_source(source, self.replicating, self.allow_partial)?;
        let run = match &self.signing {
            Some(signing) => signing.apply(&mut zones, previous)?,
            None => SigningRun::default(),
        };
        verify_zones(&zones, &self.validator, &run, &self.proved)?;
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
        let specs = self.secondaries.specs();
        if specs.is_empty() {
            return;
        }
        withdraw_unvouched_zones(&specs, served, zone_dir).await;
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
    /// Is this the reload whose point is that the signatures come out new?
    ///
    /// The re-signing timer refreshes *by reloading*
    /// ([`ZoneSigning::resign_interval`]), so it is the one trigger that may
    /// not carry a signature forward — everything it would carry is what it
    /// woke up to replace. SIGHUP and the control socket are an operator or a
    /// catalog saying the files moved, and there the served version is a
    /// previous version in exactly the sense `sign_zone_incrementally` means
    /// (`TODO.md` #65a).
    fn refreshes_signatures(&self) -> bool {
        matches!(self, ReloadTrigger::Timer)
    }

    /// What the log line says this reload was for.
    fn why(&self) -> &'static str {
        match self {
            ReloadTrigger::Signal => "SIGHUP",
            ReloadTrigger::Timer => "signature refresh",
            ReloadTrigger::Control(_) => "control socket",
        }
    }
}

/// Everything a reload acts on, fixed for the life of the process.
///
/// A struct because the list reached eight and clippy says so at seven, which
/// is `CLAUDE.md` §14's rule and the same one `ServePolicy` exists for: two of
/// these are `Arc`-shaped and two are path-shaped, one swap away from each
/// other with nothing to catch it.
struct ReloadContext {
    reloading: Reloading,
    source: ZoneSource,
    served: ZoneContext,
    notify: Arc<NotifyPolicy>,
    /// Re-read on every reload, so a renewed certificate costs a SIGHUP rather
    /// than a restart (`TODO.md` #42a). `None` when there is no DoT listener.
    tls: Option<Arc<CertificateStore>>,
}

/// One reload, installed and announced. What SIGHUP, the re-signing timer and
/// the control socket all do, so that they cannot drift apart (`CLAUDE.md` §7).
///
/// Returns the announced-serial state to carry into the next round.
async fn reload_once(
    ctx: &ReloadContext,
    announced: Vec<(Name, Serial)>,
    busy: &Busy,
    trigger: ReloadTrigger,
) -> Vec<(Name, Serial)> {
    let ReloadContext {
        reloading,
        source,
        served,
        notify,
        tls,
    } = ctx;
    let why = trigger.why();
    // Before the zones, and independent of whether they load. This is the one
    // function SIGHUP, `rdnsctl reload` and the re-signing timer all pass
    // through, which is why the certificate renewal story is a reload and not a
    // restart (`TODO.md` #42a): `certbot --deploy-hook 'rdnsctl reload'`.
    //
    // A failure here is a warning and nothing more. `CertificateStore::reload`
    // keeps the certificate it is already serving, so half a renewal costs a
    // log line rather than the listener — and the zones, which have nothing to
    // do with it, still reload.
    if let Some(store) = tls {
        match store.reload() {
            Ok(()) => tracing::info!("TLS certificate re-read ({why})"),
            Err(e) => tracing::warn!("could not re-read the TLS certificate ({why}): {e:#}"),
        }
    }
    // Under the read lock and nothing else: a `ZoneMap` is `Arc`s, so this is a
    // hash map's worth of refcount bumps and no query waits on a signing run.
    let previous = if reloading.signing.is_some() && !trigger.refreshes_signatures() {
        Some(served.zone_map.read().await.snapshot_all())
    } else {
        None
    };
    let (announced, outcome) = match reloading.load(source, previous).await {
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
                announce_zones(&served.zone_map, &announced, notify, busy).await,
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
    ctx: ReloadContext,
    announced: Vec<(Name, Serial)>,
    lifecycle: Lifecycle,
) -> mpsc::Sender<ReloadTrigger> {
    let Lifecycle { stop, busy } = lifecycle;
    // `None` when nothing is signed: a server with no keys has nothing to
    // re-sign, and a timer that fired anyway would reload the zones on a
    // schedule nobody asked for.
    if let Some(signing) = ctx.reloading.signing.as_ref() {
        let every = signing.resign_interval();
        let ordinary = rdns::zone_signer::resign_after(signing.shortest_validity()).max(60);
        tracing::info!(
            "re-signing every {}h, {}",
            every.as_secs() / 3600,
            if every.as_secs() < ordinary {
                // The number and the reason for it, because the two differ and
                // an operator reading "a third of the validity" against a
                // four-hour interval would go looking for the wrong bug.
                "the next key rollover step (RFC 6781)".to_string()
            } else {
                format!(
                    "a third of the {}-day signature validity",
                    signing.validity_days()
                )
            },
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
        let mut signals = reload_signal();
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
                reloaded = next_reload(&mut signals) => {
                    if !reloaded {
                        break;
                    }
                    ReloadTrigger::Signal
                }
                // `None` is unreachable while `_keepalive` is alive, and it is
                // alive for exactly as long as this loop.
                Some(trigger) = receiver.recv() => trigger,
                // Asked each time round rather than once at startup: the
                // interval follows the nearest key rollover step when one is
                // closer than the ordinary tick, and that moment moves as the
                // steps are taken (`TODO.md` #44f).
                _ = sleep_for(ctx.reloading.signing.as_ref().map(|s| s.resign_interval()))
                    => ReloadTrigger::Timer,
                _ = stop.wait() => break,
            };
            announced = reload_once(&ctx, announced, &_busy, trigger).await;
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

/// `addr[:port][#keyname]` for a secondary, resolved against the keyring.
///
/// The spelling is `rdns::endpoint`'s, shared with `--secondary`, and the key
/// lookup is `NotifyTarget::resolve` — so a `#key` naming nothing is a startup
/// error here for the same reason and in the same words as there.
fn parse_notify_peers(specs: &[String], keys: &TsigKeyring) -> Result<Vec<NotifyPeer>> {
    let mut peers = Vec::new();
    for spec in specs {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        peers.push(
            notify::NotifyTarget::parse(spec)
                .map_err(|e| anyhow!("--also-notify {e}"))?
                .resolve(keys)?,
        );
    }
    Ok(peers)
}

/// The global list plus whatever `[zones."x"].also-notify` adds per zone.
///
/// The per-zone half is #46c: it was parsed into `PerZone::notify` and read by
/// nothing, so a config that named extra secondaries for one zone was accepted
/// and silently ignored, with `docs/spec/03-authoritative-server.md` and
/// `06-operations.md` both documenting it as working.
fn build_notify_policy(
    cli: &Cli,
    per_zone: &BTreeMap<String, Vec<String>>,
    keys: &TsigKeyring,
) -> Result<NotifyPolicy> {
    let mut policy = NotifyPolicy::new(parse_notify_peers(&cli.also_notify, keys)?);
    for (origin, specs) in per_zone {
        let zone = Name::from_presentation(&absolute_name(origin))
            .map_err(|e| anyhow!("zone {origin:?}: {e}"))?;
        policy.add_zone(zone.as_ref(), parse_notify_peers(specs, keys)?);
    }
    Ok(policy)
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
    notify: &NotifyPolicy,
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

    if notify.is_empty() || pending.is_empty() {
        return current;
    }
    for (zone, serial, soa) in pending {
        // Per zone, not once for the whole run: `[zones."x"].also-notify` adds
        // to the global list for that zone alone (#46c).
        for peer in notify.targets_for(zone.as_ref()) {
            let peer = peer.clone();
            let zone = zone.clone();
            let soa = soa.clone();
            // Fire-and-forget, but not unaccounted-for: a NOTIFY dropped at
            // shutdown is a secondary that waits out a whole REFRESH before it
            // learns of a change we already knew about, so the drain covers it.
            let busy = busy.clone();
            tokio::spawn(async move {
                let _busy = busy;
                send_notify(zone.as_ref(), serial, soa, peer).await;
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
    notify: &NotifyPolicy,
    busy: &Busy,
) {
    for peer in notify.targets_for(zone) {
        let (zone, soa, peer) = (zone.to_owned(), soa.clone(), peer.clone());
        // Accounted for by the drain, like the primary's announcements: a NOTIFY
        // dropped at shutdown costs the level below us a whole REFRESH before it
        // learns of a change that has already reached us.
        let busy = busy.clone();
        tokio::spawn(async move {
            let _busy = busy;
            send_notify(zone.as_ref(), serial, soa, peer).await;
        });
    }
}

/// Send one NOTIFY, retrying until it is answered (RFC 1996 §3.6).
///
/// Signed when the target carries a key (RFC 8945), because a secondary's notify
/// ACL can demand one and two of the three this tree is tested against do when
/// asked — `TODO.md` #46a. The reply is then verified: an unsigned or wrongly
/// signed answer to a signed request is not an answer.
///
/// Every rcode ends the retries, because the secondary has the message and
/// repeating it would not change its mind — but only NOERROR means it will
/// refresh, and the difference is logged rather than flattened into
/// "acknowledged" (#46b).
///
/// Giving up after [`notify::NOTIFY_ATTEMPTS`] is safe because the secondary's
/// refresh timer is the backstop this is an optimisation over.
async fn send_notify(
    zone: NameRef<'_>,
    serial: Serial,
    soa: Option<rdns::ResourceRecord>,
    peer: NotifyPeer,
) {
    let target = peer.addr;
    let Ok(socket) = UdpSocket::bind(bind_addr_for(target)).await else {
        tracing::warn!("NOTIFY {zone} to {peer}: could not open a socket");
        return;
    };

    let mut wait = Duration::from_secs(notify::NOTIFY_RETRY_SECS);
    let mut last_tsig_error: Option<&'static str> = None;

    for attempt in 1..=notify::NOTIFY_ATTEMPTS {
        let id = rdns::rand_id();
        let msg = notify::notify_request(zone, soa.clone(), id);
        // `to_bytes_within` sizes the buffer to what the message needs and
        // only truncates past the ceiling, so the wire maximum here is not a
        // 64 KiB allocation. It replaces a fixed 512-byte buffer that
        // `to_bytes` would have refused to write into for a zone whose SOA
        // carries long enough names -- losing the notification, with
        // "could not serialize" as the only sign.
        let Ok(mut packet) = msg.to_bytes_within(u16::MAX as usize) else {
            tracing::warn!("NOTIFY {zone}: could not serialize");
            return;
        };
        // The MAC of our request opens the digest the reply is verified against
        // (RFC 8945 §4.3.3), so it has to be kept — the same sequence
        // `rdns::xfr` uses on the client side of a transfer.
        let mut request_mac = Vec::new();
        if let Some(key) = &peer.key {
            match tsig::sign_request(packet, key, tsig::now()) {
                Ok(signed) => {
                    request_mac = tsig::request_mac(&signed).unwrap_or_default();
                    packet = signed;
                }
                Err(e) => {
                    tracing::warn!("NOTIFY {zone} to {peer}: could not sign: {e}");
                    return;
                }
            }
        }
        if socket.send_to(&packet, target).await.is_err() {
            tracing::warn!("NOTIFY {zone} to {peer}: send failed");
            return;
        }

        // A NOTIFY reply echoes the question and carries no data; 4 KiB is well
        // past anything one plus a TSIG can weigh.
        let mut reply = vec![0u8; 4096];
        // Something answered, but not this? Treat it as no answer rather than as
        // an acknowledgement: an off-path reply should not be able to silence a
        // notification. A TSIG that does not verify is the same case — which is
        // why this keeps retrying rather than returning, and remembers the
        // reason for the line at the end.
        if let Ok(Ok((n, _))) = tokio::time::timeout(wait, socket.recv_from(&mut reply)).await {
            let packet = &reply[..n];
            let verified = match &peer.key {
                Some(key) => {
                    match tsig::check_response(packet, key, &request_mac, true, tsig::now()) {
                        Ok(_) => true,
                        Err(e) => {
                            last_tsig_error = Some(e.reason());
                            false
                        }
                    }
                }
                None => true,
            };
            if verified {
                if let Ok(parsed) = DnsMessage::try_from_bytes(packet) {
                    match notify::outcome(&parsed, id) {
                        Some(NotifyOutcome::Accepted) => {
                            tracing::info!("NOTIFY {zone} serial {serial} to {peer}: accepted");
                            return;
                        }
                        // It arrived and was refused, so stop — but say so.
                        // Nothing is going to refresh, and the zone is stale on
                        // that secondary until its REFRESH timer fires.
                        Some(NotifyOutcome::Rejected(rcode)) => {
                            tracing::warn!(
                                "NOTIFY {zone} serial {serial} to {peer}: refused ({rcode:?}) — \
                                 that secondary will not refresh until its REFRESH timer fires{}",
                                if peer.key.is_none() {
                                    ". This NOTIFY was unsigned; if that secondary's \
                                     notify ACL names a key, give it here as \
                                     --also-notify ADDR#KEYNAME"
                                } else {
                                    ""
                                }
                            );
                            return;
                        }
                        None => {}
                    }
                }
            }
        }
        if attempt < notify::NOTIFY_ATTEMPTS {
            wait *= 2;
        }
    }
    tracing::warn!(
        "NOTIFY {zone} serial {serial} to {peer}: no answer after {} attempts{}",
        notify::NOTIFY_ATTEMPTS,
        match last_tsig_error {
            Some(reason) => format!(" (the last reply did not verify: {reason})"),
            None => String::new(),
        }
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
    // Loaded before anything binds, like every other thing that can stop the
    // start. A certificate that will not read is a DoT listener that answers
    // nothing, which is the failure `--metrics-listen` is already refused for.
    let encrypted =
        cli.tls_listen.is_some() || cli.quic_listen.is_some() || cli.https_listen.is_some();
    let tls_store = match (encrypted, &cli.tls_cert, &cli.tls_key) {
        (true, Some(cert), Some(key)) => Some(CertificateStore::load(cert, key)?),
        // In code rather than in clap's `requires`, because the config file has
        // no such mechanism and would otherwise bind 853 with nothing to present
        // on it — and because either listener needs the pair, which `requires`
        // cannot express as an "or".
        (true, _, _) => {
            return Err(anyhow!(
                "tls-listen, quic-listen and https-listen need both tls-cert and tls-key"
            ))
        }
        _ => None,
    };
    // A transfer arrives on a connection, and if none of them can be encrypted
    // then this refuses every transfer there will ever be. That is a
    // configuration that cannot do what it says, so it is a startup error and
    // not a server that answers REFUSED to its own secondaries all night
    // (`CLAUDE.md` §15).
    if cli.transfer_tls_only && !encrypted {
        return Err(anyhow!(
            "--transfer-tls-only needs a listener a transfer can arrive on: \
             --tls-listen, --quic-listen or --https-listen. Without one, every \
             transfer is refused"
        ));
    }

    // After the keyring, because a `#key` names one of its entries.
    let notify = Arc::new(build_notify_policy(&cli, &per_zone.notify, &tsig_keys)?);
    // Said out loud for the reason the transfer policy is: whether a NOTIFY is
    // signed decides whether a secondary with a keyed notify ACL will act on it,
    // and the failure is otherwise a zone that is quietly hours stale (#46).
    if !notify.is_empty() {
        tracing::info!("notifying {}", notify.describe());
    }
    let query_limit = RateLimitConfig::per_second(cli.query_rate, cli.query_burst).exempting(
        TransferAcl::parse_named(&cli.query_rate_exempt, "--query-rate-exempt")?,
    );

    let mut secondary_specs = parse_secondary_specs(&cli.secondary)?;
    // A catalog is replicated by the same machinery as any other zone
    // (RFC 9432 §5.1), so it joins the list rather than growing a second one:
    // the refresh timers, the NOTIFY handling, the EXPIRE withdrawal and the
    // file on disk are then the ones that are already tested.
    let catalog_specs = parse_catalog_specs(&cli.catalog)?;
    // Here rather than where the refresh tasks start, which is after
    // `--check-config` has already answered: a dry run has to run everything
    // that does not bind a socket (`CLAUDE.md` §15), and a spec naming a key no
    // `--tsig-key` defines is a startup failure either way.
    for spec in secondary_specs.iter() {
        resolve_key(spec, &tsig_keys, "--secondary")?;
    }
    for spec in catalog_specs.iter() {
        resolve_key(spec, &tsig_keys, "--catalog")?;
    }
    secondary_specs.extend(catalog_specs.iter().cloned());

    // The anchors every XoT master is checked against, and the check that a
    // spec asking for TLS has somewhere to check against. Here, with the key
    // resolution above and for the same reason: `--check-config` has to reach
    // it, and "no anchors" is a startup failure rather than a transfer that
    // goes out in clear months later (`CLAUDE.md` §4).
    // Both or neither: clap's `requires` says so for the flags, and the config
    // file has no equivalent, so `Config::check` says it there.
    let transfer_identity = match (&cli.transfer_tls_cert, &cli.transfer_tls_key) {
        (Some(cert), Some(key)) => Some(TlsIdentity::from_files(
            cert,
            key,
            "the transfer client certificate",
        )?),
        (None, None) => None,
        _ => {
            return Err(anyhow!(
                "--transfer-tls-cert and --transfer-tls-key go together: a chain with \
                 no key cannot be presented, and a key with no chain is not an \
                 identity (RFC 9103 §7.5)"
            ))
        }
    };
    if transfer_identity.is_some() && cli.transfer_tls_ca.is_none() {
        return Err(anyhow!(
            "--transfer-tls-cert is the certificate this server presents when it \
             *fetches* a zone over TLS, and --transfer-tls-ca names no anchors, \
             so nothing here fetches one"
        ));
    }
    let xot = match &cli.transfer_tls_ca {
        Some(path) => Some(XotTrust::from_ca_file(path, transfer_identity)?),
        None => None,
    };
    // What the outgoing half of RFC 9103 is configured to do, where the two
    // facts an operator cannot otherwise see are the anchor count and whether a
    // client certificate is loaded. A certificate is offered only when a master
    // sends a CertificateRequest, so "mTLS is in force" is not a claim this end
    // can make; what it can say is what it holds (`CLAUDE.md` §4). This is also
    // `XotTrust::anchor_count`'s first caller — it was written for a banner
    // that was never added (`CLAUDE.md` §18).
    if let Some(xot) = &xot {
        tracing::info!(
            "zone transfers fetched over TLS: {} trust anchor(s), client certificate {}",
            xot.anchor_count(),
            if xot.presents_a_certificate() {
                "loaded, offered if a master asks (RFC 9103 §7.5 mTLS)"
            } else {
                "none (--transfer-tls-cert); masters authorize by address and TSIG"
            }
        );
    }
    if xot.is_none() {
        if let Some(spec) = secondary_specs.iter().find(|spec| spec.tls.is_some()) {
            return Err(anyhow!(
                "{} is replicated from {} over TLS, and --transfer-tls-ca names \
                 no trust anchors to check its certificate against \
                 (RFC 9103 §7.5)",
                spec.zone,
                spec.master
            ));
        }
    }

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
    let run = match &signing {
        // Startup: nothing is being served, so there is nothing to carry
        // forward from (`ZoneSigning::apply`).
        Some(signing) => signing.apply(&mut zones, None)?,
        None => SigningRun::default(),
    };
    let mut validator = DnssecValidator::new(cli.require_signed || signing.is_some());
    validator.set_require_signed(cli.require_signed);
    let validator = Arc::new(validator);
    // Empty, so this pass checks everything; what it proves is what the reload
    // path may then skip.
    let proved = ProvenSigning::default();
    verify_zones(&zones, &validator, &run, &proved)?;

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
            "configuration is valid: {} zone(s){}, {} TSIG key(s), signing {}, encrypted transports {}",
            zones.len(),
            // Said out loud because the member zones are not among the count
            // above: they arrive with the catalog, and what a dry run can check
            // is that the catalog itself is configured and its key resolves.
            match catalog_specs.len() {
                0 => String::new(),
                n => format!(", {n} catalog(s) to consume"),
            },
            cli.tsig_key.len(),
            match &signing {
                Some(s) => format!("{} zone(s)", s.signed_zone_count(&zones)),
                None => "disabled".to_string(),
            },
            // Named because the certificate was read, permission-checked and
            // matched against its key above — a dry run has to run everything
            // that does not bind a socket (`CLAUDE.md` §15), and saying nothing
            // about it would leave an operator unable to tell whether it did.
            match (&cli.tls_listen, &cli.quic_listen, &tls_store) {
                (None, None, _) | (_, _, None) => "disabled".to_string(),
                (dot, doq, Some(_)) => format!(
                    "on {}, certificate loads",
                    [dot.as_deref().map(|a| format!("{a} DoT")), doq.as_deref().map(|a| format!("{a} DoQ"))]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>()
                        .join(" and ")
                ),
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
    let mut reload_zone_dir: Option<PathBuf> = None;
    // Filled in below for a secondary. A primary's is empty and it is ready as
    // soon as it is alive: every zone it serves was loaded, signed and verified
    // above, and a failure in any of that stopped the start rather than reaching
    // here.
    let mut readiness = Readiness::ready();
    let secondaries = Arc::new(Secondaries::default());
    // Hoisted out of the block below so the control socket can report what each
    // catalog holds (`TODO.md` #49). A server with no `--secondary` and no
    // `--catalog` never enters that block, and this stays the empty consumer —
    // which `rdnsctl catalog` answers as "this server consumes no catalogs".
    let mut control_catalogs: Option<Arc<Catalogs>> = None;
    if !secondary_specs.is_empty() {
        let ZoneSource::Directory(dir) = &source else {
            // `validate_zone_source` has already refused this combination; this
            // is the compiler being told so.
            return Err(anyhow!("--secondary and --catalog require --zone-dir"));
        };
        let zone_dir = PathBuf::from(dir);
        withdraw_unvouched_zones(&secondary_specs, &served, &zone_dir).await;
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

        // What a catalog may not take over (RFC 9432 §5.2): the zones the
        // configuration names, and the zones already on disk that no catalog
        // says are its.
        let held: Vec<Name> = {
            let zones = zone_map.read().await;
            zones.keys().map(|key| key.as_name().to_owned()).collect()
        };
        let catalogs = Catalogs::new(
            catalog_specs,
            &tsig_keys,
            secondary_specs
                .iter()
                .map(|spec| rdns::name_keys::NameKeyBuf::new(spec.zone.as_ref()))
                .collect(),
            held,
            &zone_dir,
            secondaries.clone(),
            &per_zone.groups,
        )?;
        control_catalogs = Some(catalogs.clone());

        let replication = ReplicationContext {
            served: served.clone(),
            state: Arc::new(Mutex::new(StateFile::load(&state_file_path(&zone_dir)))),
            zone_dir,
            notify: notify.clone(),
            readiness: readiness.clone(),
            catalogs: catalogs.clone(),
            xot: xot.clone(),
        };
        // Before the tasks start and before anything is served: the members a
        // previous run provisioned are on disk too, and their refresh tasks do
        // not exist until their catalog is reconciled below.
        catalogs.vouch_for_members(&replication).await;

        spawn_secondaries(
            secondary_specs,
            &tsig_keys,
            &replication,
            &shutdown.lifecycle(),
            &secondaries,
        )?;

        // The members of every catalog we already hold a copy of. A reload does
        // not repeat this: a catalog reaches a consumer by transfer, and the
        // refresh task reconciles what it installs, so the only thing a SIGHUP
        // re-reads is the file that transfer wrote.
        for zone in catalogs.zones() {
            catalogs
                .reconcile(zone.as_ref(), &replication, &shutdown.lifecycle())
                .await;
        }
    }

    // A zone that has just been loaded is news to every secondary, which is why
    // this runs at startup and not only on reload.
    let announced = announce_zones(&zone_map, &[], &notify, &shutdown.busy()).await;

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
    let udp = UdpSizes::new(cli.udp_payload_size, cli.max_udp_response);

    let reloads = spawn_zone_maintenance(
        ReloadContext {
            reloading: Reloading {
                replicating,
                allow_partial: cli.allow_partial_load,
                secondaries: secondaries.clone(),
                zone_dir: reload_zone_dir,
                signing,
                validator,
                proved,
            },
            source,
            served: served.clone(),
            notify,
            tls: tls_store.clone(),
        },
        announced,
        shutdown.lifecycle(),
    );

    serve(
        &addr,
        zone_map,
        ServePolicy {
            transfer_acl,
            transfer_tls_only: cli.transfer_tls_only,
            tsig_keys,
            response_rate: cli.response_rate,
            query_limit,
            admission: admission_limits(udp, cli.max_udp_request, cli.max_tcp_request),
            udp,
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
            tls: tls_store.clone().map(|store| TlsPolicy {
                dot: cli.tls_listen,
                doq: cli.quic_listen,
                doh: cli.https_listen.map(|addr| (addr, cli.https_path.clone())),
                store,
            }),
            readiness,
            updates,
            journal,
            dnstap: match &cli.dnstap {
                Some(spec) => Some((spec.parse()?, cli.dnstap_max_bytes)),
                None => None,
            },
            control: ControlPolicy {
                socket: cli.control_socket,
                reloads,
                secondaries: secondaries.clone(),
                catalogs: match control_catalogs {
                    Some(catalogs) => catalogs,
                    // No `--secondary` and no `--catalog`: a consumer of
                    // nothing, rather than an `Option` every caller unwraps.
                    None => Catalogs::new(
                        Vec::new(),
                        &TsigKeyring::default(),
                        std::collections::HashSet::new(),
                        Vec::new(),
                        Path::new("."),
                        secondaries.clone(),
                        &std::collections::BTreeMap::new(),
                    )?,
                },
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
    // The second half of the same operator task, which nothing else names: a
    // parent that polls CDS does not need the paste, and the only way to ask it
    // to is a field in the key file (RFC 7344, `TODO.md` #55). Said here
    // because this is the one command an operator runs before a rollover, and a
    // feature nobody can find is a feature nobody uses (`CLAUDE.md` §14).
    println!(
        "\nFor a parent that polls CDS/CDNSKEY instead (RFC 7344), add\n\
         \n    SyncPublish: <unix seconds>\n\
         \nto {} and reload. The records appear at the apex, signed by the \
         KSK, and go away again at an optional SyncDelete.",
        ksk.file_name()
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
    use rdns::secondary::{zone_file_path, MasterSpec, RefreshTimers, TransferState};
    use rdns::tsig::{TsigAlgorithm, TsigKey};
    use rdns::validation::{Arrival, TlsVersion};
    use rdns::zone_signer::{sign_zone, DenialChain, SigningPolicy};
    use rdns::Class;
    use rdns::QueryClass;
    use rdns::{OpCode, Qtype, ResponseCode, Ttl};
    use rdns_transport::tcp::Reply;
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};
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
                &Wire::Framed(&tx, Arrival::Tcp),
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
            udp: UdpSizes::default(),
            clock: Clock::system(),
        }
    }

    fn server_with(zone: Zone) -> Arc<Server> {
        server_with_keys(zone, Vec::new())
    }

    fn server_with_keys(zone: Zone, keys: Vec<TsigKey>) -> Arc<Server> {
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
        Arc::new(Server {
            zone_map: Arc::new(RwLock::new(Zones::new(zones))),
            ctx: test_context(),
            journal: None,
            transfer_acl: Arc::new(TransferAcl::parse(&["127.0.0.1".to_string()]).expect("acl")),
            transfer_tls_only: false,
            tsig_keys: Arc::new(TsigKeyring::new(keys)),
            secondaries: Arc::new(Secondaries::default()),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
            updates: Arc::new(UpdateHandling::disabled()),
            dnstap: None,
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

        /// A round-robin pool of `count` addresses, which is how both size
        /// tests below put an answer at a chosen weight.
        fn pool_zone(count: u32) -> Zone {
            let mut text = String::from(
                "$ORIGIN example.com.\n\
                 $TTL 3600\n\
                 @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                 @   IN NS  ns1.example.com.\n\
                 ns1 IN A   192.0.2.1\n",
            );
            for i in 0..count {
                text.push_str(&format!("pool IN A 198.51.100.{}\n", i % 254 + 1));
            }
            rdns::zone::parse_zone_file(&text, "example.com.").expect("the zone parses")
        }

        /// The client's EDNS advertisement is a ceiling this server may lower,
        /// not one it has to honour (`TODO.md` #41b).
        ///
        /// Before: `max_len` was `request.udp_payload_size()` alone, so a client
        /// advertising 65,535 was given 65,535 and a large answer left as ~45 IP
        /// fragments — which middleboxes drop and which is what every other
        /// implementation's `max-udp-size` exists to prevent. Watched failing
        /// against that: the reply comes back whole, over 1232 octets, with TC
        /// clear.
        ///
        /// The cap is the datagram's alone. The same question over TCP is
        /// answered in full, which is where a truncated client is sent.
        #[tokio::test]
        async fn a_udp_reply_is_capped_by_this_server_and_not_only_by_the_client() {
            let server = server_with(pool_zone(128));
            let cap = server.ctx.udp.max_response() as usize;
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
            let peer = client.local_addr().expect("addr");

            let greedy = rdns::DnsMessageBuilder::new()
                .with_id(1)
                .with_query(nm("pool.example.com."), Qtype::of(record_types::A))
                .with_recursion(false)
                .with_edns(u16::MAX, false)
                .build()
                .to_bytes_within(4096)
                .expect("serialize");

            let mut scratch = Scratch::default();
            server
                .answer(
                    &greedy,
                    peer,
                    tsig::now(),
                    &Wire::Datagram(&socket, peer),
                    &mut scratch,
                )
                .await;
            assert!(
                scratch.out.len() <= cap,
                "a {}-octet datagram went out under a {cap}-octet cap",
                scratch.out.len()
            );
            let reply = DnsMessage::try_from_bytes(&scratch.out).expect("it parses");
            assert!(reply.truncation, "and says so, so the client retries");
            assert!(
                reply.answers.is_empty(),
                "a truncated reply carries nothing"
            );

            // The same question on the transport a TC=1 sends the client to.
            let (tx, mut rx) = tokio::sync::mpsc::channel(4);
            server
                .answer(
                    &greedy,
                    peer,
                    tsig::now(),
                    &Wire::Framed(&tx, Arrival::Tcp),
                    &mut Scratch::default(),
                )
                .await;
            let Some(rdns_transport::tcp::Reply::Frame(framed)) = rx.recv().await else {
                panic!("one framed reply");
            };
            let over_tcp = DnsMessage::try_from_bytes(&framed[2..]).expect("it parses");
            assert!(!over_tcp.truncation, "TCP is not capped by either number");
            assert_eq!(over_tcp.answers.len(), 128);
        }

        /// The TSIG comes out of the reply's ceiling, not on top of it
        /// (`TODO.md` #41d).
        ///
        /// `TsigSession::sign` appends its record to bytes already serialized
        /// to `max_len`, so before this the signed datagram went out at the cap
        /// *plus* 85 octets — a cap exceeded by a fixed amount is not a cap.
        /// RFC 8945 §5.3 says what to do instead: "If addition of the TSIG
        /// record will cause the message to be truncated, the server MUST alter
        /// the response so that a TSIG can be included. This response contains
        /// only the question and a TSIG record, has the TC bit set, and has an
        /// RCODE of 0 (NOERROR)."
        ///
        /// The zone is sized so the answer lands in the window where the
        /// question is live: it fits the cap and does not fit the cap with a
        /// signature. The first assertion holds that window, so a zone that
        /// drifts out of it fails loudly rather than passing for the wrong
        /// reason (`CLAUDE.md` §1).
        ///
        /// Watched failing against the unreserved ceiling: 1,250 octets out of
        /// a 1,232-octet cap, TC clear.
        #[tokio::test]
        async fn a_signed_reply_reserves_its_signature_out_of_the_ceiling() {
            let key = TsigKey::new("transfer.key.", TsigAlgorithm::HmacSha256, vec![0x0b; 32]);
            let server = server_with_keys(pool_zone(70), vec![key.clone()]);
            let cap = server.ctx.udp.max_response() as usize;
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
            let peer = client.local_addr().expect("addr");

            let question = rdns::DnsMessageBuilder::new()
                .with_id(1)
                .with_query(nm("pool.example.com."), Qtype::of(record_types::A))
                .with_recursion(false)
                .with_edns(u16::MAX, false)
                .build()
                .to_bytes_within(4096)
                .expect("serialize");

            // Read off the wire, not out of the scratch buffer: signing builds
            // a message of its own, so the bytes that were sent are the only
            // ones this is about.
            let answer = |packet: &[u8]| {
                let server = Arc::clone(&server);
                let packet = packet.to_vec();
                let socket = &socket;
                let client = &client;
                async move {
                    let mut scratch = Scratch::default();
                    server
                        .answer(
                            &packet,
                            peer,
                            tsig::now(),
                            &Wire::Datagram(socket, peer),
                            &mut scratch,
                        )
                        .await;
                    let mut buf = vec![0u8; UDP_RECEIVE_BUFFER];
                    let n = client.recv(&mut buf).await.expect("one datagram");
                    buf.truncate(n);
                    buf
                }
            };
            client
                .connect(socket.local_addr().expect("addr"))
                .await
                .expect("connect");

            // The window: unsigned it fits, and it would not fit signed.
            let unsigned = answer(&question).await;
            let overhead = {
                let probe = rdns::tsig::sign_request(question.clone(), &key, tsig::now())
                    .expect("sign the probe");
                let rdns::tsig::TsigCheck::Verified(session) =
                    rdns::tsig::check_request(&probe, &server.tsig_keys, tsig::now())
                else {
                    panic!("the probe verifies");
                };
                session.reply_overhead()
            };
            assert!(
                unsigned.len() <= cap && unsigned.len() + overhead > cap,
                "the zone must answer in the window this is about: {} octets, \
                 cap {cap}, signature {overhead}",
                unsigned.len()
            );
            assert!(!rdns::response::is_truncated(&unsigned), "unsigned it fits");

            let signed = rdns::tsig::sign_request(question, &key, tsig::now()).expect("sign");
            let reply = answer(&signed).await;
            assert!(
                reply.len() <= cap,
                "a {}-octet signed datagram went out under a {cap}-octet cap",
                reply.len()
            );
            let parsed = DnsMessage::try_from_bytes(&reply).expect("it parses");
            assert!(parsed.truncation, "TC=1, so the client comes back over TCP");
            assert!(parsed.answers.is_empty(), "the question and a TSIG");
            assert_eq!(parsed.rcode, ResponseCode::Ok, "RFC 8945 §5.3's RCODE");
            assert!(
                parsed
                    .additionals
                    .iter()
                    .any(|rr| rr.rdata.rtype() == rdns::Rtype::new(250)),
                "and the TSIG it was altered to make room for, in {} octets",
                reply.len()
            );
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

            let err = rdns::xfr::fetch_zone(
                &rdns::xfr::Master::plain(master),
                nm("example.com.").as_ref(),
                Some(&scoped),
            )
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

            let zone = rdns::xfr::fetch_zone(
                &rdns::xfr::Master::plain(master),
                nm("example.com.").as_ref(),
                Some(&scoped),
            )
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

            let zone = rdns::xfr::fetch_zone(
                &rdns::xfr::Master::plain(master),
                nm("example.com.").as_ref(),
                Some(&scoped),
            )
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

            let zone = rdns::xfr::fetch_zone(
                &rdns::xfr::Master::plain(master),
                nm("example.com.").as_ref(),
                Some(&unscoped),
            )
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
        spawn_primary_full(zone, acl, log, keys, false, Arrival::Tcp).await
    }

    /// A primary with the two XoT knobs exposed: whether it requires an
    /// encrypted transfer, and what the connection claims to be.
    ///
    /// The privacy is asserted rather than negotiated, which is the point of
    /// the split: `rdns_transport::tls` reads it off a real handshake and has
    /// its own test for that, and this one is about what `answer_transfer`
    /// does with the answer.
    async fn spawn_primary_full(
        zone: Zone,
        acl: &[String],
        log: DeltaLog,
        keys: TsigKeyring,
        transfer_tls_only: bool,
        arrival: Arrival,
    ) -> SocketAddr {
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));

        let server = Arc::new(Server {
            zone_map: Arc::new(RwLock::new(Zones::new(zones))),
            ctx: test_context(),
            transfer_acl: Arc::new(TransferAcl::parse(acl).expect("acl")),
            transfer_tls_only,
            tsig_keys: Arc::new(keys),
            secondaries: Arc::new(Secondaries::default()),
            deltas: Arc::new(RwLock::new(log)),
            updates: Arc::new(UpdateHandling::disabled()),
            journal: None,
            dnstap: None,
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
                    arrival,
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
            transfer_tls_only: false,
            tsig_keys: Arc::new(TsigKeyring::new(vec![key])),
            secondaries: Arc::new(Secondaries::default()),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
            updates: Arc::new(UpdateHandling {
                source: Some(source),
                signing: None,
                applying: tokio::sync::Mutex::new(()),
            }),
            journal,
            dnstap: None,
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
                    Arrival::Tcp,
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
    /// A signed UPDATE over 512 octets is admitted on UDP, because that is what
    /// this server advertises it can reassemble.
    ///
    /// `TODO.md` #40f, and the defect rather than the knob: every reply's OPT
    /// says 4,096 (RFC 6891 §6.2.4) while admission refused over 512 and did it
    /// in silence — no FORMERR, nothing on the wire. A 2,048-bit DKIM key
    /// rotation is the ordinary request that falls in the gap, and the TSIG this
    /// server *requires* is what pushes it over: 470 octets unsigned, 566 signed
    /// (`rdns/examples/request_size_probe.rs`).
    ///
    /// Watched failing with `max_udp_size` back at 512: the signed message was
    /// refused and the unsigned one, being smaller, was not.
    #[test]
    fn a_signed_dkim_sized_update_is_admitted_on_udp() {
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let dkim = format!("v=DKIM1; k=rsa; p={}", "A".repeat(392));
        let txt = ResourceRecord {
            name: nm("s2026._domainkey.example.com."),
            class: rdns::Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::TXT(
                dkim.as_bytes().chunks(255).map(<[u8]>::to_vec).collect(),
            ))
            .expect("encodes"),
        };
        let bytes = update_message("example.com.", vec![txt])
            .to_bytes_within(4096)
            .expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, &key, tsig::now()).expect("sign");

        let udp = UdpSizes::default();
        assert!(
            signed.len() > 512 && signed.len() < udp.advertised() as usize,
            "the request this is about weighs {} octets: over the old cap, under \
             what is advertised",
            signed.len()
        );

        // The cap set to the floor, which is the smallest this server can be
        // configured to accept.
        let check = AdmissionCheck::new(admission_limits(udp, 512, 16 * 1024));
        assert!(
            check
                .validate_packet(&signed, Transport::Udp)
                .error()
                .is_none(),
            "a legitimate signed UPDATE must not be dropped in silence"
        );
    }

    /// The UDP cap cannot be set below what this server advertises.
    ///
    /// Accepting less than the OPT promises is the broken promise above; accepting
    /// more misleads nobody, so only the floor is enforced (`CLAUDE.md` §14 — a
    /// mistyped knob should be wrong, not fatal).
    #[test]
    fn the_udp_request_cap_cannot_fall_below_what_is_advertised() {
        let udp = UdpSizes::default();
        assert_eq!(
            admission_limits(udp, 512, 16 * 1024).caps().0,
            udp.advertised() as usize,
            "512 is below the advertisement and is floored to it"
        );
        assert_eq!(
            admission_limits(udp, 8192, 16 * 1024).caps().0,
            8192,
            "above it is the operator's business"
        );
    }

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

    /// The refusal says why, to a client that sent an OPT to hear it in
    /// (RFC 8914 §2).
    ///
    /// PROHIBITED for all four ways permission can be missing, and no finer:
    /// telling a stranger *which* of them it was is telling it about the
    /// keyring. The text is what an operator reads, and the RCODE is still
    /// REFUSED whatever §3 says about EDE â "applications MUST continue to
    /// follow requirements ... on how to process RCODEs".
    #[tokio::test]
    async fn a_refused_update_says_why_when_the_client_used_edns() {
        let dir = ScratchDir::new("update-ede");
        let key = update_key(rdns::tsig::UpdatePolicy::Zones(vec![
            "elsewhere.test.".to_string()
        ]));
        let addr = spawn_updatable(dir.path(), key).await;
        let changes = vec![a_record("new.example.com.", "192.0.2.50")];

        let mut asked = update_message("example.com.", changes.clone());
        asked.set_edns(rdns::Edns::with_payload_size(4096));
        let reply = round_trip(addr, asked.to_bytes_within(4096).expect("serialize")).await;
        assert_eq!(reply.rcode, ResponseCode::Refused);
        let edns = reply.edns.as_ref().expect("the OPT is mirrored");
        let errors = rdns::ExtendedError::all_in(edns).expect("a well-formed option list");
        assert_eq!(
            errors
                .iter()
                .map(|(code, _)| *code)
                .collect::<Vec<rdns::InfoCode>>(),
            vec![rdns::InfoCode::PROHIBITED]
        );

        // The same UPDATE with no OPT: the same refusal, and nowhere to say why.
        let plain = update_message("example.com.", changes);
        let reply = round_trip(addr, plain.to_bytes_within(4096).expect("serialize")).await;
        assert_eq!(reply.rcode, ResponseCode::Refused);
        assert!(reply.edns.is_none(), "an unsolicited OPT is not mirroring");
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

    /// A consumer of no catalogs, for the refresh tests: they are about the
    /// transfer, and `--catalog` adds nothing to it until a catalog arrives.
    fn no_catalogs() -> Arc<crate::catalog::Catalogs> {
        crate::catalog::Catalogs::new(
            Vec::new(),
            &TsigKeyring::default(),
            std::collections::HashSet::new(),
            Vec::new(),
            Path::new("."),
            Arc::new(Secondaries::default()),
            &std::collections::BTreeMap::new(),
        )
        .expect("no specs, nothing to resolve")
    }

    /// The replication context a refresh runs in, over a scratch directory.
    fn replication(dir: &ScratchDir, notify: NotifyPolicy) -> ReplicationContext {
        ReplicationContext {
            served: ZoneContext {
                zone_map: Arc::new(RwLock::new(Zones::default())),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
                metrics: Arc::new(DnsMetrics::new()),
                journal: None,
            },
            state: Arc::new(Mutex::new(StateFile::load(&state_file_path(dir.path())))),
            zone_dir: dir.path().to_path_buf(),
            notify: Arc::new(notify),
            // Nothing here probes `/readyz`; `readiness::tests` is where the
            // latch itself is checked.
            readiness: Readiness::ready(),
            catalogs: no_catalogs(),
            xot: None,
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
            tls: None,
        };
        let r = replication(&dir, NotifyPolicy::default());

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
            tls: None,
        };
        let r = replication(&dir, NotifyPolicy::default());

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
        let r = replication(&dir, NotifyPolicy::default());

        let old = spawn_primary(&zone_text(7)).await;
        refresh_once(
            &MasterSpec {
                zone: nm(&spec_zone.clone()),
                master: old,
                key_name: None,
                tls: None,
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
                tls: None,
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
            tls: None,
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
            notify: Arc::new(NotifyPolicy::default()),
            readiness: Readiness::ready(),
            catalogs: no_catalogs(),
            xot: None,
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
            tls: None,
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
            notify: Arc::new(NotifyPolicy::default()),
            readiness: Readiness::ready(),
            catalogs: no_catalogs(),
            xot: None,
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

        let r = replication(&dir, NotifyPolicy::default());

        // Start from version 7, fetched in full because we hold nothing yet.
        let first = spawn_primary(&old_text).await;
        let spec = |master| MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
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

        let r = replication(
            &dir,
            NotifyPolicy::new(vec![NotifyPeer {
                addr: target,
                key: None,
            }]),
        );
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
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

    /// #46a: a NOTIFY signed, and verified by the *reader* rather than by
    /// looking at it. `check_request` is the same function the answering path
    /// runs on an inbound message, so this is the check a real secondary makes.
    ///
    /// Against the old code this fails at `TsigCheck::Unsigned`: `notify.rs`
    /// mentioned TSIG nowhere and `--also-notify` had no way to name a key.
    #[tokio::test]
    async fn test_a_notify_can_be_signed_and_verifies_as_a_request() {
        let dir = ScratchDir::new("announce-signed");
        let master = spawn_primary(&zone_text(11)).await;
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");

        let key = TsigKey::new("notify.key.", TsigAlgorithm::HmacSha256, vec![0x2b; 32]);
        let r = replication(
            &dir,
            NotifyPolicy::new(vec![NotifyPeer {
                addr: target,
                key: Some(key.clone()),
            }]),
        );
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
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

        let keyring = TsigKeyring::new(vec![key]);
        match tsig::check_request(&buf[..n], &keyring, tsig::now()) {
            rdns::tsig::TsigCheck::Verified(session) => {
                assert_eq!(session.key_name(), "notify.key.");
            }
            rdns::tsig::TsigCheck::Unsigned => panic!("the NOTIFY went out unsigned"),
            rdns::tsig::TsigCheck::Rejected(r) => {
                panic!("the NOTIFY did not verify: {}", r.error.reason())
            }
        }

        let msg = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");
        assert_eq!(msg.opcode, OpCode::Notify, "still a NOTIFY, signed or not");
        assert_eq!(notify::notified_zone(&msg), Some(nm("example.com.")));
    }

    /// A refusal ends the sending: it arrived, and repeating it would not change
    /// the secondary's mind.
    ///
    /// **Not a regression test for #46b**, and saying so is the point (§10).
    /// The old code stopped here too — what it did wrong was call it
    /// `acknowledged` at INFO. That distinction lives in `notify::outcome`'s
    /// return type and is tested beside it; this only holds the retry behaviour
    /// that the rewording must not have changed.
    #[tokio::test]
    async fn test_a_refused_notify_is_not_retried() {
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");

        let sender = tokio::spawn(async move {
            send_notify(
                nm("example.com.").as_ref(),
                Serial::new(7),
                None,
                NotifyPeer {
                    addr: target,
                    key: None,
                },
            )
            .await;
        });

        let mut buf = vec![0u8; 4096];
        let (n, from) =
            tokio::time::timeout(Duration::from_secs(5), downstream.recv_from(&mut buf))
                .await
                .expect("the first NOTIFY")
                .expect("recv");
        let request = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");
        let refusal = notify::notify_response(&request, ResponseCode::Refused, 1232, None);
        let bytes = refusal.to_bytes_within(512).expect("serialize");
        downstream.send_to(&bytes, from).await.expect("reply");

        // Nothing further: the message got there, and a second copy would not
        // make a secondary that refused it change its answer.
        assert!(
            tokio::time::timeout(Duration::from_secs(3), downstream.recv_from(&mut buf))
                .await
                .is_err(),
            "a refusal must end the retries"
        );
        sender.await.expect("the sender finishes");
    }

    /// An unsigned answer to a signed NOTIFY is not an answer: otherwise anyone
    /// who can guess the transaction could silence a notification with a forged
    /// datagram, which is the property the retry loop already had for a reply
    /// carrying the wrong id.
    #[tokio::test]
    async fn test_an_unsigned_reply_to_a_signed_notify_is_not_an_acknowledgement() {
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");
        let key = TsigKey::new("notify.key.", TsigAlgorithm::HmacSha256, vec![0x3c; 32]);

        let sender = tokio::spawn(async move {
            send_notify(
                nm("example.com.").as_ref(),
                Serial::new(7),
                None,
                NotifyPeer {
                    addr: target,
                    key: Some(key),
                },
            )
            .await;
        });

        let mut buf = vec![0u8; 4096];
        let mut answered = 0;
        // Every attempt gets an unsigned "yes", and none of them counts.
        while let Ok(Ok((n, from))) =
            tokio::time::timeout(Duration::from_secs(4), downstream.recv_from(&mut buf)).await
        {
            answered += 1;
            let request = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");
            let reply = notify::notify_response(&request, ResponseCode::Ok, 1232, None);
            let bytes = reply.to_bytes_within(512).expect("serialize");
            downstream.send_to(&bytes, from).await.expect("reply");
        }
        assert_eq!(
            answered,
            notify::NOTIFY_ATTEMPTS,
            "an unsigned NOERROR must not stop the retries"
        );
        sender.await.expect("the sender finishes");
    }

    /// #46c: `[zones."x"].also-notify` adds to the global list for that zone
    /// and leaves every other zone's alone.
    ///
    /// There is no old behaviour for this to fail against, which is the finding:
    /// the per-zone list was parsed into `PerZone::notify` and read by nothing.
    #[test]
    fn test_per_zone_notify_targets_add_to_the_global_list() {
        let peer = |s: &str| NotifyPeer {
            addr: s.parse().expect("an address"),
            key: None,
        };
        let mut policy = NotifyPolicy::new(vec![peer("192.0.2.1:53")]);
        policy.add_zone(
            nm("example.com.").as_ref(),
            vec![peer("192.0.2.2:53"), peer("192.0.2.1:53")],
        );

        let addrs = |zone: &str| {
            policy
                .targets_for(nm(zone).as_ref())
                .iter()
                .map(|p| p.addr.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            addrs("example.com."),
            ["192.0.2.1:53", "192.0.2.2:53"],
            "the global list plus this zone's, and the repeat named once"
        );
        assert_eq!(
            addrs("example.net."),
            ["192.0.2.1:53"],
            "a zone with no list of its own gets the global one"
        );
        assert_eq!(
            addrs("EXAMPLE.COM."),
            ["192.0.2.1:53", "192.0.2.2:53"],
            "matched as a name, so case does not decide who is told (RFC 4343)"
        );
    }

    /// A `#key` naming a key nothing defines stops the server, for the reason
    /// `--secondary` already does: the operator asked for authentication and
    /// would otherwise not be able to see that they did not get it.
    #[test]
    fn test_a_notify_key_that_no_tsig_key_defines_is_a_startup_error() {
        let keys = TsigKeyring::new(vec![TsigKey::new(
            "known.key.",
            TsigAlgorithm::HmacSha256,
            vec![0x4d; 32],
        )]);
        let err = parse_notify_peers(&["192.0.2.1#missing.key.".to_string()], &keys)
            .expect_err("a key nobody defines");
        assert!(
            err.to_string().contains("missing.key."),
            "the message names the key that is missing: {err}"
        );

        // And the one that is defined resolves, whatever its algorithm — the
        // operator wrote the algorithm once, beside the secret.
        let peers = parse_notify_peers(&["192.0.2.1#known.key.".to_string()], &keys)
            .expect("a key that exists");
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].key.as_ref().map(|k| k.name.as_str()),
            Some("known.key.")
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

        let r = replication(
            &dir,
            NotifyPolicy::new(vec![NotifyPeer {
                addr: target,
                key: None,
            }]),
        );
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
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
        let r = replication(&dir, NotifyPolicy::default());
        let spec = |master| MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
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

    /// RFC 9103 §11's server half: with `--transfer-tls-only` a transfer that
    /// arrived in clear is refused, whatever the ACL says about the peer.
    ///
    /// The ACL here *allows* 127.0.0.1, so the only thing that can refuse this
    /// is the transport policy — which is what makes it a test of the policy
    /// and not of the ACL.
    #[tokio::test]
    async fn a_transfer_in_clear_is_refused_when_tls_is_required() {
        let zone = rdns::zone::parse_zone_file(&zone_text(7), "example.com.").expect("zone");
        let master = spawn_primary_full(
            zone,
            &["127.0.0.1".to_string()],
            DeltaLog::new(),
            TsigKeyring::new(Vec::new()),
            true,
            Arrival::Tcp,
        )
        .await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        let dir = ScratchDir::new("xot-required");
        let r = replication(&dir, NotifyPolicy::default());

        let err = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Refused"), "got: {err}");
    }

    /// And the refusal says which policy refused it, because "REFUSED" over a
    /// working TLS connection is otherwise an afternoon's debugging
    /// (RFC 8914, `TODO.md` #44b). Read off the wire rather than from the
    /// constant: the reply's OPT is where it has to be (RFC 8914 §2), and an
    /// EDE that never reaches it is the same as none.
    #[tokio::test]
    async fn the_refusal_says_the_transfer_must_be_encrypted() {
        let zone = rdns::zone::parse_zone_file(&zone_text(7), "example.com.").expect("zone");
        let master = spawn_primary_full(
            zone,
            &["127.0.0.1".to_string()],
            DeltaLog::new(),
            TsigKeyring::new(Vec::new()),
            true,
            Arrival::Tcp,
        )
        .await;

        // With an OPT, because that is where the reason rides and a request
        // without one gets a reply without one.
        let mut request = rdns::xfr::axfr_request(nm("example.com.").as_ref(), 0x77);
        request.edns = Some(rdns::Edns::with_payload_size(4096));
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
        let reply = rdns::DnsMessage::try_from_bytes(&packet).expect("parse the reply");

        assert_eq!(reply.rcode, ResponseCode::Refused);
        let edns = reply.edns.as_ref().expect("the reply mirrors the OPT");
        let reasons = rdns::ExtendedError::all_in(edns).expect("readable options");
        assert!(
            reasons
                .iter()
                .any(|(_, text)| text.contains("over TLS 1.3 only")),
            "the refusal should say which policy refused it: {reasons:?}"
        );
    }

    /// And the same server answers the same request when the connection is one
    /// RFC 9103 §7.2 accepts. Without this the test above is equally consistent
    /// with a server that refuses every transfer.
    #[tokio::test]
    async fn the_same_transfer_is_answered_over_tls() {
        let zone = rdns::zone::parse_zone_file(&zone_text(7), "example.com.").expect("zone");
        let master = spawn_primary_full(
            zone,
            &["127.0.0.1".to_string()],
            DeltaLog::new(),
            TsigKeyring::new(Vec::new()),
            true,
            Arrival::Dot(TlsVersion::Tls13),
        )
        .await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        let dir = ScratchDir::new("xot-allowed");
        let r = replication(&dir, NotifyPolicy::default());

        refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("a transfer over an encrypted connection");
        assert!(
            r.served
                .zone_map
                .read()
                .await
                .matching(nm("example.com.").as_ref())
                .is_some(),
            "the zone should have been installed"
        );
    }

    /// TLS 1.2 is a fine way to ask a question and not a way to take a zone:
    /// RFC 9103 §7.2 is "MUST use only TLS 1.3 [RFC8446] or later", where
    /// RFC 7858 §4.1 asks only for 1.2. A bool in place of [`Privacy`] would
    /// have made this case invisible.
    #[tokio::test]
    async fn tls_older_than_1_3_does_not_satisfy_the_transfer_policy() {
        let zone = rdns::zone::parse_zone_file(&zone_text(7), "example.com.").expect("zone");
        let master = spawn_primary_full(
            zone,
            &["127.0.0.1".to_string()],
            DeltaLog::new(),
            TsigKeyring::new(Vec::new()),
            true,
            Arrival::Dot(TlsVersion::Older),
        )
        .await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        let dir = ScratchDir::new("xot-tls12");
        let r = replication(&dir, NotifyPolicy::default());

        let err = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Refused"), "got: {err}");
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
            tls: None,
        };
        let dir = ScratchDir::new("refused");
        let r = replication(&dir, NotifyPolicy::default());

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
                tls: None,
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
                secondaries: Arc::new(Secondaries::default()),
                zone_dir: Some(dir.path().to_path_buf()),
                signing: None,
                validator: Arc::new(DnssecValidator::new(false)),
                proved: ProvenSigning::default(),
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
                reloading.load(&source, None).await
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
            transfer_tls_only: false,
            tsig_keys: Arc::new(TsigKeyring::new(Vec::new())),
            secondaries: Arc::new(Secondaries::default()),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
            updates: Arc::new(UpdateHandling::disabled()),
            dnstap: None,
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
            let run = signing.apply(&mut zones, None).expect("sign");

            // Checked with the same validator the server runs before serving.
            let mut validator = DnssecValidator::new(true);
            validator.set_require_signed(true);
            let proved = ProvenSigning::default();
            verify_zones(&zones, &validator, &run, &proved)
                .expect("the zone we just signed verifies");

            // And the same zones again, without re-signing: the run is the same
            // and the keys have not moved, so nothing is checked a second time
            // (`TODO.md` #53).
            assert_eq!(
                verify_zones(&zones, &validator, &run, &proved).expect("verifies"),
                zones::Checked {
                    zones: 0,
                    rrsets: 0,
                    skipped: 1,
                },
            );

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
            let err = verify_zones(
                &zones,
                &validator,
                &SigningRun::default(),
                &ProvenSigning::default(),
            )
            .unwrap_err();
            assert!(err.to_string().contains("not signed"), "{err}");

            // And without the assertion, the same zone is fine: most zones are
            // unsigned and serving them is the normal case.
            let permissive = DnssecValidator::new(true);
            assert!(verify_zones(
                &zones,
                &permissive,
                &SigningRun::default(),
                &ProvenSigning::default()
            )
            .is_ok());
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
            let err = verify_zones(
                &zones,
                &validator,
                &SigningRun::default(),
                &ProvenSigning::default(),
            )
            .unwrap_err();
            assert!(err.to_string().contains("does not verify"), "{err}");
        }
    }

    /// A reload keeps the signatures it can, and the re-signing timer does not.
    ///
    /// `TODO.md` #65a. `ZoneSigning::apply` signed every zone from scratch at
    /// every load, so a SIGHUP or an `rdnsctl reload` cost a full sign — 27.6 s
    /// at a million records against 9.7 s (#65b) — and moved the RDATA of every
    /// RRSIG in the zone, which is the whole zone in the next IXFR delta.
    ///
    /// The timer is the exception and has to stay one: it reloads *in order to*
    /// refresh (`ZoneSigning::resign_interval`), so everything it would carry
    /// forward is what it woke up to replace.
    ///
    /// The discriminator is the expiration, not the signature bytes. The served
    /// version is signed for 30 days and the reload is configured for 7, so a
    /// carried signature is one expiring more than a week out — `expiry_for`
    /// spreads back by a fifth, which leaves the two windows 17 days apart.
    /// ECDSA would give fresh bytes anyway, since its nonce is random, but a
    /// test that turns on that is a test passing for a reason unrelated to its
    /// subject.
    #[tokio::test]
    async fn a_reload_carries_signatures_forward_and_the_resigning_timer_does_not() {
        use clap::Parser;
        use rdns::dnssec::DNSKEY_FLAG_ZONE;
        use rdns::dnssec_key::{SigningAlgorithm, SigningKey};

        const ZONE: &str = "example.com.";
        let dir = ScratchDir::new("reload-carry-forward");
        let key_dir = dir.path().join("keys");
        std::fs::create_dir_all(&key_dir).expect("the key directory");
        let key = SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ZONE, DNSKEY_FLAG_ZONE)
            .expect("a key");
        key.write_to_dir(&key_dir).expect("the key file");
        let text = "$TTL 3600\n\
                    @ IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n\
                    @ IN NS ns.example.com.\n\
                    ns IN A 192.0.2.1\n\
                    www IN A 192.0.2.10\n";
        std::fs::write(dir.path().join("example.com.zone"), text).expect("the zone file");

        let mut cli = Cli::parse_from(["rdnsd"]);
        cli.signing_key_dir = Some(key_dir);
        cli.signature_validity = 7;
        let signing = ZoneSigning::load(&cli, &BTreeMap::new())
            .expect("the keys load")
            .expect("a key directory means signing");

        let zone_map = Arc::new(RwLock::new(Zones::default()));
        let deltas = Arc::new(RwLock::new(DeltaLog::new()));
        let ctx = ReloadContext {
            reloading: Reloading {
                replicating: false,
                allow_partial: false,
                secondaries: Arc::new(Secondaries::default()),
                zone_dir: None,
                signing: Some(Arc::new(signing)),
                validator: Arc::new(DnssecValidator::new(true)),
                proved: ProvenSigning::default(),
            },
            source: ZoneSource::Directory(dir.path().to_string_lossy().to_string()),
            served: served(&zone_map, &deltas),
            notify: Arc::new(NotifyPolicy::default()),
            tls: None,
        };

        // The version being served when the reload arrives: the same file, signed
        // for thirty days rather than the seven the daemon is configured for.
        let long = || {
            let parsed = rdns::zone::parse_zone_file(text, ZONE).expect("the fixture parses");
            sign_zone(
                &parsed,
                std::slice::from_ref(&key),
                &SigningPolicy::valid_for(rdns::clock::current_unix_timestamp(), 30 * 86_400)
                    .with_chain(DenialChain::Nsec),
            )
            .expect("the fixture signs")
        };

        /// How many of the zone's RRSIGs expire more than a week out — which is
        /// to say, how many came from the served version rather than this run.
        async fn carried(zone_map: &Arc<RwLock<Zones>>) -> usize {
            let week = rdns::clock::current_unix_timestamp() + 7 * 86_400;
            let zones = zone_map.read().await;
            let zone = zones
                .matching(nm(ZONE).as_ref())
                .expect("the zone is served");
            zone.records()
                .iter()
                .filter(|r| r.rdata.rtype() == record_types::RRSIG)
                .filter(|r| match r.rdata.parse() {
                    Ok(rdns::ParsedRecord::RRSIG { expiration, .. }) => {
                        u64::from(expiration) > week
                    }
                    _ => false,
                })
                .count()
        }

        let busy = test_shutdown().lifecycle().busy;

        drop(zone_map.write().await.insert(long()));
        let before = carried(&zone_map).await;
        assert!(before > 3, "the fixture has signatures to carry: {before}");

        let (tx, rx) = tokio::sync::oneshot::channel();
        reload_once(&ctx, Vec::new(), &busy, ReloadTrigger::Control(tx)).await;
        assert_eq!(rx.await.expect("the reload answered"), Ok(1));
        // All of them, the apex SOA's included: the served serial is the file's
        // plus a term in *hours* (`zone_signer::signed_serial`), so two runs in
        // the same hour agree about it and the RRset has not moved either.
        assert_eq!(
            carried(&zone_map).await,
            before,
            "a control reload carried fewer than all {before} signatures forward",
        );

        drop(zone_map.write().await.insert(long()));
        reload_once(&ctx, Vec::new(), &busy, ReloadTrigger::Timer).await;
        assert_eq!(
            carried(&zone_map).await,
            0,
            "the re-signing timer reloads in order to refresh, so it may carry nothing",
        );
    }
}
