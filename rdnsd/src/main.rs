//! `rdnsd` — the authoritative server: UDP and TCP from one process.
//!
//! One process because anything that writes state — a fetched zone, a refresh
//! timestamp, a journal — needs a single owner.
//!
//! What stays in this root is the shell around the answering: the CLI,
//! startup's order (config, secrets, zones, signing, verification, then a
//! socket), the two socket loops, the reload and maintenance timers, and NOTIFY
//! going *out*. Elsewhere, on `TODO.md` #38d's criterion: [`zones`] (where a
//! zone comes from and how it is swapped in), [`replication`] (being a
//! secondary), [`dispatch`] (one request in, its reply on the wire), [`answer`]
//! (what a name deserves, with no sockets in it), [`config`] and [`control`].
//!
//! Every listening socket this binary binds is bound here or in `control`, and
//! nothing below them decides to exit. A change about *what an answer is* belongs
//! two modules down.

// `TODO.md` #82b's ratchet; the reason is at the top of `rdns/src/lib.rs`.
#![warn(unreachable_pub)]
// `push_str(&format!(..))` allocates a `String` to copy it; `write!` into the
// target does not. Off by default (restriction group).
#![warn(clippy::format_push_string)]

mod answer;
/// Consuming catalog zones: what `--catalog` provisions (RFC 9432).
mod catalog;
mod catalog_gen;
mod config;
/// Control socket: a Unix socket, or a named pipe on Windows.
mod control;
/// Answering one request, on either transport.
mod dispatch;
mod notify_out;
mod parental;
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
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zones::{
    discard_orphan_journals, install_all_zones, load_zones, note_serials, restore_journals,
    validate_zone_source, verify_zones, Keepable, Loaded, LoadedFiles, ProvenSigning, SigningRun,
    ZoneContext, ZoneMap, ZoneSigning, ZoneSource, Zones,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use rdns::clock::Clock;
use rdns::compression::NameCompressor;
use rdns::tls_identity::TlsIdentity;
use rdns::xot::TlsClientTrust;
use rdns::{
    dnssec::{DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE},
    dnssec_key::{SigningAlgorithm, SigningKey},
    dnssec_validation_mode::DnssecValidator,
    ixfr::DeltaLog,
    journal::Journal,
    logging::{watch_anomalies, AnomalyThresholds, QueryLogger},
    metrics::DnsMetrics,
    notify::NotifyPolicy,
    secondary::{state_file_path, StateFile},
    security::{RateLimitConfig, RateLimiter, ResponseLimiter, TransferAcl, TransferCertificates},
    shutdown::{next_reload, reload_signal, Busy, Lifecycle, Shutdown, Stop},
    tsig::TsigKeyring,
    validation::{AdmissionCheck, AdmissionLimits, Transport},
    Serial,
};
use rdns::{Name, UdpSizes};
use rdns_transport::bind;
use rdns_transport::encrypted::{Encrypted, EncryptedFlags, EncryptedListeners};
use rdns_transport::logging::LogLevel;
use rdns_transport::metrics_server;
use rdns_transport::readiness::Readiness;
use rdns_transport::tcp;
use rdns_transport::tls::CertificateStore;
use rdns_transport::{
    recv_error_is_transient, QueryAcl, ServeContext, SourceConnections, TransportLimits,
    UDP_RECEIVE_BUFFER,
};

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

// Defaults in one place, which `Cli` and the config file both take; in the
// crate root, so `config` sees them (`CLAUDE.md` §17).

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
fn default_max_connections() -> std::num::NonZeroUsize {
    rdns_transport::DEFAULT_MAX_CONNECTIONS
}
fn default_connection_idle_timeout() -> std::num::NonZeroU64 {
    rdns_transport::DEFAULT_IDLE_TIMEOUT_SECS
}
fn default_max_connections_per_source() -> usize {
    rdns_transport::DEFAULT_MAX_CONNECTIONS_PER_SOURCE
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

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinSet;

// Re-exported with `pub(crate) use`: textual scoping would force `mod
// dispatch;` below here, and `#[macro_export]` would make them public.

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

use dispatch::{Server, UpdateHandling, Wire};
use rdns::peer::Peer;

/// Authoritative DNS server.
///
/// UDP and TCP from one process: anything that writes state (a fetched zone, a
/// refresh timestamp) needs a single owner.
#[derive(Parser)]
#[command(version = rdns::VERSION, about, long_about = None)]
struct Cli {
    /// Address to listen on, for both transports.
    ///
    /// `::` serves IPv4 and IPv6 on every platform; a specific IPv6 address,
    /// such as `::1`, serves IPv6 only.
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
    /// Ask this server for ZONE's DS before one of ZONE's key-signing keys
    /// retires: `ZONE@ADDR[:PORT][#KEY][+tls=NAME]`, repeatable, as
    /// --secondary. A retiring KSK keeps signing until every agent's DS RRset
    /// has shown an active successor for its TTL. Answers are not validated, so
    /// use #KEY or +tls= across an untrusted path: a forged DS retires a key
    /// early.
    #[arg(
        long,
        value_name = "ZONE@AGENT[:PORT][#KEY][+tls=NAME]",
        conflicts_with = "config"
    )]
    parental_agent: Vec<String>,
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
    /// Publish an RFC 9432 catalog zone at NAME listing every zone this server
    /// is primary for. NAME under invalid., or under a primary zone here (§6).
    ///
    /// Rebuilt on every reload; `catalog-member = false` opts a zone out.
    /// Served by transfer only, under --allow-transfer; queries under it are
    /// REFUSED.
    #[arg(long, value_name = "NAME", conflicts_with = "config")]
    generate_catalog: Option<String>,
    /// Response bytes per second, per IPv4 /24 or IPv6 /56 a reply goes to.
    /// 0 turns the budget off.
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
    /// Floored at the advertised payload size (RFC 6891 §6.2.4), a promise to
    /// clients. Raise it for large signed UPDATEs, such as a DKIM key rotation
    /// (`rdns/examples/request_size_probe.rs`). Over it is dropped silently;
    /// the startup line shows the value.
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
    /// asking for 65,535 given exactly that gets a large signed answer as ~45
    /// IP fragments. Over it the reply is an empty TC=1 and the client asks
    /// again over TCP, which is never capped. What a signed answer off these
    /// zones weighs is measured in `rdnsd/src/response_size.rs`. 65535 is
    /// "whatever the client asked for"; floored at 512.
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
    /// Concurrent connections each stream listener holds — TCP, DoT, DoH and
    /// DoQ count separately.
    ///
    /// A full listener leaves the next connection in the kernel's backlog until
    /// one closes, and says so once in the log and in
    /// `dns_connection_accept_waits_total`. No `0` for "no limit": the ceiling
    /// is what stands between a connection flood and the descriptor limit.
    #[arg(
        long,
        value_name = "N",
        default_value_t = default_max_connections(),
        conflicts_with = "config"
    )]
    max_connections: std::num::NonZeroUsize,
    /// Seconds a stream connection may go without the client starting a
    /// message, request or DoQ stream before it is closed, and a DoT or DoH
    /// TLS handshake may take. DoH and DoQ let what is in flight finish, for
    /// at most one more timeout.
    #[arg(
        long,
        value_name = "SECONDS",
        default_value_t = default_connection_idle_timeout(),
        conflicts_with = "config"
    )]
    connection_idle_timeout: std::num::NonZeroU64,
    /// Connections one source may hold on each stream listener; 0 turns the
    /// limit off.
    ///
    /// A source is an IPv4 address or an IPv6 /56. Over the limit the
    /// connection is closed with no reply, counted in
    /// `dns_connections_refused_per_source_total`, and the source named in the
    /// log at most once a minute. Without it one peer can hold every slot of a
    /// listener.
    #[arg(
        long,
        value_name = "N",
        default_value_t = default_max_connections_per_source(),
        conflicts_with = "config"
    )]
    max_connections_per_source: usize,
    /// An address or CIDR prefix `--max-connections-per-source` does not apply
    /// to, repeatable. Matched against the connecting address.
    #[arg(long, value_name = "ADDR|CIDR", conflicts_with = "config")]
    max_connections_per_source_exempt: Vec<String>,
    /// Queries per second, per source: an IPv4 address or an IPv6 /56.
    /// 0 turns the limit off.
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
    /// PEM bundle of the certificate authorities a *client's* certificate is
    /// checked against (RFC 9103 §7.5's mutual TLS, `TODO.md` #59).
    ///
    /// Naming it makes every encrypted listener ask for a certificate and take
    /// no for an answer: one `ServerConfig` serves DoT, DoQ and DoH, so
    /// demanding one would demand it of every stub resolver on the same port,
    /// and RFC 8310 §8.2's mTLS for DoT is a different relationship from
    /// §7.5's. What a presented certificate may then transfer is
    /// --allow-transfer-cert's business and nothing else's.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    transfer_client_ca: Option<PathBuf>,
    /// A client certificate that may transfer, as `name[:zone[,zone]]`.
    ///
    /// The name is a subject alternative name, checked by the code that
    /// verified the chain. Without zones it may transfer every zone, like an
    /// unscoped --tsig-key; the startup banner prints each rule. Repeatable.
    /// Needs --transfer-client-ca (`CLAUDE.md` §15).
    #[arg(
        long,
        value_name = "NAME[:ZONES]",
        requires = "transfer_client_ca",
        conflicts_with = "config"
    )]
    allow_transfer_cert: Vec<String>,
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
    /// `tcp:<addr:port>` for a collector, `file:<path>` for a `dnstap -r`
    /// capture; the scheme is required. The queue to the sink is bounded and
    /// drops (`dns_dnstap_dropped_total`), so a stalled collector is not an
    /// outage. No Unix socket: `tokio` has none on Windows.
    #[arg(
        long,
        value_name = "tcp:ADDR:PORT|file:PATH",
        conflicts_with = "config"
    )]
    dnstap: Option<String>,
    /// Stop writing a dnstap *file* after this many octets. 0 is no limit.
    ///
    /// A capture is not rotated, so the bound protects the disk; past it,
    /// writing stops, one warning, and the rest count as dropped. Ignored for
    /// `tcp:`. The config file's `server.dnstap-max-bytes` shares
    /// [`default_dnstap_max_bytes`].
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
    /// Answer an NSID request (RFC 5001) with this identifier: text, or `0x`
    /// and hex. Off unless given, as §5 calls it "security sensitive"; only a
    /// query carrying the option gets one (§2.2).
    #[arg(long, value_name = "TEXT|0xHEX", conflicts_with = "config")]
    nsid: Option<String>,
    /// Answer `rdnsctl` on this Unix socket, or on Windows this named pipe
    /// (`\\.\pipe\NAME`): `status`, `reload`, `dump <zone>`.
    ///
    /// Access control is the authentication: the socket is mode 0600, so the
    /// server's user and root; the pipe's default descriptor lets only the
    /// owner, administrators and SYSTEM write. That is also why these commands
    /// are not on `--metrics-listen`, where `reload` would be a POST with no
    /// credential.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    control_socket: Option<PathBuf>,
    /// Write log lines to this file instead of standard error, appended,
    /// each with a UTC timestamp. Reopened on every reload, so an external
    /// rotation needs only a reload after the move.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    log_file: Option<PathBuf>,
    /// Run as Windows service NAME under the service control manager, which
    /// is what starts it: `sc.exe create NAME binPath= "... --service NAME
    /// ..."`. STOP drains as Ctrl-C does; PARAMCHANGE (`sc.exe control NAME
    /// paramchange`) reloads as SIGHUP does. Needs --log-file, since a
    /// service's standard error goes nowhere. Windows only.
    #[arg(long, value_name = "NAME")]
    service: Option<String>,
    /// Read the settings from a TOML file instead of from flags.
    ///
    /// Exclusive of the flags it would set, so no silent precedence. It can
    /// also hold a TSIG secret in its own file and per-zone signing settings.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Validate the configuration and exit without binding a socket.
    ///
    /// Reads the config, the TSIG secrets and the signing keys; exit 0 means it
    /// would start. Works with flags as with `--config`, as `rdnsr`'s does.
    #[arg(long)]
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

/// The policy knobs `serve` applies.
///
/// A struct rather than more positional parameters: two `u32`s and two
/// address-shaped things are one edit away from being swapped silently.
struct ServePolicy {
    transfer_acl: TransferAcl,
    /// Which client certificates may transfer which zones (`TODO.md` #59).
    transfer_clients: TransferCertificates,
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
    /// What one connection may cost on each stream listener.
    connections: TransportLimits,
    /// And how many of them one source may hold.
    per_source: SourceConnections,
    /// The catalog this server generates, whose names ordinary queries are
    /// refused for (`TODO.md` #182).
    generated_catalog: Option<Name>,
    /// RFC 5001's identifier, or off.
    nsid: Option<&'static [u8]>,
    /// Where to serve Prometheus metrics, if anywhere.
    metrics_listen: Option<String>,
    /// Where to answer DNS over TLS, QUIC and HTTPS, and with what. `None` is
    /// off.
    tls: Option<Encrypted>,
    /// Whether every zone this server answers for is in the map yet, for
    /// `/readyz` on that same listener.
    readiness: Readiness,
    /// What a dynamic UPDATE needs; refuses everything when unconfigured.
    updates: UpdateHandling,
    /// Where the delta log is persisted, if anywhere.
    journal: Option<Arc<Journal>>,
    /// Where the query stream goes, and what a capture file may weigh.
    dnstap: Option<(rdns_transport::dnstap::Target, u64)>,
    /// The control socket, and what a `reload` on it pokes.
    control: ControlPolicy,
}

/// Where the control socket lives and how it asks for a reload.
struct ControlPolicy {
    socket: Option<PathBuf>,
    reloads: mpsc::Sender<ReloadTrigger>,
    /// Zones this server replicates, so `status` says `secondary` from what is
    /// being replicated rather than guessing from an absent timestamp, which a
    /// primary also has. The live registry, because a catalog's members are
    /// replicated and arrive after startup.
    secondaries: Arc<Secondaries>,
    /// The catalogs this server consumes, so `status` can name the catalog a
    /// zone came from and `catalog` can report what one holds — refusals
    /// included, which have no zone and so no row in `status`.
    catalogs: Arc<crate::catalog::Catalogs>,
    /// For `status`'s uptime. Taken in `main`, not here: loading and signing
    /// every zone happens before `serve` and is the bulk of a big start.
    started: Instant,
    /// Keys whose retirement waits on the parent's DS (`TODO.md` #180).
    parental: parental::ParentalGate,
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
        generated_catalog,
        transfer_acl,
        transfer_clients,
        transfer_tls_only,
        tsig_keys,
        response_rate,
        query_limit,
        admission,
        udp,
        anomalies: (anomaly_interval, anomaly_thresholds),
        udp_workers,
        connections,
        per_source,
        nsid,
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
    // Appended: `--transfer-tls-only` narrows every rule above, which the
    // operator should not need to know the flag to learn (`CLAUDE.md` §14).
    let transfers = if transfer_tls_only {
        format!("{transfers}, over TLS 1.3 only (--transfer-tls-only)")
    } else {
        transfers
    };
    let budget = if response_rate == 0 {
        "off".to_string()
    } else {
        format!("{response_rate} bytes/s per IPv4 /24 or IPv6 /56")
    };
    // Printed: over-limit queries are dropped silently, as a reply to a spoofed
    // source amplifies.
    let query_limit_note = if query_limit.tokens_per_window == 0 {
        "off".to_string()
    } else {
        format!(
            "{} q/s per source (IPv4 address, IPv6 /56), burst {}{}",
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

    // Bind everything before announcing anything, the metrics listener too, so
    // a port conflict or a typo stops the start.
    let socket = bind::udp(addr).await?;
    let listening = socket.describe();
    let socket = Arc::new(socket.socket);
    let listener = bind::tcp(addr).await?.socket;
    let metrics_listener = match &metrics_listen {
        Some(spec) => Some(
            bind::tcp(spec)
                .await
                .with_context(|| format!("--metrics-listen {spec}"))?,
        ),
        None => None,
    };
    // And the encrypted listeners, for the same reason.
    let stream_listeners = EncryptedListeners::bind(tls.as_ref(), connections).await?;
    // Same rule for the control socket: a path that cannot be bound stops the
    // start.
    let control_listener = match &control.socket {
        Some(path) => Some(control::bind(path)?),
        None => None,
    };

    // Before the sockets: an unreachable collector or unwritable capture is a
    // misconfiguration, not a stream that never appears (`CLAUDE.md` §4).
    let dnstap = match &dnstap {
        Some((target, max_bytes)) => Some(
            rdns_transport::dnstap::Sink::spawn(
                target,
                *max_bytes,
                rdns_transport::dnstap::hostname(),
                format!("rdnsd {}", env!("CARGO_PKG_VERSION")).into_bytes(),
                (*metrics).clone(),
                shutdown.stop_handle(),
            )
            .await?,
        ),
        None => None,
    };

    let server = Arc::new(
        Server::new(
            zone_map,
            ServeContext {
                limiter: Arc::new(RateLimiter::new(query_limit)),
                responses: Arc::new(ResponseLimiter::per_second(response_rate)),
                admission: Arc::new(AdmissionCheck::new(admission.clone())),
                logger: Arc::new(QueryLogger::new()),
                metrics,
                udp,
                per_source: per_source.clone(),
                // A query ACL is `rdnsr`'s (`TODO.md` #171): an authoritative
                // server answers whoever asks about its zones.
                acl: QueryAcl::Open,
                nsid,
                clock: Clock::system(),
            },
        )
        .with_transfers(transfer_acl, transfer_clients, transfer_tls_only)
        .with_tsig_keys(tsig_keys)
        .with_secondaries(secondaries)
        .with_history(deltas, journal)
        .with_updates(updates)
        .with_dnstap(dnstap)
        .with_generated_catalog(generated_catalog),
    );
    // The effective policy, at the default level: a control nobody can observe
    // is a control nobody can debug.
    tracing::info!(
        "rdnsd listening on {listening} (UDP+TCP), zone transfer: {transfers}, \
         response budget: {budget}, query rate: {query_limit_note}, \
         request cap: {udp_cap}B UDP / {tcp_cap}B TCP, \
         UDP reply cap: {reply_cap}B (advertising {advertised}B), \
         UDP workers: {udp_workers}, anomaly warnings: {anomaly_note}, \
         connections: {} per listener, {}, idle {}s, \
         TSIG keys: {}, encrypted: {}, metrics: {}, control: {}, NSID: {}",
        connections.max_connections,
        per_source.describe(),
        connections.idle_timeout.as_secs(),
        server.tsig_keys().len(),
        match &tls {
            Some(encrypted) => stream_listeners.describe(encrypted),
            None => "off (--tls-listen, --quic-listen)".to_string(),
        },
        match &metrics_listener {
            Some(bound) => format!("{}/metrics ({})", bound.local, bound.families),
            None => "off (--metrics-listen)".to_string(),
        },
        match &control.socket {
            Some(path) => format!("{} ({})", path.display(), rdns_transport::control::ACCESS),
            None => "off (--control-socket)".to_string(),
        },
        match nsid {
            Some(nsid) => rdns::config::show_nsid(nsid),
            None => "off (--nsid)".to_string(),
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

    // Outside the `JoinSet`, as it ends on the stop signal by design; joined
    // after the drain, so not detached (`CLAUDE.md` §9).
    let anomalies = tokio::spawn(watch_anomalies(
        server.ctx().logger.clone(),
        anomaly_thresholds,
        anomaly_interval,
        shutdown.stop_handle(),
    ));

    // `JoinSet`, not `JoinHandle`s in a `select!`: dropping a handle detaches
    // its task, and `join_next` is cancel-safe.
    let mut loops = JoinSet::new();
    // Workers are peers on one socket, so the first to stop for any reason but
    // the signal ends the process.
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
    stream_listeners.spawn(
        listener,
        server.clone(),
        tcp::RateLimit::PerMessage,
        &shutdown,
        &mut loops,
    );
    // A listener like the others: if it dies, the process does. A server whose
    // metrics stopped is one nobody is watching.
    if let Some(metrics_listener) = metrics_listener {
        loops.spawn(metrics_server::serve(
            metrics_listener.socket,
            server.ctx().metrics.clone(),
            readiness,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
    }
    // And the control socket, for the same reason.
    if let Some(control_listener) = control_listener {
        let ControlPolicy {
            socket,
            reloads,
            secondaries,
            catalogs,
            started,
            parental,
        } = control;
        loops.spawn(control::serve(
            control_listener,
            socket.expect("a listener implies a path"),
            Arc::new(control::Control {
                served: server.zone_context(),
                secondaries,
                catalogs,
                reloads,
                started,
                listen: addr.to_string(),
                parental,
            }),
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
    }

    // The first listener to end ends the process; the drain waits for an AXFR
    // on the wire, which a client cannot tell from a complete one if cut.
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
/// A fixed pool bounds concurrency before the copy, and the kernel drops and
/// counts the overflow; one 64 KB buffer per worker ([`default_udp_workers`]).
/// This loop must not block. A panic ends the worker, then the process.
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
        let (size, from) = match received {
            Ok(received) => received,
            Err(e) if recv_error_is_transient(&e) => continue,
            Err(e) => return Err(e),
        };
        let packet = &buf[..size];
        // Canonical for every check and record; the reply goes to `from`, the
        // form a dual-stack socket sends to.
        let peer = rdns::peer::canonical(from);

        // One clock read per datagram, for limiter, logger, TSIG and response
        // budget, through `ctx` so a test's `Clock::fixed` reaches UDP too.
        let now = server.ctx().clock.now();

        // Both are decisions to do nothing, so they run on `&buf[..size]` with
        // nothing copied and nothing spawned.
        if !server.ctx().allow_source(Peer::from(peer), now) {
            continue;
        }
        if !server
            .ctx()
            .accept_packet(Peer::from(peer), packet, Transport::Udp)
        {
            continue;
        }

        // Claims the drain for this answer only; held across the loop it would
        // keep the drain open.
        let _busy = busy.clone();
        server
            .answer(
                packet,
                peer,
                now,
                &Wire::Datagram(&socket, from),
                &mut scratch,
            )
            .await;
    }
}

/// What one UDP worker reuses from datagram to datagram: the reply buffer,
/// sized to the largest EDNS payload asked, and the name compressor.
///
/// One struct, as they are one scratch space and clippy limits arguments
/// (`CLAUDE.md` §14).
#[derive(Default)]
struct Scratch {
    out: Vec<u8>,
    compressor: NameCompressor,
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
    /// The zones we replicate, and the directory their state sidecar lives in,
    /// so a reload cannot resurrect a zone withdrawn for EXPIRE.
    ///
    /// The live registry, not the `--secondary` specs: catalog members share
    /// the directory, and a list fixed at startup would serve one with AA
    /// however stale.
    secondaries: Arc<Secondaries>,
    zone_dir: Option<PathBuf>,
    signing: Option<Arc<ZoneSigning>>,
    validator: Arc<DnssecValidator>,
    /// Shared with the startup pass, which is the run that proves most of it: a
    /// reload that re-signs a zone with the same keys has nothing new to check.
    proved: ProvenSigning,
    /// The catalog to rebuild from the zones each reload loads (`TODO.md`
    /// #182).
    catalog: Option<Arc<catalog_gen::GeneratedCatalog>>,
    /// What each zone file held when it was last parsed, so a reload can keep
    /// the zone it is serving for a file nobody touched — 11.4 s per unchanged
    /// million-record signed zone (`TODO.md` #64f). Shared with the startup
    /// pass for the same reason `proved` is: the first SIGHUP after a start has
    /// something to compare against.
    files: LoadedFiles,
}

#[cfg_attr(not(unix), allow(dead_code))]
impl Reloading {
    /// Read the zones again and put them through signing and checking, or say
    /// why not.
    ///
    /// All or nothing: half a reload would serve two versions. All of it on a
    /// blocking thread: read, parse, sign and verify each block, and the
    /// listeners are live.
    async fn load(&self, source: &ZoneSource, previous: Option<ZoneMap>) -> Result<ZoneMap> {
        let reloading = self.clone();
        let source = source.clone();
        tokio::task::spawn_blocking(move || reloading.load_blocking(&source, previous.as_ref()))
            .await
            .context("the zone-loading task")?
    }

    /// The blocking half of [`Reloading::load`], and named so at the call site.
    fn load_blocking(&self, source: &ZoneSource, previous: Option<&ZoneMap>) -> Result<ZoneMap> {
        // One moment for the whole reload, so a key crossing its Activate
        // between two reads cannot be silently declined.
        let signed_at = rdns::clock::current_unix_timestamp();
        // Empty when the re-signing timer calls: nothing kept, but what it read
        // is recorded, or the next SIGHUP re-parses everything.
        let nothing = ZoneMap::new();
        let keep = Keepable {
            files: &self.files,
            served: previous.unwrap_or(&nothing),
            signing: self.signing.as_deref(),
            proved: &self.proved,
            signed_at,
        };
        let Loaded { mut zones, kept } =
            load_zones(source, self.replicating, self.allow_partial, Some(&keep))?;
        let run = match &self.signing {
            Some(signing) => signing.apply_keeping(&mut zones, previous, &kept, signed_at)?,
            None => SigningRun::default(),
        };
        verify_zones(&zones, &self.validator, &run, &self.proved)?;
        // From the set that loaded, all or nothing: a reload that failed above
        // never reaches here, so the catalog keeps its members.
        if let Some(catalog) = &self.catalog {
            let zone = catalog.build(
                zones.keys().map(|k| k.as_name()),
                |z| self.secondaries.replicates(z),
                signed_at,
            )?;
            zones.insert(crate::zones::zone_key(&zone), Arc::new(zone));
        }
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
    /// A key-signing key let go by the parental-agent gate (`TODO.md` #180):
    /// the DNSKEY RRset changes, so the zone is re-signed now rather than at
    /// the next tick.
    ParentDs,
}

impl ReloadTrigger {
    /// Is this the reload whose point is that the signatures come out new?
    ///
    /// The re-signing timer refreshes *by reloading*
    /// ([`ZoneSigning::resign_interval`]), so it is the one trigger that may
    /// not carry a signature forward — everything it would carry is what it
    /// woke up to replace. SIGHUP and the control socket are an operator or a
    /// catalog saying the files moved, and there the served version is a
    /// previous version in exactly the sense `sign_zone_incrementally` means.
    fn refreshes_signatures(&self) -> bool {
        matches!(self, ReloadTrigger::Timer)
    }

    /// What the log line says this reload was for.
    fn why(&self) -> &'static str {
        match self {
            ReloadTrigger::Signal if cfg!(windows) => "PARAMCHANGE",
            ReloadTrigger::Signal => "SIGHUP",
            ReloadTrigger::Timer => "signature refresh",
            ReloadTrigger::Control(_) => "control socket",
            ReloadTrigger::ParentDs => "a key retiring once the parent's DS moved",
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
    // Rotation: a log file moved away is followed from here (`TODO.md` #190).
    rdns_transport::logging::reopen();
    // Every reload path passes here, so a certificate renewal is `rdnsctl
    // reload`; a failure warns and the old certificate stays.
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
            // A reload is a version step: the difference is what an IXFR
            // answers, and only now do both versions exist.
            install_all_zones(served, new_zones).await;
            // The files bring back a zone withdrawn for EXPIRE; judge it again
            // before anything is announced or answered.
            reloading.withdraw_unvouched(served).await;
            tracing::info!("zones reloaded ({why})");
            // Something changed, new data or at least new signatures and
            // serial, so the secondaries hear of it.
            (
                crate::notify_out::announce_zones(&served.zone_map, &announced, notify, busy).await,
                Ok(loaded),
            )
        }
        Err(e) => {
            // The loaded zones keep answering: the version in memory is the
            // last known good.
            tracing::error!("failed to reload zones ({why}): {e}");
            // `{e:#}` for the requester: the whole `anyhow` chain, where the
            // log line keeps the outermost context.
            (announced, Err(format!("{e:#}")))
        }
    };
    // A dropped receiver is an `rdnsctl` that gave up; the reload happened and
    // the log has it.
    if let ReloadTrigger::Control(reply) = trigger {
        let _ = reply.send(outcome);
    }
    announced
}

/// Keep the zones current: reload on SIGHUP or on the control socket, and
/// re-sign on a timer.
///
/// One task: re-signing is a reload ([`ZoneSigning::resign_interval`]), and two
/// tasks would install different snapshots concurrently. It holds a [`Busy`]
/// and exits on [`Stop`], so the drain waits for an install.
fn spawn_zone_maintenance(
    ctx: ReloadContext,
    announced: Vec<(Name, Serial)>,
    lifecycle: Lifecycle,
) -> mpsc::Sender<ReloadTrigger> {
    let Lifecycle { stop, busy } = lifecycle;
    // `None` when nothing is signed, so no timer reloads on a schedule nobody
    // asked for.
    if let Some(signing) = ctx.reloading.signing.as_ref() {
        tracing::info!("{}", signing.resign_interval());
    }

    // Depth 1: a reload is the whole set, so a second request waits for the
    // slot and a third has nothing to add.
    let (requests, mut receiver) = mpsc::channel(1);
    // A sender of its own keeps `recv` parked rather than returning `None` when
    // there is no control socket.
    let keepalive = requests.clone();

    tokio::spawn(async move {
        let _busy = busy;
        let _keepalive = keepalive;
        let mut announced = announced;
        let mut signals = reload_signal();
        loop {
            // Ignored during shutdown. `recv` is cancel-safe: a request losing
            // to the stop stays queued, and its sender learns of the stop.
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
                // Asked each time: the interval follows the nearest key
                // rollover step, which moves as steps are taken.
                _ = sleep_for(ctx.reloading.signing.as_ref().map(|s| s.resign_interval().every))
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

/// DHAT's allocator shim, only under `--features dhat-heap`.
///
/// It records a backtrace per allocation, which dominates everything — so a
/// build with this on answers *how many* and *how big* and says nothing useful
/// about *how fast*. Never read a timing number from one.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    // `--check-config` is a console answer even with `--service` beside it.
    let service = cli.service.clone().filter(|_| !cli.check_config);
    rdns_transport::entry::run(service.as_deref(), move || serve_main(cli))
}

async fn serve_main(mut cli: Cli) -> Result<()> {
    // Held to the end of `main`: the profiler writes `dhat-heap.json` on
    // `Drop`, and binding it in `serve` would drop it before the drain.
    #[cfg(feature = "dhat-heap")]
    let _dhat = dhat::Profiler::new_heap();

    // First, so `status`'s uptime covers the zone load, which on a signed
    // server is the start.
    let started = Instant::now();

    // The file replaces the flags rather than layering over them; `config` says
    // why.
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
    // Early, as the file may name the log file. clap refuses `--quiet` with
    // `--log-level`, so this is a rename (`CLAUDE.md` §15).
    rdns_transport::logging::init(
        if cli.quiet {
            LogLevel::Error
        } else {
            cli.log_level
        },
        cli.log_file.as_deref(),
    )?;

    // Before the dry run (`TODO.md` #190).
    if cli.service.is_some() {
        if !cfg!(windows) {
            return Err(anyhow!(
                "--service is the Windows service control manager's; under systemd or \
                 another supervisor run the binary as it is"
            ));
        }
        if cli.log_file.is_none() {
            return Err(anyhow!(
                "--service needs --log-file: a service's standard error goes nowhere, so \
                 without one nothing it says reaches anybody"
            ));
        }
    }

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
    // Refused *here* so `--check-config` says so too: on Windows a path that is
    // not a pipe name.
    if let Some(path) = &cli.control_socket {
        rdns_transport::control::check(path)?;
    }

    // Here, not in `serve`: the startup NOTIFY burst and every refresh task
    // start before the listeners, and the drain must wait for them.
    let shutdown = Shutdown::new();
    // Here for the same reason: served serials and transfer times are true from
    // the initial load.
    let metrics = Arc::new(DnsMetrics::new());
    // A typo in either list stops the server rather than quietly narrowing it —
    // or, worse, being read as something wider.
    let transfer_acl = TransferAcl::parse(&cli.allow_transfer)?;
    let tsig_keys = TsigKeyring::parse(&cli.tsig_key)?;
    // The incoming half of RFC 9103 §7.5: anchors for a client's certificate,
    // which the encrypted listeners are built with.
    let client_anchors = match &cli.transfer_client_ca {
        Some(path) => Some(rdns::tls_identity::TrustAnchors::from_ca_file(
            path,
            "the transfer client trust anchors",
        )?),
        None => None,
    };
    // Before anything binds: a certificate that will not read is a DoT listener
    // that answers nothing.
    let encrypted = Encrypted::configure(
        EncryptedFlags {
            tls_listen: cli.tls_listen.as_deref(),
            quic_listen: cli.quic_listen.as_deref(),
            https_listen: cli.https_listen.as_deref(),
            https_path: &cli.https_path,
            tls_cert: cli.tls_cert.as_deref(),
            tls_key: cli.tls_key.as_deref(),
        },
        client_anchors,
    )?;
    // With no encrypted listener this refuses every transfer, so it is a
    // startup error (`CLAUDE.md` §15).
    if cli.transfer_tls_only && encrypted.is_none() {
        return Err(anyhow!(
            "--transfer-tls-only needs a listener a transfer can arrive on: \
             --tls-listen, --quic-listen or --https-listen. Without one, every \
             transfer is refused"
        ));
    }

    // After the keyring, because a `#key` names one of its entries.
    let notify = Arc::new(notify_out::build_notify_policy(
        &cli.also_notify,
        &per_zone.notify,
        &tsig_keys,
    )?);
    // Said out loud: whether a NOTIFY is signed decides whether a keyed notify
    // ACL acts on it.
    if !notify.is_empty() {
        tracing::info!("notifying {}", notify.describe());
    }
    let query_limit = RateLimitConfig::per_second(cli.query_rate, cli.query_burst).exempting(
        TransferAcl::parse_named(&cli.query_rate_exempt, "--query-rate-exempt")?,
    );
    let per_source = SourceConnections::new(
        cli.max_connections_per_source,
        TransferAcl::parse_named(
            &cli.max_connections_per_source_exempt,
            "--max-connections-per-source-exempt",
        )?,
    );
    // Above the dry run (`CLAUDE.md` §15). Leaked once: read on every reply,
    // and `'static` keeps `ServerOpt` `Copy`.
    let nsid: Option<&'static [u8]> = cli
        .nsid
        .as_deref()
        .map(rdns::config::parse_nsid)
        .transpose()?
        .map(|bytes| &*Box::leak(bytes.into_boxed_slice()));

    let mut secondary_specs = parse_secondary_specs(&cli.secondary)?;
    // A catalog replicates like any zone (RFC 9432 §5.1), so it joins the list
    // and reuses the tested timers, NOTIFY, EXPIRE and file handling.
    let catalog_specs = parse_catalog_specs(&cli.catalog)?;
    // Here, above the dry run: a spec naming an undefined key fails the start
    // either way (`CLAUDE.md` §15).
    for spec in secondary_specs.iter() {
        resolve_key(spec, &tsig_keys, "--secondary")?;
    }
    for spec in catalog_specs.iter() {
        resolve_key(spec, &tsig_keys, "--catalog")?;
    }
    secondary_specs.extend(catalog_specs.iter().cloned());

    // The outgoing XoT identity and anchors, here so `--check-config` reaches
    // them. Both or neither: `Config::check` says so for the file.
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
        Some(path) => Some(TlsClientTrust::from_ca_file(path, transfer_identity)?),
        None => None,
    };
    // The outgoing half of RFC 9103: anchor count and whether a client
    // certificate is held, which is all this end can claim about mTLS.
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
    // The incoming half of §7.5: which client may take which zone, refused
    // without a listener to arrive on (`CLAUDE.md` §15).
    let transfer_clients = TransferCertificates::parse(&cli.allow_transfer_cert)?;
    if cli.transfer_client_ca.is_some() && encrypted.is_none() {
        return Err(anyhow!(
            "--transfer-client-ca asks transfer clients for a certificate, and \
             there is no encrypted listener for one to arrive on: add \
             --tls-listen, --quic-listen or --https-listen"
        ));
    }
    if let Some(anchors) = encrypted.as_ref().and_then(Encrypted::clients) {
        // Printed: an unscoped rule transfers everything (`CLAUDE.md` §14,
        // §16).
        tracing::info!(
            "zone transfers accepted over mTLS: {} trust anchor(s), {} client(s) listed",
            anchors.len(),
            transfer_clients.listed().len()
        );
        for client in transfer_clients.listed() {
            tracing::info!(
                "  transfer certificate {} may transfer {}",
                client.name(),
                match client.scope() {
                    Some(zones) => zones.join(", "),
                    None => "every zone (no zone list)".to_string(),
                }
            );
        }
        if transfer_clients.is_empty() {
            tracing::warn!(
                "--transfer-client-ca names anchors and --allow-transfer-cert names \
                 nobody, so a verified client certificate authorizes nothing"
            );
        }
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
    let mut signing = ZoneSigning::load(&cli, &per_zone.signing)?;
    // Before the first signing run: unknown is hold, so a retiring key signs
    // until the parent has been asked.
    let parental_agents = parental::parse_agents(&cli.parental_agent, &tsig_keys, xot.as_ref())?;
    let gated: Vec<Name> = parental_agents.keys().cloned().collect();
    let parental = parental::ParentalGate::new(parental_agents, |origin| {
        signing
            .as_ref()
            .and_then(|s| s.keys_for(origin))
            .map(|keys| keys.iter().collect())
    })?;
    if let Some(signing) = &mut signing {
        signing.gate(&gated);
    }
    let signing = signing.map(Arc::new);
    let source = if per_zone.files.is_empty() {
        validate_zone_source(cli.zone_file, cli.zone_dir, replicating)?
    } else {
        // Zones naming their own files; `Config::apply` and `Config::check`
        // refused the combinations that cannot work.
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
    // Blocking on this thread: nothing is bound yet. Nothing can be kept; the
    // pass records digests so the first SIGHUP skips untouched files.
    let files = LoadedFiles::default();
    let nothing = ZoneMap::new();
    let proved = ProvenSigning::default();
    let signed_at = rdns::clock::current_unix_timestamp();
    let mut zones = load_zones(
        &source,
        replicating,
        cli.allow_partial_load,
        Some(&Keepable {
            files: &files,
            served: &nothing,
            signing: signing.as_deref(),
            proved: &proved,
            signed_at,
        }),
    )?
    .zones;

    // Verify what was just signed, so a canonicalization bug is caught here,
    // not at every validator.
    let run = match &signing {
        // Startup: nothing is being served, so there is nothing to carry
        // forward from (`ZoneSigning::apply`).
        Some(signing) => signing.apply(&mut zones, None)?,
        None => SigningRun::default(),
    };
    let mut validator = DnssecValidator::new(cli.require_signed || signing.is_some());
    validator.set_require_signed(cli.require_signed);
    let validator = Arc::new(validator);
    // `proved` was empty above, so this pass checks everything; what it proves is
    // what the reload path may then skip.
    verify_zones(&zones, &validator, &run, &proved)?;
    // Before the dry run answers (`TODO.md` #182).
    let generator = match &cli.generate_catalog {
        Some(text) => {
            let name = Name::from_presentation(text)
                .map_err(|e| anyhow!("--generate-catalog {text:?}: {e}"))?;
            if catalog_specs.iter().any(|spec| spec.zone == name) {
                return Err(anyhow!(
                    "--generate-catalog {name}: this server would consume the catalog it \
                     generates; a consumer takes it from somewhere else"
                ));
            }
            let replicated: Vec<&Name> = secondary_specs.iter().map(|s| &s.zone).collect();
            catalog_gen::check_name(
                &name,
                zones
                    .keys()
                    .map(|k| k.as_name())
                    .filter(|z| !replicated.iter().any(|r| r.as_ref() == *z)),
            )?;
            Some(Arc::new(catalog_gen::GeneratedCatalog::new(
                name,
                per_zone
                    .not_in_catalog
                    .iter()
                    .filter_map(|z| Name::from_presentation(z).ok())
                    .collect(),
            )))
        }
        None => None,
    };
    if let Some(origin) = gated
        .iter()
        .find(|o| !zones.keys().any(|k| k.as_name() == o.as_ref()))
    {
        return Err(anyhow!(
            "--parental-agent {origin}@...: no zone {origin} is served here"
        ));
    }

    // Parsed here, not in `serve`'s arguments, which run below the dry-run exit
    // (`CLAUDE.md` §15).
    let dnstap = match &cli.dnstap {
        Some(spec) => Some((
            spec.parse::<rdns_transport::dnstap::Target>()?,
            cli.dnstap_max_bytes,
        )),
        None => None,
    };

    // The dry run exits here: everything above is knowable without the network,
    // including every zone loaded, signed and verified; what is left binds.
    if cli.check_config {
        // `println!`: the answer goes to stdout for a deploy script, and
        // `--quiet` must not hide it.
        println!(
            "configuration is valid: {} zone(s){}, {} TSIG key(s), signing {}, listening on {}, \
             encrypted transports {}, NSID {}",
            zones.len(),
            // Said because members are not in the count: they arrive with the
            // catalog.
            match catalog_specs.len() {
                0 => String::new(),
                n => format!(", {n} catalog(s) to consume"),
            },
            cli.tsig_key.len(),
            match &signing {
                Some(s) => format!("{} zone(s)", s.signed_zone_count(&zones)),
                None => "disabled".to_string(),
            },
            // What the bind will make of the address, since nothing is bound
            // here (`TODO.md` #159).
            {
                let addr = format!("{}:{}", cli.host, cli.port);
                bind::planned(&addr).unwrap_or(addr)
            },
            // Named because the certificate was read and checked above, so the
            // dry run says it did (`CLAUDE.md` §15).
            match &encrypted {
                None => "disabled".to_string(),
                Some(encrypted) => format!("on {}, certificate loads", encrypted.listeners()),
            },
            match nsid {
                Some(nsid) => rdns::config::show_nsid(nsid),
                None => "off (--nsid)".to_string(),
            }
        );
        return Ok(());
    }

    note_serials(&metrics, &zones);
    let zone_map = Arc::new(RwLock::new(Zones::new(zones)));
    // Empty at startup: no previous version exists in this process, so an
    // increment across a restart is a full transfer (RFC 1995 §4).
    let deltas = Arc::new(RwLock::new(DeltaLog::new()));
    // The journal persists the steps across restarts, with a directory source
    // only: `--zone-file` gives no directory to write into.
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
        // A separate walk for a separate question: journals that are no zone's
        // (`CLAUDE.md` §4).
        discard_orphan_journals(journal, &zone_map).await;
    }
    let addr = format!("{}:{}", cli.host, cli.port);

    // Before anything is served: a replicated copy past its EXPIRE is not ours
    // to answer for.
    let mut reload_zone_dir: Option<PathBuf> = None;
    // Filled in below for a secondary. A primary is ready once alive: every
    // zone loaded, signed and verified, or the start failed.
    let mut readiness = Readiness::ready();
    let secondaries = Arc::new(Secondaries::default());
    // Hoisted so the control socket can report catalogs; without `--secondary`
    // or `--catalog` it stays the empty consumer.
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

        // What we answer for but do not hold, asked after the withdrawal above
        // and built before the refresh tasks can report an arrival.
        readiness = {
            let zones = zone_map.read().await;
            Readiness::waiting_for(
                secondary_specs
                    .iter()
                    .filter(|spec| zones.matching(spec.zone.as_ref()).is_none())
                    .map(|spec| spec.zone.as_ref().to_presentation()),
            )
        };

        // What a catalog may not take over (RFC 9432 §5.2): configured zones
        // and zones on disk no catalog claims.
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
            clock: Clock::system(),
        };
        // Before the tasks and serving: members from a previous run are on
        // disk, and their tasks start only once their catalog is reconciled.
        catalogs.vouch_for_members(&replication).await;

        spawn_secondaries(
            secondary_specs,
            &tsig_keys,
            &replication,
            &shutdown.lifecycle(),
            &secondaries,
        )?;

        // The members of every catalog held. A reload does not repeat this: the
        // refresh task reconciles what each transfer installs.
        for zone in catalogs.zones() {
            catalogs
                .reconcile(zone.as_ref(), &replication, &shutdown.lifecycle())
                .await;
        }
    }

    // After the secondaries and catalog members are registered, so none of
    // them is listed as ours (`TODO.md` #182).
    if let Some(generator) = &generator {
        let zone = {
            let zones = zone_map.read().await;
            generator.build(
                zones.keys().map(|k| k.as_name()),
                |z| secondaries.replicates(z),
                rdns::clock::current_unix_timestamp(),
            )?
        };
        crate::zones::install_zone(&served, zone).await;
    }

    // A zone that has just been loaded is news to every secondary, which is why
    // this runs at startup and not only on reload.
    let announced = notify_out::announce_zones(&zone_map, &[], &notify, &shutdown.busy()).await;

    // Taken before `source` and `signing` move into the maintenance task: an
    // UPDATE must read and sign exactly as a reload does.
    let updates = UpdateHandling::new(source.clone(), signing.clone(), Arc::clone(&validator));

    let udp = UdpSizes::new(cli.udp_payload_size, cli.max_udp_response);

    // Reload and re-sign in one loop; the sender it returns is how
    // `rdnsctl reload` reaches it.
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
                files,
                catalog: generator.clone(),
            },
            source,
            served: served.clone(),
            notify,
            tls: encrypted.as_ref().map(Encrypted::store),
        },
        announced,
        shutdown.lifecycle(),
    );
    if !parental.is_empty() {
        let reloads = reloads.clone();
        tokio::spawn(parental::run(
            parental.clone(),
            parental::Network,
            rdns::clock::Clock::system(),
            // `try_send`: a reload already queued re-signs with the key let go.
            move || {
                let _ = reloads.try_send(ReloadTrigger::ParentDs);
            },
            shutdown.stop_handle(),
        ));
    }

    serve(
        &addr,
        zone_map,
        ServePolicy {
            generated_catalog: generator.as_ref().map(|g| g.name().clone()),
            transfer_acl,
            transfer_clients,
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
            connections: TransportLimits::configured(
                cli.max_connections,
                cli.connection_idle_timeout,
            ),
            per_source,
            nsid,
            metrics_listen: cli.metrics_listen,
            tls: encrypted,
            readiness,
            updates,
            journal,
            dnstap,
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
                parental,
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

    let ksk = write_key_pair(dir, |flags| SigningKey::generate(algorithm, &zone, flags))?;

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
    // CDS polling (RFC 7344) needs no paste but a key-file field; said here,
    // the command run before a rollover (`CLAUDE.md` §14).
    println!(
        "\nFor a parent that polls CDS/CDNSKEY instead (RFC 7344), add\n\
         \n    SyncPublish: <unix seconds>\n\
         \nto {} and reload. The records appear at the apex, signed by the \
         KSK, and go away again at an optional SyncDelete.",
        ksk.file_name()
    );
    Ok(())
}

/// A KSK and a ZSK out of `generate`, which is given the flags, written into
/// `dir`. Returns the KSK, for its DS.
///
/// Distinct from every key already there as well as from each other: the file
/// name is the tag, and a rollover generates beside the live keys (`TODO.md`
/// #125). `generate` is a parameter so a test can hand it a colliding key.
fn write_key_pair(
    dir: &Path,
    mut generate: impl FnMut(u16) -> rdns::error::DnssecResult<SigningKey>,
) -> Result<SigningKey> {
    let existing = SigningKey::load_dir(dir)?;
    let mut others: Vec<&SigningKey> = existing.iter().collect();
    let ksk = SigningKey::distinct_from(&others, || generate(DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP))?;
    others.push(&ksk);
    let zsk = SigningKey::distinct_from(&others, || generate(DNSKEY_FLAG_ZONE))?;
    let pair = [&ksk, &zsk];
    let written: Result<Vec<PathBuf>, _> = pair.iter().map(|key| key.write_to_dir(dir)).collect();
    let written = match written {
        Ok(written) => written,
        // All or nothing: a key left behind has no timing and would publish and
        // sign.
        Err(e) => return Err(remove_key_pair(dir, pair, e.into())),
    };
    for path in written {
        // Stdout, as for `--check-config`: the DS record is output to paste.
        println!("Wrote {}", path.display());
    }
    Ok(ksk)
}

/// `err`, after removing whatever of `pair` reached `dir`, with each key that
/// could not be removed named in it.
fn remove_key_pair(dir: &Path, pair: [&SigningKey; 2], mut err: anyhow::Error) -> anyhow::Error {
    for key in pair {
        if let Err(e) = key.remove_from_dir(dir) {
            err = err.context(format!(
                "{} is left in {} and must be removed by hand, or the server signs with it \
                 ({e})",
                key.file_name(),
                dir.display()
            ));
        }
    }
    err
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{
        answered, nm, query, served, server_with, server_with_keys, server_with_keys_at,
        test_shutdown, update_key, update_message, zkey, ScratchDir,
    };
    use crate::zones::zone_key;
    use rdns::secondary::{MasterSpec, TransferState};
    use rdns::tsig::{TsigAlgorithm, TsigKey};
    use rdns::validation::Arrival;
    use rdns::zone_signer::{sign_zone, DenialChain, SigningPolicy};
    use rdns::{clock::current_unix_timestamp, tsig, zone::Zone, DnsMessage, ResourceRecord};
    use rdns::{record_types, Qtype, ResponseCode, Ttl};
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::net::{IpAddr, SocketAddr};

    /// A new key colliding with one in the directory, or with the run's own
    /// KSK, is generated again rather than written over it (`TODO.md` #125).
    /// The collisions are copies of one key: the only colliding pair `rdnsd`
    /// can make without `rdns`'s stored fixtures. The ZSK's is a copy of the
    /// KSK, SEP flag and all, since only an identical tag collides.
    #[test]
    fn a_new_key_pair_differs_from_the_directory_and_from_itself() {
        let key = |flags| {
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, "example.com.", flags)
                .expect("a key")
        };
        let dir = ScratchDir::new("key-pair");
        let live = key(DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP);
        live.write_to_dir(dir.path()).expect("the live key");

        let copies = ScratchDir::new("key-pair-copies");
        let ksk = key(DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP);
        live.write_to_dir(copies.path()).expect("write");
        ksk.write_to_dir(copies.path()).expect("write");
        let (mut live_copy, mut ksk_copy): (Vec<_>, Vec<_>) = SigningKey::load_dir(copies.path())
            .expect("load")
            .into_iter()
            .partition(|k| k.dnskey_public_key() == live.dnskey_public_key());
        let (live_copy, ksk_copy) = (live_copy.pop().expect("live"), ksk_copy.pop().expect("ksk"));
        let zsk = key(DNSKEY_FLAG_ZONE);
        let (ksk_public, zsk_public) = (
            ksk.dnskey_public_key().to_vec(),
            zsk.dnskey_public_key().to_vec(),
        );
        let mut candidates = vec![zsk, ksk_copy, ksk, live_copy];

        let written = write_key_pair(dir.path(), |_| Ok(candidates.pop().expect("a candidate")))
            .expect("both copies refused, both others written");

        assert!(candidates.is_empty(), "all four were drawn");
        assert_eq!(written.dnskey_public_key(), ksk_public);
        let mut on_disk: Vec<Vec<u8>> = SigningKey::load_dir(dir.path())
            .expect("load")
            .iter()
            .map(|k| k.dnskey_public_key().to_vec())
            .collect();
        let mut expected = vec![live.dnskey_public_key().to_vec(), ksk_public, zsk_public];
        on_disk.sort();
        expected.sort();
        assert_eq!(on_disk, expected);
    }

    /// A ZSK that cannot be written takes the KSK written before it back out,
    /// and leaves the file that stopped it. The generator takes the ZSK's name
    /// after `load_dir` has looked, as a second writer would.
    #[test]
    fn a_key_pair_that_fails_halfway_leaves_nothing_behind() {
        let dir = ScratchDir::new("key-pair-halfway");
        let mut drawn = 0;
        let err = write_key_pair(dir.path(), |flags| {
            let key =
                SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, "example.com.", flags)?;
            drawn += 1;
            if drawn == 2 {
                dir.write(&key.file_name(), "another writer's\n");
            }
            Ok(key)
        })
        .expect_err("the ZSK's name is taken");

        assert_eq!(drawn, 2);
        let entries = dir.entries();
        assert_eq!(entries.len(), 1, "the KSK is gone: {entries:?}");
        let planted = std::fs::read_to_string(dir.join(&entries[0])).expect("read");
        assert_eq!(planted, "another writer's\n", "{err:#}");
    }

    /// Reading the directory first means a directory the server would refuse
    /// is refused here, before anything is written.
    #[test]
    fn a_key_pair_is_not_written_beside_a_broken_key() {
        let dir = ScratchDir::new("key-pair-broken");
        rdns::persist::create_atomically_private(
            &dir.join("broken.rdnskey"),
            "Owner: example.com.\n",
        )
        .expect("write");

        let err = write_key_pair(dir.path(), |flags| {
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, "example.com.", flags)
        })
        .expect_err("the directory does not load");

        assert!(format!("{err:#}").contains("broken.rdnskey"), "{err:#}");
        assert_eq!(dir.entries(), vec!["broken.rdnskey".to_string()]);
    }

    /// A suppressed log line must not build its message: `tracing`'s macros
    /// evaluate nothing without a subscriber, and `bad_request!` wraps one.
    ///
    /// Counted all the same, or `total_errors` means "errors we logged".
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
        let ip = Peer::from(
            "198.51.100.7"
                .parse::<IpAddr>()
                .expect("a documentation address"),
        );
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
        // `port` is a `u16`; this pins the maximum.
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
            use std::fmt::Write as _;
            let mut text = String::from(
                "$ORIGIN example.com.\n\
                 $TTL 3600\n\
                 @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                 @   IN NS  ns1.example.com.\n\
                 ns1 IN A   192.0.2.1\n",
            );
            for i in 0..count {
                let _ = writeln!(text, "pool IN A 198.51.100.{}", i % 254 + 1);
            }
            rdns::zone::parse_zone_file(&text, "example.com.").expect("the zone parses")
        }

        /// The client's EDNS advertisement is a ceiling this server may lower,
        /// not one it has to honour.
        ///
        /// At 65,535 a large answer leaves as IP fragments, which
        /// `max-udp-size` in other servers prevents. Fails with the reply
        /// whole, over 1232, TC clear. TCP is answered in full.
        #[tokio::test]
        async fn a_udp_reply_is_capped_by_this_server_and_not_only_by_the_client() {
            let server = server_with(pool_zone(128));
            let cap = server.ctx().udp.max_response() as usize;
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

        /// The TSIG comes out of the reply's ceiling, not on top of it.
        ///
        /// Otherwise the datagram leaves at the cap plus the record; RFC 8945
        /// §5.3 says to alter the response instead. The first assertion holds
        /// the zone in the window where it matters (`CLAUDE.md` §1). Fails
        /// unreserved: 1,250 octets out of a 1,232 cap, TC clear.
        #[tokio::test]
        async fn a_signed_reply_reserves_its_signature_out_of_the_ceiling() {
            let key = TsigKey::new("transfer.key.", TsigAlgorithm::HmacSha256, vec![0x0b; 32]);
            let server = server_with_keys(pool_zone(70), vec![key.clone()]);
            let cap = server.ctx().udp.max_response() as usize;
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

            // Off the wire: signing builds its own message, so the sent bytes
            // are what counts.
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
                    rdns::tsig::check_request(&probe, server.tsig_keys(), tsig::now())
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

        /// A transfer asked for over UDP is not streamed, by a branch rather
        /// than a position.
        ///
        /// AXFR is FORMERR (RFC 5936 §4.2), IXFR a single SOA (RFC 1995 §2).
        /// Fails without the `Wire::Framed` guard: the zone streams into the
        /// datagram path.
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
        /// `dns_queries_received_total` says "received" (`CLAUDE.md` §14). Both
        /// transports, as the claim is that they agree. Fails with the UDP
        /// count after the check.
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
                    server
                        .ctx()
                        .metrics
                        .queries_received
                        .load(Ordering::Relaxed),
                    1,
                    "{transport} did not count a TSIG-rejected request as received"
                );
                assert_eq!(
                    server.ctx().metrics.queries_type_a.load(Ordering::Relaxed),
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

        /// The UDP loop's instant is `ServeContext`'s, not the wall clock's.
        ///
        /// TSIG compares the server's instant with the client's within a
        /// 300-second fudge (RFC 8945 §5.2.3), so signing far outside it shows
        /// which clock the loop reads. Fails with `let now = tsig::now()`:
        /// `NotAuthorized`.
        #[tokio::test]
        async fn the_udp_loop_signs_and_checks_against_the_context_clock() {
            // 2023-11-14, far past any fudge from the real now, and fixed so
            // this test reads the same in 2030.
            const WHEN: u64 = 1_700_000_000;
            let key = TsigKey::new("udp.key.", TsigAlgorithm::HmacSha256, vec![0x5c; 32]);
            let server =
                server_with_keys_at(one_record_zone(), vec![key.clone()], Clock::fixed(WHEN));

            let shutdown = Shutdown::new();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
            let server_addr = socket.local_addr().expect("addr");
            let worker = tokio::spawn(udp_loop(
                socket,
                server,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));

            let signed = rdns::tsig::sign_request(a_query(), &key, WHEN).expect("sign");
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
            client.send_to(&signed, server_addr).await.expect("send");
            let mut buf = vec![0u8; 4096];
            let (n, _) = client.recv_from(&mut buf).await.expect("an answer");
            let reply = DnsMessage::try_from_bytes(&buf[..n]).expect("a parseable answer");

            assert_eq!(
                reply.rcode,
                ResponseCode::Ok,
                "NOTAUTH: the loop checked the TSIG against the wall clock, not `ctx.clock`"
            );
            assert_eq!(reply.answers.len(), 1, "the A record for www");

            shutdown.begin();
            worker
                .await
                .expect("the worker joins")
                .expect("no io error");
        }

        /// A response sent to the UDP port must not be answered (`CLAUDE.md`
        /// §8): two servers pointed at each other would loop. Both paths refuse
        /// QR=1 in `rdns::validation::Request`; this states the behaviour.
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

        /// The response buffer is the worker's, not the datagram's. On pointer
        /// and capacity, which are exact (`CLAUDE.md` §10). Fails if
        /// `answer_datagram` allocates per answer.
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

    /// An UPDATE reaches the zone file, not just the zone map: the re-signing
    /// timer reloads from files, so a change in memory alone is lost.
    ///
    /// A signed DKIM-sized UPDATE over 512 octets is admitted on UDP, as the
    /// OPT advertises 4,096 (RFC 6891 §6.2.4; `TODO.md` #40f). Fails with
    /// `max_udp_size` at 512: the signed message is refused.
    #[test]
    fn a_signed_dkim_sized_update_is_admitted_on_udp() {
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let dkim = format!("v=DKIM1; k=rsa; p={}", "A".repeat(392));
        let txt = ResourceRecord {
            name: nm("s2026._domainkey.example.com."),
            class: rdns::Class::IN,
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

    // Loading a directory of zones: three questions, three answers

    /// IPv4 clients of a dual-stack `[::]` socket arrive as `::ffff:a.b.c.d`
    /// (`TODO.md` #158). Each socket is built with `IPV6_V6ONLY` 0 rather than
    /// taken from the OS default, which is 0 on Linux and 1 on Windows, so
    /// these run the same on both (`CLAUDE.md` §1).
    mod dual_stack {
        use super::*;
        use crate::dispatch::Server;
        use crate::replication::Secondaries;
        use crate::testutil::test_context;
        use rdns::security::{TransferAcl, TransferCertificates};
        use socket2::{Domain, Socket, Type};

        fn dual_stack(kind: Type) -> Socket {
            let socket = Socket::new(Domain::IPV6, kind, None).expect("an IPv6 socket");
            socket.set_only_v6(false).expect("IPV6_V6ONLY 0");
            socket
                .bind(&"[::]:0".parse::<SocketAddr>().expect("an address").into())
                .expect("bind [::]:0");
            socket.set_nonblocking(true).expect("non-blocking");
            socket
        }

        fn port_of(socket: &Socket) -> u16 {
            socket
                .local_addr()
                .expect("bound")
                .as_socket()
                .expect("an inet address")
                .port()
        }

        fn one_record_zone() -> Zone {
            rdns::zone::parse_zone_file(
                "$ORIGIN example.com.\n\
                 $TTL 3600\n\
                 @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                 @   IN NS  ns1.example.com.\n\
                 ns1 IN A   192.0.2.1\n",
                "example.com.",
            )
            .expect("the zone parses")
        }

        fn zone_map(zone: Zone) -> Arc<RwLock<Zones>> {
            let mut zones = HashMap::new();
            zones.insert(zone_key(&zone), Arc::new(zone));
            Arc::new(RwLock::new(Zones::new(zones)))
        }

        /// `--allow-transfer 127.0.0.1`, and a transfer from 127.0.0.1 over
        /// the dual-stack listener gets the zone.
        #[tokio::test]
        async fn an_ipv4_rule_allows_an_ipv4_secondary_on_a_dual_stack_listener() {
            let socket = dual_stack(Type::STREAM);
            let port = port_of(&socket);
            socket.listen(16).expect("listen");
            let listener = tokio::net::TcpListener::from_std(std::net::TcpListener::from(socket))
                .expect("a listener");
            let server = Arc::new(
                Server::new(zone_map(one_record_zone()), test_context()).with_transfers(
                    TransferAcl::parse(&["127.0.0.1".to_string()]).expect("acl"),
                    TransferCertificates::default(),
                    false,
                ),
            );
            let shutdown = Shutdown::new();
            tokio::spawn(tcp::serve(
                listener,
                server,
                TransportLimits::default(),
                tcp::RateLimit::PerMessage,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));

            let master = SocketAddr::from(([127, 0, 0, 1], port));
            let zone = rdns::xfr::fetch_zone(
                &rdns::xfr::Master::plain(master),
                nm("example.com.").as_ref(),
                None,
            )
            .await
            .expect("the IPv4 rule matches the IPv4 client");
            assert_eq!(zone.serial(), Some(rdns::Serial::new(1)));
            shutdown.begin();
        }

        /// A NOTIFY from 127.0.0.1, the master of a zone this server
        /// replicates, over the dual-stack UDP socket: acted on, and the reply
        /// reaches the client — which needs the mapped address, not the
        /// canonical one, as the `send_to` target.
        #[tokio::test]
        async fn a_notify_from_an_ipv4_master_on_a_dual_stack_socket_is_acted_on() {
            let socket = dual_stack(Type::DGRAM);
            let port = port_of(&socket);
            let socket =
                Arc::new(UdpSocket::from_std(std::net::UdpSocket::from(socket)).expect("a socket"));
            let secondaries = Arc::new(Secondaries::replicating(&[MasterSpec {
                zone: nm("example.com."),
                master: "127.0.0.1:53".parse().expect("an address"),
                key_name: None,
                tls: None,
            }]));
            let server = Arc::new(
                Server::new(zone_map(one_record_zone()), test_context())
                    .with_secondaries(secondaries),
            );
            let shutdown = Shutdown::new();
            tokio::spawn(udp_loop(
                socket,
                server,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));

            let notify = rdns::notify::notify_request(nm("example.com.").as_ref(), None, 7)
                .to_bytes_within(512)
                .expect("serialize");
            let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
            client
                .send_to(&notify, SocketAddr::from(([127, 0, 0, 1], port)))
                .await
                .expect("send");
            let mut buf = vec![0u8; 4096];
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
                .await
                .expect("a reply within 5 s")
                .expect("a reply");
            let reply = DnsMessage::try_from_bytes(&buf[..n]).expect("parseable");
            assert_eq!(
                reply.rcode,
                ResponseCode::Ok,
                "REFUSED: the master match compared the mapped address"
            );
            shutdown.begin();
        }
    }

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

        /// Fails if one bad file out of three is a line on stderr, exit code 0,
        /// and that zone answering REFUSED — indistinguishable from a zone
        /// nobody configured. Installing the survivors wholesale defeats
        /// `Reloading::load`'s all-or-nothing invariant: a broken file plus a
        /// deploy SIGHUP takes a *previously working* zone off the air.
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

            let err = load_zones(&source, false, false, None)
                .map(|l| l.zones)
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

            let zones = load_zones(&source, false, true, None)
                .map(|l| l.zones)
                .expect("the flag is an explicit choice to serve a partial set");
            assert_eq!(zones.len(), 1);
            assert!(zones.contains_key(zkey("example.com.").as_slice()));
        }

        /// A secondary's first start has nothing on disk yet, and refusing to
        /// run until a zone arrives would mean it never could.
        ///
        /// The emptiness check is in `load_zones`, the only place that knows
        /// the caller is a secondary.
        #[tokio::test]
        async fn a_secondary_may_start_with_an_empty_zone_directory() {
            let dir = dir_with("empty-secondary", &[]);
            let source = ZoneSource::Directory(dir.path().to_string_lossy().to_string());

            let zones = load_zones(&source, true, false, None)
                .map(|l| l.zones)
                .expect("a secondary starts before its first transfer");
            assert!(zones.is_empty());

            // A primary with an empty --zone-dir is a typo in the path, and
            // serving nothing is not what was asked for.
            assert!(load_zones(&source, false, false, None)
                .map(|l| l.zones)
                .is_err());
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

        /// Expiry that lasts only until the next reload is not expiry: a zone
        /// withdrawn for EXPIRE must not come back on SIGHUP with AA set.
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

        /// The other half: no record of contact at all. `StateFile::load`
        /// returns empty, so unknown age must read as "do not serve" until a
        /// transfer.
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

        /// A sidecar entry for a master no longer configured for the zone is
        /// not evidence about it, and lands in the same place. One configured
        /// master in contact does vouch (`TODO.md` #131).
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

        /// A directory that cannot be read is fatal either way, and
        /// `--allow-partial-load` must not weaken it. "Some files failed to
        /// parse" and "the directory is not there" are different questions, and
        /// only the first one has a flag.
        #[tokio::test]
        async fn an_unreadable_directory_is_fatal_even_with_partial_load() {
            let missing = ZoneSource::Directory("no-such-directory-anywhere".to_string());
            for allow_partial in [false, true] {
                assert!(
                    load_zones(&missing, true, allow_partial, None)
                        .map(|l| l.zones)
                        .is_err(),
                    "allow_partial={allow_partial}: an I/O error is not a parse failure"
                );
            }
        }

        /// A reload must not take the runtime worker with it: every load step
        /// blocks, with listeners live.
        ///
        /// One worker, so a blocked load polls the ticker never. The load is in
        /// a spawned task: `#[tokio::test]`'s body runs on the calling thread.
        #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
        async fn a_reload_does_not_block_the_runtime_it_was_called_from() {
            use std::fmt::Write as _;
            // Enough parsing to take real time — the point is that whatever it
            // costs, it is not charged to the runtime.
            let mut records = String::new();
            for i in 0..4000 {
                let _ = writeln!(records, "h{i} IN A 10.{}.{}.1", i / 256, i % 256);
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
                files: LoadedFiles::default(),
                catalog: None,
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

            // Announced, then loading, so the count spans the load and not the
            // scheduling before it.
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

    /// A reload keeps the signatures it can, and the re-signing timer does not.
    ///
    /// A full sign per reload costs time and puts every RRSIG in the next IXFR
    /// (`TODO.md` #65b); the timer reloads to refresh. Told apart by
    /// expiration, 30 days served against 7 reloaded, not by ECDSA's random
    /// bytes.
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
                files: LoadedFiles::default(),
                catalog: None,
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
        // The apex SOA too: the served serial adds an hours term, so two runs
        // in one hour agree.
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

    /// A zone directory holding one unsigned zone, and a `ReloadContext` over
    /// it serving into `zone_map`. `signing` as the caller has it.
    fn maintained(
        dir: &ScratchDir,
        zone_map: &Arc<RwLock<Zones>>,
        signing: Option<ZoneSigning>,
    ) -> ReloadContext {
        std::fs::write(
            dir.path().join("example.com.zone"),
            "$TTL 3600\n\
             @ IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n\
             @ IN NS ns.example.com.\n\
             ns IN A 192.0.2.1\n",
        )
        .expect("the zone file");
        ReloadContext {
            reloading: Reloading {
                replicating: false,
                allow_partial: false,
                secondaries: Arc::new(Secondaries::default()),
                zone_dir: None,
                signing: signing.map(Arc::new),
                validator: Arc::new(DnssecValidator::new(false)),
                proved: ProvenSigning::default(),
                files: LoadedFiles::default(),
                catalog: None,
            },
            source: ZoneSource::Directory(dir.path().to_string_lossy().to_string()),
            served: served(zone_map, &Arc::new(RwLock::new(DeltaLog::new()))),
            notify: Arc::new(NotifyPolicy::default()),
            tls: None,
        }
    }

    /// Two requests sent back to back both get an answer — the second waits for
    /// the depth-1 channel's slot rather than being dropped — and a stop ends
    /// the task and lets the drain finish.
    #[tokio::test]
    async fn zone_maintenance_answers_every_control_reload_and_ends_on_stop() {
        let dir = ScratchDir::new("maintenance-control");
        let zone_map = Arc::new(RwLock::new(Zones::default()));
        let shutdown = Shutdown::new();
        let reloads = spawn_zone_maintenance(
            maintained(&dir, &zone_map, None),
            Vec::new(),
            shutdown.lifecycle(),
        );

        let mut replies = Vec::new();
        for _ in 0..2 {
            let (tx, rx) = tokio::sync::oneshot::channel();
            reloads
                .send(ReloadTrigger::Control(tx))
                .await
                .expect("the task is listening");
            replies.push(rx);
        }
        for rx in replies {
            let outcome = tokio::time::timeout(Duration::from_secs(10), rx)
                .await
                .expect("answered in time")
                .expect("answered at all");
            assert_eq!(outcome, Ok(1));
        }
        assert!(zone_map
            .read()
            .await
            .matching(nm("example.com.").as_ref())
            .is_some());

        shutdown.begin();
        assert!(
            shutdown.drain(Duration::from_secs(5)).await,
            "the maintenance task still held its Busy after the stop"
        );
    }

    /// No keys, no timer: a server with nothing to re-sign does not reload on a
    /// schedule nobody asked for. A year of paused time passes and the map
    /// stays as it was.
    #[tokio::test(start_paused = true)]
    async fn an_unsigned_server_never_reloads_on_a_timer() {
        let dir = ScratchDir::new("maintenance-unsigned");
        let zone_map = Arc::new(RwLock::new(Zones::default()));
        let _reloads = spawn_zone_maintenance(
            maintained(&dir, &zone_map, None),
            Vec::new(),
            test_shutdown().lifecycle(),
        );

        tokio::time::sleep(Duration::from_secs(365 * 86_400)).await;
        assert!(
            zone_map
                .read()
                .await
                .matching(nm("example.com.").as_ref())
                .is_none(),
            "a timer reloaded an unsigned server"
        );
    }

    /// A signed server reloads on its re-signing interval with nobody asking.
    /// Paused time: the interval is hours.
    #[tokio::test(start_paused = true)]
    async fn a_signed_server_reloads_on_its_timer() {
        use clap::Parser;
        use rdns::dnssec::DNSKEY_FLAG_ZONE;
        use rdns::dnssec_key::{SigningAlgorithm, SigningKey};

        let dir = ScratchDir::new("maintenance-signed");
        let key_dir = dir.path().join("keys");
        std::fs::create_dir_all(&key_dir).expect("the key directory");
        SigningKey::generate(SigningAlgorithm::Ed25519, "example.com.", DNSKEY_FLAG_ZONE)
            .expect("a key")
            .write_to_dir(&key_dir)
            .expect("the key file");
        let mut cli = Cli::parse_from(["rdnsd"]);
        cli.signing_key_dir = Some(key_dir);
        let signing = ZoneSigning::load(&cli, &BTreeMap::new())
            .expect("the keys load")
            .expect("a key directory means signing");
        let interval = signing.resign_interval().every;

        let zone_map = Arc::new(RwLock::new(Zones::default()));
        let _reloads = spawn_zone_maintenance(
            maintained(&dir, &zone_map, Some(signing)),
            Vec::new(),
            test_shutdown().lifecycle(),
        );

        tokio::time::sleep(interval / 2).await;
        assert!(
            zone_map
                .read()
                .await
                .matching(nm("example.com.").as_ref())
                .is_none(),
            "reloaded before the interval"
        );

        // Auto-advance is held off while the load runs on the blocking pool, so
        // a sleep past the interval wakes after the reload, not during it.
        tokio::time::sleep(interval / 2 + Duration::from_secs(1)).await;
        assert!(
            zone_map
                .read()
                .await
                .matching(nm("example.com.").as_ref())
                .is_some(),
            "no reload within one re-signing interval"
        );
    }

    /// What a reload costs when no zone file moved (`TODO.md` #64f).
    ///
    /// `#[ignore]`d and refused in debug, like the update benchmarks it shares
    /// `one_at_a_time` with: it builds signed zones of up to a million records.
    ///
    /// ```sh
    /// cargo test -p rdnsd --release reload_cost -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore]
    fn reload_cost_against_zone_size() {
        use crate::dispatch::tests::{one_at_a_time, zone_text};
        use rdns::dnssec::DNSKEY_FLAG_ZONE;
        use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
        use std::time::Instant;

        let _turn = one_at_a_time();
        if cfg!(debug_assertions) {
            panic!(
                "this would measure the debug build. Run:
                   cargo test -p rdnsd --release reload_cost -- --ignored --nocapture"
            );
        }

        const ZONE: &str = "example.com.";
        let dir = rdns::testutil::ScratchDir::new("reload-cost");
        let key_dir = dir.path().join("keys");
        std::fs::create_dir_all(&key_dir).expect("the key directory");
        let key = SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, ZONE, DNSKEY_FLAG_ZONE)
            .expect("a key");
        key.write_to_dir(&key_dir).expect("the key file");
        let zone_dir = dir.path().join("zones");
        std::fs::create_dir_all(&zone_dir).expect("the zone directory");

        let mut cli = <Cli as clap::Parser>::parse_from(["rdnsd"]);
        cli.signing_key_dir = Some(key_dir);
        let signing = Arc::new(
            ZoneSigning::load(&cli, &BTreeMap::new())
                .expect("the keys load")
                .expect("a key directory means signing"),
        );
        let reloading = Reloading {
            replicating: false,
            allow_partial: false,
            secondaries: Arc::new(Secondaries::default()),
            zone_dir: None,
            signing: Some(signing.clone()),
            validator: Arc::new(DnssecValidator::new(true)),
            proved: ProvenSigning::default(),
            files: LoadedFiles::default(),
            catalog: None,
        };
        let source = ZoneSource::Directory(zone_dir.to_string_lossy().to_string());

        println!("{:>9}  {:>12} {:>12}", "records", "first", "unchanged");
        for records in [10_000usize, 100_000, 1_000_000] {
            std::fs::write(zone_dir.join("example.com.zone"), zone_text(records))
                .expect("the fixture");

            // The first load is what startup does: nothing served to carry from.
            let start = Instant::now();
            let served = reloading
                .load_blocking(&source, None)
                .expect("the first load");
            let first = start.elapsed();

            // And this is a SIGHUP against a directory nobody touched.
            let start = Instant::now();
            let again = reloading
                .load_blocking(&source, Some(&served))
                .expect("the reload");
            let unchanged = start.elapsed();
            assert_eq!(again.len(), 1);

            println!("{records:>9}  {:>10.1?} {:>10.1?}", first, unchanged);
        }
    }

    /// The generated catalog through the reload path (`TODO.md` #182): a
    /// new file is a new member, a removed one is gone, and a directory that
    /// cannot be read fails the reload rather than publishing an empty
    /// catalog — so the one being served keeps its members.
    #[tokio::test]
    async fn a_reload_rebuilds_the_generated_catalog_all_or_nothing() {
        let dir = ScratchDir::new("generated-catalog");
        let write = |zone: &str| {
            std::fs::write(
                dir.join(format!("{zone}.zone")),
                format!(
                    "@ IN SOA ns1.{zone} admin.{zone} 1 3600 600 604800 300\n@ IN NS ns1.{zone}\n"
                ),
            )
            .expect("write");
        };
        for zone in ["a.test.", "b.test.", "c.test."] {
            write(zone);
        }
        let generator = Arc::new(crate::catalog_gen::GeneratedCatalog::new(
            nm("catalog.invalid."),
            std::collections::HashSet::new(),
        ));
        let reloading = Reloading {
            replicating: false,
            allow_partial: false,
            secondaries: Arc::new(Secondaries::default()),
            zone_dir: Some(dir.path().to_path_buf()),
            signing: None,
            validator: Arc::new(DnssecValidator::new(false)),
            proved: ProvenSigning::default(),
            files: LoadedFiles::default(),
            catalog: Some(generator),
        };
        let source = ZoneSource::Directory(dir.path().to_string_lossy().to_string());
        let members = |zones: &ZoneMap| {
            let catalog = zones
                .values()
                .find(|z| z.origin() == nm("catalog.invalid.").as_ref())
                .expect("the catalog is in the set");
            let mut m: Vec<String> = rdns::catalog::Catalog::from_zone(catalog)
                .expect("well formed")
                .members()
                .iter()
                .map(|m| m.zone().to_string())
                .collect();
            m.sort();
            (m, catalog.serial().expect("a serial"))
        };

        let (three, first) = members(&reloading.load(&source, None).await.expect("loads"));
        assert_eq!(three, ["a.test.", "b.test.", "c.test."]);
        write("d.test.");
        let (four, second) = members(&reloading.load(&source, None).await.expect("loads"));
        assert_eq!(four.len(), 4);
        assert!(second.is_newer_than(first));
        std::fs::remove_file(dir.join("b.test..zone")).expect("remove");
        let (fewer, _) = members(&reloading.load(&source, None).await.expect("loads"));
        assert_eq!(fewer, ["a.test.", "c.test.", "d.test."]);

        let gone = ZoneSource::Directory(dir.join("no-such-dir").to_string_lossy().to_string());
        assert!(
            reloading.load(&gone, None).await.is_err(),
            "an unreadable directory fails the reload; nothing new is installed"
        );
    }
}
