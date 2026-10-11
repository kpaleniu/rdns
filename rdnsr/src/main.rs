//! `rdnsr` — the recursive resolver: UDP and TCP on one port, bound to
//! localhost by default, because an open resolver is somebody else's
//! amplifier.
//!
//! This root is the CLI and the startup order, and nothing else: the four
//! modules under it are [`anchors`] (the trust anchors and RFC 5011's rolling),
//! [`answer`] (a datagram in, the reply out — no sockets), [`reload`] (re-reading
//! the certificate and the policy feeds, off the worker threads) and [`serve`]
//! (the two socket loops and the shutdown). One `Resolver` with a mode rather
//! than two programs; the reasoning is `docs/architecture/resolver.md`.

// `TODO.md` #82b's ratchet; the reason is at the top of `rdns/src/lib.rs`.
#![warn(unreachable_pub)]
// `push_str(&format!(..))` allocates a `String` to copy it; `write!` into the
// target does not. Off by default (restriction group).
#![warn(clippy::format_push_string)]

#[cfg(test)]
mod allocations;
mod anchors;
mod answer;
mod caches;
mod config;
mod control;
#[cfg(test)]
mod flood;
mod inflight;
mod nta;
mod prefetch;
mod reload;
mod routes;
mod rpz_transfer;
mod serve;
mod tap;
#[cfg(test)]
mod testutil;

/// Allocator calls tallied per thread, for [`allocations`]. `System`, not dhat:
/// nothing here reads peak bytes, and the profiler is the part that is global
/// (`TODO.md` #88).
#[cfg(test)]
#[global_allocator]
static ALLOC: rdns::testutil::Counting<std::alloc::System> =
    rdns::testutil::Counting(std::alloc::System);

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use clap::Parser;
use rdns::cache::StalePolicy;
use rdns::clock::current_unix_timestamp;
use rdns::dns64::{Dns64, Nat64Prefix};
use rdns::dnssec_chain::TrustAnchors;
use rdns::logging::{watch_anomalies, AnomalyThresholds, QueryLogger};
use rdns::metrics::DnsMetrics;
use rdns::resolver::{Resolver, ResolverConfig, SharedAnchors};
use rdns::rfc5011::ManagedAnchors;
use rdns::rpz::{Feed, PolicyStore};
use rdns::security::{RateLimitConfig, RateLimiter, ResponseLimiter, TransferAcl};
use rdns::shutdown::Shutdown;
use rdns::validation::{AdmissionCheck, AdmissionLimits};
use rdns::UdpSizes;
use rdns_transport::bind;
use rdns_transport::encrypted::{Encrypted, EncryptedFlags, EncryptedListeners};
use rdns_transport::logging::LogLevel;
use rdns_transport::metrics_server;
use rdns_transport::readiness::Readiness;
use rdns_transport::{tcp, QueryAcl, ServeContext, SourceConnections, TransportLimits};
use tokio::task::JoinSet;

use crate::anchors::spawn_anchor_manager;
use crate::answer::{log_policy, NotifyAcl, Resolving};
use crate::caches::Caches;
use crate::reload::PolicyReload;
use crate::rpz_transfer::{refresh_task, FeedWake, TransferredFeed};
use crate::serve::udp_main;

/// UDP queries this resolver will have in flight at once, by default.
///
/// A task per datagram, unlike `rdnsd`'s workers: a recursion is seconds of
/// waiting. 1024 tasks cost ~1.5 MB, and a thousand outstanding queries is load
/// or an attack; shedding answers both.
const MAX_INFLIGHT_UDP: usize = 1024;

/// Zones whose validated denial proofs we keep for aggressive use (RFC 8198).
///
/// Zones, not records: one zone's NSEC chain answers for every non-existent
/// name in it. `NsecCache` bounds the records within each zone separately.
const NSEC_CACHE_ZONES: usize = 1000;

// Defaults in one place, which `Cli` and the config file both take; in the
// crate root, so `config` sees them (`CLAUDE.md` §17).

fn default_host() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    53
}
fn default_cache_size() -> usize {
    10_000
}
fn default_max_inflight_udp() -> usize {
    MAX_INFLIGHT_UDP
}
fn default_prefetch_workers() -> usize {
    16
}
fn default_prefetch_queue() -> usize {
    256
}
fn default_query_rate() -> u32 {
    200
}
fn default_query_burst() -> u32 {
    100
}
fn default_response_rate() -> u32 {
    8192
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
fn default_dnstap_max_bytes() -> u64 {
    1_073_741_824
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
fn default_serve_stale() -> u64 {
    0
}
fn default_resolution_timer() -> u64 {
    rdns::resolver::ResolutionTimer::DEFAULT
        .duration()
        .as_secs()
}
fn default_rpz_policy() -> rdns::rpz::PolicyOverride {
    rdns::rpz::PolicyOverride::Given
}

/// Recursive DNS resolver with caching.
///
/// Resolves from the root, caching what it learns; `--upstream` forwards every
/// name instead, as BIND's global `forwarders`. Binds to localhost by default
/// so it is not an open resolver.
#[derive(Parser)]
#[command(version = rdns::VERSION, about, long_about = None)]
// The two uses of the refresh pool: its sizes mean something with either.
// `multiple`, because clap's default makes a group's members conflict.
#[command(group(clap::ArgGroup::new("refreshing").multiple(true)))]
struct Cli {
    /// Address to listen on. Defaults to localhost to avoid an open resolver;
    /// anything else needs `--allow-query`.
    ///
    /// `::` serves IPv4 and IPv6 on every platform; a specific IPv6 address,
    /// such as `::1`, serves IPv6 only.
    #[arg(long, default_value_t = default_host(), conflicts_with = "config")]
    host: String,
    #[arg(long, default_value_t = default_port(), conflicts_with = "config")]
    port: u16,
    /// An address or CIDR prefix that may be answered, repeatable; anyone else
    /// gets REFUSED over UDP and a closed stream. Required once a listener
    /// binds off loopback; an open resolver is `0.0.0.0/0` and `::/0`. Once
    /// given, only what it lists is answered, loopback included
    /// (`docs/adr/0007`).
    #[arg(long, value_name = "ADDR|CIDR", conflicts_with = "config")]
    allow_query: Vec<String>,
    /// Forward to this resolver instead of recursing, for every name, e.g.
    /// 8.8.8.8:53 (repeatable). `ADDR[:PORT][+tls=NAME]`: with `+tls=`, DNS
    /// over TLS only (RFC 7858), port 853 by default, the certificate checked
    /// against NAME and --upstream-tls-ca; never in clear.
    #[arg(long, conflicts_with = "config")]
    upstream: Vec<String>,
    /// Send one domain to these servers with RD=1: `NAME=ADDR[,ADDR...]`,
    /// `ADDR` as `ip`, `ip:port` or `[v6]:port`. Repeatable. The most specific
    /// covering domain wins over any cached delegation; if its servers fail,
    /// SERVFAIL with EDE 22, never the public tree. Validated unless
    /// `--no-validate-zone` names it.
    #[arg(long, value_name = "NAME=ADDR[,ADDR]", conflicts_with = "config")]
    forward_zone: Vec<String>,
    /// Walk one domain's delegations starting from these servers, with RD=0:
    /// they are its authorities. Same spelling and rules as `--forward-zone`.
    #[arg(long, value_name = "NAME=ADDR[,ADDR]", conflicts_with = "config")]
    stub_zone: Vec<String>,
    /// Answer a domain from a zone file this resolver holds: `NAME=PATH`,
    /// repeatable. AA set, AD never, not cached; a referral inside it is
    /// followed, a CNAME out of it resolved. Re-read on SIGHUP, all or
    /// nothing. Not at or under a special-use name.
    #[arg(long, value_name = "NAME=PATH", conflicts_with = "config")]
    local_zone: Vec<String>,
    /// Answer a routed domain without validating it: `Indeterminate`, AD
    /// clear. For a private domain under a signed public one, which validation
    /// can only call bogus. Repeatable; must name a routed domain.
    #[arg(long, value_name = "NAME", conflicts_with = "config")]
    no_validate_zone: Vec<String>,
    /// Root hints file (named.root format) to prime recursion from, replacing
    /// the built-in list. Refused when `.` is routed — with `--upstream`, or a
    /// forward or stub zone at `.` — since then nothing recurses.
    #[arg(long, conflicts_with = "config")]
    root_hints: Option<std::path::PathBuf>,
    /// Maximum number of cached RRsets.
    #[arg(long, default_value_t = default_cache_size(), conflicts_with = "config")]
    cache_size: usize,
    /// Disable caching entirely.
    #[arg(long, conflicts_with = "config")]
    no_cache: bool,
    /// Ask every upstream for its NSID (RFC 5001) and log which instance
    /// answered: INFO when the instance behind an address changes, DEBUG
    /// otherwise, and beside a validation failure. Off by default, as BIND's
    /// `request-nsid` is. An upstream's NSID never reaches a client.
    #[arg(long, conflicts_with = "config")]
    request_nsid: bool,
    /// Validate DNSSEC on resolved answers: walk the chain of trust from a
    /// trust anchor, set AD only on answers that verify, and refuse to serve
    /// ones that fail (SERVFAIL, unless the client sets CD).
    #[arg(long, conflicts_with = "config")]
    dnssec_validate: bool,
    /// Trust anchors in DS presentation format, replacing the built-in ICANN
    /// root key. Only used with --dnssec-validate.
    ///
    /// A file rather than a rebuild, because the root KSK rolls over and a
    /// binary compiled before the roll is wrong until it is rebuilt.
    #[arg(long, conflicts_with = "config")]
    trust_anchor: Option<std::path::PathBuf>,
    /// A *managed* trust anchor file, followed and rewritten as keys roll (RFC
    /// 5011). Only used with --dnssec-validate.
    ///
    /// Unlike `--trust-anchor`, read and written: a key published 30 days is
    /// adopted, a self-revoked one dropped. Created from the anchors in force
    /// if missing.
    #[arg(long, conflicts_with = "config")]
    auto_trust_anchor: Option<std::path::PathBuf>,
    /// PEM certificate authorities a `+tls=` forwarder's certificate is checked
    /// against; required with any `+tls=` server, refused without one. No
    /// system store is read: point this at the system bundle, e.g.
    /// `/etc/ssl/certs/ca-certificates.crt`; on Windows export the roots to PEM
    /// (`Export-Certificate`, then `certutil -encode`).
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    upstream_tls_ca: Option<PathBuf>,
    /// A file of negative trust anchors (RFC 7646): subtrees answered
    /// unvalidated until a set time. Needs --dnssec-validate. One per line,
    /// `NAME UNTIL [norecheck]`, `UNTIL` in UTC as `YYYYMMDDHHmmSS` or Unix
    /// seconds, at most a week ahead (§4). Re-read on SIGHUP, keeping the old
    /// set if the file fails; each zone is rechecked every five minutes unless
    /// `norecheck`.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    negative_trust_anchors: Option<PathBuf>,
    /// Answer `rdnsctl -s PATH` on this Unix socket (`help` lists the
    /// commands). Mode 0600, so the server's user and root; that is the
    /// authentication. On Windows a named pipe, `\\.\pipe\NAME`, writable by
    /// the owner, administrators and SYSTEM.
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
    /// How much to say: error, warn, info, debug or trace.
    ///
    /// Nothing per-query is above `debug`. `RUST_LOG` overrides it, so a
    /// misbehaving resolver can be turned up without a restart into new flags.
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: LogLevel,
    /// Errors only. The same as `--log-level error`, and refused with it.
    #[arg(long, conflicts_with = "log_level")]
    quiet: bool,
    /// How many UDP queries may be in flight at once. Over it, the oldest gives
    /// way if its client stopped waiting (RFC 8767 §5's 1.8 s), else the
    /// newcomer is dropped, silently. No off switch: a recursion holds its task
    /// for seconds. 0 is floored to 1.
    #[arg(long, value_name = "QUERIES", default_value_t = default_max_inflight_udp(), conflicts_with = "config")]
    max_inflight_udp: usize,
    /// Queries per second, per source: an IPv4 address or an IPv6 /56.
    /// 0 turns the limit off.
    ///
    /// 200 where `rdnsd`'s is 1000: an authoritative server's clients are
    /// resolvers, and one resolver behind one address legitimately asks orders
    /// of magnitude more than one person does.
    #[arg(long, value_name = "QUERIES_PER_SEC", default_value_t = default_query_rate(), conflicts_with = "config")]
    query_rate: u32,
    /// How many queries may arrive at once before `--query-rate` applies.
    ///
    /// A DNS client sends its queries in bursts by nature — one page load is
    /// dozens of names at once — so a limiter with no burst allowance drops
    /// traffic that is not a flood at all.
    #[arg(long, value_name = "QUERIES", default_value_t = default_query_burst(), conflicts_with = "config")]
    query_burst: u32,
    /// An address or CIDR prefix the query rate limit does not apply to,
    /// repeatable.
    ///
    /// For a monitoring probe whose whole job is to query more often than a
    /// client would, and for a forwarder in front of this one. Without it the
    /// only way to spare a known-good source is to raise the limit for everybody.
    #[arg(long, value_name = "ADDR|CIDR", conflicts_with = "config")]
    query_rate_exempt: Vec<String>,
    /// Largest UDP request accepted, in octets.
    ///
    /// Floored at the payload size this resolver advertises it can reassemble
    /// (RFC 6891 §6.2.4): refusing under what was advertised is a promise broken
    /// in silence (`TODO.md` #40f). A client's padded query (RFC 8467) is the
    /// request here that grows, where `rdnsd`'s is a signed UPDATE.
    #[arg(long, value_name = "OCTETS", default_value_t = default_max_udp_request(), conflicts_with = "config")]
    max_udp_request: u16,
    /// Largest TCP request accepted, in octets. Not a protocol limit — the
    /// length prefix allows 65,535 — but a query has no reason to be large.
    #[arg(long, value_name = "OCTETS", default_value_t = default_max_tcp_request(), conflicts_with = "config")]
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
    /// UDP payload size advertised to clients in every reply's OPT, in octets.
    ///
    /// What this host can reassemble (RFC 6891 §6.2.3), told to clients and to
    /// the servers it asks, as Unbound's `edns-buffer-size`; it floors
    /// `--max-udp-request`. The default, [`rdns::FLAG_DAY_UDP_SIZE`], is
    /// BIND's, Knot's, NSD's and Unbound's since DNS Flag Day 2020. Floored at
    /// 512.
    #[arg(long, value_name = "OCTETS", default_value_t = default_udp_payload_size(), conflicts_with = "config")]
    udp_payload_size: u16,
    /// Largest UDP reply this resolver will send, in octets.
    ///
    /// The client's own advertisement is honoured only down to this: above it
    /// the reply fragments, and a fragment is what middleboxes drop. Over the
    /// cap the reply is an empty TC=1 and the client asks again over TCP, which
    /// is never capped. 65535 is "whatever the client asked for"; floored at
    /// 512.
    #[arg(long, value_name = "OCTETS", default_value_t = default_max_udp_response(), conflicts_with = "config")]
    max_udp_response: u16,
    /// How often to report what the last interval's traffic looked like, in
    /// seconds. 0 turns the anomaly warnings off.
    ///
    /// Every threshold below is per interval, so this is also the unit they are
    /// read in: `--anomaly-source-queries 100` at the default is a hundred
    /// queries a minute from one address.
    #[arg(long, value_name = "SECONDS", default_value_t = default_anomaly_interval(), conflicts_with = "config")]
    anomaly_interval: u64,
    /// Warn above this query rate, averaged over `--anomaly-interval`. 0 is off.
    #[arg(long, value_name = "QUERIES_PER_SEC", default_value_t = default_anomaly_query_rate(), conflicts_with = "config")]
    anomaly_query_rate: f64,
    /// Warn when more than this percentage of an interval's queries failed.
    /// 0 is off.
    #[arg(long, value_name = "PERCENT", default_value_t = default_anomaly_error_percent(), conflicts_with = "config")]
    anomaly_error_percent: f64,
    /// Warn about a source that sent more than this many queries in one
    /// interval. 0 is off.
    ///
    /// A log line, not a metric: naming the address is the point, and an
    /// address is exactly what a Prometheus label must not be — the cardinality
    /// is the client's to choose.
    #[arg(long, value_name = "QUERIES", default_value_t = default_anomaly_source_queries(), conflicts_with = "config")]
    anomaly_source_queries: u64,
    /// Warn about a source the rate limiter refused more than this many times
    /// in one interval. 0 is off.
    #[arg(long, value_name = "REFUSALS", default_value_t = default_anomaly_source_refusals(), conflicts_with = "config")]
    anomaly_source_refusals: u64,
    /// Response bytes per second, per IPv4 /24 or IPv6 /56 a reply goes to.
    /// 0 turns the budget off.
    ///
    /// A resolver needs this more than an authoritative server does: a 30-byte
    /// query can produce a 4 KB validated answer, which `--dnssec-validate`
    /// makes ordinary. Meters what leaves, since that is what an amplification
    /// attack is made of, and UDP only — a TCP query completed a handshake, so
    /// there is nobody to reflect at.
    #[arg(long, value_name = "BYTES_PER_SEC", default_value_t = default_response_rate(), conflicts_with = "config")]
    response_rate: u32,
    /// Serve Prometheus metrics and a liveness probe on this address.
    ///
    /// No meaningful `/readyz`: a resolver has nothing to wait for, so it
    /// answers ready as soon as it is up. `metrics_server` serves the route
    /// because it is shared with `rdnsd`.
    #[arg(long, value_name = "ADDR:PORT", conflicts_with = "config")]
    metrics_listen: Option<String>,
    /// Answer an NSID request (RFC 5001) with this identifier: text, or `0x`
    /// and hex. Off unless given, as §5 calls it "security sensitive"; only a
    /// query carrying the option gets one (§2.2).
    #[arg(long, value_name = "TEXT|0xHEX", conflicts_with = "config")]
    nsid: Option<String>,
    /// Stream traffic to dnstap: `tcp:<addr:port>` for a collector,
    /// `file:<path>` for a capture `dnstap -r` reads. Which traffic is
    /// `--dnstap-types`. The queue is bounded and drops rather than blocking:
    /// `dns_dnstap_dropped_total` counts what a slow collector lost.
    #[arg(long, value_name = "TARGET", conflicts_with = "config")]
    dnstap: Option<String>,
    /// Stop writing a dnstap *file* after this many octets. 0 is no limit.
    #[arg(long, value_name = "OCTETS", default_value_t = default_dnstap_max_bytes(), conflicts_with = "config")]
    dnstap_max_bytes: u64,
    /// What `--dnstap` writes, comma-separated: `client` (queries from
    /// clients and the answers), `resolver` (each query of the delegation
    /// walk and its reply), `forwarder` (each query to a forward zone's
    /// server and its reply). BIND's names. Default `client`.
    #[arg(
        long,
        value_name = "TYPES",
        value_delimiter = ',',
        conflicts_with = "config"
    )]
    dnstap_types: Vec<String>,
    /// Also answer DNS over TLS here (RFC 7858). Needs --tls-cert and --tls-key.
    ///
    /// 853 is the assigned port, and a resolver is what RFC 7858 was written
    /// for: the stub-to-recursive hop is the one it names. In addition to the
    /// plain listeners on --port, not instead of them.
    #[arg(long, value_name = "ADDR:PORT", conflicts_with = "config")]
    tls_listen: Option<String>,
    /// Also answer DNS over QUIC here (RFC 9250). Needs --tls-cert and --tls-key.
    ///
    /// 853 as well: DoT is TCP and DoQ is UDP, so the two do not collide.
    #[arg(long, value_name = "ADDR:PORT", conflicts_with = "config")]
    quic_listen: Option<String>,
    /// Also answer DNS over HTTPS here (RFC 8484). Needs --tls-cert and --tls-key.
    ///
    /// 443 is the port: DoH is meant to look like other HTTPS traffic.
    #[arg(long, value_name = "ADDR:PORT", conflicts_with = "config")]
    https_listen: Option<String>,
    /// The path --https-listen answers on.
    #[arg(long, value_name = "PATH", default_value = rdns_transport::https::DEFAULT_PATH, conflicts_with = "config")]
    https_path: String,
    /// The PEM certificate chain --tls-listen presents. Leaf first.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    tls_cert: Option<PathBuf>,
    /// The PEM private key for --tls-cert.
    ///
    /// Refused if it is readable by its group or by everybody. Unix only;
    /// Windows has no equivalent.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    tls_key: Option<PathBuf>,
    /// Synthesize AAAA records from A records under this NAT64 prefix, so an
    /// IPv6-only client can reach an IPv4-only name (RFC 6147).
    ///
    /// Without a value, the Well-Known Prefix 64:ff9b::/96 (RFC 6052 §2.1);
    /// else a prefix of length 32, 40, 48, 56, 64 or 96 (§2.2). Off unless
    /// given: it asserts a translator exists.
    #[arg(long, value_name = "PREFIX", num_args = 0..=1,
          default_missing_value = rdns::dns64::WELL_KNOWN_PREFIX, conflicts_with = "config")]
    dns64: Option<String>,
    /// Resolve this RFC 6303 empty zone instead of answering it locally,
    /// repeatable: `10.in-addr.arpa.`, `168.192.in-addr.arpa.` and the rest,
    /// for a site serving its own private reverse zones. `localhost`, `local.`
    /// and `invalid.` cannot be switched off.
    #[arg(long, value_name = "ZONE", conflicts_with = "config")]
    disable_empty_zone: Vec<String>,
    /// Resolve every RFC 6303 empty zone instead of answering it locally.
    #[arg(long, conflicts_with = "config")]
    no_empty_zones: bool,
    /// An IPv6 prefix whose presence in a AAAA answer is to be read as no
    /// answer at all (RFC 6147 §5.1.4), repeatable.
    ///
    /// Added to `::ffff:0:0/96`, which §5.1.4 asks for by name and which is
    /// never removed: an address in it is an IPv4 address written differently,
    /// so a client given one is no better off.
    #[arg(long, value_name = "CIDR", conflicts_with = "config")]
    dns64_exclude: Vec<String>,
    /// A Response Policy Zone file, repeatable and consulted in the order
    /// given: the first zone with a rule for a query decides it.
    ///
    /// The origin is the `$ORIGIN` line, or the file name. Not naming one is
    /// the off switch and costs nothing per query.
    #[arg(long, value_name = "PATH", conflicts_with = "config")]
    rpz: Vec<PathBuf>,
    /// Serve an expired answer this many seconds past its TTL when no
    /// authoritative server answers (RFC 8767); 0, the default, is off.
    ///
    /// The window is the feature, so one number; RFC 8767 §4 suggests one to
    /// three days. Off by default: a withdrawn name lives the whole window
    /// (§6). A stale answer carries a 30 s TTL and an EDE (RFC 8914 §4.4).
    #[arg(long, value_name = "SECONDS", default_value_t = default_serve_stale(), conflicts_with = "config")]
    serve_stale: u64,
    /// Abandon a resolution, and answer SERVFAIL, after this many seconds:
    /// RFC 8767 §5's query resolution timer. 1 to 30.
    ///
    /// The query budget counts queries and not time, so without it a zone
    /// delegated to silent nameservers held a UDP slot for 157.5 s
    /// (`TODO.md` #168). 10, as BIND's `resolver-query-timeout` and Knot
    /// Resolver have it. A stale answer, under `--serve-stale`, is served
    /// in place of the SERVFAIL.
    #[arg(long, value_name = "SECONDS", default_value_t = rdns::resolver::ResolutionTimer::DEFAULT, conflicts_with = "config")]
    resolution_timer: rdns::resolver::ResolutionTimer,
    /// Answer an expired name from the `--serve-stale` window at once, and
    /// re-resolve it behind the answer: BIND's `stale-answer-client-timeout 0`.
    ///
    /// A deviation from RFC 8767 §4, which serves stale only after a failed
    /// refresh (`docs/adr/0005`). The refresh goes to the `--prefetch-workers`
    /// pool, one per name per 30 seconds.
    #[arg(long, conflicts_with = "config", group = "refreshing")]
    serve_stale_first: bool,
    /// Re-resolve a cached name in the last tenth of its TTL, so a popular name
    /// never makes a client wait (Unbound's `prefetch`).
    ///
    /// One refresh per entry, on its own pool. Off by default: it doubles a
    /// query for a name nobody may ask again; compare `dns_prefetches_total`
    /// with `dns_cache_hits_total`.
    #[arg(long, conflicts_with = "config", group = "refreshing")]
    prefetch: bool,
    /// How many refreshes may resolve at once, for `--prefetch` and
    /// `--serve-stale-first` together. 0 is floored to 1.
    #[arg(long, value_name = "WALKS", default_value_t = default_prefetch_workers(), conflicts_with = "config", requires = "refreshing")]
    prefetch_workers: usize,
    /// How many refreshes may wait for a worker. Past it one is dropped and
    /// counted in `dns_prefetches_dropped_total` or
    /// `dns_stale_refreshes_dropped_total`: a live entry expires and the next
    /// client for it resolves it, a stale one is offered again after 30
    /// seconds. 0 is floored to 1.
    #[arg(long, value_name = "NAMES", default_value_t = default_prefetch_queue(), conflicts_with = "config", requires = "refreshing")]
    prefetch_queue: usize,
    /// What a policy zone's rules mean, when it should not be taken at its
    /// word: given, disabled, passthru, drop, nxdomain, nodata or tcp-only.
    ///
    /// `given`, the default, does what each rule says; `passthru` matches and
    /// changes nothing, to measure a feed; `disabled` matches nothing. Applies
    /// to every zone; `[[rpz.feeds]]` in `--config` sets one per feed.
    #[arg(long, value_name = "POLICY", default_value_t = default_rpz_policy(), conflicts_with = "config")]
    rpz_policy: rdns::rpz::PolicyOverride,
    /// Addresses that may send a NOTIFY asking for the `--rpz` files to be
    /// re-read: `192.0.2.1`, `10.0.0.0/8`, `2001:db8::/32`. Repeatable.
    ///
    /// An `rdnsd` replicating a feed announces changes this way. A list, not a
    /// default: a NOTIFY costs a re-read of the feed (`TODO.md` #71b measures
    /// it). Naming nobody leaves a NOTIFY answered NOTIMP.
    #[arg(long, value_name = "ADDR|CIDR", conflicts_with = "config")]
    rpz_notify_from: Vec<String>,
    /// Read the settings from this file instead of the command line.
    ///
    /// Exclusive of the flags it would set: `--config` with `--port` is an
    /// error and not a precedence rule, because both values are valid and the
    /// wrong one would be picked silently (`CLAUDE.md` §15).
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Validate the configuration and exit without binding a socket.
    ///
    /// Reads every policy feed, the trust anchors, every ACL, the NAT64 prefix
    /// and the certificate; exit 0 means it would start. Works with flags,
    /// unlike `rdnsd`'s, since all of it is flag-settable.
    #[arg(long)]
    check_config: bool,
    /// The feeds with a policy each, which only a config file can express.
    ///
    /// Not a flag: `--rpz-policy` is one setting for every `--rpz`, so the
    /// command line's shape is [`Feed::each`] and the file's is this. They
    /// cannot both be set — every `--rpz*` flag conflicts with `--config` — so
    /// `feeds` picking between them is not a precedence rule (`CLAUDE.md` §15).
    #[arg(skip)]
    rpz_feeds: Vec<Feed>,
    /// The feeds this resolver transfers for itself, and the file each is
    /// written to (`TODO.md` #57d shape A).
    ///
    /// Not a flag: a master needs a zone name, a key and eventually TLS
    /// anchors per feed, which is a table and not a word — the same argument
    /// `--rpz-policy` lost.
    #[arg(skip)]
    rpz_masters: Vec<TransferredFeed>,
    /// TSIG keys a transferred feed's master may be signed with, in
    /// `TsigKey::parse`'s form.
    ///
    /// Not a flag: a secret in `argv` is readable out of `ps` by anyone on the
    /// machine, and the config file is where §15 puts one. `rdnsc` has the flag
    /// form because a query client is a person at a terminal; a daemon is not.
    #[arg(skip)]
    tsig_key: Vec<String>,
}

impl Cli {
    /// The policy feeds, in the order they are consulted.
    fn feeds(&self) -> Vec<Feed> {
        if self.rpz_feeds.is_empty() {
            Feed::each(&self.rpz, self.rpz_policy)
        } else {
            self.rpz_feeds.clone()
        }
    }

    fn encrypted_flags(&self) -> EncryptedFlags<'_> {
        EncryptedFlags {
            tls_listen: self.tls_listen.as_deref(),
            quic_listen: self.quic_listen.as_deref(),
            https_listen: self.https_listen.as_deref(),
            https_path: &self.https_path,
            tls_cert: self.tls_cert.as_deref(),
            tls_key: self.tls_key.as_deref(),
        }
    }
}

/// The query ACL, or the refusal to start without one (`docs/adr/0007`).
///
/// No list is [`QueryAcl::Open`], and allowed only while every listener is on
/// loopback. A given list must hold every `--rpz-notify-from` rule: the ACL
/// runs before a NOTIFY is parsed, so a primary it does not list would be
/// refused without anything saying why.
async fn query_acl(cli: &Cli, notify_from: Option<&TransferAcl>) -> anyhow::Result<QueryAcl> {
    let acl = TransferAcl::parse_named(&cli.allow_query, "--allow-query")?;
    if acl.is_empty() {
        let plain = format!("{}:{}", cli.host, cli.port);
        for (flag, addr) in [
            ("--host", Some(plain.as_str())),
            ("--tls-listen", cli.tls_listen.as_deref()),
            ("--quic-listen", cli.quic_listen.as_deref()),
            ("--https-listen", cli.https_listen.as_deref()),
        ] {
            let Some(addr) = addr else { continue };
            if !bind::loopback_only(addr)
                .await
                .with_context(|| format!("{flag} {addr}"))?
            {
                bail!(
                    "{flag} {addr} is off loopback and no --allow-query says who may be \
                     answered; an open resolver is --allow-query 0.0.0.0/0 --allow-query ::/0"
                );
            }
        }
        return Ok(QueryAcl::Open);
    }
    if let Some(rule) = notify_from.and_then(|from| from.first_not_within(&acl)) {
        bail!(
            "--rpz-notify-from {rule} is inside no --allow-query rule, and the query ACL \
             refuses a NOTIFY from it before --rpz-notify-from is consulted"
        );
    }
    Ok(QueryAcl::Only(Arc::new(acl)))
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    // `--check-config` is a console answer even with `--service` beside it.
    let service = cli.service.clone().filter(|_| !cli.check_config);
    rdns_transport::entry::run(service.as_deref(), move || serve_main(cli))
}

async fn serve_main(mut cli: Cli) -> anyhow::Result<()> {
    // The file replaces the flags rather than layering over them; `config` says
    // why.
    if let Some(path) = cli.config.clone() {
        config::Config::load(&path)?.apply(&mut cli);
        tracing::info!("configured from {}", path.display());
    }
    let cli = cli;
    // Through the same initialiser `rdnsd` uses so the two cannot format or
    // filter differently; after the config, which may name the log file.
    rdns_transport::logging::init(
        if cli.quiet {
            LogLevel::Error
        } else {
            cli.log_level
        },
        cli.log_file.as_deref(),
    )?;
    let started = std::time::Instant::now();
    // Before the dry run (`TODO.md` #190).
    if cli.service.is_some() {
        if !cfg!(windows) {
            return Err(anyhow::anyhow!(
                "--service is the Windows service control manager's; under systemd or \
                 another supervisor run the binary as it is"
            ));
        }
        if cli.log_file.is_none() {
            return Err(anyhow::anyhow!(
                "--service needs --log-file: a service's standard error goes nowhere, so \
                 without one nothing it says reaches anybody"
            ));
        }
    }

    // Refused here, above the dry run, so `--check-config` says so too: on
    // Windows a path that is not a pipe name.
    if let Some(path) = &cli.control_socket {
        rdns_transport::control::check(path)?;
    }

    // Before anything is spawned: it owns the only durable state this process
    // writes.
    let shutdown = Shutdown::new();

    // One advertisement both ways: what this stack reassembles, as Unbound's
    // `edns-buffer-size` reads.
    let udp = UdpSizes::new(cli.udp_payload_size, cli.max_udp_response);

    // Recursion is the default; naming an upstream is what selects forwarding.
    let mut config = ResolverConfig {
        udp_payload_size: udp.advertised(),
        resolution_timer: cli.resolution_timer,
        request_nsid: cli.request_nsid,
        ..ResolverConfig::default()
    };
    // Above the dry run, with every refusal naming its entry (`TODO.md` #172).
    // `--upstream` is a forward zone at `.`.
    let routes::Built {
        routes,
        files: local_files,
        tls,
    } = routes::build(
        &cli.forward_zone,
        &cli.stub_zone,
        &cli.local_zone,
        &cli.no_validate_zone,
        &cli.upstream,
        cli.root_hints.is_some(),
    )?;
    config.routes = routes;
    // Made here rather than with the shell: the resolver counts TLS handshake
    // failures (#175) and reports the local root (#177) into it.
    let metrics = DnsMetrics::new();
    config.metrics = metrics.clone();
    // Above the dry run: a CA that does not load is a startup failure.
    let upstream_tls = match (&cli.upstream_tls_ca, tls.is_empty()) {
        (Some(path), false) => {
            let trust = rdns::xot::TlsClientTrust::for_upstreams(path)?;
            let anchors = trust.anchor_count();
            config.dot = Some(rdns::resolver::DotConfig {
                trust,
                servers: tls.clone(),
            });
            format!(
                "{} server(s) over TLS, {anchors} anchor(s) from {}",
                tls.len(),
                path.display()
            )
        }
        (None, false) => bail!(
            "a +tls= server needs --upstream-tls-ca: the certificate is checked against \
             the operator's anchors and nothing else"
        ),
        (Some(_), true) => bail!(
            "--upstream-tls-ca is given and no server is written with +tls=, so nothing \
             would use it"
        ),
        (None, true) => "off".to_string(),
    };
    let recursing = !config.routes.iter().any(|r| r.name.as_ref().is_root());

    // Fail loudly on a hints file that yields no addresses; falling back to
    // the built-ins would hide the misconfiguration.
    let mut custom_hints = false;
    if let Some(path) = &cli.root_hints {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading root hints {}", path.display()))?;
        let hints = rdns::resolver::parse_root_hints(&text);
        if hints.is_empty() {
            return Err(anyhow!("no A/AAAA records found in {}", path.display()));
        }
        config.root_hints = hints;
        custom_hints = true;
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
                // Saved now, to show what is trusted; not by a dry run, which
                // may leave it owned by someone else.
                if !path.exists() && !cli.check_config {
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
        // Above the dry run, as every file is (`CLAUDE.md` §15).
        if let Some(path) = &cli.negative_trust_anchors {
            let anchors = shared_anchors.as_ref().map(SharedAnchors::get);
            config.ntas = rdns::nta::SharedNtas::new(nta::load(
                path,
                current_unix_timestamp(),
                anchors.as_ref(),
            )?);
        }
    } else if cli.negative_trust_anchors.is_some() {
        // Refused, not warned: an exemption from validation that does not
        // validate is a setting the operator believes is in force and is not.
        bail!("--negative-trust-anchors exempts names from validation, and there is none: add --dnssec-validate");
    } else if cli.trust_anchor.is_some() || cli.auto_trust_anchor.is_some() {
        tracing::warn!(
            "--trust-anchor and --auto-trust-anchor do nothing without --dnssec-validate"
        );
    }

    // Every routed domain on the line, then where everything else goes.
    let source = {
        let rest = match (recursing, custom_hints) {
            (false, _) => String::new(),
            (true, true) => format!(
                "recursing from {} root hints in {}",
                config.root_hints.len(),
                cli.root_hints
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            ),
            (true, false) => "recursing from the built-in root hints".to_string(),
        };
        config
            .routes
            .iter()
            .map(|route| routes::describe(route, &local_files, &tls))
            .chain((!rest.is_empty()).then_some(rest))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let serving_ntas = config.ntas.clone();
    // Above the dry run (`CLAUDE.md` §15); the sink itself opens after it.
    let dnstap_target = cli
        .dnstap
        .as_deref()
        .map(str::parse::<rdns_transport::dnstap::Target>)
        .transpose()?;
    let dnstap_types = tap::types(&cli.dnstap_types, dnstap_target.is_some())?;
    let dnstap_slot: Arc<std::sync::OnceLock<rdns_transport::dnstap::Sink>> = Arc::default();
    let mut resolver = Resolver::new(config);
    if dnstap_target.is_some() && (dnstap_types.resolver || dnstap_types.forwarder) {
        resolver = resolver.with_tap(tap::exchange_tap(dnstap_slot.clone(), dnstap_types));
    }
    let resolver = Arc::new(resolver);

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

    // Above the dry run: without a window the switch is a policy believed in
    // force and not (`CLAUDE.md` §15).
    if cli.serve_stale_first && (cli.serve_stale == 0 || cli.no_cache) {
        return Err(anyhow!(
            "--serve-stale-first answers from the --serve-stale window, and \
             there is none: set --serve-stale SECONDS, and not --no-cache"
        ));
    }

    // What the flags mean for each cache is `Caches::new`'s to say.
    let capacity = if cli.no_cache { 0 } else { cli.cache_size };
    let denial_zones = if cli.no_cache || !cli.dnssec_validate {
        0
    } else {
        NSEC_CACHE_ZONES
    };
    // One clock for the process: the rate limiter, the query log and both
    // caches read the same instant, and a test can move it.
    let clock = rdns::clock::Clock::system();
    let caches = Caches::new(
        capacity,
        denial_zones,
        StalePolicy::seconds(cli.serve_stale),
        clock.clone(),
    );

    // Before anything binds: a feed that will not parse is a block not in
    // force.
    let feeds = cli.feeds();
    let policy = PolicyStore::load(&feeds)?;

    // With the policy, before anything binds: a typo here would otherwise
    // surface as a stale feed.
    let reload = PolicyReload::default();
    let rpz_notify = if cli.rpz_notify_from.is_empty() {
        None
    } else {
        if feeds.is_empty() {
            // Not a warning: with nothing to re-read, the list is a policy not
            // in force (`CLAUDE.md` §15).
            return Err(anyhow!(
                "--rpz-notify-from names who may ask for the --rpz files to be \
                 re-read, and no --rpz names one"
            ));
        }
        Some(NotifyAcl {
            from: TransferAcl::parse_named(&cli.rpz_notify_from, "--rpz-notify-from")?,
            reload: reload.clone(),
        })
    };

    // Above the dry run (`CLAUDE.md` §15). Leaked once: read on every reply,
    // and `'static` keeps `ServerOpt` `Copy`.
    let nsid: Option<&'static [u8]> = cli
        .nsid
        .as_deref()
        .map(rdns::config::parse_nsid)
        .transpose()?
        .map(|bytes| &*Box::leak(bytes.into_boxed_slice()));

    // Above the dry run: a name that is not an empty zone switches nothing
    // off, and the operator would believe it had (`CLAUDE.md` §15).
    let empty_zones =
        rdns::special_names::EmptyZones::configure(cli.no_empty_zones, &cli.disable_empty_zone)?;

    // Above the dry run, and after `--rpz-notify-from`, which it is checked
    // against: an open resolver must fail `--check-config` too.
    let acl = query_acl(&cli, rpz_notify.as_ref().map(|n| &n.from)).await?;

    // Before anything binds, as everything else operator-supplied is: a NAT64
    // prefix that does not parse is an IPv6-only network with no DNS at all.
    let dns64 = match &cli.dns64 {
        Some(spec) => Some(Dns64::new(Nat64Prefix::parse(spec)?, &cli.dns64_exclude)?),
        None => {
            if !cli.dns64_exclude.is_empty() {
                tracing::warn!("--dns64-exclude does nothing without --dns64");
            }
            None
        }
    };

    // Before anything binds, so `--check-config` reaches it; over the merged
    // view, so file and flags share one pair check.
    let encrypted = Encrypted::configure(cli.encrypted_flags(), None)?;

    // Here for the same reason, and it was below the binds too: a typo in the
    // list is a client paying the rate limit its operator exempted it from.
    let query_rate_exempt =
        TransferAcl::parse_named(&cli.query_rate_exempt, "--query-rate-exempt")?;
    let per_source = SourceConnections::new(
        cli.max_connections_per_source,
        TransferAcl::parse_named(
            &cli.max_connections_per_source_exempt,
            "--max-connections-per-source-exempt",
        )?,
    );

    // Through `TsigKey::parse`, as `rdnsd` (`CLAUDE.md` §7), and above the
    // exit, so a bad secret fails the dry run (§15).
    let policy_keys: Vec<rdns::tsig::TsigKey> = cli
        .tsig_key
        .iter()
        .map(|spec| rdns::tsig::TsigKey::parse(spec))
        .collect::<Result<_, _>>()
        .context("a TSIG key in [keys]")?;

    // The dry run exits here: everything above is knowable without binding;
    // what is left binds sockets and starts timers.
    if cli.check_config {
        // `println!`: the answer goes to stdout, and `--quiet` must not hide
        // it, as in `rdnsd --check-config`.
        let in_force = policy.in_force();
        let overridden = in_force
            .zones()
            .iter()
            .filter(|z| z.policy() != rdns::rpz::PolicyOverride::Given)
            .count();
        println!(
            "configuration is valid: {}, {} policy feed(s){}, cache {}, listening on {}, \
             encrypted transports {}, upstream TLS {}, query ACL {}, empty zones {}, NSID {}",
            source,
            in_force.zones().len(),
            // Said out loud: a feed at `passthru` or `disabled` blocks nothing
            // and looks like a working server.
            match overridden {
                0 => String::new(),
                n => format!(" ({n} not taken at their word)"),
            },
            if capacity == 0 {
                "disabled".to_string()
            } else {
                format!("{capacity} entries")
            },
            // What the bind will make of the address, since nothing is bound
            // here (`TODO.md` #159).
            {
                let addr = format!("{}:{}", cli.host, cli.port);
                bind::planned(&addr).unwrap_or(addr)
            },
            match &encrypted {
                None => "disabled".to_string(),
                Some(encrypted) => format!("on {}, certificate loads", encrypted.listeners()),
            },
            upstream_tls,
            acl.describe(),
            empty_zones.describe(),
            match nsid {
                Some(nsid) => rdns::config::show_nsid(nsid),
                None => "off (--nsid)".to_string(),
            },
        );
        return Ok(());
    }

    let addr = format!("{}:{}", cli.host, cli.port);
    // Both transports are mandatory: an answer over the client's UDP payload
    // size gets TC=1, and RFC 1035 §4.2.1 has the client retry over TCP.
    let socket = bind::udp(&addr).await?;
    let listening = socket.describe();
    let socket = Arc::new(socket.socket);
    let listener = bind::tcp(&addr).await?.socket;
    // Bound before anything is announced, so a typo in `--metrics-listen`
    // stops the start rather than losing the observability silently.
    let metrics_listener = match &cli.metrics_listen {
        Some(spec) => Some(
            bind::tcp(spec)
                .await
                .with_context(|| format!("--metrics-listen {spec}"))?,
        ),
        None => None,
    };
    // The same rule for the control socket: a path that cannot be bound stops
    // the start.
    let control_listener = match &cli.control_socket {
        Some(path) => Some(rdns_transport::control::bind(path)?),
        None => None,
    };

    let stream_listeners = EncryptedListeners::bind(
        encrypted.as_ref(),
        TransportLimits::configured(cli.max_connections, cli.connection_idle_timeout),
    )
    .await?;

    let query_limit =
        RateLimitConfig::per_second(cli.query_rate, cli.query_burst).exempting(query_rate_exempt);
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
        metrics: Arc::new(metrics),
        logger: Arc::new(QueryLogger::new()),
        admission: Arc::new(AdmissionCheck::new(admission.clone())),
        per_source: per_source.clone(),
        acl: acl.clone(),
        nsid,
        clock,
    });
    // Without validation every answer is indeterminate, so the family would say
    // nothing; absent says that.
    if cli.dnssec_validate {
        ctx.metrics.validating();
    }
    tracing::info!(
        "rdnsr listening on {} (UDP+TCP), {}, cache: {}{}, \
         UDP reply cap: {}B (advertising {}B), UDP in flight: {}, \
         connections: {} per listener, {}, idle {}s, encrypted: {}, upstream TLS: {}, \
         query ACL: {}, NSID: {}",
        listening,
        source,
        if capacity == 0 {
            "disabled".to_string()
        } else if cli.serve_stale == 0 {
            format!("{capacity} entries")
        } else {
            // Printed because an answer known to be out of date is a decision,
            // and because a window measured in days is easy to mistype.
            format!(
                "{capacity} entries, serving stale for up to {}s past the TTL{}",
                cli.serve_stale,
                if cli.serve_stale_first {
                    ", before refreshing"
                } else {
                    ""
                }
            )
        },
        dnssec_source,
        udp.max_response(),
        udp.advertised(),
        // Printed because the drops it causes are silent.
        cli.max_inflight_udp.max(1),
        cli.max_connections,
        per_source.describe(),
        cli.connection_idle_timeout,
        match &encrypted {
            Some(encrypted) => stream_listeners.describe(encrypted),
            None => "off (--tls-listen, --quic-listen, --https-listen)".to_string(),
        },
        upstream_tls,
        acl.describe(),
        match nsid {
            Some(nsid) => rdns::config::show_nsid(nsid),
            None => "off (--nsid)".to_string(),
        },
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
    log_policy(&policy.in_force());
    // Printed like the rate limit: a refused NOTIFY is silent, and a stale feed
    // looks the same either way (`CLAUDE.md` §14).
    if let Some(acl) = rpz_notify.as_ref() {
        tracing::info!(
            "a NOTIFY from {} address(es) queues a re-read of the --rpz file it \
             names; from anywhere else it is REFUSED",
            acl.from.len()
        );
    } else if !feeds.is_empty() {
        tracing::info!(
            "no --rpz-notify-from: a feed is re-read on SIGHUP only, and a NOTIFY is NOTIMP"
        );
    }

    // Printed because a private PTR leaving the host is the leak RFC 6303
    // stops.
    tracing::info!("empty zones (RFC 6303): {}", empty_zones.describe());
    // Printed because every name under one is answered unvalidated.
    if let Some(path) = &cli.negative_trust_anchors {
        let ntas = serving_ntas.snapshot();
        tracing::info!(
            "negative trust anchors (RFC 7646): {} from {}{}",
            ntas.len(),
            path.display(),
            ntas.iter()
                .map(|n| format!(", {} until {}", n.name, n.until))
                .collect::<String>()
        );
    }

    if let Some(dns64) = dns64.as_ref() {
        tracing::info!(
            "DNS64: synthesizing AAAA under {} (RFC 6147)",
            dns64.prefix()
        );
    }

    let (udp_cap, tcp_cap) = admission.caps();
    tracing::info!(
        "query rate: {}, response budget: {}, request cap: {udp_cap}B UDP / {tcp_cap}B TCP, \
         metrics: {}, anomaly warnings: {}",
        if cli.query_rate == 0 {
            "unlimited (--query-rate 0)".to_string()
        } else {
            format!(
                "{}/s per source (IPv4 address, IPv6 /56), burst {}{}",
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
            format!("{} bytes/s per IPv4 /24 or IPv6 /56", cli.response_rate)
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

    // Outside the `JoinSet`, as it ends on the stop signal by design; joined
    // after the drain, so not detached (`CLAUDE.md` §9).
    let anomalies = tokio::spawn(watch_anomalies(
        ctx.logger.clone(),
        anomaly_thresholds,
        anomaly_interval,
        shutdown.stop_handle(),
    ));

    // Before `Resolving`, which holds them: a NOTIFY wakes a transferred feed's
    // task, or queues the re-read for a file feed.
    let feed_wakes: Vec<FeedWake> = cli
        .rpz_masters
        .iter()
        .map(|feed| FeedWake::new(feed.spec.zone.clone()))
        .collect();

    // Outside the `JoinSet`, like the anomaly watcher: these end on the stop
    // signal by design.
    let mut transfers = Vec::new();
    for (feed, wake) in cli.rpz_masters.iter().zip(&feed_wakes) {
        // Resolved here so an unknown key stops the process, not every refresh;
        // it holds when `Config::check` could not read a secret.
        let mut feed = feed.clone();
        if let Some(name) = &feed.spec.key_name {
            // By name, not `TsigKeyring::get`: a client knows only the name,
            // and `[keys]` gives the algorithm.
            let Some(key) = policy_keys
                .iter()
                .find(|key: &&rdns::tsig::TsigKey| key.name.eq_ignore_ascii_case(name))
            else {
                return Err(anyhow!(
                    "policy feed {} transfers with TSIG key {name:?}, which is not \
                     defined — check [keys.{name:?}] and whether its secret file \
                     could be read",
                    feed.spec.zone
                ));
            };
            feed.key = Some(key.clone());
        }
        transfers.push(tokio::spawn(refresh_task(
            feed,
            policy.clone(),
            reload.clone(),
            wake.clone(),
            ctx.metrics.clone(),
            ctx.clock.clone(),
            shutdown.lifecycle(),
        )));
    }

    // One handle for every listener (`CLAUDE.md` §7).
    let (refreshes, refresh_queue) = if cli.prefetch || cli.serve_stale_first {
        let (refreshes, queue) = prefetch::channel(
            cli.prefetch_queue,
            prefetch::Uses {
                prefetch: cli.prefetch,
                stale_first: cli.serve_stale_first,
            },
        );
        (Some(refreshes), Some(queue))
    } else {
        (None, None)
    };
    let dnstap = match &dnstap_target {
        Some(target) => {
            let sink = rdns_transport::dnstap::Sink::spawn(
                target,
                cli.dnstap_max_bytes,
                rdns_transport::dnstap::hostname(),
                format!("rdnsr {}", env!("CARGO_PKG_VERSION")).into_bytes(),
                (*ctx.metrics).clone(),
                shutdown.lifecycle(),
            )
            .await?;
            let _ = dnstap_slot.set(sink.clone());
            tracing::info!(
                "dnstap: {} ({})",
                cli.dnstap.as_deref().unwrap_or_default(),
                [
                    (dnstap_types.client, "client"),
                    (dnstap_types.resolver, "resolver"),
                    (dnstap_types.forwarder, "forwarder")
                ]
                .iter()
                .filter(|(on, _)| *on)
                .map(|(_, name)| *name)
                .collect::<Vec<_>>()
                .join(",")
            );
            dnstap_types.client.then_some(sink)
        }
        None => None,
    };
    let serving = Arc::new(Resolving {
        resolver,
        caches,
        policy,
        refreshes,
        dns64,
        empty_zones,
        rpz_notify,
        feed_wakes,
        dnstap,
        ctx: ctx.clone(),
    });

    // Not `JoinHandle`s in a `select!`: dropping the loser detaches it, where
    // `join_next` is cancel-safe and keeps every task owned (`CLAUDE.md` §9).
    let mut loops = JoinSet::new();
    loops.spawn(udp_main(
        socket,
        serving.clone(),
        cli.max_inflight_udp,
        shutdown.stop_handle(),
        shutdown.busy(),
    ));
    if let Some(queue) = refresh_queue {
        loops.spawn(prefetch::run(
            queue,
            serving.clone(),
            cli.prefetch_workers,
            shutdown.stop_handle(),
        ));
    }
    // Per connection, not per message: a resolver's clients open a connection
    // and ask a few things (`TODO.md` #30e).
    stream_listeners.spawn(
        listener,
        serving.clone(),
        tcp::RateLimit::PerConnection,
        &shutdown,
        &mut loops,
    );
    // A no-op without a stub zone at `.` (RFC 8806). Outside the `JoinSet`:
    // it ends on the stop signal by design.
    tokio::spawn(
        serving
            .resolver
            .clone()
            .keep_local_root(shutdown.stop_handle()),
    );
    let nta_file = cli.negative_trust_anchors.clone().map(nta::NtaFile);
    if nta_file.is_some() {
        serving
            .ctx
            .metrics
            .negative_trust_anchors(serving.resolver.ntas().snapshot().len());
        nta::spawn_maintainer(serving.clone(), shutdown.stop_handle(), shutdown.busy());
    }
    let local_files = Arc::new(local_files);
    // A control socket's `reload` goes through this task, so it runs whenever
    // there is a socket, even with nothing to re-read: it says so.
    let (control_reloads, controlled) = tokio::sync::mpsc::channel(1);
    if encrypted.is_some()
        || serving.policy.is_configured()
        || nta_file.is_some()
        || !local_files.is_empty()
        || cli.control_socket.is_some()
    {
        tokio::spawn(reload::reload_task(
            encrypted.as_ref().map(Encrypted::store),
            nta_file,
            local_files.clone(),
            serving.clone(),
            reload,
            controlled,
            shutdown.stop_handle(),
        ));
    }
    // A listener like the others: if it dies, the process does.
    if let Some(control_listener) = control_listener {
        loops.spawn(rdns_transport::control::serve(
            control_listener,
            cli.control_socket
                .clone()
                .expect("a listener implies a path"),
            Arc::new(control::Control {
                serving: serving.clone(),
                reloads: control_reloads,
                local: local_files.clone(),
                started,
            }),
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
    }
    // A listener like the others: if it dies, the process does. Metrics that
    // silently stopped are worse than a resolver that is plainly down.
    if let Some(metrics_listener) = metrics_listener {
        // Taken here, not before the `if`: an unmoved `Busy` clone held by
        // `main` keeps the drain from reaching zero.
        let (stop, busy) = (shutdown.stop_handle(), shutdown.busy());
        loops.spawn(async move {
            metrics_server::serve(
                metrics_listener.socket,
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

    // The first listener to end ends the process; the drain waits for
    // resolutions clients await and an RFC 5011 anchor rewrite.
    let stopped = rdns_transport::serve_until_stopped(loops, anomalies, shutdown).await;
    serving.resolver.close_upstream_connections().await;
    stopped
}
