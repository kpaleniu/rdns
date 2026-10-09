//! The socket layer both daemons run, minus the answering.
//!
//! `rdnsd` and `rdnsr` had written this twice: the same admission sequence, the
//! same five transport constants under two names, the same shutdown epilogue,
//! the same reporting of a listener that stopped (`TODO.md` #30). What is here
//! is what they agree on; what they disagree on stays a parameter, because the
//! disagreements are deliberate — an authoritative server and a recursive
//! resolver have no reason to hold the same connection ceiling, and the
//! resolver reads the clock twice on purpose because a recursion sits between
//! the two reads.
//!
//! Not in `rdns`: everything here reports to a human reading a log line and so
//! returns `anyhow::Error`, which the library may not depend on (`CLAUDE.md`
//! §3). A crate whose only consumers are the two daemons may — that is the
//! boundary argument #31 measured, rather than tidiness.
//!
//! It holds no DNS logic. Deciding what a question deserves is `rdns`'s, and
//! answering it is each daemon's.

// `TODO.md` #82b's ratchet; the reason is at the top of `rdns/src/lib.rs`.
#![warn(unreachable_pub)]
// `push_str(&format!(..))` allocates a `String` to copy it; `write!` into the
// target does not. Off by default (restriction group).
#![warn(clippy::format_push_string)]

pub mod bind;
pub mod control;
pub mod dnstap;
pub mod encrypted;
pub mod entry;
pub mod https;
pub mod logging;
pub mod metrics_server;
pub mod quic;
pub mod readiness;
#[cfg(windows)]
pub mod service;
mod slots;
pub mod tcp;
#[cfg(test)]
mod testutil;
pub mod tls;

use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use rdns::clock::Clock;
use rdns::logging::QueryLogger;
use rdns::metrics::{DnsMetrics, LatencyTimer, StreamListener};
use rdns::peer::Peer;
use rdns::security::{RateLimiter, ResponseLimiter, ResponseVerdict, TransferAcl};
use rdns::shutdown::{stop_signal, Shutdown};
use rdns::validation::{AdmissionCheck, Transport};
use rdns::{ResponseCode, UdpSizes};

/// WSAEMSGSIZE: the datagram was larger than the buffer offered for it. Rust has
/// no [`std::io::ErrorKind`] for it — it arrives as `Uncategorized` — so the raw
/// code is the only way to recognize it.
const WSAEMSGSIZE: i32 = 10040;

/// Whether a UDP receive error is about a datagram rather than about the health
/// of the socket.
///
/// Both servers end their receive loop, and with it the process, when `recv_from`
/// returns `Err`, so anything a remote party can provoke has to be recognized
/// here or it is a remote kill switch. Two such: Windows reports a stray ICMP
/// port-unreachable on the socket's *next* `recv_from`, and fails an oversized
/// receive (WSAEMSGSIZE) instead of truncating it.
pub fn recv_error_is_transient(e: &std::io::Error) -> bool {
    if e.raw_os_error() == Some(WSAEMSGSIZE) {
        return true;
    }
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            // The portable spelling of "that datagram did not fit".
            | std::io::ErrorKind::InvalidInput
    )
}

/// Descriptor and buffer exhaustion, which `accept` reports with no portable
/// [`std::io::ErrorKind`]: `EMFILE` arrives as `Uncategorized`.
///
/// Linux and Windows only; another Unix falls through to the kinds below, a
/// smaller set and not a wrong one.
#[cfg(target_os = "linux")]
const ACCEPT_EXHAUSTION: &[i32] = &[
    24,  // EMFILE — this process is at its descriptor limit
    23,  // ENFILE — the system is
    105, // ENOBUFS
    12,  // ENOMEM
];
#[cfg(windows)]
const ACCEPT_EXHAUSTION: &[i32] = &[
    10024, // WSAEMFILE
    10055, // WSAENOBUFS
];
#[cfg(not(any(target_os = "linux", windows)))]
const ACCEPT_EXHAUSTION: &[i32] = &[];

/// How long an accept loop waits after descriptor or buffer exhaustion.
///
/// The length is not the point; having one is. `continue` on `EMFILE` with no
/// pause spins a core against a kernel that has nothing to hand back until
/// somebody else's connection closes.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What an accept loop does with an `accept` error: `Ok` to carry on, `Err` for
/// one worth ending the process over.
///
/// A loop's end ends the process, so an error that clears by itself, such as
/// `EMFILE` as connections close, must not end it (`CLAUDE.md` §4; UDP's is
/// [`recv_error_is_transient`]). The aborted-connection kinds are what BSD
/// returns for a peer reset before the accept.
pub async fn survive_accept_error(
    e: std::io::Error,
    transport: &str,
) -> Result<(), std::io::Error> {
    // The connection died between the handshake and the accept. Whatever else
    // is queued is still good, so there is nothing to wait for.
    if matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
    ) {
        return Ok(());
    }
    if e.kind() == std::io::ErrorKind::OutOfMemory
        || e.raw_os_error()
            .is_some_and(|c| ACCEPT_EXHAUSTION.contains(&c))
    {
        // Visible, because the alternative is a server that quietly refuses
        // connections for as long as the pressure lasts (§4).
        tracing::warn!(
            transport,
            error = %e,
            backoff_ms = ACCEPT_BACKOFF.as_millis() as u64,
            "out of descriptors accepting a connection; pausing"
        );
        tokio::time::sleep(ACCEPT_BACKOFF).await;
        return Ok(());
    }
    Err(e)
}

/// The receive buffer one datagram needs.
///
/// Not the EDNS payload size either server advertises: that bounds *responses*,
/// and a client may send anything a UDP length field can express.
pub const UDP_RECEIVE_BUFFER: usize = 65_535;

/// What a task needs to serve a request that is not the answer itself.
///
/// The five handles both daemons hold, one type rather than two spellings of
/// the same purpose, which is how an admission pipeline comes to be written
/// twice. `Arc`-cloned into every task, so this is a bag by construction and
/// says so in its name.
#[derive(Clone)]
pub struct ServeContext {
    /// Queries per second per source. The first refusal, and the cheapest.
    pub limiter: Arc<RateLimiter>,
    /// Response *bytes* per second per response target, for UDP only — a TCP peer
    /// completed a handshake, so there is nobody to reflect at.
    pub responses: Arc<ResponseLimiter>,
    /// Size and section caps, applied before a packet is parsed.
    pub admission: Arc<AdmissionCheck>,
    /// Per-source counters and the periodic anomaly warnings.
    pub logger: Arc<QueryLogger>,
    /// What an operator scrapes.
    pub metrics: Arc<DnsMetrics>,
    /// What this host advertises it can reassemble, and the largest datagram it
    /// will send. Not an `Arc`: two `u16`s fixed at startup.
    pub udp: UdpSizes,
    /// How many connections one source may hold on each stream listener.
    pub per_source: SourceConnections,
    /// Which peers may be answered at all. `rdnsd` is [`QueryAcl::Open`].
    pub acl: QueryAcl,
    /// The operator's NSID (RFC 5001, `--nsid`), or `None` for off. `'static`
    /// because it is read on every reply and set once, at startup.
    pub nsid: Option<&'static [u8]>,
    /// Where the accept loops read the wall clock.
    ///
    /// Not `rdns::clock::current_unix_timestamp()`, which leaves a rate-limit
    /// test deciding on whether two connects straddled a second boundary. A
    /// handler still gets `now` as an argument for the reason
    /// [`ServeContext::allow_source`] gives — the clock read belongs to the
    /// caller — and this says which clock that read comes from.
    pub clock: Clock,
}

impl ServeContext {
    /// What a reply's OPT says about this server: what it can reassemble and
    /// its NSID, for [`rdns::response::ClientEdns::mirror`].
    pub fn server_opt(&self) -> rdns::response::ServerOpt {
        rdns::response::ServerOpt {
            payload_size: self.udp.advertised(),
            nsid: self.nsid,
        }
    }

    /// Whether a stream listener may serve a connection from `peer`, counted
    /// per listener when it may not.
    ///
    /// Before the per-source limit, the rate limiter and any handshake: a
    /// peer the ACL refuses gets no table entry anywhere (`CLAUDE.md` §5),
    /// and a TLS or QUIC handshake is work done for somebody who may ask
    /// nothing.
    pub fn admits_connection(&self, peer: Peer, listener: StreamListener) -> bool {
        if self.acl.admits(peer) {
            return true;
        }
        self.metrics.listener(listener).refused_for_acl();
        tracing::debug!(%peer, transport = listener.label(), "connection refused: query ACL");
        false
    }

    /// Whether this source may be answered at all.
    ///
    /// Silent when it may not: answering a spoofed source is what an amplifier
    /// does. The refusal is counted (`CLAUDE.md` §14). `now` is the caller's:
    /// `rdnsr` reads it again after a recursion, so the wait's refill is not
    /// lost.
    pub fn allow_source(&self, peer: Peer, now: u64) -> bool {
        let judged = self.limiter.judge(peer, now);
        if judged.untracked {
            self.metrics.count(&self.metrics.rate_limiter_untracked);
        }
        if judged.verdict {
            return true;
        }
        self.logger.log_rate_limited(peer);
        self.metrics.count(&self.metrics.rate_limited);
        false
    }

    /// Whether this packet is worth parsing: the size cap for its transport and
    /// the per-section counts, on bytes nothing has trusted yet.
    ///
    /// Not validation: [`rdns::DnsMessage::try_from_bytes`] and
    /// [`rdns::validation::Request`] decide that. A failure is counted, and
    /// logged at DEBUG only if something listens: this is the flood path.
    pub fn accept_packet(&self, peer: Peer, packet: &[u8], transport: Transport) -> bool {
        let verdict = self.admission.validate_packet(packet, transport);
        if verdict.is_valid() {
            return true;
        }
        self.logger.count_error(peer);
        // `to_string` inside the macro's arguments: `tracing` evaluates them
        // only when something listens.
        tracing::debug!(
            peer = %peer,
            "invalid query: {}",
            verdict
                .error()
                .map_or_else(|| "unknown error".to_string(), |e| e.to_string())
        );
        self.metrics.count(&self.metrics.packets_rejected);
        false
    }

    /// Whether the answer already built may be sent, and the counting either
    /// refusal owes.
    ///
    /// The verdict, not the reply: `rdnsd` rebuilds a truncated answer from the
    /// question, `rdnsr` shortens its bytes (`TODO.md` #30j). `now` is the
    /// caller's, as for [`ServeContext::allow_source`].
    pub fn admit_response(&self, peer: Peer, len: usize, now: u64) -> ResponseVerdict {
        let judged = self.responses.judge(peer, len, now);
        if judged.untracked {
            self.metrics.count(&self.metrics.response_limiter_untracked);
        }
        let verdict = judged.verdict;
        match verdict {
            ResponseVerdict::Send => {}
            ResponseVerdict::Truncate => {
                self.logger.log_rate_limited(peer);
                self.metrics.count(&self.metrics.rate_limited);
            }
            ResponseVerdict::Drop => {
                self.logger.log_rate_limited(peer);
                self.metrics.count(&self.metrics.queries_dropped);
            }
        }
        verdict
    }

    /// Record an answer by the code it carries and how long it took.
    ///
    /// Here rather than at each `return`: an answer leaves a resolver from four
    /// places and the histogram has to see all four.
    pub fn record_answer(&self, rcode: ResponseCode, timer: LatencyTimer) {
        self.metrics.count_response(rcode);
        self.metrics.observe_latency_us(timer.elapsed_us());
    }
}

/// Who may be answered (`TODO.md` #171, `docs/adr/0007`).
///
/// Not `Option<TransferAcl>`: an empty `TransferAcl` allows nobody, so `None`
/// would mean the opposite of the list it stands beside (`CLAUDE.md` §17).
#[derive(Clone)]
pub enum QueryAcl {
    /// Everybody. `rdnsd`, and `rdnsr` bound to loopback only with no list.
    Open,
    /// The listed addresses and prefixes, matched as a [`Peer`]; nobody else,
    /// loopback included.
    Only(Arc<TransferAcl>),
}

impl QueryAcl {
    pub fn admits(&self, peer: Peer) -> bool {
        match self {
            QueryAcl::Open => true,
            QueryAcl::Only(acl) => acl.allows(peer),
        }
    }

    /// For the startup line.
    pub fn describe(&self) -> String {
        match self {
            QueryAcl::Open => "open (loopback listeners only)".to_string(),
            QueryAcl::Only(acl) => format!("{} --allow-query rule(s)", acl.len()),
        }
    }
}

/// How many connections one source may hold open on each stream listener:
/// `--max-connections-per-source`, and who is exempt.
///
/// Without it one peer could hold every slot with queries inside the idle
/// timeout. A source is a [`rdns::peer::Source`], so rotating within an IPv6
/// /56 gains nothing. Its own exempt list, apart from `--query-rate-exempt`.
/// Off by default; both daemons set it from their flag.
#[derive(Clone, Default)]
pub struct SourceConnections {
    /// 0 is off.
    limit: usize,
    exempt: Arc<TransferAcl>,
}

impl SourceConnections {
    pub fn new(limit: usize, exempt: TransferAcl) -> Self {
        SourceConnections {
            limit,
            exempt: Arc::new(exempt),
        }
    }

    /// For the startup line.
    pub fn describe(&self) -> String {
        match (self.limit, self.exempt.len()) {
            (0, _) => "no per-source limit".to_string(),
            (n, 0) => format!("{n} per source"),
            (n, rules) => format!("{n} per source, {rules} exempt rule(s)"),
        }
    }
}

/// `--max-connections-per-source`' default: about ten times what RFC 7766
/// §6.2.2 asks of a conforming client — one connection per purpose — and a
/// quarter of a listener's default ceiling.
pub const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: usize = 32;

/// `--max-connections`' default, per listener (`TODO.md` #155).
pub const DEFAULT_MAX_CONNECTIONS: NonZeroUsize = NonZeroUsize::new(128).unwrap();

/// `--connection-idle-timeout`'s default, in seconds.
pub const DEFAULT_IDLE_TIMEOUT_SECS: NonZeroU64 = NonZeroU64::new(10).unwrap();

/// What a connection may cost, per listener.
///
/// A struct, not shared `const`s, so the two daemons may differ. The connection
/// ceiling and the idle timeout are settings, as in BIND, NSD, Unbound and
/// Knot; the other two stay constants, which only Knot offers (`TODO.md` #155).
#[derive(Debug, Clone, Copy)]
pub struct TransportLimits {
    /// How long a connection may sit idle between messages. RFC 7766 §6.2.3
    /// wants connections reused rather than reopened; an idle one still costs a
    /// socket, so this is the compromise the RFC asks for.
    pub idle_timeout: Duration,
    /// How long the rest of a message may take once its length prefix arrived:
    /// mid-message the peer has committed to `len` bytes, so a stall gets a
    /// shorter leash than idle. Also how long a reply may go without progress
    /// (`write_progressing`), as Knot's `tcp-io-timeout` covers both.
    pub read_timeout: Duration,
    /// Concurrent connections. Without a ceiling, an accept loop that spawns per
    /// connection is a free file-descriptor exhaustion vector.
    pub max_connections: usize,
    /// Messages one connection may have in flight, which doubles as the reply
    /// channel's depth — so a client that pipelines faster than it reads pushes
    /// back on the read loop instead of growing a queue in memory. DoQ's
    /// stream credit and DoH's HTTP/2 stream limit too.
    pub max_inflight_per_connection: usize,
}

impl TransportLimits {
    /// The two settings an operator has, over the defaults of the rest.
    ///
    /// Non-zero by type: zero connections blocks every accept and a zero idle
    /// timeout fails the first length read, so clap and serde refuse `0` by
    /// name before anything binds (`CLAUDE.md` §15). "Zero is no limit" was
    /// declined because it reopens the descriptor exhaustion the ceiling is
    /// for — so, against §14, neither knob has an off switch.
    pub fn configured(max_connections: NonZeroUsize, idle_timeout_secs: NonZeroU64) -> Self {
        TransportLimits {
            max_connections: max_connections.get(),
            idle_timeout: Duration::from_secs(idle_timeout_secs.get()),
            ..TransportLimits::default()
        }
    }
}

impl Default for TransportLimits {
    fn default() -> Self {
        TransportLimits {
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS.get()),
            read_timeout: Duration::from_secs(5),
            max_connections: DEFAULT_MAX_CONNECTIONS.get(),
            max_inflight_per_connection: 16,
        }
    }
}

/// Write all of `buf`, failing with `TimedOut` once nothing has moved for
/// `stall`.
///
/// A deadline on progress rather than on the whole write: a peer that reads
/// nothing and one that reads slowly differ only in whether anything moves.
/// A whole-write deadline of 5 s on a 64 KB transfer envelope was a 13 KB/s
/// floor on every secondary (`TODO.md` #163).
pub(crate) async fn write_progressing<W>(
    writer: &mut W,
    mut buf: &[u8],
    stall: Duration,
) -> std::io::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
{
    use tokio::io::AsyncWriteExt;
    while !buf.is_empty() {
        match tokio::time::timeout(stall, writer.write(buf)).await {
            Ok(Ok(0)) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(Ok(n)) => buf = &buf[n..],
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("nothing written for {stall:?}"),
                ))
            }
        }
    }
    Ok(())
}

/// Serve until a listener stops or the operator does, then drain.
///
/// The first listener to end ends the process: half a server is worse than
/// none. `background` is awaited, not dropped (`CLAUDE.md` §9), and kept out of
/// the `JoinSet`, where `--anomaly-interval 0` returning at once would end it.
pub async fn serve_until_stopped(
    mut loops: tokio::task::JoinSet<Result<(), std::io::Error>>,
    background: tokio::task::JoinHandle<()>,
    shutdown: Shutdown,
) -> anyhow::Result<()> {
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
    // Awaiting them is what makes "stopped accepting" true before the drain
    // starts counting.
    while let Some(joined) = loops.join_next().await {
        if failure.is_none() {
            failure = listener_failure(joined);
        }
    }
    let _ = background.await;

    // Wait for work accepted before the stop: a client cannot tell a truncated
    // AXFR from a complete one.
    shutdown.drain_reporting().await;

    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// How a finished listener task is reported.
///
/// A cancelled task is not a failure: it is a task that was told to stop. Both
/// daemons had this, identical but for whether `anyhow!` was imported.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{context, query};
    use rdns::clock::current_unix_timestamp;
    use rdns::security::RateLimitConfig;

    /// The oversized-datagram case, tested through the raw code because
    /// WSAEMSGSIZE's `ErrorKind` is `Uncategorized` and carries no information.
    #[test]
    fn an_oversized_datagram_is_not_a_reason_to_stop_serving() {
        let too_big = std::io::Error::from_raw_os_error(WSAEMSGSIZE);
        assert!(
            recv_error_is_transient(&too_big),
            "WSAEMSGSIZE arrives as {:?}, which is why matching on the kind alone missed it",
            too_big.kind()
        );
    }

    #[test]
    fn a_stray_icmp_report_is_not_a_reason_to_stop_serving() {
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::NetworkUnreachable,
            std::io::ErrorKind::HostUnreachable,
        ] {
            assert!(
                recv_error_is_transient(&std::io::Error::from(kind)),
                "{kind:?}"
            );
        }
    }

    /// The predicate has to stay narrow: a server that cannot receive is not
    /// serving, and pretending otherwise looks healthy and answers nothing.
    #[test]
    fn a_broken_socket_is_still_fatal() {
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::AddrNotAvailable,
            std::io::ErrorKind::OutOfMemory,
        ] {
            assert!(
                !recv_error_is_transient(&std::io::Error::from(kind)),
                "{kind:?}"
            );
        }
    }

    /// Both refusals are silent on the wire, so both have to be visible in the
    /// counters — that is the whole reason they are not two `if`s at four call
    /// sites (`CLAUDE.md` §14).
    #[test]
    fn a_refusal_is_silent_and_counted() {
        let ctx = context(1);
        let peer = Peer::from("192.0.2.9".parse::<std::net::IpAddr>().unwrap());
        let now = current_unix_timestamp();

        assert!(ctx.allow_source(peer, now), "a burst of one admits one");
        assert!(!ctx.allow_source(peer, now), "and refuses the second");
        assert_eq!(
            ctx.metrics
                .rate_limited
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        assert!(ctx.accept_packet(peer, &query(0x1234), Transport::Udp));
        assert!(
            !ctx.accept_packet(peer, &[0x12, 0x34], Transport::Udp),
            "two octets cannot hold a header"
        );
        assert_eq!(
            ctx.metrics
                .packets_rejected
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// And so is the third refusal. The verdict is the daemons'; the counting,
    /// two counter increments, is not.
    ///
    /// Slip of two so both refusals appear: the first response over budget is
    /// dropped and the second truncated, which is what RRL's slip means.
    #[test]
    fn the_response_budget_is_a_refusal_too() {
        let ctx = ServeContext {
            responses: Arc::new(ResponseLimiter::new(100, 100, 2)),
            ..context(1)
        };
        let peer = Peer::from("192.0.2.11".parse::<std::net::IpAddr>().unwrap());
        let now = current_unix_timestamp();
        let counter =
            |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);

        assert_eq!(
            ctx.admit_response(peer, 100, now),
            ResponseVerdict::Send,
            "a burst of 100 bytes covers the first answer"
        );
        assert_eq!(ctx.admit_response(peer, 100, now), ResponseVerdict::Drop);
        assert_eq!(counter(&ctx.metrics.queries_dropped), 1);
        assert_eq!(
            ctx.admit_response(peer, 100, now),
            ResponseVerdict::Truncate
        );
        assert_eq!(counter(&ctx.metrics.rate_limited), 1);
    }

    /// Past `max_tracked` the query limiter admits and the response limiter
    /// truncates, and each says so in the scrape (`TODO.md` #157).
    #[test]
    fn a_full_limiter_table_is_counted_in_the_scrape() {
        let ctx = ServeContext {
            limiter: Arc::new(RateLimiter::new(RateLimitConfig {
                max_tracked: 1,
                ..RateLimitConfig::per_second(1, 1)
            })),
            responses: Arc::new(ResponseLimiter::per_second(1000).tracking_at_most(1)),
            ..context(1)
        };
        let now = current_unix_timestamp();
        let ip = |s: &str| Peer::from(s.parse::<std::net::IpAddr>().unwrap());
        let (a, b) = (ip("192.0.2.1"), ip("198.51.100.1"));

        assert!(ctx.allow_source(a, now));
        assert!(ctx.allow_source(b, now), "admitted with no bucket");
        assert_eq!(ctx.admit_response(a, 100, now), ResponseVerdict::Send);
        assert_eq!(ctx.admit_response(b, 100, now), ResponseVerdict::Truncate);

        let scrape = ctx.metrics.to_prometheus_format();
        assert!(
            scrape.contains("dns_rate_limiter_untracked_total 1"),
            "{scrape}"
        );
        assert!(
            scrape.contains("dns_response_limiter_untracked_total 1"),
            "{scrape}"
        );
    }

    /// The size cap is the transport's, which is the reason [`Transport`] is
    /// carried rather than an `is_tcp` bool.
    ///
    /// The two numbers moved with `TODO.md` #40f — the UDP cap is the payload
    /// size a daemon advertises it can reassemble (4,096), not RFC 1035 §4.2.1's
    /// 512, which is a limit on what a server may *send* — so this test's 1,024
    /// octets is now admitted on both and the boundary is 8 KiB. It asserted the
    /// old pair, which is a test encoding the bug (`CLAUDE.md` §1).
    #[test]
    fn the_size_cap_belongs_to_the_transport() {
        let ctx = context(0);
        let peer = Peer::from("192.0.2.10".parse::<std::net::IpAddr>().unwrap());
        let mut big = query(0x1234);
        big.resize(8 * 1024, 0);

        assert!(
            !ctx.accept_packet(peer, &big, Transport::Udp),
            "over the advertised 4096 on UDP"
        );
        assert!(
            ctx.accept_packet(peer, &big, Transport::Tcp),
            "and still under the TCP ceiling"
        );
    }

    /// The provocation is in `TODO.md` #69: at `ulimit -n`, `accept` returns
    /// this, and a loop that `?`s it ends the process because the first task
    /// out of the `JoinSet` ends it. `Uncategorized`, so the raw code is the
    /// whole test.
    #[tokio::test]
    async fn descriptor_exhaustion_does_not_end_an_accept_loop() {
        let exhausted = std::io::Error::from_raw_os_error(if cfg!(windows) { 10024 } else { 24 });
        // `Uncategorized` is unnameable on stable, so the claim is spelled as
        // what it is not: no kind recognizes this and only the raw code does.
        assert!(
            !matches!(
                exhausted.kind(),
                std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::OutOfMemory
            ),
            "{:?}",
            exhausted.kind()
        );
        assert!(survive_accept_error(exhausted, "tcp").await.is_ok());
    }

    /// A connection that died before the accept costs the next one nothing.
    #[tokio::test]
    async fn an_aborted_connection_is_retried_at_once() {
        let start = std::time::Instant::now();
        let aborted = std::io::Error::from(std::io::ErrorKind::ConnectionAborted);
        assert!(survive_accept_error(aborted, "tcp").await.is_ok());
        assert!(
            start.elapsed() < ACCEPT_BACKOFF,
            "no backoff for an aborted connection: {:?}",
            start.elapsed()
        );
    }

    /// Recovering from everything would turn a listener that cannot work into a
    /// loop that says so ten times a second forever.
    #[tokio::test]
    async fn a_listener_that_cannot_work_still_ends_the_loop() {
        let broken = std::io::Error::from(std::io::ErrorKind::InvalidInput);
        assert!(survive_accept_error(broken, "tcp").await.is_err());
    }
}
