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

pub mod tcp;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rdns::logging::QueryLogger;
use rdns::metrics::{DnsMetrics, LatencyTimer};
use rdns::security::{RateLimiter, ResponseLimiter};
use rdns::shutdown::{stop_signal, Shutdown};
use rdns::validation::AdmissionCheck;
use rdns::ResponseCode;

/// Which transport a message arrived on.
///
/// Not a bool: it decides the admission size cap (RFC 1035 §4.2.1's 512 against
/// a ceiling we chose), whether a reply may be truncated, and whether the peer
/// completed a handshake — three questions one `is_tcp` was answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Transport {
    pub fn is_tcp(self) -> bool {
        self == Transport::Tcp
    }
}

/// What a task needs to serve a request that is not the answer itself.
///
/// The five handles both daemons hold: `rdnsr` had them as `Shell` and `rdnsd`
/// as five loose fields of `Server`, same types and same purpose under two
/// spellings, which is how the admission pipeline came to be written twice
/// (`TODO.md` #32). `Arc`-cloned into every task, so this is a bag by
/// construction and says so in its name.
#[derive(Clone)]
pub struct ServeContext {
    /// Queries per second per source. The first refusal, and the cheapest.
    pub limiter: Arc<RateLimiter>,
    /// Response *bytes* per second per source, for UDP only — a TCP peer
    /// completed a handshake, so there is nobody to reflect at.
    pub responses: Arc<ResponseLimiter>,
    /// Size and section caps, applied before a packet is parsed.
    pub validator: Arc<AdmissionCheck>,
    /// Per-source counters and the periodic anomaly warnings.
    pub logger: Arc<QueryLogger>,
    /// What an operator scrapes.
    pub metrics: Arc<DnsMetrics>,
}

impl ServeContext {
    /// Whether this source may be answered at all.
    ///
    /// Silent when it may not: replying to a source that may be spoofed is what
    /// an amplifier does, which is why the effective policy is printed at
    /// startup and the refusal is counted here (`CLAUDE.md` §14).
    ///
    /// `now` is the caller's. `rdnsd` reads the clock once for the limiter, the
    /// logger and the TSIG check; `rdnsr` reads it again after a recursion,
    /// because charging a response against the query's instant would deny the
    /// bucket the refill the wait earned it. A pipeline that read the clock
    /// itself would silently pick the first of those (`TODO.md` #28a, #30e).
    pub fn allow_source(&self, peer: IpAddr, now: u64) -> bool {
        if self.limiter.should_allow(peer, now) {
            return true;
        }
        self.logger.log_rate_limited(peer);
        self.metrics.count(&self.metrics.rate_limited);
        false
    }

    /// Whether this packet is worth parsing: the size cap for its transport and
    /// the per-section counts, on bytes nothing has trusted yet.
    ///
    /// Not validation — a packet that passes is not known to be well formed.
    /// [`rdns::DnsMessage::try_from_bytes`] decides that, afterwards, and
    /// [`rdns::validation::Request`] decides whether it is a question at all.
    ///
    /// The failure is logged at DEBUG and counted: this is the path a flood
    /// takes, so the message must not be built unless somebody asked for it,
    /// and the counter is the signal in either case.
    pub fn accept_packet(&self, peer: IpAddr, packet: &[u8], transport: Transport) -> bool {
        let verdict = self.validator.validate_packet(packet, transport.is_tcp());
        if verdict.is_valid() {
            return true;
        }
        self.logger.count_error(peer);
        // The `to_string` is inside the macro's arguments on purpose: `tracing`
        // only evaluates those when something is listening, so a flood costs no
        // formatting at the default level.
        tracing::debug!(
            peer = %peer,
            "invalid query: {}",
            verdict
                .error()
                .map_or_else(|| "unknown error".to_string(), |e| e.to_string())
        );
        self.metrics.count(&self.metrics.validation_errors);
        false
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

/// What a connection may cost, per listener.
///
/// A struct rather than shared `const`s: one constant would force an
/// authoritative server and a recursive resolver to hold the same connection
/// ceiling forever, and they have no reason to (`TODO.md` #30b). The defaults
/// are what both daemons ran with, and each may take the field it disagrees
/// about without either editing the other's.
#[derive(Debug, Clone, Copy)]
pub struct TransportLimits {
    /// How long a connection may sit idle between messages. RFC 7766 §6.2.3
    /// wants connections reused rather than reopened; an idle one still costs a
    /// socket, so this is the compromise the RFC asks for.
    pub idle_timeout: Duration,
    /// How long the rest of a message may take once its length prefix arrived.
    /// Mid-message the peer has committed to `len` bytes, so a stall gets a much
    /// shorter leash than an idle connection.
    pub read_timeout: Duration,
    /// Concurrent connections. Without a ceiling, an accept loop that spawns per
    /// connection is a free file-descriptor exhaustion vector.
    pub max_connections: usize,
    /// Messages one connection may have in flight, which doubles as the reply
    /// channel's depth — so a client that pipelines faster than it reads pushes
    /// back on the read loop instead of growing a queue in memory.
    pub max_inflight_per_connection: usize,
}

impl Default for TransportLimits {
    fn default() -> Self {
        TransportLimits {
            idle_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
            max_connections: 128,
            max_inflight_per_connection: 16,
        }
    }
}

/// Serve until a listener stops or the operator does, then drain.
///
/// The epilogue both daemons had written out (`TODO.md` #30d): whichever
/// listener ends first ends the process, because answering on one transport and
/// not the other is worse than being plainly down; a signal is an orderly stop.
///
/// `background` is the task that is *not* a listener — the periodic anomaly
/// warnings — and is awaited rather than dropped, because dropping a
/// `JoinHandle` detaches the task instead of cancelling it (`CLAUDE.md` §9). It
/// is not in the `JoinSet` for a sharper reason: that set's rule is "the first
/// task to end ends the process", and `--anomaly-interval 0` returns at once.
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

    // Wait for work accepted before the stop. A client cannot tell a truncated
    // AXFR from a complete one, so cutting one mid-stream is the case this is
    // for.
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
pub fn listener_failure(
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
    use rdns::security::RateLimitConfig;
    use rdns::utils::current_unix_timestamp;

    fn context(rate: u32) -> ServeContext {
        ServeContext {
            limiter: Arc::new(RateLimiter::new(RateLimitConfig::per_second(rate, rate))),
            responses: Arc::new(ResponseLimiter::disabled()),
            validator: Arc::new(AdmissionCheck::with_defaults()),
            logger: Arc::new(QueryLogger::new()),
            metrics: Arc::new(DnsMetrics::new()),
        }
    }

    /// A minimal question: twelve octets of header and one question section.
    fn query() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, // id
            0x00, 0x00, // QR=0, opcode QUERY
            0x00, 0x01, // one question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(b"\x07example\x03com\x00");
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
        packet
    }

    /// Both refusals are silent on the wire, so both have to be visible in the
    /// counters — that is the whole reason they are not two `if`s at four call
    /// sites (`CLAUDE.md` §14).
    #[test]
    fn a_refusal_is_silent_and_counted() {
        let ctx = context(1);
        let peer: IpAddr = "192.0.2.9".parse().unwrap();
        let now = current_unix_timestamp();

        assert!(ctx.allow_source(peer, now), "a burst of one admits one");
        assert!(!ctx.allow_source(peer, now), "and refuses the second");
        assert_eq!(
            ctx.metrics
                .rate_limited
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        assert!(ctx.accept_packet(peer, &query(), Transport::Udp));
        assert!(
            !ctx.accept_packet(peer, &[0x12, 0x34], Transport::Udp),
            "two octets cannot hold a header"
        );
        assert_eq!(
            ctx.metrics
                .validation_errors
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// The size cap is the transport's, which is the reason [`Transport`] is
    /// carried rather than an `is_tcp` bool: 512 octets on UDP (RFC 1035
    /// §4.2.1) against the 16 KiB ceiling this codebase chose for TCP.
    #[test]
    fn the_size_cap_belongs_to_the_transport() {
        let ctx = context(0);
        let peer: IpAddr = "192.0.2.10".parse().unwrap();
        let mut big = query();
        big.resize(1024, 0);

        assert!(
            !ctx.accept_packet(peer, &big, Transport::Udp),
            "over 512 on UDP"
        );
        assert!(
            ctx.accept_packet(peer, &big, Transport::Tcp),
            "and well under the TCP ceiling"
        );
    }
}
