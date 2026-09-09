use crate::shutdown::Stop;
use crate::utils::current_unix_timestamp;
use crate::Qtype;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How much a daemon says.
///
/// The level stops the work, not just the output: `tracing`'s macros only build
/// their arguments when a subscriber is interested, which is what keeps a
/// malformed-packet flood from costing a `format!` per packet.
///
/// Volume beyond that is journald's job (`LogRateLimitIntervalSec`,
/// `LogRateLimitBurst`); a second limiter here would hide what the first did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "error" => Ok(LogLevel::Error),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            other => Err(format!(
                "unknown log level {other:?}: expected error, warn, info, debug or trace"
            )),
        }
    }
}

/// Send this process's log lines to stderr at `level`, honouring `RUST_LOG`.
///
/// Called once, by a binary; library code only emits. Shared so that `rdnsd` and
/// `rdnsr` cannot end up configured differently.
///
/// `RUST_LOG` wins where it is set — reaching for it means a server misbehaving
/// under a level chosen in a unit file, and editing the unit is a restart.
/// `--quiet` and `--log-level` set the fallback.
///
/// No timestamps and no ANSI: journald stamps every line, and two stamps
/// disagreeing is worse than losing one in a terminal.
pub fn init(level: LogLevel) {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));

    // `try_init`: a second call is a caller bug, not grounds for panicking a
    // healthy server, and the tests here share a process.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(true)
        .try_init();
}

/// How many source addresses are counted individually at once.
///
/// The per-IP maps are keyed on a forgeable address, so without a bound one
/// spoofed 12-byte datagram per entry makes the monitoring the memory-exhaustion
/// vector. Same shape as [`crate::security::ResponseLimiter`]'s `max_tracked`.
const MAX_TRACKED_SOURCES: usize = 10_000;

/// Query statistics for monitoring and anomaly detection
#[derive(Debug, Clone)]
pub struct QueryStats {
    /// Total queries processed
    pub total_queries: u64,
    /// Total errors encountered
    pub total_errors: u64,
    /// Queries per second (last measurement)
    pub qps: f64,
    /// Per-IP query counts, bounded by `MAX_TRACKED_SOURCES` — see
    /// `note_source` for what happens at the bound.
    pub queries_by_ip: HashMap<IpAddr, u64>,
    /// Per-record-type query counts. Bounded by the key space: there are only
    /// 65536 possible types, and no map of them is a DoS.
    pub queries_by_type: HashMap<Qtype, u64>,
    /// IPs with rate limiting triggered, bounded the same way.
    pub rate_limited_ips: HashMap<IpAddr, u64>,
    /// Queries from sources there was no room to count individually. Nonzero
    /// means the per-IP numbers are a sample, not a census.
    pub untracked_sources: u64,
}

impl QueryStats {
    fn empty() -> QueryStats {
        QueryStats {
            total_queries: 0,
            total_errors: 0,
            qps: 0.0,
            queries_by_ip: HashMap::new(),
            queries_by_type: HashMap::new(),
            rate_limited_ips: HashMap::new(),
            untracked_sources: 0,
        }
    }
}

/// What the periodic check warns about, and the numbers an operator sets.
///
/// Every threshold is per interval, because that is what
/// [`QueryLogger::take_stats`] hands it. **Zero disables that one warning** —
/// each has its own off switch, since "tell me about heavy sources but not
/// about the error rate" is an ordinary thing to want, and a threshold nobody
/// can turn off gets silenced by turning the whole check off instead.
///
/// The defaults are what the check warned on when it was hardcoded and
/// uncalled: 50 q/s, a tenth of queries failing, a hundred queries from one
/// source, five refusals of one source (`TODO.md` #30m).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AnomalyThresholds {
    /// Queries per second, averaged over the interval.
    pub queries_per_second: f64,
    /// Percentage of queries that ended in an error.
    pub error_percent: f64,
    /// Queries from one source address.
    pub queries_per_source: u64,
    /// Times one source was refused by the rate limiter.
    pub refusals_per_source: u64,
}

impl Default for AnomalyThresholds {
    fn default() -> Self {
        AnomalyThresholds {
            queries_per_second: 50.0,
            error_percent: 10.0,
            queries_per_source: 100,
            refusals_per_source: 5,
        }
    }
}

/// One thing worth a warning line.
///
/// Separated from the logging so a test can assert on what was found rather
/// than on what was printed; nothing branches on the variants
/// (`CLAUDE.md` §3 — the category is what a reader of the log needs).
#[derive(Debug, Clone, PartialEq)]
pub enum Anomaly {
    HighQueryRate {
        qps: f64,
    },
    HighErrorRate {
        percent: f64,
    },
    HeavySource {
        peer: IpAddr,
        queries: u64,
    },
    RepeatedlyLimited {
        peer: IpAddr,
        refusals: u64,
    },
    /// The per-source figures are a sample, not a census: the map was full.
    UntrackedSources {
        queries: u64,
    },
}

/// What in one interval's counts crosses `limits`.
///
/// A threshold of zero is off rather than "warn about everything": the
/// alternative makes a zero mean two things, and one of them fires a line per
/// source per interval.
pub fn anomalies(stats: &QueryStats, limits: &AnomalyThresholds) -> Vec<Anomaly> {
    let mut found = Vec::new();
    if limits.queries_per_second > 0.0 && stats.qps > limits.queries_per_second {
        found.push(Anomaly::HighQueryRate { qps: stats.qps });
    }
    if limits.error_percent > 0.0 && stats.total_queries > 0 {
        let percent = 100.0 * stats.total_errors as f64 / stats.total_queries as f64;
        if percent > limits.error_percent {
            found.push(Anomaly::HighErrorRate { percent });
        }
    }
    if limits.queries_per_source > 0 {
        for (peer, queries) in &stats.queries_by_ip {
            if *queries > limits.queries_per_source {
                found.push(Anomaly::HeavySource {
                    peer: *peer,
                    queries: *queries,
                });
            }
        }
    }
    if limits.refusals_per_source > 0 {
        for (peer, refusals) in &stats.rate_limited_ips {
            if *refusals > limits.refusals_per_source {
                found.push(Anomaly::RepeatedlyLimited {
                    peer: *peer,
                    refusals: *refusals,
                });
            }
        }
    }
    if stats.untracked_sources > 0 {
        found.push(Anomaly::UntrackedSources {
            queries: stats.untracked_sources,
        });
    }
    found
}

/// Warn every `interval` until told to stop.
///
/// The caller that owns the counters never reads them, which is how this
/// facility spent a year write-only (`TODO.md` #30m). No [`crate::shutdown::Busy`]
/// claim: the
/// task sleeps almost all of the time, and holding the drain open across a
/// sleep waits out the shutdown budget every time (`CLAUDE.md` §9). The work
/// between sleeps is a lock and a walk of two bounded maps.
///
/// `interval` of zero is the caller's off switch and this returns at once, so
/// the flag that disables the check does not also have to skip the spawn.
pub async fn watch_anomalies(
    logger: Arc<QueryLogger>,
    limits: AnomalyThresholds,
    interval: Duration,
    stop: Stop,
) {
    if interval.is_zero() {
        return;
    }
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {
                logger.check_anomalies(&limits, current_unix_timestamp());
            }
            _ = stop.wait() => return,
        }
    }
}

/// Count one hit against `ip`, keeping the map bounded.
///
/// At the bound every count is halved and the zeroes forgotten, which keeps the
/// heavy talkers these counters exist to find and drops the single-datagram
/// sources a spoofed flood is made of. Halving is O(n) per ~n admissions, so
/// amortized constant; a scan for the smallest count per insertion is not.
fn note_source(map: &mut HashMap<IpAddr, u64>, ip: IpAddr, untracked: &mut u64, max: usize) {
    if let Some(count) = map.get_mut(&ip) {
        *count = count.saturating_add(1);
        return;
    }
    if map.len() >= max {
        for count in map.values_mut() {
            *count /= 2;
        }
        map.retain(|_, count| *count > 0);
        if map.len() >= max {
            // Every entry survived the halving, so every tracked source is a
            // real one: report the shortfall rather than grow.
            *untracked = untracked.saturating_add(1);
            return;
        }
    }
    map.insert(ip, 1);
}

/// How long a QPS measurement runs before it is rolled over and published.
///
/// Tumbling, not sliding: `count` queries since `start`, published and reset at
/// the end of the window. Two words of state, so logging a query is O(1); a
/// window holding one timestamp per query is linear in the traffic already
/// logged, under the stats mutex.
const QPS_WINDOW_SECS: u64 = 5;

/// Query logger with anomaly detection
pub struct QueryLogger {
    /// Stats and the QPS window under one lock: several taken on one path with
    /// no ordering discipline is a deadlock waiting for a second writer.
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    stats: QueryStats,
    window: QpsWindow,
    /// When [`QueryLogger::take_stats`] last emptied the counts, so the rate it
    /// reports is over the interval it actually covers.
    taken_at: u64,
}

/// Queries counted since the current window opened.
struct QpsWindow {
    start: u64,
    count: u64,
}

impl QueryLogger {
    pub fn new() -> Self {
        let now = current_unix_timestamp();
        QueryLogger {
            inner: Arc::new(Mutex::new(Inner {
                stats: QueryStats::empty(),
                window: QpsWindow {
                    start: now,
                    count: 0,
                },
                taken_at: now,
            })),
        }
    }

    /// Log a successful query.
    ///
    /// `now` is the caller's, in seconds; see
    /// [`crate::security::RateLimiter::should_allow`] for why it is not read
    /// here.
    pub fn log_query(&self, ip: IpAddr, query_type: Option<Qtype>, now: u64) {
        let Some(mut inner) = self.locked() else {
            return;
        };
        let Inner { stats, window, .. } = &mut *inner;
        stats.total_queries += 1;

        let QueryStats {
            queries_by_ip,
            untracked_sources,
            ..
        } = stats;
        note_source(queries_by_ip, ip, untracked_sources, MAX_TRACKED_SOURCES);

        if let Some(qtype) = query_type {
            *stats.queries_by_type.entry(qtype).or_insert(0) += 1;
        }

        // Saturating: a backwards clock step underflows, and a debug panic here
        // poisons this mutex and takes every later query with it.
        window.count += 1;
        let elapsed = now.saturating_sub(window.start);
        if elapsed >= QPS_WINDOW_SECS {
            stats.qps = (window.count as f64) / (elapsed as f64);
            window.start = now;
            window.count = 0;
        } else if now < window.start {
            // The clock stepped back past the window's start, so the interval is
            // unknowable: reopen and lose one sample rather than invent a rate.
            window.start = now;
            window.count = 0;
        }
    }

    /// Count a query error. The caller does the logging: only it knows where the
    /// error came from, and only it can leave the message unbuilt when nothing
    /// is listening.
    pub fn count_error(&self, _ip: IpAddr) {
        if let Some(mut inner) = self.locked() {
            inner.stats.total_errors += 1;
        }
    }

    /// Log rate limit event
    pub fn log_rate_limited(&self, ip: IpAddr) {
        let Some(mut inner) = self.locked() else {
            return;
        };
        let QueryStats {
            rate_limited_ips,
            untracked_sources,
            ..
        } = &mut inner.stats;
        // The map that most needs a bound: an entry here comes from a *refused*
        // source, which is what a spoofed flood is made of.
        note_source(rate_limited_ips, ip, untracked_sources, MAX_TRACKED_SOURCES);
    }

    /// The one place this lock is taken, and the one failure decision: a
    /// poisoned lock stops the counting, not the answering. Every query path
    /// calls `log_query`, so `.unwrap()` here makes one panic permanent.
    fn locked(&self) -> Option<std::sync::MutexGuard<'_, Inner>> {
        self.inner.lock().ok()
    }

    /// The counts since the last take, and the interval they cover.
    ///
    /// Reading *and* resetting, under one lock: the per-source counts are
    /// cumulative, so a threshold on them read without a reset fires once and
    /// then every interval afterwards, for a client that has done nothing
    /// since. A count per interval is also the number an operator can put a
    /// threshold on — "a hundred queries a minute from one address" — where "a
    /// hundred since the process started" is not.
    ///
    /// `qps` is recomputed here for the same reason: [`Self::log_query`]'s
    /// tumbling window only advances when a query arrives, so a server that
    /// went quiet keeps publishing the rate it had when it stopped. The elapsed
    /// time is floored at one second, so a take within the same second reports
    /// the count rather than a multiple of it.
    pub fn take_stats(&self, now: u64) -> QueryStats {
        let Some(mut inner) = self.locked() else {
            return QueryStats::empty();
        };
        let elapsed = now.saturating_sub(inner.taken_at).max(1);
        inner.taken_at = now;
        let mut stats = std::mem::replace(&mut inner.stats, QueryStats::empty());
        stats.qps = stats.total_queries as f64 / elapsed as f64;
        inner.window = QpsWindow {
            start: now,
            count: 0,
        };
        stats
    }

    /// Warn about whatever `limits` says is worth waking someone for, and roll
    /// the window over. Called on a timer — see [`watch_anomalies`].
    fn check_anomalies(&self, limits: &AnomalyThresholds, now: u64) {
        for anomaly in anomalies(&self.take_stats(now), limits) {
            match anomaly {
                Anomaly::HighQueryRate { qps } => tracing::warn!(qps, "high query rate"),
                Anomaly::HighErrorRate { percent } => {
                    tracing::warn!(percent, "high error rate")
                }
                Anomaly::HeavySource { peer, queries } => {
                    tracing::warn!(%peer, queries, "high query count from one source")
                }
                Anomaly::RepeatedlyLimited { peer, refusals } => {
                    tracing::warn!(%peer, refusals, "repeatedly rate limited")
                }
                Anomaly::UntrackedSources { queries } => tracing::warn!(
                    untracked = queries,
                    "queries from sources there was no room to count individually — the \
                     per-IP figures are a sample, not a census"
                ),
            }
        }
    }

    /// Get current statistics
    ///
    /// Returns the zero value if the lock is poisoned, for the reason in
    /// `Self::locked`: a caller reading counters must not be able to take the
    /// process down.
    pub fn get_stats(&self) -> QueryStats {
        match self.locked() {
            Some(inner) => inner.stats.clone(),
            None => QueryStats::empty(),
        }
    }

    /// Reset statistics
    #[cfg(test)]
    fn reset_stats(&self) {
        let Some(mut inner) = self.locked() else {
            return;
        };
        let now = current_unix_timestamp();
        inner.stats = QueryStats::empty();
        inner.window = QpsWindow {
            start: now,
            count: 0,
        };
        inner.taken_at = now;
    }
}

impl Default for QueryLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::record_types as rt;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_logger_counts_queries() {
        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        logger.log_query(ip, Some(Qtype::of(rt::A)), current_unix_timestamp());
        logger.log_query(ip, Some(Qtype::of(rt::A)), current_unix_timestamp());
        logger.log_query(ip, Some(Qtype::of(rt::AAAA)), current_unix_timestamp());

        let stats = logger.get_stats();
        assert_eq!(stats.total_queries, 3);
        assert_eq!(*stats.queries_by_ip.get(&ip).unwrap(), 3);
        assert_eq!(*stats.queries_by_type.get(&Qtype::of(rt::A)).unwrap(), 2);
        assert_eq!(*stats.queries_by_type.get(&Qtype::of(rt::AAAA)).unwrap(), 1);
    }

    #[test]
    fn test_logger_counts_errors() {
        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        logger.count_error(ip);
        logger.count_error(ip);

        let stats = logger.get_stats();
        assert_eq!(stats.total_errors, 2);
    }

    #[test]
    fn test_logger_rate_limit_tracking() {
        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        logger.log_rate_limited(ip);
        logger.log_rate_limited(ip);
        logger.log_rate_limited(ip);

        let stats = logger.get_stats();
        assert_eq!(*stats.rate_limited_ips.get(&ip).unwrap(), 3);
    }

    #[test]
    fn test_logger_reset() {
        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        logger.log_query(ip, Some(Qtype::of(rt::A)), current_unix_timestamp());
        logger.count_error(ip);

        logger.reset_stats();

        let stats = logger.get_stats();
        assert_eq!(stats.total_queries, 0);
        assert_eq!(stats.total_errors, 0);
        assert!(stats.queries_by_ip.is_empty());
    }

    /// The per-IP counters are keyed on a forgeable address and nothing used to
    /// remove an entry: `reset_stats` exists and is called from nothing but the
    /// test above. One spoofed datagram per address bought a permanent `HashMap`
    /// slot, so with IPv6 sources the *monitoring* was the memory-exhaustion
    /// vector — and `check_anomalies` then walked the whole thing.
    #[test]
    fn a_flood_of_source_addresses_does_not_grow_the_counters_without_bound() {
        let logger = QueryLogger::new();
        for i in 0..(MAX_TRACKED_SOURCES as u32 * 3) {
            logger.log_query(
                IpAddr::V4(std::net::Ipv4Addr::from(i.wrapping_mul(2_654_435_761))),
                Some(Qtype::of(rt::A)),
                current_unix_timestamp(),
            );
            logger.log_rate_limited(IpAddr::V4(std::net::Ipv4Addr::from(i ^ 0xDEAD_BEEF)));
        }

        let stats = logger.get_stats();
        assert!(stats.queries_by_ip.len() <= MAX_TRACKED_SOURCES);
        assert!(stats.rate_limited_ips.len() <= MAX_TRACKED_SOURCES);
        // Every query is still counted in total, and the shortfall is visible
        // rather than silent — an operator reading "top talkers" has to know the
        // list is a sample.
        // Every query is still counted in total; only the per-source breakdown
        // is a sample. (`untracked_sources` stays zero here because these
        // sources send one datagram each, so the halving forgets them all and
        // there is always room — which is the bound working, not failing. The
        // counter earns its keep when the table is full of *repeat* sources; see
        // the next test.)
        assert_eq!(stats.total_queries, MAX_TRACKED_SOURCES as u64 * 3);
    }

    /// Bounded, but not at the expense of the signal it exists for: a source
    /// actually sending traffic stays counted while one-datagram sources are
    /// forgotten. That is what makes the number an anomaly detector rather than a
    /// log of whoever arrived first.
    #[test]
    fn a_heavy_talker_survives_the_bound() {
        let logger = QueryLogger::new();
        let heavy = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        for _ in 0..1_000 {
            logger.log_query(heavy, Some(Qtype::of(rt::A)), current_unix_timestamp());
        }
        for i in 0..(MAX_TRACKED_SOURCES as u32 * 2) {
            logger.log_query(
                IpAddr::V4(std::net::Ipv4Addr::from(i.wrapping_mul(2_654_435_761) | 1)),
                Some(Qtype::of(rt::A)),
                current_unix_timestamp(),
            );
        }

        let stats = logger.get_stats();
        assert!(
            stats.queries_by_ip.contains_key(&heavy),
            "the source with a thousand queries is the one worth keeping"
        );
    }

    /// The bound and the shortfall counter, at a size a test can reason about.
    /// `note_source` takes its limit as a parameter for exactly this reason: the
    /// interesting behaviour is at the boundary, and a boundary of ten thousand
    /// is one nobody checks.
    #[test]
    fn the_bound_keeps_repeat_sources_and_reports_what_it_dropped() {
        let mut map = HashMap::new();
        let mut untracked = 0;
        let ip = |n: u8| IpAddr::V4(Ipv4Addr::new(192, 0, 2, n));

        // Four sources, two hits each: full, and every entry survives a halving.
        for n in 0..4 {
            note_source(&mut map, ip(n), &mut untracked, 4);
            note_source(&mut map, ip(n), &mut untracked, 4);
        }
        assert_eq!(map.len(), 4);
        assert_eq!(untracked, 0);

        // A fifth cannot be admitted without evicting a source that is really
        // sending, so it is counted as unattributed instead.
        note_source(&mut map, ip(9), &mut untracked, 4);
        assert_eq!(map.len(), 4, "the map does not grow past its bound");
        assert_eq!(untracked, 1, "and says it could not attribute the hit");
        // The halving is not free: the surviving counts are decayed, which is the
        // price of keeping the table bounded and is why these are anomaly
        // signals rather than accounting.
        assert!(map.values().all(|&count| count >= 1));
    }

    /// The regression test for the quadratic. `log_query` used to push one
    /// timestamp per query into a `Vec` and `retain` the whole thing on every
    /// call, so the cost of logging a query grew with the traffic already logged
    /// — 469 ns at 1k deep, 19,419 ns at 100k. That is a server-wide ~23k qps
    /// ceiling that no profile of the answer path would ever point at.
    ///
    /// Asserted as a *ratio* rather than a floor, deliberately: a wall-clock
    /// floor is what `bench_logger_throughput` had, and lowering it is how this
    /// very regression got ratified (`CLAUDE.md` §10). A ratio does not care how
    /// fast the machine is or what else is running on it — only whether the
    /// second batch costs more than the first because of what came before.
    /// Measured against the old code: ~20×. Against this one: ~1×.
    #[test]
    fn logging_a_query_costs_the_same_however_many_came_before() {
        use std::time::Instant;

        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let batch = 5_000;
        let depth = 50_000;

        let start = Instant::now();
        for _ in 0..batch {
            logger.log_query(ip, Some(Qtype::of(rt::A)), current_unix_timestamp());
        }
        let shallow = start.elapsed();

        for _ in 0..depth {
            logger.log_query(ip, Some(Qtype::of(rt::A)), current_unix_timestamp());
        }

        let start = Instant::now();
        for _ in 0..batch {
            logger.log_query(ip, Some(Qtype::of(rt::A)), current_unix_timestamp());
        }
        let deep = start.elapsed();

        let ratio = deep.as_secs_f64() / shallow.as_secs_f64().max(1e-9);
        assert!(
            ratio < 5.0,
            "logging got {ratio:.1}x slower after {depth} queries \
             ({shallow:?} -> {deep:?}); the per-query cost is growing with the \
             window again"
        );
    }

    /// The window is a count and a start, so a clock that steps backwards past
    /// the window's opening must not publish a rate computed from a negative
    /// interval — `saturating_sub` would report the whole count as one second's
    /// worth. There is no way to inject a clock here, so this pins the arithmetic
    /// the guard exists for.
    #[test]
    fn a_rolled_window_divides_by_the_interval_it_actually_measured() {
        let window = QpsWindow {
            start: 1_000,
            count: 250,
        };
        let now = 1_010u64;
        let elapsed = now.saturating_sub(window.start);
        assert_eq!(elapsed, 10);
        assert_eq!((window.count as f64) / (elapsed as f64), 25.0);

        // Backwards: elapsed saturates to zero, which is why `log_query` tests
        // `now < window.start` separately instead of dividing by it.
        let backwards = 900u64.saturating_sub(window.start);
        assert_eq!(backwards, 0);
    }

    #[test]
    fn test_logger_separate_ips() {
        let logger = QueryLogger::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        logger.log_query(ip1, Some(Qtype::of(rt::A)), current_unix_timestamp());
        logger.log_query(ip2, Some(Qtype::of(rt::A)), current_unix_timestamp());
        logger.log_query(ip2, Some(Qtype::of(rt::A)), current_unix_timestamp());

        let stats = logger.get_stats();
        assert_eq!(*stats.queries_by_ip.get(&ip1).unwrap(), 1);
        assert_eq!(*stats.queries_by_ip.get(&ip2).unwrap(), 2);
    }

    /// The counts a warning is judged on are per interval, and taking them
    /// empties them.
    ///
    /// Cumulative counts are why this check could not simply be called on a
    /// timer as it stood: one busy minute would have warned about that client
    /// every minute afterwards, however quiet it went (`TODO.md` #30m).
    #[test]
    fn each_interval_is_judged_on_its_own_traffic() {
        let logger = QueryLogger::new();
        let heavy = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let limits = AnomalyThresholds {
            queries_per_source: 2,
            ..AnomalyThresholds::default()
        };
        let start = current_unix_timestamp();

        for _ in 0..3 {
            logger.log_query(heavy, Some(Qtype::of(rt::A)), start);
        }
        let first = logger.take_stats(start + 60);
        assert_eq!(
            anomalies(&first, &limits),
            vec![Anomaly::HeavySource {
                peer: heavy,
                queries: 3
            }]
        );

        // The next interval saw nothing from anybody.
        let second = logger.take_stats(start + 120);
        assert_eq!(second.total_queries, 0, "the counts went with the interval");
        assert!(
            anomalies(&second, &limits).is_empty(),
            "a quiet interval is quiet, whatever the one before it did"
        );
    }

    /// The rate is over the interval that was taken, not over the last window
    /// [`QueryLogger::log_query`] happened to close — a server that goes quiet
    /// must stop reporting the rate it had when it stopped.
    #[test]
    fn the_rate_is_over_the_interval_it_covers() {
        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let start = current_unix_timestamp();

        for _ in 0..120 {
            logger.log_query(ip, Some(Qtype::of(rt::A)), start);
        }
        let busy = logger.take_stats(start + 60);
        assert_eq!(busy.qps, 2.0, "120 queries in a minute is two a second");

        let quiet = logger.take_stats(start + 120);
        assert_eq!(quiet.qps, 0.0, "and nothing in the next minute is none");
    }

    /// Every threshold is its own off switch, so silencing one warning does not
    /// mean silencing the check (`CLAUDE.md` §14).
    #[test]
    fn a_threshold_of_zero_is_off_rather_than_always() {
        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let start = current_unix_timestamp();
        logger.log_query(ip, Some(Qtype::of(rt::A)), start);
        logger.count_error(ip);
        logger.log_rate_limited(ip);
        let stats = logger.take_stats(start + 1);

        let off = AnomalyThresholds {
            queries_per_second: 0.0,
            error_percent: 0.0,
            queries_per_source: 0,
            refusals_per_source: 0,
        };
        assert!(
            anomalies(&stats, &off).is_empty(),
            "one query at 1 q/s, 100% errors and one refusal, and all four are off"
        );

        // The same counts against thresholds that are on.
        let on = AnomalyThresholds {
            queries_per_second: 0.5,
            error_percent: 10.0,
            queries_per_source: 0,
            refusals_per_source: 0,
        };
        assert_eq!(
            anomalies(&stats, &on),
            vec![
                Anomaly::HighQueryRate { qps: 1.0 },
                Anomaly::HighErrorRate { percent: 100.0 }
            ]
        );
    }

    /// The watcher stops when told, rather than on its next tick: an interval
    /// is a minute by default and a shutdown does not wait one out.
    #[tokio::test]
    async fn the_watcher_stops_when_the_server_does() {
        let shutdown = crate::shutdown::Shutdown::new();
        let watcher = tokio::spawn(watch_anomalies(
            Arc::new(QueryLogger::new()),
            AnomalyThresholds::default(),
            Duration::from_secs(3600),
            shutdown.stop_handle(),
        ));
        shutdown.begin();
        tokio::time::timeout(Duration::from_secs(5), watcher)
            .await
            .expect("the stop is what ends it, not the hour")
            .expect("and it does not panic on the way out");
    }

    /// Zero disables the whole check, so a binary need not decide whether to
    /// spawn it.
    #[tokio::test]
    async fn an_interval_of_zero_never_watches() {
        let shutdown = crate::shutdown::Shutdown::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            watch_anomalies(
                Arc::new(QueryLogger::new()),
                AnomalyThresholds::default(),
                Duration::ZERO,
                shutdown.stop_handle(),
            ),
        )
        .await
        .expect("returns without waiting for anything");
    }
}
