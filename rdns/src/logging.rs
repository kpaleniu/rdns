use crate::utils::current_unix_timestamp;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// How many source addresses are counted individually at once.
///
/// The per-IP maps below are keyed on something an attacker chooses and can
/// forge, one entry per address, and nothing used to remove an entry —
/// `reset_stats` exists and is called from nothing but tests. With IPv6 source
/// addresses that is unbounded in practice: a spoofed-source flood costs the
/// attacker one 12-byte datagram per entry and the server a `HashMap` slot
/// forever, so the *monitoring* is the memory-exhaustion vector.
///
/// [`crate::security::ResponseLimiter`] already solved this two hundred lines
/// away, with a `max_tracked` and a `forget_idle`, and a comment explaining that
/// the table would otherwise be the next amplification vector. That reasoning
/// applies verbatim to the counters that run *first*; they simply never got it.
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
    /// Per-IP query counts, bounded by [`MAX_TRACKED_SOURCES`] — see
    /// [`note_source`] for what happens at the bound.
    pub queries_by_ip: HashMap<IpAddr, u64>,
    /// Per-record-type query counts. Bounded by the key space: there are only
    /// 65536 possible types, and no map of them is a DoS.
    pub queries_by_type: HashMap<u16, u64>,
    /// IPs with rate limiting triggered, bounded the same way.
    pub rate_limited_ips: HashMap<IpAddr, u64>,
    /// Queries from sources there was no room to count individually.
    ///
    /// Nonzero means the per-IP numbers are a sample rather than a census, and
    /// an operator reading a "top talkers" list needs to know that. It is also
    /// the signal that a source flood is happening at all.
    pub untracked_sources: u64,
}

/// Count one hit against `ip`, keeping the map bounded.
///
/// A source already being counted always is. A new one is admitted while there
/// is room; at the bound, every count is **halved** and the entries that reach
/// zero are forgotten. That keeps whoever is actually sending traffic — the
/// anomaly signal these counters exist for — and drops the single-datagram
/// sources a spoofed flood is made of. Halving is O(n) once per roughly n
/// admissions, so it is amortized constant per query, unlike a scan for the
/// smallest count on every insertion.
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
            // real one. Say so and move on rather than growing.
            *untracked = untracked.saturating_add(1);
            return;
        }
    }
    map.insert(ip, 1);
}

/// Query logger with anomaly detection
pub struct QueryLogger {
    stats: Arc<Mutex<QueryStats>>,
    last_qps_update: Arc<Mutex<u64>>,
    query_window: Arc<Mutex<QueryWindow>>,
}

struct QueryWindow {
    queries: Vec<u64>, // timestamps
    max_age_secs: u64,
}

impl QueryLogger {
    pub fn new() -> Self {
        QueryLogger {
            stats: Arc::new(Mutex::new(QueryStats {
                total_queries: 0,
                total_errors: 0,
                qps: 0.0,
                queries_by_ip: HashMap::new(),
                queries_by_type: HashMap::new(),
                rate_limited_ips: HashMap::new(),
                untracked_sources: 0,
            })),
            last_qps_update: Arc::new(Mutex::new(current_unix_timestamp())),
            query_window: Arc::new(Mutex::new(QueryWindow {
                queries: Vec::new(),
                max_age_secs: 10,
            })),
        }
    }

    /// Log a successful query
    pub fn log_query(&self, ip: IpAddr, query_type: Option<u16>) {
        let now = current_unix_timestamp();

        let mut stats = self.stats.lock().unwrap();
        stats.total_queries += 1;

        // Track per-IP queries, bounded — see `note_source`.
        let QueryStats {
            queries_by_ip,
            untracked_sources,
            ..
        } = &mut *stats;
        note_source(queries_by_ip, ip, untracked_sources, MAX_TRACKED_SOURCES);

        // Track per-type queries
        if let Some(qtype) = query_type {
            *stats.queries_by_type.entry(qtype).or_insert(0) += 1;
        }

        // Update query window for QPS calculation
        let max_age_secs = {
            let window = self.query_window.lock().unwrap();
            window.max_age_secs
        };

        let mut window = self.query_window.lock().unwrap();
        window.queries.push(now);

        // Remove old entries (older than max_age). Saturating, like every other
        // subtraction of two wall-clock stamps in this workspace: the clock can
        // step backwards, and an underflow here is a debug panic *while holding
        // the stats mutex*, which poisons it and takes every later query down
        // with it. Same defect as the one `security::RateLimiter` had.
        let age_limit = now.saturating_sub(max_age_secs);
        window.queries.retain(|&t| t > age_limit);

        // Update QPS periodically
        let mut last_update = self.last_qps_update.lock().unwrap();
        if now.saturating_sub(*last_update) >= 5 {
            *last_update = now;
            stats.qps = (window.queries.len() as f64) / max_age_secs as f64;
        }
    }

    /// Log a query error
    pub fn log_error(&self, _ip: IpAddr, reason: &str) {
        let mut stats = self.stats.lock().unwrap();
        stats.total_errors += 1;

        // Log detailed error message
        eprintln!("[QueryLogger] Error: {}", reason);
    }

    /// Log rate limit event
    pub fn log_rate_limited(&self, ip: IpAddr) {
        let mut stats = self.stats.lock().unwrap();
        let QueryStats {
            rate_limited_ips,
            untracked_sources,
            ..
        } = &mut *stats;
        // The map that most needs a bound: an entry here is created for a source
        // that was *refused*, which is exactly the traffic an attacker sends in
        // volume from addresses they do not own.
        note_source(rate_limited_ips, ip, untracked_sources, MAX_TRACKED_SOURCES);
    }

    /// Check for anomalies and print warnings
    pub fn check_anomalies(&self) {
        let stats = self.stats.lock().unwrap();

        // Check for high QPS
        if stats.qps > 50.0 {
            eprintln!(
                "[QueryLogger] WARNING: High QPS detected: {:.2} q/s",
                stats.qps
            );
        }

        // Check for high error rate
        let error_rate = if stats.total_queries > 0 {
            (stats.total_errors as f64) / (stats.total_queries as f64)
        } else {
            0.0
        };

        if error_rate > 0.1 {
            eprintln!(
                "[QueryLogger] WARNING: High error rate: {:.2}%",
                error_rate * 100.0
            );
        }

        // Check for IPs with many queries
        for (ip, count) in &stats.queries_by_ip {
            if *count > 100 {
                eprintln!(
                    "[QueryLogger] WARNING: High query count from {}: {}",
                    ip, count
                );
            }
        }

        if stats.untracked_sources > 0 {
            eprintln!(
                "[QueryLogger] WARNING: {} queries from sources there was no room to count                  individually — the per-IP figures below are a sample, not a census",
                stats.untracked_sources
            );
        }

        // Check for IPs that have been rate limited multiple times
        for (ip, count) in &stats.rate_limited_ips {
            if *count > 5 {
                eprintln!("[QueryLogger] WARNING: {} rate limited {} times", ip, count);
            }
        }
    }

    /// Get current statistics
    pub fn get_stats(&self) -> QueryStats {
        self.stats.lock().unwrap().clone()
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        let mut stats = self.stats.lock().unwrap();
        stats.total_queries = 0;
        stats.total_errors = 0;
        stats.qps = 0.0;
        stats.queries_by_ip.clear();
        stats.queries_by_type.clear();
        stats.rate_limited_ips.clear();
        stats.untracked_sources = 0;
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
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_logger_counts_queries() {
        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        logger.log_query(ip, Some(1));
        logger.log_query(ip, Some(1));
        logger.log_query(ip, Some(28));

        let stats = logger.get_stats();
        assert_eq!(stats.total_queries, 3);
        assert_eq!(*stats.queries_by_ip.get(&ip).unwrap(), 3);
        assert_eq!(*stats.queries_by_type.get(&1u16).unwrap(), 2);
        assert_eq!(*stats.queries_by_type.get(&28u16).unwrap(), 1);
    }

    #[test]
    fn test_logger_counts_errors() {
        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        logger.log_error(ip, "invalid packet");
        logger.log_error(ip, "parse error");

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

        logger.log_query(ip, Some(1));
        logger.log_error(ip, "error");

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
                Some(1),
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
            logger.log_query(heavy, Some(1));
        }
        for i in 0..(MAX_TRACKED_SOURCES as u32 * 2) {
            logger.log_query(
                IpAddr::V4(std::net::Ipv4Addr::from(i.wrapping_mul(2_654_435_761) | 1)),
                Some(1),
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

    #[test]
    fn test_logger_separate_ips() {
        let logger = QueryLogger::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        logger.log_query(ip1, Some(1));
        logger.log_query(ip2, Some(1));
        logger.log_query(ip2, Some(1));

        let stats = logger.get_stats();
        assert_eq!(*stats.queries_by_ip.get(&ip1).unwrap(), 1);
        assert_eq!(*stats.queries_by_ip.get(&ip2).unwrap(), 2);
    }
}
