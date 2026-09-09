use crate::error::{ConfigError, ConfigResult};
use crate::utils::current_unix_timestamp;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Number of tokens available per window. Zero turns the limiter off.
    pub tokens_per_window: u32,
    /// Window size in seconds
    pub window_size_secs: u64,
    /// Maximum burst size
    pub burst_size: u32,
    /// Cleanup interval for inactive IPs (in seconds)
    pub cleanup_interval_secs: u64,
    /// The most source addresses tracked at once. See [`RateLimiter`].
    pub max_tracked: usize,
    /// Addresses the limit does not apply to. Empty by default: nobody is
    /// exempt unless an operator says so.
    pub exempt: TransferAcl,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            tokens_per_window: 100,     // 100 queries per window
            window_size_secs: 10,       // 10 second window
            burst_size: 20,             // Allow burst of 20
            cleanup_interval_secs: 600, // 10 minute cleanup
            max_tracked: 10_000,        // See RateLimiter: the table is attacker-keyed
            exempt: TransferAcl::default(),
        }
    }
}

impl RateLimitConfig {
    /// A limit in the unit an operator states it in: queries per second, and how
    /// many may arrive at once before the rate applies.
    ///
    /// `per_sec` of 0 disables the limiter entirely; [`ResponseLimiter`] is the
    /// control that actually stops amplification.
    pub fn per_second(per_sec: u32, burst: u32) -> Self {
        RateLimitConfig {
            tokens_per_window: per_sec,
            window_size_secs: 1,
            // A burst of zero would refuse every query outright, since a bucket
            // starts full and a full bucket of nothing has no token to spend.
            burst_size: burst.max(1),
            ..Default::default()
        }
    }

    /// Exempt these addresses (bare or CIDR) from the limit.
    pub fn exempting(mut self, exempt: TransferAcl) -> Self {
        self.exempt = exempt;
        self
    }
}

/// Per-IP token bucket state
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: u64,
}

/// Rate limiter using token bucket algorithm.
///
/// The table is attacker-keyed: a bucket is created before anything validates the
/// packet. Above `max_tracked` no new bucket is created and the packet is
/// *allowed*, because failing closed lets one flood deny service to everybody.
///
/// `current_unix_timestamp` is wall-clock, so all time arithmetic here saturates:
/// a backwards NTP step would otherwise underflow and refill every bucket.
///
/// **One mutex, and it is the ceiling.** Every UDP worker takes `buckets` for
/// every datagram, so the limiter serializes what the pool parallelizes. At
/// ~4 µs of syscall per query it is nowhere near the bottleneck and sharding it
/// would be premature — but it is the first thing to shard if a query ever gets
/// cheap enough to notice, and that is worth saying here rather than leaving to
/// be rediscovered under load (`TODO.md` #25f).
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
    /// When the sweep last ran. An `AtomicU64` and not a `Mutex`: this is read
    /// on every datagram to decide *not* to sweep, and a lock for that made the
    /// common path two mutexes deep for one comparison.
    last_cleanup: AtomicU64,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        RateLimiter {
            config,
            buckets: Arc::new(Mutex::new(HashMap::new())),
            last_cleanup: AtomicU64::new(current_unix_timestamp()),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Check if a request from the given IP should be allowed.
    ///
    /// `now` is the caller's, in seconds: one datagram passes through this, the
    /// logger and the response budget, and each read its own clock — four
    /// `SystemTime::now` calls for one instant, 24-26 ns each. See `TODO.md`
    /// #28a. The value is seconds old at worst and every bucket here is
    /// second-granularity.
    pub fn should_allow(&self, ip: IpAddr, now: u64) -> bool {
        // Before the lock and before a bucket is created: a disabled limiter must
        // not be a mutex on every query.
        if self.config.tokens_per_window == 0 || self.config.exempt.allows(ip) {
            return true;
        }

        // Cleanup old entries periodically
        self.cleanup_if_needed(now);

        let Ok(mut buckets) = self.buckets.lock() else {
            // Poisoned: state unknown. Allow, rather than answer nothing until
            // restarted.
            return true;
        };
        if !buckets.contains_key(&ip) && buckets.len() >= self.config.max_tracked {
            return true;
        }
        let bucket = buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.config.burst_size as f64,
            last_refill: now,
        });

        // Saturating: the clock is wall-clock and can step backwards.
        let time_elapsed = now.saturating_sub(bucket.last_refill);
        let tokens_to_add = (time_elapsed as f64 / self.config.window_size_secs as f64)
            * self.config.tokens_per_window as f64;

        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.config.burst_size as f64);
        bucket.last_refill = now;

        // Check if we have tokens
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Get current remaining tokens for an IP (for monitoring/logging).
    ///
    /// A poisoned lock reads as a full bucket, matching the direction
    /// [`RateLimiter::should_allow`] fails in.
    #[cfg(test)]
    fn get_tokens(&self, ip: IpAddr) -> f64 {
        let Ok(buckets) = self.buckets.lock() else {
            return self.config.burst_size as f64;
        };
        buckets
            .get(&ip)
            .map(|b| b.tokens)
            .unwrap_or(self.config.burst_size as f64)
    }

    /// Clean up inactive IPs from the bucket map.
    ///
    /// The common answer is "not yet", and it costs one relaxed load. `Relaxed`
    /// is enough for both: the value is a coarse timer rather than a
    /// happens-before edge, and the sweep it guards takes the bucket lock, which
    /// is where the ordering that matters comes from.
    fn cleanup_if_needed(&self, now: u64) {
        let last = self.last_cleanup.load(Ordering::Relaxed);
        if now.saturating_sub(last) < self.config.cleanup_interval_secs {
            return;
        }
        // Exactly one caller sweeps: whoever wins the swap. The losers return
        // without touching the bucket lock, where a `Mutex` here made every
        // worker that arrived in the same second queue behind the sweep.
        if self
            .last_cleanup
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let Ok(mut buckets) = self.buckets.lock() else {
            return;
        };

        // Saturating: a clock step backwards would otherwise underflow, and in
        // debug panic while holding both locks.
        buckets.retain(|_, bucket| {
            now.saturating_sub(bucket.last_refill) < self.config.cleanup_interval_secs
        });
    }

    /// Get statistics (for monitoring). Zeros for a poisoned lock.
    pub fn get_stats(&self) -> RateLimiterStats {
        let Ok(buckets) = self.buckets.lock() else {
            return RateLimiterStats {
                tracked_ips: 0,
                total_tokens: 0,
            };
        };
        RateLimiterStats {
            tracked_ips: buckets.len(),
            total_tokens: buckets.values().map(|b| b.tokens as u64).sum(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub tracked_ips: usize,
    pub total_tokens: u64,
}

/// What to do with a response that is over its client's byte budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseVerdict {
    /// Send it as built.
    Send,
    /// Send a truncated (TC=1) reply instead — no records, so it cannot amplify.
    /// A legitimate client retries over TCP.
    Truncate,
    /// Send nothing.
    Drop,
}

/// A per-client budget on response *bytes*, not queries — the reflected traffic
/// is what amplification is measured in (RFC 5358; Response Rate Limiting).
///
/// Above `max_tracked` the table stops growing and every response is truncated:
/// a spoofed flood arrives from every address there is, so the table would
/// otherwise be the next amplification vector.
///
/// UDP only. A TCP query completed a handshake, so there is nobody to reflect at.
pub struct ResponseLimiter {
    /// Sustained bytes per second per client. Zero disables the limiter.
    bytes_per_sec: u32,
    /// The most a client may be ahead of that rate, in bytes.
    burst_bytes: u32,
    /// One in every `slip` over-budget responses is truncated rather than
    /// dropped. 1 truncates all of them; 0 drops all of them.
    slip: u32,
    clients: Mutex<HashMap<IpAddr, ByteBucket>>,
    max_tracked: usize,
}

#[derive(Debug, Clone)]
struct ByteBucket {
    bytes: f64,
    last_refill: u64,
    /// How many responses to this client have been over budget, for slip.
    over_budget: u32,
}

impl ResponseLimiter {
    /// `bytes_per_sec` of 0 disables the limiter entirely.
    pub fn new(bytes_per_sec: u32, burst_bytes: u32, slip: u32) -> Self {
        ResponseLimiter {
            bytes_per_sec,
            burst_bytes,
            slip,
            clients: Mutex::new(HashMap::new()),
            max_tracked: 10_000,
        }
    }

    /// A budget from the one number an operator sets: `bytes_per_sec`
    /// sustained, four seconds' worth of it as burst — so a page load's dozen
    /// names is never touched — and BIND's own slip default of 2, truncating
    /// every second response over budget.
    ///
    /// Zero disables, because `new(0, ..)` *is* [`disabled`](Self::disabled):
    /// `is_enabled` is `bytes_per_sec > 0` and `admit` sends when it is false.
    /// Both binaries wrote the branch and the arithmetic out by hand
    /// (`TODO.md` #30f).
    pub fn per_second(bytes_per_sec: u32) -> Self {
        Self::new(bytes_per_sec, bytes_per_sec.saturating_mul(4), 2)
    }

    /// 8 KiB/s per client — the same number both daemons default
    /// `--response-rate` to.
    pub fn with_defaults() -> Self {
        Self::per_second(8192)
    }

    /// A limiter that permits everything, for `--no-response-limit`.
    pub fn disabled() -> Self {
        Self::new(0, 0, 0)
    }

    pub fn is_enabled(&self) -> bool {
        self.bytes_per_sec > 0
    }

    /// Charge `response_bytes` to `ip` and say what to do with the response.
    ///
    /// `now` is the caller's; see [`RateLimiter::should_allow`].
    pub fn admit(&self, ip: IpAddr, response_bytes: usize, now: u64) -> ResponseVerdict {
        if !self.is_enabled() {
            return ResponseVerdict::Send;
        }
        let Ok(mut clients) = self.clients.lock() else {
            // A poisoned lock is a bug elsewhere, not a licence to amplify.
            return ResponseVerdict::Truncate;
        };

        if !clients.contains_key(&ip) && clients.len() >= self.max_tracked {
            self.forget_idle(&mut clients, now);
            if clients.len() >= self.max_tracked {
                return ResponseVerdict::Truncate;
            }
        }

        let bucket = clients.entry(ip).or_insert_with(|| ByteBucket {
            bytes: self.burst_bytes as f64,
            last_refill: now,
            over_budget: 0,
        });

        let elapsed = now.saturating_sub(bucket.last_refill);
        bucket.bytes = (bucket.bytes + elapsed as f64 * self.bytes_per_sec as f64)
            .min(self.burst_bytes as f64);
        bucket.last_refill = now;

        if bucket.bytes >= response_bytes as f64 {
            bucket.bytes -= response_bytes as f64;
            bucket.over_budget = 0;
            return ResponseVerdict::Send;
        }

        bucket.over_budget = bucket.over_budget.saturating_add(1);
        if self.slip > 0 && bucket.over_budget % self.slip == 0 {
            ResponseVerdict::Truncate
        } else {
            ResponseVerdict::Drop
        }
    }

    /// How many clients are being tracked. For tests and diagnostics.
    pub fn tracked(&self) -> usize {
        self.clients.lock().map(|c| c.len()).unwrap_or(0)
    }

    /// Drop clients that have been quiet long enough to have refilled anyway —
    /// their bucket is full, so forgetting them changes nothing.
    fn forget_idle(&self, clients: &mut HashMap<IpAddr, ByteBucket>, now: u64) {
        let full_after = self
            .burst_bytes
            .checked_div(self.bytes_per_sec)
            .unwrap_or(1)
            .max(1) as u64;
        clients.retain(|_, bucket| now.saturating_sub(bucket.last_refill) < full_after);
    }
}

/// Who may ask for a zone transfer. Empty means nobody, and empty is the
/// default — an AXFR is the whole database, so it is allowed by list only.
///
/// A rule is a bare address or a CIDR prefix. Address families do not mix: a v4
/// rule never matches a v4-mapped v6 peer, which would be a way around the list.
#[derive(Debug, Clone, Default)]
pub struct TransferAcl {
    rules: Vec<AclRule>,
}

#[derive(Debug, Clone, Copy)]
struct AclRule {
    addr: IpAddr,
    /// How many leading bits must match. A bare address is a full-length prefix.
    prefix: u8,
}

impl TransferAcl {
    /// Parse rules like `192.0.2.1`, `10.0.0.0/8`, `2001:db8::/32`.
    ///
    /// A rule that does not parse is an error rather than a skip: a typo must
    /// stop the server, not leave the list shorter than the operator believes.
    pub fn parse(specs: &[String]) -> ConfigResult<Self> {
        Self::parse_named(specs, "transfer ACL")
    }

    /// [`Self::parse`] for another address list — the query-rate exemptions.
    /// Only the error text differs, so an operator running two lists is told
    /// which one has the typo.
    pub fn parse_named(specs: &[String], what: &str) -> ConfigResult<Self> {
        let mut rules = Vec::new();
        for spec in specs {
            let spec = spec.trim();
            if spec.is_empty() {
                continue;
            }
            let (addr_part, prefix_part) = match spec.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (spec, None),
            };
            let addr: IpAddr = addr_part.parse().map_err(|e| {
                ConfigError::new(format!("bad address {addr_part:?} in {what}: {e}"))
            })?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            let prefix = match prefix_part {
                Some(p) => p.parse::<u8>().map_err(|e| {
                    ConfigError::new(format!("bad prefix length {p:?} in {what}: {e}"))
                })?,
                None => max,
            };
            if prefix > max {
                return Err(ConfigError::new(format!(
                    "prefix /{prefix} is longer than an {} address allows",
                    if addr.is_ipv4() { "IPv4" } else { "IPv6" }
                )));
            }
            rules.push(AclRule { addr, prefix });
        }
        Ok(TransferAcl { rules })
    }

    /// Whether `ip` is on the list. An empty list allows nothing.
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.rules.iter().any(|rule| rule.matches(ip))
    }

    /// Whether the list is empty, i.e. transfers are refused outright.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

impl AclRule {
    fn matches(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(rule), IpAddr::V4(peer)) => {
                prefix_matches(&rule.octets(), &peer.octets(), self.prefix)
            }
            (IpAddr::V6(rule), IpAddr::V6(peer)) => {
                prefix_matches(&rule.octets(), &peer.octets(), self.prefix)
            }
            // Different families never match.
            _ => false,
        }
    }
}

/// Whether the first `prefix` bits of two addresses agree.
fn prefix_matches(rule: &[u8], peer: &[u8], prefix: u8) -> bool {
    let whole_bytes = (prefix / 8) as usize;
    if rule[..whole_bytes] != peer[..whole_bytes] {
        return false;
    }
    let leftover = prefix % 8;
    if leftover == 0 {
        return true;
    }
    // The high `leftover` bits of the next byte.
    let mask = 0xffu8 << (8 - leftover);
    rule[whole_bytes] & mask == peer[whole_bytes] & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::with_defaults();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should allow up to burst size
        for _ in 0..20 {
            assert!(
                limiter.should_allow(ip, current_unix_timestamp()),
                "should allow within burst size"
            );
        }
    }

    #[test]
    fn test_rate_limiter_denies_over_limit() {
        let limiter = RateLimiter::with_defaults();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Use up burst
        for _ in 0..20 {
            limiter.should_allow(ip, current_unix_timestamp());
        }

        // Next one should be denied (no tokens available)
        assert!(
            !limiter.should_allow(ip, current_unix_timestamp()),
            "should deny when over limit"
        );
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::with_defaults();
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        // Use up burst for ip1
        for _ in 0..20 {
            limiter.should_allow(ip1, current_unix_timestamp());
        }

        // ip2 should still have tokens
        assert!(
            limiter.should_allow(ip2, current_unix_timestamp()),
            "different IPs should have separate buckets"
        );
    }

    /// Unbounded, the rate limiter is itself the memory-exhaustion vector: one
    /// spoofed 12-byte datagram per source address buys an entry.
    #[test]
    fn a_flood_of_source_addresses_does_not_grow_the_table_without_bound() {
        let config = RateLimitConfig {
            max_tracked: 64,
            ..RateLimitConfig::default()
        };
        let limiter = RateLimiter::new(config);

        for i in 0..5_000u32 {
            // Spread across the whole v4 space, as a spoofing source would.
            limiter.should_allow(
                IpAddr::V4(Ipv4Addr::from(i.wrapping_mul(2_654_435_761))),
                current_unix_timestamp(),
            );
        }

        assert!(
            limiter.get_stats().tracked_ips <= 64,
            "tracked {} addresses with a bound of 64",
            limiter.get_stats().tracked_ips
        );
    }

    /// At the bound the answer is "allow": failing closed would let one flood
    /// take the server off the air for every legitimate client.
    #[test]
    fn a_source_the_table_has_no_room_for_is_still_served() {
        let config = RateLimitConfig {
            max_tracked: 1,
            ..RateLimitConfig::default()
        };
        let limiter = RateLimiter::new(config);
        let tracked = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let untracked = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

        assert!(limiter.should_allow(tracked, current_unix_timestamp()));
        for _ in 0..100 {
            assert!(
                limiter.should_allow(untracked, current_unix_timestamp()),
                "an untracked source is not a refused source"
            );
        }
        // The one address that did get a bucket is still limited normally.
        for _ in 0..19 {
            limiter.should_allow(tracked, current_unix_timestamp());
        }
        assert!(
            !limiter.should_allow(tracked, current_unix_timestamp()),
            "the tracked bucket still empties"
        );
    }

    /// A clock step backwards must not panic, and must not silently refill every
    /// bucket either.
    ///
    /// It steps the clock, rather than reaching into `buckets` to stamp one
    /// entry in the future as it did before `now` became the caller's: an NTP
    /// step back is what this is about, and now it can be the input.
    #[test]
    fn a_clock_step_backwards_neither_panics_nor_refills_the_bucket() {
        let limiter = RateLimiter::with_defaults();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let now = current_unix_timestamp();

        assert!(limiter.should_allow(ip, now));

        // The clock jumps an hour backwards. Without saturation the first call
        // refills to burst on an underflowed elapsed time, so the bucket never
        // empties.
        let stepped_back = now - 3600;
        for _ in 0..19 {
            limiter.should_allow(ip, stepped_back);
        }
        assert!(
            !limiter.should_allow(ip, stepped_back),
            "a bucket last refilled in the future must not refill again — that is \
             the limiter silently switching itself off"
        );
    }

    #[test]
    fn test_rate_limiter_get_stats() {
        let limiter = RateLimiter::with_defaults();
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        limiter.should_allow(ip1, current_unix_timestamp());
        limiter.should_allow(ip2, current_unix_timestamp());

        let stats = limiter.get_stats();
        assert_eq!(stats.tracked_ips, 2);
    }

    #[test]
    fn test_rate_limiter_get_tokens() {
        let limiter = RateLimiter::with_defaults();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Initial tokens should be burst_size
        let initial = limiter.get_tokens(ip);
        assert_eq!(initial as u32, 20);

        // After using one, should have one less
        limiter.should_allow(ip, current_unix_timestamp());
        let after_one = limiter.get_tokens(ip);
        assert!(after_one < initial);
    }

    /// The sweep still runs, and an idle source is forgotten by it — the
    /// property the timestamp guards, now that the timestamp is an atomic and
    /// only the caller that wins the swap sweeps (`TODO.md` #25f).
    #[test]
    fn an_idle_source_is_swept_once_the_interval_has_passed() {
        let limiter = RateLimiter::new(RateLimitConfig {
            cleanup_interval_secs: 60,
            ..RateLimitConfig::per_second(10, 10)
        });
        let idle = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        let busy = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        // The real clock, because `last_cleanup` is seeded from it at
        // construction: a synthetic `now` in the past never reaches the
        // interval, and the sweep would silently never run.
        let start = current_unix_timestamp();

        assert!(limiter.should_allow(idle, start));
        assert_eq!(limiter.get_stats().tracked_ips, 1);

        // Past the interval, and the first caller through does the sweep. The
        // busy source is admitted after it, so it survives.
        assert!(limiter.should_allow(busy, start + 61));
        assert_eq!(
            limiter.get_stats().tracked_ips,
            1,
            "the idle source went, the one doing the asking stayed"
        );
        assert_eq!(limiter.get_tokens(idle), limiter.get_tokens(busy) + 1.0);

        // And the next caller in the same interval does not sweep again: `busy`
        // is one second old and would survive either way, so what this holds is
        // that the timestamp advanced rather than that nothing was dropped.
        assert!(limiter.should_allow(busy, start + 62));
        assert_eq!(limiter.get_stats().tracked_ips, 1);
    }

    #[test]
    fn test_rate_limiter_custom_config() {
        let config = RateLimitConfig {
            tokens_per_window: 10,
            window_size_secs: 5,
            burst_size: 5,
            cleanup_interval_secs: 60,
            ..RateLimitConfig::default()
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Allow up to burst
        for _ in 0..5 {
            assert!(limiter.should_allow(ip, current_unix_timestamp()));
        }

        // Next should fail
        assert!(!limiter.should_allow(ip, current_unix_timestamp()));
    }

    #[test]
    fn test_rate_limiter_zero_tokens_prevents_all() {
        let config = RateLimitConfig {
            tokens_per_window: 100,
            window_size_secs: 10,
            burst_size: 0, // No burst allowed
            cleanup_interval_secs: 60,
            ..RateLimitConfig::default()
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should deny immediately
        assert!(!limiter.should_allow(ip, current_unix_timestamp()));
    }

    /// The limit is a *rate*: 100 tokens per 10-second window reads as "100
    /// queries" and is 10 a second, below what one busy resolver sends.
    #[test]
    fn a_per_second_limit_means_what_it_says() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        // The burst is what may arrive at once, before the rate applies.
        let limiter = RateLimiter::new(RateLimitConfig::per_second(1000, 200));
        for i in 0..200 {
            assert!(
                limiter.should_allow(ip, current_unix_timestamp()),
                "query {i} of the burst"
            );
        }
        assert!(
            !limiter.should_allow(ip, current_unix_timestamp()),
            "and the burst is a bound, not a suggestion"
        );

        // The default, stated in its own units, is 10 q/s.
        let old = RateLimitConfig::default();
        assert_eq!(
            old.tokens_per_window as f64 / old.window_size_secs as f64,
            10.0
        );
    }

    /// 0 turns the limiter off outright rather than refusing everything.
    #[test]
    fn a_rate_of_zero_disables_the_limiter_rather_than_refusing_everything() {
        let limiter = RateLimiter::new(RateLimitConfig::per_second(0, 1));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        for i in 0..10_000 {
            assert!(
                limiter.should_allow(ip, current_unix_timestamp()),
                "query {i}"
            );
        }
        // And nothing was tracked, so "off" is not "a bucket per source".
        assert_eq!(limiter.get_stats().tracked_ips, 0);
    }

    /// An exempt source is never limited, and does not exempt anybody else.
    #[test]
    fn an_exempt_source_is_not_rate_limited_and_its_neighbours_still_are() {
        let limiter = RateLimiter::new(RateLimitConfig::per_second(10, 2).exempting(
            TransferAcl::parse_named(&["192.0.2.0/24".to_string()], "test list").unwrap(),
        ));
        let exempt = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        let ordinary = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

        for i in 0..1_000 {
            assert!(
                limiter.should_allow(exempt, current_unix_timestamp()),
                "exempt query {i}"
            );
        }
        assert!(limiter.should_allow(ordinary, current_unix_timestamp()));
        assert!(limiter.should_allow(ordinary, current_unix_timestamp()));
        assert!(
            !limiter.should_allow(ordinary, current_unix_timestamp()),
            "an address outside the exemption keeps its own bucket"
        );
    }

    /// A burst of zero would refuse every query — a bucket starts full, and a
    /// full bucket of nothing has no token to spend.
    #[test]
    fn a_burst_of_zero_does_not_become_a_total_outage() {
        let limiter = RateLimiter::new(RateLimitConfig::per_second(10, 0));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert!(
            limiter.should_allow(ip, current_unix_timestamp()),
            "one query must still get through"
        );
    }

    #[test]
    fn test_rate_limiter_concurrent_ips() {
        let limiter = Arc::new(RateLimiter::with_defaults());
        let mut handles = vec![];

        // Test with multiple IPs in parallel
        for i in 0..10 {
            let limiter = limiter.clone();
            let handle = std::thread::spawn(move || {
                let ip = IpAddr::V4(Ipv4Addr::new(127, 0, i, 0));
                let mut count = 0;
                for _ in 0..30 {
                    if limiter.should_allow(ip, current_unix_timestamp()) {
                        count += 1;
                    }
                }
                count
            });
            handles.push(handle);
        }

        let total_allowed: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();

        // Each IP should allow its burst size (20)
        // So 10 IPs * 20 = 200
        assert_eq!(total_allowed, 200);
    }

    fn parse_acl(specs: &[&str]) -> TransferAcl {
        TransferAcl::parse(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("should parse")
    }

    /// An AXFR is the whole zone, so with no list there is nobody to give it to.
    #[test]
    fn test_an_empty_acl_allows_nobody() {
        let acl = TransferAcl::default();
        assert!(acl.is_empty());
        assert!(!acl.allows("127.0.0.1".parse().unwrap()));
        assert!(!acl.allows("::1".parse().unwrap()));
    }

    #[test]
    fn test_bare_address_matches_only_itself() {
        let acl = parse_acl(&["192.0.2.10", "2001:db8::1"]);
        assert!(acl.allows("192.0.2.10".parse().unwrap()));
        assert!(!acl.allows("192.0.2.11".parse().unwrap()));
        assert!(acl.allows("2001:db8::1".parse().unwrap()));
        assert!(!acl.allows("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn test_cidr_prefixes_match_on_bit_boundaries() {
        let acl = parse_acl(&["10.0.0.0/8", "192.0.2.128/25", "2001:db8::/32"]);

        assert!(acl.allows("10.1.2.3".parse().unwrap()));
        assert!(!acl.allows("11.1.2.3".parse().unwrap()));

        // /25 splits a byte: .128 through .255 are in, .127 and below are not.
        assert!(acl.allows("192.0.2.200".parse().unwrap()));
        assert!(acl.allows("192.0.2.128".parse().unwrap()));
        assert!(!acl.allows("192.0.2.127".parse().unwrap()));

        assert!(acl.allows("2001:db8:dead:beef::5".parse().unwrap()));
        assert!(!acl.allows("2001:db9::5".parse().unwrap()));
    }

    /// A v4 rule must not admit a v6 peer, mapped or otherwise.
    #[test]
    fn test_families_do_not_mix() {
        let acl = parse_acl(&["10.0.0.0/8"]);
        assert!(!acl.allows("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!acl.allows("::1".parse().unwrap()));

        let v6 = parse_acl(&["::/0"]);
        assert!(
            v6.allows("2001:db8::1".parse().unwrap()),
            "/0 matches its own family"
        );
        assert!(!v6.allows("10.0.0.1".parse().unwrap()));
    }

    /// A typo has to stop the server, not shorten the list silently.
    #[test]
    fn test_a_bad_rule_is_an_error() {
        assert!(TransferAcl::parse(&["not-an-address".to_string()]).is_err());
        assert!(
            TransferAcl::parse(&["10.0.0.0/33".to_string()]).is_err(),
            "v4 prefix too long"
        );
        assert!(TransferAcl::parse(&["2001:db8::/129".to_string()]).is_err());
        assert!(TransferAcl::parse(&["10.0.0.0/eight".to_string()]).is_err());
    }

    /// What the query counter cannot see: one query, a big answer.
    #[test]
    fn test_a_big_answer_costs_more_than_a_small_one() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        // 4 KiB of budget, no refill within the test's second.
        let limiter = ResponseLimiter::new(1, 4096, 2);

        // Eight 512-byte answers fit exactly.
        for i in 0..8 {
            assert_eq!(
                limiter.admit(ip, 512, current_unix_timestamp()),
                ResponseVerdict::Send,
                "response {i} should fit"
            );
        }
        assert_ne!(
            limiter.admit(ip, 512, current_unix_timestamp()),
            ResponseVerdict::Send,
            "budget spent"
        );

        // The same budget is one large answer, not eight.
        let big = ResponseLimiter::new(1, 4096, 2);
        assert_eq!(
            big.admit(ip, 4000, current_unix_timestamp()),
            ResponseVerdict::Send
        );
        assert_ne!(
            big.admit(ip, 512, current_unix_timestamp()),
            ResponseVerdict::Send,
            "4000 bytes ate it"
        );
    }

    /// Slip: every second over-budget response is truncated rather than dropped,
    /// so a legitimate client learns to use TCP instead of going silent.
    #[test]
    fn test_slip_truncates_every_second_over_budget_response() {
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        let limiter = ResponseLimiter::new(1, 100, 2);
        assert_eq!(
            limiter.admit(ip, 100, current_unix_timestamp()),
            ResponseVerdict::Send
        );

        let verdicts: Vec<ResponseVerdict> = (0..6)
            .map(|_| limiter.admit(ip, 100, current_unix_timestamp()))
            .collect();
        assert_eq!(
            verdicts,
            vec![
                ResponseVerdict::Drop,
                ResponseVerdict::Truncate,
                ResponseVerdict::Drop,
                ResponseVerdict::Truncate,
                ResponseVerdict::Drop,
                ResponseVerdict::Truncate,
            ],
            "one in two over-budget responses is answerable"
        );
    }

    #[test]
    fn test_slip_of_one_truncates_all_and_zero_drops_all() {
        let ip: IpAddr = "192.0.2.3".parse().unwrap();

        let always = ResponseLimiter::new(1, 10, 1);
        assert_eq!(
            always.admit(ip, 100, current_unix_timestamp()),
            ResponseVerdict::Truncate
        );
        assert_eq!(
            always.admit(ip, 100, current_unix_timestamp()),
            ResponseVerdict::Truncate
        );

        let never = ResponseLimiter::new(1, 10, 0);
        assert_eq!(
            never.admit(ip, 100, current_unix_timestamp()),
            ResponseVerdict::Drop
        );
        assert_eq!(
            never.admit(ip, 100, current_unix_timestamp()),
            ResponseVerdict::Drop
        );
    }

    /// One client's flood must not spend another client's budget.
    #[test]
    fn test_budgets_are_per_client() {
        let noisy: IpAddr = "192.0.2.4".parse().unwrap();
        let quiet: IpAddr = "192.0.2.5".parse().unwrap();
        let limiter = ResponseLimiter::new(1, 512, 2);

        assert_eq!(
            limiter.admit(noisy, 512, current_unix_timestamp()),
            ResponseVerdict::Send
        );
        assert_ne!(
            limiter.admit(noisy, 512, current_unix_timestamp()),
            ResponseVerdict::Send
        );
        assert_eq!(
            limiter.admit(quiet, 512, current_unix_timestamp()),
            ResponseVerdict::Send,
            "the quiet client still has its own budget"
        );
    }

    /// A spoofed flood arrives from every address there is, so the tracking
    /// table is the next thing to exhaust.
    #[test]
    fn test_the_client_table_is_bounded() {
        let mut limiter = ResponseLimiter::new(8192, 32768, 2);
        limiter.max_tracked = 16;

        let mut truncated = 0;
        for i in 0..200u32 {
            let ip: IpAddr = format!("198.51.100.{}", i % 256).parse().unwrap();
            let ip = if i < 256 {
                ip
            } else {
                format!("203.0.113.{}", i % 256).parse().unwrap()
            };
            if limiter.admit(ip, 100, current_unix_timestamp()) == ResponseVerdict::Truncate {
                truncated += 1;
            }
        }
        assert!(limiter.tracked() <= 16, "tracked {}", limiter.tracked());
        assert!(
            truncated > 0,
            "past the bound, responses are truncated rather than tracked"
        );
    }

    #[test]
    fn test_a_disabled_limiter_sends_everything() {
        let ip: IpAddr = "192.0.2.6".parse().unwrap();
        let limiter = ResponseLimiter::disabled();
        assert!(!limiter.is_enabled());
        for _ in 0..1000 {
            assert_eq!(
                limiter.admit(ip, 65535, current_unix_timestamp()),
                ResponseVerdict::Send
            );
        }
    }

    /// A rate of 0 permits everything, so the `if rate == 0 { disabled() }`
    /// both binaries wrote around this constructor was dead code
    /// (`TODO.md` #30f): `disabled()` *is* `new(0, 0, 0)`.
    #[test]
    fn a_budget_of_zero_is_no_budget() {
        let limiter = ResponseLimiter::per_second(0);
        assert!(!limiter.is_enabled());
        assert_eq!(
            limiter.admit(
                "192.0.2.9".parse().unwrap(),
                60_000,
                current_unix_timestamp()
            ),
            ResponseVerdict::Send,
            "and a maximal response still goes out whole"
        );
    }

    /// The default must be generous enough that a page load never sees it.
    #[test]
    fn test_the_default_budget_passes_an_ordinary_burst() {
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let limiter = ResponseLimiter::with_defaults();
        for i in 0..40 {
            assert_eq!(
                limiter.admit(ip, 300, current_unix_timestamp()),
                ResponseVerdict::Send,
                "answer {i} of an ordinary burst"
            );
        }
    }
}
