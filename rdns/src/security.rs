use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use crate::utils::current_unix_timestamp;

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Number of tokens available per window
    pub tokens_per_window: u32,
    /// Window size in seconds
    pub window_size_secs: u64,
    /// Maximum burst size
    pub burst_size: u32,
    /// Cleanup interval for inactive IPs (in seconds)
    pub cleanup_interval_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            tokens_per_window: 100,      // 100 queries per window
            window_size_secs: 10,        // 10 second window
            burst_size: 20,              // Allow burst of 20
            cleanup_interval_secs: 600,  // 10 minute cleanup
        }
    }
}

/// Per-IP token bucket state
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: u64,
}

/// Rate limiter using token bucket algorithm
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
    last_cleanup: Arc<Mutex<u64>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        RateLimiter {
            config,
            buckets: Arc::new(Mutex::new(HashMap::new())),
            last_cleanup: Arc::new(Mutex::new(current_unix_timestamp())),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Check if a request from the given IP should be allowed
    pub fn should_allow(&self, ip: IpAddr) -> bool {
        let now = current_unix_timestamp();
        
        // Cleanup old entries periodically
        self.cleanup_if_needed(now);

        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.config.burst_size as f64,
            last_refill: now,
        });

        // Refill tokens based on time elapsed
        let time_elapsed = now - bucket.last_refill;
        let tokens_to_add = (time_elapsed as f64 / self.config.window_size_secs as f64)
            * self.config.tokens_per_window as f64;

        bucket.tokens = (bucket.tokens + tokens_to_add)
            .min(self.config.burst_size as f64);
        bucket.last_refill = now;

        // Check if we have tokens
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Get current remaining tokens for an IP (for monitoring/logging)
    pub fn get_tokens(&self, ip: IpAddr) -> f64 {
        let buckets = self.buckets.lock().unwrap();
        buckets
            .get(&ip)
            .map(|b| b.tokens)
            .unwrap_or(self.config.burst_size as f64)
    }

    /// Clean up inactive IPs from the bucket map
    fn cleanup_if_needed(&self, now: u64) {
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        
        if now - *last_cleanup < self.config.cleanup_interval_secs {
            return;
        }

        *last_cleanup = now;
        let mut buckets = self.buckets.lock().unwrap();
        
        // Remove entries that haven't been used in the last cleanup interval
        buckets.retain(|_, bucket| {
            now - bucket.last_refill < self.config.cleanup_interval_secs
        });
    }

    /// Get statistics (for monitoring)
    pub fn get_stats(&self) -> RateLimiterStats {
        let buckets = self.buckets.lock().unwrap();
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
    /// Send a truncated (TC=1) reply instead — no records, so it is about the
    /// size of the query. A legitimate client retries over TCP and gets its
    /// answer; a spoofed source receives a packet no larger than the one
    /// supposedly sent, which is the whole point.
    Truncate,
    /// Send nothing.
    Drop,
}

/// A per-client budget on response *bytes*, not queries.
///
/// The query limiter above counts requests, which says nothing about
/// amplification: a query is a query whether the answer is 60 bytes or 4000. An
/// attacker forging a victim's source address picks the query whose answer is
/// largest and lets the server do the work — the reflected traffic is what
/// matters, so the reflected traffic is what has to be metered (RFC 5358 on the
/// attack, and the technique authoritative servers call Response Rate Limiting).
///
/// Two things make this usable rather than merely strict:
///
/// - **Slip.** Every `slip`-th response over budget is answered TC=1 instead of
///   dropped. That reply carries no records, so it cannot amplify — while a
///   legitimate client, which is what a rate limiter mostly catches, sees
///   truncation and retries over TCP, where the handshake proves the source
///   address and the budget does not apply.
/// - **A bounded table.** Tracking is per address, and a spoofed flood arrives
///   from every address there is, so the table itself would be the next
///   amplification vector. Above `max_tracked` it stops growing and every
///   response is truncated instead: small, still answerable over TCP, and no
///   longer proportional to the number of forged sources.
///
/// Only for UDP. A TCP query has completed a handshake, so its source address is
/// real and there is nobody to reflect at.
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

    /// 8 KiB/s sustained per client with a 32 KiB burst, truncating every second
    /// response over budget.
    ///
    /// A stub resolver asking real questions is nowhere near this: 8 KiB is some
    /// twenty full-size answers a second, sustained, from one address. The burst
    /// is four seconds' worth so that a browser opening a page — a dozen names at
    /// once — is never touched. The slip of 2 is what BIND's own default is.
    pub fn with_defaults() -> Self {
        Self::new(8192, 32768, 2)
    }

    /// A limiter that permits everything, for `--no-response-limit`.
    pub fn disabled() -> Self {
        Self::new(0, 0, 0)
    }

    pub fn is_enabled(&self) -> bool {
        self.bytes_per_sec > 0
    }

    /// Charge `response_bytes` to `ip` and say what to do with the response.
    pub fn admit(&self, ip: IpAddr, response_bytes: usize) -> ResponseVerdict {
        if !self.is_enabled() {
            return ResponseVerdict::Send;
        }
        let now = current_unix_timestamp();
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

/// Who may ask for a zone transfer.
///
/// **Empty means nobody, and empty is the default.** An AXFR hands over every
/// name in the zone in one request: hosts that were never meant to be found,
/// internal naming, the shape of the network. It is the one query where the
/// answer is the whole database, so it is allowed by list and refused otherwise —
/// the opposite of how the rest of a nameserver works.
///
/// A rule is a bare address or a CIDR prefix. Address families do not mix: a v4
/// rule never matches a v6 peer, including a v4-mapped one, because
/// `::ffff:10.0.0.1` reaching a `10.0.0.0/8` rule would be a way around the list
/// rather than an application of it.
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
    /// A rule that does not parse is an error rather than a skip: a typo in an
    /// ACL must stop the server, not silently leave the list shorter than the
    /// operator believes it to be.
    pub fn parse(specs: &[String]) -> Result<Self, String> {
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
            let addr: IpAddr = addr_part
                .parse()
                .map_err(|e| format!("bad address {addr_part:?} in transfer ACL: {e}"))?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            let prefix = match prefix_part {
                Some(p) => p
                    .parse::<u8>()
                    .map_err(|e| format!("bad prefix length {p:?} in transfer ACL: {e}"))?,
                None => max,
            };
            if prefix > max {
                return Err(format!(
                    "prefix /{prefix} is longer than an {} address allows",
                    if addr.is_ipv4() { "IPv4" } else { "IPv6" }
                ));
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
            assert!(limiter.should_allow(ip), "should allow within burst size");
        }
    }

    #[test]
    fn test_rate_limiter_denies_over_limit() {
        let limiter = RateLimiter::with_defaults();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Use up burst
        for _ in 0..20 {
            limiter.should_allow(ip);
        }

        // Next one should be denied (no tokens available)
        assert!(!limiter.should_allow(ip), "should deny when over limit");
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::with_defaults();
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        // Use up burst for ip1
        for _ in 0..20 {
            limiter.should_allow(ip1);
        }

        // ip2 should still have tokens
        assert!(limiter.should_allow(ip2), "different IPs should have separate buckets");
    }

    #[test]
    fn test_rate_limiter_get_stats() {
        let limiter = RateLimiter::with_defaults();
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        limiter.should_allow(ip1);
        limiter.should_allow(ip2);

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
        limiter.should_allow(ip);
        let after_one = limiter.get_tokens(ip);
        assert!(after_one < initial);
    }

    #[test]
    fn test_rate_limiter_custom_config() {
        let config = RateLimitConfig {
            tokens_per_window: 10,
            window_size_secs: 5,
            burst_size: 5,
            cleanup_interval_secs: 60,
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Allow up to burst
        for _ in 0..5 {
            assert!(limiter.should_allow(ip));
        }

        // Next should fail
        assert!(!limiter.should_allow(ip));
    }

    #[test]
    fn test_rate_limiter_zero_tokens_prevents_all() {
        let config = RateLimitConfig {
            tokens_per_window: 100,
            window_size_secs: 10,
            burst_size: 0, // No burst allowed
            cleanup_interval_secs: 60,
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Should deny immediately
        assert!(!limiter.should_allow(ip));
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
                    if limiter.should_allow(ip) {
                        count += 1;
                    }
                }
                count
            });
            handles.push(handle);
        }

        let total_allowed: u32 = handles.into_iter()
            .map(|h| h.join().unwrap())
            .sum();

        // Each IP should allow its burst size (20)
        // So 10 IPs * 20 = 200
        assert_eq!(total_allowed, 200);
    }

    // -----------------------------------------------------------------
    // The zone-transfer ACL
    // -----------------------------------------------------------------

    fn parse_acl(specs: &[&str]) -> TransferAcl {
        TransferAcl::parse(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("should parse")
    }

    /// The default is the one that matters: an AXFR is the whole zone, so with
    /// no list there is nobody to give it to.
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

    /// A v4 rule must not admit a v6 peer, mapped or otherwise — that would be a
    /// way around the list rather than an application of it.
    #[test]
    fn test_families_do_not_mix() {
        let acl = parse_acl(&["10.0.0.0/8"]);
        assert!(!acl.allows("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!acl.allows("::1".parse().unwrap()));

        let v6 = parse_acl(&["::/0"]);
        assert!(v6.allows("2001:db8::1".parse().unwrap()), "/0 matches its own family");
        assert!(!v6.allows("10.0.0.1".parse().unwrap()));
    }

    /// A typo has to stop the server. Leaving the list shorter than the operator
    /// wrote it is how a rule silently stops applying.
    #[test]
    fn test_a_bad_rule_is_an_error() {
        assert!(TransferAcl::parse(&["not-an-address".to_string()]).is_err());
        assert!(TransferAcl::parse(&["10.0.0.0/33".to_string()]).is_err(), "v4 prefix too long");
        assert!(TransferAcl::parse(&["2001:db8::/129".to_string()]).is_err());
        assert!(TransferAcl::parse(&["10.0.0.0/eight".to_string()]).is_err());
    }

    // -----------------------------------------------------------------
    // The response byte budget
    // -----------------------------------------------------------------

    /// The thing the query counter could not see: one query, a big answer. A
    /// budget in bytes is spent by the size of what goes out, so a client asking
    /// for large RRsets runs out sooner than one asking for addresses.
    #[test]
    fn test_a_big_answer_costs_more_than_a_small_one() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        // 4 KiB of budget, no refill within the test's second.
        let limiter = ResponseLimiter::new(1, 4096, 2);

        // Eight 512-byte answers fit exactly.
        for i in 0..8 {
            assert_eq!(
                limiter.admit(ip, 512),
                ResponseVerdict::Send,
                "response {i} should fit"
            );
        }
        assert_ne!(limiter.admit(ip, 512), ResponseVerdict::Send, "budget spent");

        // The same budget is one large answer, not eight.
        let big = ResponseLimiter::new(1, 4096, 2);
        assert_eq!(big.admit(ip, 4000), ResponseVerdict::Send);
        assert_ne!(big.admit(ip, 512), ResponseVerdict::Send, "4000 bytes ate it");
    }

    /// Slip: every second response over budget is truncated rather than dropped,
    /// so a legitimate client learns to use TCP instead of going silent.
    #[test]
    fn test_slip_truncates_every_second_over_budget_response() {
        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        let limiter = ResponseLimiter::new(1, 100, 2);
        assert_eq!(limiter.admit(ip, 100), ResponseVerdict::Send);

        let verdicts: Vec<ResponseVerdict> = (0..6).map(|_| limiter.admit(ip, 100)).collect();
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
        assert_eq!(always.admit(ip, 100), ResponseVerdict::Truncate);
        assert_eq!(always.admit(ip, 100), ResponseVerdict::Truncate);

        let never = ResponseLimiter::new(1, 10, 0);
        assert_eq!(never.admit(ip, 100), ResponseVerdict::Drop);
        assert_eq!(never.admit(ip, 100), ResponseVerdict::Drop);
    }

    /// One client's flood must not spend another client's budget.
    #[test]
    fn test_budgets_are_per_client() {
        let noisy: IpAddr = "192.0.2.4".parse().unwrap();
        let quiet: IpAddr = "192.0.2.5".parse().unwrap();
        let limiter = ResponseLimiter::new(1, 512, 2);

        assert_eq!(limiter.admit(noisy, 512), ResponseVerdict::Send);
        assert_ne!(limiter.admit(noisy, 512), ResponseVerdict::Send);
        assert_eq!(
            limiter.admit(quiet, 512),
            ResponseVerdict::Send,
            "the quiet client still has its own budget"
        );
    }

    /// A spoofed flood arrives from every address there is, so the tracking
    /// table is the next thing to exhaust. Past its bound it stops growing and
    /// truncates instead — small, still answerable over TCP.
    #[test]
    fn test_the_client_table_is_bounded() {
        let mut limiter = ResponseLimiter::new(8192, 32768, 2);
        limiter.max_tracked = 16;

        let mut truncated = 0;
        for i in 0..200u32 {
            let ip: IpAddr = format!("198.51.100.{}", i % 256).parse().unwrap();
            let ip = if i < 256 { ip } else { format!("203.0.113.{}", i % 256).parse().unwrap() };
            if limiter.admit(ip, 100) == ResponseVerdict::Truncate {
                truncated += 1;
            }
        }
        assert!(limiter.tracked() <= 16, "tracked {}", limiter.tracked());
        assert!(truncated > 0, "past the bound, responses are truncated rather than tracked");
    }

    #[test]
    fn test_a_disabled_limiter_sends_everything() {
        let ip: IpAddr = "192.0.2.6".parse().unwrap();
        let limiter = ResponseLimiter::disabled();
        assert!(!limiter.is_enabled());
        for _ in 0..1000 {
            assert_eq!(limiter.admit(ip, 65535), ResponseVerdict::Send);
        }
    }

    /// The default has to be generous enough that ordinary use never sees it:
    /// a page load is a dozen names at once, and that must go through untouched.
    #[test]
    fn test_the_default_budget_passes_an_ordinary_burst() {
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let limiter = ResponseLimiter::with_defaults();
        for i in 0..40 {
            assert_eq!(
                limiter.admit(ip, 300),
                ResponseVerdict::Send,
                "answer {i} of an ordinary burst"
            );
        }
    }
}
