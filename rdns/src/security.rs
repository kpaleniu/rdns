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
}

