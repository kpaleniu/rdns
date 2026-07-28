use std::sync::atomic::{AtomicU64, Ordering};
use crate::error::ConfigResult;
use std::sync::Arc;
use std::time::Instant;

/// Metrics for DNS query processing.
/// Uses atomic counters for thread-safe concurrent access.
#[derive(Clone)]
pub struct DnsMetrics {
    /// Total number of DNS queries processed
    pub query_counter: Arc<AtomicU64>,
    /// Number of cache hits
    pub cache_hits: Arc<AtomicU64>,
    /// Number of cache misses
    pub cache_misses: Arc<AtomicU64>,
    /// Number of successful DNSSEC validations
    pub dnssec_validations: Arc<AtomicU64>,
    /// Number of failed DNSSEC validations
    pub dnssec_failures: Arc<AtomicU64>,
}

impl DnsMetrics {
    /// Create new DNS metrics with all counters initialized to 0.
    pub fn new() -> Self {
        DnsMetrics {
            query_counter: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            dnssec_validations: Arc::new(AtomicU64::new(0)),
            dnssec_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Increment query counter and return current count.
    pub fn increment_query_counter(&self) -> u64 {
        self.query_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Increment cache hit counter.
    pub fn increment_cache_hits(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment cache miss counter.
    pub fn increment_cache_misses(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment successful DNSSEC validation counter.
    pub fn increment_dnssec_validations(&self) {
        self.dnssec_validations.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment failed DNSSEC validation counter.
    pub fn increment_dnssec_failures(&self) {
        self.dnssec_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current value of query counter.
    pub fn get_query_count(&self) -> u64 {
        self.query_counter.load(Ordering::Relaxed)
    }

    /// Get current value of cache hits counter.
    pub fn get_cache_hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    /// Get current value of cache misses counter.
    pub fn get_cache_misses(&self) -> u64 {
        self.cache_misses.load(Ordering::Relaxed)
    }

    /// Get cache hit rate as a percentage (0.0-100.0).
    pub fn get_cache_hit_rate(&self) -> f64 {
        let hits = self.cache_hits.load(Ordering::Relaxed) as f64;
        let misses = self.cache_misses.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        if total > 0.0 {
            (hits / total) * 100.0
        } else {
            0.0
        }
    }

    /// Get current value of DNSSEC validation counter.
    pub fn get_dnssec_validations(&self) -> u64 {
        self.dnssec_validations.load(Ordering::Relaxed)
    }

    /// Get current value of DNSSEC failure counter.
    pub fn get_dnssec_failures(&self) -> u64 {
        self.dnssec_failures.load(Ordering::Relaxed)
    }

    /// Get DNSSEC validation success rate as a percentage (0.0-100.0).
    pub fn get_dnssec_success_rate(&self) -> f64 {
        let successes = self.dnssec_validations.load(Ordering::Relaxed) as f64;
        let failures = self.dnssec_failures.load(Ordering::Relaxed) as f64;
        let total = successes + failures;
        if total > 0.0 {
            (successes / total) * 100.0
        } else {
            0.0
        }
    }

    /// Reset all counters to 0 (for testing or metrics reset).
    pub fn reset(&self) {
        self.query_counter.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
        self.dnssec_validations.store(0, Ordering::Relaxed);
        self.dnssec_failures.store(0, Ordering::Relaxed);
    }

    /// Log current metrics snapshot.
    pub fn log_snapshot(&self) {
        let queries = self.get_query_count();
        let hits = self.get_cache_hits();
        let misses = self.get_cache_misses();
        let hit_rate = self.get_cache_hit_rate();
        let validations = self.get_dnssec_validations();
        let failures = self.get_dnssec_failures();
        let dnssec_rate = self.get_dnssec_success_rate();

        tracing::info!(
            queries = queries,
            cache_hits = hits,
            cache_misses = misses,
            cache_hit_rate = format!("{:.2}%", hit_rate),
            dnssec_validations = validations,
            dnssec_failures = failures,
            dnssec_success_rate = format!("{:.2}%", dnssec_rate),
            "metrics snapshot"
        );
    }
}

impl Default for DnsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Timer for measuring query latency.
pub struct LatencyTimer {
    start: Instant,
}

impl LatencyTimer {
    /// Create a new latency timer.
    pub fn new() -> Self {
        LatencyTimer {
            start: Instant::now(),
        }
    }

    /// Get elapsed time in milliseconds.
    pub fn elapsed_ms(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1000.0
    }

    /// Get elapsed time in microseconds.
    pub fn elapsed_us(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1_000_000.0
    }
}

impl Default for LatencyTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Instrumentation helpers for tracing query processing.
pub mod instrumentation {
    use std::net::IpAddr;

    /// Trace entry into query processing.
    pub fn trace_query_received(remote_addr: &IpAddr, query_name: &str, query_type: u16) {
        tracing::debug!(remote_addr = %remote_addr, query_name, query_type, "query_received");
    }

    /// Trace rate limiting decision.
    pub fn trace_rate_limit_check(remote_addr: &IpAddr, allowed: bool) {
        if !allowed {
            tracing::warn!(remote_addr = %remote_addr, "rate_limit_exceeded");
        } else {
            tracing::debug!(remote_addr = %remote_addr, "rate_limit_allowed");
        }
    }

    /// Trace validation result.
    pub fn trace_validation(remote_addr: &IpAddr, valid: bool, reason: Option<&str>) {
        if valid {
            tracing::debug!(remote_addr = %remote_addr, "validation_passed");
        } else {
            tracing::warn!(remote_addr = %remote_addr, reason = ?reason, "validation_failed");
        }
    }

    /// Trace cache lookup.
    pub fn trace_cache_lookup(query_name: &str, query_type: u16, hit: bool) {
        if hit {
            tracing::debug!(query_name, query_type, "cache_hit");
        } else {
            tracing::debug!(query_name, query_type, "cache_miss");
        }
    }

    /// Trace DNSSEC validation.
    pub fn trace_dnssec_validation(signer_name: &str, valid: bool) {
        if valid {
            tracing::info!(signer_name, "dnssec_validation_passed");
        } else {
            tracing::warn!(signer_name, "dnssec_validation_failed");
        }
    }

    /// Trace query response generation with latency.
    pub fn trace_query_response(query_name: &str, query_type: u16, latency_ms: f64, error: Option<&str>) {
        if let Some(e) = error {
            tracing::error!(query_name, query_type, latency_ms, error = e, "query_response_error");
        } else {
            tracing::info!(query_name, query_type, latency_ms, "query_response_generated");
        }
    }

    /// Trace informational event.
    pub fn trace_info(context: &str, message: &str) {
        tracing::info!(context, message, "info_event");
    }

    /// Trace error condition.
    pub fn trace_error(context: &str, remote_addr: Option<&IpAddr>, message: &str) {
        if let Some(addr) = remote_addr {
            tracing::error!(context, remote_addr = %addr, message, "error_event");
        } else {
            tracing::error!(context, message, "error_event");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = DnsMetrics::new();
        assert_eq!(metrics.get_query_count(), 0);
        assert_eq!(metrics.get_cache_hits(), 0);
        assert_eq!(metrics.get_cache_misses(), 0);
    }

    #[test]
    fn test_increment_query_counter() {
        let metrics = DnsMetrics::new();
        metrics.increment_query_counter();
        assert_eq!(metrics.get_query_count(), 1);
        metrics.increment_query_counter();
        assert_eq!(metrics.get_query_count(), 2);
    }

    #[test]
    fn test_cache_hit_rate() {
        let metrics = DnsMetrics::new();
        metrics.increment_cache_hits();
        metrics.increment_cache_hits();
        metrics.increment_cache_misses();
        assert!((metrics.get_cache_hit_rate() - 66.67).abs() < 0.1);
    }

    #[test]
    fn test_dnssec_success_rate() {
        let metrics = DnsMetrics::new();
        metrics.increment_dnssec_validations();
        metrics.increment_dnssec_validations();
        metrics.increment_dnssec_failures();
        assert!((metrics.get_dnssec_success_rate() - 66.67).abs() < 0.1);
    }

    #[test]
    fn test_metrics_clone() {
        let metrics1 = DnsMetrics::new();
        metrics1.increment_query_counter();
        let metrics2 = metrics1.clone();
        assert_eq!(metrics2.get_query_count(), 1);
        metrics2.increment_query_counter();
        assert_eq!(metrics1.get_query_count(), 2);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = DnsMetrics::new();
        metrics.increment_query_counter();
        metrics.increment_cache_hits();
        metrics.reset();
        assert_eq!(metrics.get_query_count(), 0);
        assert_eq!(metrics.get_cache_hits(), 0);
    }

    #[test]
    fn test_latency_timer() {
        let timer = LatencyTimer::new();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed_ms = timer.elapsed_ms();
        assert!(elapsed_ms >= 10.0, "elapsed_ms should be >= 10ms, got {}", elapsed_ms);
    }
}
