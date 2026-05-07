use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Prometheus-compatible metrics for DNS server
pub struct DnsMetrics {
    // Query counters
    pub queries_received: Arc<AtomicU64>,
    pub queries_authoritative: Arc<AtomicU64>,
    pub queries_recursive: Arc<AtomicU64>,
    
    // Response counters
    pub responses_sent: Arc<AtomicU64>,
    pub responses_nxdomain: Arc<AtomicU64>,
    pub responses_servfail: Arc<AtomicU64>,
    pub responses_refused: Arc<AtomicU64>,
    pub responses_noerror: Arc<AtomicU64>,
    
    // Cache metrics
    pub cache_hits: Arc<AtomicU64>,
    pub cache_misses: Arc<AtomicU64>,
    
    // Security metrics
    pub rate_limited: Arc<AtomicU64>,
    pub validation_errors: Arc<AtomicU64>,
    pub queries_dropped: Arc<AtomicU64>,
    
    // Record type counters
    pub queries_type_a: Arc<AtomicU64>,
    pub queries_type_aaaa: Arc<AtomicU64>,
    pub queries_type_mx: Arc<AtomicU64>,
    pub queries_type_ns: Arc<AtomicU64>,
    pub queries_type_cname: Arc<AtomicU64>,
    pub queries_type_txt: Arc<AtomicU64>,
    pub queries_type_soa: Arc<AtomicU64>,
    pub queries_type_ptr: Arc<AtomicU64>,
    pub queries_type_other: Arc<AtomicU64>,
}

impl DnsMetrics {
    pub fn new() -> Self {
        DnsMetrics {
            queries_received: Arc::new(AtomicU64::new(0)),
            queries_authoritative: Arc::new(AtomicU64::new(0)),
            queries_recursive: Arc::new(AtomicU64::new(0)),
            responses_sent: Arc::new(AtomicU64::new(0)),
            responses_nxdomain: Arc::new(AtomicU64::new(0)),
            responses_servfail: Arc::new(AtomicU64::new(0)),
            responses_refused: Arc::new(AtomicU64::new(0)),
            responses_noerror: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            rate_limited: Arc::new(AtomicU64::new(0)),
            validation_errors: Arc::new(AtomicU64::new(0)),
            queries_dropped: Arc::new(AtomicU64::new(0)),
            queries_type_a: Arc::new(AtomicU64::new(0)),
            queries_type_aaaa: Arc::new(AtomicU64::new(0)),
            queries_type_mx: Arc::new(AtomicU64::new(0)),
            queries_type_ns: Arc::new(AtomicU64::new(0)),
            queries_type_cname: Arc::new(AtomicU64::new(0)),
            queries_type_txt: Arc::new(AtomicU64::new(0)),
            queries_type_soa: Arc::new(AtomicU64::new(0)),
            queries_type_ptr: Arc::new(AtomicU64::new(0)),
            queries_type_other: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Track query type
    pub fn track_query_type(&self, qtype: u16) {
        match qtype {
            1 => self.queries_type_a.fetch_add(1, Ordering::Relaxed),
            28 => self.queries_type_aaaa.fetch_add(1, Ordering::Relaxed),
            15 => self.queries_type_mx.fetch_add(1, Ordering::Relaxed),
            2 => self.queries_type_ns.fetch_add(1, Ordering::Relaxed),
            5 => self.queries_type_cname.fetch_add(1, Ordering::Relaxed),
            16 => self.queries_type_txt.fetch_add(1, Ordering::Relaxed),
            6 => self.queries_type_soa.fetch_add(1, Ordering::Relaxed),
            12 => self.queries_type_ptr.fetch_add(1, Ordering::Relaxed),
            _ => self.queries_type_other.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Generate Prometheus format metrics output
    pub fn to_prometheus_format(&self) -> String {
        let mut output = String::new();

        output.push_str("# HELP dns_queries_received_total Total DNS queries received\n");
        output.push_str("# TYPE dns_queries_received_total counter\n");
        output.push_str(&format!(
            "dns_queries_received_total {}\n",
            self.queries_received.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_queries_authoritative_total Authoritative queries handled\n");
        output.push_str("# TYPE dns_queries_authoritative_total counter\n");
        output.push_str(&format!(
            "dns_queries_authoritative_total {}\n",
            self.queries_authoritative.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_queries_recursive_total Recursive queries handled\n");
        output.push_str("# TYPE dns_queries_recursive_total counter\n");
        output.push_str(&format!(
            "dns_queries_recursive_total {}\n",
            self.queries_recursive.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_responses_sent_total Total DNS responses sent\n");
        output.push_str("# TYPE dns_responses_sent_total counter\n");
        output.push_str(&format!(
            "dns_responses_sent_total {}\n",
            self.responses_sent.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_responses_nxdomain_total NXDOMAIN responses\n");
        output.push_str("# TYPE dns_responses_nxdomain_total counter\n");
        output.push_str(&format!(
            "dns_responses_nxdomain_total {}\n",
            self.responses_nxdomain.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_responses_servfail_total SERVFAIL responses\n");
        output.push_str("# TYPE dns_responses_servfail_total counter\n");
        output.push_str(&format!(
            "dns_responses_servfail_total {}\n",
            self.responses_servfail.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_responses_refused_total REFUSED responses\n");
        output.push_str("# TYPE dns_responses_refused_total counter\n");
        output.push_str(&format!(
            "dns_responses_refused_total {}\n",
            self.responses_refused.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_responses_noerror_total NOERROR responses\n");
        output.push_str("# TYPE dns_responses_noerror_total counter\n");
        output.push_str(&format!(
            "dns_responses_noerror_total {}\n",
            self.responses_noerror.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_cache_hits_total Cache hits\n");
        output.push_str("# TYPE dns_cache_hits_total counter\n");
        output.push_str(&format!(
            "dns_cache_hits_total {}\n",
            self.cache_hits.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_cache_misses_total Cache misses\n");
        output.push_str("# TYPE dns_cache_misses_total counter\n");
        output.push_str(&format!(
            "dns_cache_misses_total {}\n",
            self.cache_misses.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_rate_limited_total Rate limited queries\n");
        output.push_str("# TYPE dns_rate_limited_total counter\n");
        output.push_str(&format!(
            "dns_rate_limited_total {}\n",
            self.rate_limited.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_validation_errors_total Validation errors\n");
        output.push_str("# TYPE dns_validation_errors_total counter\n");
        output.push_str(&format!(
            "dns_validation_errors_total {}\n",
            self.validation_errors.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP dns_queries_dropped_total Dropped queries\n");
        output.push_str("# TYPE dns_queries_dropped_total counter\n");
        output.push_str(&format!(
            "dns_queries_dropped_total {}\n",
            self.queries_dropped.load(Ordering::Relaxed)
        ));

        // Record type metrics
        output.push_str("# HELP dns_queries_type Total queries by type\n");
        output.push_str("# TYPE dns_queries_type counter\n");
        output.push_str(&format!(
            "dns_queries_type{{type=\"A\"}} {}\n",
            self.queries_type_a.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"AAAA\"}} {}\n",
            self.queries_type_aaaa.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"MX\"}} {}\n",
            self.queries_type_mx.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"NS\"}} {}\n",
            self.queries_type_ns.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"CNAME\"}} {}\n",
            self.queries_type_cname.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"TXT\"}} {}\n",
            self.queries_type_txt.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"SOA\"}} {}\n",
            self.queries_type_soa.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"PTR\"}} {}\n",
            self.queries_type_ptr.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "dns_queries_type{{type=\"OTHER\"}} {}\n",
            self.queries_type_other.load(Ordering::Relaxed)
        ));

        output
    }

    /// Get current metrics snapshot
    pub fn get_snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queries_received: self.queries_received.load(Ordering::Relaxed),
            queries_authoritative: self.queries_authoritative.load(Ordering::Relaxed),
            queries_recursive: self.queries_recursive.load(Ordering::Relaxed),
            responses_sent: self.responses_sent.load(Ordering::Relaxed),
            responses_nxdomain: self.responses_nxdomain.load(Ordering::Relaxed),
            responses_servfail: self.responses_servfail.load(Ordering::Relaxed),
            responses_refused: self.responses_refused.load(Ordering::Relaxed),
            responses_noerror: self.responses_noerror.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            validation_errors: self.validation_errors.load(Ordering::Relaxed),
            queries_dropped: self.queries_dropped.load(Ordering::Relaxed),
        }
    }
}

impl Default for DnsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub queries_received: u64,
    pub queries_authoritative: u64,
    pub queries_recursive: u64,
    pub responses_sent: u64,
    pub responses_nxdomain: u64,
    pub responses_servfail: u64,
    pub responses_refused: u64,
    pub responses_noerror: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub rate_limited: u64,
    pub validation_errors: u64,
    pub queries_dropped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = DnsMetrics::new();
        assert_eq!(metrics.queries_received.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_increment() {
        let metrics = DnsMetrics::new();
        metrics.queries_received.fetch_add(1, Ordering::Relaxed);
        metrics.responses_sent.fetch_add(1, Ordering::Relaxed);

        assert_eq!(metrics.queries_received.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.responses_sent.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_track_query_type() {
        let metrics = DnsMetrics::new();
        
        metrics.track_query_type(1);  // A
        metrics.track_query_type(1);  // A
        metrics.track_query_type(28); // AAAA
        metrics.track_query_type(99); // Unknown

        assert_eq!(metrics.queries_type_a.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.queries_type_aaaa.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.queries_type_other.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_prometheus_format() {
        let metrics = DnsMetrics::new();
        metrics.queries_received.fetch_add(100, Ordering::Relaxed);
        metrics.responses_sent.fetch_add(90, Ordering::Relaxed);

        let prometheus = metrics.to_prometheus_format();
        assert!(prometheus.contains("dns_queries_received_total 100"));
        assert!(prometheus.contains("dns_responses_sent_total 90"));
        assert!(prometheus.contains("# HELP"));
        assert!(prometheus.contains("# TYPE"));
    }

    #[test]
    fn test_metrics_snapshot() {
        let metrics = DnsMetrics::new();
        metrics.queries_received.fetch_add(50, Ordering::Relaxed);
        metrics.cache_hits.fetch_add(25, Ordering::Relaxed);

        let snapshot = metrics.get_snapshot();
        assert_eq!(snapshot.queries_received, 50);
        assert_eq!(snapshot.cache_hits, 25);
    }
}
