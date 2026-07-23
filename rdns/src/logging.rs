use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use crate::utils::current_unix_timestamp;

/// Query statistics for monitoring and anomaly detection
#[derive(Debug, Clone)]
pub struct QueryStats {
    /// Total queries processed
    pub total_queries: u64,
    /// Total errors encountered
    pub total_errors: u64,
    /// Queries per second (last measurement)
    pub qps: f64,
    /// Per-IP query counts
    pub queries_by_ip: HashMap<IpAddr, u64>,
    /// Per-record-type query counts
    pub queries_by_type: HashMap<u16, u64>,
    /// IPs with rate limiting triggered
    pub rate_limited_ips: HashMap<IpAddr, u64>,
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
        
        // Track per-IP queries
        *stats.queries_by_ip.entry(ip).or_insert(0) += 1;
        
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
        
        // Remove old entries (older than max_age)
        let age_limit = now - max_age_secs;
        window.queries.retain(|&t| t > age_limit);
        
        // Update QPS periodically
        let mut last_update = self.last_qps_update.lock().unwrap();
        if now - *last_update >= 5 {
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
        *stats.rate_limited_ips.entry(ip).or_insert(0) += 1;
    }

    /// Check for anomalies and print warnings
    pub fn check_anomalies(&self) {
        let stats = self.stats.lock().unwrap();
        
        // Check for high QPS
        if stats.qps > 50.0 {
            eprintln!("[QueryLogger] WARNING: High QPS detected: {:.2} q/s", stats.qps);
        }
        
        // Check for high error rate
        let error_rate = if stats.total_queries > 0 {
            (stats.total_errors as f64) / (stats.total_queries as f64)
        } else {
            0.0
        };
        
        if error_rate > 0.1 {
            eprintln!("[QueryLogger] WARNING: High error rate: {:.2}%", error_rate * 100.0);
        }
        
        // Check for IPs with many queries
        for (ip, count) in &stats.queries_by_ip {
            if *count > 100 {
                eprintln!("[QueryLogger] WARNING: High query count from {}: {}", ip, count);
            }
        }
        
        // Check for IPs that have been rate limited multiple times
        for (ip, count) in &stats.rate_limited_ips {
            if *count > 5 {
                eprintln!(
                    "[QueryLogger] WARNING: {} rate limited {} times",
                    ip, count
                );
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
