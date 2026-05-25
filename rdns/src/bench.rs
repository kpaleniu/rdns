/// Performance benchmarking for Phase 3 features
/// This module provides utilities to measure the impact of rate limiting,
/// validation, and logging on DNS query performance.

#[cfg(test)]
mod benches {
    use crate::security::RateLimiter;
    use crate::validation::RequestValidator;
    use crate::logging::QueryLogger;
    use crate::cache::DnsCache;
    use crate::metrics::DnsMetrics;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    #[test]
    fn bench_rate_limiter_throughput() {
        let limiter = RateLimiter::with_defaults();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let iterations = 10_000;

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = limiter.should_allow(ip);
        }
        let elapsed = start.elapsed();

        let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
        println!(
            "Rate Limiter: {:.0} ops/sec ({:.3}ms total for {} ops)",
            ops_per_sec,
            elapsed.as_secs_f64() * 1000.0,
            iterations
        );

        // Sanity check: should be very fast (>100k ops/sec)
        assert!(ops_per_sec > 100_000.0, "rate limiter too slow: {:.0} ops/sec", ops_per_sec);
    }

    #[test]
    fn bench_validator_throughput() {
        let validator = RequestValidator::with_defaults();
        let packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags
            0x00, 0x01, // 1 query
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authorities
            0x00, 0x00, // 0 additionals
            0x03, 0x77, 0x77, 0x77, // "www"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // root
            0x00, 0x01, // A record
            0x00, 0x01, // IN class
        ];

        let iterations = 10_000;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = validator.validate_packet(&packet, false);
        }
        let elapsed = start.elapsed();

        let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
        println!(
            "Validator: {:.0} ops/sec ({:.3}ms total for {} ops)",
            ops_per_sec,
            elapsed.as_secs_f64() * 1000.0,
            iterations
        );

        // Sanity check: should be very fast (>50k ops/sec)
        assert!(ops_per_sec > 50_000.0, "validator too slow: {:.0} ops/sec", ops_per_sec);
    }

    #[test]
    fn bench_logger_throughput() {
        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let iterations = 10_000;

        let start = Instant::now();
        for _ in 0..iterations {
            logger.log_query(ip, Some(1));
        }
        let elapsed = start.elapsed();

        let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
        println!(
            "Logger: {:.0} ops/sec ({:.3}ms total for {} ops)",
            ops_per_sec,
            elapsed.as_secs_f64() * 1000.0,
            iterations
        );

        // Sanity check: should be fast enough (>45k ops/sec with mutex overhead)
        assert!(ops_per_sec > 45_000.0, "logger too slow: {:.0} ops/sec", ops_per_sec);
    }

    #[test]
    fn bench_cache_throughput() {
        let cache = DnsCache::with_defaults();
        let iterations = 10_000;

        let start = Instant::now();
        for i in 0..iterations {
            let name = format!("example{}.com.", i % 100);
            let _ = cache.get(&name, 1);
        }
        let elapsed = start.elapsed();

        let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
        println!(
            "Cache Get: {:.0} ops/sec ({:.3}ms total for {} ops)",
            ops_per_sec,
            elapsed.as_secs_f64() * 1000.0,
            iterations
        );

        // Sanity check: should be fast (>50k ops/sec with mutex)
        assert!(ops_per_sec > 50_000.0, "cache get too slow: {:.0} ops/sec", ops_per_sec);
    }

    #[test]
    fn bench_metrics_throughput() {
        let metrics = DnsMetrics::new();
        let iterations = 100_000;

        let start = Instant::now();
        for _ in 0..iterations {
            metrics.queries_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            metrics.track_query_type(1);
        }
        let elapsed = start.elapsed();

        let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
        println!(
            "Metrics: {:.0} ops/sec ({:.3}ms total for {} ops)",
            ops_per_sec,
            elapsed.as_secs_f64() * 1000.0,
            iterations
        );

        // Sanity check: should be extremely fast (atomic operations)
        assert!(ops_per_sec > 1_000_000.0, "metrics too slow: {:.0} ops/sec", ops_per_sec);
    }

    #[test]
    fn bench_combined_pipeline() {
        // Simulate full query processing pipeline
        let limiter = RateLimiter::with_defaults();
        let validator = RequestValidator::with_defaults();
        let logger = QueryLogger::new();
        let cache = DnsCache::with_defaults();
        let metrics = DnsMetrics::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let packet = vec![
            0x00, 0x01, // ID
            0x00, 0x00, // flags
            0x00, 0x01, // 1 query
            0x00, 0x00, // 0 answers
            0x00, 0x00, // 0 authorities
            0x00, 0x00, // 0 additionals
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // root
            0x00, 0x01, // A record
            0x00, 0x01, // IN class
        ];

        let iterations = 5_000;
        let start = Instant::now();
        for i in 0..iterations {
            metrics.queries_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            
            if limiter.should_allow(ip) {
                let validation = validator.validate_packet(&packet, false);
                if validation.is_valid() {
                    logger.log_query(ip, Some(1));
                    metrics.track_query_type(1);
                    
                    // Cache get
                    let name = format!("google{}.com.", i % 10);
                    let _ = cache.get(&name, 1);
                }
            }
        }
        let elapsed = start.elapsed();

        let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
        println!(
            "Combined Pipeline: {:.0} ops/sec ({:.3}ms total for {} ops)",
            ops_per_sec,
            elapsed.as_secs_f64() * 1000.0,
            iterations
        );

        // Sanity check: should handle at least 10k ops/sec combined
        assert!(ops_per_sec > 10_000.0, "pipeline too slow: {:.0} ops/sec", ops_per_sec);
    }

    #[test]
    fn bench_nested_record_type_matching() {
        // Performance review: nested enum pattern matching in zone queries
        // This tests the hot path: zone.query() -> record_type() matching
        use crate::{ResourceRecord, RecordData, StandardRecord, DnssecRecord};
        use std::net::{Ipv4Addr, Ipv6Addr};

        let records = vec![
            ResourceRecord {
                name: "www.example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: RecordData::Standard(StandardRecord::A(Ipv4Addr::new(1, 2, 3, 4))),
            },
            ResourceRecord {
                name: "mail.example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: RecordData::Standard(StandardRecord::MX {
                    preference: 10,
                    exchange: "mx.example.com.".to_string(),
                }),
            },
            ResourceRecord {
                name: "example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: RecordData::Standard(StandardRecord::NS("ns1.example.com.".to_string())),
            },
            ResourceRecord {
                name: "ipv6.example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: RecordData::Standard(StandardRecord::AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            },
            ResourceRecord {
                name: "example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: RecordData::Dnssec(DnssecRecord::DNSKEY {
                    flags: 256,
                    protocol: 3,
                    algorithm: 8,
                    public_key: vec![1, 2, 3, 4, 5],
                }),
            },
            ResourceRecord {
                name: "example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: RecordData::Dnssec(DnssecRecord::DS {
                    key_tag: 12345,
                    algorithm: 8,
                    digest_type: 2,
                    digest: vec![1, 2, 3, 4],
                }),
            },
        ];

        let iterations = 50_000;
        let start = Instant::now();

        for _ in 0..iterations {
            for record in &records {
                // Simulate zone query type matching (2-level nested match)
                let _type_id = match &record.rdata {
                    RecordData::Standard(sr) => match sr {
                        StandardRecord::A(_) => 1u16,
                        StandardRecord::NS(_) => 2u16,
                        StandardRecord::CNAME(_) => 5u16,
                        StandardRecord::SOA { .. } => 6u16,
                        StandardRecord::PTR(_) => 12u16,
                        StandardRecord::MX { .. } => 15u16,
                        StandardRecord::TXT(_) => 16u16,
                        StandardRecord::AAAA(_) => 28u16,
                    },
                    RecordData::Dnssec(dr) => match dr {
                        DnssecRecord::DS { .. } => 43u16,
                        DnssecRecord::RRSIG { .. } => 46u16,
                        DnssecRecord::NSEC { .. } => 47u16,
                        DnssecRecord::DNSKEY { .. } => 48u16,
                        DnssecRecord::NSEC3 { .. } => 50u16,
                    },
                    RecordData::Unknown(id) => *id,
                };
            }
        }

        let elapsed = start.elapsed();
        let ops_per_sec = (iterations * records.len()) as f64 / elapsed.as_secs_f64();
        println!(
            "Nested Pattern Matching: {:.0} ops/sec ({:.3}μs per match)",
            ops_per_sec,
            elapsed.as_secs_f64() * 1_000_000.0 / (iterations * records.len()) as f64
        );

        // Sanity check: should be very fast (compiler should inline the matches)
        assert!(ops_per_sec > 100_000_000.0, "nested matching too slow: {:.0} ops/sec", ops_per_sec);
    }

    #[test]
    fn bench_recorddata_clone_performance() {
        // Test cloning performance of RecordData (refactoring impact on cache/storage)
        use crate::{RecordData, StandardRecord, DnssecRecord};

        // Most common case: StandardRecord with String data (NS/CNAME/MX/TXT)
        let mx_record = RecordData::Standard(StandardRecord::MX {
            preference: 10,
            exchange: "mail.example.com.".to_string(),
        });

        // Less common: DNSSEC with Vec<u8> (cryptographic data)
        let dnskey_record = RecordData::Dnssec(DnssecRecord::DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 8,
            public_key: vec![0; 256], // 256-byte RSA public key
        });

        let iterations = 100_000;

        // Benchmark StandardRecord clone (most common)
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = mx_record.clone();
        }
        let standard_elapsed = start.elapsed();
        let standard_ops_per_sec = iterations as f64 / standard_elapsed.as_secs_f64();

        // Benchmark DnssecRecord clone (less common)
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = dnskey_record.clone();
        }
        let dnssec_elapsed = start.elapsed();
        let dnssec_ops_per_sec = iterations as f64 / dnssec_elapsed.as_secs_f64();

        println!(
            "StandardRecord clone: {:.0} ops/sec ({:.3}μs per clone)",
            standard_ops_per_sec,
            standard_elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64
        );
        println!(
            "DnssecRecord clone (256b key): {:.0} ops/sec ({:.3}μs per clone)",
            dnssec_ops_per_sec,
            dnssec_elapsed.as_secs_f64() * 1_000_000.0 / iterations as f64
        );

        // Should be reasonably fast (String clone is cheap unless strings are huge)
        assert!(standard_ops_per_sec > 1_000_000.0, "StandardRecord clone too slow");
    }
}
