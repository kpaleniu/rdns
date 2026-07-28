//! Performance benchmarking for Phase 3 features
//! This module provides utilities to measure the impact of rate limiting,
//! validation, and logging on DNS query performance.

#[cfg(test)]
mod benches {
    use crate::cache::DnsCache;
    use crate::logging::QueryLogger;
    use crate::metrics::DnsMetrics;
    use crate::security::RateLimiter;
    use crate::validation::RequestValidator;
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
        assert!(
            ops_per_sec > 100_000.0,
            "rate limiter too slow: {:.0} ops/sec",
            ops_per_sec
        );
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
        assert!(
            ops_per_sec > 50_000.0,
            "validator too slow: {:.0} ops/sec",
            ops_per_sec
        );
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

        // The floor was 45k, which is what this measures on an idle machine
        // (47-50k here) — so any competing load failed the suite and the number
        // said nothing about the code. A regression that matters, like a write
        // or an allocation per call, costs an order of magnitude; 10k catches
        // that and survives a busy machine.
        assert!(
            ops_per_sec > 10_000.0,
            "logger too slow: {:.0} ops/sec",
            ops_per_sec
        );
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
        assert!(
            ops_per_sec > 50_000.0,
            "cache get too slow: {:.0} ops/sec",
            ops_per_sec
        );
    }

    #[test]
    fn bench_metrics_throughput() {
        let metrics = DnsMetrics::new();
        let iterations = 100_000;

        let start = Instant::now();
        for _ in 0..iterations {
            metrics
                .queries_received
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        assert!(
            ops_per_sec > 1_000_000.0,
            "metrics too slow: {:.0} ops/sec",
            ops_per_sec
        );
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
            metrics
                .queries_received
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

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
        assert!(
            ops_per_sec > 10_000.0,
            "pipeline too slow: {:.0} ops/sec",
            ops_per_sec
        );
    }

    #[test]
    fn bench_nested_record_type_matching() {
        // Performance review: nested enum pattern matching in zone queries
        // This tests the hot path: zone.query() -> record_type() matching
        use crate::{ParsedRecord, RecordData, ResourceRecord};
        use std::net::{Ipv4Addr, Ipv6Addr};

        let build = |parsed: ParsedRecord| RecordData::from_parsed(&parsed).unwrap();
        let records = vec![
            ResourceRecord {
                name: "www.example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: build(ParsedRecord::A(Ipv4Addr::new(1, 2, 3, 4))),
            },
            ResourceRecord {
                name: "mail.example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: build(ParsedRecord::MX {
                    preference: 10,
                    exchange: "mx.example.com.".to_string(),
                }),
            },
            ResourceRecord {
                name: "example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: build(ParsedRecord::NS("ns1.example.com.".to_string())),
            },
            ResourceRecord {
                name: "ipv6.example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: build(ParsedRecord::AAAA(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
                ))),
            },
            ResourceRecord {
                name: "example.com.".to_string(),
                class: 1,
                ttl: 3600,
                rdata: build(ParsedRecord::DNSKEY {
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
                rdata: build(ParsedRecord::DS {
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
                // With raw-byte storage the record type is a direct field read,
                // not a two-level enum match.
                let _type_id = record.rdata.rtype;
                std::hint::black_box(_type_id);
            }
        }

        let elapsed = start.elapsed();
        let ops_per_sec = (iterations * records.len()) as f64 / elapsed.as_secs_f64();
        println!(
            "Record type lookup: {:.0} ops/sec ({:.3}μs per lookup)",
            ops_per_sec,
            elapsed.as_secs_f64() * 1_000_000.0 / (iterations * records.len()) as f64
        );

        // Gross-regression floor, not a benchmark: a plain field read should never
        // drop to parse-like cost. Kept well below the observed debug-build rate
        // (~150M ops/sec) so parallel-test CPU contention doesn't make it flaky.
        assert!(
            ops_per_sec > 10_000_000.0,
            "type lookup too slow: {:.0} ops/sec",
            ops_per_sec
        );
    }

    #[test]
    fn bench_recorddata_clone_performance() {
        // Test cloning performance of RecordData (refactoring impact on cache/storage)
        use crate::{ParsedRecord, RecordData};

        // Most common case: a name-bearing record (NS/CNAME/MX/TXT).
        let mx_record = RecordData::from_parsed(&ParsedRecord::MX {
            preference: 10,
            exchange: "mail.example.com.".to_string(),
        })
        .unwrap();

        // Less common: DNSSEC with a large key.
        let dnskey_record = RecordData::from_parsed(&ParsedRecord::DNSKEY {
            flags: 256,
            protocol: 3,
            algorithm: 8,
            public_key: vec![0; 256], // 256-byte RSA public key
        })
        .unwrap();

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
        assert!(
            standard_ops_per_sec > 1_000_000.0,
            "StandardRecord clone too slow"
        );
    }

    /// Zone lookup on a zone big enough for the difference to matter.
    ///
    /// `Zone::query` used to filter the whole record vector per query, and the
    /// name comparison normalized and lower-cased *both* names into fresh
    /// `String`s for every record it touched — so one lookup on a 10k-record
    /// zone did 20k allocations. Measured here before and after the index went
    /// in: **227 lookups/sec (4.4 ms each) → 1.32M lookups/sec (0.755 µs)**, in
    /// a debug build.
    ///
    /// The floor asserted below is an order of magnitude under the second figure
    /// and three under the first: it is a guard against going back to a linear
    /// scan, not a claim about how fast this machine is on any given day.
    #[test]
    fn bench_zone_lookup() {
        use crate::zone::{Zone, ZoneRecord};
        use crate::{ParsedRecord, RecordData};
        use std::net::Ipv4Addr;

        let mut zone = Zone::new("example.com.".to_string());
        for i in 0..10_000u32 {
            zone.add_record(ZoneRecord {
                name: format!("host{i}"),
                ttl: 3600,
                class: 1,
                rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(
                    192,
                    0,
                    2,
                    (i % 254) as u8 + 1,
                )))
                .unwrap(),
            });
        }

        let iterations = 20_000;
        let start = Instant::now();
        for i in 0..iterations {
            // A hit deep in the zone, and a miss — the miss is what a linear
            // scan pays the most for, and what a random-name flood produces.
            let hit = format!("host{}.example.com.", 9_000 + (i % 1_000));
            assert_eq!(zone.query(&hit, 1).len(), 1);
            assert!(zone.query("nothing-here.example.com.", 1).is_empty());
        }
        let elapsed = start.elapsed();

        let lookups_per_sec = (iterations * 2) as f64 / elapsed.as_secs_f64();
        println!(
            "Zone lookup (10k records): {:.0} lookups/sec ({:.3}us per lookup)",
            lookups_per_sec,
            elapsed.as_secs_f64() * 1_000_000.0 / (iterations * 2) as f64
        );

        assert!(
            lookups_per_sec > 100_000.0,
            "zone lookup has gone back to scanning: {lookups_per_sec:.0} lookups/sec"
        );
    }
}
