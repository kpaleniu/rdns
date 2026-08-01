//! Two wall-clock floors that guard a complexity class. **Not benchmarks.**
//!
//! The benchmarks are in `benches/answer_path.rs` and run under criterion, which
//! measures optimized code and can compare a run against a saved baseline. This
//! file used to hold nine `#[test]`s that timed things in a **debug** build and
//! asserted an ops/sec floor, which is neither: a debug number cannot judge an
//! optimization, and most of those floors guarded nothing that could regress in
//! a way a floor would notice (`TODO.md` #9e).
//!
//! What is left are the two where the floor *is* the point — where the thing
//! being asserted is not "this is fast" but "this has not gone back to being
//! O(n)". Those belong in `cargo test`, where CI runs them on every commit,
//! rather than in a benchmark nobody runs before a change. Both have a factor of
//! ten or more of headroom for exactly the reason `CLAUDE.md` §10 gives: a
//! wall-clock assertion with no headroom is a coin toss, not a test.
//!
//! The file keeps its name because the history references it — `CLAUDE.md` §10
//! and several `TODO.md` entries name `bench_logger_throughput` and
//! `bench_zone_lookup` as the examples they argue from.
//!
//! Seven went, and what replaced each:
//!
//! | deleted | why |
//! |---|---|
//! | `bench_rate_limiter_throughput` | measured in release now as `admission/rate limiter`; the floor guarded no complexity class |
//! | `bench_validator_throughput` | `admission/request validator` |
//! | `bench_cache_throughput` | it only ever called `get` on an *empty* cache, so it never reached `evict_oldest` and could not see the O(n²) eviction it looked like it was watching. `cache::tests::evicting_a_large_cache_is_linear_not_quadratic` is the tripwire; `state/100 puts into a full cache` is the measurement |
//! | `bench_metrics_throughput` | a floor on `AtomicU64::fetch_add`, which measures the machine |
//! | `bench_combined_pipeline` | a synthetic pipeline that did not parse, look up or serialize anything — `answer/one whole answer` is the real one |
//! | `bench_nested_record_type_matching` | it asserted that reading a `u16` field is fast, after the enum match it was written for stopped existing |
//! | `bench_recorddata_clone_performance` | a `Box<[u8]>` clone, measured now where it actually happens, on the answer path |

#[cfg(test)]
mod benches {
    use crate::logging::QueryLogger;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

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

        // The floor has moved twice and the history is the point. It was 45k —
        // exactly what an idle machine measured — so any competing load failed
        // the suite; it was lowered to 10k and blamed on that competing load,
        // which ratified the O(window) regression in `log_query` the benchmark
        // had correctly caught (`CLAUDE.md` §10). With the window replaced by a
        // count this measures ~3.1M ops/sec in debug, so 100k is well past the
        // factor of ten of headroom `bench_zone_lookup` sets as the rule, and
        // still an order of magnitude above what the quadratic could reach.
        //
        // The floor is not the real guard, though: it is a wall-clock number and
        // a busy machine can still move it. `logging::tests::
        // logging_a_query_costs_the_same_however_many_came_before` asserts the
        // shape — cost independent of depth — as a ratio, which is what actually
        // catches this class coming back. `state/log a query with 1k sources
        // tracked` in `benches/answer_path.rs` is the number in release: 49 ns.
        assert!(
            ops_per_sec > 100_000.0,
            "logger too slow: {:.0} ops/sec",
            ops_per_sec
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
    /// scan, not a claim about how fast this machine is on any given day. The
    /// release figures are `zone/hit in a 10k-record zone` (64 ns) and
    /// `zone/miss in a 10k-record zone` (165 ns) in `benches/answer_path.rs`.
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
