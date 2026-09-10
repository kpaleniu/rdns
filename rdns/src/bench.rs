//! Two wall-clock floors that guard a complexity class. Not benchmarks —
//! those are in `benches/answer_path.rs`, under criterion.
//!
//! Each asserts "this has not gone back to being O(n)" rather than "this is
//! fast", so they belong in `cargo test`. Both have a factor of ten or more of
//! headroom.

#[cfg(test)]
mod benches {
    use crate::logging::QueryLogger;
    use crate::record_types as rt;
    use crate::test_records::nm;
    use crate::utils::current_unix_timestamp;
    use crate::Qtype;
    use crate::{Class, Ttl};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    #[test]
    fn bench_logger_throughput() {
        let logger = QueryLogger::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let iterations = 10_000;

        let start = Instant::now();
        for _ in 0..iterations {
            logger.log_query(ip, Some(Qtype::of(rt::A)), current_unix_timestamp());
        }
        let elapsed = start.elapsed();

        let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
        println!(
            "Logger: {:.0} ops/sec ({:.3}ms total for {} ops)",
            ops_per_sec,
            elapsed.as_secs_f64() * 1000.0,
            iterations
        );

        // ~3.1M ops/sec in debug, so 100k is a factor of thirty of headroom and
        // still an order of magnitude above what the O(window) `log_query`
        // reached. A wall-clock floor is not the real guard:
        // `logging::tests::logging_a_query_costs_the_same_however_many_came_before`
        // asserts the shape as a ratio.
        assert!(
            ops_per_sec > 100_000.0,
            "logger too slow: {:.0} ops/sec",
            ops_per_sec
        );
    }

    /// A guard against `Zone::query` going back to scanning the whole record
    /// vector per query, not a claim about this machine.
    ///
    /// Debug build, before and after the index: 227 lookups/sec against 1.32M.
    /// The floor below is an order of magnitude under the second and three above
    /// the first.
    #[test]
    fn bench_zone_lookup() {
        use crate::zone::{Zone, ZoneRecord};
        use crate::{ParsedRecord, RecordData};
        use std::net::Ipv4Addr;

        let mut zone = Zone::new(nm("example.com."));
        for i in 0..10_000u32 {
            zone.add_record(ZoneRecord {
                name: nm(&format!("host{i}.example.com.")),
                ttl: Ttl::from_secs(3600),
                class: Class::new(1),
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
            // The miss is what a linear scan pays the most for, and what a
            // random-name flood produces.
            let hit = format!("host{}.example.com.", 9_000 + (i % 1_000));
            assert_eq!(zone.query(nm(&hit).as_ref(), Qtype::of(rt::A)).len(), 1);
            assert!(zone
                .query(nm("nothing-here.example.com.").as_ref(), Qtype::of(rt::A))
                .is_empty());
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
