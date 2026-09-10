//! What one admission decision costs, and what the shared mutex does to it.
//!
//! `TODO.md` #25f. `should_allow` took *two* global locks per datagram — one to
//! compare a cleanup timestamp, one for the bucket map — and the first is an
//! `AtomicU64` now. The second stays and is the ceiling: every UDP worker takes
//! it for every datagram.
//!
//! ```sh
//! cargo run --release -p rdns --example limiter_probe
//! ```
//!
//! Development machine, 2026-09-04, with the limit set high enough that nothing
//! is refused (the refusal path is cheaper, not dearer):
//!
//! ```text
//!                  Windows before   Windows after   Linux after
//!     1 thread          38.0 ns        29.8 ns        33.6 ns
//!     16 threads       180.2 ns       160.0 ns       143.2 ns
//! ```
//!
//! The gap between one thread and sixteen is what the remaining lock costs, and
//! it is why the bucket map is the first thing to shard — but at ~4 µs of
//! syscall per query it is 4% of a datagram, so not yet.

use std::hint::black_box;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use rdns::clock::current_unix_timestamp;
use rdns::security::{RateLimitConfig, RateLimiter};

fn main() {
    let rounds = 500_000u32;
    for threads in [1usize, 16] {
        let limiter = Arc::new(RateLimiter::new(RateLimitConfig::per_second(
            1_000_000, 1_000_000,
        )));
        let now = current_unix_timestamp();
        let start = Instant::now();
        let mut handles = Vec::new();
        for t in 0..threads {
            let limiter = limiter.clone();
            handles.push(std::thread::spawn(move || {
                let ip: IpAddr = format!("198.51.100.{}", t + 1).parse().unwrap();
                for _ in 0..rounds {
                    black_box(limiter.should_allow(black_box(ip), black_box(now)));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let ns = start.elapsed().as_nanos() as f64 / (rounds as f64 * threads as f64);
        println!("{threads:>3} threads: {ns:6.1} ns per admission");
    }
}
