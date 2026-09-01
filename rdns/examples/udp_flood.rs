//! A closed-loop UDP load generator, for asking whether something on the answer
//! path is a ceiling. Kept because #28d's answer is a *negative* result, and a
//! negative result nobody can reproduce is an opinion (`TODO.md` §10).
//!
//! Each thread owns a socket bound to its own loopback address, sends one query,
//! waits for the answer, repeats. Reports answers per second across all threads.
//! Pair it with the server's own CPU time — `utime + stime` from
//! `/proc/<pid>/stat` — since on one box the client competes with the server for
//! cores and throughput alone cannot tell you which of them the ceiling belongs
//! to.
//!
//! ```sh
//! cargo run --release -p rdns --example udp_flood -- 127.0.0.1:15353 16 5
//! cargo run --release -p rdns --example udp_flood -- 127.0.0.1:15353 16 5 mixed
//! ```

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

fn query(id: u16, mixed_case: bool) -> Vec<u8> {
    let (a, b, c): (&[u8], &[u8], &[u8]) = if mixed_case {
        (b"WwW", b"eXaMpLe", b"CoM")
    } else {
        (b"www", b"example", b"com")
    };
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x00]); // flags: QUERY, RD=0
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0]); // AN, NS
    out.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT: the OPT below
    for label in [a, b, c] {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
                                                // OPT: root owner, TYPE 41, 1232 payload, DO set, one cookie option.
    out.push(0);
    out.extend_from_slice(&41u16.to_be_bytes());
    out.extend_from_slice(&1232u16.to_be_bytes());
    out.extend_from_slice(&0x0000_8000u32.to_be_bytes());
    out.extend_from_slice(&12u16.to_be_bytes());
    out.extend_from_slice(&10u16.to_be_bytes()); // COOKIE
    out.extend_from_slice(&8u16.to_be_bytes());
    out.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let target = args.get(1).cloned().unwrap_or("127.0.0.1:15353".into());
    let threads: usize = args.get(2).map_or(8, |s| s.parse().unwrap());
    let secs: u64 = args.get(3).map_or(5, |s| s.parse().unwrap());
    let mixed = args.get(4).is_some_and(|s| s == "mixed");

    let answered = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(threads + 1));

    let mut handles = Vec::new();
    for t in 0..threads {
        let (answered, stop, barrier, target) = (
            answered.clone(),
            stop.clone(),
            barrier.clone(),
            target.clone(),
        );
        handles.push(std::thread::spawn(move || {
            // A distinct source address per thread. All of them sharing one
            // would put the whole load in a single token bucket, so the run
            // would measure the rate limiter's *policy* instead of its cost.
            let socket = UdpSocket::bind(format!("127.0.0.{}:0", t + 1))
                .unwrap_or_else(|e| panic!("bind 127.0.0.{}: {e}", t + 1));
            socket
                .set_read_timeout(Some(Duration::from_millis(500)))
                .expect("timeout");
            let packet = query(t as u16, mixed);
            let mut buf = [0u8; 1500];
            let mut n = 0u64;
            barrier.wait();
            while !stop.load(Ordering::Relaxed) {
                if socket.send_to(&packet, &target).is_err() {
                    continue;
                }
                if socket.recv_from(&mut buf).is_ok() {
                    n += 1;
                }
            }
            answered.fetch_add(n, Ordering::Relaxed);
        }));
    }

    barrier.wait();
    let start = Instant::now();
    std::thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    let elapsed = start.elapsed().as_secs_f64();
    let total = answered.load(Ordering::Relaxed);
    println!(
        "{:.0} answers/s ({total} in {elapsed:.2}s, {threads} client threads)",
        total as f64 / elapsed
    );
}
