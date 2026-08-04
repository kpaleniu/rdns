//! What one zone lookup costs in cache misses and branch mispredicts — the
//! diagnostic half of `TODO.md` #11.
//!
//! Run under cachegrind, which simulates the cache rather than reading a PMU: it
//! is deterministic, it models whatever cache size it is told to (the dev box
//! has 96 MiB of L3, so a 10k-record zone never leaves it and a real LLC counter
//! would read ~0), and the uncore PMU is not exposed on the Linux side anyway.
//!
//! Setup is cancelled by subtraction: run the same binary at `n` and `2n` and
//! subtract, so building the zone appears in both.
//!
//! ```sh
//! cargo build --release --example zone_lookup_probe
//! valgrind --tool=cachegrind --cache-sim=yes --branch-sim=yes \
//!     ./target/release/examples/zone_lookup_probe miss 100000
//! ```
//!
//! # Measured 2026-08-04
//!
//! Per lookup, `n=200_000` minus `n=100_000`. On the Linux side, cachegrind's
//! default model (32 KiB I1, 48 KiB D1, 128 MiB LL).
//!
//! | | instructions | cond. branches | D1 read misses | LL read misses |
//! |---|---|---|---|---|
//! | hit | 1,052 | 122 | 6.4 | 0 |
//! | miss | 2,786 | 338 | < 0.08 | 0 |
//!
//! A miss costs 2.6× a hit and touches almost no memory doing it: it is compute,
//! not pointer chasing. SipHash is 19.8% of all instructions and 23.2% of all
//! branch mispredicts. The hit path has the real pointer chase (`index` →
//! `Vec<usize>` → `records[i]`), all of it served by L2.
//!
//! The miss-path D1 figure is a bound, not a measurement: `RandomState` reseeds
//! per process, so three identical runs spread 7,776 D1 read misses against a
//! signal of 3,630. Tightening it means a fixed-seed `BuildHasher` on `Zone`,
//! which changes the type under test.
//!
//! # Callgrind, same date
//!
//! `--collect-atstart=no --toggle-collect='*probe_loop*'`, which agrees with
//! cachegrind to the instruction (2,786 Ir per miss). Per miss, before the
//! `has_wildcards` short-circuit:
//!
//! | | Ir | share |
//! |---|---|---|
//! | `name_kind_of_key` (inclusive) | 2,411 | 86.5% |
//! | `format!("*.{encloser}")` | 454 | 16.3% |
//! | `lookup_key` | 294 | 10.6% |
//! | `is_at_or_under` | 227 | 8.2% |
//! | `delegation_for_key` | 181 | 6.5% |
//!
//! `hash_one::<&str>` is called exactly 3 times per miss, from three sites — not
//! the five or six a reading of the code suggests.
//!
//! That table produced `Zone::has_wildcards`: with no wildcard in the zone, both
//! branches after the closest encloser end in `NotFound`, so the `format!`, the
//! delegation check and one hash are dead work. Skipping them took the miss path
//! from 2,786 to 1,900 instructions (31.8%), hit path unchanged.

use std::hint::black_box;
use std::net::Ipv4Addr;

use rdns::utils::record_types;
use rdns::zone::{Zone, ZoneRecord};
use rdns::{Class, ParsedRecord, Qtype, RecordData, Ttl};

/// The same zone `benches/answer_path.rs` builds, so the two measurements are
/// about one thing. Ten thousand names, one A record each.
fn ten_thousand_records() -> Zone {
    let mut zone = Zone::new("example.com.".to_string());
    for i in 0..10_000u32 {
        zone.add_record(ZoneRecord {
            name: format!("host{i}"),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(
                192,
                0,
                2,
                (i % 254) as u8 + 1,
            )))
            .expect("build the rdata"),
        });
    }
    zone
}

fn main() {
    let mut args = std::env::args().skip(1);
    let which = args.next().unwrap_or_else(|| "miss".to_string());
    let n: usize = args
        .next()
        .unwrap_or_else(|| "100000".to_string())
        .parse()
        .expect("iteration count");

    let zone = ten_thousand_records();
    let qtype = Qtype::of(record_types::A);

    // The names are built once, outside the loop: a `format!` per iteration
    // would be measuring the allocator, which is what `TODO.md` #9e already
    // did and is not this question.
    let hits: Vec<String> = (0..256)
        .map(|i| format!("host{}.example.com.", i * 37 % 10_000))
        .collect();
    let misses: Vec<String> = (0..256)
        .map(|i| format!("nothing-here-{i}.example.com."))
        .collect();
    let names = if which == "hit" { &hits } else { &misses };

    let found = probe_loop(&zone, names, qtype, n);
    // Printed so the loop cannot be optimized away, and so a run that measured
    // nothing is visible rather than silent.
    println!("{which} {n} -> {found} records");
}

/// The measured region, in a function of its own so callgrind can collect only
/// this.
///
/// `#[inline(never)]` is load-bearing: `--toggle-collect` starts and stops
/// collection on entry to and exit from a named symbol, and a symbol that was
/// inlined into `main` is one callgrind cannot toggle on. That is the
/// difference between reading call *counts* straight off the profile and having
/// to subtract two runs the way the cachegrind pass did — and call counts are
/// the thing cachegrind could not give at all.
#[inline(never)]
fn probe_loop(zone: &Zone, names: &[String], qtype: Qtype, n: usize) -> usize {
    let mut found = 0usize;
    for i in 0..n {
        // Cycling through 256 names rather than repeating one: a single name
        // would sit in L1 and answer a question nobody asked.
        let name = &names[i % names.len()];
        found += black_box(zone.query(black_box(name), qtype)).len();
    }
    found
}
