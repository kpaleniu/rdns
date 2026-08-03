//! What one zone lookup costs in cache misses and branch mispredicts.
//!
//! **The diagnostic half of `TODO.md` #11.** `cargo bench` says a miss in a
//! 10k-record zone is 159 ns; it cannot say whether that is pointer chasing, and
//! without that a layout change is a guess with a stopwatch attached.
//!
//! Run under cachegrind, which *simulates* the cache rather than reading a PMU.
//! Three reasons that is the right instrument here and not a fallback:
//!
//! 1. **It is deterministic.** Two runs give identical counts, so a difference
//!    of a few per cent is signal rather than noise — which is exactly what
//!    `CLAUDE.md` §10 means by preferring a deterministic assertion to a
//!    stopwatch.
//! 2. **It does not care what machine it is on.** The box this was developed on
//!    is a 9800X3D with **96 MiB of L3**, so a 10k-record zone never leaves last
//!    level cache and a real LLC counter would read ~0 whatever the layout is.
//!    Cachegrind simulates whatever cache it is told to, so the question stays
//!    answerable.
//! 3. **The uncore PMU is not exposed on the Linux side anyway** — the core counters
//!    are (verified), but `amd_l3` is not, so `perf` could not read LL misses
//!    here even if the L3 were small enough for them to mean anything.
//!
//! **Setup is cancelled by subtraction, not by instrumentation control.**
//! Cachegrind counts the whole process, and building a 10k-record zone dwarfs
//! the lookups. Rather than reach for client requests and a C shim, run the same
//! binary at `n` and `2n` and subtract: everything that is not a lookup appears
//! in both and cancels. That is the same shape as
//! `logging_a_query_costs_the_same_however_many_came_before`.
//!
//! ```sh
//! cargo build --release --example zone_lookup_probe
//! valgrind --tool=cachegrind --cache-sim=yes --branch-sim=yes \
//!     ./target/release/examples/zone_lookup_probe miss 100000
//! ```
//!
//! # What it measured, 2026-08-04
//!
//! Per lookup, by subtracting the `n=100_000` run from the `n=200_000` one so
//! that building the zone cancels. On the Linux side, cachegrind's default
//! model (32 KiB I1, 48 KiB D1, 128 MiB LL).
//!
//! | | instructions | cond. branches | D1 read misses | LL read misses |
//! |---|---|---|---|---|
//! | **hit** | 1,052 | 122 | 6.4 | **0** |
//! | **miss** | 2,786 | 338 | **< 0.08** | **0** |
//!
//! **A miss costs 2.6× a hit and touches almost no memory to do it.** That is
//! the answer to #11 on the path #11 cared about: `benches/answer_path.rs` calls
//! the miss "the one to watch: it is what a random-name flood produces", and it
//! is compute, not pointer chasing. `cg_annotate` says where: **SipHash is 19.8%
//! of all instructions in the run and 23.2% of all branch mispredicts.** A miss
//! probes `index`, then `non_terminals`, then walks up the name probing both
//! again per level, then `format!`s a `*.encloser` key and probes once more —
//! ~~five or six hashes~~ **three** of a ~25-octet string, plus an allocation.
//! (The count was a guess from reading the code; callgrind measured it at
//! exactly three. Corrected here rather than silently, because the guess is why
//! the callgrind pass was worth running.)
//!
//! **The hit path is the one with a real pointer chase** — 6.4 D1 read misses
//! walking `index` → `Vec<usize>` → `records[i]` — and every one of them is
//! served by L2, because the LL miss count is *identical to the digit* across
//! every run at both sizes. A 10k-record zone simply fits.
//!
//! # The miss-path D1 figure is a bound, not a measurement
//!
//! `HashMap`'s `RandomState` reseeds per process, so the probe sequence — and
//! therefore which lines are touched — differs run to run. Three identical runs
//! spread **7,776** D1 read misses, against a signal of 3,630 between `n` and
//! `2n`. The signal is under the noise, which is why the table says `< 0.08`
//! rather than a number: `CLAUDE.md` §10's rule about checking a count is stable
//! before trusting it, applied to a count that turned out not to be.
//!
//! # What callgrind added, 2026-08-04
//!
//! Cachegrind says what a lookup *costs*; callgrind says how many times and from
//! where. Run with `--collect-atstart=no --toggle-collect='*probe_loop*'`, so
//! setup is excluded by instrumentation rather than by subtraction — the two
//! methods agree to the instruction (2,786 Ir per miss either way), which is
//! the cross-check that makes both believable.
//!
//! Per miss lookup, before the `has_wildcards` short-circuit:
//!
//! | | Ir | share |
//! |---|---|---|
//! | `name_kind_of_key` (inclusive) | 2,411 | 86.5% |
//! | `format!("*.{encloser}")` | 454 | 16.3% |
//! | `lookup_key` | 294 | 10.6% |
//! | `is_at_or_under` | 227 | 8.2% |
//! | `delegation_for_key` | 181 | 6.5% |
//!
//! **`hash_one::<&str>` is called exactly 3 times per miss**, not the five or
//! six a reading of the code suggests — 60,000 calls for 20,000 lookups, from
//! three distinct sites. Call counts are the thing cachegrind could not give,
//! and the guess they corrected had already been written down.
//!
//! That table is what produced `Zone::has_wildcards`: once the closest encloser
//! is found, a zone with no wildcard has both remaining branches ending in
//! `NotFound`, so the `format!`, the delegation check and one of the three
//! hashes are dead work. Skipping them took the miss path from **2,786 to 1,900
//! instructions, 31.8%**, with the hit path unchanged to the instruction (1,052
//! either way, because a hit returns `Exact` before the walk).
//!
//! It does not weaken the conclusion — a per-lookup cost buried beneath its own
//! measurement floor is not a cost worth restructuring a data layout for — but
//! the honest form of the claim is the bound. Tightening it means giving `Zone`
//! a fixed-seed `BuildHasher`, which is a change to the type under test and was
//! not worth it for an answer that is already decisive.

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
