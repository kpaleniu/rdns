//! What one zone lookup costs in instructions, cache misses and branch
//! mispredicts.
//!
//! Setup is cancelled by subtraction: run at `n` and `2n` and subtract, so
//! building the zone appears in both.
//!
//! ```sh
//! cargo build --release --example zone_lookup_probe
//! valgrind --tool=cachegrind --cache-sim=yes --branch-sim=yes \
//!     ./target/release/examples/zone_lookup_probe miss 100000
//! valgrind --tool=callgrind --collect-atstart=no \
//!     --toggle-collect='*probe_loop*' ./target/release/examples/zone_lookup_probe miss 100000
//! ```
//!
//! A miss is compute, not pointer chasing: 2,786 instructions against a hit's
//! 1,052, with almost no memory traffic. That is what produced
//! `Zone::has_wildcards` — with no wildcard in the zone the `format!`, the
//! delegation check and one hash after the closest encloser are dead work, and
//! skipping them took the miss path to 1,900.

use std::hint::black_box;
use std::net::Ipv4Addr;

use rdns::utils::record_types;
use rdns::zone::{Zone, ZoneRecord};
use rdns::{Class, Name, ParsedRecord, Qtype, RecordData, Ttl};

/// A name from a literal, for a probe only: `Name` is fallible to build and a
/// probe that writes a bad one should fail loudly at that line.
fn nm(text: &str) -> Name {
    text.parse().expect("a probe name parses")
}

/// The same zone `benches/answer_path.rs` builds, so the two measurements are
/// about one thing. Ten thousand names, one A record each.
fn ten_thousand_records() -> Zone {
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

    // Built outside the loop: a `format!` per iteration measures the
    // allocator, which is a different question.
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
        found += black_box(zone.query(black_box(nm(name).as_ref()), qtype)).len();
    }
    found
}
