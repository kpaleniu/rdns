//! What the "does this name need folding?" scan costs, searched against folded.
//!
//! `TODO.md` #25g. `bytes().any(..)` exits on the first hit, and LLVM will not
//! vectorize a loop whose exit depends on the data — so the *test* that avoids
//! `make_ascii_lowercase` ran one byte per iteration where the fold it avoids
//! runs thirty-two. An OR-reduction has no early exit and vectorizes.
//!
//! ```sh
//! cargo run --release -p rdns --example fold_scan_probe
//! ```
//!
//! On the development machine (Windows, 2026-09-04), for a name of all
//! lowercase letters — the case that matters, since a name that needs no fold
//! is the one that reads every byte:
//!
//! ```text
//!     search   16 octets:   4.05 ns        fold   16 octets:   1.56 ns
//!     search   64 octets:  13.56 ns        fold   64 octets:   2.00 ns
//!     search  200 octets:  58.51 ns        fold  200 octets:   4.91 ns
//! ```
//!
//! The length is the client's to choose, which is the half worth caring about:
//! the search is linear in it and the fold is nearly flat.

use std::hint::black_box;
use std::time::Instant;

fn searching(name: &str) -> bool {
    name.bytes().any(|b| b.is_ascii_uppercase())
}

fn folding(name: &str) -> bool {
    name.bytes()
        .fold(0u8, |seen, b| seen | u8::from(b.wrapping_sub(b'A') < 26))
        != 0
}

fn time(label: &str, name: &str, f: fn(&str) -> bool) {
    let rounds = 2_000_000u32;
    // warm up
    for _ in 0..100_000 {
        black_box(f(black_box(name)));
    }
    let start = Instant::now();
    for _ in 0..rounds {
        black_box(f(black_box(name)));
    }
    let ns = start.elapsed().as_nanos() as f64 / rounds as f64;
    println!("{label:>10} {:>4} octets: {ns:6.2} ns", name.len());
}

fn main() {
    for len in [16usize, 64, 200] {
        let name = "a".repeat(len);
        time("search", &name, searching);
        time("fold", &name, folding);
    }
}
