//! The pre-authentication path against mutated wire data: everything a
//! datagram touches before a TSIG MAC is verified, and for an unsigned query
//! everything up to serializing the answer.
//!
//! The UDP path answers inline, so a panic there ends the worker and `serve`
//! ends the process: any reachable panic is a remote kill switch. Hand-rolled
//! so it runs on stable on every push; random bytes never get past the header
//! check, so it mutates valid messages. `fuzz/` runs the same inputs
//! coverage-guided on nightly, seeded by `write_fuzz_seeds`.
//!
//! A soak is the same test with more cases:
//!
//! ```sh
//! RDNS_FUZZ_ITERATIONS=2000000 cargo test -p rdns --test no_input_panics -- --nocapture
//! RDNS_FUZZ_SEED=12345 cargo test -p rdns --test no_input_panics
//! RDNS_FUZZ_SEEDS="$PWD/fuzz/seeds" cargo test -p rdns --test no_input_panics -- --ignored
//! ```

use std::panic::{catch_unwind, AssertUnwindSafe};

#[path = "support/wire_input.rs"]
mod wire_input;

use rdns::tsig;
use rdns::zone::Zone;
use wire_input::{corpus, exercise, transfers, upstream_replies, Fixture};

/// Cases per corpus entry. Small enough to stay under a second in CI.
const ITERATIONS: usize = 250;

/// A seeded xorshift64*, so a failing run is reproducible from its seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // Not cryptographic and does not need to be: it decides which byte to
        // corrupt, not what a key is.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// One mutation of `seed_bytes`, chosen by `rng`.
///
/// Truncation finds parsers that read past what arrived; the bias towards `0xc0`
/// and `0xff` aims at the two structurally meaningful values on the wire, a
/// compression pointer and a maximal length field.
fn mutate(rng: &mut Rng, seed_bytes: &[u8]) -> Vec<u8> {
    let mut data = seed_bytes.to_vec();
    if data.is_empty() {
        return data;
    }
    match rng.below(6) {
        // Flip one to four bits.
        0 => {
            for _ in 0..=rng.below(4) {
                let at = rng.below(data.len());
                data[at] ^= 1 << rng.below(8);
            }
        }
        // Cut it short, anywhere.
        1 => {
            let at = rng.below(data.len());
            data.truncate(at);
        }
        // Write a structurally interesting byte.
        2 => {
            let at = rng.below(data.len());
            data[at] = match rng.below(4) {
                0 => 0xc0,
                1 => 0xff,
                2 => 0x00,
                _ => (rng.next() & 0xff) as u8,
            };
        }
        // Write a whole 16-bit field: a length, a count, a pointer.
        3 => {
            if data.len() >= 2 {
                let at = rng.below(data.len() - 1);
                let value: u16 = match rng.below(4) {
                    0 => 0xffff,
                    1 => 0xc000,
                    2 => 0x0000,
                    _ => (rng.next() & 0xffff) as u16,
                };
                data[at..at + 2].copy_from_slice(&value.to_be_bytes());
            }
        }
        // Splice a run of random bytes over the middle.
        4 => {
            let at = rng.below(data.len());
            let run = 1 + rng.below(8);
            for i in 0..run {
                if at + i < data.len() {
                    data[at + i] = (rng.next() & 0xff) as u8;
                }
            }
        }
        // Arbitrary, occasionally longer than any datagram this server accepts.
        _ => {
            let len = rng.below(600);
            data = (0..len).map(|_| (rng.next() & 0xff) as u8).collect();
        }
    }
    data
}

#[test]
fn no_input_panics_before_authentication() {
    let seed: u64 = std::env::var("RDNS_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5eed_1234_abcd_0001);
    let iterations: usize = std::env::var("RDNS_FUZZ_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(ITERATIONS);

    let fx = Fixture::new();
    let (zone, signed, keyring, now) = (&fx.zone, &fx.signed, &fx.keyring, fx.now);
    let corpus = corpus(zone, signed);
    let mut rng = Rng(seed);
    let mut cases = 0u64;

    println!(
        "seed {seed:#x}, {iterations} iterations over {} corpus entries",
        corpus.len()
    );

    for (what, seed_bytes) in &corpus {
        // Unmutated first: if the corpus itself panics, the rest is noise.
        check(seed_bytes, what, seed, cases, zone, signed, keyring, now);
        cases += 1;

        for _ in 0..iterations {
            let data = mutate(&mut rng, seed_bytes);
            check(&data, what, seed, cases, zone, signed, keyring, now);
            cases += 1;
        }
    }

    println!("{cases} cases, no panics");
}

/// Run one case, and turn a panic into a message that says how to reproduce it:
/// the seed, and the bytes to paste into the regression test.
#[allow(clippy::too_many_arguments)]
fn check(
    data: &[u8],
    what: &str,
    seed: u64,
    case: u64,
    zone: &Zone,
    signed: &Zone,
    keyring: &tsig::TsigKeyring,
    now: u64,
) {
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        exercise(data, zone, signed, keyring, now)
    }));
    if outcome.is_err() {
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        panic!(
            "panicked on case {case} (seed {seed:#x}), a mutation of {what}:\n\
             {hex}\n\
             reproduce with RDNS_FUZZ_SEED={seed}"
        );
    }
}

/// Writes the `fuzz/` targets' seed corpora under `$RDNS_FUZZ_SEEDS`: one
/// directory per target, each file a seed. The resolver and transfer targets
/// read a flags byte first; each seed is written with every flag combination.
/// The path wants to be absolute: cargo runs this in `rdns/`.
#[test]
#[ignore = "writes files; run with RDNS_FUZZ_SEEDS set"]
fn write_fuzz_seeds() {
    let dir = std::path::PathBuf::from(
        std::env::var("RDNS_FUZZ_SEEDS").expect("RDNS_FUZZ_SEEDS names the directory"),
    );
    let fx = Fixture::new();
    let write = |target: &str, seeds: Vec<(&str, Vec<u8>)>, flags: &[Option<u8>]| {
        let at = dir.join(target);
        std::fs::create_dir_all(&at).expect("create the seed directory");
        for (what, bytes) in seeds {
            let stem: String = what
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect();
            for flag in flags {
                let seed: Vec<u8> = flag.iter().copied().chain(bytes.iter().copied()).collect();
                let name = flag.map_or(stem.clone(), |f| format!("{stem}-{f}"));
                std::fs::write(at.join(name), seed).expect("write a seed");
            }
        }
    };
    write("server", corpus(&fx.zone, &fx.signed), &[None]);
    write("resolver", upstream_replies(&fx), &[Some(0), Some(1)]);
    write(
        "transfer",
        transfers(&fx),
        &[Some(0), Some(1), Some(2), Some(3)],
    );
}
