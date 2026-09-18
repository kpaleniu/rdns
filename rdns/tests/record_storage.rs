//! What a zone's records cost to hold, to copy and to load — `TODO.md` #71e
//! and #71f.
//!
//! Two questions the rest of the suite does not ask. What a `Zone::clone` is
//! made of, which is what decides whether 71a can copy rather than rebuild; and
//! what a feed's *load* is made of, which is what #71f took away.
//!
//! ```sh
//! cargo test --release -p rdns --test record_storage -- --ignored --nocapture
//! ```
//!
//! `#[ignore]` and `--release` refused, as `tests/rpz_install.rs` is and for
//! its reasons; its allocator and its turnstile too, since the recipe above
//! selects every test in the file.
//!
//! `RDNS_RECORDS` sets the size.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rdns::zone::{Zone, ZoneRecord};
use rdns::{Class, Name, ParsedRecord, RecordData, Ttl};

#[global_allocator]
static ALLOC: Counting = Counting;

static IN_USE: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            IN_USE.fetch_add(layout.size(), Ordering::Relaxed);
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        IN_USE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            IN_USE.fetch_add(new_size, Ordering::Relaxed);
            IN_USE.fetch_sub(layout.size(), Ordering::Relaxed);
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        p
    }
}

fn in_use() -> usize {
    IN_USE.load(Ordering::Relaxed)
}

fn allocs() -> usize {
    ALLOCS.load(Ordering::Relaxed)
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn knob(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A debug build would measure the allocator's checks and nothing here.
fn refuse_debug() {
    if cfg!(debug_assertions) {
        panic!(
            "this would measure the debug build. Run:
               cargo test --release -p rdns --test record_storage -- --ignored --nocapture"
        );
    }
}

fn nm(text: &str) -> Name {
    text.parse().expect("a probe name parses")
}

/// A feed-shaped zone: one A record per name, every name a child of the apex.
/// The shape #71's numbers are all taken on.
fn feed(rules: usize) -> Zone {
    let mut zone = Zone::new(nm("example.com."));
    for i in 0..rules {
        zone.add_record(ZoneRecord {
            name: nm(&format!("rule{i}.example.com.")),
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

#[test]
#[ignore = "minutes and a gigabyte"]
fn what_a_copy_is_made_of() {
    let _turn = rdns::testutil::one_at_a_time();
    refuse_debug();
    let rules = knob("RDNS_RECORDS", 1_000_000);

    let before = (in_use(), allocs());
    let zone = feed(rules);
    println!(
        "zone of {rules}: {:.1} MiB, {} allocations live",
        mib(in_use() - before.0),
        allocs() - before.1
    );

    // The first copy in a process pays for whatever the allocator has not
    // warmed; the loop below is what is read.
    let warm = zone.clone();
    drop(warm);

    for _ in 0..3 {
        let a0 = allocs();
        let started = Instant::now();
        let copy = zone.clone();
        let cloned = started.elapsed();
        let allocated = allocs() - a0;
        let held = in_use();
        let started = Instant::now();
        drop(copy);
        let dropped = started.elapsed();
        println!(
            "Zone::clone {:.1} ms ({allocated} allocations, {:.1} MiB), drop {:.1} ms",
            cloned.as_secs_f64() * 1000.0,
            mib(held - before.0),
            dropped.as_secs_f64() * 1000.0,
        );
    }

    // The records alone, without the index: the vector is `Copy`-shaped apart
    // from the two `Box`es per record, so this is 71e's whole question.
    let records: Vec<ZoneRecord> = zone.records().to_vec();
    for _ in 0..3 {
        let a0 = allocs();
        let started = Instant::now();
        let copy = records.clone();
        let cloned = started.elapsed();
        let allocated = allocs() - a0;
        let started = Instant::now();
        drop(copy);
        let dropped = started.elapsed();
        println!(
            "Vec<ZoneRecord>::clone {:.1} ms ({allocated} allocations), drop {:.1} ms",
            cloned.as_secs_f64() * 1000.0,
            dropped.as_secs_f64() * 1000.0,
        );
    }

    // What the same bytes cost with nothing per record on the heap: two
    // vectors and a memcpy, which is the ceiling any arena shape is measured
    // against.
    let mut arena: Vec<u8> = Vec::new();
    let mut ranges: Vec<(u32, u32, u32, u32)> = Vec::with_capacity(records.len());
    for r in &records {
        let name_at = arena.len() as u32;
        arena.extend_from_slice(r.name.as_ref().as_wire());
        let rdata_at = arena.len() as u32;
        arena.extend_from_slice(r.rdata.bytes());
        ranges.push((
            name_at,
            rdata_at - name_at,
            rdata_at,
            (arena.len() - rdata_at as usize) as u32,
        ));
    }
    println!(
        "arena: {:.1} MiB for {} records",
        mib(arena.len() + ranges.len() * std::mem::size_of::<(u32, u32, u32, u32)>()),
        ranges.len()
    );
    for _ in 0..3 {
        let started = Instant::now();
        let copy = (arena.clone(), ranges.clone());
        let cloned = started.elapsed();
        let started = Instant::now();
        drop(copy);
        let dropped = started.elapsed();
        println!(
            "arena clone {:.1} ms, drop {:.1} ms",
            cloned.as_secs_f64() * 1000.0,
            dropped.as_secs_f64() * 1000.0,
        );
    }

    println!(
        "size_of::<ZoneRecord>() = {}",
        std::mem::size_of::<ZoneRecord>()
    );
}

/// What one feed's *load* is made of, so the shapes above are read against the
/// path that pays for them rather than against each other.
#[test]
#[ignore = "minutes and a gigabyte"]
fn what_a_feed_load_is_made_of() {
    let _turn = rdns::testutil::one_at_a_time();
    refuse_debug();
    let rules = knob("RDNS_RECORDS", 1_000_000);

    let dir = rdns::testutil::ScratchDir::new("record-storage");
    let mut text = String::from(
        "$ORIGIN rpz.example.\n\
         $TTL 60\n\
         @ IN SOA ns.rpz.example. hostmaster.rpz.example. 1 3600 600 86400 60\n\
         @ IN NS localhost.\n",
    );
    for i in 0..rules {
        text.push_str(&format!("www.malware{i:07}.example IN CNAME .\n"));
    }
    let path = dir.join("feed.zone");
    std::fs::write(&path, &text).expect("the feed is written");

    // Warm whatever the process has not initialized (`CLAUDE.md` §10).
    drop(rdns::zone::parse_zone_file_at(&path, "rpz.example.").expect("parses"));

    let a0 = allocs();
    let held0 = in_use();
    let started = Instant::now();
    let zone = rdns::zone::parse_zone_file_at(&path, "rpz.example.").expect("parses");
    let parsed = started.elapsed();
    println!(
        "parse {rules} rules: {:.1} ms, {} allocations, {:.1} MiB held",
        parsed.as_secs_f64() * 1000.0,
        allocs() - a0,
        mib(in_use() - held0),
    );

    let started = Instant::now();
    let bytes = std::fs::read(&path).expect("read back");
    let read = started.elapsed();
    println!(
        "read {:.1} MiB: {:.1} ms",
        mib(bytes.len()),
        read.as_secs_f64() * 1000.0
    );

    let a0 = allocs();
    let started = Instant::now();
    let text = rdns::zone_writer::zone_to_string(&zone).expect("serializes");
    let written = started.elapsed();
    println!(
        "zone_to_string: {:.1} ms, {} allocations, {} MiB",
        written.as_secs_f64() * 1000.0,
        allocs() - a0,
        text.len() / (1024 * 1024),
    );
}
