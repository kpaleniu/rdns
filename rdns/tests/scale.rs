//! What this server costs above a test zone — `TODO.md` #44c.
//!
//! Not a guard and not a benchmark. `bench.rs`'s two floors watch a complexity
//! class and `benches/answer_path.rs` times one query; this measures what an
//! operator sizes a machine by, which nothing here had ever measured: a zone of
//! a million records, signing it, how many zones one process holds, and what
//! reloading all of them costs. Nothing asserts a number, because the numbers
//! are the output. They are in `TODO.md` #44c beside the machine that produced
//! them.
//!
//! ```sh
//! cargo test --release -p rdns --test scale -- --ignored --nocapture
//! ```
//!
//! `#[ignore]`, because the default run is minutes and allocates gigabytes.
//! `--release` is refused rather than warned about: a debug figure here is an
//! order of magnitude out and its only use would be being quoted as this
//! server's load time.
//!
//! Its own test binary because `#[global_allocator]` applies to the whole one
//! (`CLAUDE.md` §10). The allocator is two atomics rather than dhat, because
//! dhat takes a backtrace per allocation and here the bytes and the wall clock
//! are measured in the same run.
//!
//! Sizes come from the environment so a smaller box can still take the
//! measurement: `RDNS_SCALE_RECORDS` (the largest zone), `RDNS_SCALE_ZONES`
//! (how many zones), `RDNS_SCALE_RELOAD` (how many files a reload reads) and
//! `RDNS_SCALE_VERIFY`, which is three orders of magnitude smaller than the
//! rest because what it measures is quadratic — see `verifying_a_signed_zone`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdns::clock::current_unix_timestamp;
use rdns::dnssec::Rrsig;
use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::dnssec_validation_mode::DnssecValidator;
use rdns::ixfr::plan_change;
use rdns::name_keys::NameKeyBuf;
use rdns::zone::{parse_zone_file, parse_zone_file_at, Zone, ZoneRecord};
use rdns::zone_signer::{sign_zone, SigningPolicy};
use rdns::{Class, Name, ParsedRecord, Qtype, RecordData, ResourceRecord, Rtype, Ttl};

#[global_allocator]
static ALLOC: Tracking = Tracking;

/// Bytes handed out and not yet given back, and the high-water mark since it
/// was last reset.
///
/// Relaxed throughout: one test, one thread doing the work, and a byte count
/// that is a measurement rather than a synchronization. Other threads exist —
/// libtest's — which is why every figure below is a *difference* taken around
/// one call.
static IN_USE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Tracking;

impl Tracking {
    fn grew(by: usize) {
        let now = IN_USE.fetch_add(by, Ordering::Relaxed) + by;
        PEAK.fetch_max(now, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            Tracking::grew(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            Tracking::grew(layout.size());
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
            if new_size >= layout.size() {
                Tracking::grew(new_size - layout.size());
            } else {
                IN_USE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

/// What one measured call cost: how long, what it left on the heap, and how far
/// above that the heap went while it ran.
struct Cost {
    elapsed: Duration,
    /// Bytes still allocated afterwards — the standing cost of whatever was
    /// built.
    held: usize,
    /// Bytes the run peaked at above `held`. A vector that grows by doubling
    /// asks for this and gives it back; the machine has to have it anyway.
    transient: usize,
}

/// Run `f`, timing it and measuring what it left behind.
fn measure<T>(f: impl FnOnce() -> T) -> (T, Cost) {
    let before = IN_USE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let start = Instant::now();
    let out = f();
    let elapsed = start.elapsed();
    let after = IN_USE.load(Ordering::Relaxed);
    let peak = PEAK.load(Ordering::Relaxed);
    (
        out,
        Cost {
            elapsed,
            held: after.saturating_sub(before),
            transient: peak.saturating_sub(after),
        },
    )
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Nanoseconds per unit of whatever was counted.
fn per(total: Duration, n: usize) -> f64 {
    total.as_secs_f64() * 1e9 / n as f64
}

/// A size knob, from the environment or its default.
fn knob(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// A directory of our own under the system temp directory, emptied first.
///
/// `std::env::temp_dir()`, as the three permission tests do, rather than beside
/// the source: the development machine's tree is on a DrvFs mount from the
/// Linux side, and writing 45 MB of zone file to it would measure the mount.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rdns-scale-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// An ordinary small zone: apex SOA, two NS, their glue, mail and www. What a
/// hosting fleet holds ten thousand of.
fn small_zone_text(origin: &str, serial: u32) -> String {
    format!(
        "$ORIGIN {origin}\n\
         $TTL 3600\n\
         @    IN SOA ns1.{origin} admin.{origin} ( {serial} 3600 600 604800 300 )\n\
         @    IN NS  ns1.{origin}\n\
         @    IN NS  ns2.{origin}\n\
         ns1  IN A   192.0.2.1\n\
         ns2  IN A   192.0.2.2\n\
         @    IN MX  10 mail.{origin}\n\
         mail IN A   192.0.2.10\n\
         www  IN A   192.0.2.20\n\
         www  IN AAAA 2001:db8::20\n"
    )
}

/// One zone of `hosts` A records, in presentation form.
fn big_zone_text(hosts: usize) -> String {
    // Built outside every `measure`, and with its capacity up front, so none of
    // this is in a number below.
    let mut text = String::with_capacity(hosts * 48 + 256);
    text.push_str(
        "$ORIGIN example.com.\n\
         $TTL 3600\n\
         @    IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
         @    IN NS  ns1.example.com.\n\
         ns1  IN A   192.0.2.1\n",
    );
    for i in 0..hosts {
        let a = Ipv4Addr::new(192, 0, 2, (i % 254) as u8 + 1);
        text.push_str(&format!("host{i} IN A {a}\n"));
    }
    text
}

fn write_zone(dir: &Path, origin: &str, text: &str) -> PathBuf {
    let path = dir.join(format!("{origin}zone"));
    std::fs::write(&path, text).expect("write a zone file");
    path
}

fn keys_for(origin: &str) -> Vec<SigningKey> {
    vec![
        SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            origin,
            rdns::dnssec::DNSKEY_FLAG_ZONE | rdns::dnssec::DNSKEY_FLAG_SEP,
        )
        .expect("a KSK"),
        SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            origin,
            rdns::dnssec::DNSKEY_FLAG_ZONE,
        )
        .expect("a ZSK"),
    ]
}

fn policy() -> SigningPolicy {
    SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400)
}

/// 10k, 100k and 1M, clipped to whatever the largest size asked for is, so a
/// smaller box measures the same shape.
fn sizes_up_to(largest: usize) -> Vec<usize> {
    [10_000, 100_000, 1_000_000]
        .into_iter()
        .filter(|n| *n < largest)
        .chain(std::iter::once(largest))
        .collect()
}

#[test]
#[ignore = "minutes and gigabytes: a measurement to take, not a check to run"]
fn scale() {
    if cfg!(debug_assertions) {
        panic!(
            "this would measure the debug build. Run:\n  \
             cargo test --release -p rdns --test scale -- --ignored --nocapture"
        );
    }

    one_big_zone();
    signing_one_big_zone();
    verifying_a_signed_zone();
    many_small_zones();
    reloading_them_all();
}

/// Load time and memory for a zone up to a million records, at three sizes so
/// the shape is visible rather than one number that could be anything.
///
/// The read is separated from the parse, which `parse_zone_file_at` does in one
/// call: otherwise the whole file — which it holds in a `String` and drops —
/// lands in the parser's transient column and the peak cannot be attributed.
fn one_big_zone() {
    let largest = knob("RDNS_SCALE_RECORDS", 1_000_000);
    let dir = scratch("one-zone");
    println!(
        "\n== one zone, loaded from a file ({} bytes per `ZoneRecord` before \
         its name and RDATA)\n\
         {:>10}  {:>9}  {:>7}  {:>8}  {:>8}  {:>10}  {:>9}  {:>10}",
        std::mem::size_of::<rdns::zone::ZoneRecord>(),
        "records",
        "file",
        "read",
        "parse",
        "ns/rec",
        "held",
        "bytes/rec",
        "transient"
    );

    for hosts in sizes_up_to(largest) {
        let path = write_zone(&dir, "example.com.", &big_zone_text(hosts));

        let (text, read) = measure(|| std::fs::read_to_string(&path).expect("read"));
        let file_bytes = text.len();
        let (zone, cost) = measure(|| parse_zone_file(&text, "example.com.").expect("parse"));
        drop(text);

        let records = zone.records().len();
        println!(
            "{records:>10}  {:>7.1}MB  {:>6.2}s  {:>7.2}s  {:>8.0}  {:>8.1}MB  {:>9.0}  {:>8.1}MB",
            mib(file_bytes),
            read.elapsed.as_secs_f64(),
            cost.elapsed.as_secs_f64(),
            per(cost.elapsed, records),
            mib(cost.held),
            cost.held as f64 / records as f64,
            mib(cost.transient),
        );
        drop(zone);
        std::fs::remove_file(&path).expect("remove the zone file");
    }
    let _ = std::fs::remove_dir_all(&dir);
    building_without_parsing(largest);
}

/// The same zone assembled record by record, to say whose the peak above is.
///
/// The records are built before the measurement and *moved* in, so their names
/// and RDATA are not in these figures: what is left is the record vector, the
/// owner index, and whatever growing them costs. The transient here against the
/// transient above is the whole question — the containers' or the parser's.
fn building_without_parsing(hosts: usize) {
    let apex: Name = "example.com.".parse().expect("the apex parses");
    let records: Vec<ZoneRecord> = (0..hosts)
        .map(|i| ZoneRecord {
            name: format!("host{i}.example.com.")
                .parse()
                .expect("a host name parses"),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(
                192,
                0,
                2,
                (i % 254) as u8 + 1,
            )))
            .expect("the rdata"),
        })
        .collect();

    let (zone, cost) = measure(|| {
        let mut zone = Zone::new(apex);
        for record in records {
            zone.add_record(record);
        }
        zone
    });
    println!(
        "{:>10}  {:>26}  {:>8.0}  {:>8.1}MB  {:>9.0}  {:>8.1}MB",
        zone.records().len(),
        "built, not parsed",
        per(cost.elapsed, zone.records().len()),
        mib(cost.held),
        cost.held as f64 / zone.records().len() as f64,
        mib(cost.transient),
    );
}

/// Signing the same zone at the same sizes.
///
/// One RRSIG per RRset and an NSEC chain over every name, so the number of
/// signatures is the number of names and the crypto is a floor: what the timing
/// says is how far above that floor the rest of the signer sits.
fn signing_one_big_zone() {
    let largest = knob("RDNS_SCALE_RECORDS", 1_000_000);
    let keys = keys_for("example.com.");
    println!(
        "\n== signing that zone (two P-256 keys, NSEC)\n\
         {:>10}  {:>9}  {:>9}  {:>11}  {:>10}  {:>9}  {:>10}",
        "records", "sign", "µs/rec", "records out", "held", "bytes/out", "both"
    );

    for hosts in sizes_up_to(largest) {
        let text = big_zone_text(hosts);
        // Measured, because what a machine has to have is both versions at
        // once: `ZoneSigning::apply` replaces the `Arc` and the unsigned zone
        // is dropped only after the signed one exists.
        let (zone, load) = measure(|| parse_zone_file(&text, "example.com.").expect("parse"));
        drop(text);
        let records = zone.records().len();

        let (signed, cost) = measure(|| sign_zone(&zone, &keys, &policy()).expect("sign"));
        let out = signed.records().len();
        println!(
            "{records:>10}  {:>8.2}s  {:>9.1}  {out:>11}  {:>8.1}MB  {:>9.0}  {:>8.1}MB",
            cost.elapsed.as_secs_f64(),
            cost.elapsed.as_secs_f64() * 1e6 / records as f64,
            mib(cost.held),
            cost.held as f64 / out as f64,
            mib(load.held + cost.held),
        );
    }
}

/// What `rdnsd` does to a zone it has just signed, before serving any of it.
///
/// `zones::verify_zones` runs on every load whenever signing is configured, and
/// it asks `DnssecValidator::validate_response` once per signed RRset — which
/// collects every DNSKEY and every RRSIG *in the whole zone* per call. That is
/// quadratic and is `TODO.md` #50, which this stage found. So the sizes here
/// are a quarter, a half and all of a number three orders of magnitude below
/// the one the sections above use, and what to read is the µs/RRset column
/// against itself rather than any single figure.
fn verifying_a_signed_zone() {
    let largest = knob("RDNS_SCALE_VERIFY", 2_000);
    let keys = keys_for("example.com.");
    let validator = DnssecValidator::new(true);
    println!(
        "\n== verifying it, as every load does (`zones::verify_zones`)\n\
         {:>10}  {:>10}  {:>9}  {:>11}  {:>10}",
        "records", "signed", "rrsets", "verify", "µs/rrset"
    );

    for hosts in [largest / 4, largest / 2, largest] {
        let text = big_zone_text(hosts);
        let zone = parse_zone_file(&text, "example.com.").expect("parse");
        drop(text);
        let signed = sign_zone(&zone, &keys, &policy()).expect("sign");

        // `zones::signed_rrsets`, which is `rdnsd`'s and private: every
        // (owner, type) some RRSIG in the zone claims to cover.
        let mut rrsets: Vec<(Name, Rtype)> = signed
            .records()
            .iter()
            .filter(|r| r.rdata.rtype() == rdns::record_types::RRSIG)
            .filter_map(|r| {
                Rrsig::from_record(&ResourceRecord {
                    name: r.name.clone(),
                    class: r.class,
                    ttl: r.ttl,
                    rdata: r.rdata.clone(),
                })
            })
            .map(|sig| (sig.owner, sig.type_covered))
            .collect();
        rrsets.sort_by(|a, b| {
            a.0.as_ref()
                .folded()
                .cmp(&b.0.as_ref().folded())
                .then(a.1.to_u16().cmp(&b.1.to_u16()))
        });
        rrsets.dedup();

        let (checked, cost) = measure(|| {
            let mut checked = 0usize;
            for (name, rtype) in &rrsets {
                let records = signed.query(name.as_ref(), Qtype::of(*rtype));
                let (ok, _) = validator.validate_response(
                    &signed,
                    &records,
                    &name.as_ref().to_presentation(),
                );
                assert!(ok, "the zone we just signed verifies");
                checked += 1;
            }
            checked
        });
        println!(
            "{:>10}  {:>10}  {:>9}  {:>10.2}s  {:>10.0}",
            zone.records().len(),
            signed.records().len(),
            checked,
            cost.elapsed.as_secs_f64(),
            cost.elapsed.as_secs_f64() * 1e6 / checked as f64,
        );
    }
}

/// How many zones one process holds: the standing cost of the map `rdnsd`
/// answers from, per zone of the ordinary shape.
fn many_small_zones() {
    let count = knob("RDNS_SCALE_ZONES", 10_000);
    let texts: Vec<String> = (0..count)
        .map(|i| small_zone_text(&format!("z{i}.example."), 1))
        .collect();

    let (map, cost) = measure(|| {
        let mut map: HashMap<NameKeyBuf, Arc<Zone>> = HashMap::with_capacity(texts.len());
        for (i, text) in texts.iter().enumerate() {
            let origin = format!("z{i}.example.");
            let zone = parse_zone_file(text, &origin).expect("parse");
            map.insert(NameKeyBuf::new(zone.origin()), Arc::new(zone));
        }
        map
    });

    let records: usize = map.values().map(|z| z.records().len()).sum();
    let per_zone = cost.held as f64 / map.len() as f64;
    println!(
        "\n== {} zones of {} records each, as `rdnsd` holds them\n\
         parse and insert  {:>8.2}s  ({:.0} µs/zone)\n\
         held              {:>7.1}MB  ({per_zone:.0} bytes/zone, {:.0} bytes/record)\n\
         transient         {:>7.1}MB\n\
         a GiB of zone map holds {:.0} zones of this shape",
        map.len(),
        records / map.len(),
        cost.elapsed.as_secs_f64(),
        cost.elapsed.as_secs_f64() * 1e6 / map.len() as f64,
        mib(cost.held),
        cost.held as f64 / records as f64,
        mib(cost.transient),
        (1024.0 * 1024.0 * 1024.0) / per_zone,
    );
    drop(map);
}

/// What a reload costs: what `rdnsd`'s SIGHUP path does, in the order it does
/// it — read and parse every file, sign every zone, then diff each new version
/// against the one being served.
///
/// The diff is measured twice because `ixfr::plan_change` returns before
/// walking when the serial has not moved, and an operator editing one zone in a
/// fleet reloads the whole set: the unchanged number is what the other N-1
/// zones cost.
fn reloading_them_all() {
    let count = knob("RDNS_SCALE_RELOAD", 1_000);
    let dir = scratch("reload");
    let origins: Vec<String> = (0..count).map(|i| format!("z{i}.example.")).collect();
    for origin in &origins {
        write_zone(&dir, origin, &small_zone_text(origin, 1));
    }

    let (served, parse) = measure(|| load_dir(&dir));
    assert_eq!(served.len(), count, "every zone file was read");

    // Signing, as `ZoneSigning::apply` does it. The keys are generated outside
    // the measurement: that is a deploy-time cost, not a reload's.
    let keys: HashMap<&str, Vec<SigningKey>> =
        origins.iter().map(|o| (o.as_str(), keys_for(o))).collect();
    let (signed, sign) = measure(|| {
        let policy = policy();
        served
            .values()
            .map(|zone| {
                let origin = zone.origin().to_presentation();
                sign_zone(zone, &keys[origin.as_str()], &policy).expect("sign")
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(signed.len(), count, "every zone was signed");

    // A reload of the same files: every zone re-parsed, no serial moved.
    let (reloaded, reparse) = measure(|| load_dir(&dir));
    let (unchanged, diff_same) = measure(|| plan_all(&served, &reloaded));
    assert_eq!(
        unchanged, 0,
        "nothing moved, so there is no delta to record"
    );

    // And one where every zone was edited: a bumped serial and one record more.
    for origin in &origins {
        let mut text = small_zone_text(origin, 2);
        text.push_str("extra IN A 192.0.2.30\n");
        write_zone(&dir, origin, &text);
    }
    let (edited, _) = measure(|| load_dir(&dir));
    let (changed, diff_moved) = measure(|| plan_all(&served, &edited));
    assert_eq!(changed, count, "every zone moved");

    let each = |cost: &Cost| cost.elapsed.as_secs_f64() * 1e6 / count as f64;
    println!(
        "\n== reloading {count} zones from a directory\n\
         read and parse      {:>8.2}s  ({:.0} µs/zone, {:>5.1}MB held)\n\
         sign every zone     {:>8.2}s  ({:.0} µs/zone, {:>5.1}MB held)\n\
         re-read and parse   {:>8.2}s  ({:.0} µs/zone, {:>5.1}MB held)\n\
         diff, nothing moved {:>8.2}s  ({:.0} µs/zone)\n\
         diff, all moved     {:>8.2}s  ({:.0} µs/zone)",
        parse.elapsed.as_secs_f64(),
        each(&parse),
        mib(parse.held),
        sign.elapsed.as_secs_f64(),
        each(&sign),
        mib(sign.held),
        reparse.elapsed.as_secs_f64(),
        each(&reparse),
        mib(reparse.held),
        diff_same.elapsed.as_secs_f64(),
        each(&diff_same),
        diff_moved.elapsed.as_secs_f64(),
        each(&diff_moved),
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Every `.zone` file in `dir`, parsed and keyed as `rdnsd`'s `ZoneMap` is.
fn load_dir(dir: &Path) -> HashMap<NameKeyBuf, Arc<Zone>> {
    let mut map = HashMap::new();
    for entry in std::fs::read_dir(dir).expect("read the zone directory") {
        let path = entry.expect("a directory entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("zone") {
            continue;
        }
        let origin = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix("zone"))
            .expect("an origin in the file name")
            .to_owned();
        let zone = parse_zone_file_at(&path, &origin).expect("parse");
        map.insert(NameKeyBuf::new(zone.origin()), Arc::new(zone));
    }
    map
}

/// How many of `new` would record a delta against `old`.
fn plan_all(old: &HashMap<NameKeyBuf, Arc<Zone>>, new: &HashMap<NameKeyBuf, Arc<Zone>>) -> usize {
    new.values()
        .filter(|zone| {
            let previous = old.get(&NameKeyBuf::new(zone.origin())).map(|z| &**z);
            plan_change(previous, zone).is_some()
        })
        .count()
}
