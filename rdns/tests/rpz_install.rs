//! What a *transferred* policy zone costs to install, two ways — `TODO.md` #57d.
//!
//! 57d's A and B differ in one place and everything else about them follows
//! from it. A transfer hands back a [`Zone`] (`rdns::xfr::fetch_zone`). Shape A
//! writes it to a file and lets the existing reload path read it back; shape B
//! hands it to [`PolicyZone::new`] directly. This measures that difference and
//! nothing else: no socket, no timer, no config. The zone is built in memory
//! rather than transferred, because what is being compared is what happens
//! *after* the last envelope arrives.
//!
//! **`installing_a_transferred_policy_zone` is that comparison as it was
//! taken**, and A is no longer what the resolver does: #71f writes the file and
//! installs the zone the process holds, so the reload reads the file to prove
//! it is still that zone rather than to parse it. The live cost is the `#71f`
//! column of `refreshing_a_transferred_policy_zone` below. Kept as it was
//! because it is the measurement 57d was decided on.
//!
//! ```sh
//! cargo test --release -p rdns --test rpz_install -- --ignored --nocapture
//! ```
//!
//! `#[ignore]` and `--release` refused, as `tests/scale.rs` is and for its
//! reasons. Its own test binary for the same reason as well: the tracking
//! allocator is a `#[global_allocator]` and applies to the whole one
//! (`CLAUDE.md` §10).
//!
//! `RDNS_RPZ_RULES` sets the largest feed; the three smaller sizes are fixed so
//! the shape is visible rather than one number that could be anything.
//!
//! The three take turns (`rdns::testutil::one_at_a_time`), because the recipe
//! above selects all of them and libtest runs what a filter selects in
//! parallel: the cold load below read 3 123 ms against three concurrent
//! million-rule runs and 2 198 with the binary to itself.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rdns::rpz::{Feed, PolicyOverride, PolicyStore, PolicyZone};
use rdns::zone::{parse_zone_file_at, Zone};
use rdns::zone_writer::{write_zone_file, write_zone_text, zone_to_string};

#[global_allocator]
static ALLOC: Tracking = Tracking;

static IN_USE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Tracking;

impl Tracking {
    fn grew(by: usize) {
        let now = IN_USE.fetch_add(by, Ordering::Relaxed) + by;
        PEAK.fetch_max(now, Ordering::Relaxed);
    }
}

// Verbatim `tests/scale.rs`'s allocator, which is deliberate duplication: a
// `#[global_allocator]` is per binary, so sharing it would mean a library item
// that every other test binary then links (`CLAUDE.md` §7's exception — this is
// not shared reasoning, it is a per-binary attribute).
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

#[derive(Clone, Copy)]
struct Cost {
    elapsed: Duration,
    held: usize,
    transient: usize,
}

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

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn per_rule(bytes: usize, rules: usize) -> f64 {
    bytes as f64 / rules as f64
}

fn knob(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rdns-rpz-install-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// A QNAME feed: the shape a blocklist actually has, which is what #61 and #62b
/// measured against.
fn feed_text(rules: usize) -> String {
    let mut text = String::from(
        "$ORIGIN rpz.example.\n\
         $TTL 60\n\
         @ IN SOA ns.rpz.example. hostmaster.rpz.example. 1 3600 600 86400 60\n\
         @ IN NS localhost.\n",
    );
    for i in 0..rules {
        text.push_str(&format!("www.malware{i:07}.example IN CNAME .\n"));
    }
    text
}

/// The zone a transfer would have handed back.
fn transferred(dir: &Path, rules: usize) -> Zone {
    let path = dir.join("source.zone");
    std::fs::write(&path, feed_text(rules)).expect("the feed is written");
    let zone = parse_zone_file_at(&path, "rpz.example.").expect("the feed parses");
    let _ = std::fs::remove_file(&path);
    zone
}

#[test]
#[ignore = "a measurement to take, not a check to run"]
fn installing_a_transferred_policy_zone() {
    let _turn = rdns::testutil::one_at_a_time();
    if cfg!(debug_assertions) {
        panic!(
            "this would measure the debug build. Run:\n  \
             cargo test --release -p rdns --test rpz_install -- --ignored --nocapture"
        );
    }

    let largest = knob("RDNS_RPZ_RULES", 1_000_000);
    let sizes: Vec<usize> = [10_000, 100_000]
        .into_iter()
        .filter(|n| *n < largest)
        .chain(std::iter::once(largest))
        .collect();

    // The first measured block in a process picks up one-off initialization,
    // which for a comparison of two paths lands entirely on whichever runs
    // first (`CLAUDE.md` §10). Run both once and throw the numbers away.
    {
        let dir = scratch("warmup");
        let zone = transferred(&dir, 1_000);
        let path = dir.join("a.zone");
        write_zone_file(&zone, &path).expect("written");
        drop(PolicyZone::load(&path, PolicyOverride::Given).expect("loads"));
        drop(PolicyZone::new(zone, PolicyOverride::Given).expect("indexes"));
    }

    println!(
        "\n{:>9} | {:>9} {:>9} {:>9} | {:>9} | {:>8} {:>8}",
        "rules", "A: write", "A: reload", "A: total", "B: index", "A held", "B held"
    );
    println!("{:->9}-+-{:->31}-+-{:->9}-+-{:->17}", "", "", "", "");

    for rules in sizes {
        let dir = scratch(&format!("{rules}"));
        // Measured, because it is what B is handed and what A throws away: the
        // two columns below are otherwise taken from different baselines and
        // the memory comparison is between a zone and no zone.
        let (zone, from_transfer) = measure(|| transferred(&dir, rules));
        let path = dir.join("feed.zone");

        // A: serialize, write, then read the file back and index it. Both
        // halves separately, because the row's open question is whether the
        // serialization it never measured is the expensive one.
        let (_, serialized) = measure(|| zone_to_string(&zone).expect("serializes"));
        let (_, written) = measure(|| write_zone_file(&zone, &path).expect("written"));
        let (a_zone, reloaded) =
            measure(|| PolicyZone::load(&path, PolicyOverride::Given).expect("loads"));

        // B: index the transferred zone as it stands. It consumes the zone, so
        // this is the last thing done with it.
        let (b_zone, indexed) =
            measure(|| PolicyZone::new(zone, PolicyOverride::Given).expect("indexes"));

        // Counts: `PolicyZone::records` is a record count and not the records.
        // Record-for-record equality is
        // `rpz::tests::what_is_installed_is_what_the_file_would_have_parsed_to`,
        // which is in the suite because #71f rests on it — this line read as
        // that for a day and was not it (`CLAUDE.md` §4).
        assert_eq!(
            a_zone.records(),
            b_zone.records(),
            "the two shapes must install a zone of the same size"
        );
        assert_eq!(a_zone.trigger_counts(), b_zone.trigger_counts());

        let a_total = serialized.elapsed + written.elapsed + reloaded.elapsed;
        println!(
            "{rules:>9} | {:>9.1} {:>9.1} {:>9.1} | {:>9.1} | {:>8.1} {:>8.1}",
            ms(serialized.elapsed + written.elapsed),
            ms(reloaded.elapsed),
            ms(a_total),
            ms(indexed.elapsed),
            per_rule(reloaded.held, rules),
            // B keeps the zone it was handed, so its footprint is that zone
            // plus whatever indexing added. A's `held` already contains a zone,
            // because it parsed a second one out of the file.
            per_rule(from_transfer.held + indexed.held, rules),
        );
        println!(
            "{:>9} | serialize {:.1} ms, {:.0} B/rule transient; write {:.1} ms; \
             transferred zone {:.0} B/rule; reload transient {:.0} B/rule; \
             index transient {:.0} B/rule",
            "",
            ms(serialized.elapsed),
            per_rule(serialized.transient + serialized.held, rules),
            ms(written.elapsed),
            per_rule(from_transfer.held, rules),
            per_rule(reloaded.transient, rules),
            per_rule(indexed.transient, rules),
        );

        drop(a_zone);
        drop(b_zone);
        let _ = std::fs::remove_dir_all(&dir);
    }
    println!();
}

/// What one *refresh* of an already-installed feed costs, which is the question
/// `TODO.md` #57e asks and the test above does not.
///
/// The test above measures the install: what happens after the last envelope
/// arrives. A refresh is the whole round — ask the master what it has, get what
/// changed, put it where the answer path reads it — and the three routes are
/// timed against each other at each size, over a loopback socket against a
/// master built from `axfr_messages`/`ixfr_response`. That is the same code
/// `rdnsd` answers a transfer with, so this is the two halves against each
/// other rather than a mock.
///
/// Time only, and no memory column: the master runs in this process, so the
/// global counter above would be reading both sides of the wire at once.
#[test]
#[ignore = "a measurement to take, not a check to run"]
fn refreshing_a_transferred_policy_zone() {
    let _turn = rdns::testutil::one_at_a_time();
    if cfg!(debug_assertions) {
        panic!(
            "this would measure the debug build. Run:\n  \
             cargo test --release -p rdns --test rpz_install -- --ignored --nocapture"
        );
    }

    let largest = knob("RDNS_RPZ_RULES", 1_000_000);
    let changed = knob("RDNS_RPZ_DELTA", 40);
    let sizes: Vec<usize> = [10_000, 100_000]
        .into_iter()
        .filter(|n| *n < largest)
        .chain(std::iter::once(largest))
        .collect();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    print!(
        "\n{:>9} | {:>9} {:>9} | {:>9} {:>9} | {:>9} {:>9}",
        "rules", "SOA probe", "AXFR", "IXFR", "of which apply", "re-read", "#71f"
    );
    println!(" | {:>9} {:>9} {:>9}", "apply", "of which copy", "drop");
    println!(
        "{:->9}-+-{:->19}-+-{:->19}-+-{:->19}-+-{:->29}",
        "", "", "", "", ""
    );

    for rules in sizes {
        let dir = scratch(&format!("refresh-{rules}"));
        let before = transferred(&dir, rules);
        let after = changed_by(&dir, rules, changed);

        // The master holds both versions and the step between them, which is
        // what lets it answer an IXFR at all.
        let mut deltas = rdns::ixfr::DeltaLog::new();
        deltas.note_change(Some(&before), &after);

        let (probe, axfr, ixfr, applied) = runtime.block_on(async {
            let addr = spawn_master(after.clone(), deltas).await;
            let master = rdns::xfr::Master::plain(addr);
            let zone = before.origin().to_owned();

            // Warm the path once and discard it: the first connection pays for
            // whatever this process has not initialized yet (`CLAUDE.md` §10).
            let _ = rdns::xfr::fetch_soa(&master, zone.as_ref(), None).await;

            let start = Instant::now();
            let serial = rdns::xfr::fetch_soa(&master, zone.as_ref(), None)
                .await
                .expect("the master answers a SOA probe");
            let probe = start.elapsed();
            assert!(
                serial.is_newer_than(before.serial().expect("a serial")),
                "the probe has to see the bump, or the refresh it gates never runs"
            );

            let start = Instant::now();
            let whole = rdns::xfr::fetch_zone(&master, zone.as_ref(), None)
                .await
                .expect("the master answers an AXFR");
            let axfr = start.elapsed();

            let start = Instant::now();
            let outcome = rdns::xfr::fetch_changes(&master, &before, None)
                .await
                .expect("the master answers an IXFR");
            let ixfr = start.elapsed();

            let rdns::xfr::IxfrOutcome::Updated { zone: patched, .. } = outcome else {
                panic!("the master holds the step, so this is an increment and not a full zone");
            };
            assert_eq!(
                whole.records().len(),
                patched.records().len(),
                "both routes must arrive at the same zone, or this times two things"
            );

            // The half of an IXFR that is not the wire. An empty difference
            // sequence is the floor: whatever this costs is what applying
            // *nothing* to a zone of this size costs.
            let start = Instant::now();
            let (rebuilt, _) = rdns::ixfr::apply_changes(
                &before,
                &[],
                &[],
                &after.apex_soa_record().expect("an apex SOA"),
            );
            let applied = start.elapsed();
            assert_eq!(rebuilt.records().len(), before.records().len());

            (probe, axfr, ixfr, applied)
        });

        // What applying the *real* difference costs, and what it is made of.
        // #71a took the rebuild out of this, and what is left is nearly all the
        // copy: the next stage is the copy's two allocations per record (#71e),
        // not anything in `Patch`.
        let delta = rdns::ixfr::diff(&before, &after).expect("both versions have an SOA");
        let new_soa = after.apex_soa_record().expect("an apex SOA");
        let mut patch = rdns::ixfr::Patch::new();
        patch.step(&delta.deleted, &delta.added);
        let start = Instant::now();
        let (patched, missing) = patch.apply(&before, &new_soa);
        let edit = start.elapsed();
        assert_eq!(missing, 0, "the fixture's deletions all name records");
        assert_eq!(patched.records().len(), after.records().len());

        let start = Instant::now();
        let copy = before.clone();
        let cloned = start.elapsed();
        let start = Instant::now();
        drop(copy);
        let dropped = start.elapsed();

        // What either route pays afterwards, and the reason #57e is a question
        // about the whole refresh rather than about the format: shape A writes
        // the file, and the two columns are whether it then parses it back.
        let path = dir.join("feed.zone");
        let (_, installed) = measure(|| {
            write_zone_file(&after, &path).expect("written");
            PolicyZone::load(&path, PolicyOverride::Given).expect("loads")
        });

        // #71f: the same file, written the same way, and a reload that reads
        // it to prove it is still the zone this process holds rather than to
        // parse it.
        //
        // Its own file, holding the *previous* version: a store already at the
        // new one keeps what it has and the column would measure neither route
        // (the assertion below is what caught that).
        let path = dir.join("feed-71f.zone");
        write_zone_file(&before, &path).expect("the previous version is on disk");
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("the feed loads");
        let held = after.clone();
        let (_, offered) = measure(|| {
            let text = zone_to_string(&held).expect("serializes");
            let written = write_zone_text(&text, &path).expect("written");
            store.offer(&written, held).expect("the feed is configured");
            let reloaded = store.reload().expect("re-reads");
            assert_eq!(
                (reloaded.reread, reloaded.installed),
                (0, 1),
                "the install must be the offered zone, or this measures a parse"
            );
        });

        print!(
            "{rules:>9} | {:>9.1} {:>9.1} | {:>9.1} {:>9.1} | {:>9.1} {:>9.1}",
            ms(probe),
            ms(axfr),
            ms(ixfr),
            ms(applied),
            ms(installed.elapsed),
            ms(offered.elapsed),
        );
        println!(
            " | {:>9.1} {:>9.1} {:>9.1}",
            ms(edit),
            ms(cloned),
            ms(dropped)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    println!();
}

/// What a *set* of feeds costs when one of them publishes — `TODO.md` #71b.
///
/// The two above measure one feed. This one measures the thing an operator
/// actually runs: several feeds, one publisher, and a reload that used to be
/// all-or-nothing over the set. `RDNS_RPZ_FEEDS` sets how many.
///
/// Three rows, and the middle one is the number the row was filed on: a cold
/// load of the set, a reload with nothing changed, and a reload with exactly
/// one feed rewritten. What the last two cost above the read-and-digest floor
/// is the parse that was not skipped.
#[test]
#[ignore = "a measurement to take, not a check to run"]
fn reloading_a_set_when_one_feed_publishes() {
    let _turn = rdns::testutil::one_at_a_time();
    if cfg!(debug_assertions) {
        panic!(
            "this would measure the debug build. Run:\n  \
             cargo test --release -p rdns --test rpz_install -- --ignored --nocapture"
        );
    }

    let largest = knob("RDNS_RPZ_RULES", 1_000_000);
    let feeds = knob("RDNS_RPZ_FEEDS", 3);
    let sizes: Vec<usize> = [10_000, 100_000]
        .into_iter()
        .filter(|n| *n < largest)
        .chain(std::iter::once(largest))
        .collect();

    {
        // The first measured block pays for whatever this process has not
        // initialized yet (`CLAUDE.md` §10).
        let dir = scratch("reload-warmup");
        let path = dir.join("warm.zone");
        std::fs::write(&path, feed_text(1_000)).expect("written");
        let store = PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("loads");
        drop(store.reload().expect("re-reads"));
    }

    println!(
        "\n{:>9} | {:>11} {:>11} {:>11} | {:>9}",
        "rules", "cold load", "none moved", "one moved", "feeds"
    );
    println!("{:->9}-+-{:->35}-+-{:->9}", "", "", "");

    for rules in sizes {
        let dir = scratch(&format!("reload-set-{rules}"));
        // Each feed gets its own origin, so the set is a set rather than one
        // zone held several times.
        let paths: Vec<PathBuf> = (0..feeds)
            .map(|i| {
                let path = dir.join(format!("feed{i}.zone"));
                let text = feed_text(rules).replace("rpz.example.", &format!("rpz{i}.example."));
                std::fs::write(&path, text).expect("the feed is written");
                path
            })
            .collect();
        let configured = Feed::each(&paths, PolicyOverride::Given);

        let (store, cold) = measure(|| PolicyStore::load(&configured).expect("the set loads"));
        let (unchanged, quiet) = measure(|| store.reload().expect("re-reads"));
        assert_eq!(unchanged.reread, 0, "nothing was rewritten");

        // One feed publishes: same rules, one more, and a bumped serial.
        let text = feed_text(rules).replace("rpz.example.", "rpz0.example.")
            + "www.late.example IN CNAME .\n";
        std::fs::write(&paths[0], text).expect("the publication is written");
        let (published, busy) = measure(|| store.reload().expect("re-reads"));
        assert_eq!(published.reread, 1, "one feed moved out of {feeds}");

        println!(
            "{rules:>9} | {:>11.1} {:>11.1} {:>11.1} | {feeds:>9}",
            ms(cold.elapsed),
            ms(quiet.elapsed),
            ms(busy.elapsed),
        );
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
    println!();
}

/// The same feed with `changed` rules rewritten and the serial bumped — one
/// publication of a blocklist.
fn changed_by(dir: &Path, rules: usize, changed: usize) -> Zone {
    let path = dir.join("changed.zone");
    let mut text = feed_text(rules).replacen(
        "hostmaster.rpz.example. 1 ",
        "hostmaster.rpz.example. 2 ",
        1,
    );
    for i in 0..changed {
        let old = format!("www.malware{i:07}.example IN CNAME .\n");
        let new = format!("www.malware{i:07}.example IN CNAME *.\n");
        text = text.replacen(&old, &new, 1);
    }
    std::fs::write(&path, text).expect("the changed feed is written");
    let zone = parse_zone_file_at(&path, "rpz.example.").expect("the changed feed parses");
    let _ = std::fs::remove_file(&path);
    zone
}

/// A master on loopback answering a SOA probe, an AXFR and an IXFR.
async fn spawn_master(zone: Zone, deltas: rdns::ixfr::DeltaLog) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a master");
    let addr = listener.local_addr().expect("local addr");
    let shared = std::sync::Arc::new((zone, deltas));

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let shared = shared.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let (zone, deltas) = &*shared;
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).await.is_err() {
                    return;
                }
                let mut packet = vec![0u8; u16::from_be_bytes(length) as usize];
                if stream.read_exact(&mut packet).await.is_err() {
                    return;
                }
                let request = rdns::DnsMessage::try_from_bytes(&packet).expect("a request");
                let replies = match request.queries[0].qtype {
                    q if q == rdns::Qtype::of(rdns::record_types::AXFR) => {
                        rdns::transfer::axfr_messages(&request, zone).expect("an AXFR")
                    }
                    q if q == rdns::Qtype::of(rdns::record_types::IXFR) => {
                        rdns::ixfr::ixfr_response(&request, zone, deltas)
                            .expect("an IXFR")
                            .messages(&request, zone)
                            .expect("its messages")
                    }
                    _ => {
                        let mut reply = request.clone();
                        reply.response = true;
                        reply.authoritive = true;
                        reply.answers = vec![zone.apex_soa_record().expect("an apex SOA")];
                        vec![reply]
                    }
                };
                for reply in replies {
                    let mut buf = vec![0u8; 65535];
                    let n = reply.to_bytes(&mut buf).expect("serialize");
                    let mut framed = (n as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&buf[..n]);
                    if stream.write_all(&framed).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    addr
}
