//! Allocation counts for the paths that matter, as exact assertions.
//!
//! Its own test binary: `#[global_allocator]` applies to the whole binary.
//!
//! One `#[test]` only — add a function and call it from [`allocation_counts`].
//! The profiler is global and libtest's per-test bookkeeping runs on threads no
//! mutex here can hold, so as separate tests one measurement read 15 where it
//! reads 7. Assertions are ranges only where the thing measured has a degree of
//! freedom; update one with the reason, as a benchmark floor is updated.
//!
//! Counts come from [`Counting`], which tallies per thread, because a mutex
//! cannot make a global counter exact: see [`allocations`]. dhat still supplies
//! the peak-bytes figures, which are about the whole heap by definition.

use rdns::Class;
use rdns::Rtype;
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use rdns::dnssec::{dnskeys_in, rrsigs_in, verify_rrset, Rrset, RrsetProof};
use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::utils::{current_unix_timestamp, record_types};
use rdns::zone::{parse_zone_file, NameKind};
use rdns::zone_signer::{sign_zone, DenialChain, SigningPolicy};
use rdns::{
    DnsMessage, Edns, EdnsOption, OpCode, Qtype, QueryClass, QuerySection, ResourceRecord,
    ResponseCode,
};

#[global_allocator]
static ALLOC: Counting = Counting;

/// dhat, with a per-thread tally of the allocator calls in front of it.
///
/// Everything is passed through to [`dhat::Alloc`], so the peak-bytes
/// measurements are unchanged. What is added is the count: dhat's own is a
/// global, and this is the file that cannot use one (see [`allocations`]).
struct Counting;

thread_local! {
    /// Allocator calls made by this thread: `alloc`, `alloc_zeroed` and
    /// `realloc`, which is what dhat's `total_blocks` counts, so no expected
    /// number in this file moves.
    static BLOCKS: Cell<u64> = const { Cell::new(0) };
    /// True while this thread is inside an allocator call.
    static INSIDE: Cell<bool> = const { Cell::new(false) };
}

/// This thread's allocator calls so far.
fn blocks() -> u64 {
    BLOCKS.with(Cell::get)
}

/// Enter one allocator call, counting it if `count` and this is the outermost
/// one on this thread. Nested calls are dhat's own bookkeeping, not the
/// caller's cost — which is why every entry point takes this guard, including
/// the one that counts nothing.
///
/// `try_with`: a thread allocating while its own TLS is being destroyed must
/// not resurrect the key. Both cells are `const`-initialized and have no
/// destructor, so the access itself never allocates and cannot recurse.
fn enter(count: bool) -> impl Drop {
    struct Guard(bool);
    impl Drop for Guard {
        fn drop(&mut self) {
            if self.0 {
                let _ = INSIDE.try_with(|c| c.set(false));
            }
        }
    }
    let outermost = INSIDE.try_with(|c| !c.replace(true)).unwrap_or(false);
    if outermost && count {
        let _ = BLOCKS.try_with(|b| b.set(b.get() + 1));
    }
    Guard(outermost)
}

unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let _entered = enter(true);
        unsafe { dhat::Alloc.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        let _entered = enter(true);
        unsafe { dhat::Alloc.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        let _entered = enter(true);
        unsafe { dhat::Alloc.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // `total_blocks` is allocations, so nothing is counted here — the guard
        // is for what dhat may allocate while recording the free.
        let _entered = enter(false);
        unsafe { dhat::Alloc.dealloc(ptr, layout) }
    }
}

/// Every measurement in this file, in one test; see the module header for why.
#[test]
fn allocation_counts() {
    let _serial = exclusive();

    one_query_end_to_end();
    writing_a_response_costs_nothing_per_record();
    the_lookups_behind_one_answer_allocate_only_the_answer();
    a_case_randomized_qname_costs_a_fold_per_lookup();
    reading_one_integer_out_of_an_soa();
    reading_a_requests_edns_parameters_allocates_nothing();
    a_response_full_of_shared_suffixes();
    one_zone_load_and_sign();
    one_axfr_out();
    scanning_a_query_for_a_tsig();
    comparing_two_names_allocates_nothing();
    ordering_two_names_canonically();
    building_the_metrics_registry();
    proving_a_signed_nxdomain();
    proving_a_signed_nxdomain_under_nsec3();
    verifying_an_rrset_against_two_candidate_signatures();
    a_busy_neighbour_stays_out_of_the_count();
}

/// Two measured bodies must not overlap: the profiler is global, so an
/// overlapping body's allocations land in whichever measurement is running —
/// guarding only the measurement call gave 4 where the truth was 12.
///
/// Poisoning is ignored: a panic in one measurement must not become a second,
/// confusing failure.
static PROFILER: Mutex<()> = Mutex::new(());

/// Take exclusive use of the profiler, and warm it up.
///
/// The first profiled block in a process picks up a one-off from dhat's own lazy
/// state, so without the warm-up the first measurement reads one high.
fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    let guard = PROFILER.lock().unwrap_or_else(|e| e.into_inner());
    static WARMED: std::sync::Once = std::sync::Once::new();
    WARMED.call_once(|| {
        let profiler = dhat::Profiler::builder().testing().build();
        let _ = dhat::HeapStats::get();
        drop(profiler);
    });
    guard
}

/// Report how many allocations `body` made on this thread.
///
/// Counted here rather than read from dhat because dhat's counters are global:
/// any other thread allocating inside the window lands in the total, and the
/// windows are microseconds, so the failure is rare and remote. A CI run read
/// 10 for a parse that reads 6 on four machines, and passed on re-run.
/// [`exclusive`] cannot fix that — the threads that allocate are libtest's, not
/// this file's. Measurements are still taken under it, because [`peak_bytes`]
/// needs the profiler to itself.
fn allocations<T>(body: impl FnOnce() -> T) -> (T, u64) {
    let before = blocks();
    let out = body();
    (out, blocks() - before)
}

/// Run `body` under a profiler and report the most memory it held at once.
///
/// A streaming transfer calls the allocator about as often as a materializing
/// one; what differs is how much is alive at the same time.
///
/// Call only while holding [`exclusive`].
fn peak_bytes<T>(body: impl FnOnce() -> T) -> (T, usize) {
    let profiler = dhat::Profiler::builder().testing().build();
    let out = body();
    // Read while `out` is alive: for the materializing case, what it holds *is*
    // the measurement.
    let peak = dhat::HeapStats::get().max_bytes;
    drop(profiler);
    (out, peak)
}

/// Assert a count is in `range`, printing it either way so a failure says what
/// to change the range to.
#[track_caller]
fn within(what: &str, count: u64, range: std::ops::RangeInclusive<u64>) {
    println!("{what}: {count} allocations");
    assert!(
        range.contains(&count),
        "{what} made {count} allocations, expected {range:?} — if this is a \
         deliberate change, move the range and say why"
    );
}

const ZONE: &str = "$ORIGIN example.com.
$TTL 3600
@    IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@    IN NS  ns1.example.com.
ns1  IN A   192.0.2.1
www  IN A   192.0.2.10
www  IN AAAA 2001:db8::10
mail IN MX  10 mx.example.com.
mx   IN A   192.0.2.20
";

fn query_bytes(qname: &str, qtype: Qtype) -> Vec<u8> {
    query_message(qname, qtype)
        .to_bytes_within(512)
        .expect("serialize the query")
}

/// The same query as a real resolver sends it: EDNS0, DO set, a DNS cookie
/// (RFC 7873). The cookie is the point — an OPT record with no options parses
/// into an empty `Vec`, which does not allocate, hiding what reading it costs.
fn query_bytes_with_edns(qname: &str, qtype: Qtype) -> Vec<u8> {
    let mut msg = query_message(qname, qtype);
    msg.set_edns(
        Edns::with_options(
            1232,
            0,
            true,
            &[EdnsOption {
                code: rdns::EDNS_OPTION_COOKIE,
                data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }],
        )
        .expect("encode the options"),
    );
    msg.to_bytes_within(512).expect("serialize the query")
}

fn query_message(qname: &str, qtype: Qtype) -> DnsMessage {
    DnsMessage {
        id: 0x1234,
        response: false,
        opcode: OpCode::Query,
        authoritive: false,
        truncation: false,
        recursion: false,
        recursion_ok: false,
        ad: false,
        cd: false,
        rcode: ResponseCode::Ok,
        queries: vec![QuerySection {
            qname: qname.to_string(),
            qtype,
            qclass: QueryClass::IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        edns: None,
    }
}

/// One UDP query end to end, split into parse, look up and serialize so the
/// answer is a breakdown rather than one number.
fn one_query_end_to_end() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let wire = query_bytes("www.example.com.", Qtype::of(record_types::A));

    let (parsed, parse_count) =
        allocations(|| DnsMessage::try_from_bytes(&wire).expect("parse the query"));
    // Three: the label vector, the `String` it becomes, the question vector. A
    // QNAME cannot hold a compression pointer, so `DNameUnpacker` does not copy
    // its labels.
    within("parse a one-question query", parse_count, 3..=3);

    let (answers, lookup_count) = allocations(|| {
        zone.query("www.example.com.", Qtype::of(record_types::A))
            .into_iter()
            .map(|r| ResourceRecord {
                name: r.name.clone(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.clone(),
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(answers.len(), 1);
    // Four, all of them the `ResourceRecord` this closure builds: two `Vec`s,
    // the cloned owner name, the cloned rdata. `Zone::query` contributes only
    // the first. Exact, because nothing here is input-dependent or hash-ordered:
    // a fifth would be the lookup key becoming an owned `String` again.
    within("look up one A record in the zone", lookup_count, 4..=4);

    let mut response = parsed.clone();
    response.response = true;
    response.authoritive = true;
    response.answers = answers;

    let (bytes, serialize_count) = allocations(|| {
        response
            .to_bytes_within(4096)
            .expect("serialize the response")
    });
    // Three: the output buffer, and the compressor's two — the arena of names
    // seen and the table of suffixes into it.
    within("serialize a one-record response", serialize_count, 3..=3);
    assert!(bytes.len() < 100);

    // Why `to_bytes_within_buf` exists: a send path keeping one buffer pays
    // nothing per response after the first.
    let mut scratch = Vec::new();
    response
        .to_bytes_within_buf(4096, &mut scratch)
        .expect("warm the buffer");
    let ((), reused_count) = allocations(|| {
        response
            .to_bytes_within_buf(4096, &mut scratch)
            .expect("serialize into the warm buffer")
    });
    // The compressor's two and nothing else, when it is built per message.
    within("serialize into a reused buffer", reused_count, 2..=2);
    assert!(
        reused_count < serialize_count,
        "reusing the buffer must cost less than allocating one"
    );

    // And nothing at all when the compressor is carried too, which is what a
    // send loop does (`TODO.md` #27b). Its state is per message, so it is
    // cleared by `to_bytes_with` rather than by the caller — see the tests in
    // `lib.rs` for what a stale one writes.
    let mut compressor = rdns::compression::NameCompressor::new();
    response
        .to_bytes_within_buf_with(4096, &mut scratch, &mut compressor)
        .expect("warm the compressor");
    let ((), carried_count) = allocations(|| {
        response
            .to_bytes_within_buf_with(4096, &mut scratch, &mut compressor)
            .expect("serialize with both carried")
    });
    within(
        "serialize with the buffer and the compressor carried",
        carried_count,
        0..=0,
    );
}

/// Writing an answer straight to the wire costs nothing: not per record, and
/// not for the echoed question either (`TODO.md` #27b).
///
/// The build-then-serialize path this replaced paid an owner `String`, a cloned
/// `RecordData` and a `Vec` push per record, plus a `queries.clone()` for the
/// echo — five for the one-record answer below, which is what `rdnsd`'s dhat
/// numbers moved by.
fn writing_a_response_costs_nothing_per_record() {
    use rdns::compression::NameCompressor;
    use rdns::response::{ResponseWriter, Section};

    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let wire = query_bytes("www.example.com.", Qtype::of(record_types::A));
    let request = DnsMessage::try_from_bytes(&wire).expect("parse the query");
    let records = zone.query("www.example.com.", Qtype::of(record_types::A));
    assert_eq!(records.len(), 1);

    let mut out = Vec::new();
    let mut compressor = NameCompressor::new();
    let write = |out: &mut Vec<u8>, compressor: &mut NameCompressor| {
        let mut w = ResponseWriter::start(out, compressor, 4096, &request).expect("start");
        w.set_authoritative(true);
        for r in &records {
            w.push(
                Section::Answer,
                "www.example.com.",
                r.class,
                r.ttl,
                &r.rdata,
            )
            .expect("push");
        }
        w.set_edns(Edns::with_payload_size(1232));
        w.finish().expect("finish");
    };
    write(&mut out, &mut compressor);
    let ((), count) = allocations(|| write(&mut out, &mut compressor));
    within("write a one-record response", count, 0..=0);
    assert!(!out.is_empty());
}

/// The three zone lookups `rdnsd` makes per query (RFC 1034 §4.3.2) cost one
/// allocation between them, and it is the answer: the `Vec` `Zone::query`
/// returns.
///
/// A guard against `zone::absolutize` going back to an owned `String`, which
/// made a copy of the lookup key per lookup — four per query, ~14% of everything
/// an answer allocated. Against that code this reads 5.
fn the_lookups_behind_one_answer_allocate_only_the_answer() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");

    // Warm first: the first run of any path pays for state unrelated to the
    // count, and a target this small cannot absorb it.
    let warm = |zone: &rdns::zone::Zone| {
        let cut = zone.delegation_for("www.example.com.");
        let kind = zone.name_kind("www.example.com.");
        let records = zone
            .query("www.example.com.", Qtype::of(record_types::A))
            .len();
        (cut, kind, records)
    };
    let _ = warm(&zone);

    let ((cut, kind, records), count) = allocations(|| warm(&zone));
    assert_eq!(cut, None, "www is not below a delegation in this zone");
    assert_eq!(kind, NameKind::Exact, "www.example.com. is in the zone");
    assert_eq!(records, 1, "and holds exactly one A record");
    within("the three lookups behind one answer", count, 1..=1);
}

/// The same three lookups against the name a DNS-0x20 resolver actually sends.
///
/// Case randomization is a resolver's spoofing defence (Google Public DNS and
/// Unbound's `use-caps-for-id` both do it), so mixed case is ordinary traffic
/// and not an attack. Every `Zone` entry point folds the name itself
/// (`Zone::lookup_key`), and `ascii_lowered_cow` can only borrow when there is
/// nothing to fold — so the count above is the count for a name that happened
/// to arrive lower-case, and this is the count for the rest.
///
/// Measured on `rdnsd` under dhat, a whole query goes 13 to 18 with the case
/// randomized and 17 to 22 with EDNS0 as well: four folds in `Zone` — the walks
/// here plus `add_answer`'s own — and a fifth in `Zones::for_query`.
fn a_case_randomized_qname_costs_a_fold_per_lookup() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let walks = |zone: &rdns::zone::Zone, name: &str| {
        let cut = zone.delegation_for(name);
        let kind = zone.name_kind(name);
        let records = zone.query(name, Qtype::of(record_types::A)).len();
        (cut, kind, records)
    };

    let mixed = "WwW.eXaMpLe.CoM.";
    let _ = walks(&zone, mixed);

    let ((cut, kind, records), count) = allocations(|| walks(&zone, mixed));
    assert_eq!(cut, None, "the same answers as the lower-case name");
    assert_eq!(kind, NameKind::Exact);
    assert_eq!(records, 1);
    // The answer `Vec` as above, plus one fold per lookup that folds. `ZONE`
    // delegates nothing, so `delegation_for` answers without folding at all
    // (`TODO.md` #28c); it read 4 while every zone paid for that walk.
    within("the same three lookups, case randomized", count, 3..=3);

    // What the answer path asks now, in the order it asks: fold once at the
    // door (`TODO.md` #27a), then the delegation walk and one `locate` that
    // serves both the existence test and the records (#28b, #27c). Nothing is
    // collected — `query` built a `Vec` for a question that was `is_empty()`.
    let answer_path = |zone: &rdns::zone::Zone, name: &str| {
        let key = rdns::utils::absolute_lowered(name);
        let cut = zone.delegation_for(&key);
        let located = zone.locate(&key);
        let has = located.has_type(Qtype::of(record_types::A));
        let records = located.of_type(Qtype::of(record_types::A)).count();
        (cut, located.kind().clone(), has, records)
    };
    let _ = answer_path(&zone, mixed);

    let ((cut, kind, has, records), count) = allocations(|| answer_path(&zone, mixed));
    assert_eq!((cut, kind, has, records), (None, NameKind::Exact, true, 1));
    // The fold at the door and nothing else. It read 4 before #28b, #28c, #27a
    // and #27c; the one left is the fold itself, and it needs somewhere to put
    // the bytes that outlives the question (#27d).
    within("the answer path's lookups, case randomized", count, 1..=1);

    // The same against a zone with a child, where the delegation walk runs.
    let delegating = parse_zone_file(
        concat!(
            "@   IN SOA ns1 admin ( 1 3600 600 604800 300 )
",
            "@   IN NS  ns1
",
            "ns1 IN A   192.0.2.1
",
            "www IN A   192.0.2.10
",
            "sub IN NS  ns1.sub.example.com.
",
        ),
        "example.com.",
    )
    .expect("parse");
    let _ = answer_path(&delegating, mixed);

    let ((cut, kind, has, records), count) = allocations(|| answer_path(&delegating, mixed));
    assert_eq!((cut, kind, has, records), (None, NameKind::Exact, true, 1));
    within("the same, in a zone with a child", count, 1..=1);
}

/// Reading the SOA's MINIMUM — the ceiling on how long a negative answer may be
/// cached (RFC 2308 §3) — costs nothing, and cost four allocations for one `u32`
/// when it went through `RecordData::parse`.
///
/// `parse` decodes the whole RDATA, and an SOA's opens with MNAME and RNAME: a
/// label `Vec` and a `String` each, both discarded. Every NXDOMAIN and every
/// NODATA paid it, which is the shape a random-subdomain flood generates. The
/// old cost is measured beside the new one so this is a ratio rather than an
/// assertion that zero is zero.
fn reading_one_integer_out_of_an_soa() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let soa = *zone
        .query("example.com.", Qtype::of(record_types::SOA))
        .first()
        .expect("the apex SOA");

    // The shape this replaced, kept as a measurement rather than as code.
    let old = |soa: &rdns::zone::ZoneRecord| match soa.rdata.parse() {
        Ok(rdns::ParsedRecord::SOA { minimum, .. }) => minimum,
        _ => panic!("the apex SOA parses"),
    };
    let _warm = (old(soa), soa.rdata.soa_minimum());

    let (value, before) = allocations(|| old(soa));
    assert_eq!(value, 300, "the MINIMUM this zone file sets");
    within("read the MINIMUM out of an SOA, the old way", before, 4..=4);

    let (value, after) = allocations(|| soa.rdata.soa_minimum());
    assert_eq!(value, Some(300), "the same answer");
    within("read the MINIMUM out of an SOA", after, 0..=0);
}

/// The three things a server asks of a request's OPT record — reply size, EDNS
/// version, DO bit — read without building the option list.
///
/// `edns_header` against `options()` below is the ratio: asking through the
/// option list costs a `Vec` plus a `Vec<u8>` per option, and a resolver sending
/// a DNS cookie paid that per query for two flags.
fn reading_a_requests_edns_parameters_allocates_nothing() {
    let wire = query_bytes_with_edns("www.example.com.", Qtype::of(record_types::A));
    let msg = DnsMessage::try_from_bytes(&wire).expect("parse the query");

    // Warm first: a target of exactly zero cannot absorb another path's one-off.
    let _warm = msg.edns_header();

    let (header, count) = allocations(|| msg.edns_header());
    let header = header
        .expect("the option list is well formed")
        .expect("OPT");
    assert!(header.do_bit, "the measurement is about a real DO query");
    assert_eq!(header.udp_payload_size, 1232);
    within("read a request's EDNS parameters", count, 0..=0);

    // Six: an OPT record never becomes a `ResourceRecord`, so it costs one less
    // than the same query with a real additional record. It read 8 while
    // `Additional::try_from_bytes` parsed the owner name twice to peek at TYPE.
    let (parsed, parse_count) = allocations(|| DnsMessage::try_from_bytes(&wire));
    assert!(parsed.expect("parses").edns().is_some(), "the OPT is there");
    within("parse a query that carries EDNS", parse_count, 6..=6);

    let (found, found_count) = allocations(|| msg.edns());
    let found = found.expect("OPT");
    within("reach the OPT record", found_count, 0..=0);

    // The same two allocations as before the split, now charged to the caller
    // that asks for the options rather than to reaching the record.
    let (full, full_count) = allocations(|| found.options());
    assert_eq!(full.expect("well-formed").len(), 1, "one cookie");
    within(
        "and the same three fields through the full option parse",
        full_count,
        2..=2,
    );
}

/// A neighbouring thread's allocations are not this thread's.
///
/// Against dhat's global `total_blocks` this reads high, by however much the
/// neighbour got through — which is the shape of the CI failure that prompted
/// the change: 10 for a parse that reads 6 on four machines, green on a re-run
/// of the same commit.
fn a_busy_neighbour_stays_out_of_the_count() {
    let wire = query_bytes("www.example.com.", Qtype::of(record_types::A));
    let _warm = DnsMessage::try_from_bytes(&wire);

    static RUNNING: AtomicBool = AtomicBool::new(false);
    static STOP: AtomicBool = AtomicBool::new(false);
    let neighbour = std::thread::spawn(|| {
        RUNNING.store(true, Ordering::Release);
        while !STOP.load(Ordering::Relaxed) {
            std::hint::black_box(vec![0u8; 64]);
        }
    });
    while !RUNNING.load(Ordering::Acquire) {
        std::hint::spin_loop();
    }

    // A hundred parses, not one: a window of a few microseconds is one a
    // neighbour can miss, and a proof that holds by luck is not one.
    let (_, count) = allocations(|| {
        for _ in 0..100 {
            std::hint::black_box(DnsMessage::try_from_bytes(&wire).expect("parse"));
        }
    });
    STOP.store(true, Ordering::Relaxed);
    neighbour.join().expect("the neighbour thread");

    within("a hundred parses beside a busy thread", count, 300..=300);
}

/// Name compression is most of response serialization by time. This is what it
/// costs on a response whose names share suffixes, and what reading one back in
/// costs.
fn a_response_full_of_shared_suffixes() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let mut response =
        DnsMessage::try_from_bytes(&query_bytes("example.com.", Qtype::of(record_types::ANY)))
            .expect("parse");
    response.response = true;
    response.authoritive = true;
    for name in ["www.example.com.", "mx.example.com.", "ns1.example.com."] {
        for record in zone.query(name, Qtype::of(record_types::A)) {
            response.answers.push(ResourceRecord {
                name: name.to_string(),
                class: record.class,
                ttl: record.ttl,
                rdata: record.rdata.clone(),
            });
        }
    }
    assert_eq!(response.answers.len(), 3);

    let (_, count) = allocations(|| response.to_bytes_within(4096).expect("serialize"));
    // Three names sharing `example.com.`, plus the question. A range rather than
    // exact: the two compressor vectors grow with the number of distinct names
    // and choose their own reallocation points.
    within("serialize four names sharing a suffix", count, 5..=10);

    // The only measurement here that parses a name which is actually
    // *compressed* — a QNAME has nothing before it to point at — so the only one
    // covering `DNameUnpacker`'s pointer following.
    //
    // It holds down the visited-offsets set: cycle prevention was a
    // `RefCell<HashSet<usize>>` costing one allocation per message with a
    // pointer in it, and requiring a pointer to point backwards (RFC 1035
    // §4.1.4) makes a cycle unreachable rather than detected. 20 with it, 19
    // without; the rest is the message itself.
    let wire = response.to_bytes_within(4096).expect("serialize");
    let (reparsed, count) = allocations(|| DnsMessage::try_from_bytes(&wire).expect("parse back"));
    assert_eq!(
        reparsed.answers.len(),
        3,
        "the measurement is only meaningful if it parsed"
    );
    within("parse a response with compressed names", count, 19..=19);
}

/// A full zone load and sign, which runs on a worker that is also serving
/// queries.
fn one_zone_load_and_sign() {
    let (zone, parse_count) = allocations(|| parse_zone_file(ZONE, "example.com.").expect("parse"));
    // Eight records. A ceiling on how much per record, not a claim that a
    // per-record cost is wrong.
    within("parse an eight-record zone", parse_count, 120..=320);

    let keys = vec![
        SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            rdns::dnssec::DNSKEY_FLAG_ZONE | rdns::dnssec::DNSKEY_FLAG_SEP,
        )
        .expect("ksk"),
        SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            rdns::dnssec::DNSKEY_FLAG_ZONE,
        )
        .expect("zsk"),
    ];
    let policy = SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400);

    let (signed, sign_count) = allocations(|| sign_zone(&zone, &keys, &policy).expect("sign"));
    assert!(signed.records().len() > zone.records().len());
    // Moved 922 -> 924 when sealing `RecordData` put `zone_signer::dnskey_rdata`
    // through the checked constructor: a DNSKEY decoder allocates one `Vec` for
    // the public key, and there are two keys. NSEC3 is off in this policy, so
    // `nsec3param_rdata` does not run.
    within("sign an eight-record zone", sign_count, 600..=1_400);
}

/// An AXFR out, where a per-record allocation multiplies by the zone size.
fn one_axfr_out() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let request =
        DnsMessage::try_from_bytes(&query_bytes("example.com.", Qtype::of(record_types::AXFR)))
            .expect("parse");

    let (messages, count) =
        allocations(|| rdns::transfer::axfr_messages(&request, &zone).expect("axfr"));
    assert_eq!(messages.len(), 1, "this zone fits one message");
    let records = messages[0].answers.len();
    assert_eq!(
        records,
        zone.records().len() + 1,
        "every record, then the closing SOA again (RFC 5936 §2.2)"
    );
    within("build an AXFR of an eight-record zone", count, 10..=60);

    let (_, serialize_count) = allocations(|| {
        messages[0]
            .to_bytes_within(u16::MAX as usize)
            .expect("serialize")
    });
    // Nine records into one message: 41 before the compressor stopped keeping a
    // label-offset vector per name and a second copy of every name it had seen,
    // 19 after — a transfer is nothing but names.
    within("serialize one AXFR message", serialize_count, 14..=26);

    the_first_envelope_costs_the_same_however_big_the_zone_is(&request);
}

/// The cost of the first envelope must not grow with the zone: `axfr_messages`
/// built every frame before the first byte went out.
///
/// Equality rather than a bound — the two zones differ only in how many records
/// follow the measured envelope, so anything eager shows up as a difference.
fn the_first_envelope_costs_the_same_however_big_the_zone_is(request: &DnsMessage) {
    let small = big_zone(600);
    let large = big_zone(1_200);

    let (envelopes, small_count) = allocations(|| {
        rdns::transfer::axfr_envelopes(request, &small)
            .expect("envelopes")
            .next()
            .expect("one envelope")
    });
    let held = envelopes.answers.len();
    assert!(
        held < 600,
        "the zones have to be bigger than one envelope for this to measure anything: {held}"
    );
    let (_, large_count) = allocations(|| {
        rdns::transfer::axfr_envelopes(request, &large)
            .expect("envelopes")
            .next()
            .expect("one envelope")
    });
    assert_eq!(
        small_count, large_count,
        "the first envelope of a 1,200-record zone cost {large_count} against {small_count} \
         for a 600-record one: the zone is being materialized ahead of the writer"
    );
    within(
        "build the first envelope of an AXFR",
        small_count,
        1..=4_000,
    );

    // The whole transfer, for contrast: what the daemon used to pay before
    // sending anything.
    let (_, whole_count) =
        allocations(|| rdns::transfer::axfr_messages(request, &large).expect("axfr"));
    assert!(
        whole_count > large_count,
        "materializing the whole transfer cannot cost less than one envelope of it"
    );
    within(
        "build every envelope of the same AXFR",
        whole_count,
        2_200..=2_700,
    );

    // The count is not the point; the peak is. Streaming calls the allocator
    // about as often as materializing — the difference is how much is alive at
    // once, which is what a large transfer costs a server.
    let whole = big_zone(5_000);
    let (_envelope, envelope_peak) = peak_bytes(|| {
        rdns::transfer::axfr_envelopes(request, &whole)
            .expect("envelopes")
            .next()
            .expect("one envelope")
    });
    let (_messages, whole_peak) =
        peak_bytes(|| rdns::transfer::axfr_messages(request, &whole).expect("axfr"));
    assert!(
        whole_peak > envelope_peak * 4,
        "one envelope of a 5,000-record zone held {envelope_peak} bytes at its peak and the \
         whole transfer {whole_peak}: the sequence is not being built lazily"
    );
    println!("peak bytes: one envelope {envelope_peak}, the whole transfer {whole_peak}");
}

/// A zone of `records` A records, all sharing one suffix, plus its apex SOA.
fn big_zone(records: usize) -> rdns::zone::Zone {
    let mut text = String::from(
        "$ORIGIN example.com.\n\
         $TTL 3600\n\
         @ IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
         @ IN NS  ns1.example.com.\n",
    );
    for i in 0..records {
        text.push_str(&format!("h{i} IN A 192.0.2.{}\n", i % 254 + 1));
    }
    parse_zone_file(&text, "example.com.").expect("parse")
}

/// Every packet is scanned for a TSIG record, and the scan used to heap-allocate
/// a four-element `Vec<usize>` of section counts *before* checking whether there
/// was an additional section at all — one block per query on every server, TSIG
/// configured or not.
///
/// Both shapes, because the plain one alone is not evidence: `find_tsig` returns
/// at `ar == 0` before reaching its body, so a query with no additional section
/// measures the early exit and nothing else. Everything a resolver sends has an
/// OPT record.
fn scanning_a_query_for_a_tsig() {
    let keyring = rdns::tsig::TsigKeyring::new(Vec::new());
    let plain = query_bytes("www.example.com.", Qtype::of(record_types::A));
    let with_opt = query_bytes_with_edns("www.example.com.", Qtype::of(record_types::A));

    // Warm first: a target of exactly zero cannot absorb another path's
    // lazily-initialized state. This read 1 or 0 depending on scheduling.
    let _warm = rdns::tsig::check_request(&plain, &keyring, 0);
    let _warm = rdns::tsig::check_request(&with_opt, &keyring, 0);

    let (check, count) = allocations(|| rdns::tsig::check_request(&plain, &keyring, 0));
    assert!(
        matches!(check, rdns::tsig::TsigCheck::Unsigned),
        "a plain query carries no TSIG"
    );
    within("scan a TSIG-less query for a TSIG", count, 0..=0);

    let (check, count) = allocations(|| rdns::tsig::check_request(&with_opt, &keyring, 0));
    assert!(
        matches!(check, rdns::tsig::TsigCheck::Unsigned),
        "an OPT record is not a TSIG"
    );
    // Zero since `find_tsig` checks the record's TYPE before reading its owner
    // name; it read 1 while the name came first, on every EDNS query.
    within(
        "scan a TSIG-less query that carries an OPT record",
        count,
        0..=0,
    );
}

/// Comparing two names is a question about bytes and should cost nothing.
///
/// `resolver::names_equal` was `normalize(a) == normalize(b)`: two `String`s per
/// comparison, inside `.any()` loops over an answer section. The old shape is
/// measured beside the new one so this is a ratio and not an assertion that zero
/// is zero.
fn comparing_two_names_allocates_nothing() {
    let a = "www.example.com.";
    let b = "WWW.Example.COM.";

    // The shape this replaced, kept as a measurement rather than as code.
    let old = |x: &str, y: &str| {
        let n = |s: &str| {
            let lowered = s.to_ascii_lowercase();
            if lowered.ends_with('.') {
                lowered
            } else {
                format!("{lowered}.")
            }
        };
        n(x) == n(y)
    };

    let _warm = (old(a, b), rdns::utils::names_equal(a, b));

    let (was_equal, before) = allocations(|| old(a, b));
    assert!(was_equal);
    within("compare two names, the old way", before, 2..=2);

    let (is_equal, after) = allocations(|| rdns::utils::names_equal(a, b));
    assert!(is_equal, "the same answer");
    within("compare two names", after, 0..=0);
}

/// [`ZONE`] signed by a KSK and a ZSK, which is the ordinary shape: an RRset
/// carries one RRSIG and the DNSKEY RRset carries two.
fn signed_zone() -> rdns::zone::Zone {
    signed_zone_with(DenialChain::Nsec)
}

fn signed_zone_nsec3() -> rdns::zone::Zone {
    signed_zone_with(DenialChain::nsec3())
}

fn signed_zone_with(chain: DenialChain) -> rdns::zone::Zone {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let keys = vec![
        SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            rdns::dnssec::DNSKEY_FLAG_ZONE | rdns::dnssec::DNSKEY_FLAG_SEP,
        )
        .expect("ksk"),
        SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            rdns::dnssec::DNSKEY_FLAG_ZONE,
        )
        .expect("zsk"),
    ];
    sign_zone(
        &zone,
        &keys,
        &SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400).with_chain(chain),
    )
    .expect("sign")
}

/// One metrics registry, which every task that reports anything holds a clone
/// of.
///
/// Not on the answer path — it is built at startup and cloned per task, not per
/// query — so this is here as the shape rather than as a cost: a counter per
/// `Arc` is one allocation per counter and one refcount operation per counter on
/// every clone, where one `Arc` around all of them is one of each.
fn building_the_metrics_registry() {
    let _warm = rdns::metrics::DnsMetrics::new();

    let (metrics, count) = allocations(rdns::metrics::DnsMetrics::new);
    within("build a metrics registry", count, 1..=1);

    let (clone, clone_count) = allocations(|| metrics.clone());
    within("clone one", clone_count, 0..=0);
    drop((metrics, clone));
}

/// DNSSEC canonical ordering (RFC 4034 §6.1) is a question about bytes.
///
/// It went through a `Vec<String>` of down-cased labels, so one comparison cost
/// a `Vec` and a `String` per label at each side — and `Nsec::covers` makes
/// three comparisons, so a validator paid twelve per candidate NSEC. The sort
/// key keeps one allocation, which is the key it returns.
fn ordering_two_names_canonically() {
    let a = "a.z.example.com.";
    let b = "B.example.COM.";
    let _warm = (
        rdns::dnssec_denial::canonical_name_cmp(a, b),
        rdns::dnssec_denial::canonical_sort_key(a),
    );

    let (order, count) = allocations(|| rdns::dnssec_denial::canonical_name_cmp(a, b));
    assert_eq!(
        order,
        std::cmp::Ordering::Greater,
        "the rightmost differing label decides, and case does not"
    );
    within("order two names canonically", count, 0..=0);

    let (key, count) = allocations(|| rdns::dnssec_denial::canonical_sort_key(a));
    assert!(!key.is_empty());
    within("build a canonical sort key", count, 1..=1);
}

/// The whole authority section of a signed NXDOMAIN: the SOA and its signature,
/// the NSEC denying the name, and the NSEC denying the wildcard that could have
/// answered it (RFC 4035 §3.1.3.2).
///
/// A range, because it is proportional to the records the proof needs rather
/// than to anything fixed. It is here because it is the shape a random-subdomain
/// flood generates: **142** before the canonical ordering above stopped
/// allocating, 114 after, **34** since the RRSIG filter stopped parsing, 29
/// since an NXDOMAIN stopped asking whether the zone is signed twice, and 24
/// since the walk to the closest encloser stopped building a `String` per
/// ancestor.
///
/// So the ordering was 28 of the 142 and not, as `TODO.md` #25d implied, most of
/// it. Most of it was `signatures_at`, which read TYPE COVERED by decoding each
/// candidate RRSIG whole — 36 allocations for the one signature over the apex
/// SOA. What is left is the records themselves, each an owner `String` and a
/// cloned RDATA, plus a `Zone::query` `Vec` per lookup: those are what a
/// response written straight to the wire would remove (`TODO.md` #27e), and
/// nothing smaller.
fn proving_a_signed_nxdomain() {
    let signed = signed_zone();
    let _warm =
        rdns::dnssec_answer::negative_proof(&signed, "nope.example.com.", &NameKind::NotFound);

    let (proof, count) = allocations(|| {
        rdns::dnssec_answer::negative_proof(&signed, "nope.example.com.", &NameKind::NotFound)
    });
    assert_eq!(
        proof.len(),
        5,
        "SOA, its RRSIG, and two denials with theirs"
    );
    within("prove a signed NXDOMAIN", count, 20..=30);
}

/// The same NXDOMAIN over an NSEC3-signed zone, where the proof is a walk and
/// not a lookup: a hash chain cannot point at a name, so the answer names the
/// closest encloser and the next closer name (RFC 5155 §7.2.1), and finding the
/// encloser is a hash per label of the QNAME.
///
/// **129** when it was first split out of the NSEC figure above, 76 once the
/// naming stopped allocating, 48 once the walk ran once, 38 once the chain's
/// salt and iteration count were read at their offset instead of parsed out of
/// a record per answer, and 28 once the walk itself stopped allocating.
///
/// The naming around the hashing was the cost, not the hashing: an owner name
/// was `format!("{}.{origin}", base32hex_encode(h).to_lowercase())`, three
/// allocations, and `nsec3_hash` rebuilt the digest as a `Vec` per iteration
/// over a `Vec` of the wire name over a down-cased copy of the text — four more.
/// Both are per *candidate* name, and the two halves of an NXDOMAIN each walked
/// the QNAME to the same closest encloser.
fn proving_a_signed_nxdomain_under_nsec3() {
    let signed = signed_zone_nsec3();
    let _warm =
        rdns::dnssec_answer::negative_proof(&signed, "nope.example.com.", &NameKind::NotFound);

    let (proof, count) = allocations(|| {
        rdns::dnssec_answer::negative_proof(&signed, "nope.example.com.", &NameKind::NotFound)
    });
    // Five, not seven: one NSEC3 covers the next closer name *and* the
    // wildcard, and `push_with_signatures` drops the identical second copy —
    // which it could not while the two halves each built their own `Vec`.
    assert_eq!(proof.len(), 5, "the SOA's RRSIG and two NSEC3s with theirs");
    within("prove a signed NXDOMAIN under NSEC3", count, 24..=34);
}

/// `verify_rrset` rebuilds the canonical form of the whole RRset per candidate
/// RRSIG, so an RRset signed by both a KSK and a ZSK can do all of it twice.
fn verifying_an_rrset_against_two_candidate_signatures() {
    let signed = signed_zone();

    let owned = |name: &str, rtype: Rtype| -> Vec<ResourceRecord> {
        signed
            .query(name, Qtype::of(rtype))
            .into_iter()
            .map(|r| ResourceRecord {
                name: r.name.clone(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.clone(),
            })
            .collect()
    };

    // The DNSKEY RRset is the one signed by both keys, which is exactly the
    // two-candidate case.
    let dnskeys = dnskeys_in(&owned("example.com.", record_types::DNSKEY));
    let rrsigs = rrsigs_in(&owned("example.com.", record_types::RRSIG));
    let rdatas: Vec<_> = owned("example.com.", record_types::DNSKEY)
        .into_iter()
        .map(|r| r.rdata)
        .collect();
    let rrset = Rrset::new("example.com.", record_types::DNSKEY, Class::new(1), &rdatas);
    let now = current_unix_timestamp();

    let (proof, count) =
        allocations(|| verify_rrset(&rrset, &rrsigs, &dnskeys, "example.com.", now));
    assert!(
        matches!(proof, RrsetProof::Verified { .. }),
        "the measurement is only meaningful if it verified: {proof:?}"
    );
    within(
        "verify a DNSKEY RRset with two candidate signatures",
        count,
        0..=u64::MAX,
    );
}
