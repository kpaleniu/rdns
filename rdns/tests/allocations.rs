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
//! Counts come from [`rdns::testutil::Counting`], which tallies per thread,
//! because a mutex cannot make a global counter exact — its doc comment says
//! why, and `rdnsr`'s allocation test wraps a different allocator with the same
//! type (`TODO.md` #88). dhat still supplies the peak-bytes figures, which are
//! about the whole heap by definition.

use rdns::Class;
use rdns::Name;
use rdns::NameRef;
use rdns::Rtype;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use rdns::testutil::{allocations, Counting};

use rdns::clock::current_unix_timestamp;
use rdns::dnssec::{dnskeys_in, rrsigs_in, verify_rrset, Rrset, RrsetProof};
use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::dnssec_validation_mode::{DnssecValidator, Verdict, ZoneKeys};
use rdns::record_types;
use rdns::zone::{parse_zone_file, NameKind};
use rdns::zone_signer::{sign_zone, DenialChain, SigningPolicy};
use rdns::{DnsMessage, DnsMessageBuilder, Edns, EdnsOption, Qtype, ResourceRecord};

/// A name from a literal, for tests only: `Name` is fallible to build and a test
/// that writes a bad one should fail loudly at that line.
fn nm(text: &str) -> Name {
    text.parse().expect("a test name parses")
}

#[global_allocator]
static ALLOC: Counting<dhat::Alloc> = Counting(dhat::Alloc);

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
    answering_a_signed_query();
    proving_a_signed_nxdomain_under_nsec3();
    checking_a_signed_nxdomain();
    what_the_resolvers_caches_cost();
    verifying_an_rrset_against_two_candidate_signatures();
    checking_one_rrset_does_not_read_the_whole_zone();
    a_busy_neighbour_stays_out_of_the_count();
    writing_a_record_as_text_borrows_it();
}

/// Rendering a record as a zone-file line costs the line and nothing else.
///
/// `record_line` takes the fields, so `journal`'s `ResourceRecord`s need no
/// throwaway `ZoneRecord`. Asserted as the two entry points costing the same;
/// fails by two blocks if the `ResourceRecord` path builds a record.
fn writing_a_record_as_text_borrows_it() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("the zone parses");
    let record = zone
        .records()
        .iter()
        .find(|r| r.rdata.rtype() == rdns::record_types::A)
        .expect("an A record");
    let wire = rdns::ResourceRecord {
        name: record.name.to_owned(),
        class: record.class,
        ttl: record.ttl,
        rdata: record.rdata.to_owned(),
    };

    // The first call in a process picks up one-off initialization
    // (`CLAUDE.md` §10).
    let _ = rdns::zone_writer::record_to_string(record);

    let (from_zone, zone_blocks) =
        allocations(|| rdns::zone_writer::record_to_string(record).expect("a line"));
    let (from_wire, wire_blocks) =
        allocations(|| rdns::record_text::resource_record_line(&wire).expect("a line"));

    // The shape this replaced, measured rather than asserted in prose: the
    // journal held a `ResourceRecord` and built a `ZoneRecord` to render it.
    let (from_copy, copy_blocks) = allocations(|| {
        rdns::zone_writer::record_to_string(
            rdns::zone::ZoneRecord {
                name: wire.name.clone(),
                ttl: wire.ttl,
                class: wire.class,
                rdata: wire.rdata.clone(),
            }
            .as_ref(),
        )
        .expect("a line")
    });

    assert_eq!(from_zone, from_wire, "the same record, the same line");
    assert_eq!(from_zone, from_copy, "and the same line the old path wrote");
    assert_eq!(
        copy_blocks,
        wire_blocks + 2,
        "the copy is the name and the RDATA, once each, per record journalled"
    );
    println!("record_to_string: {zone_blocks} allocations, resource_record_line: {wire_blocks}");
    assert_eq!(
        zone_blocks, wire_blocks,
        "neither entry point may copy the record to render it"
    );
    // A backstop, not a budget: RFC 3597's hex form is built only when the
    // type-specific one fails, or it costs an allocation per RDATA octet.
    within("rendering one A record as a line", zone_blocks, 5..=18);
}

/// What checking one RRset of a signed zone costs, at two zone sizes.
///
/// The two counts must be equal: collecting the zone's keys per call made the
/// cost grow with the zone and loading quadratic (`TODO.md` #50). A count,
/// exact on every machine (`CLAUDE.md` §10).
fn checking_one_rrset_does_not_read_the_whole_zone() {
    use std::fmt::Write as _;
    let validator = DnssecValidator::new(true);

    let count_for = |hosts: usize| -> u64 {
        let mut text = String::from(ZONE);
        for i in 0..hosts {
            let _ = writeln!(text, "host{i} IN A 192.0.2.9");
        }
        let zone = parse_zone_file(&text, "example.com.").expect("parse");
        let keys = vec![SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            rdns::dnssec::DNSKEY_FLAG_ZONE,
        )
        .expect("zsk")];
        let signed = sign_zone(
            &zone,
            &keys,
            &SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400),
        )
        .expect("sign");
        let zone_keys = ZoneKeys::of(&signed);
        let records = signed.query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A));
        assert!(!records.is_empty(), "the RRset to check has to be there");

        // Once before measuring: the first call allocates what later ones
        // reuse, and the target is a difference.
        let _ = validator.validate_rrset(&signed, &zone_keys, &records);
        let (verdict, count) =
            allocations(|| validator.validate_rrset(&signed, &zone_keys, &records));
        assert_eq!(
            verdict,
            Verdict::Valid,
            "the measurement means nothing unless it verified"
        );
        count
    };

    let small = count_for(10);
    let large = count_for(500);
    println!("check one RRset in a 10-host zone: {small} allocations");
    println!("check one RRset in a 500-host zone: {large} allocations");
    assert_eq!(
        small, large,
        "checking one RRset allocated {small} in a small zone and {large} in one \
         fifty times the size: the check is reading the whole zone again"
    );
}

/// Two measured bodies must not overlap: the profiler is global, so another
/// body's allocations land in the running measurement. Poisoning is ignored, so
/// one failure stays one.
static PROFILER: Mutex<()> = Mutex::new(());

/// Take exclusive use of the profiler, and warm it up.
///
/// The first profiled block in a process picks up a one-off from dhat's own lazy
/// state, so without the warm-up the first measurement reads one high.
fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    let guard = PROFILER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    static WARMED: std::sync::Once = std::sync::Once::new();
    WARMED.call_once(|| {
        let profiler = dhat::Profiler::builder().testing().build();
        let _ = dhat::HeapStats::get();
        drop(profiler);
    });
    guard
}

// `allocations` is `rdns::testutil`'s, per thread, as dhat's global counters
// see libtest's threads; [`exclusive`] still guards [`peak_bytes`].

/// Run `body` under a profiler and report the most memory it held at once:
/// streaming and materializing transfers allocate as often, but hold different
/// amounts. Call only while holding [`exclusive`].
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
    DnsMessageBuilder::new()
        .with_id(0x1234)
        .with_query(nm(qname), qtype)
        .with_recursion(false)
        .build()
}

/// One UDP query end to end, split into parse, look up and serialize so the
/// answer is a breakdown rather than one number.
fn one_query_end_to_end() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let wire = query_bytes("www.example.com.", Qtype::of(record_types::A));

    let (parsed, parse_count) =
        allocations(|| DnsMessage::try_from_bytes(&wire).expect("parse the query"));
    // Two: the QNAME `String` and the question vector. A QNAME has nothing to
    // point back at, so it is built from its own bytes.
    within("parse a one-question query", parse_count, 2..=2);

    // Built outside: off the wire the name is already a `Name`, and parsing
    // presentation text is the zone file's cost rather than a query's.
    let qname = nm("www.example.com.");
    let (answers, lookup_count) = allocations(|| {
        zone.query(qname.as_ref(), Qtype::of(record_types::A))
            .into_iter()
            .map(|r| ResourceRecord {
                name: r.name.to_owned(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.to_owned(),
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(answers.len(), 1);
    // Three: `Zone::query`'s vector and the owner and RDATA from the arenas;
    // `collect` reuses `query`'s allocation, both 48 bytes.
    within("look up one A record in the zone", lookup_count, 3..=3);

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

    // Nothing when the compressor is carried too, as a send loop does
    // (`TODO.md` #27b); `to_bytes_with` clears it per message.
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
    let qname = nm("www.example.com.");
    let records = zone.query(qname.as_ref(), Qtype::of(record_types::A));
    assert_eq!(records.len(), 1);

    let mut out = Vec::new();
    let mut compressor = rdns::compression::NameCompressor::new();
    let write = |out: &mut Vec<u8>, compressor: &mut NameCompressor| {
        let mut w = ResponseWriter::start(out, compressor, 4096, &request).expect("start");
        w.set_authoritative(true);
        for r in &records {
            w.push(Section::Answer, qname.as_ref(), r.class, r.ttl, r.rdata)
                .expect("push");
        }
        w.set_edns(Edns::with_payload_size(1232));
        w.finish().expect("finish");
    };
    write(&mut out, &mut compressor);
    let ((), count) = allocations(|| write(&mut out, &mut compressor));
    within("write a one-record response", count, 0..=0);
    assert!(!out.is_empty());

    // With neither in hand: what `rdnsd` pays per message on TCP (`TODO.md`
    // #39e), against 0 on UDP's held scratch.
    let ((), cold) = allocations(|| {
        let mut out = Vec::new();
        let mut compressor = NameCompressor::new();
        write(&mut out, &mut compressor);
        assert!(!out.is_empty());
    });
    within("write it with a fresh buffer and compressor", cold, 3..=3);
}

/// One zone answer to a lower-case question costs nothing: the lookups borrow
/// the name and the records go straight to the writer.
///
/// Through [`rdns::zone_answer::write`]. A guard against the lookup key going
/// back to an owned copy per lookup: four per query, ~14% of everything an
/// answer allocates.
fn the_lookups_behind_one_answer_allocate_only_the_answer() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let (reply, count) =
        zone_answer_count(&zone, "www.example.com.", Qtype::of(record_types::A), false);
    assert_eq!(
        reply.answers.len(),
        1,
        "www.example.com. holds exactly one A"
    );
    within("one zone answer", count, 0..=0);
}

/// The same three lookups against the name a DNS-0x20 resolver actually sends.
///
/// Mixed case is ordinary traffic, and every `Zone` entry point folds;
/// `folded_in` borrows only a lower-case name, so this counts the rest
/// (`TODO.md` #160).
fn a_case_randomized_qname_costs_a_fold_per_lookup() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let walks = |zone: &rdns::zone::Zone, name: NameRef<'_>| {
        let cut = zone.delegation_for(name);
        let kind = zone.name_kind(name);
        let records = zone.query(name, Qtype::of(record_types::A)).len();
        (cut, kind, records)
    };

    // Built outside the measurement: parsing presentation text is the zone
    // file's cost, not a query's — off the wire a name arrives already built.
    let mixed = nm("WwW.eXaMpLe.CoM.");
    let mixed = mixed.as_ref();
    let _ = walks(&zone, mixed);

    let ((cut, kind, records), count) = allocations(|| walks(&zone, mixed));
    assert_eq!(cut, None, "the same answers as the lower-case name");
    assert_eq!(kind, NameKind::Exact);
    assert_eq!(records, 1);
    // The answer `Vec`, plus a fold per lookup that folds; `ZONE` delegates
    // nothing, so `delegation_for` does not.
    within("the same three lookups, case randomized", count, 3..=3);

    // The answer path: the fold at the door onto the stack, the delegation
    // walk, and one `locate` for existence and records.
    let (reply, count) =
        zone_answer_count(&zone, "WwW.eXaMpLe.CoM.", Qtype::of(record_types::A), false);
    assert_eq!(reply.answers.len(), 1);
    within("the answer path's lookups, case randomized", count, 0..=0);

    // The `Zone` primitives the answer path calls, in its order, for the two
    // measurements below.
    let answer_path = |zone: &rdns::zone::Zone, name: NameRef<'_>| {
        let mut buf = Vec::new();
        let key = name.folded_in(&mut buf);
        let cut = zone.delegation_for(key);
        let located = zone.locate(key);
        let has = located.has_type(Qtype::of(record_types::A));
        let records = located.of_type(Qtype::of(record_types::A)).count();
        (cut, located.kind().clone(), has, records)
    };
    // With a buffer, nothing: the steady state of a reused, warmed `Vec`.
    // `zone_answer::write` folds onto the stack instead.
    let buffered = |zone: &rdns::zone::Zone, name: NameRef<'_>, buf: &mut Vec<u8>| {
        let key = name.folded_in(buf);
        let cut = zone.delegation_for(key);
        let located = zone.locate(key);
        let has = located.has_type(Qtype::of(record_types::A));
        let records = located.of_type(Qtype::of(record_types::A)).count();
        (cut, located.kind().clone(), has, records)
    };
    let mut key_buf = Vec::new();
    let _ = buffered(&zone, mixed, &mut key_buf);

    let (answers, count) = allocations(|| buffered(&zone, mixed, &mut key_buf));
    assert_eq!(
        answers,
        (None, NameKind::Exact, true, 1),
        "the same answers"
    );
    within(
        "the answer path's lookups, into a worker's buffer",
        count,
        0..=0,
    );

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

/// Reading the SOA's MINIMUM, the ceiling on how long a negative answer may be
/// cached (RFC 2308 §3), costs nothing.
///
/// A full `parse` decodes MNAME and RNAME to discard them, on every NXDOMAIN
/// and NODATA; it is measured beside, so this is a ratio, not zero against
/// zero.
fn reading_one_integer_out_of_an_soa() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let soa = *zone
        .query(nm("example.com.").as_ref(), Qtype::of(record_types::SOA))
        .first()
        .expect("the apex SOA");

    // The shape this replaced, kept as a measurement rather than as code.
    let old = |soa: rdns::zone::ZoneRecordRef<'_>| match soa.rdata.parse() {
        Ok(rdns::ParsedRecord::SOA { minimum, .. }) => minimum,
        _ => panic!("the apex SOA parses"),
    };
    let _warm = (old(soa), soa.rdata.soa_minimum());

    let (value, before) = allocations(|| old(soa));
    assert_eq!(value, 300, "the MINIMUM this zone file sets");
    within("read the MINIMUM out of an SOA, the old way", before, 2..=2);

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

    // Three: the question `Vec`, the QNAME, and the OPT's option list in wire
    // form. The OPT's owner is never decoded (RFC 6891 §6.1.2).
    let (parsed, parse_count) = allocations(|| DnsMessage::try_from_bytes(&wire));
    assert!(parsed.expect("parses").edns().is_some(), "the OPT is there");
    within("parse a query that carries EDNS", parse_count, 3..=3);

    let (found, found_count) = allocations(|| msg.edns());
    let found = found.expect("OPT");
    within("reach the OPT record", found_count, 0..=0);

    // Two allocations, charged to the caller that asks for the options rather
    // than to reaching the record.
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

    within("a hundred parses beside a busy thread", count, 200..=200);
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
        for record in zone.query(nm(name).as_ref(), Qtype::of(record_types::A)) {
            response.answers.push(ResourceRecord {
                name: nm(name),
                class: record.class,
                ttl: record.ttl,
                rdata: record.rdata.to_owned(),
            });
        }
    }
    assert_eq!(response.answers.len(), 3);

    let (_, count) = allocations(|| response.to_bytes_within(4096).expect("serialize"));
    // A range: the compressor's vectors grow with the distinct names and pick
    // their own reallocation points.
    within("serialize four names sharing a suffix", count, 5..=10);

    // The one parse of an actually compressed name, covering `DNameUnpacker`'s
    // pointer following, with no visited set (`docs/adr/0002`).
    let wire = response.to_bytes_within(4096).expect("serialize");
    let (reparsed, count) = allocations(|| DnsMessage::try_from_bytes(&wire).expect("parse back"));
    assert_eq!(
        reparsed.answers.len(),
        3,
        "the measurement is only meaningful if it parsed"
    );
    within("parse a response with compressed names", count, 15..=15);
}

/// A full zone load and sign, which runs on a worker that is also serving
/// queries.
fn one_zone_load_and_sign() {
    let (zone, parse_count) = allocations(|| parse_zone_file(ZONE, "example.com.").expect("parse"));
    // A ceiling per record, for eight records: the file's fixed costs, arenas
    // (`TODO.md` #71d, #71e) traded for nothing per record (#72, #72b).
    within("parse an eight-record zone", parse_count, 20..=200);

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
    // A wide range: fixed arena growth dominates an eight-record zone
    // (`TODO.md` #64e, #64g, #71d, #71e have each move).
    within("sign an eight-record zone", sign_count, 400..=1_400);
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
    // Nine records into one message; a transfer is nothing but names.
    within("serialize one AXFR message", serialize_count, 9..=20);

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

    // The whole transfer, for contrast: what building it before sending
    // anything costs.
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

    // The peak, not the count: streaming allocates as often as materializing,
    // but holds less at once.
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
    use std::fmt::Write as _;
    let mut text = String::from(
        "$ORIGIN example.com.\n\
         $TTL 3600\n\
         @ IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
         @ IN NS  ns1.example.com.\n",
    );
    for i in 0..records {
        let _ = writeln!(text, "h{i} IN A 192.0.2.{}", i % 254 + 1);
    }
    parse_zone_file(&text, "example.com.").expect("parse")
}

/// Every packet is scanned for a TSIG, so the scan must not allocate before
/// seeing an additional section. Both shapes, as `find_tsig` returns at `ar ==
/// 0` and every resolver query carries an OPT.
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
    let (a, b) = (nm("www.example.com."), nm("WWW.Example.COM."));

    // The shape this replaced, kept as a measurement rather than as code: two
    // names were `String`s, so folding them to compare meant a copy each.
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

    let (text_a, text_b) = (a.to_string(), b.to_string());
    let _warm = (old(&text_a, &text_b), a == b);

    let (was_equal, before) = allocations(|| old(&text_a, &text_b));
    assert!(was_equal);
    within("compare two names, the old way", before, 2..=2);

    // `Name`'s `Eq` folds ASCII as it goes (RFC 4343), so there is nothing to
    // copy — the comparison walks the wire octets of both.
    let (is_equal, after) = allocations(|| a == b);
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

    // One scrape: the output buffer growing, plus a `to_string` and an
    // `escape_label` per zone. The bytes out are identical either way.
    for zone in ["example.com.", "example.net."] {
        metrics.set_zone_serial(
            zone.parse::<rdns::Name>().expect("a zone name").as_ref(),
            rdns::Serial::new(7),
        );
    }
    let _warm_scrape = metrics.to_prometheus_format();
    let (scrape, scrape_count) = allocations(|| metrics.to_prometheus_format());
    within("render one scrape", scrape_count, 16..=16);
    drop((metrics, clone, scrape));
}

/// DNSSEC canonical ordering (RFC 4034 §6.1) is a question about bytes.
///
/// It went through a `Vec<String>` of down-cased labels, so one comparison cost
/// a `Vec` and a `String` per label at each side — and `Nsec::covers` makes
/// three comparisons, so a validator paid twelve per candidate NSEC. The sort
/// key keeps one allocation, which is the key it returns.
fn ordering_two_names_canonically() {
    let a: rdns::Name = "a.z.example.com.".parse().expect("a name");
    let b: rdns::Name = "B.example.COM.".parse().expect("a name");
    let (a, b) = (a.as_ref(), b.as_ref());
    let _warm = (
        rdns::denial_wire::canonical_name_cmp(a, b),
        rdns::denial_wire::canonical_sort_key(a),
    );

    let (order, count) = allocations(|| rdns::denial_wire::canonical_name_cmp(a, b));
    assert_eq!(
        order,
        std::cmp::Ordering::Greater,
        "the rightmost differing label decides, and case does not"
    );
    within("order two names canonically", count, 0..=0);

    let (key, count) = allocations(|| rdns::denial_wire::canonical_sort_key(a));
    assert_ne!(
        key,
        rdns::denial_wire::canonical_sort_key(nm("other.test.").as_ref())
    );
    within("build a canonical sort key", count, 1..=1);
}

/// The whole authority section of a signed NXDOMAIN: the SOA and its signature,
/// and the NSECs denying the name and the wildcard (RFC 4035 §3.1.3.2). A
/// range, proportional to the proof's records: the random-subdomain flood's
/// shape (`TODO.md` #25d, #27e).
fn proving_a_signed_nxdomain() {
    let (reply, count) = nxdomain_proof(&signed_zone());
    assert_eq!(
        reply.authorities.len(),
        6,
        "the SOA, its RRSIG, and two NSECs with theirs"
    );
    // The whole answer, SOA included; the proof alone reads one more on its own
    // than beside the SOA, uninvestigated.
    within("prove a signed NXDOMAIN", count, 5..=15);
}

/// A positive answer from a signed zone: the records and the RRSIGs over them,
/// through [`rdns::zone_answer::write`], which is `rdnsd`'s answer path.
///
/// The gate is on the *sequence*, because what #25a removed is a repetition
/// between the two halves: the signatures located the name a second time and
/// canonicalized a name the caller had already folded. The lookup is time
/// rather than allocations, so what this holds is the fold — one per signed
/// answer, and none for a name that arrives lower-case.
fn answering_a_signed_query() {
    let zone = signed_zone();
    let (reply, count) =
        zone_answer_count(&zone, "www.example.com.", Qtype::of(record_types::A), true);
    assert_eq!(reply.answers.len(), 2, "the A record and its RRSIG");
    within("answer a signed query", count, 0..=0);
}

/// The same NXDOMAIN over an NSEC3-signed zone: the encloser is a hash per
/// QNAME label (RFC 5155 §7.2.1).
///
/// What costs is naming around the hashing, per candidate; one walk serves both
/// halves, and salt and iterations are read at their offset.
fn proving_a_signed_nxdomain_under_nsec3() {
    let (reply, count) = nxdomain_proof(&signed_zone_nsec3());
    // Six, not eight: one NSEC3 covers the next closer name and the wildcard,
    // and the writer skips the second copy.
    assert_eq!(
        reply.authorities.len(),
        6,
        "the SOA, its RRSIG, and two NSEC3s with theirs"
    );
    // The same SOA as above.
    within("prove a signed NXDOMAIN under NSEC3", count, 5..=15);
}

/// An NXDOMAIN through [`rdns::zone_answer::write`], and what writing it costs.
///
/// The whole answer, not the proof alone: the SOA and the walk that decides
/// NXDOMAIN are counted too, because `rdnsd` pays for them on the same query
/// and the proof is reached no other way.
fn nxdomain_proof(signed: &rdns::zone::Zone) -> (rdns::DnsMessage, u64) {
    let (reply, count) = zone_answer_count(
        signed,
        "nope.example.com.",
        Qtype::of(record_types::A),
        true,
    );
    assert_eq!(reply.rcode, rdns::ResponseCode::NoSuchDomain);
    (reply, count)
}

/// What one [`rdns::zone_answer::write`] costs, in a reply started outside the
/// measurement: the 64 KB scratch every response path already owns is not the
/// answer's cost. Run once first, because the first call in a process picks up
/// a one-off.
fn zone_answer_count(
    zone: &rdns::zone::Zone,
    qname: &str,
    qtype: Qtype,
    dnssec_ok: bool,
) -> (rdns::DnsMessage, u64) {
    let request = rdns::DnsMessageBuilder::new()
        .with_query(nm(qname), qtype)
        .with_id(1)
        .with_dnssec(dnssec_ok)
        .build();
    // Built outside: off the wire a name arrives already built.
    let qname = nm(qname);
    let mut out = Vec::new();
    let mut compressor = rdns::compression::NameCompressor::new();
    let mut answer = || {
        let mut w = rdns::response::ResponseWriter::start(
            &mut out,
            &mut compressor,
            u16::MAX as usize,
            &request,
        )
        .expect("start a reply");
        let ((), count) = allocations(|| {
            rdns::zone_answer::write(zone, &qname, qtype, dnssec_ok, &mut w)
                .expect("the answer writes")
        });
        w.finish().expect("the reply serializes");
        count
    };
    let _ = answer();
    let count = answer();
    let reply = rdns::DnsMessage::try_from_bytes(&out).expect("and parses back");
    (reply, count)
}

/// The other end of the two answers above: what the *validator* pays to check
/// the proof, on the resolver's path, with no zone to read from.
///
/// Its walk is per QNAME label, which a client picks, so the hash is an array
/// and each candidate a suffix slice (`CLAUDE.md` §7).
fn checking_a_signed_nxdomain() {
    // Both are 1: `Nsec` and `Nsec3` hold `Name`s, the encloser is a borrowed
    // suffix, and the wildcard is the one name built.
    for (what, zone, expected) in [
        ("NSEC", signed_zone(), 1),
        ("NSEC3", signed_zone_nsec3(), 1),
    ] {
        let (reply, _) = nxdomain_proof(&zone);
        let nsecs = rdns::dnssec_denial::nsecs_in(&reply.authorities);
        let nsec3s = rdns::dnssec_denial::nsec3s_in(&reply.authorities);
        // The first call in a process picks up a one-off; measure the second.
        let denial = rdns::dnssec_denial::proves_nxdomain(
            nm("nope.example.com.").as_ref(),
            nm("example.com.").as_ref(),
            &nsecs,
            &nsec3s,
        );
        assert!(
            matches!(denial, rdns::dnssec_denial::Denial::Proved),
            "the measurement is only meaningful if the proof stands: {denial:?}"
        );
        // Names made outside: this measures the proof; a caller's names came
        // off the wire.
        let (qname, zone_name) = (nm("nope.example.com."), nm("example.com."));
        let (_, count) = allocations(|| {
            rdns::dnssec_denial::proves_nxdomain(
                qname.as_ref(),
                zone_name.as_ref(),
                &nsecs,
                &nsec3s,
            )
        });
        within(
            &format!("check a signed NXDOMAIN under {what}, as a validator"),
            count,
            expected..=expected,
        );
    }
}

/// The two caches every `rdnsr` query meets first (`TODO.md` #29). A miss, the
/// flood shape, costs zero: a question in key form is looked up as it stands,
/// with borrowed ancestors.
fn what_the_resolvers_caches_cost() {
    let cache = rdns::cache::DnsCache::new(1_000);
    let qtype = Qtype::of(record_types::A);
    // The names are built once, outside every measurement: a QNAME arrives off
    // the wire and the caches take it as it stands.
    let held = nm("www.example.com.");
    let absent = nm("nothing.example.com.");
    let rrset: Vec<ResourceRecord> = (0..3)
        .map(|_| ResourceRecord {
            name: held.clone(),
            class: Class::IN,
            ttl: rdns::Ttl::from_wire(3600),
            rdata: rdns::RecordData::new(record_types::A, vec![192u8, 0, 2, 1]).expect("A"),
        })
        .collect();
    cache.put(held.as_ref(), qtype, rrset);
    // The first call in a process picks up a one-off.
    let _ = cache.get(held.as_ref(), qtype);
    let (hit, count) = allocations(|| cache.get(held.as_ref(), qtype));
    assert_eq!(hit.expect("a hit").len(), 3);
    // One per record's owner and RDATA, and the `Vec` spine: the copy the
    // caller is handed. An eighth would be a folded lookup key.
    within("look one RRset up in the answer cache", count, 7..=7);

    let (miss, count) = allocations(|| cache.get(absent.as_ref(), qtype));
    assert!(miss.is_none());
    within("miss in the answer cache", count, 0..=0);

    // The denial cache is consulted before either of the others, so its miss is
    // the first thing a flood of random names reaches.
    let denials = rdns::nsec_cache::NsecCache::new(16);
    let _ = denials.synthesize(absent.as_ref(), qtype);
    let (miss, count) = allocations(|| denials.synthesize(absent.as_ref(), qtype));
    assert!(miss.is_none());
    within("miss in the denial cache", count, 0..=0);

    let negative = rdns::negative_cache::NegativeCache::new(1_000);
    let _ = negative.get(absent.as_ref(), qtype);
    let (miss, count) = allocations(|| negative.get(absent.as_ref(), qtype));
    assert!(miss.is_none());
    within("miss in the negative cache", count, 0..=0);

    // Mixed case folds into one buffer for the whole walk, not one per
    // ancestor.
    let shouted = nm("NOTHING.Example.COM.");
    let _ = negative.get(shouted.as_ref(), qtype);
    let (miss, count) = allocations(|| negative.get(shouted.as_ref(), qtype));
    assert!(miss.is_none());
    within(
        "miss in the negative cache, name in mixed case",
        count,
        1..=1,
    );
}

/// `verify_rrset` rebuilds the canonical form of the whole RRset per candidate
/// RRSIG, so an RRset signed by both a KSK and a ZSK can do all of it twice.
fn verifying_an_rrset_against_two_candidate_signatures() {
    let signed = signed_zone();

    let owned = |name: &str, rtype: Rtype| -> Vec<ResourceRecord> {
        signed
            .query(nm(name).as_ref(), Qtype::of(rtype))
            .into_iter()
            .map(|r| ResourceRecord {
                name: r.name.to_owned(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.to_owned(),
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
    let apex = nm("example.com.");
    let rrset = Rrset::new(apex.as_ref(), record_types::DNSKEY, Class::IN, &rdatas);
    let now = current_unix_timestamp();

    let (proof, count) =
        allocations(|| verify_rrset(&rrset, &rrsigs, &dnskeys, nm("example.com.").as_ref(), now));
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
