//! Allocation counts for the paths that matter, as exact assertions.
//!
//! **Why this is a separate test binary.** DHAT works by replacing the global
//! allocator, and a `#[global_allocator]` applies to a whole binary — putting it
//! in `rdns`'s unit tests would make all 593 of them record a backtrace per
//! allocation. Here it costs only the handful of tests in this file.
//!
//! **Why counts rather than timings.** An allocation count is exact and does not
//! care what else is running on the machine. `bench.rs`'s wall-clock floors do,
//! which is how the `log_query` quadratic survived being caught: the floor was
//! lowered and the regression was blamed on competing load. See `CLAUDE.md` §10.
//!
//! **What a number here means.** It is a measurement, not a target. A count that
//! moves is a change in what the code allocates, which is worth a look and is
//! sometimes entirely correct — the assertions are ranges where the thing
//! measured has a degree of freedom (a `HashMap` growing differently) and exact
//! where it does not. Update them *with* the reason, the same way a benchmark
//! floor is (§10).
//!
//! **Why this file is one `#[test]`.** Because the profiler is global and the
//! *test harness* is not something a mutex in this file can serialize. The
//! measurements used to be a `#[test]` each, holding a mutex for the whole of
//! every body so that no two bodies could overlap — and that much was true: two
//! overlapping bodies would make `dhat::Profiler::builder().build()` panic
//! rather than mis-count, and it never panicked. What still overlapped was
//! libtest's own work on its other threads: the per-test bookkeeping that
//! happens *around* a body, outside anything this file can hold a lock across.
//! One measurement read 15 where it reads 7, on three runs out of five on Linux
//! and none observed on Windows, which is the worst way for a number to be
//! wrong. With one test there is one thread doing anything at all.
//!
//! So: **do not add a second `#[test]` here.** Add a function and call it from
//! [`allocation_counts`]. The cost of the arrangement is that the first failing
//! measurement hides the ones after it, which is a fair price for a count that
//! is exact on both platforms.

use rdns::Class;
use rdns::Rtype;
use std::sync::Mutex;

use rdns::dnssec::{dnskeys_in, rrsigs_in, verify_rrset, Rrset, RrsetProof};
use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::utils::{current_unix_timestamp, record_types};
use rdns::zone::{parse_zone_file, NameKind};
use rdns::zone_signer::{sign_zone, SigningPolicy};
use rdns::{
    DnsMessage, Edns, EdnsOption, OpCode, Qtype, QueryClass, QuerySection, ResourceRecord,
    ResponseCode,
};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Every measurement in this file, in one test — see the note at the top of it
/// for why that is not an accident.
#[test]
fn allocation_counts() {
    let _serial = exclusive();

    one_query_end_to_end();
    the_lookups_behind_one_answer_allocate_only_the_answer();
    reading_a_requests_edns_parameters_allocates_nothing();
    a_response_full_of_shared_suffixes();
    one_zone_load_and_sign();
    one_axfr_out();
    scanning_a_plain_query_for_a_tsig_allocates_nothing();
    comparing_two_names_allocates_nothing();
    verifying_an_rrset_against_two_candidate_signatures();
}

/// Belt to the braces of there being one test: two bodies must not overlap.
///
/// Only one `dhat::Profiler` may exist at a time — a second panics rather than
/// mis-counting — and the profiler is *global*, so an overlapping body's
/// allocations would land in whichever measurement was running. Guarding only
/// the measurement call and not the whole body gave 4 where the truth was 12 and
/// 208 where it was 1015, changing with `--test-threads`. An exact count that is
/// not actually exact is worse than a timing, because it looks trustworthy.
///
/// This no longer has anything to serialize against, since the harness runs one
/// test; it stays because it is what a second `#[test]` would collide with, and
/// a deadlock or a panic is a better outcome there than a wrong number.
///
/// Poisoning is ignored on purpose: a panic in one measurement must not turn
/// this into a second, confusing failure.
static PROFILER: Mutex<()> = Mutex::new(());

/// Take exclusive use of the profiler, and warm it up.
///
/// The warm-up is not decoration. The **first** profiled block in the process
/// picks up a one-off allocation from dhat's own lazily-initialized state, so
/// without it the first measurement reads one higher than the same measurement
/// anywhere else — a count that depends on ordering, which is precisely the kind
/// of not-quite-exact number this file exists to avoid.
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

/// Run `body` under a profiler and report how many allocations it made.
///
/// Call only while holding [`exclusive`].
fn allocations<T>(body: impl FnOnce() -> T) -> (T, u64) {
    let profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get().total_blocks;
    let out = body();
    let after = dhat::HeapStats::get().total_blocks;
    // Stats have to be read while the profiler is alive; dropping it ends
    // profiling, and `HeapStats::get` panics without one.
    drop(profiler);
    (out, after - before)
}

/// Assert a count is in `range`, printing the actual number either way so a
/// failure says what to change the range to and a pass leaves the figure in the
/// test log.
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

/// The same query as a real resolver sends it: EDNS0, DO set, and a DNS cookie
/// (RFC 7873), which BIND and Unbound both send by default. The cookie is the
/// point — an OPT record with no options parses into an empty `Vec`, which does
/// not allocate, so a query without one hides what reading the OPT costs.
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

/// The first thing #9e says to measure: one UDP query end to end, and how much
/// of it is response serialization.
///
/// Split into three so the answer is a breakdown rather than one number — the
/// point of measuring was never the total.
fn one_query_end_to_end() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let wire = query_bytes("www.example.com.", Qtype::of(record_types::A));

    let (parsed, parse_count) =
        allocations(|| DnsMessage::try_from_bytes(&wire).expect("parse the query"));
    // Three: the label vector the name is parsed into, the `String` it becomes,
    // and the vector of questions. It measured 4 until `DNameUnpacker` stopped
    // copying the labels of a name that has no compression pointer in it — and a
    // QNAME cannot have one, there being nothing before it to point at.
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
    // Four, and all four are the `ResourceRecord` this closure builds: the two
    // `Vec`s (`of_type`'s and the `collect`), the owner name it clones and the
    // rdata it clones. `Zone::query` itself contributes only the first of them.
    //
    // It measured 5 until `zone::absolutize` learned to borrow (#9e); the fifth
    // was the lookup key, a copy of a name that had arrived absolute and lower
    // case already. The range that used to be here was `1..=10`, which admitted
    // both numbers and so would not have noticed the fix — or its loss
    // (`CLAUDE.md` §10). Exact now, because nothing in the closure is
    // input-dependent or hash-ordered.
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
    // seen and the table of suffixes into it. Was 6, which was those three plus
    // a `Vec` of label offsets per name written (`compression::label_starts` is
    // an iterator now) and a second copy of a name already in the table.
    within("serialize a one-record response", serialize_count, 3..=3);
    assert!(bytes.len() < 100);

    // And the reason `to_bytes_within_buf` exists: a send path that keeps one
    // buffer pays nothing per response after the first. This is the assertion
    // that would have caught the 64 KiB scratch as a *count* rather than as a
    // capacity — and it is what a future "reuse the buffer in the UDP loop"
    // change gets to point at.
    let mut scratch = Vec::new();
    response
        .to_bytes_within_buf(4096, &mut scratch)
        .expect("warm the buffer");
    let ((), reused_count) = allocations(|| {
        response
            .to_bytes_within_buf(4096, &mut scratch)
            .expect("serialize into the warm buffer")
    });
    // The two the compressor makes, and nothing else: it is per-message state,
    // so unlike the buffer it cannot be carried across. Was 5.
    within("serialize into a reused buffer", reused_count, 2..=2);
    assert!(
        reused_count < serialize_count,
        "reusing the buffer must cost less than allocating one"
    );
}

/// The three lookups that stand between a question and an answer, measured
/// together — because the finding was not about any one of them.
///
/// `rdnsd` walks RFC 1034 §4.3.2 by asking the zone three questions (is there a
/// delegation above this name, does the name exist, what does it hold), and then
/// `add_answer` asks the third one again to render it. Each began by making the
/// lookup key with `zone::absolutize`, which returned an owned `String`
/// unconditionally — so four copies per query of a name that arrived absolute and
/// lower case and needed neither step. The DHAT profile put it at 4 allocations
/// of 16 bytes, ~14% of everything an answer allocated, and it was the largest
/// single item left on #9e.
///
/// One allocation now, and it is the answer itself: the `Vec` `Zone::query`
/// returns. Both walks are pure comparisons against the index — which is what
/// `Cow` plus `HashMap<String, _>::get` taking a `&str` buys, and what the number
/// here is a guard against losing again.
///
/// Against the old code this reads 5.
fn the_lookups_behind_one_answer_allocate_only_the_answer() {
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");

    // Once through before measuring, for the same reason the TSIG test below
    // does it: the first run of any path in a process pays for state that has
    // nothing to do with what is being counted, and a target this small cannot
    // absorb it.
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

/// What a server asks of a request's OPT record, and what asking used to cost.
///
/// Both daemons ask the same three questions — how big a reply may be, is this a
/// version we implement, does the client want DNSSEC — and `rdnsd` asked them
/// through `edns()` twice in sixteen lines. `edns()` builds the option list to
/// get at fields that are not in it: a `Vec` plus a `Vec<u8>` per option, built
/// and dropped. A resolver sending a DNS cookie therefore paid four allocations
/// per query for two flags, and that is what a resolver does — BIND and Unbound
/// both cookie by default.
///
/// The second measurement is the old cost, taken live rather than quoted, so the
/// comparison cannot go stale: `edns()` is still there for a caller that
/// actually wants the options.
fn reading_a_requests_edns_parameters_allocates_nothing() {
    let wire = query_bytes_with_edns("www.example.com.", Qtype::of(record_types::A));
    let msg = DnsMessage::try_from_bytes(&wire).expect("parse the query");

    // One call before the measured one, for the reason the TSIG test gives: a
    // target of exactly zero cannot absorb somebody else's one-off.
    let _warm = msg.edns_header();

    let (header, count) = allocations(|| msg.edns_header());
    let header = header
        .expect("the option list is well formed")
        .expect("OPT");
    assert!(header.do_bit, "the measurement is about a real DO query");
    assert_eq!(header.udp_payload_size, 1232);
    within("read a request's EDNS parameters", count, 0..=0);

    // Reaching the OPT record is now free — it is a field, not something to be
    // found in the additional section (`TODO.md` #13d).
    // Parsing the query in the first place, which is what a server does before
    // any of the above. **This measurement was added during review of #13**,
    // because nothing covered parsing an EDNS-bearing query and the OPT record's
    // move into its own field changed exactly that path — a gap the gate could
    // not see through, and it hid a regression for two commits.
    //
    // Measured against `main` with the same probe: **7 before #13, 8 after the
    // first version of `Additional::try_from_bytes` — which parsed the owner
    // name twice to peek at the TYPE — and 6 once the fields are read once and
    // branched on.** The extra one below `main` is the `RecordData` that an OPT
    // record no longer needs building on the way past, since it never becomes a
    // `ResourceRecord` at all.
    let (parsed, parse_count) = allocations(|| DnsMessage::try_from_bytes(&wire));
    assert!(parsed.expect("parses").edns().is_some(), "the OPT is there");
    within("parse a query that carries EDNS", parse_count, 6..=6);

    let (found, found_count) = allocations(|| msg.edns());
    let found = found.expect("OPT");
    within("reach the OPT record", found_count, 0..=0);

    // Building the option list is where the cost went, and it is only paid by a
    // caller that asks for the options. **This measurement moved**: it used to
    // call `edns()`, which parsed the list as part of reaching the record and so
    // read 2 here; `edns()` now allocates nothing and `options()` is the parse.
    // Same two allocations, charged to the call that actually wants them —
    // which is the point of the split, and the reason the number is unchanged
    // rather than lowered (`CLAUDE.md` §10).
    let (full, full_count) = allocations(|| found.options());
    assert_eq!(full.expect("well-formed").len(), 1, "one cookie");
    within(
        "and the same three fields through the full option parse",
        full_count,
        2..=2,
    );
}

/// A compressed name is the majority of response serialization by time, and #9e
/// claimed ~8 allocations per name before the arena. This is that claim as a
/// number, on a response holding several names that share suffixes.
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
    // Three names sharing `example.com.`, plus the question. The old compressor
    // allocated twice per suffix per name — a join and a lowercase — so this
    // shape cost upwards of twenty on its own; the arena took it to 11, and
    // dropping the per-name vector of label offsets takes it to 7. The range is
    // narrow rather than exact because the two compressor vectors grow with the
    // number of distinct names, and where they choose to reallocate is theirs.
    within("serialize four names sharing a suffix", count, 5..=10);
}

/// The second thing to measure: a full zone load and sign. Nobody had looked at
/// this one, and it runs on a worker that is also serving queries.
fn one_zone_load_and_sign() {
    let (zone, parse_count) = allocations(|| parse_zone_file(ZONE, "example.com.").expect("parse"));
    // Eight records. A per-record cost is expected and correct here — this is a
    // ceiling on how *much* per record, not a claim that it should be free.
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
    within("sign an eight-record zone", sign_count, 600..=1_400);
}

/// The third: an AXFR out. A transfer builds every record in the zone into
/// messages, so this is the one where a per-record allocation multiplies by the
/// zone size — and #9e says nobody had looked.
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
    // Nine records into one message: 41 before the compressor stopped allocating
    // a vector of label offsets per name and a second copy of every name it had
    // already seen, 19 after — the biggest proportional move of the four, because
    // a transfer is nothing but names.
    within("serialize one AXFR message", serialize_count, 14..=26);
}

/// Every packet the server receives is scanned for a TSIG record, and that scan
/// used to heap-allocate a four-element `Vec<usize>` for the section counts —
/// **before** the "is there an additional section at all" check, so it happened
/// for every query on every server, TSIG configured or not. One block per query
/// for four numbers whose count is known at compile time.
///
/// Found by the DHAT profile rather than by reading, which is the whole point of
/// #9e's first item: it was not on the hand-written list below it.
fn scanning_a_plain_query_for_a_tsig_allocates_nothing() {
    let wire = query_bytes("www.example.com.", Qtype::of(record_types::A));
    let keyring = rdns::tsig::TsigKeyring::new(Vec::new());

    // One call before the measured one. Whichever code path in the process runs
    // first pays for lazily-initialized state that has nothing to do with this
    // function, and a target of exactly zero cannot tolerate borrowing someone
    // else's one-off — it made this read 1 or 0 depending on which test the
    // scheduler happened to start first.
    let _warm = rdns::tsig::check_request(&wire, &keyring, 0);

    let (check, count) = allocations(|| rdns::tsig::check_request(&wire, &keyring, 0));
    assert!(
        matches!(check, rdns::tsig::TsigCheck::Unsigned),
        "a plain query carries no TSIG"
    );
    within("scan a TSIG-less query for a TSIG", count, 0..=0);
}

/// Comparing two names is a question about bytes, and should cost nothing.
///
/// `resolver::names_equal` was `normalize(a) == normalize(b)`, and `normalize`
/// is `to_ascii_lowercase` — which allocates whether or not there is anything to
/// fold — plus a `format!` when the trailing dot is missing. So every comparison
/// built two `String`s and dropped them, inside `.any()` loops over an answer
/// section. `utils::names_equal` strips at most one trailing dot from each side
/// and calls `eq_ignore_ascii_case`, which is the same RFC 4343 fold done in
/// place (`TODO.md` #13b).
///
/// The old shape is measured beside the new one on purpose: without it this is
/// an assertion that zero is zero, and §10 asks for the ratio rather than the
/// floor wherever one exists.
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

/// The fourth is "one recursive resolution with validation", which needs the
/// mock hierarchy that lives in `resolver.rs`'s private test module and cannot
/// be reached from an integration test. Measured here instead is the part of it
/// #9e already suspects: `verify_rrset` rebuilds the canonical form of the whole
/// RRset **per candidate RRSIG**, so an RRset signed by both a KSK and a ZSK
/// does all of it twice for an identical result.
///
/// This is the number that item gets to be judged against.
fn verifying_an_rrset_against_two_candidate_signatures() {
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
    let signed = sign_zone(
        &zone,
        &keys,
        &SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400),
    )
    .expect("sign");

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
