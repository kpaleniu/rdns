//! Allocation counts for the paths that matter, as exact assertions.
//!
//! Its own test binary: `#[global_allocator]` applies to the whole binary.
//!
//! One `#[test]` only — add a function and call it from [`allocation_counts`].
//! The profiler is global and libtest's per-test bookkeeping runs on threads no
//! mutex here can hold, so as separate tests one measurement read 15 where it
//! reads 7. Assertions are ranges only where the thing measured has a degree of
//! freedom; update one with the reason, as a benchmark floor is updated.

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

/// Every measurement in this file, in one test; see the module header for why.
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

/// Run `body` under a profiler and report how many allocations it made.
///
/// Call only while holding [`exclusive`].
fn allocations<T>(body: impl FnOnce() -> T) -> (T, u64) {
    let profiler = dhat::Profiler::builder().testing().build();
    let before = dhat::HeapStats::get().total_blocks;
    let out = body();
    let after = dhat::HeapStats::get().total_blocks;
    // `HeapStats::get` panics without a live profiler.
    drop(profiler);
    (out, after - before)
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
    // The compressor's two and nothing else: per-message state, so unlike the
    // buffer it cannot be carried across.
    within("serialize into a reused buffer", reused_count, 2..=2);
    assert!(
        reused_count < serialize_count,
        "reusing the buffer must cost less than allocating one"
    );
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
fn scanning_a_plain_query_for_a_tsig_allocates_nothing() {
    let wire = query_bytes("www.example.com.", Qtype::of(record_types::A));
    let keyring = rdns::tsig::TsigKeyring::new(Vec::new());

    // Warm first: a target of exactly zero cannot absorb another path's
    // lazily-initialized state. This read 1 or 0 depending on scheduling.
    let _warm = rdns::tsig::check_request(&wire, &keyring, 0);

    let (check, count) = allocations(|| rdns::tsig::check_request(&wire, &keyring, 0));
    assert!(
        matches!(check, rdns::tsig::TsigCheck::Unsigned),
        "a plain query carries no TSIG"
    );
    within("scan a TSIG-less query for a TSIG", count, 0..=0);
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

/// `verify_rrset` rebuilds the canonical form of the whole RRset per candidate
/// RRSIG, so an RRset signed by both a KSK and a ZSK can do all of it twice.
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
