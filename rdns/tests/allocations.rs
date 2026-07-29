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
//! sometimes entirely correct — the assertions are deliberately ranges wide
//! enough to survive a `HashMap` growing differently and narrow enough to catch
//! a per-record allocation appearing in a loop. Update them *with* the reason,
//! the same way a benchmark floor is (§10).

use std::sync::Mutex;

use rdns::dnssec::{dnskeys_in, rrsigs_in, verify_rrset, Rrset, RrsetProof};
use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
use rdns::utils::{current_unix_timestamp, record_types};
use rdns::zone::parse_zone_file;
use rdns::zone_signer::{sign_zone, SigningPolicy};
use rdns::{DnsMessage, OpCode, QueryClass, QuerySection, ResourceRecord, ResponseCode};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Serializes whole test bodies, not just the measurements.
///
/// Two reasons, and the second is the one that bites. Only one `dhat::Profiler`
/// may exist at a time — a second panics. But the profiler is *global*, so
/// while one test is measuring, every allocation made by every other test
/// thread is counted into its total as well. Guarding only the measurement gave
/// numbers that changed run to run and with `--test-threads`: 4 became 12, 208
/// became 1015. An exact count that is not actually exact is worse than a
/// timing, because it looks trustworthy.
///
/// Poisoning is ignored on purpose: a panic in one measurement must not turn
/// every other test in the file into a second, confusing failure.
static PROFILER: Mutex<()> = Mutex::new(());

/// Take exclusive use of the profiler for the whole of a test body. Every test
/// in this file must call this first.
///
/// The warm-up is not decoration. The **first** profiled block in the process
/// picks up a one-off allocation from dhat's own lazily-initialized state, so
/// without it the first measurement in whichever test happened to run first
/// reads one higher than the same measurement anywhere else — a count that
/// depends on test ordering, which is precisely the kind of not-quite-exact
/// number this file exists to avoid.
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

fn query_bytes(qname: &str, qtype: u16) -> Vec<u8> {
    let msg = DnsMessage {
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
    };
    msg.to_bytes_within(512).expect("serialize the query")
}

/// The first thing #9e says to measure: one UDP query end to end, and how much
/// of it is response serialization.
///
/// Split into three so the answer is a breakdown rather than one number — the
/// point of measuring was never the total.
#[test]
fn one_query_end_to_end() {
    let _serial = exclusive();
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let wire = query_bytes("www.example.com.", record_types::A);

    let (parsed, parse_count) =
        allocations(|| DnsMessage::try_from_bytes(&wire).expect("parse the query"));
    within("parse a one-question query", parse_count, 1..=8);

    let (answers, lookup_count) = allocations(|| {
        zone.query("www.example.com.", record_types::A)
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
    within("look up one A record in the zone", lookup_count, 1..=10);

    let mut response = parsed.clone();
    response.response = true;
    response.authoritive = true;
    response.answers = answers;

    let (bytes, serialize_count) = allocations(|| {
        response
            .to_bytes_within(4096)
            .expect("serialize the response")
    });
    within("serialize a one-record response", serialize_count, 1..=12);
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
    within("serialize into a reused buffer", reused_count, 0..=9);
    assert!(
        reused_count < serialize_count,
        "reusing the buffer must cost less than allocating one"
    );
}

/// A compressed name is the majority of response serialization by time, and #9e
/// claimed ~8 allocations per name before the arena. This is that claim as a
/// number, on a response holding several names that share suffixes.
#[test]
fn a_response_full_of_shared_suffixes() {
    let _serial = exclusive();
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let mut response =
        DnsMessage::try_from_bytes(&query_bytes("example.com.", record_types::ANY)).expect("parse");
    response.response = true;
    response.authoritive = true;
    for name in ["www.example.com.", "mx.example.com.", "ns1.example.com."] {
        for record in zone.query(name, record_types::A) {
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
    // shape cost upwards of twenty on its own.
    within("serialize four names sharing a suffix", count, 4..=20);
}

/// The second thing to measure: a full zone load and sign. Nobody had looked at
/// this one, and it runs on a worker that is also serving queries.
#[test]
fn one_zone_load_and_sign() {
    let _serial = exclusive();
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
#[test]
fn one_axfr_out() {
    let _serial = exclusive();
    let zone = parse_zone_file(ZONE, "example.com.").expect("parse");
    let request = DnsMessage::try_from_bytes(&query_bytes("example.com.", record_types::AXFR))
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
    within("serialize one AXFR message", serialize_count, 15..=80);
}

/// Every packet the server receives is scanned for a TSIG record, and that scan
/// used to heap-allocate a four-element `Vec<usize>` for the section counts —
/// **before** the "is there an additional section at all" check, so it happened
/// for every query on every server, TSIG configured or not. One block per query
/// for four numbers whose count is known at compile time.
///
/// Found by the DHAT profile rather than by reading, which is the whole point of
/// #9e's first item: it was not on the hand-written list below it.
#[test]
fn scanning_a_plain_query_for_a_tsig_allocates_nothing() {
    let _serial = exclusive();
    let wire = query_bytes("www.example.com.", record_types::A);
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

/// The fourth is "one recursive resolution with validation", which needs the
/// mock hierarchy that lives in `resolver.rs`'s private test module and cannot
/// be reached from an integration test. Measured here instead is the part of it
/// #9e already suspects: `verify_rrset` rebuilds the canonical form of the whole
/// RRset **per candidate RRSIG**, so an RRset signed by both a KSK and a ZSK
/// does all of it twice for an identical result.
///
/// This is the number that item gets to be judged against.
#[test]
fn verifying_an_rrset_against_two_candidate_signatures() {
    let _serial = exclusive();
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

    let owned = |name: &str, rtype: u16| -> Vec<ResourceRecord> {
        signed
            .query(name, rtype)
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
    let rrset = Rrset::new("example.com.", record_types::DNSKEY, 1, &rdatas);
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
