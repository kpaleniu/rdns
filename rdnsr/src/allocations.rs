//! What one answer off `rdnsr`'s cache costs the allocator.
//!
//! `TODO.md` #88. The allocation assertions in `rdns` measure the
//! *authoritative* path; this prices "the two daemons build a reply two ways"
//! from the resolver's side.
//!
//! **Why this is a module and not `rdnsr/tests/allocations.rs`.** `rdnsr` is a
//! binary, so a `tests/` file cannot reach [`crate::answer::handle_query`]
//! without a `lib.rs` and a handful of `pub`s, and `pub` in this tree is what
//! the ratchet counts (`TODO.md` #82b). `CLAUDE.md` §10 asks for a separate
//! file because a `#[global_allocator]` applies to the whole binary, and that
//! reason is answered rather than ignored: the count is
//! [`rdns::testutil::Counting`]'s **per-thread** tally, which a separate file
//! needs anyway, being neither necessary nor sufficient. The allocator here is
//! `#[cfg(test)]` and wraps `System`, so it is a pass-through plus one
//! thread-local increment for the other tests in this binary, and no dhat: the
//! profiler is the global part, and nothing here reads peak bytes.
//!
//! ```sh
//! cargo test -p rdnsr allocation -- --nocapture
//! ```

use rdns::record_types;
use rdns::testutil::allocations;
use rdns::validation::Transport;
use rdns::{DnsMessage, Qtype, ResourceRecord, ResponseCode};

use crate::answer::handle_query;
use crate::testutil::{context, nm, test_peer};

/// Assert a count is in `range`, printing it either way so a failure says what
/// to change the range to. `rdns/tests/allocations.rs`'s, for the same reason.
#[track_caller]
fn within(what: &str, count: u64, range: std::ops::RangeInclusive<u64>) {
    println!("{what}: {count} allocations");
    assert!(
        range.contains(&count),
        "{what} made {count} allocations, expected {range:?} — if this is a \
         deliberate change, move the range and say why"
    );
}

fn a_record(name: &rdns::Name) -> ResourceRecord {
    ResourceRecord {
        name: name.clone(),
        class: rdns::Class::IN,
        ttl: rdns::Ttl::from_secs(300),
        rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(std::net::Ipv4Addr::new(
            192, 0, 2, 10,
        )))
        .expect("encodes"),
    }
}

fn query_bytes(name: &rdns::Name) -> Vec<u8> {
    rdns::DnsMessageBuilder::new()
        .with_id(0x2020)
        .with_query(name.clone(), Qtype::of(record_types::A))
        .with_recursion(true)
        .with_edns(1232, false)
        .build()
        .to_bytes_within(4096)
        .expect("serialize the query")
}

/// One cache hit, from the datagram to the reply bytes, attributed: two
/// allocations parse, three serialize, and seven are the lookup, the copy out
/// of the cache and the reply message (`CLAUDE.md` §10). The seven are a
/// constant, not a per-record cost, which is why `TODO.md` #88 declined a
/// rewrite. A miss's resolution is a round trip, not an allocation question.
#[test]
fn a_cached_answer_costs_what_it_costs() {
    let serving = context();
    let name = nm("www.example.com.");
    serving.caches.remember(
        name.as_ref(),
        Qtype::of(record_types::A),
        vec![a_record(&name)],
    );

    // Current-thread, so the future runs on this thread and its allocations are
    // this thread's tally. Built outside the window: a runtime is not a query.
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    let now = rdns::clock::current_unix_timestamp();

    // The first call in a process picks up one-off initialization
    // (`CLAUDE.md` §10), and it also fills the cache's own internals.
    let warm = rt.block_on(handle_query(
        query_bytes(&name),
        test_peer(),
        now,
        &serving,
        Transport::Udp,
    ));
    let bytes = warm.expect("a cache hit is answered");
    let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
    assert_eq!(reply.rcode, ResponseCode::Ok);
    assert_eq!(reply.answers.len(), 1, "the A record, out of the cache");

    // Built outside: the query bytes are the client's, not the server's cost.
    let wire = query_bytes(&name);
    let (answered, count) = allocations(|| {
        rt.block_on(handle_query(
            wire,
            test_peer(),
            now,
            &serving,
            Transport::Udp,
        ))
    });
    assert!(answered.is_some(), "still a cache hit");
    within("answer one query from the cache", count, 12..=12);

    // The two ends priced separately, measured here rather than quoted from
    // `rdns`.
    let wire = query_bytes(&name);
    let (parsed, parse_count) = allocations(|| {
        rdns::validation::Request::from_bytes(&wire).expect("the query is a question")
    });
    within("parse the query", parse_count, 2..=2);

    let mut response = (*parsed).clone();
    response.response = true;
    response.answers = vec![a_record(&name)];
    let (_, serialize_count) =
        allocations(|| response.to_bytes_within(4096).expect("serialize the reply"));
    within("serialize the reply", serialize_count, 3..=3);

    assert_eq!(
        count - parse_count - serialize_count,
        7,
        "the cache lookup, the records copied out of it, and the message they go into"
    );
}

/// The same answer, serialized twice, costs the same twice.
///
/// The one thing the count above cannot say on its own: whether anything on
/// this path is quadratic in how often it is asked, the way `log_query` was
/// (`CLAUDE.md` §10's ratio rule). A ratio, not a floor, so it is
/// machine-independent.
#[test]
fn serving_the_same_answer_costs_the_same_however_many_came_before() {
    let serving = context();
    let name = nm("www.example.com.");
    serving.caches.remember(
        name.as_ref(),
        Qtype::of(record_types::A),
        vec![a_record(&name)],
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    let now = rdns::clock::current_unix_timestamp();

    let ask = || {
        let wire = query_bytes(&name);
        allocations(|| {
            rt.block_on(handle_query(
                wire,
                test_peer(),
                now,
                &serving,
                Transport::Udp,
            ))
        })
        .1
    };

    let _ = ask();
    let first = ask();
    for _ in 0..200 {
        let _ = ask();
    }
    let later = ask();

    println!("cache hit: {first} allocations first, {later} after 200 more");
    assert_eq!(
        first, later,
        "serving a cached answer got dearer as the cache was asked more often"
    );
}
