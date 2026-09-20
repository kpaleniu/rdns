//! What one answer off `rdnsr`'s cache costs the allocator.
//!
//! `TODO.md` #88. Every allocation assertion in this tree lived in `rdns` and
//! measured the *authoritative* path; the resolver had none, so "the two
//! daemons build a reply two ways" was an observation nobody could price.
//!
//! **Why this is a module and not `rdnsr/tests/allocations.rs`.** `rdnsr` is a
//! binary, so a `tests/` file cannot reach [`crate::answer::handle_query`]
//! without a `lib.rs` and a handful of `pub`s — and `pub` in this tree has gone
//! 517 → 651 since #38's sweep with no ratchet behind it (#82b). `CLAUDE.md`
//! §10 asks for a separate file because a `#[global_allocator]` applies to the
//! whole binary, and that reason is answered rather than ignored: the count is
//! [`rdns::testutil::Counting`]'s **per-thread** tally, which is what
//! `rdns/tests/allocations.rs` had to invent anyway when its own separate file
//! turned out to be neither necessary nor sufficient. The allocator here is
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
use crate::testutil::{context, nm, TEST_PEER};

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
        class: rdns::Class::new(1),
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

/// One cache hit, from the datagram to the reply bytes.
///
/// Exact, and attributed rather than merely recorded: an exact count that is
/// not understood is worse than a timing, because it looks trustworthy
/// (`CLAUDE.md` §10). Two of the thirteen are the parse and three are the
/// serialization, which are the same two numbers `rdns/tests/allocations.rs`
/// asserts for the authoritative path, so **eight** are what the resolver does
/// in between: the cache lookup, the records copied out of it, and the reply
/// message they are assembled into.
///
/// That eight is #88's real answer, and it says **decline**. `rdnsd` writes its
/// answer straight into a held buffer with `ResponseWriter` — `rdns`'s
/// "write a one-record response" is **0**, and **3** with neither buffer nor
/// compressor in hand, which is what it pays per message on TCP. `rdnsr` clones
/// the records out of the cache into a `DnsMessage` and serializes that, for 3.
/// So the two shapes differ by the *cache lookup and the copy out of it*, not
/// by the writing, and the difference is a constant rather than a per-record
/// cost — which the ratio test below is the other half of. There is a number to
/// argue from now instead of a paragraph, and it does not argue for a rewrite.
///
/// What it does **not** measure: the resolution behind a miss, which is a
/// network round trip and not an allocation question.
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
        TEST_PEER,
        now,
        &serving,
        Transport::Udp,
    ));
    let bytes = warm.reply.expect("a cache hit is answered");
    let reply = DnsMessage::try_from_bytes(&bytes).expect("a well-formed reply");
    assert_eq!(reply.rcode, ResponseCode::Ok);
    assert_eq!(reply.answers.len(), 1, "the A record, out of the cache");

    // Built outside: the query bytes are the client's, not the server's cost.
    let wire = query_bytes(&name);
    let (answered, count) =
        allocations(|| rt.block_on(handle_query(wire, TEST_PEER, now, &serving, Transport::Udp)));
    assert!(answered.reply.is_some(), "still a cache hit");
    within("answer one query from the cache", count, 13..=13);

    // The two ends of it, priced separately so the total is attributed. Both
    // are `rdns`'s own numbers for the authoritative path, measured here
    // against the same message rather than quoted.
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
        8,
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
        allocations(|| rt.block_on(handle_query(wire, TEST_PEER, now, &serving, Transport::Udp))).1
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
