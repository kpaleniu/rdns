//! What an upstream's 0x20 scramble does to the bytes a client reads
//! (`TODO.md` #93).
//!
//! `rdnsr` sends a case-randomized QNAME (RFC 5452 §9.1), an authoritative
//! server copies it into the answer's owner name, and `rdnsr` caches that
//! answer verbatim. #93 was filed on the reading that the scramble is therefore
//! what every later client is served. It is not, and the reason is name
//! compression rather than anything the resolver does.
//!
//! The question section is written first, in the client's own case, and
//! `NameCompressor::lookup` compares case-insensitively (RFC 4343) — so an
//! owner name equal to the QNAME is emitted as a pointer to the question, and
//! the client reads back exactly what it asked. Only labels the client did not
//! supply carry the upstream's case, and those belong to the zone that
//! published them, which is the one thing #93 said must not be rewritten.
//!
//! Unbound, the implementation that ships 0x20, ends up in the same place by
//! the same route: `dname_lab_cmp` folds with `tolower` and the question's
//! qname is the first entry in its compression tree. BIND ships no 0x20 at all,
//! and renders with `DNS_COMPRESS_CASE` — case-*sensitive* compression — unless
//! a client matches its `no-case-compress` ACL.
//!
//! A test rather than a note because the property rests on two things that
//! could move independently: the question being written before the answers, and
//! the compressor folding.

use rdns::record_types as rt;
use rdns::{
    Class, DnsMessage, Name, OpCode, Qtype, QueryClass, QuerySection, RecordData, ResourceRecord,
    ResponseCode, Ttl,
};

fn a_record(owner: &str, last: u8) -> ResourceRecord {
    ResourceRecord {
        name: owner.parse().expect("a name"),
        class: Class::new(1),
        ttl: Ttl::from_secs(300),
        rdata: RecordData::new(rt::A, vec![10, 0, 0, last]).expect("an A"),
    }
}

/// The answer a cache holds after one 0x20 resolution, rendered for a client
/// that asked in lower case.
fn served(question: &str, answers: Vec<ResourceRecord>) -> (Vec<u8>, DnsMessage) {
    let qname: Name = question.parse().expect("a name");
    let msg = DnsMessage {
        id: 0x4242,
        response: true,
        opcode: OpCode::Query,
        authoritive: false,
        truncation: false,
        recursion: true,
        recursion_ok: true,
        ad: false,
        cd: false,
        rcode: ResponseCode::Ok,
        queries: vec![QuerySection {
            qname,
            qtype: Qtype::of(rt::A),
            qclass: QueryClass::IN,
        }],
        answers,
        authorities: vec![],
        additionals: vec![],
        edns: None,
    };
    let mut buf = vec![0u8; 512];
    let n = msg.to_bytes(&mut buf).expect("serializes");
    buf.truncate(n);
    let parsed = DnsMessage::try_from_bytes(&buf).expect("parses");
    (buf, parsed)
}

/// An owner name equal to the QNAME never reaches the wire at all: it is two
/// bytes of pointer at the question.
#[test]
fn a_scrambled_owner_name_is_a_pointer_to_the_clients_question() {
    let (wire, parsed) = served("example.com.", vec![a_record("EXaMPLe.cOm.", 5)]);

    // 12 bytes of header, then `example.com.` in the client's case.
    assert_eq!(&wire[12..25], b"\x07example\x03com\x00");
    // Then the answer's owner: `c0 0c`, a pointer to offset 12.
    assert_eq!(
        &wire[25..29],
        b"\x00\x01\x00\x01",
        "the question's type and class"
    );
    assert_eq!(&wire[29..31], b"\xc0\x0c", "the owner name compressed away");

    assert_eq!(
        parsed.answers[0].name.to_string(),
        "example.com.",
        "the client reads back the case it asked in"
    );
    assert!(
        !wire.windows(2).any(|w| w == b"EX"),
        "no part of the upstream's scramble is on the wire"
    );
}

/// A label the client did not supply does carry the upstream's case — and only
/// that label, because the shared tail compresses against the question.
#[test]
fn only_labels_the_client_did_not_send_keep_the_upstreams_case() {
    let (wire, parsed) = served(
        "example.com.",
        vec![a_record("EXaMPLe.cOm.", 5), a_record("WwW.eXaMpLe.CoM.", 6)],
    );

    assert_eq!(
        parsed.answers[1].name.to_string(),
        "WwW.example.com.",
        "one label from the upstream, the rest from the client's question"
    );
    // `03 W w W` then a pointer — four bytes of upstream case, not twelve.
    let owner = wire
        .windows(6)
        .find(|w| w.starts_with(b"\x03WwW"))
        .expect("the third label is written out");
    assert_eq!(&owner[4..6], b"\xc0\x0c", "and the tail is the question");
}
