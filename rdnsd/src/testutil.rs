//! Message builders shared by more than one module's tests.
//!
//! Builders only. A helper that asserts, or that knows what a correct answer
//! looks like, belongs beside the tests that care — that knowledge is what a
//! reader is checking.

use rdns::{DnsMessage, OpCode, Qtype, QueryClass, QuerySection, ResponseCode};

/// A query for `qname`/`qtype`, with DO set when `dnssec_ok`.
///
/// The OPT record is always attached; only the DO bit moves. Attaching it only
/// for DO would look neater and would stop every caller from exercising
/// `make_response`'s OPT mirroring (RFC 6891 §6.1.1).
pub(crate) fn query(qname: &str, qtype: Qtype, dnssec_ok: bool) -> DnsMessage {
    let mut msg = DnsMessage {
        id: 1,
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
    };
    let mut edns = rdns::Edns::with_payload_size(4096);
    edns.do_bit = dnssec_ok;
    msg.set_edns(edns);
    msg
}
