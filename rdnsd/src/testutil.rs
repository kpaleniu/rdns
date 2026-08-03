//! Message builders shared by more than one module's tests.
//!
//! **This exists because `query` was used by two test modules that now live in
//! two files** (`TODO.md` #20). The alternatives were both worse: duplicating it
//! is the thing this repo keeps finding and consolidating (`CLAUDE.md` §7), and
//! having `main`'s tests reach into `answer`'s test module would make the
//! dependency run the wrong way — `answer` is the leaf.
//!
//! Nothing here is compiled into a release build. Keep it to *builders*: a
//! helper that asserts, or that knows what a correct answer looks like, belongs
//! beside the tests that care, because that knowledge is what a reader is
//! checking.

use rdns::{DnsMessage, OpCode, Qtype, QueryClass, QuerySection, ResponseCode};

/// A query for `qname`/`qtype`, with DO set when `dnssec_ok`.
///
/// **The OPT record is always attached**, whatever `dnssec_ok` says — only the
/// DO bit moves. That is deliberate and was worth checking rather than
/// tidying: a caller passing `false` still gets an EDNS query, so every test
/// using this exercises the OPT-mirroring path in `make_response` (RFC 6891
/// §6.1.1). A version that attached the record only when DO was wanted would
/// look neater and would quietly stop testing that.
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
