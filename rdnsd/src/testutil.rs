//! Message builders shared by more than one module's tests.
//!
//! Builders only. A helper that asserts, or that knows what a correct answer
//! looks like, belongs beside the tests that care — that knowledge is what a
//! reader is checking.

use rdns::compression::NameCompressor;
use rdns::metrics::DnsMetrics;
use rdns::{DnsMessage, DnsMessageBuilder, Qtype};

use crate::answer::write_response;
use crate::zones::Zones;

/// The answer to `msg`, read back off the wire.
///
/// `write_response` writes bytes, so a test that wants to look at sections has
/// to parse them — which is the right way round: our serializer agreeing with
/// our own record structs proves nothing, and this puts the reader between the
/// two (`CLAUDE.md` §1). `u16::MAX` because nothing here is about truncation;
/// the tests that are pass their own limit.
pub(crate) fn make_response(msg: &DnsMessage, zones: &Zones, metrics: &DnsMetrics) -> DnsMessage {
    let mut out = Vec::new();
    let mut compressor = NameCompressor::new();
    write_response(
        msg,
        zones,
        metrics,
        u16::MAX as usize,
        &mut out,
        &mut compressor,
        &mut String::new(),
    )
    .expect("the response serializes");
    DnsMessage::try_from_bytes(&out).expect("and parses back")
}

/// A query for `qname`/`qtype`, with DO set when `dnssec_ok`.
///
/// The OPT record is always attached; only the DO bit moves. Attaching it only
/// for DO would look neater and would stop every caller from exercising
/// `make_response`'s OPT mirroring (RFC 6891 §6.1.1).
pub(crate) fn query(qname: &str, qtype: Qtype, dnssec_ok: bool) -> DnsMessage {
    DnsMessageBuilder::new()
        .with_id(1)
        .with_query(qname, qtype)
        .with_recursion(false)
        .with_edns(4096, dnssec_ok)
        .build()
}
