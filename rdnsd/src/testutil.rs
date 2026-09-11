//! Message builders and a scratch directory, shared by more than one module's
//! tests.
//!
//! Builders only. A helper that asserts, or that knows what a correct answer
//! looks like, belongs beside the tests that care — that knowledge is what a
//! reader is checking.
//!
//! `rdns` has its own `ScratchDir`, identical: a `#[cfg(test)]` item is
//! invisible to another crate, which is the whole of `TODO.md` #38e. One copy
//! per crate is the floor without a `testkit` feature.

use rdns::metrics::DnsMetrics;
use rdns::{DnsMessage, DnsMessageBuilder, Qtype};

use crate::answer::write_response;
use crate::zones::Zones;
use crate::Scratch;

/// The answer to `msg`, read back off the wire.
///
/// `write_response` writes bytes, so a test that wants to look at sections has
/// to parse them — which is the right way round: our serializer agreeing with
/// our own record structs proves nothing, and this puts the reader between the
/// two (`CLAUDE.md` §1). `u16::MAX` because nothing here is about truncation;
/// the tests that are pass their own limit.
pub(crate) fn make_response(msg: &DnsMessage, zones: &Zones, metrics: &DnsMetrics) -> DnsMessage {
    let mut scratch = Scratch::default();
    write_response(
        msg,
        zones,
        metrics,
        u16::MAX as usize,
        rdns::UdpSizes::default().advertised(),
        &mut scratch,
    )
    .expect("the response serializes");
    DnsMessage::try_from_bytes(&scratch.out).expect("and parses back")
}

/// A query for `qname`/`qtype`, with DO set when `dnssec_ok`.
///
/// The OPT record is always attached; only the DO bit moves. Attaching it only
/// for DO would look neater and would stop every caller from exercising
/// `make_response`'s OPT mirroring (RFC 6891 §6.1.1).
/// A name from a literal, for tests only: `Name` is fallible to build and a
/// test that writes a bad one should fail loudly at that line.
pub(crate) fn nm(text: &str) -> rdns::Name {
    text.parse().expect("a test name parses")
}

/// The key the served-zone maps use: the folded wire form of the origin, which
/// is what `zones::zone_key` builds.
pub(crate) fn zkey(text: &str) -> Vec<u8> {
    nm(text).as_ref().folded().into_owned()
}

pub(crate) fn query(qname: &str, qtype: Qtype, dnssec_ok: bool) -> DnsMessage {
    DnsMessageBuilder::new()
        .with_id(1)
        .with_query(nm(qname), qtype)
        .with_recursion(false)
        .with_edns(4096, dnssec_ok)
        .build()
}

/// A directory under `TEMP`, removed when it goes out of scope.
///
/// `main.rs` had this inside its own `mod tests`, where `control.rs` and
/// `zones.rs` could not reach it and wrote the half that creates a directory
/// without the half that removes it.
pub(crate) struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    pub(crate) fn new(tag: &str) -> ScratchDir {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("rdnsd-{tag}-{unique}"));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        ScratchDir(dir)
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.0
    }

    /// A path inside it. Nothing is created.
    pub(crate) fn join(&self, name: impl AsRef<std::path::Path>) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
