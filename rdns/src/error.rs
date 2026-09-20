//! The failures that are not about the wire: a transfer, and DNSSEC.
//!
//! Split from [`rdns_core::error`] when the wire codec became its own crate
//! (`TODO.md` #31). Core keeps what a client linking core alone can raise; this
//! module holds the rest and re-exports core's, so `rdns::error` is still the
//! one import path (`CLAUDE.md` §3).
//!
//! `DnssecError` and `BrokenCatalog` arrived here on 2026-09-20 (`TODO.md` #86)
//! from core, where no module named them. `ZoneError` stayed: `rdns-present`
//! returns it and does not depend on `rdns`.
//!
//! **It no longer depends on `tokio`, and must not again** (`TODO.md` #67b).
//! `From<tokio::time::error::Elapsed>` can only be written where the error type
//! is defined, so two such impls held a runtime dependency in a module almost
//! every other one imports — which made 30 of 41 modules read as needing a
//! runtime. The `TransferError` one had no caller at all; the `ResolveError`
//! one moved to [`crate::resolver`], where the timeout is. `ResolveError` is
//! deliberately *not* re-exported here: a `pub use` would restore the edge.

use std::io;

pub use rdns_core::error::*;

/// A zone transfer, a NOTIFY, or the TSIG on either.
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    /// The peer refused, or answered something that is not a transfer.
    #[error("{0}")]
    Refused(String),
    /// The transfer arrived but does not assemble into a zone.
    #[error("{0}")]
    Malformed(String),
    /// A TSIG that is absent, unknown, or does not verify. Distinct because it
    /// is the one failure here that means "this peer is not who it says".
    #[error("TSIG: {0}")]
    Tsig(String),
    /// The peer did not answer in time. Its own variant because it is the one
    /// failure a secondary should simply retry on its RETRY timer rather than
    /// treat as a reason to give up on the master.
    #[error("{0}")]
    Timeout(String),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Zone(#[from] ZoneError),
    #[error(transparent)]
    Config(#[from] ConfigError),
}

impl TransferError {
    pub fn refused(detail: impl Into<String>) -> Self {
        TransferError::Refused(detail.into())
    }
    pub fn malformed(detail: impl Into<String>) -> Self {
        TransferError::Malformed(detail.into())
    }
    pub fn tsig(detail: impl Into<String>) -> Self {
        TransferError::Tsig(detail.into())
    }
    pub fn timeout(detail: impl Into<String>) -> Self {
        TransferError::Timeout(detail.into())
    }
}

/// A signature, key, or proof that does not hold.
///
/// `Bogus` is kept distinct from every other variant on purpose: it means the
/// data is *authenticated as wrong*, which for a resolver is SERVFAIL and never
/// a fallback to serving it unvalidated. The rest are reasons validation could
/// not be completed, which is a different answer.
#[derive(Debug, thiserror::Error)]
pub enum DnssecError {
    /// A signature did not verify, a digest did not match, a proof does not
    /// prove what it was offered for.
    #[error("{0}")]
    Bogus(String),
    /// A key, digest or signature algorithm this build does not implement.
    /// Reads as *insecure*, not bogus: a zone signing itself with something we
    /// cannot check is not evidence of an attack.
    #[error("{what} algorithm {algorithm} is not supported")]
    UnsupportedAlgorithm { what: &'static str, algorithm: u8 },
    /// A key that will not load or will not sign — a bad private key file, a
    /// key published at the wrong owner name, a generator that failed.
    #[error("{0}")]
    Key(String),
    /// The zone could not be signed at all.
    #[error("{0}")]
    Signing(String),
    /// Presentation-format text that will not read: a DS record, a trust anchor
    /// file, the DER inside a key file. Distinct from `Bogus` because nothing
    /// has been checked yet — this is input we could not get as far as judging.
    #[error("{0}")]
    Parse(String),
    /// The records themselves do not decode.
    #[error(transparent)]
    Wire(#[from] WireError),
}

impl DnssecError {
    pub fn bogus(detail: impl Into<String>) -> Self {
        DnssecError::Bogus(detail.into())
    }
    pub fn key(detail: impl Into<String>) -> Self {
        DnssecError::Key(detail.into())
    }
    pub fn signing(detail: impl Into<String>) -> Self {
        DnssecError::Signing(detail.into())
    }
    pub fn parse(detail: impl Into<String>) -> Self {
        DnssecError::Parse(detail.into())
    }
}

/// A zone that is not the catalog zone it was configured as (RFC 9432).
///
/// The variants are the RFC's own list of what makes a catalog "broken" — §4.1
/// for the member nodes, §4.2.1 for the version property, §4.3.1 for `coo` —
/// and no consumer branches on them: §5.1 gives one answer for all of them,
/// which is to keep the membership already in force and say so. They are
/// separate anyway because the operator has to fix a specific record, and
/// because a test asserting on the variant is a test that survives rewording
/// (`CLAUDE.md` §3).
///
/// Not a reason to reject the *zone*: §5.1 says a name server "MAY allow
/// loading and transfer of broken zones with incorrect catalog zone syntax (as
/// they are treated as regular zones)", so this describes the catalog reading
/// and nothing else.
#[derive(Debug, thiserror::Error)]
pub enum BrokenCatalog {
    #[error(
        "there is no version.$CATZ TXT record, so this is not a catalog zone (RFC 9432 §4.2.1)"
    )]
    NoVersion,
    #[error("the version.$CATZ TXT RRset holds {0} records, not one (RFC 9432 §4.2.1)")]
    VersionRrset(usize),
    #[error("catalog schema version {0:?} is not implemented; this build reads version 2 (RFC 9432 §4.2.1)")]
    Version(String),
    #[error("the member node {node} holds {records} PTR records, not one (RFC 9432 §4.1)")]
    MemberRrset { node: crate::Name, records: usize },
    #[error("{first} and {second} both name the member zone {zone} (RFC 9432 §4.1)")]
    DuplicateMember {
        zone: crate::Name,
        first: crate::Name,
        second: crate::Name,
    },
    #[error("the coo property at {node} holds {records} PTR records, not one (RFC 9432 §4.3.1)")]
    CooRrset { node: crate::Name, records: usize },
    /// A property RR of the right type whose RDATA does not decode — §4.2's
    /// "known properties that have the correct RR type but are for some reason
    /// invalid".
    #[error("the record at {name} does not decode: {source}")]
    Undecodable {
        name: crate::Name,
        #[source]
        source: WireError,
    },
}

/// Per-layer `Result` aliases, matching core's. `ResolveResult` is
/// `crate::resolver`'s, with the type it names (`TODO.md` #67b).
pub type TransferResult<T> = std::result::Result<T, TransferError>;
pub type DnssecResult<T> = std::result::Result<T, DnssecError>;
