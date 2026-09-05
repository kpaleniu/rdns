//! The two failures that are about the network, and so about `tokio`.
//!
//! Split from [`rdns_core::error`] when the wire codec became its own crate:
//! `From<tokio::time::error::Elapsed>` can only be written where the error type
//! is defined, so these two types are what kept a `tokio` dependency in a crate
//! that is otherwise a parser (`TODO.md` #31). Everything else is core's, and
//! this module re-exports it — `rdns::error` is still the one import path
//! (`CLAUDE.md` §3).

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

/// A recursive resolution that did not produce an answer.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// Nobody answered, or nobody answered in time.
    #[error("{0}")]
    NoResponse(String),
    /// The delegation chain could not be followed — a lame server, a referral
    /// out of bailiwick, a loop.
    #[error("{0}")]
    Delegation(String),
    /// The query budget was spent. Its own variant because it is the
    /// NXNSAttack defence firing, which is an operational signal — a zone naming
    /// dozens of glueless nameservers — rather than a fault in the name being
    /// looked up, and an operator wants those counted separately from ordinary
    /// failures.
    #[error("the query budget was exhausted")]
    BudgetExhausted,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Dnssec(#[from] DnssecError),
}

impl ResolveError {
    pub fn no_response(detail: impl Into<String>) -> Self {
        ResolveError::NoResponse(detail.into())
    }
    pub fn delegation(detail: impl Into<String>) -> Self {
        ResolveError::Delegation(detail.into())
    }
}

/// A timeout *is* "nobody answered in time", which is what `NoResponse` says —
/// so the conversion is meaning-preserving rather than a convenience, and `?`
/// on a `tokio::time::timeout` reads correctly without a `map_err` at every
/// call site.
impl From<tokio::time::error::Elapsed> for ResolveError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        ResolveError::NoResponse("the query timed out".to_string())
    }
}

impl From<tokio::time::error::Elapsed> for TransferError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        TransferError::Timeout("the transfer timed out".to_string())
    }
}

/// Per-layer `Result` aliases for the two above, matching core's.
pub type TransferResult<T> = std::result::Result<T, TransferError>;
pub type ResolveResult<T> = std::result::Result<T, ResolveError>;
