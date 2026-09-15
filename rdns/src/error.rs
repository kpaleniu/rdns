//! The one failure that is about a transfer rather than about the wire.
//!
//! Split from [`rdns_core::error`] when the wire codec became its own crate
//! (`TODO.md` #31). Everything else is core's, and this module re-exports it —
//! `rdns::error` is still the one import path (`CLAUDE.md` §3).
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

/// A per-layer `Result` alias, matching core's. `ResolveResult` is
/// `crate::resolver`'s, with the type it names (`TODO.md` #67b).
pub type TransferResult<T> = std::result::Result<T, TransferError>;
