//! The two failures that are about the network, and so about `tokio`.
//!
//! Split from [`rdns_core::error`] when the wire codec became its own crate:
//! `From<tokio::time::error::Elapsed>` can only be written where the error type
//! is defined, so these two types are what kept a `tokio` dependency in a crate
//! that is otherwise a parser (`TODO.md` #31). Everything else is core's, and
//! this module re-exports it — `rdns::error` is still the one import path
//! (`CLAUDE.md` §3).

use std::io;

use rdns_core::ede::InfoCode;
use rdns_core::ExtendedError;

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
    /// A [`crate::resolver::NameserverPolicy`] refused a delegation. Its own
    /// variant because it is not a failure: the caller that supplied the policy
    /// has an answer to send and the walk stopped so it could (`TODO.md` #56).
    #[error("a delegation was refused by policy")]
    PolicyStopped,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Dnssec(#[from] DnssecError),
}

impl ResolveError {
    /// What to tell the client about this failure (RFC 8914).
    ///
    /// Here rather than at the SERVFAIL that reports it, because the variant
    /// *is* the answer (`CLAUDE.md` §3) and a second reader would have to
    /// re-derive it from the message. The text is fixed and says nothing the
    /// client did not already send us — §2 asks that EXTRA-TEXT leak nothing —
    /// so the detail stays in the log line beside the counter.
    pub fn extended_error(&self) -> ExtendedError {
        match self {
            // §4.23: "could not reach any of the authoritative name servers (or
            // they potentially refused to reply)". A lame delegation is the
            // second half of that sentence.
            ResolveError::NoResponse(_) => {
                ExtendedError::new(InfoCode::NO_REACHABLE_AUTHORITY, "no authority answered")
            }
            ResolveError::Delegation(_) => ExtendedError::new(
                InfoCode::NO_REACHABLE_AUTHORITY,
                "the delegation chain could not be followed",
            ),
            // The NXNSAttack defence firing is this resolver's own limit, not
            // anything the registry has a name for.
            ResolveError::BudgetExhausted => {
                ExtendedError::new(InfoCode::OTHER, "the query budget was exhausted")
            }
            // §4.16 Blocked: "blocked for administrative reasons". Only read by
            // a caller that set a policy and then discarded what it recorded;
            // the rewrite carries its own code through `apply_policy`.
            ResolveError::PolicyStopped => ExtendedError::new(
                InfoCode::BLOCKED,
                "this answer is the resolver operator's policy",
            ),
            ResolveError::Io(_) => {
                ExtendedError::new(InfoCode::NETWORK_ERROR, "the upstream query failed")
            }
            ResolveError::Wire(_) => {
                ExtendedError::new(InfoCode::OTHER, "the upstream answer did not parse")
            }
            // A `DnssecError` reaching here is a key or a digest we could not
            // read rather than a chain that failed; the chain walk reports its
            // own code through `ValidationState::Bogus`.
            ResolveError::Dnssec(_) => {
                ExtendedError::new(InfoCode::DNSSEC_BOGUS, "this answer did not validate")
            }
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant maps to a code, and the ones an operator acts on
    /// differently map to different codes.
    ///
    /// The point of RFC 8914 here: "no authority answered" sends somebody to
    /// the delegation, "the query budget was exhausted" to a zone naming
    /// dozens of glueless nameservers, and a bare SERVFAIL to neither. The
    /// same distinction `ResolveError` already draws for the log line and the
    /// counter (`CLAUDE.md` §3), now visible on the wire.
    #[test]
    fn every_lookup_failure_has_a_code_a_client_can_act_on() {
        let cases = [
            (
                ResolveError::no_response("nothing came back"),
                InfoCode::NO_REACHABLE_AUTHORITY,
            ),
            (
                ResolveError::delegation("lame"),
                InfoCode::NO_REACHABLE_AUTHORITY,
            ),
            (ResolveError::BudgetExhausted, InfoCode::OTHER),
            (
                ResolveError::Io(io::Error::other("socket")),
                InfoCode::NETWORK_ERROR,
            ),
            (
                ResolveError::Wire(WireError::malformed("RDATA", "short")),
                InfoCode::OTHER,
            ),
            (
                ResolveError::Dnssec(DnssecError::bogus("no")),
                InfoCode::DNSSEC_BOGUS,
            ),
        ];
        for (error, expected) in &cases {
            assert_eq!(error.extended_error().info_code(), *expected, "{error}");
        }
        assert!(
            cases
                .iter()
                .any(|(_, code)| *code != InfoCode::NO_REACHABLE_AUTHORITY),
            "a mapping that is one code everywhere is a mapping nobody needed"
        );
    }
}
