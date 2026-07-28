//! The error types this library returns.
//!
//! **Typed, not `anyhow`, because this is a library.** An `anyhow::Error` is a
//! message: it tells a human what went wrong and tells a caller nothing it can
//! branch on. That is the right trade in a binary, where the only consumer is a
//! log line, and the wrong one here — a DNS server has to turn a failure into a
//! *response code*, and "the packet was truncated" and "the packet asked for
//! something we do not implement" are FORMERR and NOTIMP respectively. With a
//! string in hand there is nothing to match on and the choice cannot be made.
//! See `CLAUDE.md` for the convention.
//!
//! They live in one module rather than beside each of their callers because the
//! conversions between them are the interesting part — `DnssecError` wraps
//! `WireError` because verifying a signature means re-encoding records, and
//! `TransferError` wraps both — and a reader checking that those nest sensibly
//! should not have to open six files to do it.
//!
//! **Where a variant carries a `String`, that is deliberate and bounded.** The
//! structural ways a DNS message can be wrong are open-ended and mostly
//! one-off; enumerating all of them would produce a hundred variants nobody
//! matches on, while losing the text would make a malformed packet
//! undiagnosable. So the *category* is typed — which is what a caller branches
//! on — and the detail stays human-readable inside it.

use std::io;

/// A message, record, or name that does not decode.
///
/// The four variants are the four things a server does about it. `Truncated` and
/// `Malformed` are FORMERR; `Unsupported` is NOTIMP, because the encoding was
/// legal and we are the ones who fall short; `TooLong` is a limit deliberately
/// enforced, which is worth counting separately since it is what an attacker
/// probing for a parser bug produces.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The message ended before a field it had already declared.
    #[error("{what} needs {need} bytes, {have} remain")]
    Truncated {
        what: &'static str,
        need: usize,
        have: usize,
    },
    /// A field is longer than the protocol permits.
    #[error("{what} is {actual}, over the limit of {limit}")]
    TooLong {
        what: &'static str,
        limit: usize,
        actual: usize,
    },
    /// A legal encoding this codec does not implement — a binary label, say.
    /// The sender is not at fault, which is why it is not FORMERR.
    #[error("{what} is not supported")]
    Unsupported { what: &'static str },
    /// A structural rule of the encoding is broken.
    #[error("malformed {what}: {detail}")]
    Malformed { what: &'static str, detail: String },
}

impl WireError {
    /// Shorthand for the common case, so a call site stays one line.
    pub fn malformed(what: &'static str, detail: impl Into<String>) -> Self {
        WireError::Malformed {
            what,
            detail: detail.into(),
        }
    }
}

/// A label that is not UTF-8 is a malformed name, not a separate kind of
/// failure — DNS labels are byte strings, and this library only calls for text
/// where the protocol has already promised one (RFC 1035 §2.3.1).
impl From<std::str::Utf8Error> for WireError {
    fn from(source: std::str::Utf8Error) -> Self {
        WireError::malformed("a label", format!("not valid UTF-8: {source}"))
    }
}

/// A zone that will not load, or will not be written back out.
#[derive(Debug, thiserror::Error)]
pub enum ZoneError {
    /// A zone file line that does not parse. The line number is the whole
    /// value of this being typed: it is what an operator needs and what a
    /// stringly-typed error kept losing on its way up.
    #[error("line {line}: {detail}")]
    Syntax { line: usize, detail: String },
    /// The zone is syntactically fine and semantically impossible — a CNAME
    /// sharing its owner, a record outside the origin, no SOA at the apex.
    #[error("{0}")]
    Invalid(String),
    /// `$INCLUDE` nested past the depth limit, or a file that could not be read.
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    /// A record whose RDATA could not be encoded on the way out.
    #[error("writing {name}: {source}")]
    Encoding {
        name: String,
        #[source]
        source: WireError,
    },
}

impl ZoneError {
    /// A parse failure at a known line.
    ///
    /// The line number is a *field* rather than the first eight characters of a
    /// message, which is what lets `--check-config` (when it exists) group by
    /// file and sort by line without parsing its own error strings back.
    pub fn syntax(line: usize, detail: impl Into<String>) -> Self {
        ZoneError::Syntax {
            line,
            detail: detail.into(),
        }
    }

    /// A rule the zone breaks that has no single line to blame — a CNAME
    /// sharing its owner name is a fact about two records.
    pub fn invalid(detail: impl Into<String>) -> Self {
        ZoneError::Invalid(detail.into())
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

/// Operator-supplied text that does not parse: a `--secondary` spec, a TSIG key
/// spec, a CIDR in an ACL.
///
/// A struct rather than an enum, because there is genuinely one failure mode —
/// the operator wrote something the flag does not accept — and inventing
/// variants for it would be ceremony. It exists as a type at all so these
/// parsers compose with `?` and so that "bad configuration" is distinguishable
/// from "the network did something", which is the difference between exiting at
/// startup and retrying.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

impl ConfigError {
    pub fn new(detail: impl Into<String>) -> Self {
        ConfigError(detail.into())
    }
}

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

/// A fixed-width field read from a slice of the wrong length. The parser checks
/// lengths itself almost everywhere; this covers the few places that lean on
/// `try_into` for an address, where the slice length *is* the check.
impl From<std::array::TryFromSliceError> for WireError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        WireError::malformed("RDATA", "a fixed-width field has the wrong length")
    }
}

/// Per-layer `Result` aliases.
///
/// Each module uses the one for its own layer, so a signature reads
/// `Result<Zone>` rather than `Result<Zone, DnssecError>` — the same shape
/// `anyhow::Result` gave, without the erasure.
pub type WireResult<T> = std::result::Result<T, WireError>;
pub type ZoneResult<T> = std::result::Result<T, ZoneError>;
pub type DnssecResult<T> = std::result::Result<T, DnssecError>;
pub type TransferResult<T> = std::result::Result<T, TransferError>;
pub type ConfigResult<T> = std::result::Result<T, ConfigError>;
pub type ResolveResult<T> = std::result::Result<T, ResolveError>;

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
