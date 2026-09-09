//! The error types this library returns.
//!
//! Typed, not `anyhow`: a server turns a failure into a response code, and
//! "truncated" and "not implemented" are FORMERR and NOTIMP. A `String` inside a
//! variant is deliberate where the category is the typed part — the structural
//! ways a message can be wrong are open-ended.

use std::io;

/// A message, record, or name that does not decode.
///
/// The variants are the four things a server does about it: `Truncated` and
/// `Malformed` are FORMERR, `Unsupported` is NOTIMP (the encoding was legal and
/// we fall short), `TooLong` is a limit we enforce and count.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("{what} needs {need} bytes, {have} remain")]
    Truncated {
        what: &'static str,
        need: usize,
        have: usize,
    },
    #[error("{what} is {actual}, over the limit of {limit}")]
    TooLong {
        what: &'static str,
        limit: usize,
        actual: usize,
    },
    /// A legal encoding this codec does not implement — a binary label, say.
    #[error("{what} is not supported")]
    Unsupported { what: &'static str },
    #[error("malformed {what}: {detail}")]
    Malformed { what: &'static str, detail: String },
}

impl WireError {
    pub fn malformed(what: &'static str, detail: impl Into<String>) -> Self {
        WireError::Malformed {
            what,
            detail: detail.into(),
        }
    }
}

/// Labels are byte strings; text is only asked for where the protocol promises
/// one (RFC 1035 §2.3.1), so a non-UTF-8 label is a malformed name.
impl From<std::str::Utf8Error> for WireError {
    fn from(source: std::str::Utf8Error) -> Self {
        WireError::malformed("a label", format!("not valid UTF-8: {source}"))
    }
}

/// A packet that arrived at a listening socket and is not a question.
///
/// Both are dropped; the distinction is the operational signal. `NotAQuestion`
/// means two servers pointed at each other, or a spoofed source naming one — an
/// operator chasing a traffic loop has to tell that from ordinary garbage. It is
/// not a `WireError` because the packet decoded perfectly and the server says
/// nothing at all; see [`crate::validation::Request`].
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("a response arrived at a listening socket")]
    NotAQuestion,
}

/// Why a reply is not an answer to the query that was sent.
///
/// RFC 5452 §9.1's list, minus the parts the socket already enforces: with a
/// `connect`ed socket the kernel checks both addresses and both ports, so what
/// is left for a caller is "Query ID", "Query name" and "Query class and type".
///
/// Every caller drops the packet, so the variants are for the operator, not for
/// branching: `rdnsc` prints the reason and the resolver counts a non-answer.
/// They stay separate anyway because a test asserts on the variant rather than
/// on a message (`CLAUDE.md` §3), and because "the id was wrong" and "the
/// question was somebody else's" are different things to see in a log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnswerMismatch {
    /// QR is clear. Not on RFC 5452's list, which assumes a response; a query
    /// echoed back is not an answer to it (RFC 1035 §4.1.1).
    #[error("QR is clear, so it is a query and not an answer")]
    NotAResponse,
    #[error("id {got:#06x} does not match the {want:#06x} we asked with")]
    Id { got: u16, want: u16 },
    #[error("no question section to compare")]
    NoQuestion,
    #[error("answers {got}, not the {want} we asked")]
    Question { got: String, want: String },
}

/// A zone that will not load, or will not be written back out.
#[derive(Debug, thiserror::Error)]
pub enum ZoneError {
    #[error("line {line}: {detail}")]
    Syntax { line: usize, detail: String },
    /// Syntactically fine and semantically impossible — a CNAME sharing its
    /// owner, a record outside the origin, no SOA at the apex.
    #[error("{0}")]
    Invalid(String),
    /// `$INCLUDE` nested past the depth limit, or a file that could not be read.
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("writing {name}: {source}")]
    Encoding {
        name: String,
        #[source]
        source: WireError,
    },
}

impl ZoneError {
    /// A parse failure at a known line. The line is a field rather than a prefix
    /// on the message, so a caller can group and sort without re-parsing text.
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
pub type RequestResult<T> = std::result::Result<T, RequestError>;
pub type DnssecResult<T> = std::result::Result<T, DnssecError>;
pub type ConfigResult<T> = std::result::Result<T, ConfigError>;
