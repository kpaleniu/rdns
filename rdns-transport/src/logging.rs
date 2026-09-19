//! Where this process's log lines go.
//!
//! Not `rdns::logging`, which is the counting a log line is drawn from and is
//! library code. Installing a subscriber is a process-global decision, so it
//! belongs to whoever *is* the process: the workspace manifest says it on the
//! `tracing` entry — "the library only emits; the binaries choose where it goes"
//! — and `rdns::logging::init` was the one place that did not hold
//! (`TODO.md` #85).
//!
//! Here rather than twice, once per binary, for the reason in this crate's
//! header: the two daemons are its only consumers, and two copies of a level
//! table drift (`CLAUDE.md` §7).

use std::str::FromStr;

/// How much a daemon says.
///
/// The level stops the work, not just the output: `tracing`'s macros only build
/// their arguments when a subscriber is interested, which is what keeps a
/// malformed-packet flood from costing a `format!` per packet.
///
/// Volume beyond that is journald's job (`LogRateLimitIntervalSec`,
/// `LogRateLimitBurst`); a second limiter here would hide what the first did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

impl FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "error" => Ok(LogLevel::Error),
            "warn" | "warning" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            other => Err(format!(
                "unknown log level {other:?}: expected error, warn, info, debug or trace"
            )),
        }
    }
}

/// Send this process's log lines to stderr at `level`, honouring `RUST_LOG`.
///
/// Called once, by a binary; library code only emits. Shared so that `rdnsd` and
/// `rdnsr` cannot end up configured differently.
///
/// `RUST_LOG` wins where it is set — reaching for it means a server misbehaving
/// under a level chosen in a unit file, and editing the unit is a restart.
/// `--quiet` and `--log-level` set the fallback.
///
/// No timestamps and no ANSI: journald stamps every line, and two stamps
/// disagreeing is worse than losing one in a terminal.
pub fn init(level: LogLevel) {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));

    // `try_init`: a second call is a caller bug, not grounds for panicking a
    // healthy server, and the tests here share a process.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .without_time()
        .with_target(true)
        .try_init();
}
