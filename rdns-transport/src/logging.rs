//! Where this process's log lines go.
//!
//! Not `rdns::logging`, which is the counting a log line is drawn from and is
//! library code. Installing a subscriber is a process-global decision, so it
//! belongs to whoever *is* the process: the workspace manifest says it on the
//! `tracing` entry — "the library only emits; the binaries choose where it
//! goes" — so no subscriber is installed in `rdns`.
//!
//! Here rather than twice, once per binary, for the reason in this crate's
//! header: the two daemons are its only consumers, and two copies of a level
//! table drift (`CLAUDE.md` §7).

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

/// How much a daemon says.
///
/// The level stops the work: `tracing` builds a macro's arguments only when a
/// subscriber wants them. Volume beyond that is journald's job
/// (`LogRateLimitIntervalSec`).
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

/// Send log lines to stderr at `level`, honouring `RUST_LOG`, or to `file`
/// (`--log-file`); called once, by a binary.
///
/// `RUST_LOG` wins where set: editing a unit file is a restart. No timestamps
/// or ANSI on stderr, which journald stamps; a file gets a UTC timestamp per
/// line. A file that cannot be opened is an error (`CLAUDE.md` §4).
pub fn init(level: LogLevel, file: Option<&Path>) -> std::io::Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.as_str()));

    // `try_init`: a second call is a caller bug, not grounds for panicking a
    // healthy server, and the tests here share a process.
    match file {
        None => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .without_time()
                .with_target(true)
                .try_init();
        }
        Some(path) => {
            let log = Arc::new(LogFile::open(path)?);
            let _ = LOG_FILE.set(log.clone());
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(Shared(log))
                .with_ansi(false)
                .with_target(true)
                .try_init();
        }
    }
    Ok(())
}

/// Reopen the log file at its path, so a rotation that moved the old one
/// away is followed (`TODO.md` #190). What every reload calls; nothing
/// without `--log-file`. A failure keeps writing to the file already open and
/// says so there.
pub fn reopen() {
    if let Some(log) = LOG_FILE.get() {
        if let Err(e) = log.reopen() {
            tracing::error!(
                "could not reopen {}: {e}; still writing to the file already open",
                log.path.display()
            );
        }
    }
}

/// Whether log lines go to a file rather than standard error.
pub fn to_file() -> bool {
    LOG_FILE.get().is_some()
}

static LOG_FILE: OnceLock<Arc<LogFile>> = OnceLock::new();

/// The log file and the path it is reopened from.
struct LogFile {
    path: PathBuf,
    file: Mutex<File>,
}

impl LogFile {
    fn open(path: &Path) -> std::io::Result<LogFile> {
        Ok(LogFile {
            path: path.to_path_buf(),
            file: Mutex::new(append(path)?),
        })
    }

    fn reopen(&self) -> std::io::Result<()> {
        let fresh = append(&self.path)?;
        *self.file.lock().unwrap_or_else(PoisonError::into_inner) = fresh;
        Ok(())
    }
}

fn append(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| std::io::Error::new(e.kind(), format!("--log-file {}: {e}", path.display())))
}

/// One event's worth of the file, locked for the line.
pub struct LogLine<'a>(MutexGuard<'a, File>);

impl Write for LogLine<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// The file as the subscriber holds it, shared with [`reopen`].
struct Shared(Arc<LogFile>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Shared {
    type Writer = LogLine<'a>;

    fn make_writer(&'a self) -> LogLine<'a> {
        self.0.make_writer()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogFile {
    type Writer = LogLine<'a>;

    fn make_writer(&'a self) -> LogLine<'a> {
        // A poisoned lock is a panic mid-line in another thread; the file is
        // still a file, and losing the log is worse than one torn line.
        LogLine(self.file.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::fmt::MakeWriter;

    /// Appended, and followed to a new file once the old one is moved away
    /// and `reopen` runs — what a rotation does.
    #[test]
    fn a_log_file_is_appended_and_reopened_after_a_move() {
        let dir = std::env::temp_dir().join(format!("rdns-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("rdnsd.log");
        let moved = dir.join("rdnsd.log.1");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&moved);
        let log = LogFile::open(&path).expect("opens");
        log.make_writer().write_all(b"first\n").expect("write");
        std::fs::rename(&path, &moved).expect("rotate");
        log.make_writer()
            .write_all(b"still the old file\n")
            .expect("write");
        log.reopen().expect("reopens");
        log.make_writer().write_all(b"second\n").expect("write");
        assert_eq!(
            std::fs::read_to_string(&moved).expect("read"),
            "first\nstill the old file\n"
        );
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "second\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
