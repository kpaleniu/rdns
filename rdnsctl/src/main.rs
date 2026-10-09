//! `rdnsctl` — ask a running `rdnsd` or `rdnsr` what it is doing, and tell it
//! to reload.
//!
//! One connect, one command, one reply, then close ([`rdns_core::control`]). Nothing
//! to overlap, so `std` rather than `tokio`.
//!
//! A Unix socket, or on Windows a named pipe.

// `TODO.md` #82b's ratchet; the reason is at the top of `rdns/src/lib.rs`.
#![warn(unreachable_pub)]
// `push_str(&format!(..))` allocates a `String` to copy it; `write!` into the
// target does not. Off by default (restriction group).
#![warn(clippy::format_push_string)]

use clap::Parser;

/// `/run` rather than `/var/run` (its symlink) or `/tmp`: tmpfs, cleared on
/// boot so a stale socket cannot outlive a crash, and what a systemd unit's
/// `RuntimeDirectory=` creates with the service's own ownership.
#[cfg(unix)]
const DEFAULT_SOCKET: &str = "/run/rdns/rdnsd.sock";
#[cfg(windows)]
const DEFAULT_SOCKET: &str = r"\\.\pipe\rdnsd";

#[derive(Parser)]
#[command(version = rdns_core::VERSION, about, long_about = None)]
struct Cli {
    /// The control socket the server was started with (`--control-socket`).
    /// The default is `rdnsd`'s; `rdnsr`'s has to be named.
    #[arg(short, long, value_name = "PATH", default_value = DEFAULT_SOCKET)]
    socket: std::path::PathBuf,
    /// How long to wait for a reply, in seconds.
    ///
    /// Long because `reload` re-reads, signs and verifies every zone before
    /// answering, and the server bounds its own reply at 120 seconds.
    #[arg(short, long, value_name = "SECONDS", default_value = "150")]
    timeout: u64,
    /// What to ask. Each server has its own commands, and `help` lists them:
    /// this client does not, so it cannot fall behind either server
    /// (`TODO.md` #178).
    #[arg(value_name = "COMMAND", default_value = "status")]
    command: String,
    /// Arguments for the command, such as a name.
    #[arg(value_name = "ARG")]
    args: Vec<String>,
}

/// 0 the command worked, 1 the server refused it, 2 we could not ask. A script
/// retrying a `reload` must tell a config that needs fixing from a daemon that
/// needs starting.
const EXIT_REFUSED: i32 = 1;
const EXIT_UNREACHABLE: i32 = 2;

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            // `{e:#}` for the whole context chain; the outermost clause alone
            // is half the message.
            eprintln!("rdnsctl: {e:#}");
            std::process::ExitCode::from(EXIT_UNREACHABLE as u8)
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<std::process::ExitCode> {
    use rdns_core::control::{parse_reply, Reply, Request};
    use std::io::Write;

    let request = Request {
        command: cli.command.clone(),
        args: cli.args.clone(),
    };
    let reply = exchange(cli, &request.encode())?;

    match parse_reply(&reply) {
        Reply::Ok(body) => {
            // Unadorned: `rdnsctl dump example.com. > example.com.zone` has to
            // produce a zone file, not one with a status line in it.
            print!("{body}");
            std::io::stdout().flush().ok();
            Ok(std::process::ExitCode::SUCCESS)
        }
        Reply::Err(why) => {
            eprintln!("rdnsctl: {why}");
            Ok(std::process::ExitCode::from(EXIT_REFUSED as u8))
        }
    }
}

fn unreachable(cli: &Cli) -> String {
    format!(
        "connecting to {} — is the server running with --control-socket?",
        cli.socket.display()
    )
}

#[cfg(unix)]
fn exchange(cli: &Cli, request: &str) -> anyhow::Result<String> {
    use anyhow::Context;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut stream = UnixStream::connect(&cli.socket).with_context(|| unreachable(cli))?;
    let timeout = Some(Duration::from_secs(cli.timeout.max(1)));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;

    stream
        .write_all(request.as_bytes())
        .context("sending the command")?;
    // Half-close, so a server reading to end-of-line *or* to EOF sees the end
    // of the request either way rather than both ends waiting.
    stream.shutdown(std::net::Shutdown::Write).ok();

    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .context("reading the reply")?;
    Ok(reply)
}

/// The pipe opened as a file. A pipe has no half-close and `std` no read
/// timeout on a file, so the request ends at its newline and the exchange runs
/// on a thread the timeout abandons.
#[cfg(windows)]
fn exchange(cli: &Cli, request: &str) -> anyhow::Result<String> {
    use anyhow::Context;
    use std::io::{Read, Write};
    use std::time::Duration;

    /// ERROR_PIPE_BUSY: every instance is taken, which lasts only until the
    /// server creates the next one.
    const ERROR_PIPE_BUSY: i32 = 231;

    let mut tries = 0;
    let mut pipe = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cli.socket)
        {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < 50 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            opened => break opened.with_context(|| unreachable(cli))?,
        }
    };
    let request = request.to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = pipe
            .write_all(request.as_bytes())
            .context("sending the command")
            .and_then(|()| {
                let mut reply = String::new();
                pipe.read_to_string(&mut reply)
                    .context("reading the reply")
                    .map(|_| reply)
            });
        let _ = tx.send(result);
    });
    rx.recv_timeout(Duration::from_secs(cli.timeout.max(1)))
        .map_err(|_| anyhow::anyhow!("no reply within {} s", cli.timeout.max(1)))?
}
