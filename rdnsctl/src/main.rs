//! `rdnsctl` — ask a running `rdnsd` what it is doing, and tell it to reload.
//!
//! One connect, one command, one reply, then close ([`rdns::control`]). Nothing
//! to overlap, so `std` rather than `tokio`.
//!
//! Unix only, because the socket is. On Windows it says so and exits 2 rather
//! than not existing, so `cargo build --workspace` still covers it.

use clap::Parser;

/// `/run` rather than `/var/run` (its symlink) or `/tmp`: tmpfs, cleared on
/// boot so a stale socket cannot outlive a crash, and what a systemd unit's
/// `RuntimeDirectory=` creates with the service's own ownership.
const DEFAULT_SOCKET: &str = "/run/rdns/rdnsd.sock";

#[derive(Parser)]
#[command(version = rdns::VERSION, about, long_about = None)]
struct Cli {
    /// The control socket `rdnsd` was started with (`--control-socket`).
    #[arg(short, long, value_name = "PATH", default_value = DEFAULT_SOCKET)]
    socket: std::path::PathBuf,
    /// How long to wait for a reply, in seconds.
    ///
    /// Long because `reload` re-reads, signs and verifies every zone before
    /// answering, and the server bounds its own reply at 120 seconds.
    #[arg(short, long, value_name = "SECONDS", default_value = "150")]
    timeout: u64,
    /// `status`, `reload`, `dump <zone>`, `version`, or `help`.
    #[arg(value_name = "COMMAND", default_value = "status")]
    command: String,
    /// Arguments for the command — a zone name, for `dump`.
    #[arg(value_name = "ARG")]
    args: Vec<String>,
}

/// 0 the command worked, 1 the server refused it, 2 we could not ask. A script
/// retrying a `reload` must tell a config that needs fixing from a daemon that
/// needs starting.
#[cfg_attr(not(unix), allow(dead_code))]
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

#[cfg(unix)]
fn run(cli: &Cli) -> anyhow::Result<std::process::ExitCode> {
    use anyhow::Context;
    use rdns::control::{parse_reply, Reply, Request};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let request = Request {
        command: cli.command.clone(),
        args: cli.args.clone(),
    };

    let mut stream = UnixStream::connect(&cli.socket).with_context(|| {
        format!(
            "connecting to {} — is rdnsd running with --control-socket?",
            cli.socket.display()
        )
    })?;
    let timeout = Some(Duration::from_secs(cli.timeout.max(1)));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;

    stream
        .write_all(request.encode().as_bytes())
        .context("sending the command")?;
    // Half-close, so a server reading to end-of-line *or* to EOF sees the end
    // of the request either way rather than both ends waiting.
    stream.shutdown(std::net::Shutdown::Write).ok();

    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .context("reading the reply")?;

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

#[cfg(not(unix))]
fn run(_cli: &Cli) -> anyhow::Result<std::process::ExitCode> {
    Err(anyhow::anyhow!(
        "the control socket is a Unix domain socket, which neither std nor \
         tokio exposes on Windows — rdnsd refuses --control-socket here for \
         the same reason"
    ))
}
