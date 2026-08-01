//! `rdnsctl` — ask a running `rdnsd` what it is doing, and tell it to reload.
//!
//! One connect, one command, one reply, and the connection closes. That is the
//! whole protocol ([`rdns::control`]), which is why this is `std` and not
//! `tokio`: there is nothing here to overlap.
//!
//! **A separate binary rather than a subcommand.** Every DNS server ships one —
//! `rndc`, `knotc`, `nsd-control`, `pdns_control`, `unbound-control` — and an
//! operator reaching for a control channel is reaching for a command, not for a
//! flag on the daemon. It also keeps the two apart on the box: this can be
//! installed where an admin's PATH is without the daemon being there.
//!
//! **Unix only**, because the socket is. On Windows it says so and exits 2
//! rather than not existing, so `cargo build --workspace` covers it and nobody
//! discovers the gap by finding the command missing.

use clap::Parser;

/// Where a control socket lives when nobody says otherwise.
///
/// `/run` rather than `/var/run` (its symlink) and rather than `/tmp`: it is
/// tmpfs, it is cleared on boot so a stale socket cannot survive a crash across
/// one, and a directory under it is what a systemd unit's `RuntimeDirectory=`
/// creates with the service's own ownership.
const DEFAULT_SOCKET: &str = "/run/rdns/rdnsd.sock";

#[derive(Parser)]
#[command(version = rdns::VERSION, about, long_about = None)]
struct Cli {
    /// The control socket `rdnsd` was started with (`--control-socket`).
    #[arg(short, long, value_name = "PATH", default_value = DEFAULT_SOCKET)]
    socket: std::path::PathBuf,
    /// How long to wait for a reply, in seconds.
    ///
    /// Longer than it sounds on purpose: `reload` re-reads, signs and verifies
    /// every zone before answering, and the server bounds its own reply at 120
    /// seconds. A shorter value here would time out on exactly the reload worth
    /// watching. Lower it for `status` on a server suspected of being wedged —
    /// the control socket is answered independently of the DNS path, so a hang
    /// there is a real symptom rather than load.
    #[arg(short, long, value_name = "SECONDS", default_value = "150")]
    timeout: u64,
    /// `status`, `reload`, `dump <zone>`, `version`, or `help`.
    #[arg(value_name = "COMMAND", default_value = "status")]
    command: String,
    /// Arguments for the command — a zone name, for `dump`.
    #[arg(value_name = "ARG")]
    args: Vec<String>,
}

/// 0 the command worked, 1 the server refused it, 2 we could not ask.
///
/// Three codes and not two, because a script retrying a `reload` needs to tell
/// "the server said no" from "there was no server": the first is a config that
/// needs fixing and the second is a daemon that needs starting.
#[cfg_attr(not(unix), allow(dead_code))]
const EXIT_REFUSED: i32 = 1;
const EXIT_UNREACHABLE: i32 = 2;

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            // `{e:#}` for the whole context chain: "connecting to /run/...: No
            // such file or directory" is the message, and the outermost clause
            // alone would be half of it.
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
    // of the request either way, and a bug on either side shows up as an error
    // rather than as both ends waiting for the other.
    stream.shutdown(std::net::Shutdown::Write).ok();

    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .context("reading the reply")?;

    match parse_reply(&reply) {
        Reply::Ok(body) => {
            // The body goes to stdout unchanged and unadorned: `rdnsctl dump
            // example.com. > example.com.zone` has to produce a zone file, not
            // a zone file with a status line in it.
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
