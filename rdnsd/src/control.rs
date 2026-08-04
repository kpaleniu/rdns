//! The control socket: what an operator asks a running `rdnsd` at 3am.
//!
//! Of the four questions under `TODO.md` #9d, one could be answered before this
//! existed. "Is example.com loaded, at what serial?" — query the SOA. "Is
//! broken.test loaded?" — REFUSED, which a zone that was never configured also
//! answers. "Is the secondary in sync?" — read the state sidecar by hand. "Why
//! did that reload not take effect?" — grep the log and hope the level was left
//! on. `status`, `reload` and `dump` answer all four, from the process that
//! knows.
//!
//! A Unix socket and no TCP; see [`rdns::control`] for the survey that settled
//! it. That is also why `reload` is not a `POST` on the metrics listener.
//!
//! Unix-only: `tokio` exposes no `UnixListener` on Windows (AF_UNIX exists there
//! since 10 1803, but neither `std` nor `tokio` exposes it), so this module is
//! `#[cfg(unix)]` and `--control-socket` is refused at startup rather than
//! accepted and ignored.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rdns::control::{err, ok, Request, MAX_REQUEST};
use rdns::metrics::ZoneFacts;
use rdns::shutdown::{Busy, Stop};
use rdns::utils::current_unix_timestamp;
use rdns::zone_writer::zone_to_string;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

use crate::{ReloadTrigger, Served};

/// How long a client gets to send its command before we give up on it.
///
/// The same reasoning as the metrics endpoint's: a connection that connected
/// and then said nothing is a stalled script or a mistake, and neither is worth
/// holding a socket for.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `reload` waits for the maintenance task to finish before answering
/// anyway.
///
/// A reload is a full parse and a full signing run over every zone, so seconds
/// is normal and this is not a timeout on the *work* — the reload carries on
/// regardless, exactly as a SIGHUP one would. It is a bound on how long a
/// person stares at a terminal before being told to read the log instead.
const RELOAD_REPORT_TIMEOUT: Duration = Duration::from_secs(120);

/// Everything a command needs to answer, gathered once so the handlers take one
/// argument rather than six (`CLAUDE.md` §14).
pub struct Control {
    pub served: Served,
    /// Zones this server replicates, so `status` can say which are secondary
    /// without inferring it from a timestamp that is also absent on a primary.
    pub replicated: Vec<String>,
    /// Where a `reload` request goes: the same loop SIGHUP and the re-signing
    /// timer feed, because three triggers for one operation must not be three
    /// implementations of it — two reloads running at once would install two
    /// different snapshots of the same files.
    pub reloads: tokio::sync::mpsc::Sender<ReloadTrigger>,
    /// For the uptime line. `Instant`, not a wall clock: this is an interval,
    /// and a clock step backwards must not make the server look newly started
    /// (`CLAUDE.md` §6).
    pub started: Instant,
    /// The address the DNS listeners are on, for the header line — an operator
    /// on a box running two of these wants to know which one answered.
    pub listen: String,
}

/// Bind the socket, refusing rather than stealing it if a server is already
/// there.
///
/// Three things happen here that a plain `bind` would get wrong:
///
/// - **A live socket is not replaced.** `connect` first: if something accepts,
///   another `rdnsd` is running on this path and starting a second one over the
///   top of it would leave two daemons and one working control channel. A
///   connection *refused* means the file is a leftover from a process that
///   died, which is the ordinary case after a crash and must not stop a start.
/// - **The permissions are in place before the path is.** Bound under a
///   temporary name in the same directory, restricted to the owner, and then
///   renamed over the target — so there is no window in which the socket is
///   reachable at its published path with whatever mode the umask gave it. This
///   is `persist`'s atomic-rename idiom applied to a socket, and it works for
///   the same reason: `connect` resolves a path to an inode, and the rename
///   moves the name rather than the socket.
/// - **The rename replaces a stale file atomically**, so there is no
///   unlink-then-bind gap for a racing process to bind into.
pub fn bind(path: &Path) -> Result<UnixListener> {
    if let Ok(dir) = path.parent().ok_or(()) {
        if !dir.as_os_str().is_empty() && !dir.is_dir() {
            return Err(anyhow!(
                "--control-socket {}: {} is not a directory",
                path.display(),
                dir.display()
            ));
        }
    }
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        return Err(anyhow!(
            "--control-socket {}: another server is already listening there",
            path.display()
        ));
    }

    let temp = temp_path(path);
    // A leftover from an interrupted start of our own; the target is left alone
    // until the rename.
    let _ = std::fs::remove_file(&temp);
    let listener = UnixListener::bind(&temp)
        .with_context(|| format!("--control-socket {}", path.display()))?;
    let restricted = restrict_to_owner(&temp).and_then(|()| std::fs::rename(&temp, path));
    if let Err(e) = restricted {
        let _ = std::fs::remove_file(&temp);
        return Err(anyhow::Error::from(e).context(format!("--control-socket {}", path.display())));
    }
    Ok(listener)
}

/// `<name>.<pid>.tmp` beside the target, so two servers racing to start on the
/// same path cannot collide on the temporary either.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Accept control connections until told to stop.
///
/// The socket file is removed on the way out. A stale one is survivable — the
/// next start replaces it — but leaving it behind means `rdnsctl` reports
/// "connection refused" against a path that looks like a running server, when
/// "no such file" would have said what actually happened.
pub async fn serve(
    listener: UnixListener,
    path: PathBuf,
    control: Arc<Control>,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    let result = accept_loop(listener, &control, stop, busy).await;
    let _ = std::fs::remove_file(&path);
    result
}

async fn accept_loop(
    listener: UnixListener,
    control: &Arc<Control>,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    loop {
        // `accept` is cancel-safe, so losing this race to the stop drops
        // nothing that was ours — the client simply finds the socket gone and
        // says so.
        let (stream, _) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = stop.wait() => return Ok(()),
        };
        let control = control.clone();
        // A command in flight holds the drain. `dump` of a large zone and
        // `reload` are both worth finishing rather than cutting: a half-written
        // dump is the "client cannot tell a truncated transfer from a complete
        // one" problem again, in a smaller place.
        let busy = busy.clone();
        tokio::spawn(async move {
            let _busy = busy;
            if let Err(e) = converse(stream, &control).await {
                // DEBUG: a control client that hangs up mid-write is not an
                // operator-actionable event, and this socket is not reachable
                // by anyone who is not already trusted.
                tracing::debug!("control connection: {e}");
            }
        });
    }
}

/// One connection: read a command, run it, write the reply, close.
async fn converse(mut stream: UnixStream, control: &Control) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(256);
    let line = loop {
        if let Some(at) = buf.iter().position(|b| *b == b'\n') {
            break String::from_utf8_lossy(&buf[..at]).into_owned();
        }
        if buf.len() >= MAX_REQUEST {
            return write_all(&mut stream, &err("command too long")).await;
        }
        let mut chunk = [0u8; 256];
        match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut chunk)).await {
            // A client that closed without a newline still gets its command
            // run, so `printf status | socat ...` — no trailing newline — works
            // the way anyone would expect it to.
            Ok(Ok(0)) => break String::from_utf8_lossy(&buf).into_owned(),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(e),
            Err(_) => return write_all(&mut stream, &err("timed out waiting for a command")).await,
        }
    };

    let reply = run(Request::parse(&line), control).await;
    write_all(&mut stream, &reply).await
}

async fn write_all(stream: &mut UnixStream, text: &str) -> std::io::Result<()> {
    stream.write_all(text.as_bytes()).await?;
    stream.flush().await
}

/// The command table.
async fn run(request: Request, control: &Control) -> String {
    match request.command.as_str() {
        "status" => ok(&status(control).await),
        "reload" => reload(&request.args, control).await,
        "dump" => dump(&request.args, control).await,
        "version" => ok(&format!("rdnsd {}", rdns::VERSION)),
        "help" | "" => ok(HELP),
        other => err(&format!(
            "unknown command {other:?} — try `help` for the list"
        )),
    }
}

const HELP: &str = "\
status          what is loaded, at what serial, and when each replica last heard \
from a master
reload          re-read every zone file, sign, verify, and install the set
dump <zone>     the zone as it is being served right now, in presentation format
version         the server's version
help            this";

/// The four 3am questions, in one screen.
///
/// The per-zone numbers come from [`rdns::metrics::DnsMetrics::zone_facts`] —
/// the same gauges the Prometheus scrape reads, rather than a second view that
/// could disagree with the dashboard about which serial is being served
/// (`CLAUDE.md` §7). Everything else comes from the zone map, under a read
/// guard held for as long as it takes to copy the numbers out and no longer.
async fn status(control: &Control) -> String {
    let facts = control.served.metrics.zone_facts();
    let now = current_unix_timestamp();

    struct Row {
        zone: String,
        serial: Serial,
        records: usize,
        signing: &'static str,
        replicated: bool,
        last_transfer: Option<u64>,
    }

    let rows: Vec<Row> = {
        let zones = control.served.zone_map.read().await;
        let mut rows: Vec<Row> = zones
            .values()
            .map(|zone| {
                let gauge = facts
                    .iter()
                    .find(|f| f.zone.eq_ignore_ascii_case(zone.origin()));
                Row {
                    zone: zone.origin().to_string(),
                    // The gauge is the number being *served*, which is not the
                    // number in the file once signing is on — see TODO.md #8.
                    // Falling back to the zone's own SOA covers the moment
                    // between a zone being installed and its gauge being set.
                    serial: gauge
                        .map(|g| g.serial)
                        .or_else(|| zone.serial())
                        .unwrap_or(Serial::new(0)),
                    records: zone.records().len(),
                    signing: if zone.has_nsec3_chain() {
                        "NSEC3"
                    } else if zone.has_nsec_chain() {
                        "NSEC"
                    } else {
                        "-"
                    },
                    replicated: control
                        .replicated
                        .iter()
                        .any(|z| z.eq_ignore_ascii_case(zone.origin())),
                    last_transfer: gauge.and_then(|g: &ZoneFacts| g.last_transfer),
                }
            })
            .collect();
        rows.sort_by(|a, b| a.zone.cmp(&b.zone));
        rows
    };

    let replicated = rows.iter().filter(|r| r.replicated).count();
    let mut out = format!(
        "rdnsd {} on {}, up {}\n\
         zones: {} loaded, {replicated} replicated\n\n",
        rdns::VERSION,
        control.listen,
        duration(control.started.elapsed().as_secs()),
        rows.len(),
    );
    out.push_str(
        "zone                            serial  records  denial  role       last contact\n",
    );
    for row in &rows {
        out.push_str(&format!(
            "{:<30}  {:>6}  {:>7}  {:<6}  {:<9}  {}\n",
            row.zone,
            row.serial,
            row.records,
            row.signing,
            if row.replicated {
                "secondary"
            } else {
                "primary"
            },
            match row.last_transfer {
                // The instant *and* the age. A dashboard gets the instant
                // (TODO.md #9d's metrics rule); a person reading this at 3am is
                // answering "is it stale?", which is the age.
                Some(at) => format!("{at} ({} ago)", duration(now.saturating_sub(at))),
                // Not "never" and not zero: a primary has no master to have
                // heard from, and a secondary that has not managed one yet is a
                // different thing that the next line of the log will name.
                None => "-".to_string(),
            }
        ));
    }
    if rows.is_empty() {
        out.push_str("(none — every query will be REFUSED)\n");
    }
    out
}

/// `1d 2h`, `3h 4m`, `5m 6s`, `7s`. Two units is as much as anyone reads off a
/// status line, and rounding down is right for an age: "0s ago" is a fact and
/// "1s ago" would be a guess.
fn duration(seconds: u64) -> String {
    let (d, h, m, s) = (
        seconds / 86_400,
        (seconds % 86_400) / 3600,
        (seconds % 3600) / 60,
        seconds % 60,
    );
    match (d, h, m) {
        (0, 0, 0) => format!("{s}s"),
        (0, 0, _) => format!("{m}m {s}s"),
        (0, _, _) => format!("{h}h {m}m"),
        _ => format!("{d}d {h}h"),
    }
}

/// Re-read every zone file, sign, verify, install — and say whether it worked.
///
/// **No per-zone reload, and that is a decision rather than a gap.** The
/// finding under #9d asked for `reload [zone]`, but `Reloading::load` is
/// all-or-nothing on purpose: nothing is installed unless the whole set comes
/// through, because a partial reload leaves the server serving a mixture of two
/// versions and the half that failed is the half that needed attention
/// (`CLAUDE.md` §4). Reloading one zone out of a set that was never validated
/// as a set would be that same bug with a smaller blast radius, which is not the
/// same as not having it.
async fn reload(args: &[String], control: &Control) -> String {
    if !args.is_empty() {
        return err(
            "reload takes no arguments: a reload is the whole set or nothing, \
             because nothing is installed unless every zone parses, signs and \
             verifies",
        );
    }
    let (tx, rx) = oneshot::channel();
    if control
        .reloads
        .send(ReloadTrigger::Control(tx))
        .await
        .is_err()
    {
        return err("the zone maintenance task is gone; the server is shutting down");
    }
    match tokio::time::timeout(RELOAD_REPORT_TIMEOUT, rx).await {
        Ok(Ok(Ok(zones))) => ok(&format!("reloaded {zones} zone(s)")),
        Ok(Ok(Err(why))) => err(&format!(
            "the reload failed and the zones already loaded are still being served: {why}"
        )),
        // The maintenance task dropped the channel: it is stopping, and the
        // reload either happened or never will. Saying so beats reporting a
        // success we did not observe.
        Ok(Err(_)) => err("the server stopped before the reload finished"),
        Err(_) => err(&format!(
            "the reload is still running after {}s — it is not cancelled, so watch the log for the result",
            RELOAD_REPORT_TIMEOUT.as_secs()
        )),
    }
}

/// The zone as it is being served, which is not the zone as it is on disk.
///
/// That difference is the whole value of the command: with signing on, what is
/// served carries RRSIGs, a DNSKEY RRset and an NSEC or NSEC3 chain that exist
/// only in memory, and a served serial that is deliberately not the file's
/// (#8). "Read the zone file" answers a different question.
async fn dump(args: &[String], control: &Control) -> String {
    let [name] = args else {
        return err("dump takes exactly one zone name");
    };
    let zones = control.served.zone_map.read().await;
    let Some(zone) = zones.matching(name) else {
        // Spelling the alternatives out, because the commonest reason for this
        // is a missing trailing dot and the second commonest is asking the
        // wrong server.
        return err(&format!(
            "no zone {name:?} is loaded — this server holds: {}",
            if zones.is_empty() {
                "nothing".to_string()
            } else {
                let mut held: Vec<&str> = zones.values().map(|z| z.origin()).collect();
                held.sort_unstable();
                held.join(", ")
            }
        ));
    };
    match zone_to_string(zone) {
        Ok(text) => ok(&text),
        Err(e) => err(&format!("could not render {name:?}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdns::control::{parse_reply, Reply};
    use rdns::zone::Zone;

    fn zone() -> Zone {
        rdns::zone::parse_zone_file(
            "$ORIGIN example.com.\n\
             $TTL 3600\n\
             @   IN SOA ns1.example.com. admin.example.com. ( 42 3600 600 604800 300 )\n\
             @   IN NS  ns1.example.com.\n\
             ns1 IN A   192.0.2.1\n",
            "example.com.",
        )
        .expect("the zone parses")
    }

    fn control(
        replicated: Vec<String>,
    ) -> (Arc<Control>, tokio::sync::mpsc::Receiver<ReloadTrigger>) {
        use std::collections::HashMap;
        use tokio::sync::RwLock;

        let mut zones = HashMap::new();
        zones.insert("example.com.".to_string(), zone());
        let metrics = Arc::new(rdns::metrics::DnsMetrics::new());
        metrics.set_zone_serial("example.com.", 42);
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        (
            Arc::new(Control {
                served: Served {
                    zone_map: Arc::new(RwLock::new(crate::Zones::new(zones))),
                    deltas: Arc::new(RwLock::new(rdns::ixfr::DeltaLog::new())),
                    metrics,
                },
                replicated,
                reloads: tx,
                started: Instant::now(),
                listen: "127.0.0.1:15353".to_string(),
            }),
            rx,
        )
    }

    async fn ask(control: &Control, line: &str) -> Reply {
        parse_reply(&run(Request::parse(line), control).await)
    }

    /// The question that had no answer before this existed: a zone that is not
    /// loaded and a zone that was never configured both answer REFUSED on the
    /// wire, so "is broken.test loaded?" was unanswerable from outside the box.
    #[tokio::test]
    async fn status_says_which_zones_are_loaded_and_at_what_serial() {
        let (control, _rx) = control(Vec::new());
        let Reply::Ok(body) = ask(&control, "status").await else {
            panic!("status failed");
        };
        assert!(body.contains("example.com."), "{body}");
        assert!(body.contains("42"), "the served serial: {body}");
        assert!(body.contains("primary"), "{body}");
        assert!(!body.contains("broken.test."), "{body}");
    }

    /// A primary has no master to have heard from and a secondary that has not
    /// managed a transfer has not heard from one, and neither is zero — which
    /// would render as 1970 and read as catastrophically stale.
    #[tokio::test]
    async fn a_zone_with_no_contact_shows_no_time_rather_than_the_epoch() {
        let (control, _rx) = control(vec!["example.com.".to_string()]);
        let Reply::Ok(body) = ask(&control, "status").await else {
            panic!("status failed");
        };
        assert!(body.contains("secondary"), "{body}");
        assert!(!body.contains("1970"), "{body}");
        assert!(
            body.lines()
                .any(|l| l.starts_with("example.com.") && l.ends_with('-')),
            "the last-contact column should be empty, not zero: {body}"
        );
    }

    /// What is served is not what is on disk once signing is on, which is the
    /// reason this command is not "cat the zone file".
    #[tokio::test]
    async fn dump_renders_the_zone_that_is_being_served() {
        let (control, _rx) = control(Vec::new());
        let Reply::Ok(body) = ask(&control, "dump example.com.").await else {
            panic!("dump failed");
        };
        assert!(body.contains("SOA"), "{body}");
        assert!(body.contains("192.0.2.1"), "{body}");
    }

    /// The commonest way to get this wrong is a missing trailing dot, so the
    /// refusal lists what is actually held rather than only saying no.
    #[tokio::test]
    async fn dump_of_an_unknown_zone_names_what_is_held() {
        let (control, _rx) = control(Vec::new());
        let Reply::Err(why) = ask(&control, "dump nosuch.test.").await else {
            panic!("dumping a zone we do not hold must fail");
        };
        assert!(why.contains("nosuch.test."), "{why}");
        assert!(why.contains("example.com."), "{why}");
    }

    /// A zone name is matched however either side spells its case, the same way
    /// the answer path matches it (RFC 4343).
    #[tokio::test]
    async fn dump_matches_a_zone_name_case_insensitively() {
        let (control, _rx) = control(Vec::new());
        assert!(matches!(
            ask(&control, "dump EXAMPLE.COM.").await,
            Reply::Ok(_)
        ));
    }

    #[tokio::test]
    async fn an_unknown_command_is_refused_and_says_so() {
        let (control, _rx) = control(Vec::new());
        let Reply::Err(why) = ask(&control, "restart").await else {
            panic!("an unknown command must not look like it worked");
        };
        assert!(why.contains("restart"), "{why}");
    }

    /// A blank line is what a human gets by pressing return, and answering it
    /// with the command list is more use than answering it with an error.
    #[tokio::test]
    async fn a_blank_command_prints_the_help() {
        let (control, _rx) = control(Vec::new());
        let Reply::Ok(body) = ask(&control, "").await else {
            panic!("a blank line should be answered, not refused");
        };
        assert!(body.contains("status"), "{body}");
    }

    /// `reload example.com.` is refused rather than quietly reloading
    /// everything — the operator asked for something this cannot do, and doing
    /// something else instead is how a runbook comes to say the wrong thing.
    #[tokio::test]
    async fn reload_refuses_a_zone_argument_and_explains_why() {
        let (control, _rx) = control(Vec::new());
        let Reply::Err(why) = ask(&control, "reload example.com.").await else {
            panic!("a per-zone reload must not report success");
        };
        assert!(why.contains("whole set"), "{why}");
    }

    /// The reload itself is the maintenance task's, and this is the handoff:
    /// the request arrives there, and the answer the operator sees is the one
    /// that task reports back rather than "sent".
    #[tokio::test]
    async fn reload_reports_what_the_maintenance_task_did() {
        let (control, mut rx) = control(Vec::new());
        let responder = tokio::spawn(async move {
            match rx.recv().await {
                Some(ReloadTrigger::Control(reply)) => {
                    let _ = reply.send(Ok(7));
                }
                other => panic!("expected a control reload, got {}", other.is_some()),
            }
        });
        let Reply::Ok(body) = ask(&control, "reload").await else {
            panic!("reload failed");
        };
        assert!(body.contains('7'), "{body}");
        responder.await.expect("the responder joins");
    }

    /// A failed reload must not read as a success. The zones already loaded
    /// keep answering, which is the useful half of the message.
    #[tokio::test]
    async fn a_failed_reload_says_the_old_zones_are_still_being_served() {
        let (control, mut rx) = control(Vec::new());
        let responder = tokio::spawn(async move {
            if let Some(ReloadTrigger::Control(reply)) = rx.recv().await {
                let _ = reply.send(Err("example.com.zone:12: bad TTL".to_string()));
            }
        });
        let Reply::Err(why) = ask(&control, "reload").await else {
            panic!("a failed reload must not report success");
        };
        assert!(why.contains("still being served"), "{why}");
        assert!(why.contains("bad TTL"), "{why}");
        responder.await.expect("the responder joins");
    }

    #[test]
    fn a_duration_reads_the_way_a_person_says_it() {
        assert_eq!(duration(0), "0s");
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(125), "2m 5s");
        assert_eq!(duration(7_265), "2h 1m");
        assert_eq!(duration(90_000), "1d 1h");
    }

    /// End to end over a real socket, because everything above tests the
    /// command table and none of it tests the framing, the permissions or the
    /// bind. A control channel that answers in a unit test and not over its
    /// socket is not a control channel.
    #[tokio::test]
    async fn the_socket_answers_and_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::AsyncWriteExt;

        let dir = std::env::temp_dir().join(format!("rdnsd-control-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("rdnsd.sock");
        let listener = bind(&path).expect("bind");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the socket must not be reachable by anyone but its owner"
        );

        let shutdown = rdns::shutdown::Shutdown::new();
        let (control, _rx) = control(Vec::new());
        let server = tokio::spawn(serve(
            listener,
            path.clone(),
            control,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let mut client = UnixStream::connect(&path).await.expect("connect");
        client.write_all(b"status\n").await.expect("send");
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.expect("read");
        assert!(matches!(parse_reply(&reply), Reply::Ok(_)), "{reply}");

        shutdown.begin();
        server.await.expect("joins").expect("no io error");
        assert!(
            !path.exists(),
            "a socket left behind makes `rdnsctl` say `connection refused` about a server that is not running"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Starting a second server over a running one would leave two daemons and
    /// one working control channel, and the second would look fine.
    #[tokio::test]
    async fn binding_over_a_live_socket_is_refused() {
        let dir = std::env::temp_dir().join(format!("rdnsd-control-live-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("rdnsd.sock");
        let first = bind(&path).expect("the first bind");

        let err = bind(&path).expect_err("the second bind must be refused");
        assert!(err.to_string().contains("already listening"), "{err}");

        drop(first);
        // ...but a socket file left behind by a process that died is not a
        // reason to refuse to start, which is the case that matters after a
        // crash.
        std::fs::write(&path, b"").ok();
        assert!(
            bind(&path).is_ok(),
            "a stale socket file must not block a start"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
