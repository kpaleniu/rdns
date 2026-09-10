//! The control socket: `status`, `reload` and `dump`, answered by the process
//! that knows.
//!
//! A Unix socket and no TCP; see [`rdns::control`]. Unix-only because neither
//! `std` nor `tokio` exposes AF_UNIX on Windows, where `--control-socket` is
//! refused at startup rather than accepted and ignored.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rdns::clock::current_unix_timestamp;
use rdns::control::{err, ok, Request, MAX_REQUEST};
use rdns::metrics::ZoneFacts;
use rdns::persist;
use rdns::shutdown::{Busy, Stop};
use rdns::zone_writer::zone_to_string;
use rdns::Name;
use rdns::Serial;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

use crate::{ReloadTrigger, ZoneContext};

/// How long a client gets to send its command before we give up on it.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `reload` waits for the maintenance task before answering anyway.
///
/// Not a timeout on the work: the reload carries on regardless, as a SIGHUP one
/// would.
const RELOAD_REPORT_TIMEOUT: Duration = Duration::from_secs(120);

/// Everything a command needs to answer, so the handlers take one argument.
pub struct Control {
    pub served: ZoneContext,
    /// Zones this server replicates, so `status` can say which are secondary
    /// without inferring it from a timestamp that is also absent on a primary.
    pub replicated: Vec<String>,
    /// Where a `reload` request goes: the same loop SIGHUP and the re-signing
    /// timer feed, so two reloads cannot install two snapshots of one file set.
    pub reloads: tokio::sync::mpsc::Sender<ReloadTrigger>,
    /// For the uptime line. `Instant`: an interval, and a clock step backwards
    /// must not make the server look newly started.
    pub started: Instant,
    /// The address the DNS listeners are on, for the header line.
    pub listen: String,
}

/// Bind the socket, refusing rather than stealing it if a server is already
/// there.
///
/// - `connect` first: something accepting means another `rdnsd` holds the path.
///   Connection refused means a leftover from a dead process, which must not
///   stop a start.
/// - Bind under a temporary name, restrict to the owner, rename over the
///   target: the mode is in place before the published path exists, and the
///   rename leaves no unlink-then-bind gap for a racing process.
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
    let restricted = persist::restrict_to_owner(&temp).and_then(|()| std::fs::rename(&temp, path));
    if let Err(e) = restricted {
        let _ = std::fs::remove_file(&temp);
        return Err(anyhow::Error::from(e).context(format!("--control-socket {}", path.display())));
    }
    Ok(listener)
}

/// `<name>.<pid>.tmp` beside the target, so two servers racing to start cannot
/// collide on the temporary either.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    path.with_file_name(name)
}

/// Accept control connections until told to stop.
///
/// The socket file is removed on the way out: a leftover makes `rdnsctl` say
/// "connection refused" where "no such file" is the truth.
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
        // `accept` is cancel-safe, so losing this race drops nothing.
        let (stream, _) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = stop.wait() => return Ok(()),
        };
        let control = control.clone();
        // A command in flight holds the drain: a half-written `dump` cannot be
        // told from a complete one.
        let busy = busy.clone();
        tokio::spawn(async move {
            let _busy = busy;
            if let Err(e) = converse(stream, &control).await {
                // DEBUG: a client hanging up mid-write is not actionable, and
                // this socket is reachable only by the trusted.
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
            // run: `printf status | socat ...` sends no trailing newline.
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

/// What is loaded, at what serial, and when each replica last heard from a
/// master.
///
/// The per-zone numbers come from [`rdns::metrics::DnsMetrics::zone_facts`], the
/// same gauges the scrape reads, so the two cannot disagree. The zone-map read
/// guard is held only long enough to copy the numbers out.
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
                // Both lists are presentation text — a metrics label and a
                // config string — so the comparison happens there rather than
                // as names.
                let origin = zone.origin().to_presentation();
                let gauge = facts.iter().find(|f| f.zone.eq_ignore_ascii_case(&origin));
                Row {
                    zone: origin.clone(),
                    // The gauge is the number being served, which is not the
                    // file's once signing is on. The fallback covers the moment
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
                        .any(|z| z.eq_ignore_ascii_case(&origin)),
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
                // The instant for a dashboard, the age for the person reading
                // this, who is asking whether it is stale.
                Some(at) => format!("{at} ({} ago)", duration(now.saturating_sub(at))),
                // Not zero: a primary has no master to have heard from.
                None => "-".to_string(),
            }
        ));
    }
    if rows.is_empty() {
        out.push_str("(none — every query will be REFUSED)\n");
    }
    out
}

/// `1d 2h`, `3h 4m`, `5m 6s`, `7s`. Rounds down: for an age, "0s ago" is a fact
/// and "1s ago" would be a guess.
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
/// No per-zone reload: `Reloading::load` is all-or-nothing, because a partial
/// reload serves a mixture of two versions and the half that failed is the half
/// that needed attention.
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
        // The channel dropped: the task is stopping, and the reload either
        // happened or never will. Do not report a success nobody observed.
        Ok(Err(_)) => err("the server stopped before the reload finished"),
        Err(_) => err(&format!(
            "the reload is still running after {}s — it is not cancelled, so watch the log for the result",
            RELOAD_REPORT_TIMEOUT.as_secs()
        )),
    }
}

/// The zone as it is being served, which is not the zone as it is on disk: with
/// signing on the RRSIGs, DNSKEY RRset, denial chain and served serial exist
/// only in memory.
async fn dump(args: &[String], control: &Control) -> String {
    let [name] = args else {
        return err("dump takes exactly one zone name");
    };
    let zones = control.served.zone_map.read().await;
    let asked: Option<Name> = name.parse().ok();
    let Some(zone) = asked.as_ref().and_then(|n| zones.matching(n.as_ref())) else {
        // The commonest cause is a missing trailing dot, the next is asking the
        // wrong server, so name what is held.
        return err(&format!(
            "no zone {name:?} is loaded — this server holds: {}",
            if zones.is_empty() {
                "nothing".to_string()
            } else {
                let mut held: Vec<String> = zones
                    .values()
                    .map(|z| z.origin().to_presentation())
                    .collect();
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
    use crate::testutil::ScratchDir;
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
        use tokio::sync::RwLock;

        let mut zones = crate::Zones::default();
        drop(zones.insert(zone()));
        let metrics = Arc::new(rdns::metrics::DnsMetrics::new());
        metrics.set_zone_serial("example.com.", Serial::new(42));
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        (
            Arc::new(Control {
                served: ZoneContext {
                    zone_map: Arc::new(RwLock::new(zones)),
                    deltas: Arc::new(RwLock::new(rdns::ixfr::DeltaLog::new())),
                    metrics,
                    journal: None,
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

    /// On the wire a zone that failed to load and one that was never configured
    /// both answer REFUSED; `status` tells them apart.
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

    /// Neither a primary nor a secondary that has never transferred has a
    /// contact time, and zero renders as 1970 and reads as catastrophically
    /// stale.
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

    #[tokio::test]
    async fn dump_renders_the_zone_that_is_being_served() {
        let (control, _rx) = control(Vec::new());
        let Reply::Ok(body) = ask(&control, "dump example.com.").await else {
            panic!("dump failed");
        };
        assert!(body.contains("SOA"), "{body}");
        assert!(body.contains("192.0.2.1"), "{body}");
    }

    /// The commonest cause is a missing trailing dot, so the refusal lists what
    /// is held.
    #[tokio::test]
    async fn dump_of_an_unknown_zone_names_what_is_held() {
        let (control, _rx) = control(Vec::new());
        let Reply::Err(why) = ask(&control, "dump nosuch.test.").await else {
            panic!("dumping a zone we do not hold must fail");
        };
        assert!(why.contains("nosuch.test."), "{why}");
        assert!(why.contains("example.com."), "{why}");
    }

    /// Case-insensitively, as the answer path matches it (RFC 4343).
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

    /// A blank line is what pressing return sends; the command list is more use
    /// than an error.
    #[tokio::test]
    async fn a_blank_command_prints_the_help() {
        let (control, _rx) = control(Vec::new());
        let Reply::Ok(body) = ask(&control, "").await else {
            panic!("a blank line should be answered, not refused");
        };
        assert!(body.contains("status"), "{body}");
    }

    /// Refused rather than quietly reloading everything: doing something other
    /// than what was asked is how a runbook comes to say the wrong thing.
    #[tokio::test]
    async fn reload_refuses_a_zone_argument_and_explains_why() {
        let (control, _rx) = control(Vec::new());
        let Reply::Err(why) = ask(&control, "reload example.com.").await else {
            panic!("a per-zone reload must not report success");
        };
        assert!(why.contains("whole set"), "{why}");
    }

    /// The operator sees what the maintenance task reported, not "sent".
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

    /// A failed reload must not read as a success, and that the old zones keep
    /// answering is the useful half of the message.
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

    /// End to end over a real socket: everything above tests the command table
    /// and none of it the framing, the permissions or the bind.
    #[tokio::test]
    async fn the_socket_answers_and_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::AsyncWriteExt;

        let dir = ScratchDir::new("control");
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
    }

    /// A second server over a running one would leave two daemons and one
    /// working control channel, and the second would look fine.
    #[tokio::test]
    async fn binding_over_a_live_socket_is_refused() {
        let dir = ScratchDir::new("control-live");
        let path = dir.join("rdnsd.sock");
        let first = bind(&path).expect("the first bind");

        let err = bind(&path).expect_err("the second bind must be refused");
        assert!(err.to_string().contains("already listening"), "{err}");

        drop(first);
        // A file left behind by a dead process must not refuse a start.
        std::fs::write(&path, b"").ok();
        assert!(
            bind(&path).is_ok(),
            "a stale socket file must not block a start"
        );
    }
}
