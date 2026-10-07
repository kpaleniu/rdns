//! The control socket's commands for `rdnsr` (`TODO.md` #178): flush and dump
//! the caches, list the negative trust anchors, and run SIGHUP's reload. The
//! socket, or named pipe on Windows, is `rdns_transport::control`, shared with
//! `rdnsd`; this is only the command table.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rdns::control::{duration, err, ok, Request};
use rdns::denial_wire::canonical_sort_key;
use rdns::record_text::resource_record_line;
use rdns::{Name, Ttl};
use tokio::sync::{mpsc, oneshot};

use crate::answer::Resolving;
use crate::routes::LocalFile;

/// How long `reload` waits for the reload task before answering anyway. Not a
/// timeout on the work: the reload carries on, as a SIGHUP one would.
const RELOAD_REPORT_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) struct Control {
    pub(crate) serving: Arc<Resolving>,
    /// SIGHUP's reload task, which sends its report back on the oneshot.
    pub(crate) reloads: mpsc::Sender<oneshot::Sender<String>>,
    /// For `status`'s route lines, which name the file a local zone came from.
    pub(crate) local: Arc<Vec<LocalFile>>,
    /// `Instant`: a clock step must not make the server look newly started.
    pub(crate) started: Instant,
}

impl rdns_transport::control::Commands for Control {
    async fn run(&self, request: Request) -> String {
        run(request, self).await
    }
}

async fn run(request: Request, control: &Control) -> String {
    let args = &request.args[..];
    match request.command.as_str() {
        "status" => ok(&status(control)),
        "reload" if args.is_empty() => reload(control).await,
        "reload" => err("reload takes no arguments: it re-reads what SIGHUP does"),
        "flush" if args.is_empty() => flush_tree(control, &Name::root()),
        "flush" => err("flush takes no arguments; flushname and flushtree take a name"),
        "flushname" => match name_arg("flushname", args) {
            Ok(name) => ok(&format!(
                "{} entries removed",
                control.serving.caches.forget_name(name.as_ref())
            )),
            Err(why) => why,
        },
        "flushtree" => match name_arg("flushtree", args) {
            Ok(name) => flush_tree(control, &name),
            Err(why) => why,
        },
        "dump" => match args {
            [] => dump(control, &Name::root()),
            _ => match name_arg("dump", args) {
                Ok(name) => dump(control, &name),
                Err(why) => why,
            },
        },
        "nta" if args.is_empty() => ok(&ntas(control)),
        "nta" => {
            err("nta takes no arguments: anchors are added and removed in the file, then reload")
        }
        "version" => ok(&format!("rdnsr {}", rdns::VERSION)),
        "help" | "" => ok(HELP),
        other => err(&format!(
            "unknown command {other:?} — try `help` for the list"
        )),
    }
}

const HELP: &str = "\
status          uptime, the size of each cache, negative trust anchors, routed domains
reload          what SIGHUP re-reads: certificate, NTA file, local zones, RPZ feeds
flush           every cache
flushname NAME  answers and negative answers at exactly NAME, every type
flushtree NAME  every cache, at and below NAME
dump [NAME]     cached answers, at and below NAME if given, with the TTL left
nta             the negative trust anchors in force
version         the server's version
help            this";

/// Exactly one argument, parsed as a name. The `Err` is the reply.
fn name_arg(command: &str, args: &[String]) -> Result<Name, String> {
    let [text] = args else {
        return Err(err(&format!("{command} takes exactly one name")));
    };
    text.parse()
        .map_err(|e| err(&format!("{command} {text:?}: not a name: {e}")))
}

fn status(control: &Control) -> String {
    let serving = &control.serving;
    let mut out = format!(
        "rdnsr {}, up {}\n",
        rdns::VERSION,
        duration(control.started.elapsed().as_secs())
    );
    let caches = serving.caches.sizes();
    let resolver = serving.resolver.cache_sizes();
    let sizes: Vec<String> = caches
        .iter()
        .chain(resolver.iter())
        .map(|(what, n)| format!("{what} {n}"))
        .collect();
    let _ = writeln!(out, "caches: {}", sizes.join(", "));
    let _ = writeln!(
        out,
        "negative trust anchors: {}",
        serving.resolver.ntas().snapshot().len()
    );
    let routes = serving.resolver.routes();
    let _ = writeln!(out, "routed domains: {}", routes.len());
    for route in routes {
        let _ = writeln!(out, "  {}", crate::routes::describe(route, &control.local));
    }
    out
}

/// Every cache at and below `node`; with the root, the RTTs and NSIDs too.
/// Trust anchors and RPZ policy are not caches and stay (`TODO.md` #178).
fn flush_tree(control: &Control, node: &Name) -> String {
    let removed = control.serving.caches.forget_at_or_below(node.as_ref())
        + control.serving.resolver.forget_at_or_below(node.as_ref());
    ok(&format!("{removed} entries removed"))
}

/// One line per record, owner order, the TTL being what is left. An entry past
/// its TTL and kept for RFC 8767 is marked, since it is served only when
/// upstream fails.
fn dump(control: &Control, node: &Name) -> String {
    // Copied out under the lock and formatted after (`CLAUDE.md` §9).
    let mut held = control.serving.caches.dump(node.as_ref());
    held.sort_by_cached_key(|d| {
        d.records
            .first()
            .map(|r| (canonical_sort_key(r.name.as_ref()), r.rdata.rtype()))
    });
    let mut out = String::new();
    for entry in &held {
        let ttl = Ttl::from_secs(u32::try_from(entry.remaining).unwrap_or(u32::MAX));
        let mark = match (entry.stale, entry.outcome.label()) {
            (true, outcome) => format!(" ; stale, {outcome}"),
            (false, outcome) => format!(" ; {outcome}"),
        };
        for record in &entry.records {
            let shown = rdns::ResourceRecord {
                ttl,
                ..record.clone()
            };
            match resource_record_line(&shown) {
                Ok(line) => {
                    let _ = writeln!(out, "{}{mark}", line.trim_end());
                }
                Err(e) => {
                    let _ = writeln!(out, "; {}: could not render: {e}", record.name);
                }
            }
        }
    }
    let _ = write!(out, "; {} RRsets", held.len());
    ok(&out)
}

fn ntas(control: &Control) -> String {
    let now = control.serving.ctx.clock.now();
    let set = control.serving.resolver.ntas().snapshot();
    let mut out = String::new();
    for nta in set.iter() {
        let _ = writeln!(
            out,
            "{} until {} (in {}){}",
            nta.name,
            nta.until,
            duration(nta.until.saturating_sub(now)),
            if nta.recheck {
                ", lifted early once the zone validates"
            } else {
                ", norecheck"
            }
        );
    }
    let _ = write!(out, "{} in force", set.len());
    out
}

/// SIGHUP's reload, through SIGHUP's task, so the two cannot overlap.
async fn reload(control: &Control) -> String {
    let (tx, rx) = oneshot::channel();
    if control.reloads.send(tx).await.is_err() {
        return err("the reload task is gone; the server is shutting down");
    }
    match tokio::time::timeout(RELOAD_REPORT_TIMEOUT, rx).await {
        Ok(Ok(report)) => ok(&report),
        // Do not report a success nobody observed.
        Ok(Err(_)) => err("the server stopped before the reload finished"),
        Err(_) => err(&format!(
            "the reload is still running after {}s — it is not cancelled, so watch the log for the result",
            RELOAD_REPORT_TIMEOUT.as_secs()
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rdns::cache::StalePolicy;
    use rdns::clock::{current_unix_timestamp, Clock};
    use rdns::control::{parse_reply, Reply};
    use rdns::resolver::{Resolver, ResolverConfig, Route, Upstream};
    use rdns::rpz::PolicyZones;
    use rdns::validation::Transport;
    use rdns::{record_types, DnsMessage, OpCode, Qtype, QuerySection, ResourceRecord};

    use super::*;
    use crate::answer::handle_query;
    use crate::caches::Caches;
    use crate::testutil::{message, nm, serving, test_peer, test_shell};

    fn a_record(name: &Name, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: name.clone(),
            class: rdns::Class::IN,
            ttl: Ttl::from_secs(ttl),
            rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(std::net::Ipv4Addr::new(
                192, 0, 2, 10,
            )))
            .expect("encodes"),
        }
    }

    /// A forwarder whose upstream answers an A record for anything, and the
    /// count of what it was asked.
    fn counting() -> (Arc<Resolving>, Arc<AtomicUsize>) {
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        let upstream = Upstream::answering(move |_, _, query| {
            let query = DnsMessage::try_from_bytes(query).ok()?;
            counter.fetch_add(1, Ordering::SeqCst);
            let mut reply = query.clone();
            reply.response = true;
            reply.recursion_ok = true;
            reply.answers = vec![a_record(&query.queries[0].qname, 300)];
            reply.to_bytes_within(4096).ok()
        });
        let config = ResolverConfig {
            routes: vec![Route::forward(
                Name::root(),
                vec!["198.51.100.1:53".parse().expect("an address")],
            )],
            ..Default::default()
        };
        let resolver = Arc::new(Resolver::new(config).with_upstream(upstream));
        (
            serving(resolver, test_shell(), PolicyZones::default()),
            asked,
        )
    }

    fn control(serving: Arc<Resolving>) -> (Control, mpsc::Receiver<oneshot::Sender<String>>) {
        let (reloads, rx) = mpsc::channel(1);
        let control = Control {
            serving,
            reloads,
            local: Arc::new(Vec::new()),
            started: Instant::now(),
        };
        (control, rx)
    }

    async fn ask_dns(serving: &Resolving, name: &str) {
        let mut msg = DnsMessage::try_from_bytes(&message(OpCode::Query, false)).expect("parses");
        msg.queries = vec![QuerySection {
            qname: nm(name),
            qtype: Qtype::of(record_types::A),
            qclass: rdns::QueryClass::IN,
        }];
        handle_query(
            msg.to_bytes_within(512).expect("serialize"),
            test_peer(),
            current_unix_timestamp(),
            serving,
            Transport::Udp,
        )
        .await
        .expect("answered");
    }

    async fn ask(control: &Control, line: &str) -> Reply {
        parse_reply(&run(Request::parse(line), control).await)
    }

    async fn body(control: &Control, line: &str) -> String {
        match ask(control, line).await {
            Reply::Ok(body) => body,
            Reply::Err(why) => panic!("{line}: {why}"),
        }
    }

    /// The next query for a flushed name goes upstream; a sibling's does not.
    #[tokio::test]
    async fn flushname_sends_the_next_query_upstream_and_keeps_siblings() {
        let (serving, asked) = counting();
        let (control, _rx) = control(serving.clone());
        for name in ["a.example.test.", "b.example.test."] {
            ask_dns(&serving, name).await;
        }
        assert_eq!(asked.load(Ordering::SeqCst), 2);

        assert_eq!(
            body(&control, "flushname A.example.test.").await,
            "1 entries removed\n",
            "case-insensitive, and only the one name"
        );
        assert_eq!(
            body(&control, "flushname nowhere.test.").await,
            "0 entries removed\n",
            "a flush that matched nothing says so"
        );
        ask_dns(&serving, "b.example.test.").await;
        assert_eq!(asked.load(Ordering::SeqCst), 2, "the sibling is cached");
        ask_dns(&serving, "a.example.test.").await;
        assert_eq!(asked.load(Ordering::SeqCst), 3, "the flushed name is asked");
    }

    #[tokio::test]
    async fn flushtree_takes_the_subtree_and_leaves_its_parent_and_siblings() {
        let (serving, asked) = counting();
        let (control, _rx) = control(serving.clone());
        let names = [
            "example.test.",
            "a.example.test.",
            "b.c.example.test.",
            "test.",
            "other.test.",
        ];
        for name in names {
            ask_dns(&serving, name).await;
        }
        assert_eq!(asked.load(Ordering::SeqCst), 5);

        assert_eq!(
            body(&control, "flushtree example.test.").await,
            "3 entries removed\n"
        );
        for name in ["test.", "other.test."] {
            ask_dns(&serving, name).await;
        }
        assert_eq!(asked.load(Ordering::SeqCst), 5, "outside the tree stays");
        for name in &names[..3] {
            ask_dns(&serving, name).await;
        }
        assert_eq!(asked.load(Ordering::SeqCst), 8, "the tree went");
    }

    /// `flush` reports what it removed, and `status` reads zeros after.
    #[tokio::test]
    async fn flush_empties_every_cache() {
        let (serving, _asked) = counting();
        let (control, _rx) = control(serving.clone());
        for name in ["a.example.test.", "b.example.test."] {
            ask_dns(&serving, name).await;
        }
        let held: usize = serving
            .caches
            .sizes()
            .iter()
            .chain(serving.resolver.cache_sizes().iter())
            .map(|(_, n)| n)
            .sum();
        assert!(held >= 2, "the fixture cached something");

        assert_eq!(
            body(&control, "flush").await,
            format!("{held} entries removed\n")
        );
        let status = body(&control, "status").await;
        assert!(
            status.contains(
                "caches: answers 0, negatives 0, denials 0, delegations 0, keys 0, rtts 0, nsids 0"
            ),
            "{status}"
        );
    }

    /// The TTL shown is what is left, and an entry kept past its TTL for
    /// RFC 8767 is marked.
    #[tokio::test]
    async fn dump_shows_the_ttl_left_and_marks_stale_entries() {
        let clock = Clock::fixed(1_000_000_000);
        let resolving = serving(
            crate::testutil::test_resolver(),
            test_shell(),
            PolicyZones::default(),
        );
        let mut resolving = Arc::into_inner(resolving).expect("not shared yet");
        resolving.caches = Caches::new(16, 4, StalePolicy::seconds(3600), clock.clone());
        let resolving = Arc::new(resolving);
        let a = Qtype::of(record_types::A);
        let (fresh, stale, elsewhere) = (
            nm("fresh.example.test."),
            nm("stale.example.test."),
            nm("other.test."),
        );
        for (name, ttl) in [(&fresh, 300), (&stale, 100), (&elsewhere, 300)] {
            resolving
                .caches
                .remember(name.as_ref(), a, vec![a_record(name, ttl)]);
        }
        clock.advance(150);
        let (control, _rx) = control(resolving);

        let dump = body(&control, "dump example.test.").await;
        let lines: Vec<&str> = dump.lines().collect();
        assert_eq!(lines.len(), 3, "{dump}");
        let fields: Vec<&str> = lines[0].split_whitespace().collect();
        assert_eq!(
            fields[..2],
            ["fresh.example.test.", "150"],
            "counted down from 300: {dump}"
        );
        assert!(lines[0].ends_with("; indeterminate"), "{dump}");
        assert!(lines[1].starts_with("stale.example.test."), "{dump}");
        assert!(lines[1].ends_with("; stale, indeterminate"), "{dump}");
        assert_eq!(lines[2], "; 2 RRsets");

        let all = body(&control, "dump").await;
        assert!(all.contains("other.test."), "{all}");
        assert!(all.ends_with("; 3 RRsets\n"), "{all}");
    }

    /// The reply is the reload task's report, so it is SIGHUP's — including a
    /// feed that no longer parses, which keeps the set in force.
    #[tokio::test]
    async fn reload_reports_what_sighup_would() {
        use rdns::rpz::{Feed, PolicyOverride, PolicyStore};
        let dir = crate::testutil::ScratchDir::new("rdnsr-control-reload");
        let feed = |rules: &str| {
            dir.write(
                "feed.rpz.invalid.zone",
                &format!(
                    "$TTL 60\n\
                     @ IN SOA ns.rpz.invalid. hostmaster.rpz.invalid. 1 3600 600 86400 60\n\
                     @ IN NS localhost.\n{rules}"
                ),
            )
        };
        let path = feed("bad.example IN CNAME .\n");
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("the feed loads");
        let serving = crate::testutil::serving_policy(store);
        let (control, controlled) = control(serving.clone());
        let shutdown = rdns::shutdown::Shutdown::new();
        let task = tokio::spawn(crate::reload::reload_task(
            None,
            None,
            Arc::new(Vec::new()),
            serving,
            crate::reload::PolicyReload::default(),
            controlled,
            shutdown.stop_handle(),
        ));

        feed("bad.example IN CNAME .\nworse.example IN CNAME .\n");
        let reloaded = body(&control, "reload").await;
        assert!(
            reloaded.contains("policy zones re-read: 1 of 1 feeds had changed"),
            "{reloaded}"
        );

        feed("this is not a record\n");
        let failed = body(&control, "reload").await;
        assert!(
            failed.contains("the previous ones are still in force"),
            "{failed}"
        );
        assert!(matches!(ask(&control, "reload now").await, Reply::Err(_)));

        shutdown.begin();
        task.await.expect("the task ends on stop");
    }

    #[tokio::test]
    async fn an_unknown_command_names_help() {
        let (control, _rx) = control(crate::testutil::context());
        let Reply::Err(why) = ask(&control, "flushall").await else {
            panic!("an unknown command must be refused");
        };
        assert!(why.contains("help"), "{why}");
        assert!(body(&control, "help").await.contains("flushtree"));
        let Reply::Err(why) = ask(&control, "flushtree a..b").await else {
            panic!("not a name");
        };
        assert!(why.contains("not a name"), "{why}");
    }

    #[tokio::test]
    async fn nta_lists_the_anchors_in_force() {
        let resolving = crate::testutil::context();
        let now = resolving.ctx.clock.now();
        let text = format!(
            "broken.test. {}\nkept.test. {} norecheck\n",
            now + 3600,
            now + 60
        );
        let (set, _) = rdns::nta::NegativeTrustAnchors::parse(&text, now, None).expect("parses");
        resolving.resolver.ntas().update(|held| *held = set);
        let (control, _rx) = control(resolving);
        let listed = body(&control, "nta").await;
        assert!(listed.contains("broken.test. until"), "{listed}");
        assert!(listed.contains("(in 1h 0m), lifted early"), "{listed}");
        assert!(
            listed.contains("kept.test.") && listed.contains("norecheck"),
            "{listed}"
        );
        assert!(listed.ends_with("2 in force\n"), "{listed}");
    }

    /// End to end over a real socket, and the two properties of the bind.
    /// Windows' pipe has its own in `rdns_transport::control`.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_socket_is_private_answers_and_refuses_a_second_server() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = crate::testutil::ScratchDir::new("rdnsr-control");
        let path = dir.join("rdnsr.sock");
        let listener = rdns_transport::control::bind(&path).expect("bind");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let second = rdns_transport::control::bind(&path).expect_err("refused");
        assert!(second.to_string().contains("already listening"), "{second}");

        let shutdown = rdns::shutdown::Shutdown::new();
        let (control, _rx) = control(crate::testutil::context());
        let server = tokio::spawn(rdns_transport::control::serve(
            listener,
            path.clone(),
            Arc::new(control),
            shutdown.stop_handle(),
            shutdown.busy(),
        ));
        let mut client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect");
        client.write_all(b"version\n").await.expect("send");
        let mut reply = String::new();
        client.read_to_string(&mut reply).await.expect("read");
        assert_eq!(
            parse_reply(&reply),
            Reply::Ok(format!("rdnsr {}\n", rdns::VERSION))
        );
        shutdown.begin();
        server.await.expect("joins").expect("no io error");
    }
}
