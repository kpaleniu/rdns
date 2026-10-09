//! The routed-domain table, from `--forward-zone`, `--stub-zone`,
//! `--no-validate-zone` and `--upstream`, or from the config file's tables
//! written into those same flags (`TODO.md` #172).
//!
//! Every refusal here runs before the dry run answers (`CLAUDE.md` §15), and
//! names the entry: a routed domain that silently routes nothing is a setting
//! the operator believes is in force and is not.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, bail};
use rdns::endpoint::AuthName;
use rdns::resolver::{LocalZone, Route, RouteKind};
use rdns::zone::Zone;
use rdns::Name;

/// One server and, with `+tls=`, the name its certificate must carry.
type Server = (SocketAddr, Option<AuthName>);

/// `NAME=ADDR[,ADDR…]`, `ADDR` as `rdns::endpoint::parse_server` reads it.
fn parse_spec(flag: &str, spec: &str) -> anyhow::Result<(Name, Vec<Server>)> {
    let (name, servers) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("{flag} {spec:?}: want NAME=ADDR[,ADDR...]"))?;
    let name = Name::from_presentation(name.trim())
        .map_err(|e| anyhow!("{flag} {spec:?}: {name:?} is not a name: {e}"))?;
    let servers = servers
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| rdns::endpoint::parse_server(s, spec).map_err(|e| anyhow!("{flag} {e}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    if servers.is_empty() {
        bail!("{flag} {spec:?}: no servers to route {name} to");
    }
    Ok((name, servers))
}

/// A local zone's file, for the SIGHUP reload and the banner (`TODO.md`
/// #174).
#[derive(Debug)]
pub(crate) struct LocalFile {
    pub(crate) path: PathBuf,
    pub(crate) zone: LocalZone,
    /// The bytes last parsed, so an unchanged file is not parsed again
    /// (#71b's shortcut, for the same reason).
    last: Mutex<Vec<u8>>,
}

/// Parse `path` as the zone at `name`, refusing one with no SOA there.
fn read_local(name: &Name, path: &Path) -> anyhow::Result<(Zone, Vec<u8>)> {
    let bytes =
        std::fs::read(path).map_err(|e| anyhow!("--local-zone {name}={}: {e}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let zone = rdns::zone::parse_zone_text_at(&text, &name.to_string(), path)
        .map_err(|e| anyhow!("--local-zone {name}={}: {e}", path.display()))?;
    if zone.serial().is_none() {
        bail!("--local-zone {name}={}: no SOA at {name}", path.display());
    }
    Ok((zone, bytes))
}

/// Re-read every local zone file, all or nothing (`CLAUDE.md` §4): one that
/// does not parse keeps the whole old set in force. Logs each serial that
/// moved.
///
/// Returns the line a `reload` command reports (`TODO.md` #178).
pub(crate) fn reload_local(files: &[LocalFile]) -> String {
    let mut fresh = Vec::new();
    for file in files {
        let name = file.zone.get().origin().to_owned();
        let unchanged = std::fs::read(&file.path)
            .ok()
            .zip(file.last.lock().ok())
            .is_some_and(|(now, last)| now == *last);
        if unchanged {
            continue;
        }
        match read_local(&name, &file.path) {
            Ok(read) => fresh.push((file, read)),
            Err(e) => {
                let line = format!("{e:#}; keeping every local zone as it was");
                tracing::warn!("{line}");
                return line;
            }
        }
    }
    let changed = fresh.len();
    for (file, (zone, bytes)) in fresh {
        let before = file.zone.get().serial();
        let after = zone.serial();
        if before != after {
            tracing::info!(
                zone = %zone.origin(),
                "local zone re-read: serial {} -> {}",
                before.map_or("none".to_string(), |s| s.to_string()),
                after.map_or("none".to_string(), |s| s.to_string()),
            );
        }
        file.zone.replace(zone);
        if let Ok(mut last) = file.last.lock() {
            *last = bytes;
        }
    }
    format!("local zones: {changed} of {} changed", files.len())
}

/// What [`build`] made: the routes, the local zone files, and the servers
/// asked over TLS with the name each must present (`TODO.md` #175).
#[derive(Debug)]
pub(crate) struct Built {
    pub(crate) routes: Vec<Route>,
    pub(crate) files: Vec<LocalFile>,
    pub(crate) tls: HashMap<SocketAddr, AuthName>,
}

/// Record each server's TLS name, refusing one address written two ways:
/// TLS is a property of the server, which every route naming it shares.
fn note_tls(
    tls: &mut HashMap<SocketAddr, AuthName>,
    plain: &mut Vec<SocketAddr>,
    servers: Vec<Server>,
    flag: &str,
) -> anyhow::Result<Vec<SocketAddr>> {
    let mut addrs = Vec::new();
    for (addr, name) in servers {
        let clash = match &name {
            Some(name) => plain.contains(&addr) || tls.get(&addr).is_some_and(|n| n != name),
            None => tls.contains_key(&addr),
        };
        if clash {
            bail!("{flag}: {addr} is written with two different TLS settings; one server, one way");
        }
        match name {
            Some(name) => {
                tls.insert(addr, name);
            }
            None => plain.push(addr),
        }
        addrs.push(addr);
    }
    Ok(addrs)
}

/// The table, or the refusal naming what is wrong with it.
pub(crate) fn build(
    forward: &[String],
    stub: &[String],
    local: &[String],
    no_validate: &[String],
    upstream: &[String],
    root_hints: bool,
) -> anyhow::Result<Built> {
    let mut routes: Vec<Route> = Vec::new();
    let mut files = Vec::new();
    let mut tls = HashMap::new();
    let mut plain = Vec::new();
    let mut add = |route: Route, flag: &str| -> anyhow::Result<()> {
        if let Some(other) = routes.iter().find(|r| r.name == route.name) {
            bail!(
                "{flag} {}: already routed as a {} zone; one name, one route",
                route.name,
                kind(&other.kind)
            );
        }
        routes.push(route);
        Ok(())
    };
    for spec in forward {
        let (name, servers) = parse_spec("--forward-zone", spec)?;
        let servers = note_tls(&mut tls, &mut plain, servers, "--forward-zone")?;
        add(Route::forward(name, servers), "--forward-zone")?;
    }
    for spec in stub {
        let (name, servers) = parse_spec("--stub-zone", spec)?;
        // A stub zone's servers are authorities, and encrypting to those is
        // RFC 9539's question, not taken here.
        if servers.iter().any(|(_, tls)| tls.is_some()) {
            bail!("--stub-zone {spec:?}: +tls= is for forward zones; a stub's servers are authorities");
        }
        let servers = note_tls(&mut tls, &mut plain, servers, "--stub-zone")?;
        add(Route::stub(name, servers), "--stub-zone")?;
    }
    for spec in local {
        let (name, path) = spec
            .split_once('=')
            .ok_or_else(|| anyhow!("--local-zone {spec:?}: want NAME=PATH"))?;
        let name = Name::from_presentation(name.trim())
            .map_err(|e| anyhow!("--local-zone {spec:?}: {e}"))?;
        if rdns::special_names::is_special_use(name.as_ref()) {
            bail!("--local-zone {name}: a special-use name, answered by the protocol's rules");
        }
        let path = PathBuf::from(path.trim());
        let (zone, bytes) = read_local(&name, &path)?;
        let zone = LocalZone::new(zone);
        add(Route::local(zone.clone()), "--local-zone")?;
        files.push(LocalFile {
            path,
            zone,
            last: Mutex::new(bytes),
        });
    }
    if !upstream.is_empty() {
        if routes.iter().any(|r| r.name.as_ref().is_root()) {
            bail!("--upstream is a forward zone at `.`, and `.` is routed already");
        }
        let servers = upstream
            .iter()
            .map(|s| rdns::endpoint::parse_server(s, s).map_err(|e| anyhow!("--upstream {e}")))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let servers = note_tls(&mut tls, &mut plain, servers, "--upstream")?;
        routes.push(Route::forward(Name::root(), servers));
    }
    for name in no_validate {
        let parsed = Name::from_presentation(name)
            .map_err(|e| anyhow!("--no-validate-zone {name:?}: {e}"))?;
        let Some(route) = routes.iter_mut().find(|r| r.name == parsed) else {
            bail!("--no-validate-zone {name}: no routed domain of that name");
        };
        if matches!(route.kind, RouteKind::Local(_)) {
            bail!("--no-validate-zone {name}: a local zone is never validated already");
        }
        route.validate = false;
    }
    // RFC 8806 §1: the resolver "validates all responses from the root
    // service on the same host" (`TODO.md` #177).
    if routes
        .iter()
        .any(|r| r.name.as_ref().is_root() && r.kind == RouteKind::Stub && !r.validate)
    {
        bail!(
            "--no-validate-zone .: a stub zone at the root is a local root, which RFC 8806 \
             §1 requires be validated"
        );
    }
    if root_hints && routes.iter().any(|r| r.name.as_ref().is_root()) {
        bail!("--root-hints says where recursion starts, and `.` is routed, so nothing recurses");
    }
    Ok(Built { routes, files, tls })
}

fn kind(kind: &RouteKind) -> &'static str {
    match kind {
        RouteKind::Forward => "forward",
        RouteKind::Stub => "stub",
        RouteKind::Local(_) => "local",
    }
}

/// One line per route, for the startup banner: each server with its
/// authentication name when it is asked over TLS.
pub(crate) fn describe(
    route: &Route,
    files: &[LocalFile],
    tls: &HashMap<SocketAddr, AuthName>,
) -> String {
    if let RouteKind::Local(zone) = &route.kind {
        let held = zone.get();
        let path = files
            .iter()
            .find(|f| f.zone == *zone)
            .map_or(String::new(), |f| f.path.display().to_string());
        return format!(
            "local zone {} from {path}, serial {}, {} records",
            route.name,
            held.serial().map_or("none".to_string(), |s| s.to_string()),
            held.records().len()
        );
    }
    format!(
        "{} zone {} -> {}{}",
        kind(&route.kind),
        route.name,
        route
            .servers
            .iter()
            .map(|addr| match tls.get(addr) {
                Some(name) => format!("{addr}+tls={name}"),
                None => addr.to_string(),
            })
            .collect::<Vec<_>>()
            .join(","),
        if route.validate {
            ""
        } else {
            ", not validated"
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(specs: &[&str]) -> Vec<String> {
        specs.iter().map(|s| s.to_string()).collect()
    }

    /// `+tls=` defaults the port to 853 (RFC 7858 §3.1), keeps a stated one,
    /// and the same server may be named by two routes written the same way.
    #[test]
    fn a_tls_server_is_recorded_with_its_name() {
        let built = build(
            &strings(&[
                "corp.test=192.0.2.1+tls=dot.test,192.0.2.2",
                "lab.test=192.0.2.1+tls=dot.test",
            ]),
            &[],
            &[],
            &[],
            &strings(&["[2001:db8::1]:8853+tls=dot.example"]),
            false,
        )
        .expect("builds");
        let tls_addr: SocketAddr = "192.0.2.1:853".parse().unwrap();
        assert_eq!(built.routes[0].servers[0], tls_addr);
        assert_eq!(built.routes[0].servers[1].port(), 53);
        assert_eq!(built.tls.len(), 2);
        assert_eq!(built.tls[&tls_addr].to_string(), "dot.test");
        assert_eq!(
            describe(&built.routes[2], &[], &built.tls),
            "forward zone . -> [2001:db8::1]:8853+tls=dot.example"
        );
    }

    #[test]
    fn specs_parse_with_and_without_ports() {
        let Built { routes, .. } = build(
            &strings(&["corp.test=192.0.2.1,192.0.2.2:5353"]),
            &strings(&["lab.test=[2001:db8::1]:53"]),
            &[],
            &strings(&["corp.test"]),
            &[],
            false,
        )
        .expect("builds");
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].servers[0].port(), 53);
        assert_eq!(routes[0].servers[1].port(), 5353);
        assert!(!routes[0].validate);
        assert_eq!(routes[1].kind, RouteKind::Stub);
    }

    /// Each refusal names the entry.
    #[test]
    fn the_refusals() {
        let refused = |f: &[&str], s: &[&str], n: &[&str], up: &[String], hints: bool| {
            build(&strings(f), &strings(s), &[], &strings(n), up, hints)
                .expect_err("refused")
                .to_string()
        };
        let up = "192.0.2.9:53".to_string();
        for (message, wants) in [
            (
                refused(&["a..b=192.0.2.1"], &[], &[], &[], false),
                "not a name",
            ),
            (refused(&["corp.test="], &[], &[], &[], false), "no servers"),
            (
                refused(&["corp.test=nowhere"], &[], &[], &[], false),
                "not an address",
            ),
            (
                refused(
                    &["corp.test=192.0.2.1"],
                    &["corp.test=192.0.2.2"],
                    &[],
                    &[],
                    false,
                ),
                "already routed",
            ),
            (
                refused(
                    &["a.test=192.0.2.1", "A.TEST.=192.0.2.2"],
                    &[],
                    &[],
                    &[],
                    false,
                ),
                "already routed",
            ),
            (
                refused(&[], &[], &["corp.test"], &[], false),
                "no routed domain",
            ),
            (
                refused(&[".=192.0.2.1"], &[], &[], std::slice::from_ref(&up), false),
                "--upstream",
            ),
            (refused(&[], &[], &[], &[up], true), "--root-hints"),
            (
                refused(&[], &[".=127.0.0.1:5353"], &["."], &[], false),
                "RFC 8806",
            ),
            (
                refused(
                    &[],
                    &["lab.test=192.0.2.1+tls=ns.lab.test"],
                    &[],
                    &[],
                    false,
                ),
                "forward zones",
            ),
            (
                refused(&["corp.test=192.0.2.1#key"], &[], &[], &[], false),
                "TSIG key on a forwarder",
            ),
            (
                refused(
                    &["a.test=192.0.2.1+tls=dot.test", "b.test=192.0.2.1:853"],
                    &[],
                    &[],
                    &[],
                    false,
                ),
                "two different TLS settings",
            ),
            (
                refused(
                    &["a.test=192.0.2.1+tls=one.test"],
                    &[],
                    &[],
                    &["192.0.2.1+tls=two.test".to_string()],
                    false,
                ),
                "two different TLS settings",
            ),
        ] {
            assert!(message.contains(wants), "{wants}: {message}");
        }
    }

    mod local {
        use super::*;
        use crate::answer::handle_query;
        use crate::testutil::{message, nm, serving, test_peer, test_shell, ScratchDir};
        use rdns::rpz::PolicyZones;
        use rdns::validation::Transport;
        use rdns::{DnsMessage, OpCode, ResponseCode};
        use std::sync::Arc;

        const ZONE: &str = "$TTL 300\n@ IN SOA ns admin 1 3600 600 86400 300\n@ IN NS ns\nns IN A 10.0.0.2\nwww IN A 10.0.0.1\n";

        fn held(dir: &ScratchDir, name: &str, text: &str) -> (Vec<Route>, Vec<LocalFile>) {
            let path = dir.write("local.zone", text);
            let built = build(
                &[],
                &[],
                &[format!("{name}={}", path.display())],
                &[],
                &[],
                false,
            )
            .expect("builds");
            (built.routes, built.files)
        }

        fn resolving(routes: Vec<Route>, policy: PolicyZones) -> Arc<crate::answer::Resolving> {
            let resolver = rdns::resolver::Resolver::new(rdns::resolver::ResolverConfig {
                routes,
                // Nothing here may leave the host.
                root_hints: vec!["127.0.0.1:1".parse().expect("an address")],
                ..Default::default()
            });
            serving(Arc::new(resolver), test_shell(), policy)
        }

        async fn ask(
            serving: &crate::answer::Resolving,
            name: &str,
            qtype: rdns::Rtype,
        ) -> DnsMessage {
            let mut msg =
                DnsMessage::try_from_bytes(&message(OpCode::Query, false)).expect("parses");
            msg.queries[0].qname = nm(name);
            msg.queries[0].qtype = rdns::Qtype::of(qtype);
            let mut edns = rdns::Edns::with_payload_size(1232);
            edns.do_bit = true;
            msg.set_edns(edns);
            let bytes = handle_query(
                msg.to_bytes_within(512).expect("serialize"),
                test_peer(),
                rdns::clock::current_unix_timestamp(),
                serving,
                Transport::Udp,
            )
            .await
            .expect("answered");
            DnsMessage::try_from_bytes(&bytes).expect("a reply")
        }

        /// AA set, AD clear, no EDE, and not cached so a reload is seen at
        /// once. Fails with the cache check removed: the answer is in the
        /// cache.
        #[tokio::test]
        async fn a_local_answer_is_authoritative_and_not_cached() {
            let dir = ScratchDir::new("local-zone");
            let (routes, _) = held(&dir, "corp.test.", ZONE);
            let serving = resolving(routes, PolicyZones::default());
            let reply = ask(&serving, "www.corp.test.", rdns::record_types::A).await;
            assert_eq!(reply.rcode, ResponseCode::Ok);
            assert!(reply.authoritive && !reply.ad);
            let options = reply.edns.expect("the OPT").options().expect("options");
            assert!(options.is_empty(), "no EDE: {options:?}");
            assert!(serving
                .caches
                .answer(
                    nm("www.corp.test.").as_ref(),
                    rdns::Qtype::of(rdns::record_types::A),
                    false
                )
                .is_none());
        }

        /// RPZ runs first, before local zones as before everything else.
        #[tokio::test]
        async fn a_policy_rule_blocks_a_local_name() {
            let dir = ScratchDir::new("local-zone-rpz");
            let (routes, _) = held(&dir, "corp.test.", ZONE);
            let rules = "$TTL 60\n@ IN SOA ns.rpz.invalid. h.rpz.invalid. 1 3600 600 86400 60\nwww.corp.test IN CNAME .\n";
            let zone = rdns::zone::parse_zone_file(rules, "rpz.invalid.").expect("parses");
            let policy = PolicyZones::from_zones(vec![rdns::rpz::PolicyZone::new(
                zone,
                rdns::rpz::PolicyOverride::Given,
            )
            .expect("indexes")]);
            let reply = ask(
                &resolving(routes, policy),
                "www.corp.test.",
                rdns::record_types::A,
            )
            .await;
            assert_eq!(reply.rcode, ResponseCode::NoSuchDomain);
        }

        /// A local zone at an empty zone's apex overrides it (ADR 0008).
        #[tokio::test]
        async fn a_local_zone_overrides_an_empty_zone() {
            let dir = ScratchDir::new("local-zone-reverse");
            let text = "$TTL 300\n@ IN SOA ns admin 1 3600 600 86400 300\n@ IN NS ns\nns IN A 10.0.0.2\n1.0.0 IN PTR www.corp.test.\n";
            let (routes, _) = held(&dir, "10.in-addr.arpa.", text);
            let reply = ask(
                &resolving(routes, PolicyZones::default()),
                "1.0.0.10.in-addr.arpa.",
                rdns::record_types::PTR,
            )
            .await;
            assert_eq!(reply.rcode, ResponseCode::Ok);
            assert_eq!(reply.answers.len(), 1);
        }

        /// SIGHUP serves an edited file; a broken one keeps every old zone.
        #[tokio::test]
        async fn a_reload_is_all_or_nothing() {
            let dir = ScratchDir::new("local-zone-reload");
            let (routes, files) = held(&dir, "corp.test.", ZONE);
            let serving = resolving(routes, PolicyZones::default());

            dir.write(
                "local.zone",
                &ZONE
                    .replace("10.0.0.1", "10.0.0.9")
                    .replace(" 1 3600", " 2 3600"),
            );
            reload_local(&files);
            let reply = ask(&serving, "www.corp.test.", rdns::record_types::A).await;
            assert_eq!(
                reply.answers[0].rdata.parse().unwrap(),
                rdns::ParsedRecord::A("10.0.0.9".parse().unwrap())
            );

            dir.write("local.zone", "$TTL 300\n@ IN SOA broken\n");
            reload_local(&files);
            let reply = ask(&serving, "www.corp.test.", rdns::record_types::A).await;
            assert_eq!(
                reply.answers[0].rdata.parse().unwrap(),
                rdns::ParsedRecord::A("10.0.0.9".parse().unwrap()),
                "the broken file left the zone as it was"
            );
        }

        /// The refusals: a special-use name, no SOA at the name, a name also
        /// routed another way, a file that does not parse.
        #[test]
        fn the_local_zone_refusals() {
            let dir = ScratchDir::new("local-zone-refusals");
            let good = dir.write("good.zone", ZONE);
            let refused = |forward: &[String], local: &[String]| {
                build(forward, &[], local, &[], &[], false)
                    .expect_err("refused")
                    .to_string()
            };
            let at = |name: &str, path: &std::path::Path| format!("{name}={}", path.display());

            assert!(refused(&[], &[at("localhost.", &good)]).contains("special-use"));
            let other = dir.write("other.zone", "$TTL 300\nwww IN A 10.0.0.1\n");
            assert!(refused(&[], &[at("corp.test.", &other)]).contains("no SOA"));
            assert!(refused(
                &["corp.test=192.0.2.1".to_string()],
                &[at("corp.test.", &good)]
            )
            .contains("already routed"));
            let broken = dir.write("broken.zone", "$TTL 300\n@ IN SOA broken\n");
            assert!(refused(&[], &[at("corp.test.", &broken)]).contains("corp.test."));
        }
    }
}
