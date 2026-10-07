//! The routed-domain table, from `--forward-zone`, `--stub-zone`,
//! `--no-validate-zone` and `--upstream`, or from the config file's tables
//! written into those same flags (`TODO.md` #172).
//!
//! Every refusal here runs before the dry run answers (`CLAUDE.md` §15), and
//! names the entry: a routed domain that silently routes nothing is a setting
//! the operator believes is in force and is not.

use std::net::{IpAddr, SocketAddr};

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{anyhow, bail};
use rdns::resolver::{LocalZone, Route, RouteKind};
use rdns::zone::Zone;
use rdns::Name;

/// `NAME=ADDR[,ADDR…]`, `ADDR` an address with an optional port, 53 by default.
fn parse_spec(flag: &str, spec: &str) -> anyhow::Result<(Name, Vec<SocketAddr>)> {
    let (name, servers) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("{flag} {spec:?}: want NAME=ADDR[,ADDR...]"))?;
    let name = Name::from_presentation(name.trim())
        .map_err(|e| anyhow!("{flag} {spec:?}: {name:?} is not a name: {e}"))?;
    let servers = servers
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| parse_addr(s).ok_or_else(|| anyhow!("{flag} {spec:?}: {s:?} is not an address")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    if servers.is_empty() {
        bail!("{flag} {spec:?}: no servers to route {name} to");
    }
    Ok((name, servers))
}

/// `ip`, `ip:port` or `[v6]:port`.
fn parse_addr(spec: &str) -> Option<SocketAddr> {
    spec.parse::<SocketAddr>().ok().or_else(|| {
        spec.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
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
pub(crate) fn reload_local(files: &[LocalFile]) {
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
                tracing::warn!("{e:#}; keeping every local zone as it was");
                return;
            }
        }
    }
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
}

/// The table, or the refusal naming what is wrong with it.
pub(crate) fn build(
    forward: &[String],
    stub: &[String],
    local: &[String],
    no_validate: &[String],
    upstream: &[SocketAddr],
    root_hints: bool,
) -> anyhow::Result<(Vec<Route>, Vec<LocalFile>)> {
    let mut routes: Vec<Route> = Vec::new();
    let mut files = Vec::new();
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
        add(Route::forward(name, servers), "--forward-zone")?;
    }
    for spec in stub {
        let (name, servers) = parse_spec("--stub-zone", spec)?;
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
        routes.push(Route::forward(Name::root(), upstream.to_vec()));
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
    if root_hints && routes.iter().any(|r| r.name.as_ref().is_root()) {
        bail!("--root-hints says where recursion starts, and `.` is routed, so nothing recurses");
    }
    Ok((routes, files))
}

fn kind(kind: &RouteKind) -> &'static str {
    match kind {
        RouteKind::Forward => "forward",
        RouteKind::Stub => "stub",
        RouteKind::Local(_) => "local",
    }
}

/// One line per route, for the startup banner.
pub(crate) fn describe(route: &Route, files: &[LocalFile]) -> String {
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
            .map(SocketAddr::to_string)
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

    #[test]
    fn specs_parse_with_and_without_ports() {
        let (routes, _) = build(
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
        let refused = |f: &[&str], s: &[&str], n: &[&str], up: &[SocketAddr], hints: bool| {
            build(&strings(f), &strings(s), &[], &strings(n), up, hints)
                .expect_err("refused")
                .to_string()
        };
        let up: SocketAddr = "192.0.2.9:53".parse().unwrap();
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
                refused(&[".=192.0.2.1"], &[], &[], &[up], false),
                "--upstream",
            ),
            (refused(&[], &[], &[], &[up], true), "--root-hints"),
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
            build(
                &[],
                &[],
                &[format!("{name}={}", path.display())],
                &[],
                &[],
                false,
            )
            .expect("builds")
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
        /// once. Watched failing with the cache check removed: the answer
        /// was in the cache.
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
