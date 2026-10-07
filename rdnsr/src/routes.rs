//! The routed-domain table, from `--forward-zone`, `--stub-zone`,
//! `--no-validate-zone` and `--upstream`, or from the config file's tables
//! written into those same flags (`TODO.md` #172).
//!
//! Every refusal here runs before the dry run answers (`CLAUDE.md` §15), and
//! names the entry: a routed domain that silently routes nothing is a setting
//! the operator believes is in force and is not.

use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, bail};
use rdns::resolver::{Route, RouteKind};
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

/// The table, or the refusal naming what is wrong with it.
pub(crate) fn build(
    forward: &[String],
    stub: &[String],
    no_validate: &[String],
    upstream: &[SocketAddr],
    root_hints: bool,
) -> anyhow::Result<Vec<Route>> {
    let mut routes: Vec<Route> = Vec::new();
    let mut add = |route: Route, flag: &str| -> anyhow::Result<()> {
        if let Some(other) = routes.iter().find(|r| r.name == route.name) {
            bail!(
                "{flag} {}: already routed as a {} zone; one name, one route",
                route.name,
                kind(other.kind)
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
        route.validate = false;
    }
    if root_hints && routes.iter().any(|r| r.name.as_ref().is_root()) {
        bail!("--root-hints says where recursion starts, and `.` is routed, so nothing recurses");
    }
    Ok(routes)
}

fn kind(kind: RouteKind) -> &'static str {
    match kind {
        RouteKind::Forward => "forward",
        RouteKind::Stub => "stub",
    }
}

/// One line per route, for the startup banner.
pub(crate) fn describe(route: &Route) -> String {
    format!(
        "{} zone {} -> {}{}",
        kind(route.kind),
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
        let routes = build(
            &strings(&["corp.test=192.0.2.1,192.0.2.2:5353"]),
            &strings(&["lab.test=[2001:db8::1]:53"]),
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
            build(&strings(f), &strings(s), &strings(n), up, hints)
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
}
