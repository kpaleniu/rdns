//! `--config`: the same settings as the command line, in a file.
//!
//! The reason this exists is that a *per-feed* setting has nowhere to go on a
//! command line: `--rpz-policy` applies to every `--rpz` zone at once, which is
//! the opposite of how a feed is introduced — one new feed is measured in
//! `passthru` while the others stay enforced (`TODO.md` #63).
//!
//! A file and the flags are mutually exclusive — `--config` with `--port` is an
//! error, not a precedence rule, because both values are valid and the failure
//! would be silent (`CLAUDE.md` §15). `--config` itself is exempt, being a
//! setting of nothing.
//!
//! Three tables and not one: `[server]` is the listeners and the limits,
//! `[resolver]` is what makes this a resolver rather than a server, and `[rpz]`
//! is the policy feeds. Every key here is a flag `rdnsr` already has.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::Cli;

/// The whole file.
///
/// `deny_unknown_fields` throughout, and it is the most important line here: a
/// mistyped key that is silently ignored is a setting the operator believes is
/// in force and is not. `dnssec-validte = true` must fail at startup with a
/// line number, not resolve without validating.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) struct Config {
    #[serde(default)]
    server: Server,
    #[serde(default)]
    resolver: ResolverSection,
    #[serde(default)]
    rpz: Rpz,
}

// `[server]`: the 22 keys both daemons have, from `rdns::server_table!`, then
// `max-inflight-udp`, which is a resolver's shape of `rdnsd`'s `udp-workers`.
// The macro writes `Default` too, so the shared half is spelled once.
rdns::server_table! {
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    struct Server {
        /// How many recursions may be outstanding. No off switch, unlike
        /// `query-rate` — see the flag.
        #[serde(default = "crate::default_max_inflight_udp")]
        max_inflight_udp: usize,
    }
    defaults {
        max_inflight_udp: crate::default_max_inflight_udp(),
    }
}

/// What makes this a resolver: where answers come from, what is kept, what is
/// checked.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct ResolverSection {
    /// Naming any upstream switches this from recursion to forwarding, exactly
    /// as the flag does.
    #[serde(default)]
    upstream: Vec<SocketAddr>,
    root_hints: Option<PathBuf>,
    #[serde(default = "crate::default_cache_size")]
    cache_size: usize,
    #[serde(default)]
    no_cache: bool,
    #[serde(default)]
    dnssec_validate: bool,
    trust_anchor: Option<PathBuf>,
    auto_trust_anchor: Option<PathBuf>,
    #[serde(default = "crate::default_serve_stale")]
    serve_stale: u64,
    #[serde(default)]
    prefetch: bool,
    /// The NAT64 prefix, in `--dns64`'s spelling. Absent is off.
    dns64: Option<Dns64>,
    #[serde(default)]
    dns64_exclude: Vec<String>,
}

impl Default for ResolverSection {
    fn default() -> Self {
        ResolverSection {
            upstream: Vec::new(),
            root_hints: None,
            cache_size: crate::default_cache_size(),
            no_cache: false,
            dnssec_validate: false,
            trust_anchor: None,
            auto_trust_anchor: None,
            serve_stale: crate::default_serve_stale(),
            prefetch: false,
            dns64: None,
            dns64_exclude: Vec::new(),
        }
    }
}

/// `dns64 = true` or `dns64 = "2001:db8::/96"`.
///
/// Two spellings because the flag has two: `--dns64` alone is the well-known
/// prefix (RFC 6052 §2.1) and `--dns64 <prefix>` is a network's own. `true` is
/// how a file says "given without a value"; `false` is off, which is also what
/// leaving the key out means.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Dns64 {
    On(bool),
    Prefix(String),
}

/// The policy feeds (RPZ).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Rpz {
    /// The zone files, in the order they are consulted: the first zone with a
    /// rule for a query decides it.
    #[serde(default)]
    files: Vec<PathBuf>,
    /// What every feed's rules mean, in `--rpz-policy`'s spelling. Parsed by
    /// `PolicyOverride::from_str`, the flag's own parser, so the two cannot
    /// disagree about what `passthru` is (`CLAUDE.md` §15).
    policy: Option<String>,
    /// Who may send a NOTIFY asking for the feeds to be re-read.
    #[serde(default)]
    notify_from: Vec<String>,
}

impl Config {
    /// Read and validate a config file.
    ///
    /// Validation happens here rather than at first use, so that everything
    /// knowable without binding a socket or reading a feed is known by the time
    /// this returns.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the config file {}", path.display()))?;
        let config: Config = toml::from_str(&text)
            .with_context(|| format!("parsing the config file {}", path.display()))?;
        config.check()?;
        Ok(config)
    }

    /// Everything that can be checked without touching the network or a feed.
    fn check(&self) -> Result<()> {
        if self.server.port == 0 {
            bail!("server.port 0 is reserved and cannot be listened on");
        }
        if self.server.query_burst == 0 && self.server.query_rate != 0 {
            bail!(
                "server.query-burst 0 with a non-zero query-rate refuses every query: \
                 a bucket starts full, and a full bucket of nothing has no token to spend"
            );
        }
        // The flag floors this at 1 instead, which is not an inconsistency: a
        // mistyped flag should be wrong rather than fatal, and a config file is
        // the one place a wrong value can be reported with a line number to the
        // operator who is editing the whole policy at once. `query-burst` above
        // splits the same way for the same reason.
        if self.server.max_inflight_udp == 0 {
            bail!(
                "server.max-inflight-udp 0 binds the UDP socket and answers nothing on \
                 it; 1 is the smallest resolver"
            );
        }
        // clap's `requires` for the three listeners, which the file has no
        // equivalent of: a listener with no certificate binds 853 and presents
        // nothing.
        let encrypted = self.server.tls_listen.is_some()
            || self.server.quic_listen.is_some()
            || self.server.https_listen.is_some();
        if encrypted && (self.server.tls_cert.is_none() || self.server.tls_key.is_none()) {
            bail!(
                "server.tls-listen, quic-listen and https-listen need server.tls-cert \
                 and server.tls-key: a listener with no certificate cannot complete a \
                 handshake"
            );
        }
        // Through the flag's own parser, so a policy name means one thing.
        if let Some(policy) = &self.rpz.policy {
            policy
                .parse::<rdns::rpz::PolicyOverride>()
                .map_err(|e| anyhow::anyhow!("rpz.policy: {e}"))?;
        }
        Ok(())
    }

    /// Fold this config into `cli`.
    ///
    /// Overwriting `cli` rather than threading a second settings type through
    /// the daemon keeps every downstream caller untouched: the flags and the
    /// file produce the same shape, so there is one code path and not two to
    /// drift apart (`CLAUDE.md` §7). It is sound because the two are mutually
    /// exclusive — nothing in `cli` can be an operator's explicit choice here.
    pub(crate) fn apply(&self, cli: &mut Cli) {
        cli.host = self.server.host.clone();
        cli.port = self.server.port;
        cli.query_rate = self.server.query_rate;
        cli.query_burst = self.server.query_burst;
        cli.query_rate_exempt = self.server.query_rate_exempt.clone();
        cli.response_rate = self.server.response_rate;
        cli.max_udp_request = self.server.max_udp_request;
        cli.max_tcp_request = self.server.max_tcp_request;
        cli.udp_payload_size = self.server.udp_payload_size;
        cli.max_udp_response = self.server.max_udp_response;
        cli.max_inflight_udp = self.server.max_inflight_udp;
        cli.anomaly_interval = self.server.anomaly_interval;
        cli.anomaly_query_rate = self.server.anomaly_query_rate;
        cli.anomaly_error_percent = self.server.anomaly_error_percent;
        cli.anomaly_source_queries = self.server.anomaly_source_queries;
        cli.anomaly_source_refusals = self.server.anomaly_source_refusals;
        cli.metrics_listen = self.server.metrics_listen.clone();
        cli.tls_listen = self.server.tls_listen.clone();
        cli.quic_listen = self.server.quic_listen.clone();
        cli.https_listen = self.server.https_listen.clone();
        // The flag has a default, so an absent key means "keep it" rather than
        // "clear it" — the `Option` here is the override, not the value (§15).
        if let Some(path) = &self.server.https_path {
            cli.https_path = path.clone();
        }
        cli.tls_cert = self.server.tls_cert.clone();
        cli.tls_key = self.server.tls_key.clone();

        cli.upstream = self.resolver.upstream.clone();
        cli.root_hints = self.resolver.root_hints.clone();
        cli.cache_size = self.resolver.cache_size;
        cli.no_cache = self.resolver.no_cache;
        cli.dnssec_validate = self.resolver.dnssec_validate;
        cli.trust_anchor = self.resolver.trust_anchor.clone();
        cli.auto_trust_anchor = self.resolver.auto_trust_anchor.clone();
        cli.serve_stale = self.resolver.serve_stale;
        cli.prefetch = self.resolver.prefetch;
        cli.dns64 = match &self.resolver.dns64 {
            Some(Dns64::On(true)) => Some(rdns::dns64::WELL_KNOWN_PREFIX.to_string()),
            Some(Dns64::On(false)) | None => None,
            Some(Dns64::Prefix(prefix)) => Some(prefix.clone()),
        };
        cli.dns64_exclude = self.resolver.dns64_exclude.clone();

        cli.rpz = self.rpz.files.clone();
        if let Some(policy) = &self.rpz.policy {
            // `check` has already parsed it.
            cli.rpz_policy = policy.parse().expect("checked in Config::check");
        }
        cli.rpz_notify_from = self.rpz.notify_from.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    fn parse(text: &str) -> Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.check()?;
        Ok(config)
    }

    /// A config file that sets nothing changes no default (`TODO.md` #63e, for
    /// this daemon).
    ///
    /// A tripwire, not a regression test (`CLAUDE.md` §10): both sides read one
    /// function in the crate root, so nothing here can be wrong today. What it
    /// catches is the next setting added with a fresh literal on each side.
    #[test]
    fn an_empty_config_changes_no_flag_default() {
        let mut cli = Cli::parse_from(["rdnsr"]);
        let defaults = Cli::parse_from(["rdnsr"]);
        parse("").expect("the empty config parses").apply(&mut cli);

        macro_rules! same {
            ($($field:ident => $key:literal),* $(,)?) => {$(
                assert_eq!(
                    cli.$field, defaults.$field,
                    concat!("`", $key, "` and its flag default disagree"),
                );
            )*};
        }
        same! {
            host => "server.host",
            port => "server.port",
            query_rate => "server.query-rate",
            query_burst => "server.query-burst",
            response_rate => "server.response-rate",
            max_udp_request => "server.max-udp-request",
            max_tcp_request => "server.max-tcp-request",
            udp_payload_size => "server.udp-payload-size",
            max_udp_response => "server.max-udp-response",
            max_inflight_udp => "server.max-inflight-udp",
            anomaly_interval => "server.anomaly-interval",
            anomaly_query_rate => "server.anomaly-query-rate",
            anomaly_error_percent => "server.anomaly-error-percent",
            anomaly_source_queries => "server.anomaly-source-queries",
            anomaly_source_refusals => "server.anomaly-source-refusals",
            https_path => "server.https-path",
            cache_size => "resolver.cache-size",
            serve_stale => "resolver.serve-stale",
            rpz_policy => "rpz.policy",
        }
    }

    /// Every flag `--config` conflicts with has a key in this file, and the two
    /// spellings match.
    ///
    /// This is what ties the two declarations together, and what #46c is the
    /// precedent for: `[zones."x"].also-notify` was parsed into a field nothing
    /// read, because a key and a flag that mean one setting were written in two
    /// places with nothing comparing them. clap knows which flags conflict with
    /// `--config` — that set *is* "what the file must be able to say" — so the
    /// check is mechanical rather than a list somebody maintains.
    ///
    /// A type error counts as found: what is being asserted is that the key
    /// exists under one of the three tables, not that this value fits it.
    #[test]
    fn every_flag_the_file_replaces_has_a_key_in_it() {
        let command = Cli::command();
        // Asked of each flag, not of `--config`: the conflict is declared on
        // the flags, and `get_arg_conflicts_with` reports what the argument
        // handed to it declares, so asking `--config` returns nothing at all.
        let replaced: Vec<_> = command
            .get_arguments()
            .filter(|arg| {
                command
                    .get_arg_conflicts_with(arg)
                    .iter()
                    .any(|other| other.get_long() == Some("config"))
            })
            .collect();
        assert!(
            replaced.len() > 30,
            "the file replaces {} flags, which is too few to be the whole set",
            replaced.len(),
        );
        // The three flags the file spells differently, because the table name
        // carries half of it. Written down rather than inferred: a rename is a
        // decision, and one that is not declared here is a typo.
        let renamed = |long: &str| match long {
            "rpz" => Some("files"),
            "rpz-policy" => Some("policy"),
            "rpz-notify-from" => Some("notify-from"),
            _ => None,
        };
        let mut missing = Vec::new();
        for arg in replaced {
            let Some(long) = arg.get_long() else { continue };
            let key = renamed(long).unwrap_or(long);
            let found = ["server", "resolver", "rpz"].iter().any(|table| {
                let text = format!(
                    "[{table}]
{key} = 0
"
                );
                match toml::from_str::<Config>(&text) {
                    Ok(_) => true,
                    Err(e) => !e.to_string().contains("unknown field"),
                }
            });
            if !found {
                missing.push(long.to_string());
            }
        }
        assert!(
            missing.is_empty(),
            "flags --config replaces with no key in the file: {missing:?}",
        );
    }

    /// The most important line in the file: a mistyped key is refused, and the
    /// message says which line it is on and what was expected.
    #[test]
    fn a_mistyped_key_is_refused_rather_than_ignored() {
        let err = parse("[resolver]\ndnssec-validte = true\n")
            .expect_err("a typo must not be silently ignored");
        let text = err.to_string();
        assert!(text.contains("dnssec-validte"), "got: {text}");
        assert!(text.contains("line 2"), "no line number: {text}");
        assert!(
            text.contains("dnssec-validate"),
            "no expected-key list: {text}"
        );

        // And at the top level, where a whole section could go missing.
        assert!(parse("[sever]\nport = 53\n").is_err(), "a mistyped table");
    }

    /// The shared fields expand in this crate, so a typo in `[server]` reads
    /// exactly as one in `[resolver]` does: the key's own line, and the list of
    /// what was expected. That is what the flattened-struct shape gave up
    /// (`TODO.md` #63h).
    #[test]
    fn a_typo_in_the_shared_table_keeps_its_line_and_its_suggestions() {
        let err = parse(
            "[server]
hsot = \"127.0.0.1\"
",
        )
        .expect_err("a typo");
        let text = err.to_string();
        assert!(text.contains("unknown field `hsot`"), "got: {text}");
        assert!(text.contains("line 2"), "the key's line: {text}");
        assert!(
            text.contains("expected one of"),
            "no expected-key list: {text}"
        );
        assert!(
            text.contains("max-inflight-udp"),
            "own keys listed too: {text}"
        );
    }

    #[test]
    fn a_tls_listener_needs_a_certificate() {
        let err = parse("[server]\ntls-listen = \"0.0.0.0:853\"\n").expect_err("no certificate");
        assert!(err.to_string().contains("tls-cert"), "got: {err}");
    }

    #[test]
    fn the_policy_is_parsed_by_the_flags_parser() {
        let err = parse("[rpz]\npolicy = \"pasthru\"\n").expect_err("a misspelled policy");
        assert!(err.to_string().contains("unknown RPZ policy"), "got: {err}");

        let mut cli = Cli::parse_from(["rdnsr"]);
        parse("[rpz]\npolicy = \"passthru\"\nfiles = [\"a.rpz\"]\n")
            .expect("parses")
            .apply(&mut cli);
        assert_eq!(cli.rpz_policy, rdns::rpz::PolicyOverride::Passthru);
        assert_eq!(cli.rpz, vec![PathBuf::from("a.rpz")]);
    }

    /// `--dns64` given without a value is the well-known prefix, and the file
    /// spells that `true`.
    #[test]
    fn dns64_is_a_bool_or_a_prefix() {
        let mut cli = Cli::parse_from(["rdnsr"]);
        parse("[resolver]\ndns64 = true\n")
            .expect("parses")
            .apply(&mut cli);
        assert_eq!(cli.dns64.as_deref(), Some(rdns::dns64::WELL_KNOWN_PREFIX));

        let mut cli = Cli::parse_from(["rdnsr"]);
        parse("[resolver]\ndns64 = \"2001:db8::/96\"\n")
            .expect("parses")
            .apply(&mut cli);
        assert_eq!(cli.dns64.as_deref(), Some("2001:db8::/96"));
    }

    #[test]
    fn a_burst_of_zero_is_refused_rather_than_silently_fatal() {
        let err = parse("[server]\nquery-burst = 0\n").expect_err("refuses every query");
        assert!(err.to_string().contains("query-burst"), "got: {err}");
        // With the limiter off it is meaningless rather than fatal.
        assert!(parse("[server]\nquery-burst = 0\nquery-rate = 0\n").is_ok());
    }
}
