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
//! is the policy feeds. Every key here is a flag `rdnsr` already has, except
//! the one the file exists for: `[[rpz.feeds]].policy`, which is per feed.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rdns::secondary::MasterSpec;
use serde::Deserialize;

use crate::rpz_transfer::TransferredFeed;
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
    /// TSIG keys, by key name, in `rdnsd`'s spelling: `[keys."partner.key."]`.
    /// A policy feed's `master` names one with `#name` (`TODO.md` #57f).
    #[serde(default)]
    keys: std::collections::BTreeMap<String, Key>,
}

/// One TSIG key, client-side.
///
/// `rdnsd`'s table has `zones` and `update-zones` beside these; a resolver
/// *fetches*, so it authenticates the master and authorizes nothing — those two
/// are a server's answer to "what may this key do" and would be settings that
/// cannot act here (`CLAUDE.md` §15, §16).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Key {
    #[serde(default = "default_tsig_algorithm")]
    algorithm: String,
    /// The secret, base64. Mutually exclusive with `secret-file`.
    secret: Option<String>,
    /// A file holding the secret, base64, whitespace trimmed. Mode-checked, and
    /// refused if anyone but its owner can read it.
    secret_file: Option<PathBuf>,
}

fn default_tsig_algorithm() -> String {
    rdns::tsig::TsigAlgorithm::DEFAULT.config_name().to_string()
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
    /// The feeds, in the order they are consulted: the first zone with a rule
    /// for a query decides it.
    ///
    /// An array of tables and not a map of them, because that order is the
    /// policy and a map would reorder it.
    #[serde(default)]
    feeds: Vec<FeedEntry>,
    /// What a feed's rules mean when it does not say for itself, in
    /// `--rpz-policy`'s spelling. Parsed by `PolicyOverride::from_str`, the
    /// flag's own parser, so the two cannot disagree about what `passthru` is
    /// (`CLAUDE.md` §15).
    policy: Option<String>,
    /// Who may send a NOTIFY asking for the feeds to be re-read.
    #[serde(default)]
    notify_from: Vec<String>,
}

/// One feed: `[[rpz.feeds]]`.
///
/// This is what #63 was filed for. A new feed is introduced by measuring it in
/// `passthru` while the others stay enforced, and `--rpz-policy` can only say
/// it of every feed at once.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct FeedEntry {
    /// Where the feed is read from — and, for a transferred one, where it is
    /// written to. Required either way, which is shape A's whole argument: the
    /// file is the thing that survives a restart (`TODO.md` #57d).
    file: PathBuf,
    /// `zone@master[:port]`, in `rdnsd`'s `--secondary` spelling and parsed by
    /// its parser, so the two cannot disagree about what a master is
    /// (`CLAUDE.md` §7). Absent is a feed somebody else writes, which is how
    /// every feed worked before this.
    master: Option<String>,
    /// Absent inherits `[rpz].policy`, which is §15's `Option` per field for an
    /// override: a feed that says nothing must not be reset to the default
    /// because another one did.
    policy: Option<String>,
    /// What an unrefreshed feed means: `enforce` (the default) or `lift`.
    /// Only a transferred feed can expire, so this without `master` is a
    /// setting that cannot act and is refused (`TODO.md` #57d).
    on_expire: Option<String>,
}

impl Config {
    /// The TSIG keys this config defines, in the `[alg:]name:secret` form
    /// `rdns::tsig::TsigKey::parse` takes.
    ///
    /// Through the parser rather than building keys directly, so this daemon,
    /// `rdnsd` and `rdnsc` cannot disagree about what a key means (§7). No zone
    /// list: the fourth field is a *server's* transfer scope, and a resolver
    /// only ever presents a key.
    ///
    /// A secret that will not read is a key that is left out, and `serve` says
    /// so — the alternative is failing the whole config for a file that may
    /// belong to a feed nobody uses this run.
    fn tsig_specs(&self) -> Vec<String> {
        let mut specs = Vec::new();
        for (name, key) in &self.keys {
            let secret = match (&key.secret, &key.secret_file) {
                (Some(secret), None) => secret.trim().to_string(),
                (None, Some(file)) => match rdns::persist::read_secret(file, "a TSIG secret") {
                    Ok(secret) => secret,
                    Err(e) => {
                        tracing::warn!(
                            "TSIG key {name}: {} could not be read, so this key is not \
                                 defined and any feed naming it will fail: {e}",
                            file.display()
                        );
                        continue;
                    }
                },
                // `check` has already refused both and neither.
                _ => continue,
            };
            specs.push(format!("{}:{name}:{secret}", key.algorithm));
        }
        specs
    }

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
        for (name, key) in &self.keys {
            match (&key.secret, &key.secret_file) {
                (Some(_), Some(_)) => bail!(
                    "TSIG key {name:?} gives both secret and secret-file; \
                     one of them is not being used and it is not obvious which"
                ),
                (None, None) => bail!("TSIG key {name:?} has neither secret nor secret-file"),
                _ => {}
            }
            if rdns::tsig::TsigAlgorithm::from_name(&key.algorithm).is_none() {
                bail!(
                    "TSIG key {name:?} names algorithm {:?}, which is not one of {}",
                    key.algorithm,
                    rdns::tsig::TsigAlgorithm::ACCEPTED_NAMES
                );
            }
        }
        // Through the flag's own parser, so a policy name means one thing.
        if let Some(policy) = &self.rpz.policy {
            policy
                .parse::<rdns::rpz::PolicyOverride>()
                .map_err(|e| anyhow::anyhow!("rpz.policy: {e}"))?;
        }
        // Named by its file rather than by its index: an operator reading this
        // has the file open at the feed, not at the third table.
        for feed in &self.rpz.feeds {
            if let Some(master) = &feed.master {
                MasterSpec::parse(master)
                    .map_err(|e| anyhow::anyhow!("rpz.feeds master {master:?}: {e}"))?;
            }
            if let Some(key) = feed
                .master
                .as_deref()
                .and_then(|m| MasterSpec::parse(m).ok())
                .and_then(|spec| spec.key_name)
            {
                // A key name that names nothing is a transfer the operator
                // believes is signed and is not (§15) — `rdnsd` refuses the
                // same way for `[zones.*].masters`.
                if !self.keys.contains_key(&key)
                    && !self.keys.keys().any(|k| k.eq_ignore_ascii_case(&key))
                {
                    bail!(
                        "rpz.feeds {} transfers with key {key:?}, and no [keys.{key:?}] \
                         defines it",
                        feed.file.display()
                    );
                }
            }
            if let Some(on_expire) = &feed.on_expire {
                on_expire
                    .parse::<crate::rpz_transfer::OnExpire>()
                    .map_err(|e| anyhow::anyhow!("rpz.feeds {}: {e}", feed.file.display()))?;
                if feed.master.is_none() {
                    bail!(
                        "rpz.feeds {}: on-expire needs master. A feed nobody transfers \
                         has no contact to lose, so the setting could never fire",
                        feed.file.display()
                    );
                }
            }
            if let Some(policy) = &feed.policy {
                policy
                    .parse::<rdns::rpz::PolicyOverride>()
                    .map_err(|e| anyhow::anyhow!("rpz.feeds {}: {e}", feed.file.display()))?;
            }
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
        self.server.apply_to(cli);

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

        if let Some(policy) = &self.rpz.policy {
            // `check` has already parsed it.
            cli.rpz_policy = policy.parse().expect("checked in Config::check");
        }
        // The global is the default for a feed that does not say, so it is read
        // after being overwritten above and not from the file again.
        let global = cli.rpz_policy;
        cli.rpz_feeds = self
            .rpz
            .feeds
            .iter()
            .map(|feed| {
                let policy = match &feed.policy {
                    Some(policy) => policy.parse().expect("checked in Config::check"),
                    None => global,
                };
                rdns::rpz::Feed::new(feed.file.clone(), policy)
            })
            .collect();
        cli.rpz_masters = self
            .rpz
            .feeds
            .iter()
            .filter_map(|feed| {
                let master = feed.master.as_ref()?;
                Some(TransferredFeed {
                    spec: MasterSpec::parse(master).expect("checked in Config::check"),
                    // Filled in by `serve`, which owns the keyring: `check` has
                    // already refused a name that defines nothing.
                    key: None,
                    file: feed.file.clone(),
                    on_expire: feed
                        .on_expire
                        .as_deref()
                        .map(|text| text.parse().expect("checked in Config::check"))
                        .unwrap_or_default(),
                })
            })
            .collect();
        cli.rpz_notify_from = self.rpz.notify_from.clone();
        cli.tsig_key = self.tsig_specs();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};
    use rdns::rpz::PolicyOverride;

    fn parse(text: &str) -> Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.check()?;
        Ok(config)
    }

    /// Every `[server]` key this daemon has, set to something that is not its
    /// default. The sibling of `rdnsd`'s fixture of the same name, and for the
    /// same reason: the minimal one compares every value against the default
    /// it already equals.
    const EVERY_SERVER_KEY: &str = r#"
[server]
host = "127.0.0.1"
port = 5353
response-rate = 4096
query-rate = 500
query-burst = 100
query-rate-exempt = ["192.0.2.3"]
max-udp-request = 2048
max-tcp-request = 8192
udp-payload-size = 1400
max-udp-response = 1100
max-inflight-udp = 7
anomaly-interval = 30
anomaly-query-rate = 25.0
anomaly-error-percent = 5.0
anomaly-source-queries = 50
anomaly-source-refusals = 2
metrics-listen = "127.0.0.1:9153"
tls-listen = "127.0.0.1:8530"
quic-listen = "127.0.0.1:8531"
https-listen = "127.0.0.1:8532"
https-path = "/query"
tls-cert = "./cert.pem"
tls-key = "./key.pem"
"#;

    /// Every `[server]` key reaches the flag of the same name, with its value.
    ///
    /// `TODO.md` #103: `deny_unknown_fields` refuses a key the struct does not
    /// declare, and nothing refused a key the struct declared and `apply`
    /// never read. The projection comes out of `server_table!` now, and this
    /// asserts the value rather than "not the default", so a key wired to the
    /// wrong flag fails here too.
    #[test]
    fn every_server_key_reaches_its_flag() {
        let mut cli = Cli::parse_from(["rdnsr"]);
        parse(EVERY_SERVER_KEY)
            .expect("the full config parses")
            .apply(&mut cli);

        macro_rules! reaches {
            ($($field:ident = $want:expr),* $(,)?) => {$(
                assert_eq!(
                    cli.$field,
                    $want,
                    "[server].{} did not reach the flag of that name",
                    stringify!($field).replace('_', "-"),
                );
            )*};
        }
        reaches! {
            host = "127.0.0.1",
            port = 5353,
            response_rate = 4096,
            query_rate = 500,
            query_burst = 100,
            query_rate_exempt = vec!["192.0.2.3".to_string()],
            max_udp_request = 2048,
            max_tcp_request = 8192,
            udp_payload_size = 1400,
            max_udp_response = 1100,
            max_inflight_udp = 7,
            anomaly_interval = 30,
            anomaly_query_rate = 25.0,
            anomaly_error_percent = 5.0,
            anomaly_source_queries = 50,
            anomaly_source_refusals = 2,
            metrics_listen = Some("127.0.0.1:9153".to_string()),
            tls_listen = Some("127.0.0.1:8530".to_string()),
            quic_listen = Some("127.0.0.1:8531".to_string()),
            https_listen = Some("127.0.0.1:8532".to_string()),
            https_path = "/query",
            tls_cert = Some(PathBuf::from("./cert.pem")),
            tls_key = Some(PathBuf::from("./key.pem")),
        }
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
            "rpz" => Some("feeds"),
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
        parse("[rpz]\npolicy = \"passthru\"\n[[rpz.feeds]]\nfile = \"a.rpz\"\n")
            .expect("parses")
            .apply(&mut cli);
        assert_eq!(cli.rpz_policy, rdns::rpz::PolicyOverride::Passthru);
        assert_eq!(feed_paths(&cli), [PathBuf::from("a.rpz")]);
    }

    fn feed_paths(cli: &Cli) -> Vec<PathBuf> {
        cli.feeds().into_iter().map(|f| f.path).collect()
    }

    fn feed_policies(cli: &Cli) -> Vec<PolicyOverride> {
        cli.feeds().into_iter().map(|f| f.policy).collect()
    }

    /// What #63 exists for: one feed is measured in `passthru` while the others
    /// stay enforced.
    ///
    /// Fails against the shape this replaced, where `[rpz].policy` was the only
    /// place a policy could be written and applied to every feed at once.
    #[test]
    fn a_feed_carries_its_own_policy_and_the_others_keep_theirs() {
        let mut cli = Cli::parse_from(["rdnsr"]);
        parse(
            "[[rpz.feeds]]
file = \"court-order.rpz\"

[[rpz.feeds]]
file = \"new-feed.rpz\"
policy = \"passthru\"
",
        )
        .expect("parses")
        .apply(&mut cli);
        assert_eq!(
            feed_paths(&cli),
            [
                PathBuf::from("court-order.rpz"),
                PathBuf::from("new-feed.rpz")
            ],
            "the order of the feeds is the order they are consulted",
        );
        assert_eq!(
            feed_policies(&cli),
            [PolicyOverride::Given, PolicyOverride::Passthru],
        );
    }

    /// Absent means inherit, and what it inherits is the global (§15's `Option`
    /// per field, not a whole struct).
    #[test]
    fn a_feed_that_says_nothing_inherits_the_global_policy() {
        let mut cli = Cli::parse_from(["rdnsr"]);
        parse(
            "[rpz]
policy = \"disabled\"

[[rpz.feeds]]
file = \"a.rpz\"

[[rpz.feeds]]
file = \"b.rpz\"
policy = \"given\"
",
        )
        .expect("parses")
        .apply(&mut cli);
        assert_eq!(
            feed_policies(&cli),
            [PolicyOverride::Disabled, PolicyOverride::Given],
        );
    }

    /// A feed's own policy goes through the flag's parser too, and the error
    /// names the feed rather than its index.
    #[test]
    fn a_misspelled_per_feed_policy_names_the_file() {
        let err = parse("[[rpz.feeds]]\nfile = \"a.rpz\"\npolicy = \"passthur\"\n")
            .expect_err("a misspelled policy");
        let text = err.to_string();
        assert!(text.contains("unknown RPZ policy"), "got: {text}");
        assert!(text.contains("a.rpz"), "which feed: {text}");
    }

    /// The flags fan one policy out over every `--rpz`, which is all a command
    /// line can say.
    #[test]
    fn the_flags_give_every_feed_the_same_policy() {
        let cli = Cli::parse_from([
            "rdnsr",
            "--rpz",
            "a.rpz",
            "--rpz",
            "b.rpz",
            "--rpz-policy",
            "passthru",
        ]);
        assert_eq!(
            feed_paths(&cli),
            [PathBuf::from("a.rpz"), PathBuf::from("b.rpz")]
        );
        assert_eq!(
            feed_policies(&cli),
            [PolicyOverride::Passthru, PolicyOverride::Passthru],
        );
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

    /// #57d shape A: a feed names a master *and* the file it is written to,
    /// because the file is both where the transfer lands and what a restart
    /// begins from.
    ///
    /// Fails against shape B, where a transferred feed has no file at all.
    #[test]
    fn a_transferred_feed_names_a_master_beside_its_file() {
        let mut cli = Cli::parse_from(["rdnsr"]);
        parse(
            "[[rpz.feeds]]
             file = \"malware.rpz.zone\"
             master = \"malware.rpz.example.@192.0.2.9\"
",
        )
        .expect("parses")
        .apply(&mut cli);

        assert_eq!(feed_paths(&cli), [PathBuf::from("malware.rpz.zone")]);
        assert_eq!(cli.rpz_masters.len(), 1);
        assert_eq!(
            cli.rpz_masters[0].spec.zone.as_ref().to_presentation(),
            "malware.rpz.example."
        );
        assert_eq!(cli.rpz_masters[0].file, PathBuf::from("malware.rpz.zone"));

        // A feed nobody transfers is still the ordinary case and starts no task.
        let mut cli = Cli::parse_from(["rdnsr"]);
        parse(
            "[[rpz.feeds]]
file = \"written-by-cron.zone\"
",
        )
        .expect("parses")
        .apply(&mut cli);
        assert!(cli.rpz_masters.is_empty());
    }

    /// A master that does not parse is a startup error with the text in it, not
    /// a feed that silently never refreshes.
    /// #57d's remedy: which way a stale feed fails is the operator's, per feed.
    ///
    /// Fails against a global setting and against a default read off the rules,
    /// both of which the row shows wrong — an `rpz-passthru` feed is an
    /// allowlist and wants the opposite answer from a blocklist.
    #[test]
    fn a_feed_says_what_its_expiry_means_and_defaults_to_enforce() {
        let mut cli = Cli::parse_from(["rdnsr"]);
        parse(
            "[[rpz.feeds]]
             file = \"block.zone\"
             master = \"block.example.@192.0.2.9\"
             [[rpz.feeds]]
             file = \"allow.zone\"
             master = \"allow.example.@192.0.2.9\"
             on-expire = \"lift\"
",
        )
        .expect("parses")
        .apply(&mut cli);

        let ways: Vec<_> = cli.rpz_masters.iter().map(|f| f.on_expire).collect();
        assert_eq!(
            ways,
            [
                crate::rpz_transfer::OnExpire::Enforce,
                crate::rpz_transfer::OnExpire::Lift
            ],
            "the feed that says nothing enforces; the one that says lift lifts"
        );
    }

    /// A setting that could never fire is refused rather than ignored (§15).
    #[test]
    fn on_expire_without_a_master_is_refused() {
        let err = parse(
            "[[rpz.feeds]]
file = \"a.zone\"
on-expire = \"lift\"
",
        )
        .expect_err("a feed nobody transfers cannot expire");
        assert!(
            err.to_string().contains("on-expire needs master"),
            "got: {err}"
        );

        let err = parse(
            "[[rpz.feeds]]
file = \"a.zone\"
master = \"a.example.@192.0.2.9\"
             on-expire = \"ignore\"
",
        )
        .expect_err("an unknown value");
        assert!(err.to_string().contains("unknown on-expire"), "got: {err}");
    }

    /// #57f: a feed's master may name a key, and a name that defines nothing is
    /// refused at startup rather than sending an unsigned transfer.
    #[test]
    fn a_feed_can_name_a_key_and_an_undefined_one_is_refused() {
        let mut cli = Cli::parse_from(["rdnsr"]);
        parse(
            "[keys.\"partner.key.\"]
             secret = \"c2VjcmV0\"
             [[rpz.feeds]]
             file = \"block.zone\"
             master = \"block.example.@192.0.2.9#partner.key.\"
",
        )
        .expect("parses")
        .apply(&mut cli);
        assert_eq!(cli.tsig_key, ["hmac-sha256:partner.key.:c2VjcmV0"]);
        assert_eq!(
            cli.rpz_masters[0].spec.key_name.as_deref(),
            Some("partner.key.")
        );

        let err = parse(
            "[[rpz.feeds]]
             file = \"block.zone\"
             master = \"block.example.@192.0.2.9#nosuch.key.\"
",
        )
        .expect_err("a key that defines nothing");
        assert!(err.to_string().contains("no [keys."), "got: {err}");
    }

    /// The same rules `rdnsd` applies to a key table, because it is the same
    /// table (§7).
    #[test]
    fn a_key_needs_exactly_one_secret_and_a_known_algorithm() {
        let err = parse(
            "[keys.\"k.\"]
secret = \"c2VjcmV0\"
secret-file = \"s\"
",
        )
        .expect_err("two secrets");
        assert!(
            err.to_string().contains("both secret and secret-file"),
            "got: {err}"
        );

        let err = parse(
            "[keys.\"k.\"]
",
        )
        .expect_err("no secret");
        assert!(
            err.to_string().contains("neither secret nor secret-file"),
            "got: {err}"
        );

        let err = parse(
            "[keys.\"k.\"]
secret = \"c2VjcmV0\"
algorithm = \"md5\"
",
        )
        .expect_err("an unknown algorithm");
        assert!(err.to_string().contains("hmac-sha256"), "got: {err}");
    }

    #[test]
    fn a_malformed_master_is_refused_at_startup() {
        let err = parse(
            "[[rpz.feeds]]
file = \"a.zone\"
master = \"192.0.2.9\"
",
        )
        .expect_err("no zone before the '@'");
        assert!(err.to_string().contains("rpz.feeds master"), "got: {err}");
    }

    #[test]
    fn a_burst_of_zero_is_refused_rather_than_silently_fatal() {
        let err = parse("[server]\nquery-burst = 0\n").expect_err("refuses every query");
        assert!(err.to_string().contains("query-burst"), "got: {err}");
        // With the limiter off it is meaningless rather than fatal.
        assert!(parse("[server]\nquery-burst = 0\nquery-rate = 0\n").is_ok());
    }
}
