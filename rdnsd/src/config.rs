//! `--config`: the same settings as the command line, in a file, plus the two
//! things a command line cannot express.
//!
//! **Why this exists.** `--tsig-key alg:name:SECRET` puts a base64 HMAC secret in
//! `argv`, which is world-readable in `ps aux` and `/proc/<pid>/cmdline`, lands in
//! shell history, and gets copied verbatim into the systemd unit the README tells
//! you to write. And at forty zones and six keys the exec line is a multi-kilobyte
//! undiffable string maintained by hand — one `--secondary` per zone, one
//! `--tsig-key` per key, one `--also-notify` per target.
//!
//! Two things the flags could never express, and this can:
//!
//! - **A secret in a file of its own**, so it appears in neither `argv` nor the
//!   main config. `secret-file` reads it, and refuses a file group- or
//!   world-readable on Unix — a key an operator believes is private and is not is
//!   worse than one they know is exposed.
//! - **Per-zone settings.** Every zone used to get the same signing policy, the
//!   same NSEC/NSEC3 choice and the same validity, because there was one flag for
//!   each and no way to say "except this one".
//!
//! **A file and the flags are mutually exclusive, deliberately.** `--config` with
//! `--port` is an error, not a precedence rule. Every precedence rule is a rule
//! somebody has to remember at 3am to explain why the server is not listening
//! where the file says it is — and the failure is silent, because both values are
//! valid. Refusing costs one restart and no confusion. `--check-config`,
//! `--generate-keys` and `--config` itself are the exceptions, since none of them
//! is a setting.
//!
//! **TOML, via `toml` and `serde`, and yes that is nine crates.** Deleting the
//! OpenTelemetry stack removed eighty-three; the argument there was never "no
//! dependencies", it was "no dependencies that do not do anything". This one does
//! the whole job, and a hand-rolled subset parser that misreads a config file is
//! precisely the class of bug this codebase keeps finding — reading configuration
//! wrong is worse than not having any.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::Cli;

/// The whole file.
///
/// `deny_unknown_fields` throughout, and it is the most important line here: a
/// mistyped key that is silently ignored is a setting the operator believes is in
/// force and is not. `require-signd = true` must fail at startup, not serve
/// unsigned zones quietly.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    #[serde(default)]
    pub server: Server,
    #[serde(default)]
    pub signing: Option<Signing>,
    /// TSIG keys, by key name. `[keys."transfer.key."]`.
    #[serde(default)]
    pub keys: BTreeMap<String, Key>,
    /// Per-zone settings, by zone apex. `[zones."example.com."]`.
    #[serde(default)]
    pub zones: BTreeMap<String, ZoneConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Server {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// A directory of `.zone` files. Zones named in `[zones.*]` may add to or
    /// override what is found here.
    pub zone_dir: Option<String>,
    #[serde(default)]
    pub allow_transfer: Vec<String>,
    #[serde(default)]
    pub also_notify: Vec<String>,
    #[serde(default = "default_response_rate")]
    pub response_rate: u32,
    #[serde(default = "default_query_rate")]
    pub query_rate: u32,
    #[serde(default = "default_query_burst")]
    pub query_burst: u32,
    #[serde(default)]
    pub query_rate_exempt: Vec<String>,
    /// Concurrent UDP answers, which is also the number of tasks sharing the
    /// socket. Defaults to the machine's parallelism — see
    /// `crate::default_udp_workers`, which is the same function the flag's
    /// default comes from so the two cannot drift.
    #[serde(default = "crate::default_udp_workers")]
    pub udp_workers: usize,
    pub metrics_listen: Option<String>,
    /// Where `rdnsctl` reaches this server. Unix only, and refused at startup
    /// on Windows rather than ignored — the field parses everywhere so that one
    /// config file can be read on either platform and fail with a sentence
    /// instead of an unknown-key error.
    pub control_socket: Option<PathBuf>,
    #[serde(default)]
    pub allow_partial_load: bool,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            host: default_host(),
            port: default_port(),
            zone_dir: None,
            allow_transfer: Vec::new(),
            also_notify: Vec::new(),
            response_rate: default_response_rate(),
            query_rate: default_query_rate(),
            query_burst: default_query_burst(),
            query_rate_exempt: Vec::new(),
            udp_workers: crate::default_udp_workers(),
            metrics_listen: None,
            control_socket: None,
            allow_partial_load: false,
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    53
}
fn default_response_rate() -> u32 {
    8192
}
fn default_query_rate() -> u32 {
    1000
}
fn default_query_burst() -> u32 {
    200
}

/// Signing defaults, which a `[zones.*]` table may override per zone.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Signing {
    pub key_dir: PathBuf,
    #[serde(default = "default_validity_days")]
    pub validity_days: u32,
    #[serde(default)]
    pub nsec3: bool,
    #[serde(default)]
    pub nsec3_opt_out: bool,
    #[serde(default)]
    pub require_signed: bool,
}

fn default_validity_days() -> u32 {
    30
}

/// One TSIG key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Key {
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// The secret, base64. Mutually exclusive with `secret-file`.
    pub secret: Option<String>,
    /// A file holding the secret, base64, whitespace trimmed. Mode-checked.
    pub secret_file: Option<PathBuf>,
    /// The zones this key may transfer. Empty means every zone — see
    /// `rdns::tsig::TsigKey`, where the same default is spelled out and argued.
    #[serde(default)]
    pub zones: Vec<String>,
    /// The zones this key may rewrite through dynamic UPDATE (RFC 2136 §3.3).
    ///
    /// **Empty means none**, which is the opposite of `zones` directly above.
    /// The argument is at `rdns::tsig::UpdatePolicy`: a transfer hands over a
    /// copy and an update rewrites the original, and no working deployment can
    /// be broken by denying something nothing has ever served. `["*"]` grants
    /// every zone, and has to be typed.
    ///
    /// The two lists sit next to each other with opposite defaults on purpose —
    /// an operator reading this table is deciding both at once, which is where
    /// `CLAUDE.md` §16 says narrowing belongs.
    #[serde(default)]
    pub update_zones: Vec<String>,
}

fn default_algorithm() -> String {
    "hmac-sha256".to_string()
}

/// One zone's own settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ZoneConfig {
    /// The zone file, if it is not simply `<zone-dir>/<name>.zone`.
    pub file: Option<String>,
    /// Masters to replicate this zone from: `addr[:port][#key-name]`, the same
    /// spelling `--secondary` uses after the `zone@`.
    #[serde(default)]
    pub masters: Vec<String>,
    /// Who to NOTIFY for *this* zone, in addition to `server.also-notify`.
    #[serde(default)]
    pub also_notify: Vec<String>,
    /// Per-zone signing overrides. Absent means "use `[signing]`".
    #[serde(default)]
    pub nsec3: Option<bool>,
    #[serde(default)]
    pub nsec3_opt_out: Option<bool>,
    #[serde(default)]
    pub validity_days: Option<u32>,
}

/// What a config file supplies that no flag can, so it cannot be folded into
/// [`Cli`]. Keyed by zone apex, absolute.
#[derive(Debug, Default)]
pub struct PerZone {
    /// Where this zone's file is, when the zone names it rather than being found
    /// in `server.zone-dir`.
    pub files: BTreeMap<String, String>,
    /// NOTIFY targets for this zone in particular, on top of the global ones.
    pub notify: BTreeMap<String, Vec<String>>,
    /// Signing settings that differ from `[signing]`.
    pub signing: BTreeMap<String, ZoneSigningOverride>,
}

/// One zone's departures from the global signing policy.
///
/// `Option` per field rather than a whole policy, so "absent" means *inherit*
/// and not "the default". An operator who sets `nsec3 = true` for one zone must
/// not silently reset that zone's validity to thirty days.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZoneSigningOverride {
    pub nsec3: Option<bool>,
    pub nsec3_opt_out: Option<bool>,
    pub validity_days: Option<u32>,
}

impl ZoneSigningOverride {
    fn is_set(&self) -> bool {
        self.nsec3.is_some() || self.nsec3_opt_out.is_some() || self.validity_days.is_some()
    }
}

/// A zone name as an absolute domain name, which is how everything downstream
/// keys on it. `[zones."example.com"]` and `[zones."example.com."]` are the same
/// zone and must not become two.
/// [`rdns::utils::absolute`], owned. See `TODO.md` #19c.
fn absolute(zone: &str) -> String {
    rdns::utils::absolute(zone).into_owned()
}

impl Config {
    /// Read and validate a config file.
    ///
    /// Validation happens here rather than at first use so that `--check-config`
    /// can be a real dry run: everything that can be known without binding a
    /// socket or reading a zone is known by the time this returns.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the config file {}", path.display()))?;
        let config: Config = toml::from_str(&text)
            .with_context(|| format!("parsing the config file {}", path.display()))?;
        config.check(path)?;
        Ok(config)
    }

    /// Everything that can be checked without touching the network or the zones.
    fn check(&self, path: &Path) -> Result<()> {
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
        if self.server.udp_workers == 0 {
            bail!(
                "server.udp-workers 0 binds the UDP socket and answers nothing on it; \
                 1 is the smallest server"
            );
        }
        for (name, key) in &self.keys {
            match (&key.secret, &key.secret_file) {
                (Some(_), Some(_)) => bail!(
                    "TSIG key {name:?} gives both secret and secret-file; \
                     one of them is not being used and it is not obvious which"
                ),
                (None, None) => {
                    bail!("TSIG key {name:?} has neither secret nor secret-file")
                }
                _ => {}
            }
            if rdns::tsig::TsigAlgorithm::from_name(&key.algorithm).is_none() {
                bail!(
                    "TSIG key {name:?} names algorithm {:?}, which is not one of \
                     hmac-sha1, hmac-sha256, hmac-sha384, hmac-sha512",
                    key.algorithm
                );
            }
        }
        // A zone naming a key that does not exist is the failure mode the flags
        // already refuse: an operator who believes a transfer is authenticated
        // and finds it is not has no way to see that from the outside.
        for (zone, settings) in &self.zones {
            for master in &settings.masters {
                if let Some((_, key)) = master.split_once('#') {
                    if !self.keys.contains_key(key)
                        && !self.keys.keys().any(|k| k.eq_ignore_ascii_case(key))
                    {
                        bail!(
                            "zone {zone:?} replicates from {master:?}, but no [keys.{key:?}] \
                             defines that key"
                        );
                    }
                }
            }
            if settings.nsec3_opt_out == Some(true) && settings.nsec3 == Some(false) {
                bail!("zone {zone:?} asks for nsec3-opt-out with nsec3 off");
            }
            if settings.file.is_none()
                && settings.masters.is_empty()
                && self.server.zone_dir.is_none()
            {
                bail!(
                    "zone {zone:?} has no file, no masters, and there is no \
                     server.zone-dir to find it in"
                );
            }
        }
        if self.zones.is_empty() && self.server.zone_dir.is_none() {
            bail!(
                "{} configures no zones: give server.zone-dir, or a [zones.*] table \
                 with a file or masters",
                path.display()
            );
        }
        Ok(())
    }

    /// The TSIG key specs this config defines, in the `[alg:]name:secret[:zones]`
    /// form `rdns::tsig::TsigKey::parse` takes.
    ///
    /// Reusing the parser rather than building `TsigKey`s directly is deliberate
    /// (`CLAUDE.md` §7): the flag path and the file path then cannot disagree
    /// about what a key means, and every rule the parser enforces — the algorithm
    /// must be known, the secret must be non-empty base64, a zone list may not
    /// have an empty entry — applies to both.
    pub fn tsig_specs(&self) -> Result<Vec<String>> {
        let mut specs = Vec::new();
        for (name, key) in &self.keys {
            let secret = match (&key.secret, &key.secret_file) {
                (Some(secret), None) => secret.trim().to_string(),
                (None, Some(file)) => read_secret_file(file)
                    .with_context(|| format!("the secret for TSIG key {name:?}"))?,
                // `check` has already refused both and neither.
                _ => unreachable!("checked in Config::check"),
            };
            let mut spec = format!("{}:{name}:{secret}", key.algorithm);
            // The update scope is the fifth field, so granting one means
            // spelling the fourth: `*` is how the unrestricted transfer scope is
            // written when it cannot simply be left off the end.
            if !key.zones.is_empty() || !key.update_zones.is_empty() {
                spec.push(':');
                if key.zones.is_empty() {
                    spec.push('*');
                } else {
                    spec.push_str(&key.zones.join(","));
                }
            }
            if !key.update_zones.is_empty() {
                spec.push(':');
                spec.push_str(&key.update_zones.join(","));
            }
            specs.push(spec);
        }
        Ok(specs)
    }

    /// Fold this config into `cli`, returning what does not fit a flag.
    ///
    /// Overwriting `cli` rather than threading a second settings type through the
    /// daemon keeps every downstream caller untouched: the flags and the file
    /// produce the same shape, so there is one code path and not two to drift
    /// apart (`CLAUDE.md` §7). It is sound because the two are mutually exclusive
    /// — nothing in `cli` can be an operator's explicit choice here.
    pub fn apply(&self, cli: &mut Cli) -> Result<PerZone> {
        cli.host = self.server.host.clone();
        cli.port = self.server.port;
        cli.zone_dir = self.server.zone_dir.clone();
        cli.allow_transfer = self.server.allow_transfer.clone();
        cli.also_notify = self.server.also_notify.clone();
        cli.response_rate = self.server.response_rate;
        cli.query_rate = self.server.query_rate;
        cli.query_burst = self.server.query_burst;
        cli.query_rate_exempt = self.server.query_rate_exempt.clone();
        cli.udp_workers = self.server.udp_workers;
        cli.metrics_listen = self.server.metrics_listen.clone();
        cli.control_socket = self.server.control_socket.clone();
        cli.allow_partial_load = self.server.allow_partial_load;
        cli.tsig_key = self.tsig_specs()?;
        cli.secondary = self.secondary_specs();

        if let Some(signing) = &self.signing {
            cli.signing_key_dir = Some(signing.key_dir.clone());
            cli.signature_validity = signing.validity_days;
            cli.nsec3 = signing.nsec3;
            cli.nsec3_opt_out = signing.nsec3_opt_out;
            cli.require_signed = signing.require_signed;
        }

        let mut per_zone = PerZone::default();
        for (zone, settings) in &self.zones {
            let origin = absolute(zone);
            if let Some(file) = &settings.file {
                if self.server.zone_dir.is_some() {
                    bail!(
                        "zone {zone:?} names a file and server.zone-dir is also set: \
                         a zone cannot come from two places, and guessing which \
                         would be a silent choice about what is being served"
                    );
                }
                // The origin comes from the *table key*, not from the file name.
                // That quietly fixes a long-standing trap the flags still have:
                // `--zone-file example.com.zone` derives the origin from the
                // filename, so a mismatch yields NXDOMAIN for everything with no
                // indication why. Here the operator has said the origin out loud.
                per_zone.files.insert(origin.clone(), file.clone());
            }
            if !settings.also_notify.is_empty() {
                per_zone
                    .notify
                    .insert(origin.clone(), settings.also_notify.clone());
            }
            let overrides = ZoneSigningOverride {
                nsec3: settings.nsec3,
                nsec3_opt_out: settings.nsec3_opt_out,
                validity_days: settings.validity_days,
            };
            if overrides.is_set() {
                if self.signing.is_none() {
                    bail!(
                        "zone {zone:?} has signing settings but there is no \
                         [signing] table, so nothing signs it"
                    );
                }
                per_zone.signing.insert(origin, overrides);
            }
        }
        Ok(per_zone)
    }

    /// The `--secondary`-shaped specs this config implies: one per (zone, master).
    pub fn secondary_specs(&self) -> Vec<String> {
        let mut specs = Vec::new();
        for (zone, settings) in &self.zones {
            for master in &settings.masters {
                specs.push(format!("{zone}@{master}"));
            }
        }
        specs
    }
}

/// Read a secret from its own file, refusing one anybody else can read.
///
/// The mode check is the point of the feature, and it lives in
/// `rdns::persist::ensure_private` — the same call the DNSSEC key loader makes,
/// because "is this file private enough to hold a secret" is one question with
/// one answer and a second copy of it would be a second thing to get wrong
/// (`CLAUDE.md` §7). The reasoning is there.
fn read_secret_file(path: &Path) -> Result<String> {
    rdns::persist::ensure_private(path, "a TSIG secret")?;
    let secret = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?
        .trim()
        .to_string();
    if secret.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.check(Path::new("test.toml"))?;
        Ok(config)
    }

    const MINIMAL: &str = r#"
[server]
zone-dir = "./zones"
"#;

    #[test]
    fn a_minimal_config_takes_the_same_defaults_as_the_flags() {
        let config = parse(MINIMAL).expect("parses");
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 53);
        assert_eq!(config.server.query_rate, 1000);
        assert_eq!(config.server.query_burst, 200);
        assert_eq!(config.server.response_rate, 8192);
        assert!(config.signing.is_none());
    }

    /// The most important line in the file. A mistyped key that is silently
    /// ignored is a setting the operator believes is in force and is not —
    /// `require-signd = true` must fail at startup rather than serving unsigned
    /// zones quietly.
    #[test]
    fn a_mistyped_key_is_refused_rather_than_ignored() {
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
[signing]
key-dir = "./keys"
require-signd = true
"#,
        )
        .expect_err("a typo must not be silently ignored");
        assert!(err.to_string().contains("require-signd"), "got: {err}");

        // And at the top level, where a whole section could go missing.
        assert!(parse("[sever]\nport = 53\n").is_err(), "a mistyped table");
    }

    #[test]
    fn a_key_needs_exactly_one_source_of_secret() {
        let both = r#"
[server]
zone-dir = "./zones"
[keys."k."]
secret = "AAECAwQFBgcICQoLDA0ODw=="
secret-file = "/etc/rdns/k"
"#;
        assert!(parse(both).is_err(), "both is ambiguous");

        let neither = r#"
[server]
zone-dir = "./zones"
[keys."k."]
algorithm = "hmac-sha256"
"#;
        assert!(parse(neither).is_err(), "neither is unusable");
    }

    #[test]
    fn an_unknown_algorithm_is_refused_at_load() {
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
[keys."k."]
algorithm = "hmac-md5"
secret = "AAECAwQFBgcICQoLDA0ODw=="
"#,
        )
        .expect_err("MD5 is deprecated and not implemented");
        assert!(err.to_string().contains("hmac-md5"), "got: {err}");
    }

    /// A zone replicating from a master `#key` that no `[keys.*]` defines is the
    /// same failure the flags already refuse: the operator believes the transfer
    /// is authenticated and it is not, and there is no way to see that from
    /// outside.
    #[test]
    fn a_zone_naming_an_undefined_key_is_refused() {
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
[zones."example.com."]
masters = ["192.0.2.1#missing.key."]
"#,
        )
        .expect_err("an undefined key must not load");
        assert!(err.to_string().contains("missing.key."), "got: {err}");
    }

    #[test]
    fn the_key_specs_round_trip_through_the_flag_parser() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
[keys."transfer.key."]
algorithm = "hmac-sha512"
secret = "AAECAwQFBgcICQoLDA0ODw=="
zones = ["example.com.", "other.test."]
"#,
        )
        .expect("parses");
        let specs = config.tsig_specs().expect("specs");
        assert_eq!(specs.len(), 1);
        // The same parser the flag uses, so the two paths cannot disagree about
        // what a key means (`CLAUDE.md` §7).
        let key = rdns::tsig::TsigKey::parse(&specs[0]).expect("the flag parser accepts it");
        assert_eq!(key.name, "transfer.key.");
        assert_eq!(key.algorithm, rdns::tsig::TsigAlgorithm::HmacSha512);
        assert!(key.may_transfer("example.com."));
        assert!(key.may_transfer("other.test."));
        assert!(!key.may_transfer("third.test."));
        assert!(
            !key.may_update("example.com."),
            "a key with no update-zones may rewrite nothing"
        );
    }

    /// `update-zones` reaches the flag parser as the fifth field, including the
    /// case the positional syntax makes awkward: unrestricted for transfers and
    /// scoped for updates, which needs the fourth field written as `*`.
    #[test]
    fn an_update_scope_round_trips_through_the_flag_parser() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
[keys."dhcp.key."]
secret = "AAECAwQFBgcICQoLDA0ODw=="
update-zones = ["dyn.example.com."]
[keys."scoped.key."]
secret = "AAECAwQFBgcICQoLDA0ODw=="
zones = ["example.com."]
update-zones = ["*"]
"#,
        )
        .expect("parses");
        let keys: Vec<rdns::tsig::TsigKey> = config
            .tsig_specs()
            .expect("specs")
            .iter()
            .map(|spec| rdns::tsig::TsigKey::parse(spec).expect("the flag parser accepts it"))
            .collect();

        let dhcp = keys.iter().find(|k| k.name == "dhcp.key.").expect("dhcp");
        assert!(
            dhcp.may_transfer("anything.test."),
            "no zones means the transfer default is untouched"
        );
        assert!(dhcp.may_update("dyn.example.com."));
        assert!(!dhcp.may_update("example.com."));

        let scoped = keys
            .iter()
            .find(|k| k.name == "scoped.key.")
            .expect("scoped");
        assert!(scoped.may_transfer("example.com."));
        assert!(!scoped.may_transfer("other.test."));
        assert_eq!(scoped.update_scope(), &rdns::tsig::UpdatePolicy::Any);
    }

    /// A key with neither list must not grow a trailing colon, which the parser
    /// reads as an empty zone list and refuses.
    #[test]
    fn a_key_with_no_lists_has_three_fields() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
[keys."plain.key."]
secret = "AAECAwQFBgcICQoLDA0ODw=="
"#,
        )
        .expect("parses");
        let specs = config.tsig_specs().expect("specs");
        assert_eq!(specs[0].split(':').count(), 3, "got {:?}", specs[0]);
        rdns::tsig::TsigKey::parse(&specs[0]).expect("and parses");
    }

    #[test]
    fn secondary_specs_are_one_per_zone_and_master() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
[keys."k."]
secret = "AAECAwQFBgcICQoLDA0ODw=="
[zones."example.com."]
masters = ["192.0.2.1", "192.0.2.2:5353#k."]
[zones."other.test."]
masters = ["192.0.2.3"]
"#,
        )
        .expect("parses");
        let mut specs = config.secondary_specs();
        specs.sort();
        assert_eq!(
            specs,
            [
                "example.com.@192.0.2.1",
                "example.com.@192.0.2.2:5353#k.",
                "other.test.@192.0.2.3",
            ]
        );
        // And each one parses as the flag would spell it.
        for spec in &specs {
            rdns::secondary::MasterSpec::parse(spec)
                .unwrap_or_else(|e| panic!("{spec} should parse: {e}"));
        }
    }

    /// A config that configures no zones at all is a server that will answer
    /// REFUSED for everything. That is indistinguishable from a broken deploy, so
    /// it fails at startup instead.
    #[test]
    fn a_config_with_no_zones_at_all_is_refused() {
        assert!(parse("[server]\nport = 5353\n").is_err());
    }

    #[test]
    fn a_burst_of_zero_with_a_rate_is_refused() {
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
query-burst = 0
"#,
        )
        .expect_err("this would refuse every query");
        assert!(err.to_string().contains("query-burst"), "got: {err}");
        // ...but with the limiter off it is meaningless rather than harmful.
        assert!(parse(
            r#"
[server]
zone-dir = "./zones"
query-rate = 0
query-burst = 0
"#
        )
        .is_ok());
    }

    /// Zero workers binds the UDP socket and answers nothing on it. The flag
    /// floors that at 1 instead of refusing it, which is not a contradiction:
    /// the file is where a wrong value can be reported with a line number to
    /// somebody who is editing the whole policy, and `query-burst` above splits
    /// the same way.
    #[test]
    fn no_udp_workers_at_all_is_refused() {
        let config = parse(MINIMAL).expect("parses");
        assert!(
            (2..=32).contains(&config.server.udp_workers),
            "the file's default is the flag's default"
        );
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
udp-workers = 0
"#,
        )
        .expect_err("this would answer no UDP query at all");
        assert!(err.to_string().contains("udp-workers"), "got: {err}");
    }

    #[test]
    fn per_zone_signing_overrides_parse() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
[signing]
key-dir = "./keys"
validity-days = 30
[zones."example.com."]
nsec3 = true
validity-days = 7
[zones."other.test."]
"#,
        )
        .expect("parses");
        let example = &config.zones["example.com."];
        assert_eq!(example.nsec3, Some(true));
        assert_eq!(example.validity_days, Some(7));
        let other = &config.zones["other.test."];
        assert_eq!(other.nsec3, None, "absent means use [signing]");
        assert_eq!(other.validity_days, None);
    }
}
