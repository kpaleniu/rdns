//! `--config`: the same settings as the command line, in a file, plus two things
//! the flags cannot express.
//!
//! - A secret in a file of its own, in neither `argv` (where `ps` and shell
//!   history expose it) nor the main config. `secret-file` refuses one that is
//!   group- or world-readable on Unix.
//! - Per-zone settings: one flag each meant one signing policy for every zone.
//!
//! A file and the flags are mutually exclusive — `--config` with `--port` is an
//! error, not a precedence rule, because both values are valid and the failure
//! would be silent. `--check-config`, `--generate-keys` and `--config` itself are
//! exempt, being settings of nothing.

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
pub(crate) struct Config {
    #[serde(default)]
    server: Server,
    #[serde(default)]
    signing: Option<Signing>,
    /// TSIG keys, by key name. `[keys."transfer.key."]`.
    #[serde(default)]
    keys: BTreeMap<String, Key>,
    /// Per-zone settings, by zone apex. `[zones."example.com."]`.
    #[serde(default)]
    zones: BTreeMap<String, ZoneConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Server {
    #[serde(default = "crate::default_host")]
    host: String,
    #[serde(default = "crate::default_port")]
    port: u16,
    /// A directory of `.zone` files. Zones named in `[zones.*]` may add to or
    /// override what is found here.
    zone_dir: Option<String>,
    #[serde(default)]
    allow_transfer: Vec<String>,
    #[serde(default)]
    also_notify: Vec<String>,
    #[serde(default = "crate::default_response_rate")]
    response_rate: u32,
    #[serde(default = "crate::default_query_rate")]
    query_rate: u32,
    #[serde(default = "crate::default_query_burst")]
    query_burst: u32,
    #[serde(default)]
    query_rate_exempt: Vec<String>,
    /// Largest request accepted, per transport, in octets. The UDP one is
    /// floored at the advertised payload size — see `crate::admission_limits`.
    #[serde(default = "crate::default_max_udp_request")]
    max_udp_request: u16,
    #[serde(default = "crate::default_max_tcp_request")]
    max_tcp_request: u16,
    /// What every reply's OPT advertises this server can reassemble, and the
    /// largest UDP reply it will send. Both floored at 512 — see
    /// `rdns::UdpSizes`.
    #[serde(default = "crate::default_udp_payload_size")]
    udp_payload_size: u16,
    #[serde(default = "crate::default_max_udp_response")]
    max_udp_response: u16,
    /// How often the anomaly warnings run, in seconds; 0 is off. The four
    /// thresholds below are per interval.
    #[serde(default = "crate::default_anomaly_interval")]
    anomaly_interval: u64,
    #[serde(default = "crate::default_anomaly_query_rate")]
    anomaly_query_rate: f64,
    #[serde(default = "crate::default_anomaly_error_percent")]
    anomaly_error_percent: f64,
    #[serde(default = "crate::default_anomaly_source_queries")]
    anomaly_source_queries: u64,
    #[serde(default = "crate::default_anomaly_source_refusals")]
    anomaly_source_refusals: u64,
    /// Concurrent UDP answers, which is also the number of tasks sharing the
    /// socket. Defaults to the machine's parallelism — see
    /// `crate::default_udp_workers`, which is the same function the flag's
    /// default comes from so the two cannot drift.
    #[serde(default = "crate::default_udp_workers")]
    udp_workers: usize,
    metrics_listen: Option<String>,
    /// Where the dnstap query stream goes: `tcp:<addr:port>` or `file:<path>`.
    /// Absent is off.
    dnstap: Option<String>,
    /// How large a dnstap *capture file* may grow before the writing stops.
    /// 0 is no limit; ignored for a `tcp:` target.
    #[serde(default = "crate::default_dnstap_max_bytes")]
    dnstap_max_bytes: u64,
    /// Where to answer DNS over TLS (RFC 7858), and with what. All three or
    /// none: `apply` refuses a listener with no certificate, because the
    /// config file has no equivalent of clap's `requires` and would otherwise
    /// bind 853 with nothing to present on it.
    tls_listen: Option<String>,
    quic_listen: Option<String>,
    https_listen: Option<String>,
    https_path: Option<String>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    /// Trust anchors for transfers this server *fetches* over TLS
    /// (RFC 9103), and whether one that arrives must have been encrypted.
    /// Separate settings because they are separate directions: a server can be
    /// a secondary over XoT, a primary that insists on it, or both.
    transfer_tls_ca: Option<PathBuf>,
    /// The certificate this server presents to a master that asks for one
    /// (RFC 9103 §7.5's mutual TLS). Both keys or neither; `check` says so,
    /// because a chain with no key cannot be presented.
    transfer_tls_cert: Option<PathBuf>,
    transfer_tls_key: Option<PathBuf>,
    #[serde(default)]
    transfer_tls_only: bool,
    /// Where `rdnsctl` reaches this server. Unix only, and refused at startup
    /// on Windows rather than ignored — the field parses everywhere so that one
    /// config file can be read on either platform and fail with a sentence
    /// instead of an unknown-key error.
    control_socket: Option<PathBuf>,
    #[serde(default)]
    allow_partial_load: bool,
}

impl Default for Server {
    fn default() -> Self {
        Server {
            host: crate::default_host(),
            port: crate::default_port(),
            zone_dir: None,
            allow_transfer: Vec::new(),
            also_notify: Vec::new(),
            response_rate: crate::default_response_rate(),
            query_rate: crate::default_query_rate(),
            query_burst: crate::default_query_burst(),
            query_rate_exempt: Vec::new(),
            max_udp_request: crate::default_max_udp_request(),
            max_tcp_request: crate::default_max_tcp_request(),
            udp_payload_size: crate::default_udp_payload_size(),
            max_udp_response: crate::default_max_udp_response(),
            anomaly_interval: crate::default_anomaly_interval(),
            anomaly_query_rate: crate::default_anomaly_query_rate(),
            anomaly_error_percent: crate::default_anomaly_error_percent(),
            anomaly_source_queries: crate::default_anomaly_source_queries(),
            anomaly_source_refusals: crate::default_anomaly_source_refusals(),
            udp_workers: crate::default_udp_workers(),
            metrics_listen: None,
            dnstap: None,
            dnstap_max_bytes: crate::default_dnstap_max_bytes(),
            tls_listen: None,
            quic_listen: None,
            https_listen: None,
            https_path: None,
            tls_cert: None,
            tls_key: None,
            transfer_tls_ca: None,
            transfer_tls_cert: None,
            transfer_tls_key: None,
            transfer_tls_only: false,
            control_socket: None,
            allow_partial_load: false,
        }
    }
}

/// Signing defaults, which a `[zones.*]` table may override per zone.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Signing {
    key_dir: PathBuf,
    #[serde(default = "crate::default_validity_days")]
    validity_days: u32,
    #[serde(default)]
    nsec3: bool,
    #[serde(default)]
    nsec3_opt_out: bool,
    #[serde(default)]
    require_signed: bool,
}

/// One TSIG key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Key {
    #[serde(default = "default_algorithm")]
    algorithm: String,
    /// The secret, base64. Mutually exclusive with `secret-file`.
    secret: Option<String>,
    /// A file holding the secret, base64, whitespace trimmed. Mode-checked.
    secret_file: Option<PathBuf>,
    /// The zones this key may transfer. Empty means every zone — see
    /// `rdns::tsig::TsigKey`, where the same default is spelled out and argued.
    #[serde(default)]
    zones: Vec<String>,
    /// The zones this key may rewrite through dynamic UPDATE (RFC 2136 §3.3).
    ///
    /// Empty means none, which is the opposite of `zones` directly above.
    /// The argument is at `rdns::tsig::UpdatePolicy`: a transfer hands over a
    /// copy and an update rewrites the original, and no working deployment can
    /// be broken by denying something nothing has ever served. `["*"]` grants
    /// every zone, and has to be typed.
    ///
    /// The two lists sit next to each other with opposite defaults on purpose —
    /// an operator reading this table is deciding both at once, which is where
    /// `CLAUDE.md` §16 says narrowing belongs.
    #[serde(default)]
    update_zones: Vec<String>,
}

fn default_algorithm() -> String {
    "hmac-sha256".to_string()
}

/// One zone's own settings.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct ZoneConfig {
    /// The zone file, if it is not simply `<zone-dir>/<name>.zone`.
    file: Option<String>,
    /// Masters to replicate this zone from: `addr[:port][#key-name][+tls=name]`,
    /// the same spelling `--secondary` uses after the `zone@` — one parser, so
    /// the flag and the file cannot disagree (`CLAUDE.md` §15). The `+tls=`
    /// half is RFC 9103's transfer over TLS and needs
    /// `server.transfer-tls-ca`.
    #[serde(default)]
    masters: Vec<String>,
    /// Who to NOTIFY for *this* zone, in addition to `server.also-notify`.
    #[serde(default)]
    also_notify: Vec<String>,
    /// Whether this zone is a catalog to consume rather than a zone to serve
    /// (RFC 9432): the zones it lists are replicated from the same masters,
    /// with the same key.
    ///
    /// It is still replicated and served like any other zone — a catalog is an
    /// ordinary zone (§5.1) — so this adds a reading of it, and takes nothing
    /// away.
    #[serde(default)]
    catalog: bool,
    /// Members of this catalog carrying one of these group values are fetched
    /// differently (RFC 9432 §4.3.2), keyed by the group value.
    ///
    /// `[zones."catalog.invalid.".groups."operator-x"]`. Per catalog zone and
    /// not globally, which is the shape §4.3.2 names: "Implementations MAY
    /// facilitate mapping of a specific group value to a specific configuration
    /// configurable on a per catalog zone basis" — a producer may publish one
    /// catalog to several consumer operators who each agreed different values.
    ///
    /// Only on a `catalog = true` zone; a group on anything else is refused,
    /// because nothing would ever read it.
    #[serde(default)]
    groups: BTreeMap<String, GroupConfig>,
    /// Per-zone signing overrides. Absent means "use `[signing]`".
    #[serde(default)]
    nsec3: Option<bool>,
    #[serde(default)]
    nsec3_opt_out: Option<bool>,
    #[serde(default)]
    validity_days: Option<u32>,
    /// Where this zone's apex DNSKEY RRset gets its signature. Absent is
    /// `local`, which is every ordinary zone.
    #[serde(default)]
    dnskey_rrsig: Option<DnskeyRrsig>,
}

/// What a catalog group value maps onto (RFC 9432 §4.3.2).
///
/// Masters and nothing else, deliberately. A group is the producer saying *how*
/// a member should be treated, and the only part of that this consumer decides
/// is where the member is fetched from and with which key — a secondary does
/// not sign a zone it replicates, and who to NOTIFY is `server.also-notify`'s,
/// which a member inherits like any other zone. A setting whose effect is
/// "nothing, here" is worse than its absence (`CLAUDE.md` §14).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct GroupConfig {
    /// Where a member of this group is replicated from, in `--secondary`'s
    /// spelling after the `zone@`. Required: a group table that changes nothing
    /// is a mapping the operator believes is in force.
    masters: Vec<String>,
}

/// Who signs a zone's apex DNSKEY RRset.
///
/// `imported` is RFC 8901 §2.1.1's Model 1, where "the zone owner holds the KSK
/// set ... and is responsible for signing the DNSKEY RRset and distributing it
/// to the providers": the RRSIG arrives in the zone file and this server keeps
/// it rather than replacing it with one from a key it does not have.
///
/// Model 2 (§2.1.2) needs no setting. Each provider has its own KSK and signs
/// the DNSKEY RRset itself; importing the other providers' ZSKs is a zone-file
/// edit, and the signer has always published a key it did not put there.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DnskeyRrsig {
    /// Signed here, by this server's SEP keys.
    Local,
    /// Signed elsewhere; keep what the zone file carries.
    Imported,
}

/// What a config file supplies that no flag can, so it cannot be folded into
/// [`Cli`]. Keyed by zone apex, absolute.
#[derive(Debug, Default)]
pub(crate) struct PerZone {
    /// Where this zone's file is, when the zone names it rather than being found
    /// in `server.zone-dir`.
    pub(crate) files: BTreeMap<String, String>,
    /// NOTIFY targets for this zone in particular, on top of the global ones.
    pub(crate) notify: BTreeMap<String, Vec<String>>,
    /// Signing settings that differ from `[signing]`.
    pub(crate) signing: BTreeMap<String, ZoneSigningOverride>,
    /// Per-catalog group rules (RFC 9432 §4.3.2), by catalog zone: the group
    /// value, and the masters a member carrying it is fetched from.
    ///
    /// A `Vec` rather than a map, in the config file's own order, so that two
    /// groups matching one member are refused with the same message every time
    /// — a conflict reported in hash order is one an operator cannot reproduce.
    pub(crate) groups: BTreeMap<String, Vec<GroupRule>>,
}

/// One catalog group value, and what it maps onto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupRule {
    /// The group value as it appears in the catalog: octets, because that is
    /// what a TXT record's character-string is. The config key's UTF-8 encoding
    /// is the needle (`TODO.md` #48).
    pub(crate) value: Vec<u8>,
    /// The config key as written, for the log line and the error message.
    pub(crate) name: String,
    /// `--secondary`-shaped, less the `zone@`.
    pub(crate) masters: Vec<String>,
}

/// One zone's departures from the global signing policy.
///
/// `Option` per field rather than a whole policy, so "absent" means *inherit*
/// and not "the default". An operator who sets `nsec3 = true` for one zone must
/// not silently reset that zone's validity to thirty days.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ZoneSigningOverride {
    pub(crate) nsec3: Option<bool>,
    pub(crate) nsec3_opt_out: Option<bool>,
    pub(crate) validity_days: Option<u32>,
    pub(crate) dnskey_rrsig: Option<DnskeyRrsig>,
}

impl ZoneSigningOverride {
    fn is_set(&self) -> bool {
        self.nsec3.is_some()
            || self.nsec3_opt_out.is_some()
            || self.validity_days.is_some()
            || self.dnskey_rrsig.is_some()
    }
}

/// A zone name as an absolute domain name, which is how everything downstream
/// keys on it. `[zones."example.com"]` and `[zones."example.com."]` are the same
/// zone and must not become two.
/// [`rdns::text_names::absolute`], owned.
fn absolute(zone: &str) -> String {
    rdns::text_names::absolute(zone).into_owned()
}

impl Config {
    /// Read and validate a config file.
    ///
    /// Validation happens here rather than at first use so that `--check-config`
    /// can be a real dry run: everything that can be known without binding a
    /// socket or reading a zone is known by the time this returns.
    pub(crate) fn load(path: &Path) -> Result<Self> {
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
        // Both or neither, and only where something fetches a zone over TLS.
        // The flags get this from clap's `requires`, which a file has no
        // equivalent of (`CLAUDE.md` §15).
        match (
            &self.server.transfer_tls_cert,
            &self.server.transfer_tls_key,
        ) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => bail!(
                "server.transfer-tls-cert and server.transfer-tls-key go together: a chain \
                 with no key cannot be presented, and a key with no chain is not \
                 an identity (RFC 9103 §7.5)"
            ),
        }
        if self.server.transfer_tls_cert.is_some() && self.server.transfer_tls_ca.is_none() {
            bail!(
                "server.transfer-tls-cert is the certificate this server presents when it \
                 *fetches* a zone over TLS, and server.transfer-tls-ca names no \
                 anchors, so nothing here fetches one"
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
        //
        // Through `MasterSpec::parse` rather than a `split_once('#')` here,
        // which is what this was until `TODO.md` #44d and is exactly the shape
        // `CLAUDE.md` §7 warns about: the endpoint syntax grew a `+tls=` suffix
        // and this copy read `k.+tls=ns1.example.net.` as the key name. The
        // flag's parser is the only thing that knows the syntax, so it is what
        // has to be asked — and asking it validates the address here too.
        for (zone, settings) in &self.zones {
            for master in &settings.masters {
                let spec = rdns::secondary::MasterSpec::parse(&format!("{zone}@{master}"))
                    .map_err(|e| anyhow::anyhow!("zone {zone:?}: {e}"))?;
                if let Some(key) = &spec.key_name {
                    if !self.keys.contains_key(key)
                        && !self.keys.keys().any(|k| k.eq_ignore_ascii_case(key))
                    {
                        bail!(
                            "zone {zone:?} replicates from {master:?}, but no [keys.{key:?}] \
                             defines that key"
                        );
                    }
                }
                // The same rule the flags get, in the place the file's own
                // reader can say it: anchors are what RFC 9103 §7.5's "the
                // client MUST authenticate the server" needs, and a `+tls=`
                // without them is a transfer that cannot happen.
                if spec.tls.is_some() && self.server.transfer_tls_ca.is_none() {
                    bail!(
                        "zone {zone:?} replicates from {master:?} over TLS, and \
                         server.transfer-tls-ca names no trust anchors to check its \
                         certificate against (RFC 9103 §7.5)"
                    );
                }
            }
            if settings.nsec3_opt_out == Some(true) && settings.nsec3 == Some(false) {
                bail!("zone {zone:?} asks for nsec3-opt-out with nsec3 off");
            }
            for (group, rules) in &settings.groups {
                if !settings.catalog {
                    bail!(
                        "zone {zone:?} defines a group {group:?} and is not a catalog: \
                         a group value comes from a catalog's member node (RFC 9432 \
                         §4.3.2), so nothing would ever match it"
                    );
                }
                if rules.masters.is_empty() {
                    bail!(
                        "zone {zone:?}: group {group:?} names no masters, so it would \
                         map its members onto the catalog's own configuration — which \
                         is what leaving the group out does"
                    );
                }
                // The same parser the zone's own masters go through, for the
                // same reason: the endpoint syntax is one thing's to know.
                for master in &rules.masters {
                    let spec = rdns::secondary::MasterSpec::parse(&format!("{zone}@{master}"))
                        .map_err(|e| anyhow::anyhow!("zone {zone:?}, group {group:?}: {e}"))?;
                    if let Some(key) = &spec.key_name {
                        if !self.keys.contains_key(key)
                            && !self.keys.keys().any(|k| k.eq_ignore_ascii_case(key))
                        {
                            bail!(
                                "zone {zone:?}, group {group:?}: no [keys.{key:?}] defines \
                                 the key {master:?} names"
                            );
                        }
                    }
                    if spec.tls.is_some() && self.server.transfer_tls_ca.is_none() {
                        bail!(
                            "zone {zone:?}, group {group:?}: {master:?} transfers over TLS \
                             and server.transfer-tls-ca names no trust anchors (RFC 9103 \
                             §7.5)"
                        );
                    }
                }
            }
            if settings.catalog && settings.masters.is_empty() {
                bail!(
                    "zone {zone:?} is marked catalog but has no masters: a catalog is \
                     consumed by replicating it, and one served from a local file is \
                     an ordinary zone this server is the producer of"
                );
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
    fn tsig_specs(&self) -> Result<Vec<String>> {
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
    pub(crate) fn apply(&self, cli: &mut Cli) -> Result<PerZone> {
        cli.host = self.server.host.clone();
        cli.port = self.server.port;
        cli.zone_dir = self.server.zone_dir.clone();
        cli.allow_transfer = self.server.allow_transfer.clone();
        cli.also_notify = self.server.also_notify.clone();
        cli.response_rate = self.server.response_rate;
        cli.query_rate = self.server.query_rate;
        cli.query_burst = self.server.query_burst;
        cli.query_rate_exempt = self.server.query_rate_exempt.clone();
        cli.max_udp_request = self.server.max_udp_request;
        cli.max_tcp_request = self.server.max_tcp_request;
        cli.udp_payload_size = self.server.udp_payload_size;
        cli.max_udp_response = self.server.max_udp_response;
        cli.anomaly_interval = self.server.anomaly_interval;
        cli.anomaly_query_rate = self.server.anomaly_query_rate;
        cli.anomaly_error_percent = self.server.anomaly_error_percent;
        cli.anomaly_source_queries = self.server.anomaly_source_queries;
        cli.anomaly_source_refusals = self.server.anomaly_source_refusals;
        cli.udp_workers = self.server.udp_workers;
        cli.metrics_listen = self.server.metrics_listen.clone();
        cli.dnstap = self.server.dnstap.clone();
        cli.dnstap_max_bytes = self.server.dnstap_max_bytes;
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
        cli.transfer_tls_ca = self.server.transfer_tls_ca.clone();
        cli.transfer_tls_cert = self.server.transfer_tls_cert.clone();
        cli.transfer_tls_key = self.server.transfer_tls_key.clone();
        cli.transfer_tls_only = self.server.transfer_tls_only;
        cli.control_socket = self.server.control_socket.clone();
        cli.allow_partial_load = self.server.allow_partial_load;
        cli.tsig_key = self.tsig_specs()?;
        cli.secondary = self.secondary_specs();
        cli.catalog = self.catalog_specs();

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
            if !settings.groups.is_empty() {
                per_zone.groups.insert(
                    origin.clone(),
                    settings
                        .groups
                        .iter()
                        .map(|(name, rules)| GroupRule {
                            value: name.as_bytes().to_vec(),
                            name: name.clone(),
                            masters: rules.masters.clone(),
                        })
                        .collect(),
                );
            }
            let overrides = ZoneSigningOverride {
                nsec3: settings.nsec3,
                nsec3_opt_out: settings.nsec3_opt_out,
                validity_days: settings.validity_days,
                dnskey_rrsig: settings.dnskey_rrsig,
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

    /// The `--secondary`-shaped specs this config implies: one per (zone,
    /// master), catalogs excluded.
    ///
    /// A catalog zone is replicated too, but `--catalog` is what says so: the
    /// startup path adds every catalog to the secondary list itself, and a zone
    /// in both lists would be fetched by two refresh tasks asking one master the
    /// same question on the same timer.
    fn secondary_specs(&self) -> Vec<String> {
        self.zone_specs(false)
    }

    /// The `--catalog`-shaped specs this config implies, in the same spelling.
    fn catalog_specs(&self) -> Vec<String> {
        self.zone_specs(true)
    }

    fn zone_specs(&self, catalog: bool) -> Vec<String> {
        let mut specs = Vec::new();
        for (zone, settings) in &self.zones {
            if settings.catalog != catalog {
                continue;
            }
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
    use clap::{CommandFactory, Parser};

    fn parse(text: &str) -> Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.check(Path::new("test.toml"))?;
        Ok(config)
    }

    const MINIMAL: &str = r#"
[server]
zone-dir = "./zones"
"#;

    /// A config file that sets only what it must changes no default
    /// (`TODO.md` #63e).
    ///
    /// The two spellings of one setting are a flag and a `[server]` or
    /// `[signing]` key, and `Config::apply` overwrites `cli` field by field —
    /// so they are never both in force and a pair that disagreed would look
    /// correct from either side. Sixteen of them had a literal on each side
    /// and nothing comparing them; both sides now read one function in the
    /// crate root, which is what makes this pass by construction rather than
    /// by luck.
    ///
    /// **A tripwire, not a regression test** (`CLAUDE.md` §10). Nothing here
    /// was wrong: all sixteen pairs agreed when they were counted. What it
    /// catches is the seventeenth, added with a fresh literal on each side —
    /// run against a `default_query_burst` of 201, it fails naming
    /// `query-burst`.
    #[test]
    fn a_minimal_config_changes_no_flag_default() {
        let mut cli = Cli::parse_from(["rdnsd"]);
        let defaults = Cli::parse_from(["rdnsd"]);
        parse(MINIMAL)
            .expect("the minimal config parses")
            .apply(&mut cli)
            .expect("and applies");

        // Every setting with a default on both sides. `zone_dir` is not one:
        // the file must name it and no flag defaults to anything.
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
            response_rate => "server.response-rate",
            query_rate => "server.query-rate",
            query_burst => "server.query-burst",
            max_udp_request => "server.max-udp-request",
            max_tcp_request => "server.max-tcp-request",
            udp_payload_size => "server.udp-payload-size",
            max_udp_response => "server.max-udp-response",
            anomaly_interval => "server.anomaly-interval",
            anomaly_query_rate => "server.anomaly-query-rate",
            anomaly_error_percent => "server.anomaly-error-percent",
            anomaly_source_queries => "server.anomaly-source-queries",
            anomaly_source_refusals => "server.anomaly-source-refusals",
            dnstap_max_bytes => "server.dnstap-max-bytes",
            signature_validity => "signing.validity-days",
        }
    }

    #[test]
    fn a_minimal_config_takes_the_same_defaults_as_the_flags() {
        let config = parse(MINIMAL).expect("parses");
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 53);
        assert_eq!(config.server.query_rate, 1000);
        assert_eq!(config.server.query_burst, 200);
        assert_eq!(config.server.response_rate, 8192);
        assert_eq!(config.server.anomaly_interval, 60);
        assert_eq!(config.server.anomaly_query_rate, 50.0);
        assert_eq!(config.server.anomaly_error_percent, 10.0);
        assert_eq!(config.server.anomaly_source_queries, 100);
        assert_eq!(config.server.anomaly_source_refusals, 5);
        assert!(config.signing.is_none());
    }

    /// The anomaly knobs come out of the file as well as the flags, which is
    /// what `deny_unknown_fields` makes an all-or-nothing question: a key the
    /// struct does not have fails the load, so one that is *missing* is a knob
    /// only settable one way (`CLAUDE.md` §15).
    #[test]
    fn the_anomaly_thresholds_are_settable_from_the_file() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
anomaly-interval = 300
anomaly-query-rate = 0
anomaly-error-percent = 25.5
anomaly-source-queries = 5000
anomaly-source-refusals = 0
"#,
        )
        .expect("parses");
        assert_eq!(config.server.anomaly_interval, 300);
        assert_eq!(config.server.anomaly_query_rate, 0.0, "off");
        assert_eq!(config.server.anomaly_error_percent, 25.5);
        assert_eq!(config.server.anomaly_source_queries, 5000);
        assert_eq!(config.server.anomaly_source_refusals, 0, "off");
    }

    /// A flag the file can also set has to be refused beside `--config` (§15):
    /// two sources for one setting is an error, not a precedence rule, and the
    /// failure is silent because both values are valid.
    ///
    /// The mirror of `rdnsr`'s tie test — there, every flag `--config` replaces
    /// has a key in the file; here, every flag it does *not* replace has none.
    /// clap owns one half and serde the other, so neither list is maintained by
    /// hand.
    #[test]
    fn a_setting_the_file_can_write_is_refused_beside_config() {
        let command = Cli::command();
        let mut both = Vec::new();
        for arg in command.get_arguments() {
            let Some(long) = arg.get_long() else { continue };
            if long == "config" {
                continue;
            }
            if command
                .get_arg_conflicts_with(arg)
                .iter()
                .any(|other| other.get_long() == Some("config"))
            {
                continue;
            }
            // Not refused beside `--config`, so the file must not have the key.
            for (table, text) in [
                (
                    "server",
                    format!(
                        "[server]
zone-dir = \"z\"
{long} = 0
"
                    ),
                ),
                (
                    "signing",
                    format!(
                        "[server]
zone-dir = \"z\"
[signing]
key-dir = \"k\"
{long} = 0
"
                    ),
                ),
            ] {
                let refused = match toml::from_str::<Config>(&text) {
                    Ok(_) => false,
                    Err(e) => e.to_string().contains(&format!("unknown field `{long}`")),
                };
                if !refused {
                    both.push(format!("{table}.{long}"));
                }
            }
        }
        assert!(
            both.is_empty(),
            "settable from the file and accepted beside --config: {both:?}",
        );
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

    /// A group table reaches `PerZone` keyed by the absolute zone, with the
    /// TOML key's octets as the value to match a catalog's group property
    /// against (RFC 9432 §4.3.2, `TODO.md` #48).
    #[test]
    fn a_catalog_group_reaches_per_zone_as_octets() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
[zones."catalog.invalid."]
masters = ["192.0.2.1"]
catalog = true
[zones."catalog.invalid.".groups."operator-x"]
masters = ["192.0.2.9"]
"#,
        )
        .expect("a catalog with one group rule");
        let mut cli = Cli::parse_from(["rdnsd"]);
        let per_zone = config.apply(&mut cli).expect("applies");
        assert_eq!(
            per_zone.groups.get("catalog.invalid."),
            Some(&vec![GroupRule {
                value: b"operator-x".to_vec(),
                name: "operator-x".to_string(),
                masters: vec!["192.0.2.9".to_string()],
            }])
        );
    }

    /// A group on a zone that is not a catalog can never match anything, so it
    /// is refused rather than ignored: a mapping the operator believes is in
    /// force and is not is what `CLAUDE.md` §15 is about.
    #[test]
    fn a_group_on_a_zone_that_is_not_a_catalog_is_refused() {
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
[zones."example.com."]
masters = ["192.0.2.1"]
[zones."example.com.".groups."operator-x"]
masters = ["192.0.2.9"]
"#,
        )
        .expect_err("a group without a catalog");
        assert!(err.to_string().contains("is not a catalog"), "{err}");
    }

    /// And one that names no masters maps its members onto the catalog's own
    /// configuration, which is what leaving the table out does.
    #[test]
    fn a_group_that_changes_nothing_is_refused() {
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
[zones."catalog.invalid."]
masters = ["192.0.2.1"]
catalog = true
[zones."catalog.invalid.".groups."operator-x"]
masters = []
"#,
        )
        .expect_err("a group with no masters");
        assert!(err.to_string().contains("names no masters"), "{err}");
    }

    /// The key a group's master names has to exist, like every other master's.
    #[test]
    fn a_group_naming_an_undefined_key_is_refused() {
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
[zones."catalog.invalid."]
masters = ["192.0.2.1"]
catalog = true
[zones."catalog.invalid.".groups."operator-x"]
masters = ["192.0.2.9#nobody.key."]
"#,
        )
        .expect_err("a group naming a key nothing defines");
        assert!(err.to_string().contains("nobody.key."), "{err}");
    }

    /// A catalog zone is in the catalog list and *not* in the secondary list:
    /// startup adds it to the second itself, and a zone in both is two refresh
    /// tasks asking one master the same question.
    #[test]
    fn a_catalog_zone_is_not_also_a_secondary_spec() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
[zones."catalog.invalid."]
masters = ["192.0.2.1"]
catalog = true
[zones."other.test."]
masters = ["192.0.2.3"]
"#,
        )
        .expect("parses");
        assert_eq!(config.catalog_specs(), ["catalog.invalid.@192.0.2.1"]);
        assert_eq!(config.secondary_specs(), ["other.test.@192.0.2.3"]);
    }

    /// A catalog is consumed by replicating it, so one with no masters is a
    /// setting that does nothing — which `CLAUDE.md` §15 says must fail rather
    /// than be ignored.
    #[test]
    fn a_catalog_with_no_masters_is_refused() {
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
[zones."catalog.invalid."]
catalog = true
"#,
        )
        .expect_err("a catalog with nowhere to fetch it from");
        assert!(
            err.to_string().contains("no masters"),
            "the message says what is missing: {err}"
        );
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

    /// The `+tls=` half of the endpoint spelling survives the file, because the
    /// file builds the same string the flag parses (`CLAUDE.md` §7). A second
    /// parser here is how the flag and the file come to disagree about which
    /// masters are reached over TLS.
    #[test]
    fn a_master_may_ask_for_a_transfer_over_tls() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
transfer-tls-ca = "/etc/rdns/anchors.pem"
[keys."k."]
secret = "AAECAwQFBgcICQoLDA0ODw=="
[zones."example.com."]
masters = ["192.0.2.1#k.+tls=ns1.example.net."]
"#,
        )
        .expect("parses");
        assert_eq!(
            config.secondary_specs(),
            ["example.com.@192.0.2.1#k.+tls=ns1.example.net."]
        );
        let spec = rdns::secondary::MasterSpec::parse(&config.secondary_specs()[0])
            .expect("the same parser the flag uses");
        assert_eq!(
            spec.master,
            "192.0.2.1:853".parse().expect("RFC 9103 §7.3's port")
        );
        assert!(spec.tls.is_some());
        assert_eq!(
            config.server.transfer_tls_ca.as_deref(),
            Some(std::path::Path::new("/etc/rdns/anchors.pem"))
        );
    }

    /// A client certificate needs its key, and clap's `requires` says so for
    /// the flags. The file has no such mechanism, so `check` does
    /// (`CLAUDE.md` §15).
    #[test]
    fn a_transfer_client_certificate_without_its_key_is_refused() {
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
transfer-tls-ca = "/etc/rdns/anchors.pem"
transfer-tls-cert = "/etc/rdns/client.pem"
"#,
        )
        .expect_err("half an identity");
        assert!(err.to_string().contains("go together"), "{err}");
    }

    /// And it is the certificate presented when this server *fetches* a zone,
    /// so without anchors there is nothing to present it to. Silence here would
    /// be an operator believing mTLS is configured on a server that never makes
    /// an outgoing TLS connection at all (`CLAUDE.md` §4).
    #[test]
    fn a_transfer_client_certificate_with_no_anchors_is_refused() {
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
transfer-tls-cert = "/etc/rdns/client.pem"
transfer-tls-key = "/etc/rdns/client.key"
"#,
        )
        .expect_err("nothing fetches over TLS");
        assert!(
            err.to_string().contains("nothing here fetches one"),
            "{err}"
        );
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

    /// The query stream is a `[server]` setting, and `--dnstap`'s default for
    /// the file bound is the same number the file's is (`TODO.md` #44g).
    #[test]
    fn the_query_stream_is_configurable_from_the_file() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
dnstap = "tcp:127.0.0.1:6000"
"#,
        )
        .expect("parses");
        assert_eq!(config.server.dnstap.as_deref(), Some("tcp:127.0.0.1:6000"));
        assert_eq!(
            config.server.dnstap_max_bytes,
            crate::default_dnstap_max_bytes(),
            "absent means the same bound the flag defaults to"
        );

        let off = parse(
            "[server]
zone-dir = \"./zones\"
",
        )
        .expect("parses");
        assert_eq!(off.server.dnstap, None, "and absent is off");
    }

    /// RFC 8901 Model 1 is one key in one zone's table (`TODO.md` #44e). Model 2
    /// is not here on purpose: it needs no setting, only the co-providers' ZSKs
    /// in the zone file.
    #[test]
    fn a_zone_can_say_its_dnskey_rrsig_is_signed_elsewhere() {
        let config = parse(
            r#"
[server]
zone-dir = "./zones"
[signing]
key-dir = "./keys"
[zones."multi.test."]
dnskey-rrsig = "imported"
[zones."ordinary.test."]
"#,
        )
        .expect("parses");
        assert_eq!(
            config.zones["multi.test."].dnskey_rrsig,
            Some(DnskeyRrsig::Imported)
        );
        assert_eq!(
            config.zones["ordinary.test."].dnskey_rrsig, None,
            "absent means this server signs it, which is every ordinary zone"
        );

        // `deny_unknown_fields` covers the key; the value is the enum's, and a
        // typo in it has to fail at startup too (`CLAUDE.md` §15).
        let err = parse(
            r#"
[server]
zone-dir = "./zones"
[zones."multi.test."]
dnskey-rrsig = "improted"
"#,
        )
        .expect_err("a misspelled value is not a setting");
        assert!(err.to_string().contains("dnskey-rrsig"), "got: {err}");
    }
}
