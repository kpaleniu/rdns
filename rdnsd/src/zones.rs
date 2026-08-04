//! The zone map and everything that puts a zone into it.
//!
//! **One lifecycle, three questions.** Where a zone comes from ([`ZoneSource`],
//! [`load_zones_from_source`]), what has to be true before it is served
//! ([`ZoneSigning`], [`verify_zones`]), and how it is swapped into the map
//! without the derived state falling out of step ([`Zones`], [`Served`],
//! [`install_zone`]). `Reloading`'s doc comment already treated these as a unit;
//! this is that unit with a file around it.
//!
//! **What is deliberately *not* here: the reload task.** `TODO.md` #20 listed
//! `Reloading`, `ReloadTrigger`, `reload_once` and `spawn_zone_maintenance` as
//! part of this seam, and moving them drags in the signal plumbing
//! (`signal_stream`, `next_reload_signal`, `sleep_for`), NOTIFY
//! (`announce_zones`) and the secondary role (`withdraw_unvouched_zones`) — nine
//! things the module would have to reach back into `main` for, against two for
//! the cut taken here. A reload is a *caller* of this module, not a part of it,
//! and the difference shows up as exactly that import count.
//!
//! The `async` in here holds locks across await points on purpose — see
//! [`install_zone`], which plans a diff under the read guard and applies it
//! under the write guard. Nothing about that changed in the move, and it is the
//! reason `CLAUDE.md` §9 is worth rereading before touching any of it.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::sync::RwLock;

use rdns::dnssec_key::SigningKey;
use rdns::dnssec_validation_mode::DnssecValidator;
use rdns::ixfr::{plan_change, DeltaLog, PlannedDelta};
use rdns::journal::Journal;
use rdns::metrics::DnsMetrics;
use rdns::utils::{current_unix_timestamp, record_types};
use rdns::zone::{parse_zone_file_at, Zone};
use rdns::zone_signer::{sign_zone, sign_zone_incrementally, DenialChain, SigningPolicy};
use rdns::{Qtype, ResourceRecord, Rtype};

use crate::config;
use crate::{absolute_name, Cli};

/// Zone source: either a single file or a directory of zone files
#[derive(Clone)]
pub(crate) enum ZoneSource {
    SingleFile(String),
    Directory(String),
    /// Zones that named their own files, from a config file's `[zones.*]`.
    ///
    /// The origin comes from the *table key* rather than the file name, which
    /// quietly removes the trap `SingleFile` still has: `--zone-file` derives the
    /// origin from the path, so `example.com.zone` holding `other.test.` yields
    /// NXDOMAIN for everything with nothing to indicate why. Only a config file
    /// can express this, because only a config file has somewhere to say the
    /// origin out loud.
    Files(Vec<(String, String)>),
}

impl ZoneSource {
    /// The file a zone's records live in, or `None` if this source has none for
    /// it.
    ///
    /// **Derived by the same function the loader derives it with**, which is the
    /// whole point of it being here rather than reconstructed at the call site
    /// (`CLAUDE.md` §7). A write that landed anywhere but where the next load
    /// reads from would be an update that vanished at the next reload, and the
    /// server would go on answering from the version it still held in memory —
    /// so the mistake would be invisible until a restart.
    ///
    /// The directory case scans rather than composing `<dir>/<origin>.zone`,
    /// because that is not the rule: `enumerate_zone_files` derives each origin
    /// *from its file name* and a zone's own `$ORIGIN` may say something else
    /// entirely. Composing the path would write `other.test.` into
    /// `example.com.zone` on exactly the deployment that trap already exists on.
    pub(crate) fn file_for(&self, origin: &str) -> Option<PathBuf> {
        let wanted = absolute_name(origin);
        let matches = |candidate: &str| absolute_name(candidate).eq_ignore_ascii_case(&wanted);
        match self {
            ZoneSource::SingleFile(path) => {
                matches(&extract_zone_origin_from_path(path)).then(|| PathBuf::from(path))
            }
            ZoneSource::Files(files) => files
                .iter()
                .find(|(zone, _)| matches(zone))
                .map(|(_, path)| PathBuf::from(path)),
            ZoneSource::Directory(dir) => std::fs::read_dir(dir)
                .ok()?
                .flatten()
                .map(|entry| entry.path())
                .find(|path| {
                    path.extension().and_then(|s| s.to_str()) == Some("zone")
                        && matches(&extract_zone_origin_from_path(&path.to_string_lossy()))
                }),
        }
    }
}

/// Replace one zone, recording what changed.
///
/// The only way a zone should ever enter the map once the server is running.
/// Both halves happen under the same pair of locks and in the same call, because
/// the delta log is *derived* from the zone map: a swap that skipped it would
/// leave us offering an IXFR chain that does not describe the zone we serve — and
/// a secondary applying that chain would end up with a zone that never existed,
/// holding a serial saying it is current.
pub(crate) async fn install_zone(served: &Served, zone: Zone) {
    let Served {
        zone_map,
        deltas,
        metrics,
        journal,
    } = served;
    let origin = zone.origin().to_string();
    if let Some(serial) = zone.serial() {
        metrics.set_zone_serial(zone.origin(), serial);
    }

    // The diff walks every record of both versions, and queries take this same
    // lock — so it is planned under the read guard, where they run alongside it,
    // rather than under the write guard, where they would all wait for it.
    let (planned, generation) = {
        let zones = zone_map.read().await;
        (
            plan_change(zones.matching(zone.origin()), &zone),
            zones.generation(),
        )
    };

    let mut zones = zone_map.write().await;
    let mut log = deltas.write().await;
    // If the map moved while we held neither guard, the plan describes a
    // version we are no longer replacing. See `Zones`.
    let planned = if zones.generation() == generation {
        planned
    } else {
        plan_change(zones.matching(zone.origin()), &zone)
    };
    let recorded = planned.is_some();
    if let Some(planned) = planned {
        log.record(planned);
    }
    // Persisted under the same guard that recorded it, for the reason `Served`
    // gives: the journal is the delta log on disk, and a window where they
    // disagree is a window in which a restart serves a chain that does not
    // describe the zone. The write is `write_atomically`, so what a reader can
    // see is the old file or the new one and never a mixture.
    //
    // A failure to write is logged and nothing more. Losing a journal costs some
    // secondaries a full transfer, which RFC 1995 §4 permits at any time and
    // which is what happened on every restart before the journal existed — so
    // refusing the update over it would trade a real change for a cosmetic one.
    if recorded {
        if let Some(journal) = journal {
            if let Err(e) = journal.save(&origin, &log.all(&origin)) {
                tracing::warn!("could not persist the delta log for {origin}: {e}");
            }
        }
    }
    let displaced = zones.insert(zone);
    drop(log);
    drop(zones);
    // Outside the guards on purpose. See `Zones::insert`.
    drop(displaced);
}

/// Replace every zone, as a reload does, recording what changed in each.
///
/// A zone that has gone from the configuration takes its history with it: we no
/// longer serve it, so we have no increments of it to offer.
// Reached only from the SIGHUP handler, which exists on Unix — the reload it
// serves has no trigger on Windows, so there it is genuinely unreachable rather
// than merely unused.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) async fn install_all_zones(served: &Served, new_zones: HashMap<String, Zone>) {
    let Served {
        zone_map,
        deltas,
        metrics,
        journal,
    } = served;
    // A reload replaces the set, so a zone that has gone takes its gauges with
    // it. Leaving them behind would show a zone nobody serves any more as
    // perfectly healthy at whatever serial it last had.
    metrics.retain_zones(
        &new_zones
            .values()
            .map(|z| z.origin().to_string())
            .collect::<Vec<_>>(),
    );
    note_serials(metrics, &new_zones);

    // A reload diffs *every* zone, so this is the call site the read/write split
    // exists for: under one write guard it blocked every query for the sum of
    // all of them. See `Zones`.
    let (mut plan, generation) = {
        let zones = zone_map.read().await;
        (plan_reload(&zones, &new_zones), zones.generation())
    };

    let mut zones = zone_map.write().await;
    let mut log = deltas.write().await;
    if zones.generation() != generation {
        plan = plan_reload(&zones, &new_zones);
    }
    let mut touched: Vec<String> = Vec::new();
    for gone in plan.forgotten {
        log.forget(&gone);
        // On disk too: a zone withdrawn from the configuration must not come
        // back after a restart offering increments of something nobody serves.
        if let Some(journal) = journal {
            journal.forget(&gone);
        }
    }
    for planned in plan.recorded {
        touched.push(planned.zone().to_string());
        log.record(planned);
    }
    if let Some(journal) = journal {
        for zone in &touched {
            if let Err(e) = journal.save(zone, &log.all(zone)) {
                tracing::warn!("could not persist the delta log for {zone}: {e}");
            }
        }
    }

    let displaced = zones.replace_all(new_zones);
    drop(log);
    drop(zones);
    // Outside the guards on purpose: freeing the set we just replaced is one
    // deallocation per record of every zone, and no query needs to wait for it.
    drop(displaced);
}

/// Prime the delta log from the journals on disk, so a restart does not drop
/// every secondary to a full transfer.
///
/// **Every failure here is a warning and nothing more, which is the opposite of
/// how this file treats the secondary state file.** That one is fatal because
/// forgetting a last-contact time is the difference between a withdrawn zone and
/// a stale one served with AA set (`CLAUDE.md` §4). Nothing here has teeth: a
/// journal that will not read means some secondaries take a full transfer, which
/// RFC 1995 §4 permits at any time and which is exactly what happened on every
/// restart before journals existed. Refusing to start over it would turn a
/// cosmetic loss into an outage.
///
/// A journal whose last step does not reach the serial we actually loaded is
/// dropped rather than kept. The zone moved past it by some route the journal
/// never saw — an operator editing the file while the process was down is the
/// ordinary one — and chaining onto it would offer a secondary a path to a
/// version nobody is serving.
pub(crate) async fn restore_journals(
    journal: &Journal,
    zone_map: &Arc<RwLock<Zones>>,
    deltas: &Arc<RwLock<DeltaLog>>,
) {
    let zones = zone_map.read().await;
    let mut log = deltas.write().await;
    for (name, zone) in zones.iter() {
        let loaded = match journal.load(name) {
            Ok(loaded) => loaded,
            Err(e) => {
                tracing::warn!("ignoring the journal for {name}: {e}");
                continue;
            }
        };
        if loaded.is_empty() {
            continue;
        }
        if !rdns::journal::usable_against(&loaded, zone) {
            tracing::info!(
                "the journal for {name} stops short of the serial loaded from disk; \
                 discarding it, so a secondary asking for an increment gets a full transfer"
            );
            journal.forget(name);
            continue;
        }
        tracing::info!(
            "restored {} version step{} for {name} from its journal",
            loaded.len(),
            if loaded.len() == 1 { "" } else { "s" }
        );
        log.restore(name, loaded);
    }
}

/// What a reload does to the delta log: which zones leave it, and which gain a
/// version step. Computed away from the write lock — see `Zones`.
pub(crate) struct ReloadPlan {
    forgotten: Vec<String>,
    recorded: Vec<PlannedDelta>,
}

pub(crate) fn plan_reload(zones: &Zones, new_zones: &HashMap<String, Zone>) -> ReloadPlan {
    let forgotten = zones
        .keys()
        .filter(|old_name| {
            !new_zones
                .values()
                .any(|z| z.origin().eq_ignore_ascii_case(old_name))
        })
        .cloned()
        .collect();
    let recorded = new_zones
        .values()
        .filter_map(|zone| plan_change(zones.matching(zone.origin()), zone))
        .collect();
    ReloadPlan {
        forgotten,
        recorded,
    }
}

/// Record the serial of every zone in `zones`.
pub(crate) fn note_serials(metrics: &DnsMetrics, zones: &HashMap<String, Zone>) {
    for zone in zones.values() {
        if let Some(serial) = zone.serial() {
            metrics.set_zone_serial(zone.origin(), serial);
        }
    }
}

/// The zones this server answers from, and a counter that moves whenever the
/// set does.
///
/// The counter is why this is not a bare `HashMap`. `ixfr::diff` walks every
/// record of both versions, so it is planned under the read lock and only
/// recorded under the write lock — under the write lock it would block every
/// query for the length of the walk, and on a SIGHUP for the sum of all of them.
///
/// That split leaves a window between dropping the read guard and taking the
/// write guard, in which another task can install, expire or withdraw a zone. A
/// delta computed against the wrong old version hands a secondary a zone that
/// never existed. `generation` closes it: equal means the plan still stands,
/// different means re-plan under the write lock.
///
/// A serial comparison would not do, which is why this is a counter and not
/// `Option<u32>`: an edited file reloaded without a bump carries the same serial
/// over different records, so the check has to be about identity.
///
/// Mutation goes through the methods below and there is no `DerefMut`, so the
/// counter cannot be forgotten at a call site.
#[derive(Debug, Default)]
pub(crate) struct Zones {
    by_name: HashMap<String, Zone>,
    generation: u64,
}

impl Zones {
    pub(crate) fn new(by_name: HashMap<String, Zone>) -> Self {
        Zones {
            by_name,
            generation: 0,
        }
    }

    /// Which version of the map this is. Only ever compared for equality.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Install one zone, replacing any version of it already held.
    ///
    /// The removal is by the key already in the map rather than by the new
    /// zone's origin, because the two can differ in case and inserting without
    /// removing would leave both (`CLAUDE.md` §8, case folding is ASCII-only).
    ///
    /// **The displaced version is handed back rather than dropped here**, so the
    /// caller can let it go after releasing the lock. Freeing a zone is one
    /// deallocation per record, and a query waiting on the lock is waiting on
    /// every one of them for no reason — the same argument as planning the diff
    /// outside the guard, applied to the other end of the swap.
    #[must_use = "drop the displaced zone after releasing the lock, not under it"]
    pub(crate) fn insert(&mut self, zone: Zone) -> Option<Zone> {
        let displaced = match self.matching_key(zone.origin()) {
            Some(key) => self.by_name.remove(&key),
            None => None,
        };
        self.by_name.insert(zone.origin().to_string(), zone);
        self.generation += 1;
        displaced
    }

    /// Withdraw a zone. `true` if one was actually held.
    pub(crate) fn remove(&mut self, name: &str) -> bool {
        let Some(key) = self.matching_key(name) else {
            return false;
        };
        self.by_name.remove(&key);
        self.generation += 1;
        true
    }

    /// Swap the whole set, as a reload does, handing back the set replaced.
    ///
    /// Dropped by the caller once the lock is released, for the reason given on
    /// [`Zones::insert`] — and it matters more here, because a reload displaces
    /// every zone at once.
    #[must_use = "drop the displaced zones after releasing the lock, not under it"]
    pub(crate) fn replace_all(&mut self, by_name: HashMap<String, Zone>) -> HashMap<String, Zone> {
        self.generation += 1;
        std::mem::replace(&mut self.by_name, by_name)
    }

    /// The key under which `name` is held, whatever case either is in.
    fn matching_key(&self, name: &str) -> Option<String> {
        self.by_name
            .keys()
            .find(|k| k.eq_ignore_ascii_case(name))
            .cloned()
    }

    /// The version held for `name`, whatever case either is in.
    pub(crate) fn matching(&self, name: &str) -> Option<&Zone> {
        self.by_name
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, zone)| zone)
    }
}

// Read-only, deliberately: every mutation has to go through a method that
// moves `generation`, and a `DerefMut` would be a way around that.
impl std::ops::Deref for Zones {
    type Target = HashMap<String, Zone>;

    fn deref(&self) -> &Self::Target {
        &self.by_name
    }
}

/// The three things that describe what this server is currently serving.
///
/// They are grouped because they are only ever updated *together*: a zone
/// installed is a new version in the delta log and a new serial on the gauge,
/// and a zone withdrawn has to leave all three. Passing them as three
/// parameters is how one of them gets forgotten at a fourth call site —
/// `CLAUDE.md` §14, and clippy objects at seven arguments for the same reason.
#[derive(Clone)]
pub(crate) struct Served {
    pub(crate) zone_map: Arc<RwLock<Zones>>,
    pub(crate) deltas: Arc<RwLock<DeltaLog>>,
    pub(crate) metrics: Arc<DnsMetrics>,
    /// Where the delta log is persisted, so a restart does not drop every
    /// secondary to a full transfer. `None` when there is no directory to put it
    /// in, which is `--zone-file` and the tests.
    ///
    /// Part of this group rather than beside it because it is the same fact
    /// written down twice: the journal *is* the delta log, on disk. A swap that
    /// updated one and not the other would offer an IXFR chain after a restart
    /// that does not describe the zone being served — the exact hazard the
    /// grouping exists to prevent.
    pub(crate) journal: Option<Arc<Journal>>,
}

/// Validate that exactly one of zone_file or zone_dir is specified
///
/// `replicating` is whether any `--secondary` was given, which narrows this: a
/// fetched zone has to be written somewhere, and a single `--zone-file` is not a
/// place to put a zone whose name we may not have seen yet.
pub(crate) fn validate_zone_source(
    zone_file: Option<String>,
    zone_dir: Option<String>,
    replicating: bool,
) -> Result<ZoneSource> {
    if replicating && zone_dir.is_none() {
        return Err(anyhow!(
            "--secondary needs --zone-dir: a transferred zone is written to disk, \
             and --zone-file names one file rather than somewhere to put them",
        ));
    }
    match (zone_file, zone_dir) {
        (Some(file), None) => {
            // Check if file exists
            if !Path::new(&file).exists() {
                return Err(anyhow!("Zone file not found: {file}"));
            }
            Ok(ZoneSource::SingleFile(file))
        }
        (None, Some(dir)) => {
            // Check if directory exists
            if !Path::new(&dir).is_dir() {
                return Err(anyhow!(
                    "Zone directory not found or not a directory: {dir}"
                ));
            }
            Ok(ZoneSource::Directory(dir))
        }
        (Some(_), Some(_)) => Err(anyhow!("Cannot specify both --zone-file and --zone-dir")),
        (None, None) => Err(anyhow!("Must specify either --zone-file or --zone-dir")),
    }
}

/// Zone signing as configured: which keys, for how long, and which chain.
///
/// Only zones loaded from disk are signed. A zone that arrived by transfer is
/// the master's, signatures included — re-signing it here would replace a
/// statement its owner made with one we made about data we do not own, and the
/// parent's DS points at their key, not ours.
pub(crate) struct ZoneSigning {
    /// Keys by the zone they are published at, down-cased.
    keys: HashMap<String, Vec<SigningKey>>,
    validity: u64,
    chain: DenialChain,
    /// Zones whose signing settings differ from the two above, by apex.
    ///
    /// Only a config file can populate this — there is no flag shape for "NSEC3
    /// for this zone and NSEC for the rest", which is the gap `TODO.md` #9d names
    /// when it says every zone got the same signing policy.
    per_zone: BTreeMap<String, config::ZoneSigningOverride>,
}

impl ZoneSigning {
    pub(crate) fn load(
        cli: &Cli,
        per_zone: &BTreeMap<String, config::ZoneSigningOverride>,
    ) -> Result<Option<Self>> {
        let Some(dir) = &cli.signing_key_dir else {
            return Ok(None);
        };
        let loaded = SigningKey::load_dir(dir).context("loading the signing keys")?;
        if loaded.is_empty() {
            // Not an error — a key directory prepared before any key is in it
            // is a reasonable state — but silence here would look exactly like
            // signing that quietly did nothing.
            tracing::warn!(
                "no .{} files in {}: no zone will be signed",
                rdns::dnssec_key::KEY_FILE_EXTENSION,
                dir.display()
            );
        }
        let mut keys: HashMap<String, Vec<SigningKey>> = HashMap::new();
        for key in loaded {
            keys.entry(key.owner().to_ascii_lowercase())
                .or_default()
                .push(key);
        }
        Ok(Some(ZoneSigning {
            keys,
            per_zone: per_zone.clone(),
            validity: u64::from(cli.signature_validity) * 86_400,
            chain: if cli.nsec3 {
                DenialChain::Nsec3 {
                    salt: Vec::new(),
                    iterations: 0,
                    opt_out: cli.nsec3_opt_out,
                }
            } else {
                DenialChain::Nsec
            },
        }))
    }

    /// The policy for one zone: the global one, with that zone's overrides
    /// applied.
    ///
    /// `signed_at` is passed in rather than read here so that every zone in one
    /// signing run shares a moment — otherwise two zones signed a second apart
    /// would derive serials from different hours at an hour boundary, which is a
    /// difference nobody could explain from the outside.
    pub(crate) fn policy_for(&self, origin: &str, signed_at: u64) -> SigningPolicy {
        let over = self
            .per_zone
            .get(absolute_name(origin).as_ref())
            .copied()
            .unwrap_or_default();
        let validity = over
            .validity_days
            .map(|days| u64::from(days) * 86_400)
            .unwrap_or(self.validity);
        let nsec3 = over
            .nsec3
            .unwrap_or(!matches!(self.chain, DenialChain::Nsec));
        let opt_out = over.nsec3_opt_out.unwrap_or(matches!(
            self.chain,
            DenialChain::Nsec3 { opt_out: true, .. }
        ));
        let chain = if nsec3 {
            DenialChain::Nsec3 {
                salt: Vec::new(),
                iterations: 0,
                opt_out,
            }
        } else {
            DenialChain::Nsec
        };
        SigningPolicy::valid_for(signed_at, validity).with_chain(chain)
    }

    /// The shortest validity any zone is signed with, which is what the
    /// re-signing interval has to follow.
    ///
    /// The *minimum*, not the global setting: a zone configured with a seven-day
    /// validity among thirty-day ones needs the timer to run on its schedule, or
    /// it is the one zone that expires.
    pub(crate) fn shortest_validity(&self) -> u64 {
        self.per_zone
            .values()
            .filter_map(|o| o.validity_days)
            .map(|days| u64::from(days) * 86_400)
            .chain(std::iter::once(self.validity))
            .min()
            .unwrap_or(self.validity)
    }

    /// How often the zones should be re-signed.
    ///
    /// A third of the validity, so a failed run has two more chances before
    /// anything expires — see `zone_signer::RESIGN_FRACTION` for the reasoning,
    /// which is BIND's.
    ///
    /// **The timer re-signs by reloading**, which is not an implementation
    /// shortcut but the only correct shape here. The served SOA serial is derived
    /// from the *file's* serial plus a time term (`zone_signer::signed_serial`),
    /// and the zone in memory already carries the derived value — so re-signing
    /// the in-memory copy would apply the derivation to its own output and
    /// compound the bump on every cycle. Re-reading the file makes it idempotent:
    /// the file's serial is the input every time. It also means an edit to a zone
    /// file is picked up within one interval without a SIGHUP, which is a
    /// behaviour change worth knowing about.
    ///
    /// Floored at a minute so that a tiny `--signature-validity`, which is only
    /// ever a test setting, cannot turn this into a spin loop.
    pub(crate) fn resign_interval(&self) -> Duration {
        Duration::from_secs((self.shortest_validity() / 3).max(60))
    }

    /// How many of `zones` this would actually sign, for `--check-config`.
    ///
    /// Counted rather than assumed: "signing is configured" and "this zone gets
    /// signed" are different claims, and a key directory that does not hold a key
    /// for the zone an operator thought it did is exactly what a dry run is for.
    pub(crate) fn signed_zone_count(&self, zones: &HashMap<String, Zone>) -> usize {
        zones
            .keys()
            .filter(|origin| self.keys.contains_key(&origin.to_ascii_lowercase()))
            .count()
    }

    /// The shortest configured validity in days, for the startup line.
    pub(crate) fn validity_days(&self) -> u64 {
        self.shortest_validity() / 86_400
    }

    /// Sign every zone there are keys for, in place.
    ///
    /// A zone we hold keys for and cannot sign is an error rather than a zone
    /// served unsigned: its parent has a DS pointing at one of these keys, so
    /// the unsigned answer would be bogus at every validating client rather
    /// than merely unvalidated.
    /// Sign one zone against the version already being served, carrying forward
    /// every signature whose RRset did not move.
    ///
    /// This is the dynamic-UPDATE path and not the load path. A full re-sign
    /// gives every RRSIG in the zone a new inception and expiration, so the IXFR
    /// delta for a one-record update is the whole zone — measured at 52 records
    /// out of 53 before this existed, against 10 after (`TODO.md` #10). At load
    /// there is no previous version to carry anything forward from and
    /// [`ZoneSigning::apply`] is the right call; here there is.
    ///
    /// A zone with no key is returned unchanged, exactly as `apply` skips it.
    pub(crate) fn sign_one_incrementally(&self, previous: &Zone, zone: &Zone) -> Result<Zone> {
        let origin = zone.origin().to_string();
        let Some(keys) = self.keys.get(&origin.to_ascii_lowercase()) else {
            return Ok(zone.clone());
        };
        let policy = self.policy_for(&origin, current_unix_timestamp());
        sign_zone_incrementally(previous, zone, keys, &policy)
            .with_context(|| format!("re-signing {origin} after an update"))
    }

    pub(crate) fn apply(&self, zones: &mut HashMap<String, Zone>) -> Result<()> {
        // One moment for the whole run — see `policy_for`.
        let signed_at = current_unix_timestamp();
        for (origin, zone) in zones.iter_mut() {
            let Some(keys) = self.keys.get(&origin.to_ascii_lowercase()) else {
                continue;
            };
            let policy = self.policy_for(origin, signed_at);
            *zone = sign_zone(zone, keys, &policy).with_context(|| format!("signing {origin}"))?;
            tracing::info!(
                "signed {origin} with {} key{}, {} for {} day{}",
                keys.len(),
                if keys.len() == 1 { "" } else { "s" },
                if matches!(policy.chain, DenialChain::Nsec) {
                    "NSEC"
                } else {
                    "NSEC3"
                },
                (u64::from(policy.expiration) - u64::from(policy.inception)) / 86_400,
                if self.validity == 86_400 { "" } else { "s" }
            );
        }
        Ok(())
    }
}

/// Check every signature in every zone before anything is served from it.
///
/// The question asked is "does each signature in this zone cover an RRset that
/// verifies", not "is every RRset signed" — a delegation's NS RRset and the
/// glue below it carry no signature by design, and demanding one would fail
/// every zone with a child. What this catches is the case worth catching: a
/// zone whose signatures have expired, or were made over data that has since
/// been edited, which otherwise keeps answering as though nothing happened.
pub(crate) fn verify_zones(
    zones: &HashMap<String, Zone>,
    validator: &DnssecValidator,
) -> Result<()> {
    if !validator.is_enabled() {
        return Ok(());
    }
    for (origin, zone) in zones {
        let signed = DnssecValidator::is_zone_signed(zone);
        if !signed {
            // `validate_response` gives the same verdict; asking it with no
            // records keeps the "is unsigned acceptable" decision in one place.
            let (ok, _) = validator.validate_response(zone, &[], origin);
            if !ok {
                return Err(anyhow!("{origin} is not signed"));
            }
            continue;
        }

        let mut checked = 0usize;
        for (name, rtype) in signed_rrsets(zone) {
            let records = zone.query(&name, Qtype::of(rtype));
            if records.is_empty() {
                return Err(anyhow!(
                    "{origin}: a signature covers the {rtype} RRset at {name}, which is not there"
                ));
            }
            let (ok, _) = validator.validate_response(zone, &records, &name);
            if !ok {
                return Err(anyhow!(
                    "{origin}: the {rtype} RRset at {name} does not verify against the zone's \
                     own keys"
                ));
            }
            checked += 1;
        }
        tracing::info!("verified {checked} signed RRsets in {origin}");
    }
    Ok(())
}

/// Every `(owner, type)` in the zone that some RRSIG claims to cover.
pub(crate) fn signed_rrsets(zone: &Zone) -> Vec<(String, Rtype)> {
    let mut seen: Vec<(String, Rtype)> = zone
        .records()
        .iter()
        .filter(|r| r.rdata.rtype() == record_types::RRSIG)
        .filter_map(|r| {
            rdns::dnssec::Rrsig::from_record(&ResourceRecord {
                name: r.name.clone(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.clone(),
            })
        })
        .map(|sig| (sig.owner, sig.type_covered))
        .collect();
    seen.sort();
    seen.dedup();
    seen
}

/// Load zones from source (single file or directory)
///
/// Three questions that used to be one:
///
/// - Could the directory be read? Always fatal. An `Err` here used to become
///   `Ok(empty)` on the `--secondary` path, so a permission change left the
///   server up, listening, and answering REFUSED for every name it serves.
/// - Did every zone file parse? Fatal unless `--allow-partial-load`. See
///   [`enumerate_zone_files`].
/// - Is the directory empty? Fatal except when replicating: a secondary's first
///   start has nothing on disk yet, while for a primary an empty `--zone-dir` is
///   a typo in the path.
///
/// The emptiness check lives here rather than in `enumerate_zone_files` because
/// only this function knows which caller is a secondary.
///
/// Blocking, and says so: `read_dir`, then a `read_to_string` and a full parse
/// per zone. It was an `async fn` with no await point. Callers that run while the
/// listeners are live put it on a blocking thread; see [`Reloading::load`].
pub(crate) fn load_zones_from_source(
    source: &ZoneSource,
    replicating: bool,
    allow_partial: bool,
) -> Result<HashMap<String, Zone>> {
    match source {
        ZoneSource::SingleFile(path) => {
            // Path-aware, so a `$INCLUDE` in the file resolves next to it rather
            // than against whatever directory the daemon happens to run in.
            let zone_origin = extract_zone_origin_from_path(path);
            let zone = parse_zone_file_at(Path::new(path), &zone_origin)?;
            let mut map = HashMap::new();
            map.insert(zone.origin().to_string(), zone);
            tracing::info!("loaded zone from {}", path);
            Ok(map)
        }
        ZoneSource::Directory(dir) => {
            let zones = enumerate_zone_files(dir, allow_partial)?;
            if zones.is_empty() && !replicating {
                return Err(anyhow!("No .zone files found in directory: {dir}"));
            }
            Ok(zones)
        }
        ZoneSource::Files(files) => {
            // All-or-nothing, like the directory path and for the same reason
            // (`CLAUDE.md` §4): one broken file out of forty must not leave the
            // server up and answering REFUSED for that one zone, which is
            // indistinguishable from a zone nobody configured. Every failure is
            // collected so a deploy is fixed in one pass.
            let mut map = HashMap::new();
            let mut failures = Vec::new();
            for (origin, path) in files {
                match parse_zone_file_at(Path::new(path), origin) {
                    Ok(zone) => {
                        map.insert(zone.origin().to_string(), zone);
                    }
                    Err(e) => failures.push(format!("  {origin} from {path}: {e}")),
                }
            }
            if !failures.is_empty() {
                let listed = failures.join(
                    "
",
                );
                if !allow_partial {
                    return Err(anyhow!(
                        "{} of {} configured zone(s) failed to load:
{listed}",
                        failures.len(),
                        files.len()
                    ));
                }
                tracing::warn!(
                    "{} of {} configured zone(s) failed to load and are NOT being served                      (--allow-partial-load):
{listed}",
                    failures.len(),
                    files.len()
                );
            }
            tracing::info!("loaded {} zone(s) named in the config", map.len());
            Ok(map)
        }
    }
}

/// Extract zone origin from zone file path
/// Example: "example.com.zone" -> "example.com."
pub(crate) fn extract_zone_origin_from_path(path: &str) -> String {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("zone");

    // Remove .zone extension if present
    let origin = if let Some(stripped) = file_name.strip_suffix(".zone") {
        stripped
    } else {
        file_name
    };

    // Ensure it ends with a dot
    if origin.ends_with('.') {
        origin.to_string()
    } else {
        format!("{}.", origin)
    }
}

/// Enumerate all .zone files in a directory and load them
pub(crate) fn enumerate_zone_files(
    dir: &str,
    allow_partial: bool,
) -> Result<HashMap<String, Zone>> {
    let mut zones = HashMap::new();
    let mut failures: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("zone") {
            let path_str = path.to_string_lossy();
            let zone_origin = extract_zone_origin_from_path(&path_str);
            match parse_zone_file_at(&path, &zone_origin) {
                Ok(zone) => {
                    tracing::info!("loaded zone from {}", path_str);
                    zones.insert(zone.origin().to_string(), zone);
                }
                Err(e) => failures.push(format!("{path_str}: {e}")),
            }
        }
    }

    // Every file, then the verdict — rather than stopping at the first failure,
    // because an operator fixing a deploy wants the whole list and not one typo
    // per restart.
    if !failures.is_empty() {
        if !allow_partial {
            // The whole list goes *in* the error rather than only on stderr
            // ahead of it. `main` prints its `Err` with `Debug`, and
            // `anyhow::Error`'s `Debug` is built for exactly this — a
            // `Box<dyn Error>` printed the message as a quoted Rust string with
            // the newlines escaped, which is why this was one line with the
            // detail somewhere else until the binaries moved to anyhow.
            return Err(anyhow!(
                "{} of {} zone files in {dir} failed to load:\n  {}\n\
                 Refusing to serve a partial set; pass --allow-partial-load to serve \
                 the {} that did.",
                failures.len(),
                failures.len() + zones.len(),
                failures.join("\n  "),
                zones.len(),
            ));
        }
        for failure in &failures {
            tracing::warn!("error loading zone file {failure}");
        }
        tracing::warn!(
            "--allow-partial-load: serving {} zones, {} failed and will answer REFUSED",
            zones.len(),
            failures.len()
        );
    }

    tracing::info!("loaded {} zones from directory {}", zones.len(), dir);
    Ok(zones)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_zone_origin_with_extension() {
        // Test zone origin extraction from filename with .zone extension
        let origin = extract_zone_origin_from_path("example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_with_path() {
        // Test zone origin extraction from full path
        let origin = extract_zone_origin_from_path("/etc/dns/example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_already_dotted() {
        // Test zone origin extraction when filename already has trailing dot
        let origin = extract_zone_origin_from_path("example.com..zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_no_extension() {
        // Test zone origin extraction from filename without .zone extension
        let origin = extract_zone_origin_from_path("example.com");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_deep_path() {
        // Test zone origin extraction from deep directory path
        let origin = extract_zone_origin_from_path("/var/lib/dns/zones/example.com.zone");
        assert_eq!(origin, "example.com.");
    }
}
