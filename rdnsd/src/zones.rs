//! The zone map and everything that puts a zone into it: where a zone comes
//! from ([`ZoneSource`], [`load_zones_from_source`]), what has to be true before
//! it is served ([`ZoneSigning`], [`verify_zones`]), and how it is swapped into
//! the map without the derived state falling out of step ([`Zones`], [`ZoneContext`],
//! [`install_zone`]). The reload task is a caller of this, not a part of it.
//!
//! Locks are held across await points on purpose — see [`install_zone`], which
//! plans a diff under the read guard and applies it under the write guard.

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
#[cfg(test)]
use rdns::utils::label_count;
use rdns::utils::{current_unix_timestamp, record_types};
use rdns::zone::{parse_zone_file_at, Zone};
use rdns::zone_signer::{sign_zone, sign_zone_incrementally, DenialChain, SigningPolicy};
use rdns::{Name, NameRef, Qtype, ResourceRecord, Rtype};

use crate::config;
use crate::{absolute_name, Cli};

/// Every zone this server holds, keyed by its origin in
/// [`rdns::utils::NameKeyBuf`] form.
///
/// The key is folded so [`Zones::for_query`] can hash the QNAME's ancestors
/// against it — bounded by the name's label count rather than by how many zones
/// are served. The `Arc` lets [`Zones::snapshot`] hand a transfer a version it
/// can write to a socket while reloads replace the map around it.
pub(crate) type ZoneMap = HashMap<Box<[u8]>, Arc<Zone>>;

/// The key a zone is held under: its own origin, folded. One definition, so no
/// call site keys on `origin().to_string()` in whatever case its file used.
pub(crate) fn zone_key(zone: &Zone) -> Box<[u8]> {
    zone.origin().folded().into_owned().into_boxed_slice()
}

/// Zone source: either a single file or a directory of zone files
#[derive(Clone)]
pub(crate) enum ZoneSource {
    SingleFile(String),
    Directory(String),
    /// Zones that named their own files, from a config file's `[zones.*]`.
    ///
    /// The origin comes from the table key rather than the file name, which
    /// removes the trap `SingleFile` has: `--zone-file` derives the origin from
    /// the path, so `example.com.zone` holding `other.test.` yields NXDOMAIN for
    /// everything with nothing to say why.
    Files(Vec<(String, String)>),
}

impl ZoneSource {
    /// The file a zone's records live in, or `None` if this source has none for
    /// it.
    ///
    /// Derived by the same function the loader uses, not reconstructed at the
    /// call site: a write landing anywhere but where the next load reads from is
    /// an update that vanishes at the next reload, invisible until a restart
    /// because the server keeps answering from memory.
    ///
    /// The directory case scans rather than composing `<dir>/<origin>.zone`:
    /// `enumerate_zone_files` derives each origin from its *file name*, and a
    /// zone's own `$ORIGIN` may say something else.
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
/// The only way a zone should enter the map once the server is running. Both
/// halves happen under the same pair of locks, because the delta log is derived
/// from the zone map: skipping it offers an IXFR chain that does not describe
/// the zone we serve, and a secondary applying it ends up with a zone that never
/// existed holding a serial saying it is current.
pub(crate) async fn install_zone(served: &ZoneContext, zone: Zone) {
    let ZoneContext {
        zone_map,
        deltas,
        metrics,
        journal,
    } = served;
    let origin = zone.origin().to_owned();
    if let Some(serial) = zone.serial() {
        metrics.set_zone_serial(&zone.origin().to_presentation(), serial);
    }

    // The diff walks every record of both versions and queries take this same
    // lock, so it is planned under the read guard rather than the write one.
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
    // Under the same guard that recorded it: the journal is the delta log on
    // disk, and a window where they disagree is one in which a restart serves a
    // chain that does not describe the zone. `write_atomically`, so a reader
    // sees the old file or the new one and never a mixture.
    //
    // A failed write is logged and nothing more: losing a journal costs some
    // secondaries a full transfer, which RFC 1995 §4 permits at any time.
    if recorded {
        if let Some(journal) = journal {
            if let Err(e) = journal.save(origin.as_ref(), &log.all(origin.as_ref())) {
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
pub(crate) async fn install_all_zones(served: &ZoneContext, new_zones: ZoneMap) {
    let ZoneContext {
        zone_map,
        deltas,
        metrics,
        journal,
    } = served;
    // A zone that has gone takes its gauges with it; left behind they show a
    // zone nobody serves as healthy at whatever serial it last had.
    metrics.retain_zones(
        &new_zones
            .values()
            .map(|z| z.origin().to_string())
            .collect::<Vec<_>>(),
    );
    note_serials(metrics, &new_zones);

    // A reload diffs *every* zone, so this is the call site the read/write
    // split exists for. See `Zones`.
    let (mut plan, generation) = {
        let zones = zone_map.read().await;
        (plan_reload(&zones, &new_zones), zones.generation())
    };

    let mut zones = zone_map.write().await;
    let mut log = deltas.write().await;
    if zones.generation() != generation {
        plan = plan_reload(&zones, &new_zones);
    }
    let mut touched: Vec<Name> = Vec::new();
    for gone in plan.forgotten {
        log.forget(gone.as_ref());
        // On disk too: a zone withdrawn from the configuration must not come
        // back after a restart offering increments of something nobody serves.
        if let Some(journal) = journal {
            journal.forget(gone.as_ref());
        }
    }
    for planned in plan.recorded {
        if let Ok(zone) = NameRef::from_wire_slice(planned.zone()) {
            touched.push(zone.to_owned());
        }
        log.record(planned);
    }
    if let Some(journal) = journal {
        for zone in &touched {
            if let Err(e) = journal.save(zone.as_ref(), &log.all(zone.as_ref())) {
                tracing::warn!("could not persist the delta log for {zone}: {e}");
            }
        }
    }

    let displaced = zones.replace_all(new_zones);
    drop(log);
    drop(zones);
    // Outside the guards: freeing the replaced set is one deallocation per
    // record of every zone, and no query need wait for it.
    drop(displaced);
}

/// Prime the delta log from the journals on disk, so a restart does not drop
/// every secondary to a full transfer.
///
/// Every failure here is a warning, unlike the secondary state file, which is
/// fatal. Nothing here has teeth: an unreadable journal costs some secondaries a
/// full transfer, which RFC 1995 §4 permits at any time.
///
/// A journal whose last step does not reach the serial actually loaded is
/// dropped: the zone moved past it by a route the journal never saw — an
/// operator editing the file while the process was down is the ordinary one —
/// and chaining onto it offers a path to a version nobody serves.
pub(crate) async fn restore_journals(
    journal: &Journal,
    zone_map: &Arc<RwLock<Zones>>,
    deltas: &Arc<RwLock<DeltaLog>>,
) {
    let zones = zone_map.read().await;
    let mut log = deltas.write().await;
    for (name, zone) in zones.iter() {
        let Ok(name) = NameRef::from_wire_slice(name) else {
            continue;
        };
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
    forgotten: Vec<Name>,
    recorded: Vec<PlannedDelta>,
}

pub(crate) fn plan_reload(zones: &Zones, new_zones: &ZoneMap) -> ReloadPlan {
    // Both sides are folded keys, so "is this zone still configured" is a
    // lookup rather than a scan of the new set per zone in the old.
    let forgotten = zones
        .keys()
        .filter(|old_name| !new_zones.contains_key(old_name.as_ref() as &[u8]))
        // The map's keys are folded wire octets, which is a name — so this
        // reads one back rather than keeping a second spelling beside it.
        .filter_map(|old_name| NameRef::from_wire_slice(old_name).ok())
        .map(|name| name.to_owned())
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
pub(crate) fn note_serials(metrics: &DnsMetrics, zones: &ZoneMap) {
    for zone in zones.values() {
        if let Some(serial) = zone.serial() {
            metrics.set_zone_serial(&zone.origin().to_presentation(), serial);
        }
    }
}

/// The zones this server answers from, and a counter that moves whenever the
/// set does.
///
/// The counter is why this is not a bare `HashMap`. `ixfr::diff` walks every
/// record of both versions, so it is planned under the read lock and recorded
/// under the write lock — under the write lock it blocks every query for the
/// length of the walk, and on a SIGHUP for the sum of all of them.
///
/// That leaves a window between the two guards in which another task can
/// install, expire or withdraw a zone, and a delta computed against the wrong
/// old version hands a secondary a zone that never existed. `generation` closes
/// it: equal means the plan stands, different means re-plan under the write
/// lock.
///
/// A counter and not a serial, because an edited file reloaded without a bump
/// carries the same serial over different records: the check is about
/// identity.
///
/// Mutation goes through the methods below and there is no `DerefMut`, so the
/// counter cannot be forgotten at a call site.
#[derive(Debug, Default)]
pub(crate) struct Zones {
    by_name: ZoneMap,
    generation: u64,
    /// The deepest origin held, in labels — where [`Zones::for_query`] starts its
    /// walk. A suffix of the QNAME with more labels than this cannot be an
    /// origin, so hashing it is work with one outcome.
    ///
    /// Without it the walk costs one lookup per label of the *client's* name: a
    /// 34-label reverse-IPv6 PTR read 598 ns against 40 for an ordinary name.
    /// With it, 53 ns either way.
    ///
    /// It only grows, which is the direction that fails safely: too large costs
    /// a few wasted lookups, too small skips the suffix one of our zones is at
    /// and answers REFUSED for it. So `insert` raises it, `remove` leaves it
    /// alone, and only `replace_all` recomputes.
    deepest: usize,
}

impl Zones {
    pub(crate) fn new(by_name: ZoneMap) -> Self {
        Zones {
            deepest: deepest_origin(&by_name),
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
    /// The key is folded, so two spellings of one origin are one entry and a
    /// plain `insert` replaces rather than duplicates.
    ///
    /// The displaced version is handed back rather than dropped, so the caller
    /// can let it go after releasing the lock: freeing a zone is one
    /// deallocation per record, and no query should wait on those.
    #[must_use = "drop the displaced zone after releasing the lock, not under it"]
    pub(crate) fn insert(&mut self, zone: Zone) -> Option<Arc<Zone>> {
        self.deepest = self.deepest.max(zone.origin().label_count());
        let displaced = self.by_name.insert(zone_key(&zone), Arc::new(zone));
        self.generation += 1;
        displaced
    }

    /// Withdraw a zone. `true` if one was actually held.
    pub(crate) fn remove(&mut self, name: NameRef<'_>) -> bool {
        if self
            .by_name
            .remove(name.folded().as_ref() as &[u8])
            .is_none()
        {
            return false;
        }
        self.generation += 1;
        true
    }

    /// Swap the whole set, as a reload does, handing back the set replaced.
    ///
    /// Dropped by the caller once the lock is released, as in [`Zones::insert`]
    /// — more so here, since a reload displaces every zone at once.
    #[must_use = "drop the displaced zones after releasing the lock, not under it"]
    pub(crate) fn replace_all(&mut self, by_name: ZoneMap) -> ZoneMap {
        self.deepest = deepest_origin(&by_name);
        self.generation += 1;
        std::mem::replace(&mut self.by_name, by_name)
    }

    /// The version held for `name`, whatever case either is in.
    ///
    /// `absolute_lowered` borrows when there is nothing to fold, so a name that
    /// arrived absolute and lower-case — every name off the wire that matches a
    /// zone — looks itself up without allocating.
    pub(crate) fn matching(&self, name: NameRef<'_>) -> Option<&Zone> {
        self.by_name.get(name.folded().as_ref()).map(Arc::as_ref)
    }

    /// The version held for `name`, as something that outlives the guard.
    ///
    /// For the one caller that cannot finish under the lock: an AXFR writes the
    /// whole zone to a socket, and holding the read guard across those writes
    /// puts every reload behind the slowest client. The snapshot stays the
    /// version current when it was taken, which is also what makes a transfer
    /// correct — half of one version and half of the next is a zone that never
    /// existed.
    pub(crate) fn snapshot(&self, name: NameRef<'_>) -> Option<Arc<Zone>> {
        self.by_name.get(name.folded().as_ref()).cloned()
    }

    /// The zone that should answer `qname`: the most specific one the name is at
    /// or under, or `None` if this server holds none.
    ///
    /// A walk up the QNAME's ancestors, not a scan of the zones. The first hit
    /// is the longest suffix that is an origin, so a server holding both
    /// `example.com` and `sub.example.com` answers for the child from the
    /// child's zone. 30 ns at one zone and 32 at ten thousand, where a scan
    /// costs 4.1 µs at a thousand and 55 µs at ten thousand.
    ///
    /// A [`ZoneMap`] key is absolute and ASCII-folded (RFC 4343), so the walk
    /// needs the QNAME in that form and nothing else. ASCII-only:
    /// `str::to_lowercase` maps U+212A KELVIN SIGN onto `k`, which would select
    /// a zone for a name that differs from its origin on the wire.
    ///
    /// Nothing scans the whole QNAME. The walk starts at the deepest suffix that
    /// could be an origin (see [`Zones::deepest`]) and folds after that, so a
    /// 34-label reverse-IPv6 PTR costs what a three-label name costs. Reaching
    /// that suffix is one `rmatch_indices` pass over the last `deepest` labels;
    /// counting from the left reads the name once per label, 340 ns against 58
    /// on a length the client picks.
    ///
    /// Both `Cow`s borrow for a name that arrived absolute and lower-case, which
    /// is every name off the wire, so the lookup allocates nothing.
    pub(crate) fn for_query(&self, qname: NameRef<'_>) -> Option<&Zone> {
        // Every ancestor from `deepest` labels down, which is where the
        // deepest zone this server holds could start.
        for candidate in qname.ancestors().skip(
            qname
                .label_count()
                .saturating_sub(self.deepest.min(qname.label_count())),
        ) {
            if let Some(zone) = self.by_name.get(candidate.folded().as_ref()) {
                return Some(zone);
            }
        }
        None
    }
}

/// The label count of the deepest origin in `zones`, for [`Zones::deepest`].
fn deepest_origin(zones: &ZoneMap) -> usize {
    zones
        .keys()
        .filter_map(|origin| NameRef::from_wire_slice(origin).ok())
        .map(|origin| origin.label_count())
        .max()
        .unwrap_or(0)
}

// Read-only, deliberately: every mutation has to go through a method that
// moves `generation`, and a `DerefMut` would be a way around that.
impl std::ops::Deref for Zones {
    type Target = ZoneMap;

    fn deref(&self) -> &Self::Target {
        &self.by_name
    }
}

/// The three things that describe what this server is currently serving.
///
/// Grouped because they are only ever updated together: a zone installed is a
/// new version in the delta log and a new serial on the gauge, and a zone
/// withdrawn has to leave all three. Three parameters is how one gets forgotten
/// at a fourth call site.
#[derive(Clone)]
pub(crate) struct ZoneContext {
    pub(crate) zone_map: Arc<RwLock<Zones>>,
    pub(crate) deltas: Arc<RwLock<DeltaLog>>,
    pub(crate) metrics: Arc<DnsMetrics>,
    /// Where the delta log is persisted, so a restart does not drop every
    /// secondary to a full transfer. `None` when there is no directory to put it
    /// in, which is `--zone-file` and the tests.
    ///
    /// In this group because the journal *is* the delta log, on disk: updating
    /// one and not the other offers an IXFR chain after a restart that does not
    /// describe the zone being served.
    pub(crate) journal: Option<Arc<Journal>>,
}

/// Exactly one of `zone_file` or `zone_dir`.
///
/// `replicating` narrows it: a fetched zone has to be written somewhere, and a
/// single `--zone-file` is no place for a zone whose name we have not seen.
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
            if !Path::new(&file).exists() {
                return Err(anyhow!("Zone file not found: {file}"));
            }
            Ok(ZoneSource::SingleFile(file))
        }
        (None, Some(dir)) => {
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
/// Only zones loaded from disk are signed. A transferred zone is the master's,
/// signatures included: the parent's DS points at their key, not ours.
pub(crate) struct ZoneSigning {
    /// Keys by the zone they are published at, down-cased.
    keys: HashMap<String, Vec<SigningKey>>,
    validity: u64,
    chain: DenialChain,
    /// Zones whose signing settings differ from the two above, by apex.
    ///
    /// Only a config file can populate this: there is no flag shape for "NSEC3
    /// for this zone and NSEC for the rest".
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
            // Not an error: a key directory prepared before any key is in it
            // is reasonable. But silence looks like signing that did nothing.
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
    /// `signed_at` is passed in so every zone in one run shares a moment: two
    /// zones signed a second apart across an hour boundary would otherwise
    /// derive serials from different hours.
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
    /// The minimum, not the global setting: a seven-day zone among thirty-day
    /// ones is the one that expires if the timer runs on the global number.
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
    /// A third of the validity — see `zone_signer::RESIGN_FRACTION`.
    ///
    /// The timer re-signs by *reloading*, which is the only correct shape: the
    /// served serial is the file's serial plus a time term
    /// (`zone_signer::signed_serial`) and the in-memory zone already carries the
    /// derived value, so re-signing that would compound the bump every cycle.
    /// Re-reading the file makes it idempotent, and picks up an edit within one
    /// interval without a SIGHUP.
    ///
    /// Floored at a minute so a tiny `--signature-validity` cannot make this a
    /// spin loop.
    pub(crate) fn resign_interval(&self) -> Duration {
        Duration::from_secs((self.shortest_validity() / 3).max(60))
    }

    /// How many of `zones` this would actually sign, for `--check-config`.
    ///
    /// Counted, not assumed: "signing is configured" and "this zone gets
    /// signed" are different claims, and a key directory missing a key is what a
    /// dry run is for.
    ///
    /// `self.keys` is keyed by `dnssec::canonical_name` — down-cased text — and
    /// a [`ZoneMap`] key is the *folded* wire form, so spelling one out is
    /// already canonical and no fold is needed per zone.
    pub(crate) fn signed_zone_count(&self, zones: &ZoneMap) -> usize {
        zones
            .keys()
            .filter_map(|origin| NameRef::from_wire_slice(origin).ok())
            .filter(|origin| self.keys.contains_key(&origin.to_presentation()))
            .count()
    }

    /// The shortest configured validity in days, for the startup line.
    pub(crate) fn validity_days(&self) -> u64 {
        self.shortest_validity() / 86_400
    }

    /// Sign every zone there are keys for, in place.
    ///
    /// A zone we hold keys for and cannot sign is an error, not a zone served
    /// unsigned: its parent's DS points at one of these keys, so the unsigned
    /// answer is bogus at every validating client rather than unvalidated.
    /// Sign one zone against the version already being served, carrying forward
    /// every signature whose RRset did not move.
    ///
    /// The dynamic-UPDATE path, not the load path. A full re-sign gives every
    /// RRSIG a new inception and expiration, so the IXFR delta for a one-record
    /// update is the whole zone — 52 records out of 53, against 10 here. At load
    /// there is no previous version to carry forward from and
    /// [`ZoneSigning::apply`] is the right call.
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

    pub(crate) fn apply(&self, zones: &mut ZoneMap) -> Result<()> {
        // One moment for the whole run — see `policy_for`.
        let signed_at = current_unix_timestamp();
        for (key, zone) in zones.iter_mut() {
            let Ok(origin) = NameRef::from_wire_slice(key) else {
                continue;
            };
            let origin = origin.to_presentation();
            let Some(keys) = self.keys.get(&origin) else {
                continue;
            };
            let policy = self.policy_for(&origin, signed_at);
            *zone = Arc::new(
                sign_zone(zone, keys, &policy).with_context(|| format!("signing {origin}"))?,
            );
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
/// "Does each signature cover an RRset that verifies", not "is every RRset
/// signed" — a delegation's NS RRset and its glue carry no signature by design,
/// so the second question fails every zone with a child. This catches expired
/// signatures, and signatures over data since edited.
pub(crate) fn verify_zones(zones: &ZoneMap, validator: &DnssecValidator) -> Result<()> {
    if !validator.is_enabled() {
        return Ok(());
    }
    for (key, zone) in zones {
        let Ok(origin) = NameRef::from_wire_slice(key) else {
            continue;
        };
        let origin = origin.to_presentation();
        let signed = DnssecValidator::is_zone_signed(zone);
        if !signed {
            // Asking `validate_response` with no records keeps the "is
            // unsigned acceptable" decision in one place.
            let (ok, _) = validator.validate_response(zone, &[], &origin);
            if !ok {
                return Err(anyhow!("{origin} is not signed"));
            }
            continue;
        }

        let mut checked = 0usize;
        for (name, rtype) in signed_rrsets(zone) {
            let records = zone.query(name.as_ref(), Qtype::of(rtype));
            if records.is_empty() {
                return Err(anyhow!(
                    "{origin}: a signature covers the {rtype} RRset at {name}, which is not there"
                ));
            }
            let (ok, _) =
                validator.validate_response(zone, &records, &name.as_ref().to_presentation());
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
pub(crate) fn signed_rrsets(zone: &Zone) -> Vec<(Name, Rtype)> {
    let mut seen: Vec<(Name, Rtype)> = zone
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
        // `Rrsig::owner` is canonical text; the caller wants a name.
        .filter_map(|sig| {
            Name::from_presentation(&sig.owner)
                .ok()
                .map(|n| (n, sig.type_covered))
        })
        .collect();
    // Sorted by the folded octets: `Name` has no `Ord`, because DNS's own
    // ordering is RFC 4034 §6.1's and not the octets' — and this only wants a
    // stable order to dedupe against.
    seen.sort_by(|a, b| {
        a.0.as_ref()
            .folded()
            .cmp(&b.0.as_ref().folded())
            .then(a.1.to_u16().cmp(&b.1.to_u16()))
    });
    seen.dedup();
    seen
}

/// Load zones from a single file or a directory.
///
/// Three questions, three answers:
///
/// - Could the directory be read? Always fatal. Reading an `Err` as an empty
///   directory leaves the server up, listening, and answering REFUSED for every
///   name it serves.
/// - Did every zone file parse? Fatal unless `--allow-partial-load`. See
///   [`enumerate_zone_files`].
/// - Is the directory empty? Fatal except when replicating: a secondary's first
///   start has nothing on disk yet, while for a primary an empty `--zone-dir` is
///   a typo in the path.
///
/// The emptiness check is here rather than in `enumerate_zone_files` because
/// only this function knows which caller is a secondary.
///
/// Blocking, and says so: `read_dir`, then a `read_to_string` and a full parse
/// per zone. Callers running while the listeners are live put it on a blocking
/// thread; see [`crate::Reloading::load`].
pub(crate) fn load_zones_from_source(
    source: &ZoneSource,
    replicating: bool,
    allow_partial: bool,
) -> Result<ZoneMap> {
    match source {
        ZoneSource::SingleFile(path) => {
            // Path-aware, so a `$INCLUDE` in the file resolves next to it rather
            // than against whatever directory the daemon happens to run in.
            let zone_origin = extract_zone_origin_from_path(path);
            let zone = parse_zone_file_at(Path::new(path), &zone_origin)?;
            let mut map = ZoneMap::new();
            map.insert(zone_key(&zone), std::sync::Arc::new(zone));
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
            // All-or-nothing, as on the directory path: one broken file out of
            // forty must not leave the server answering REFUSED for that zone,
            // which looks the same as a zone nobody configured. Every failure is
            // collected so a deploy is fixed in one pass.
            let mut map = ZoneMap::new();
            let mut failures = Vec::new();
            for (origin, path) in files {
                match parse_zone_file_at(Path::new(path), origin) {
                    Ok(zone) => {
                        map.insert(zone_key(&zone), std::sync::Arc::new(zone));
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

/// `example.com.zone` -> `example.com.`
pub(crate) fn extract_zone_origin_from_path(path: &str) -> String {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("zone");

    let origin = if let Some(stripped) = file_name.strip_suffix(".zone") {
        stripped
    } else {
        file_name
    };

    if origin.ends_with('.') {
        origin.to_string()
    } else {
        format!("{}.", origin)
    }
}

/// Enumerate all .zone files in a directory and load them
pub(crate) fn enumerate_zone_files(dir: &str, allow_partial: bool) -> Result<ZoneMap> {
    let mut zones = ZoneMap::new();
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
                    zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
                }
                Err(e) => failures.push(format!("{path_str}: {e}")),
            }
        }
    }

    // Every file, then the verdict: an operator fixing a deploy wants the whole
    // list, not one typo per restart.
    if !failures.is_empty() {
        if !allow_partial {
            // The whole list goes *in* the error, not on stderr ahead of it:
            // `main` prints its `Err` with `Debug`, which `anyhow::Error`
            // renders for reading and `Box<dyn Error>` renders as an escaped
            // Rust string literal.
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
    use crate::testutil::nm;

    #[test]
    fn test_extract_zone_origin_with_extension() {
        let origin = extract_zone_origin_from_path("example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_with_path() {
        let origin = extract_zone_origin_from_path("/etc/dns/example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_already_dotted() {
        let origin = extract_zone_origin_from_path("example.com..zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_no_extension() {
        let origin = extract_zone_origin_from_path("example.com");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_deep_path() {
        let origin = extract_zone_origin_from_path("/var/lib/dns/zones/example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    /// Two spellings of one origin are one zone, and the second replaces the
    /// first.
    ///
    /// The key type is what upholds it: a `String` key carries whatever case
    /// the zone file used, so a plain `insert` would leave both entries and the
    /// server would answer from whichever the iteration order reached first.
    #[test]
    fn one_origin_in_two_cases_is_one_zone() {
        let mut zones = Zones::default();
        drop(zones.insert(Zone::new(nm("Example.COM."))));
        let displaced = zones.insert(Zone::new(nm("example.com.")));

        assert!(displaced.is_some(), "the first version was replaced");
        assert_eq!(zones.len(), 1);
        assert!(zones.matching(nm("EXAMPLE.com.").as_ref()).is_some());
        assert!(
            zones.remove(nm("example.COM.").as_ref()),
            "and it is withdrawn by either"
        );
        assert!(zones.is_empty());
    }

    /// A snapshot is a version, not a view of the map.
    ///
    /// What lets an AXFR write a whole zone to a socket without holding the
    /// lock, and what makes that correct rather than merely allowed: half of one
    /// version followed by half of the next is a zone that never existed, which
    /// a secondary would store, serve with AA set, and hand on with a serial
    /// saying it is current.
    #[test]
    fn a_snapshot_outlives_the_reload_that_replaces_it() {
        let at = |serial: u32| {
            rdns::zone::parse_zone_file(
                &format!(
                    "$ORIGIN example.com.\n\
                     $TTL 3600\n\
                     @ IN SOA ns1.example.com. admin.example.com. ( {serial} 3600 600 604800 300 )\n\
                     @ IN NS  ns1.example.com.\n"
                ),
                "example.com.",
            )
            .expect("the test zone parses")
        };

        let mut zones = Zones::default();
        drop(zones.insert(at(1)));
        let held = zones
            .snapshot(nm("example.com.").as_ref())
            .expect("it is served");

        let mut reloaded = ZoneMap::new();
        let next = at(2);
        reloaded.insert(zone_key(&next), Arc::new(next));
        drop(zones.replace_all(reloaded));

        assert_eq!(held.serial().map(|s| s.to_u32()), Some(1), "the transfer's");
        assert_eq!(
            zones
                .matching(nm("example.com.").as_ref())
                .and_then(Zone::serial)
                .map(|s| s.to_u32()),
            Some(2),
            "and the map has moved on without it"
        );
    }

    /// Choosing a zone must cost the same however many zones are served.
    ///
    /// A ratio, not a floor: the same lookups timed against one zone and against
    /// a thousand, on whatever machine runs it. A scan reads 10.3 ns at one zone
    /// and 4.1 µs at a thousand; the walk reads 30 ns and 32. Watched failing at
    /// 554×.
    ///
    /// The two loops do identical work per query; only the map size differs.
    #[test]
    fn choosing_a_zone_costs_the_same_however_many_are_served() {
        const ZONES: usize = 1_000;
        // Deep enough to have ancestors to walk.
        const QNAME: &str = "host.deep.z500.test.";

        let mut one = Zones::default();
        drop(one.insert(Zone::new(nm("z500.test."))));
        let mut many = Zones::default();
        for i in 0..ZONES {
            drop(many.insert(Zone::new(nm(&format!("z{i}.test.")))));
        }
        assert_eq!(many.len(), ZONES, "z500 is one of the thousand");

        let with_one = time_lookups(&one, QNAME, true);
        let with_many = time_lookups(&many, QNAME, true);
        assert!(
            with_many < with_one * 10,
            "choosing among {ZONES} zones took {with_many:?} against {with_one:?} for one: \
             the cost is growing with the number of zones served"
        );
    }

    /// And it must cost the same however long the *client's* name is.
    ///
    /// The other multiplier, and the one a stranger picks. A 34-label
    /// reverse-IPv6 PTR has 34 suffixes, and on a server whose zones are two
    /// labels deep only the last two can match. Walking down from the QNAME
    /// hashes all of them: 598 ns against 40 for an ordinary name. Starting at
    /// [`Zones::deepest`] reads 53 either way.
    ///
    /// A regression for a defect the walk introduced, not for the scan it
    /// replaced — a scan gets this right by accident, its cost being the zone
    /// count and never the name.
    #[test]
    fn a_long_qname_does_not_cost_more_than_a_short_one() {
        let mut zones = Zones::default();
        drop(zones.insert(Zone::new(nm("example.test."))));

        let long: String =
            (0..32).map(|i| format!("{}.", i % 10)).collect::<String>() + "ip6.arpa.";
        let short = time_lookups(&zones, "nothing.here.test.", false);
        let deep = time_lookups(&zones, &long, false);
        assert!(
            deep < short * 10,
            "a {}-label name cost {deep:?} against {short:?} for a 3-label one: \
             the cost is growing with a length the client chooses",
            label_count(&long)
        );
    }

    /// The same lookup, timed. Best of three: a lost timeslice can only make a
    /// run look slower, so the minimum is the closest either side gets to the
    /// truth.
    fn time_lookups(zones: &Zones, qname: &str, expect_hit: bool) -> Duration {
        const QUERIES: usize = 20_000;
        let qname = nm(qname);
        (0..3)
            .map(|_| {
                let start = std::time::Instant::now();
                for _ in 0..QUERIES {
                    assert_eq!(
                        zones
                            .for_query(std::hint::black_box(qname.as_ref()))
                            .is_some(),
                        expect_hit
                    );
                }
                start.elapsed()
            })
            .min()
            .expect("three runs")
    }
}
