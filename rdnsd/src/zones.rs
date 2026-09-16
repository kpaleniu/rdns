//! The zone map and everything that puts a zone into it: where a zone comes
//! from ([`ZoneSource`], [`load_zones`]), what has to be true before
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

use rdns::clock::current_unix_timestamp;
use rdns::dnssec_key::SigningKey;
use rdns::dnssec_validation_mode::{DnssecValidator, ZoneKeys};
use rdns::ixfr::{plan_change, DeltaLog, PlannedDelta};
use rdns::journal::Journal;
use rdns::metrics::DnsMetrics;
use rdns::name_keys::NameKeyBuf;
use rdns::record_types;
use rdns::zone::{parse_zone_file_at, Zone};
use rdns::zone_signer::{
    active_signing_keys, algorithms_missing_signatures, resign_after, sign_zone,
    sign_zone_incrementally, DenialChain, DnskeySignature, SigningPolicy,
};
use rdns::{Name, NameRef, Qtype, ResourceRecord, Rtype};

use crate::config;
use crate::{absolute_name, Cli};

/// Every zone this server holds, keyed by its origin.
///
/// [`NameKeyBuf`] rather than the `Box<[u8]>` it was until `TODO.md` #40d, which
/// is where the doc comment here asserted "keyed by its origin in `NameKeyBuf`
/// form" about a type that could hold any octets at all (`CLAUDE.md` §17). The
/// key is folded so [`Zones::for_query`] can hash the QNAME's ancestors against
/// it — bounded by the name's label count rather than by how many zones are
/// served — and `Borrow<[u8]>` is what keeps that probe allocation-free.
///
/// The `Arc` lets [`Zones::snapshot`] hand a transfer a version it can write to a
/// socket while reloads replace the map around it.
pub(crate) type ZoneMap = HashMap<NameKeyBuf, Arc<Zone>>;

/// The key a zone is held under: its own origin, folded.
///
/// One definition, so no call site keys on `origin().to_string()` in whatever
/// case its file used. The type now says the same thing, which is what makes
/// reading a key back as a name infallible: six sites re-derived it with
/// `NameRef::from_wire_slice`, and every one of them skipped the zone in silence
/// on an `Err` that could not happen (`CLAUDE.md` §4).
pub(crate) fn zone_key(zone: &Zone) -> NameKeyBuf {
    NameKeyBuf::new(zone.origin())
}

/// What this server last saw in a zone file, for telling a file that moved from
/// one that did not.
///
/// Not a cryptographic digest: the question is whether the bytes changed, and
/// anybody who can rewrite the zone file already owns the process.
/// `DefaultHasher` is not stable across Rust releases, which does not matter —
/// every comparison is against a value this same process computed, and a restart
/// re-reads anyway.
///
/// One copy, used by the UPDATE path (`TODO.md` #64b) and the reload path
/// (#64f), because two implementations of "did these bytes change" is how the
/// two answers come to differ (`CLAUDE.md` §7).
pub(crate) fn digest_of(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

/// Whether `bytes` are a zone file whose content is entirely its own.
///
/// A digest of the file says nothing about a file it `$INCLUDE`s, so an edit to
/// an included file would be invisible to [`Keepable`] — the exact failure the
/// re-read exists to prevent (`CLAUDE.md` §4). A textual test rather than a
/// report from the parser: it cannot miss one, because an `$INCLUDE` the parser
/// acts on is by definition in the text, and a false positive inside a TXT
/// record costs one re-parse.
fn is_self_contained(bytes: &[u8]) -> bool {
    !bytes.split(|b| *b == b'\n').any(|line| {
        line.trim_ascii_start()
            .to_ascii_uppercase()
            .starts_with(b"$INCLUDE")
    })
}

/// What each zone file held when this process last parsed it.
///
/// Shared between the startup load and every reload, so the first SIGHUP after
/// a start already has something to compare against.
#[derive(Clone, Default)]
pub(crate) struct LoadedFiles(Arc<std::sync::Mutex<HashMap<PathBuf, (u64, NameKeyBuf)>>>);

impl LoadedFiles {
    /// The zone key this path last parsed to, if its bytes have not changed
    /// since.
    ///
    /// A poisoned lock answers `None`, so the file is parsed: skipping work on
    /// the strength of state that cannot be read is the wrong way for this to
    /// fail (`CLAUDE.md` §6).
    fn unchanged(&self, path: &Path, digest: u64) -> Option<NameKeyBuf> {
        let seen = self.0.lock().ok()?;
        let (last, key) = seen.get(path)?;
        (*last == digest).then(|| key.clone())
    }

    fn note(&self, path: &Path, digest: u64, key: &NameKeyBuf) {
        let Ok(mut seen) = self.0.lock() else {
            return;
        };
        seen.insert(path.to_path_buf(), (digest, key.clone()));
    }

    /// Forget a file, so the next load parses it.
    fn forget(&self, path: &Path) {
        let Ok(mut seen) = self.0.lock() else {
            return;
        };
        seen.remove(path);
    }
}

/// Whether a reload may keep the zone it is already serving for a file, instead
/// of parsing and signing it again — `TODO.md` #64f, measured at **11.4 s** per
/// unchanged million-record signed zone.
///
/// Two conditions, and both are about *inputs* rather than about the output:
/// the file's bytes are what this process last parsed, and the signing this
/// reload would do has the same key roles as the signing whose output was
/// verified. The second is the same comparison [`ProvenSigning`] already makes,
/// which is not a coincidence — a reload that may skip the verification because
/// nothing about the signing moved is a reload that may skip the signing.
///
/// `None` on the re-signing timer's reload, which carries nothing forward
/// because refreshing is what it woke up to do
/// ([`ZoneSigning::resign_interval`]).
pub(crate) struct Keepable<'a> {
    pub(crate) files: &'a LoadedFiles,
    /// The version being served, or an empty map at startup — where nothing can
    /// be kept and the point of passing one is to record the digests.
    pub(crate) served: &'a ZoneMap,
    pub(crate) signing: Option<&'a ZoneSigning>,
    pub(crate) proved: &'a ProvenSigning,
    /// The moment [`ZoneSigning::apply`] will use, passed rather than read
    /// again: a key crossing its Activate between the two reads would be a
    /// reload that silently declined to act on it.
    pub(crate) signed_at: u64,
}

impl Keepable<'_> {
    /// The served zone for this file, when it may be kept whole.
    fn zone_for(&self, path: &Path, bytes: &[u8]) -> Option<(NameKeyBuf, Arc<Zone>)> {
        if !is_self_contained(bytes) {
            return None;
        }
        let key = self.files.unchanged(path, digest_of(bytes))?;
        let zone = self.served.get(&key)?;
        let origin = key.as_name().to_owned();
        match self.signing.and_then(|s| s.keys_for(&origin)) {
            // Nothing signs this zone, so the file is the whole of its input.
            None => Some((key, zone.clone())),
            // Something does, and its output was verified under the key roles
            // this reload would sign with.
            Some(keys) => {
                let mut run = SigningRun::default();
                run.record(origin.clone(), keys, self.signed_at);
                self.proved
                    .already_proved(&origin, &run)
                    .then(|| (key, zone.clone()))
            }
        }
    }

    fn note(&self, path: &Path, bytes: &[u8], key: &NameKeyBuf) {
        if is_self_contained(bytes) {
            self.files.note(path, digest_of(bytes), key);
        } else {
            // An `$INCLUDE` makes the digest a claim about the wrong file.
            self.files.forget(path);
        }
    }
}

/// A load, and which of its zones came out of the previous one untouched.
pub(crate) struct Loaded {
    pub(crate) zones: ZoneMap,
    /// Kept whole by [`Keepable`], so [`ZoneSigning::apply`] has nothing to do
    /// for them and [`verify_zones`] has nothing to check.
    pub(crate) kept: std::collections::HashSet<NameKeyBuf>,
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
                matches(&rdns::zone::origin_from_path(path)).then(|| PathBuf::from(path))
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
                        && matches(&rdns::zone::origin_from_path(&path.to_string_lossy()))
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
        metrics.set_zone_serial(zone.origin(), serial);
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
            .map(|z| z.origin().to_owned())
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
        touched.push(planned.zone().to_owned());
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
    for (key, zone) in zones.iter() {
        let name = key.as_name();
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

/// Delete the journals of zones this server does not hold.
///
/// The gap [`restore_journals`] cannot see: it walks the zone list, so a journal
/// left behind by a zone removed from the configuration *while the process was
/// down* is never looked at. A reload deletes the journal of a zone it
/// withdraws, and this is the same rule for the withdrawal nobody was running
/// for (`TODO.md` #38b).
///
/// Litter is the smaller half. The larger is that the file resurfaces if a zone
/// of that name is ever added back: `journal::usable_against` refuses a history
/// that does not reach the serial loaded, but a zone re-added at the serial it
/// left at is a zone whose journal describes versions of some earlier
/// incarnation, and a secondary would apply them.
///
/// With `--allow-partial-load` a zone whose file will not parse is not held, so
/// its journal goes too. That is the right way for it to fail: the cost is a
/// full transfer once the typo is fixed, which RFC 1995 §4 permits at any time,
/// and the alternative is deciding a zone is still ours on the strength of a
/// file we could not read.
pub(crate) async fn discard_orphan_journals(journal: &Journal, zone_map: &Arc<RwLock<Zones>>) {
    let journalled = match journal.journalled_zones() {
        Ok(journalled) => journalled,
        // A warning, like every other failure on this path: nothing here has
        // teeth, and a directory we cannot read is not a reason to refuse to
        // serve what we already loaded from it.
        Err(e) => {
            tracing::warn!("could not list the journals: {e}");
            return;
        }
    };
    // Decided under the read guard, deleted outside it: unlinking a directory's
    // worth of files needs nothing from the map.
    let orphans: Vec<Name> = {
        let zones = zone_map.read().await;
        journalled
            .into_iter()
            .filter(|name| zones.matching(name.as_ref()).is_none())
            .collect()
    };
    for name in orphans {
        tracing::info!("discarding the journal for {name}, which is not a zone we hold");
        journal.forget(name.as_ref());
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
        .filter(|old_name| !new_zones.contains_key(*old_name))
        // A key is the zone's origin, so this reads the name back rather than
        // keeping a second spelling of it beside the map.
        .map(|old_name| old_name.as_name().to_owned())
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
            metrics.set_zone_serial(zone.origin(), serial);
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
        if self.by_name.remove(&*name.folded()).is_none() {
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

    /// Every zone held, as something that outlives the guard.
    ///
    /// [`Zones::snapshot`]'s reason, for the caller that wants all of them: a
    /// reload signs the new zones against the versions being served
    /// ([`ZoneSigning::apply`]) and cannot do that under the read lock, since
    /// the signing run is seconds long. `Arc`s, so this is refcounts and not
    /// zones.
    pub(crate) fn snapshot_all(&self) -> ZoneMap {
        self.by_name.clone()
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
        .map(|origin| origin.as_name().label_count())
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
            "--secondary and --catalog need --zone-dir: a transferred zone is \
             written to disk, and --zone-file names one file rather than \
             somewhere to put them",
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
    keys: HashMap<Name, Vec<SigningKey>>,
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
        let mut keys: HashMap<Name, Vec<SigningKey>> = HashMap::new();
        for key in loaded {
            keys.entry(key.owner().to_owned()).or_default().push(key);
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
        let policy = SigningPolicy::valid_for(signed_at, validity).with_chain(chain);
        match over.dnskey_rrsig {
            Some(config::DnskeyRrsig::Imported) => policy.with_imported_dnskey_rrsig(),
            Some(config::DnskeyRrsig::Local) | None => policy,
        }
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
    /// A third of the validity, which is [`resign_after`]'s to decide.
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
    ///
    /// **Shortened to the next key transition when one is nearer** (`TODO.md`
    /// #44f). A rollover moment is read by a signing *run*, so a key that
    /// activates at noon takes effect at the next run — and the ordinary
    /// interval is a third of the validity, ten days by default, for a step
    /// whose entire purpose is to land at a TTL boundary. The timer has to know
    /// what the keys are waiting for.
    pub(crate) fn resign_interval(&self) -> Duration {
        self.resign_interval_at(current_unix_timestamp())
    }

    /// [`ZoneSigning::resign_interval`] against a given instant, which is what
    /// makes it testable without waiting ten days.
    pub(crate) fn resign_interval_at(&self, now: u64) -> Duration {
        let ordinary = resign_after(self.shortest_validity()).max(60);
        let next_key_change = self
            .keys
            .values()
            .flatten()
            .filter_map(|key| key.timing().next_change(now))
            .min()
            // One second past it, not exactly on it: `is_active` is `now >= t`,
            // and waking in the same second the clock reads one tick earlier
            // would re-sign without the change and then sleep the full interval
            // with it pending.
            .map(|at| at.saturating_sub(now).saturating_add(1).max(60));
        Duration::from_secs(match next_key_change {
            Some(next) => ordinary.min(next),
            None => ordinary,
        })
    }

    /// How many of `zones` this would actually sign, for `--check-config`.
    ///
    /// Counted, not assumed: "signing is configured" and "this zone gets
    /// signed" are different claims, and a key directory missing a key is what a
    /// dry run is for.
    ///
    /// `self.keys` is keyed by the key's owner as a [`Name`], whose `Hash` and
    /// `Eq` fold ASCII case (RFC 4343), so a zone spelled with a capital finds
    /// its keys and nothing is down-cased per zone.
    pub(crate) fn signed_zone_count(&self, zones: &ZoneMap) -> usize {
        zones
            .keys()
            .filter(|origin| self.keys.contains_key(&origin.as_name().to_owned()))
            .count()
    }

    /// The shortest configured validity in days, for the startup line.
    pub(crate) fn validity_days(&self) -> u64 {
        self.shortest_validity() / 86_400
    }

    /// The keys that sign `origin`, or `None` for a zone this server does not
    /// sign. The one place the keyring is asked, so a caller cannot key on the
    /// origin in whatever case it had.
    pub(crate) fn keys_for(&self, origin: &Name) -> Option<&[SigningKey]> {
        self.keys.get(origin).map(|k| k.as_slice())
    }

    /// Sign one zone against the version already being served, carrying forward
    /// every signature whose RRset did not move.
    ///
    /// The dynamic-UPDATE path. A full re-sign gives every RRSIG a new inception
    /// and expiration, so the IXFR delta for a one-record update is the whole
    /// zone — 52 records out of 53, against 10 here.
    /// [`ZoneSigning::apply`] carries the same thing forward at a reload, and
    /// takes the whole map because a reload is every zone at once.
    ///
    /// A zone with no key is returned unchanged, exactly as `apply` skips it —
    /// by value, so that case costs no copy of the zone (`TODO.md` #64a).
    pub(crate) fn sign_one_incrementally(&self, previous: &Zone, zone: Zone) -> Result<Zone> {
        let Some(keys) = self.keys.get(&zone.origin().to_owned()) else {
            return Ok(zone);
        };
        let origin = zone.origin().to_string();
        let policy = self.policy_for(&origin, current_unix_timestamp());
        sign_zone_incrementally(previous, &zone, keys, &policy)
            .with_context(|| format!("re-signing {origin} after an update"))
    }

    /// Sign every zone there are keys for, in place.
    ///
    /// A zone we hold keys for and cannot sign is an error, not a zone served
    /// unsigned: its parent's DS points at one of these keys, so the unsigned
    /// answer is bogus at every validating client rather than unvalidated.
    ///
    /// `previous` is the version being served, when there is one: a reload that
    /// was asked for by an operator or a catalog carries every signature whose
    /// RRset did not move, which is 9.7 s against 27.6 s at a million records
    /// even when a tenth of the zone changed (`TODO.md` #65b). `None` at
    /// startup, where there is nothing to carry from, and on the re-signing
    /// timer, whose whole job is to make the signatures new — see
    /// [`ZoneSigning::resign_interval`] and #65a.
    pub(crate) fn apply(
        &self,
        zones: &mut ZoneMap,
        previous: Option<&ZoneMap>,
    ) -> Result<SigningRun> {
        // One moment for the whole run — see `policy_for`.
        self.apply_keeping(
            zones,
            previous,
            &std::collections::HashSet::new(),
            current_unix_timestamp(),
        )
    }

    /// [`ZoneSigning::apply`], told which zones a reload kept whole and given
    /// the moment [`Keepable`] asked its question at (`TODO.md` #64f).
    pub(crate) fn apply_keeping(
        &self,
        zones: &mut ZoneMap,
        previous: Option<&ZoneMap>,
        kept: &std::collections::HashSet<NameKeyBuf>,
        signed_at: u64,
    ) -> Result<SigningRun> {
        let mut run = SigningRun::default();
        for (key, zone) in zones.iter_mut() {
            let origin = key.as_name();
            let Some(keys) = self.keys.get(&origin.to_owned()) else {
                continue;
            };
            run.record(origin.to_owned(), keys, signed_at);
            if kept.contains(key) {
                // The file did not move and the key roles are the ones this
                // zone's signatures were verified under, which is what
                // `Keepable` checked before it declined to read the file. The
                // record above is what lets `verify_zones` skip it too.
                continue;
            }
            let carried = previous.and_then(|served| served.get(key));
            let origin = origin.to_presentation();
            let policy = self.policy_for(&origin, signed_at);
            *zone = Arc::new(match carried {
                Some(served) => sign_zone_incrementally(served, zone, keys, &policy)
                    .with_context(|| format!("re-signing {origin}"))?,
                None => {
                    sign_zone(zone, keys, &policy).with_context(|| format!("signing {origin}"))?
                }
            });
            tracing::info!(
                "signed {origin} with {} key{}, {} for {} day{}{}",
                keys.len(),
                if keys.len() == 1 { "" } else { "s" },
                if matches!(policy.chain, DenialChain::Nsec) {
                    "NSEC"
                } else {
                    "NSEC3"
                },
                (u64::from(policy.expiration) - u64::from(policy.inception)) / 86_400,
                if self.validity == 86_400 { "" } else { "s" },
                match policy.dnskey_signature {
                    DnskeySignature::Imported => ", DNSKEY RRSIG imported (RFC 8901 Model 1)",
                    DnskeySignature::Local => "",
                }
            );
            warn_about_unsigned_algorithms(&origin, zone);
            log_key_schedule(&origin, keys, signed_at);
        }
        Ok(run)
    }
}

/// What one signing run produced: the zones it signed, and the key tags that
/// signed each.
///
/// Handed to [`verify_zones`] so it can tell a zone this process signed a
/// moment ago from a pre-signed one an operator dropped in. Key tags rather
/// than a bare set of origins, because *which* keys sign moves without the zone
/// file moving: a key crossing its Activate changes the output on the next tick
/// (`TODO.md` #44f), and signatures no run has ever checked are exactly what
/// the pass is for.
#[derive(Debug, Default)]
pub(crate) struct SigningRun(HashMap<Name, KeyRoles>);

/// The key tags a run used, by what it used them for.
///
/// Two lists, not one: the same key can be signing and inside its
/// `SyncPublish` window, and the two windows move independently
/// (`TODO.md` #55). A run that starts publishing a CDS produces a zone nothing
/// has verified, with the signing key set unchanged — so a record keyed on the
/// signers alone would skip exactly that load.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
struct KeyRoles {
    /// Whose signatures are in the zone.
    signing: Vec<u16>,
    /// Whose CDS and CDNSKEY are at the apex (RFC 7344).
    syncing: Vec<u16>,
}

impl SigningRun {
    fn record(&mut self, origin: Name, keys: &[SigningKey], signed_at: u64) {
        // Sorted and deduped so a comparison is about the set: key tags are not
        // unique (RFC 4034 Appendix B is a checksum, not an identifier) and
        // `load_dir`'s order is a directory listing's.
        let tidy = |mut tags: Vec<u16>| {
            tags.sort_unstable();
            tags.dedup();
            tags
        };
        self.0.insert(
            origin,
            KeyRoles {
                signing: tidy(
                    active_signing_keys(keys, signed_at)
                        .iter()
                        .map(|k| k.key_tag())
                        .collect(),
                ),
                syncing: tidy(
                    keys.iter()
                        .filter(|k| k.timing().is_sync_published(signed_at))
                        .map(|k| k.key_tag())
                        .collect(),
                ),
            },
        );
    }
}

/// The signing runs this process has already checked its own output of.
///
/// [`verify_zones`] re-checks every signature at every load. For a zone this
/// server signed, with the keys it has already been checked for, that is
/// proving what it did a moment ago — and it is the expensive half: a
/// million-record zone signs in 28 s and verifies in 76 s, paid at every
/// startup, every SIGHUP, every `rdnsctl reload` and every re-signing tick
/// (`TODO.md` #53).
///
/// Not "skip whatever we signed". Verifying our own output is the one place a
/// canonicalization bug in the signer shows up, so the rule is **once per zone
/// per set of key roles**: the first run producing a given zone from a given set
/// of signing keys, with a given set of keys asking the parent for a DS, is
/// checked and its repeats are not. A zone that appears after a SIGHUP is
/// checked, a rollover step makes its zone checked again, a `SyncPublish`
/// crossing does too (`TODO.md` #55), and a zone this server did not sign is
/// checked every time.
///
/// Recorded *after* the zone verifies, never before: a run whose output is
/// rejected must not leave a note saying it was proved, or the next reload
/// installs what this one refused (`CLAUDE.md` §4).
#[derive(Clone, Default)]
pub(crate) struct ProvenSigning(Arc<std::sync::Mutex<HashMap<Name, KeyRoles>>>);

impl ProvenSigning {
    /// Has this run's signing of `origin` already been checked?
    ///
    /// A poisoned lock answers no, so the check runs: skipping work on the
    /// strength of state that cannot be read is the wrong way for this to fail
    /// (`CLAUDE.md` §6 — the decision goes here rather than in an `unwrap`).
    fn already_proved(&self, origin: &Name, run: &SigningRun) -> bool {
        let Some(roles) = run.0.get(origin) else {
            return false;
        };
        let Ok(proved) = self.0.lock() else {
            return false;
        };
        proved.get(origin).is_some_and(|seen| seen == roles)
    }

    fn prove(&self, origin: &Name, run: &SigningRun) {
        let Some(roles) = run.0.get(origin) else {
            return;
        };
        let Ok(mut proved) = self.0.lock() else {
            return;
        };
        proved.insert(origin.clone(), roles.clone());
    }
}

/// What one pass of [`verify_zones`] did.
///
/// Returned so a test can assert on counts rather than on a clock
/// (`CLAUDE.md` §10): "the second load of a zone we signed checks nothing" is
/// an equality, and a timing of the same claim is a coin toss.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Checked {
    /// Zones whose signatures were checked.
    pub(crate) zones: usize,
    /// RRsets checked across them.
    pub(crate) rrsets: usize,
    /// Zones this run signed whose output had already been proved.
    pub(crate) skipped: usize,
}

/// Say what each key is doing right now, once per load.
///
/// A rollover is four moments per key and the operator wrote them into a file
/// weeks earlier; a line per key at startup is how they find out the server
/// agrees. INFO, not DEBUG: this is a handful of lines per reload, and the
/// alternative is discovering the disagreement from a validator.
fn log_key_schedule(origin: &str, keys: &[SigningKey], now: u64) {
    for key in keys {
        let timing = key.timing();
        if timing == rdns::dnssec_key::KeyTiming::default() {
            continue;
        }
        let state = if key.is_active(now) {
            "signing"
        } else if key.is_published(now) {
            // Both ends of the window look the same in the DNSKEY RRset and are
            // different halves of the rollover, so they are not one word.
            match timing.activate {
                Some(at) if now < at => "published, not yet signing",
                _ => "published, retired from signing",
            }
        } else {
            match timing.publish {
                Some(at) if now < at => "held back, not yet published",
                _ => "withdrawn",
            }
        };
        tracing::info!(
            "{origin} key {} ({}): {state}{}",
            key.key_tag(),
            if key.is_sep() { "KSK" } else { "ZSK" },
            match timing.next_change(now) {
                Some(at) => format!(", next change in {}s", at.saturating_sub(now)),
                None => String::new(),
            }
        );
    }
}

/// Say so when a zone publishes a key of an algorithm nothing in it signs with.
///
/// RFC 6840 §5.11: "the zone MUST also be signed with each algorithm (though
/// not each key) present in the DNSKEY RRset", and "this requirement applies to
/// servers, not validators" — so nothing downstream will ever complain, and a
/// zone in this state resolves perfectly while being wrong. The two ways to get
/// here are RFC 8901 §4's "providers ... need to use a common DNSSEC signing
/// algorithm", violated by importing a co-provider's ZSK on an algorithm this
/// server holds no key for, and a half-finished algorithm rollover.
///
/// WARN rather than a refusal, deliberately. The zone validates, so refusing to
/// start would take a working deployment off the air over a conformance point
/// no resolver checks (`CLAUDE.md` §16); and it is a fact about the config, so
/// it belongs where the operator reads it once rather than in a counter.
fn warn_about_unsigned_algorithms(origin: &str, zone: &Zone) {
    let missing = algorithms_missing_signatures(zone);
    if missing.is_empty() {
        return;
    }
    tracing::warn!(
        "{origin} publishes a DNSKEY for algorithm{} {} that nothing in the zone signs with \
         (RFC 6840 §5.11) — a co-provider's key needs an algorithm this server also holds \
         (RFC 8901 §4), and a rollover needs finishing",
        if missing.len() == 1 { "" } else { "s" },
        missing
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
}

/// Check every signature in every zone before anything is served from it.
///
/// "Does each signature cover an RRset that verifies", not "is every RRset
/// signed" — a delegation's NS RRset and its glue carry no signature by design,
/// so the second question fails every zone with a child. This catches expired
/// signatures, and signatures over data since edited.
///
/// The keys are collected once per zone and the loop uses
/// [`DnssecValidator::validate_rrset`]. `validate_response` collects them per
/// call, which made this quadratic in the zone: a ten-thousand-record zone took
/// **112 s** to verify and a million-record one would have taken days, on every
/// startup, every SIGHUP, every `rdnsctl reload`, every re-signing tick and
/// inside `--check-config` (`TODO.md` #50).
///
/// `run` is what the signing that just happened produced and `proved` what this
/// process has checked before; together they say which zones this is proving
/// for a second time. See [`ProvenSigning`] for the rule and why it is not
/// "skip whatever we signed". Both empty — which is what a startup and a
/// `--check-config` hand it — checks everything.
pub(crate) fn verify_zones(
    zones: &ZoneMap,
    validator: &DnssecValidator,
    run: &SigningRun,
    proved: &ProvenSigning,
) -> Result<Checked> {
    let mut done = Checked::default();
    if !validator.is_enabled() {
        return Ok(done);
    }
    for (key, zone) in zones {
        let apex = key.as_name().to_owned();
        let origin = key.as_name().to_presentation();
        if proved.already_proved(&apex, run) {
            done.skipped += 1;
            continue;
        }
        let keys = ZoneKeys::of(zone);
        if !keys.is_signed() {
            // Asking with no records keeps the "is unsigned acceptable"
            // decision in one place.
            let (ok, _) = validator.validate_rrset(zone, &keys, &[]);
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
            let (ok, _) = validator.validate_rrset(zone, &keys, &records);
            if !ok {
                return Err(anyhow!(
                    "{origin}: the {rtype} RRset at {name} does not verify against the zone's \
                     own keys"
                ));
            }
            checked += 1;
        }
        proved.prove(&apex, run);
        done.zones += 1;
        done.rrsets += checked;
        tracing::info!("verified {checked} signed RRsets in {origin}");
    }
    if done.skipped > 0 {
        // Said out loud: a check that stopped running and says nothing is a
        // check the operator believes is in force (`CLAUDE.md` §4).
        tracing::info!(
            "{} zone{} signed here with keys already checked: not verified again",
            done.skipped,
            if done.skipped == 1 { "" } else { "s" },
        );
    }
    Ok(done)
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
        .map(|sig| (sig.owner, sig.type_covered))
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
///
/// `keep` is what a reload may take from the version being served instead of
/// reading it — see [`Keepable`]. `None` for a caller with nothing served *and*
/// nothing to remember, which is `--check-config` and the tests; startup passes
/// one over an empty map, so the first SIGHUP has digests to compare against.
pub(crate) fn load_zones(
    source: &ZoneSource,
    replicating: bool,
    allow_partial: bool,
    keep: Option<&Keepable<'_>>,
) -> Result<Loaded> {
    match source {
        ZoneSource::SingleFile(path) => {
            // Path-aware, so a `$INCLUDE` in the file resolves next to it rather
            // than against whatever directory the daemon happens to run in.
            let zone_origin = rdns::zone::origin_from_path(path);
            let mut loaded = Loaded {
                zones: ZoneMap::new(),
                kept: Default::default(),
            };
            let (key, zone, was_kept) = load_one(Path::new(path), &zone_origin, keep)?;
            if was_kept {
                loaded.kept.insert(key.clone());
            } else {
                tracing::info!("loaded zone from {}", path);
            }
            loaded.zones.insert(key, zone);
            Ok(loaded)
        }
        ZoneSource::Directory(dir) => {
            let loaded = enumerate_zone_files(dir, allow_partial, keep)?;
            if loaded.zones.is_empty() && !replicating {
                return Err(anyhow!("No .zone files found in directory: {dir}"));
            }
            Ok(loaded)
        }
        ZoneSource::Files(files) => {
            // All-or-nothing, as on the directory path: one broken file out of
            // forty must not leave the server answering REFUSED for that zone,
            // which looks the same as a zone nobody configured. Every failure is
            // collected so a deploy is fixed in one pass.
            let mut loaded = Loaded {
                zones: ZoneMap::new(),
                kept: Default::default(),
            };
            let mut failures = Vec::new();
            for (origin, path) in files {
                match load_one(Path::new(path), origin, keep) {
                    Ok((key, zone, was_kept)) => {
                        if was_kept {
                            loaded.kept.insert(key.clone());
                        }
                        loaded.zones.insert(key, zone);
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
                    "{} of {} configured zone(s) failed to load and are NOT being served \
                     (--allow-partial-load):
{listed}",
                    failures.len(),
                    files.len()
                );
            }
            tracing::info!(
                "loaded {} zone(s) named in the config, {} unchanged",
                loaded.zones.len(),
                loaded.kept.len()
            );
            Ok(loaded)
        }
    }
}

/// One zone file: keep what is being served for it, or read and parse it.
///
/// The bytes are read once whether or not they are parsed — the digest is the
/// question, and reading 24 MB is 1.8% of parsing it (`TODO.md` #64b).
fn load_one(
    path: &Path,
    origin: &str,
    keep: Option<&Keepable<'_>>,
) -> Result<(NameKeyBuf, Arc<Zone>, bool), rdns::error::ZoneError> {
    let Some(keep) = keep else {
        let zone = parse_zone_file_at(path, origin)?;
        return Ok((zone_key(&zone), Arc::new(zone), false));
    };
    let text = std::fs::read_to_string(path).map_err(|source| rdns::error::ZoneError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if let Some((key, zone)) = keep.zone_for(path, text.as_bytes()) {
        return Ok((key, zone, true));
    }
    let zone = rdns::zone::parse_zone_text_at(&text, origin, path)?;
    let key = zone_key(&zone);
    keep.note(path, text.as_bytes(), &key);
    Ok((key, Arc::new(zone), false))
}

/// Enumerate all .zone files in a directory and load them, keeping what a
/// reload need not read again.
fn enumerate_zone_files(
    dir: &str,
    allow_partial: bool,
    keep: Option<&Keepable<'_>>,
) -> Result<Loaded> {
    let mut zones = ZoneMap::new();
    let mut kept = std::collections::HashSet::new();
    let mut failures: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("zone") {
            let path_str = path.to_string_lossy().into_owned();
            let zone_origin = rdns::zone::origin_from_path(&path_str);
            match load_one(&path, &zone_origin, keep) {
                Ok((key, zone, was_kept)) => {
                    if was_kept {
                        kept.insert(key.clone());
                    } else {
                        tracing::info!("loaded zone from {}", path_str);
                    }
                    zones.insert(key, zone);
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

    tracing::info!(
        "loaded {} zones from directory {}, {} unchanged",
        zones.len(),
        dir,
        kept.len()
    );
    Ok(Loaded { zones, kept })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{nm, ScratchDir};
    use rdns::dnssec_key::KeyTiming;

    /// The re-signing timer follows the nearest key rollover step when one is
    /// closer than the ordinary tick (`TODO.md` #44f).
    ///
    /// Without it a key that activates at noon waits for the ordinary interval
    /// — ten days, by default — for a step whose entire purpose is to land at a
    /// TTL boundary.
    #[test]
    fn the_resigning_timer_wakes_for_the_next_rollover_step() {
        const NOW: u64 = 1_700_000_000;
        let ordinary = Duration::from_secs(resign_after(30 * 86_400));

        let with = |timing: KeyTiming| {
            let key = rdns::dnssec_key::SigningKey::generate(
                rdns::dnssec_key::SigningAlgorithm::Ed25519,
                "example.com.",
                0x0100,
            )
            .expect("a key")
            .with_timing(timing)
            .expect("legal timing");
            ZoneSigning {
                keys: HashMap::from([(nm("example.com."), vec![key])]),
                validity: 30 * 86_400,
                chain: DenialChain::Nsec,
                per_zone: BTreeMap::new(),
            }
        };

        // No timing at all: the ordinary interval, exactly as before #44f.
        assert_eq!(
            with(KeyTiming::default()).resign_interval_at(NOW),
            ordinary,
            "a key that does not roll schedules nothing"
        );

        // A step an hour away: wake for it, one second past so the signer's own
        // `now >= t` has already turned over.
        let soon = with(KeyTiming {
            activate: Some(NOW + 3600),
            ..KeyTiming::default()
        });
        assert_eq!(
            soon.resign_interval_at(NOW),
            Duration::from_secs(3601),
            "the step, not the tick"
        );

        // A step further away than the ordinary tick changes nothing: the tick
        // will have re-signed and recomputed by then.
        let distant = with(KeyTiming {
            activate: Some(NOW + 400 * 86_400),
            ..KeyTiming::default()
        });
        assert_eq!(distant.resign_interval_at(NOW), ordinary);

        // A step already past is not a step: nothing is scheduled behind us.
        let done = with(KeyTiming {
            activate: Some(NOW - 1),
            ..KeyTiming::default()
        });
        assert_eq!(done.resign_interval_at(NOW), ordinary);

        // And the floor holds, so a step in the next second is not a spin loop.
        let immediate = with(KeyTiming {
            activate: Some(NOW + 1),
            ..KeyTiming::default()
        });
        assert_eq!(immediate.resign_interval_at(NOW), Duration::from_secs(60));
    }

    #[test]
    fn test_extract_zone_origin_with_extension() {
        let origin = rdns::zone::origin_from_path("example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_with_path() {
        let origin = rdns::zone::origin_from_path("/etc/dns/example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_already_dotted() {
        let origin = rdns::zone::origin_from_path("example.com..zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_no_extension() {
        let origin = rdns::zone::origin_from_path("example.com");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_deep_path() {
        let origin = rdns::zone::origin_from_path("/var/lib/dns/zones/example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    /// Two spellings of one origin are one zone, and the second replaces the
    /// first.
    ///
    /// The key type is what upholds it: a `String` key carries whatever case
    /// the zone file used, so a plain `insert` would leave both entries and the
    /// server would answer from whichever the iteration order reached first.
    /// Literally the key type since `TODO.md` #40d — [`NameKeyBuf::new`] folds and
    /// is the only constructor, where `Box<[u8]>` left the folding to whichever
    /// call site built the key.
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

    /// A journal belonging to no zone we hold is deleted at startup, and one
    /// belonging to a zone we do hold is not.
    ///
    /// The withdrawal nobody was running for: a reload deletes the journal of a
    /// zone it drops, so the only way to leave one behind is to remove the zone
    /// while the process is down (`TODO.md` #38b). Nothing swept them, and the
    /// file then resurfaced under a zone of the same name.
    ///
    /// Watched failing without the sweep: both journals were still there.
    #[tokio::test]
    async fn a_journal_no_zone_claims_is_discarded_at_startup() {
        let dir = ScratchDir::new("orphan-journal");

        let at = |origin: &str, serial: u32| {
            rdns::zone::parse_zone_file(
                &format!(
                    "$ORIGIN {origin}\n\
                     $TTL 3600\n\
                     @ IN SOA ns1.{origin} admin.{origin} ( {serial} 3600 600 604800 300 )\n\
                     @ IN NS  ns1.{origin}\n\
                     www IN A 192.0.2.{serial}\n"
                ),
                origin,
            )
            .expect("the test zone parses")
        };

        let journal = Journal::new(dir.path());
        let mut log = DeltaLog::new();
        for origin in ["example.com.", "gone.example.net."] {
            let name = nm(origin);
            log.note_change(Some(&at(origin, 1)), &at(origin, 2));
            journal
                .save(name.as_ref(), &log.all(name.as_ref()))
                .expect("a journal for each");
        }
        // Through the listing rather than the paths: what the sweep reads is
        // what a test should assert on.
        let on_disk = || {
            let mut names: Vec<String> = journal
                .journalled_zones()
                .expect("the directory reads")
                .iter()
                .map(|name| name.to_string())
                .collect();
            names.sort();
            names
        };
        assert_eq!(on_disk(), ["example.com.", "gone.example.net."]);

        // Only one of the two is configured now.
        let mut zones = Zones::default();
        drop(zones.insert(at("example.com.", 2)));
        let zone_map = Arc::new(RwLock::new(zones));

        discard_orphan_journals(&journal, &zone_map).await;

        assert_eq!(
            on_disk(),
            ["example.com."],
            "a zone we serve keeps its history; one nobody serves does not \
             sit there waiting to resurface"
        );
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
            nm(&long).as_ref().label_count()
        );
    }

    /// Verifying a zone costs the same *per RRset* however big the zone is.
    ///
    /// A ratio and not a floor (`CLAUDE.md` §10), because the number itself is
    /// one ECDSA verification and belongs to the machine. What belongs to the
    /// code is the shape: `TODO.md` #50 was `validate_response` collecting
    /// every DNSKEY and every RRSIG in the zone on every call, so the per-RRset
    /// cost grew with the zone — 32 µs at 5,006 RRsets against 1,402, and
    /// 5,632 at 20,006. On a load that meant two minutes for a zone of ten
    /// thousand records and days for a million.
    ///
    /// Four times the zone, so the per-RRset cost is the assertion. Measured on
    /// the development machine, debug build: **1.02×** as it stands and
    /// **2.23×** against the old call, which is what the bound of 1.5 sits
    /// between. Not larger sizes: the quadratic would read further above 1 and
    /// the signing that sets the zone up is already three quarters of the
    /// second this test costs.
    #[test]
    fn verifying_a_zone_costs_the_same_per_rrset_however_big_it_is() {
        const SMALL: usize = 1000;
        const LARGE: usize = 4000;

        let per_rrset = |hosts: usize| -> f64 {
            let (map, rrsets) = signed_zone_of(hosts);
            let validator = DnssecValidator::new(true);
            let start = std::time::Instant::now();
            verify_zones(
                &map,
                &validator,
                &SigningRun::default(),
                &ProvenSigning::default(),
            )
            .expect("the zone we just signed verifies");
            start.elapsed().as_secs_f64() / rrsets as f64
        };

        // Small first, so the large run is not the one paying for a cold
        // allocator or a cold cache.
        let small = per_rrset(SMALL);
        let large = per_rrset(LARGE);
        assert!(
            large < small * 1.5,
            "verifying cost {:.1} µs/RRset at {LARGE} records against {:.1} at {SMALL}: \
             the cost is growing with the size of the zone",
            large * 1e6,
            small * 1e6
        );
    }

    /// A signed zone of `hosts` A records, and how many RRsets carry a
    /// signature — which is what `verify_zones` iterates.
    fn signed_zone_of(hosts: usize) -> (ZoneMap, usize) {
        use rdns::dnssec::DNSKEY_FLAG_ZONE;
        use rdns::dnssec_key::{SigningAlgorithm, SigningKey};

        let mut text = String::from(
            "$ORIGIN example.com.\n\
             $TTL 3600\n\
             @ IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
             @ IN NS ns1.example.com.\n\
             ns1 IN A 192.0.2.1\n",
        );
        for i in 0..hosts {
            text.push_str(&format!("host{i} IN A 192.0.2.2\n"));
        }
        let zone = rdns::zone::parse_zone_file(&text, "example.com.").expect("parse");
        let key = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            DNSKEY_FLAG_ZONE,
        )
        .expect("a key");
        let signed = sign_zone(
            &zone,
            std::slice::from_ref(&key),
            &SigningPolicy::valid_for(current_unix_timestamp(), 30 * 86_400),
        )
        .expect("sign");
        let rrsets = signed_rrsets(&signed).len();
        let mut map = ZoneMap::new();
        map.insert(zone_key(&signed), Arc::new(signed));
        (map, rrsets)
    }

    /// A zone this server signed is proved once, not at every reload.
    ///
    /// `TODO.md` #53: re-signing is a reload, and a reload re-verified
    /// everything — 76 s of a million-record zone to prove what the 28 s above
    /// it had just produced with the same keys.
    ///
    /// Counts, not a clock (`CLAUDE.md` §10): the claim is that the second pass
    /// checks nothing, which is an equality.
    #[test]
    fn a_zone_we_signed_with_the_same_keys_is_proved_once() {
        let signing = signing_with(vec![new_key()]);
        let validator = DnssecValidator::new(true);
        let proved = ProvenSigning::default();

        let mut zones = unsigned_zone();
        let run = signing.apply(&mut zones, None).expect("signs");
        let first = verify_zones(&zones, &validator, &run, &proved).expect("verifies");
        assert_eq!(first.zones, 1, "the first load proves it");
        assert!(first.rrsets > 0, "{first:?}");
        assert_eq!(first.skipped, 0);

        // The re-signing tick, which reloads: the same file, signed again by
        // the same keys, with new inceptions and expirations on every RRSIG.
        let mut zones = unsigned_zone();
        let run = signing.apply(&mut zones, None).expect("signs");
        assert_eq!(
            verify_zones(&zones, &validator, &run, &proved).expect("verifies"),
            Checked {
                zones: 0,
                rrsets: 0,
                skipped: 1
            },
        );
    }

    /// A different set of signing keys is a different thing to prove.
    ///
    /// The case the tracker keys on tags for: a second key starts signing and
    /// the zone file has not moved, so "we signed this zone already" would skip
    /// a signature nothing has ever checked. Two key sets rather than a clock,
    /// because `ZoneSigning::apply` reads the time itself.
    #[test]
    fn a_key_set_that_changed_is_verified_again() {
        let dir = ScratchDir::new("resign-keys");
        new_key().write_to_dir(dir.path()).expect("write");
        let validator = DnssecValidator::new(true);
        let proved = ProvenSigning::default();

        let signing = signing_with(SigningKey::load_dir(dir.path()).expect("load"));
        let mut zones = unsigned_zone();
        let run = signing.apply(&mut zones, None).expect("signs");
        verify_zones(&zones, &validator, &run, &proved).expect("verifies");

        new_key().write_to_dir(dir.path()).expect("write");
        let signing = signing_with(SigningKey::load_dir(dir.path()).expect("load"));
        let mut zones = unsigned_zone();
        let run = signing.apply(&mut zones, None).expect("signs");
        let second = verify_zones(&zones, &validator, &run, &proved).expect("verifies");
        assert_eq!(second.skipped, 0, "a key whose output was never checked");
        assert_eq!(second.zones, 1);
    }

    /// A key crossing its `SyncPublish` makes its zone verified again.
    ///
    /// The hole #55 opened in #53's rule and the reason `SigningRun` records
    /// two lists: the signing key set does not move when a CDS appears, so
    /// "once per zone per set of signing keys" would skip the one load whose
    /// output is new. The CDS and CDNSKEY RRsets are signed by the SEP key
    /// (RFC 7344 §4.1) and nothing would have checked those signatures.
    #[test]
    fn a_key_entering_its_sync_window_is_verified_again() {
        let dir = ScratchDir::new("sync-window");
        let key = SigningKey::generate(
            rdns::dnssec_key::SigningAlgorithm::Ed25519,
            "example.com.",
            rdns::dnssec::DNSKEY_FLAG_ZONE | rdns::dnssec::DNSKEY_FLAG_SEP,
        )
        .expect("a key");
        key.write_to_dir(dir.path()).expect("write");
        let validator = DnssecValidator::new(true);
        let proved = ProvenSigning::default();

        let signing = signing_with(SigningKey::load_dir(dir.path()).expect("load"));
        let mut zones = unsigned_zone();
        let run = signing.apply(&mut zones, None).expect("signs");
        let first = verify_zones(&zones, &validator, &run, &proved).expect("verifies");
        assert_eq!(first.skipped, 0);

        // The same keys, the same file, and no window: a repeat.
        let mut zones = unsigned_zone();
        let run = signing.apply(&mut zones, None).expect("signs");
        assert_eq!(
            verify_zones(&zones, &validator, &run, &proved)
                .expect("verifies")
                .skipped,
            1
        );

        // Now the operator opens the window, which is a line in the key file.
        let path = dir.path().join(key.file_name());
        let text = std::fs::read_to_string(&path).expect("read");
        std::fs::write(&path, format!("{text}SyncPublish: 1\n")).expect("write");
        let signing = signing_with(SigningKey::load_dir(dir.path()).expect("reload"));
        let mut zones = unsigned_zone();
        let run = signing.apply(&mut zones, None).expect("signs");
        let opened = verify_zones(&zones, &validator, &run, &proved).expect("verifies");
        assert_eq!(opened.skipped, 0, "a CDS nothing has checked");
        assert_eq!(opened.zones, 1);
    }

    /// A signing run whose output is rejected leaves nothing behind.
    ///
    /// Recording the proof before the check would let the next reload install
    /// what this one refused (`CLAUDE.md` §4).
    #[test]
    fn a_run_that_failed_to_verify_is_not_recorded_as_proved() {
        let signing = signing_with(vec![new_key()]);
        let validator = DnssecValidator::new(true);
        let proved = ProvenSigning::default();

        let mut zones = unsigned_zone();
        let run = signing.apply(&mut zones, None).expect("signs");
        // Edit one RRset out from under its signature, exactly as an operator
        // editing a pre-signed file does.
        let broken = {
            let zone = zones.values().next().expect("the zone");
            let mut edited = Zone::new(nm("example.com."));
            for record in zone.records() {
                let mut record = record.clone();
                if record.name == nm("ns1.example.com.") && record.rdata.rtype() == record_types::A
                {
                    record.rdata = rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                        "198.51.100.9".parse().unwrap(),
                    ))
                    .unwrap();
                }
                edited.add_record(record);
            }
            edited
        };
        zones.insert(zone_key(&broken), Arc::new(broken));
        verify_zones(&zones, &validator, &run, &proved).expect_err("does not verify");

        // The same run again, against the same tracker: still checked, and
        // still refused.
        verify_zones(&zones, &validator, &run, &proved).expect_err("still does not verify");
    }

    fn new_key() -> SigningKey {
        SigningKey::generate(
            rdns::dnssec_key::SigningAlgorithm::Ed25519,
            "example.com.",
            rdns::dnssec::DNSKEY_FLAG_ZONE,
        )
        .expect("a key")
    }

    fn signing_with(keys: Vec<SigningKey>) -> ZoneSigning {
        ZoneSigning {
            keys: HashMap::from([(nm("example.com."), keys)]),
            validity: 30 * 86_400,
            chain: DenialChain::Nsec,
            per_zone: BTreeMap::new(),
        }
    }

    /// The file, re-read. Each call is a fresh load, which is what a reload is.
    fn unsigned_zone() -> ZoneMap {
        // Unindented on purpose: a leading space makes a line a continuation of
        // the record above it, which is a zone file's own syntax and not this
        // file's formatting.
        const TEXT: &str = "$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
www IN A 192.0.2.2
";
        let zone = rdns::zone::parse_zone_file(TEXT, "example.com.").expect("parse");
        let mut map = ZoneMap::new();
        map.insert(zone_key(&zone), Arc::new(zone));
        map
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

    /// A [`Keepable`] for a server that signs nothing — the common shape in
    /// these tests, and a closure cannot spell its lifetimes.
    fn unsigned_keepable<'a>(
        files: &'a LoadedFiles,
        served: &'a ZoneMap,
        proved: &'a ProvenSigning,
    ) -> Keepable<'a> {
        Keepable {
            files,
            served,
            signing: None,
            proved,
            signed_at: 1_700_000_000,
        }
    }

    /// A directory with one zone file in it, and the source that names it.
    fn zone_dir(dir: &ScratchDir, text: &str) -> (ZoneSource, std::path::PathBuf) {
        let path = dir.path().join("example.com.zone");
        std::fs::write(&path, text).expect("the fixture");
        (
            ZoneSource::Directory(dir.path().to_string_lossy().to_string()),
            path,
        )
    }

    const ZONE_TEXT: &str = "$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )
@ IN NS ns1.example.com.
ns1 IN A 192.0.2.1
";

    /// A reload keeps the zone it is serving when the file did not move, and
    /// reads it again when it did — `TODO.md` #64f, 11.4 s against 39 ms per
    /// unchanged million-record signed zone.
    ///
    /// Pointer identity rather than a clock (`CLAUDE.md` §10): "this is the
    /// same allocation" is exactly the claim, and a timing of it is a coin
    /// toss.
    #[test]
    fn an_unchanged_zone_file_is_not_read_again_and_an_edited_one_is() {
        let dir = ScratchDir::new("keep-unchanged");
        let (source, path) = zone_dir(&dir, ZONE_TEXT);
        let files = LoadedFiles::default();
        let proved = ProvenSigning::default();
        let nothing = ZoneMap::new();
        let keep = |served| unsigned_keepable(&files, served, &proved);

        let first = load_zones(&source, false, false, Some(&keep(&nothing))).expect("loads");
        assert!(first.kept.is_empty(), "nothing was being served");

        let again = load_zones(&source, false, false, Some(&keep(&first.zones))).expect("loads");
        assert_eq!(again.kept.len(), 1, "the file did not move");
        let key = zone_key(&rdns::zone::parse_zone_file(ZONE_TEXT, "example.com.").unwrap());
        assert!(
            Arc::ptr_eq(&first.zones[&key], &again.zones[&key]),
            "the served zone is the one being served, not a copy of it"
        );

        std::fs::write(
            &path,
            format!(
                "{ZONE_TEXT}www IN A 192.0.2.9
"
            ),
        )
        .expect("the edit");
        let edited = load_zones(&source, false, false, Some(&keep(&again.zones))).expect("loads");
        assert!(edited.kept.is_empty(), "the file moved");
        assert!(!Arc::ptr_eq(&again.zones[&key], &edited.zones[&key]));
    }

    /// A digest of a zone file says nothing about a file it `$INCLUDE`s, so a
    /// zone with one is read every time.
    ///
    /// The failure this prevents is the one the re-read exists for: an
    /// operator's edit silently not taken (`CLAUDE.md` §4).
    #[test]
    fn a_zone_that_includes_another_file_is_always_read_again() {
        let dir = ScratchDir::new("keep-include");
        std::fs::write(
            dir.path().join("extra.db"),
            "www IN A 192.0.2.2
",
        )
        .expect("the include");
        let (source, _) = zone_dir(
            &dir,
            &format!(
                "{ZONE_TEXT}$INCLUDE extra.db
"
            ),
        );
        let files = LoadedFiles::default();
        let proved = ProvenSigning::default();
        let nothing = ZoneMap::new();
        let keep = |served| unsigned_keepable(&files, served, &proved);

        let first = load_zones(&source, false, false, Some(&keep(&nothing))).expect("loads");
        assert_eq!(first.zones.len(), 1);
        let key = first.zones.keys().next().expect("one zone").clone();
        assert_eq!(
            first.zones[&key]
                .query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A))
                .len(),
            1,
            "the include was read"
        );
        let again = load_zones(&source, false, false, Some(&keep(&first.zones))).expect("loads");
        assert!(
            again.kept.is_empty(),
            "the parent file's digest cannot speak for the included one"
        );
    }

    /// A key crossing its Activate changes the output with the file unchanged,
    /// so it also has to stop the file being skipped (`TODO.md` #44f, #55).
    ///
    /// The condition is `ProvenSigning`'s, which is not a coincidence: a reload
    /// that may skip verifying because nothing about the signing moved is a
    /// reload that may skip signing.
    #[test]
    fn a_key_that_activates_stops_the_zone_being_kept() {
        // The real clock, because `verify_zones` checks the signatures against
        // it and a fixed moment in the past is an expired zone.
        let now = current_unix_timestamp();
        let later = now + 86_400;
        let waiting = new_key()
            .with_timing(KeyTiming {
                activate: Some(later),
                ..KeyTiming::default()
            })
            .expect("legal timing");
        // Two, because the zone has to be signable at both moments: the second
        // key is what makes the *set* of signers differ between them.
        let signing = signing_with(vec![new_key(), waiting]);
        let validator = DnssecValidator::new(true);
        let proved = ProvenSigning::default();

        // Sign and verify as the startup pass does, at a moment the key does
        // not yet sign at.
        let mut zones = unsigned_zone();
        let run = signing
            .apply_keeping(&mut zones, None, &Default::default(), now)
            .expect("signs");
        verify_zones(&zones, &validator, &run, &proved).expect("verifies");

        let dir = ScratchDir::new("keep-activate");
        let (source, _) = zone_dir(&dir, ZONE_TEXT);
        let files = LoadedFiles::default();
        let at = |signed_at| Keepable {
            files: &files,
            served: &zones,
            signing: Some(&signing),
            proved: &proved,
            signed_at,
        };
        // The load that records the digest, and would keep it at the same
        // moment the startup pass proved it for.
        load_zones(&source, false, false, Some(&at(now))).expect("loads");
        assert_eq!(
            load_zones(&source, false, false, Some(&at(now)))
                .expect("loads")
                .kept
                .len(),
            1,
            "nothing about the signing moved"
        );
        assert!(
            load_zones(&source, false, false, Some(&at(later)))
                .expect("loads")
                .kept
                .is_empty(),
            "the key signs at this moment and did not at the last one"
        );
    }
}
