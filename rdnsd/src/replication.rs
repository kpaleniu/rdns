//! The secondary role: fetching a zone from a master and keeping it.
//!
//! Everything here belongs to a refresh task — one per zone-and-master pair —
//! and shares state with the rest of the process only through [`ReplicationContext`]
//! and `ZoneContext`.
//!
//! The three timers are the whole protocol (RFC 1035 §3.3.13): REFRESH when to
//! ask again, RETRY when to ask again after a failure, EXPIRE when to stop
//! answering. `expire_if_out_of_contact` is separate from the refresh loop
//! because "no contact in too long" is a question about the *zone*, not about
//! any one master.
//!
//! Forgetting a last-contact time is not a degraded cache: it is the difference
//! between a withdrawn zone and a stale one served with AA set. So `record_state`
//! writes through to a sidecar, and a state file that will not read stops the
//! server, where `rdns::journal` — which loses nothing but a full transfer —
//! only warns.
//!
//! The tests live in `main.rs`: a secondary test needs a live primary, so it is
//! built on the `Server` harness there.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use tokio::sync::{Notify, RwLock};

use rdns::clock::current_unix_timestamp;
use rdns::metrics::DnsMetrics;
use rdns::name_keys::NameKeyBuf;
use rdns::notify::NotifyPolicy;
use rdns::readiness::Readiness;
use rdns::secondary::{
    state_file_path, zone_file_path, MasterSpec, RefreshTimers, StateFile, TransferState,
};
use rdns::shutdown::{Busy, Lifecycle};
use rdns::tsig::{TsigKey, TsigKeyring};
use rdns::xfr::{self, Master};
use rdns::xot::{XotClient, XotTrust};
use rdns::zone::Zone;
use rdns::zone_writer::write_zone_file;
use rdns::NameRef;
use rdns::Serial;

use crate::announce_transfer;
use crate::zones::{install_zone, ZoneContext, Zones};

/// One refresh task: what it replicates, and the two handles that steer it.
pub(crate) struct RefreshTask {
    /// The zone and the master it asks, kept so the registry can say what this
    /// server is currently replicating.
    ///
    /// The alternative was the second list that already existed — the
    /// `--secondary` specs, fixed at startup, which `Reloading` held. A
    /// catalog's members would never have joined it, so a reload would re-read a
    /// member's file from disk and serve it with AA set whatever its age, and
    /// the two lists would have had to be kept in step by hand (`CLAUDE.md` §7).
    spec: MasterSpec,
    /// A NOTIFY arriving cuts the wait short.
    wake: Arc<Notify>,
    /// Held rather than dropped, so a task can be stopped. Dropping a
    /// `JoinHandle` detaches the task and cancels nothing (`CLAUDE.md` §9), and
    /// a catalog that drops a member has to stop asking its master about it.
    ///
    /// `None` only in a registry a test built: what those check is what the
    /// registry answers, and there is no runtime under them to have spawned on.
    handle: Option<tokio::task::JoinHandle<()>>,
}

/// One replicated zone: one refresh task per master, since each is on its own
/// timer.
#[derive(Default)]
pub(crate) struct ReplicatedZone {
    tasks: Vec<RefreshTask>,
}

/// Replicated zones by origin.
///
/// [`NameKeyBuf`] rather than the `Vec<u8>` it was until `TODO.md` #40d: the
/// insertion here and the probe in [`Secondaries::notified`] each folded by
/// hand, under two comments pointing at each other to say they agreed
/// (`CLAUDE.md` §17). The constructor folds, so they cannot now disagree, and
/// `Borrow<[u8]>` keeps the probe free of an allocation.
///
/// Mutable behind a lock since `TODO.md` #44a, because catalog zones make
/// membership a thing that changes while the process runs (RFC 9432 §5.1:
/// "when a name server that supports catalog zones completes a zone transfer
/// for a catalog zone, it SHOULD apply changes ... without any manual
/// intervention"). A `std::sync::RwLock` and not tokio's: every section below
/// is a map probe, `notified` is called from a `fn` on the answering path, and
/// nothing here awaits.
#[derive(Default)]
pub(crate) struct Secondaries {
    by_zone: std::sync::RwLock<HashMap<NameKeyBuf, ReplicatedZone>>,
}

/// What a NOTIFY for a zone means here. The waking happens inside
/// [`Secondaries::notified`], under the guard, so the decision and the action
/// cannot come apart.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Notified {
    /// A zone we replicate, from one of its masters: the tasks were woken.
    Refreshing,
    /// A zone we replicate, from anywhere else.
    NotItsMaster,
    /// Not a zone we replicate.
    NotOurs,
}

impl Secondaries {
    /// Read or write the registry, recovering a poisoned lock.
    ///
    /// Nothing inside any of these sections can panic — they are map probes and
    /// `Notify::notify_one` — so a poisoned lock means a panic elsewhere in the
    /// process, not a half-updated registry. Recovering is therefore right, and
    /// is the one answer that neither takes the server off the air (`CLAUDE.md`
    /// §6) nor reports a replicated zone as somebody else's.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<NameKeyBuf, ReplicatedZone>> {
        self.by_zone
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<NameKeyBuf, ReplicatedZone>> {
        self.by_zone
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether this server replicates `zone` from somebody.
    pub(crate) fn replicates(&self, zone: NameRef<'_>) -> bool {
        self.read().contains_key(&*zone.folded())
    }

    /// Act on a NOTIFY: wake the refresh tasks if it came from a master.
    pub(crate) fn notified(&self, zone: NameRef<'_>, from: IpAddr) -> Notified {
        let registry = self.read();
        let Some(replicated) = registry.get(&*zone.folded()) else {
            return Notified::NotOurs;
        };
        if !replicated
            .tasks
            .iter()
            .any(|task| task.spec.master.ip() == from)
        {
            return Notified::NotItsMaster;
        }
        for task in &replicated.tasks {
            // `notify_one` leaves a permit for a task that is mid-transfer, so a
            // NOTIFY arriving at a busy moment is not lost.
            task.wake.notify_one();
        }
        Notified::Refreshing
    }

    fn register(&self, zone: NameRef<'_>, task: RefreshTask) {
        self.write()
            .entry(NameKeyBuf::new(zone))
            .or_default()
            .tasks
            .push(task);
    }

    /// Every (zone, master) pair being replicated right now.
    ///
    /// The list a reload checks against: `--secondary` specs and catalog members
    /// alike, since both arrive here and nowhere else.
    pub(crate) fn specs(&self) -> Vec<MasterSpec> {
        self.read()
            .values()
            .flat_map(|zone| zone.tasks.iter().map(|task| task.spec.clone()))
            .collect()
    }

    /// A registry that answers for these specs, for tests that need the answer
    /// without a refresh task behind it.
    #[cfg(test)]
    pub(crate) fn replicating(specs: &[MasterSpec]) -> Secondaries {
        let registry = Secondaries::default();
        for spec in specs {
            registry.register(
                spec.zone.as_ref(),
                RefreshTask {
                    spec: spec.clone(),
                    wake: Arc::new(Notify::new()),
                    handle: None,
                },
            );
        }
        registry
    }

    /// Stop replicating `zone`: abort its refresh tasks and forget them.
    ///
    /// Aborted rather than asked to stop, so that the caller's next step — which
    /// is removing the zone and deleting its file — cannot race a transfer that
    /// is halfway through installing it. What an abort can interrupt is an await,
    /// so the two places it can land in a refresh are a socket read and a lock
    /// acquisition, and `install_zone` mutates nothing between taking its two
    /// guards and finishing.
    ///
    /// The handles come back because `abort` only *requests* it: the task stops
    /// at its next poll, which can be after a `write_zone_file` already under
    /// way. Awaiting them is what makes "deleted the member's file" true rather
    /// than likely — see [`Secondaries::retired`].
    #[must_use = "await the handles, or the file this deletes can be written again"]
    pub(crate) fn retire(&self, zone: NameRef<'_>) -> Vec<tokio::task::JoinHandle<()>> {
        let Some(replicated) = self.write().remove(&*zone.folded()) else {
            return Vec::new();
        };
        replicated
            .tasks
            .into_iter()
            .filter_map(|task| task.handle)
            .inspect(|handle| handle.abort())
            .collect()
    }

    /// [`Secondaries::retire`], waited out.
    ///
    /// A cancelled task's handle resolves as soon as it has actually stopped,
    /// which is its next poll — so this is short, and after it nothing is still
    /// writing that zone's file.
    pub(crate) async fn retired(&self, zone: NameRef<'_>) {
        for handle in self.retire(zone) {
            // `Err` is the cancellation we asked for, or a panic already logged
            // by the runtime. Either way the task has stopped, which is the
            // whole question here.
            let _ = handle.await;
        }
    }
}

/// What every refresh task shares with the server and with each other.
///
/// Bundled because the pieces are not independently choosable: the delta log is
/// derived from the zone map, and the sidecar lives in the zone directory.
#[derive(Clone)]
pub(crate) struct ReplicationContext {
    pub(crate) served: ZoneContext,
    /// One file, so one mutex: one writer.
    pub(crate) state: Arc<Mutex<StateFile>>,
    pub(crate) zone_dir: PathBuf,
    /// Who to tell when a zone we replicate moves — we are its master to them.
    pub(crate) notify: Arc<NotifyPolicy>,
    /// Ticked off when a zone this server had nothing for arrives, taking a
    /// cold-started secondary from "listening" to "ready".
    pub(crate) readiness: Readiness,
    /// The catalogs this server consumes, so a refresh that installs one
    /// provisions what it lists (RFC 9432 §5.1). Empty for a server with no
    /// `--catalog`, where every call below is a map probe that misses.
    pub(crate) catalogs: Arc<crate::catalog::Catalogs>,
    /// The anchors an XoT master's certificate is checked against
    /// (`--transfer-tls-ca`), or `None` when nothing is transferred over TLS.
    ///
    /// One per process rather than one per master: who issues certificates is
    /// not a decision an operator takes per peer, and the name that *is* per
    /// peer is in [`MasterSpec::tls`].
    pub(crate) xot: Option<XotTrust>,
}

impl ReplicationContext {
    /// How to reach this spec's master: TLS when the spec asked for it
    /// (RFC 9103), plain TCP otherwise.
    ///
    /// The error cannot be reached from a running server — startup refuses a
    /// `+tls=` spec when no `--transfer-tls-ca` names the anchors, and a
    /// catalog's member inherits its catalog's spec whole
    /// ([`MasterSpec::for_member`]). It is an error rather than a fall back to
    /// cleartext because a transfer that quietly goes out unencrypted after an
    /// operator asked for TLS is `CLAUDE.md` §4's case exactly: nothing fails,
    /// and the zone crosses the wire in the clear.
    fn master(&self, spec: &MasterSpec) -> Result<Master> {
        match (&spec.tls, &self.xot) {
            (None, _) => Ok(Master::plain(spec.master)),
            (Some(name), Some(trust)) => Ok(Master::over_tls(
                spec.master,
                XotClient::new(trust.clone(), name.clone()),
            )),
            (Some(name), None) => Err(anyhow!(
                "{} is transferred from {} over TLS as {name}, and no \
                 --transfer-tls-ca names the anchors to check its certificate \
                 against (RFC 9103 §7.5)",
                spec.zone,
                spec.master
            )),
        }
    }
}

/// Start a refresh task per (zone, master), and return what a NOTIFY needs to
/// find them.
pub(crate) fn spawn_secondaries(
    specs: Vec<MasterSpec>,
    keys: &TsigKeyring,
    replication: &ReplicationContext,
    lifecycle: &Lifecycle,
    secondaries: &Arc<Secondaries>,
) -> Result<()> {
    for spec in specs {
        let key = resolve_key(&spec, keys, "--secondary")?;
        spawn_secondary(spec, key, replication, lifecycle, secondaries);
    }
    Ok(())
}

/// The key a spec names, or an error if no `--tsig-key` defines it.
///
/// A key named but not defined is a configuration error, not a reason to
/// transfer unsigned: the operator asked for authentication and could not see
/// that they did not get it.
pub(crate) fn resolve_key(
    spec: &MasterSpec,
    keys: &TsigKeyring,
    flag: &str,
) -> Result<Option<TsigKey>> {
    match &spec.key_name {
        Some(name) => Ok(Some(
            keys.by_name(name)
                .ok_or_else(|| {
                    anyhow!("{flag} names TSIG key {name:?}, which no --tsig-key defines")
                })?
                .clone(),
        )),
        None => Ok(None),
    }
}

/// Start one refresh task and register it, so a NOTIFY can reach it.
///
/// The one way a refresh task comes into being: `--secondary` at startup and a
/// catalog adding a member (`TODO.md` #44a) go through here, so the two cannot
/// register a zone differently.
pub(crate) fn spawn_secondary(
    spec: MasterSpec,
    key: Option<TsigKey>,
    replication: &ReplicationContext,
    lifecycle: &Lifecycle,
    secondaries: &Arc<Secondaries>,
) {
    let wake = Arc::new(Notify::new());
    tracing::info!(
        "secondary for {} from {}{}",
        spec.zone,
        spec.master,
        match &spec.key_name {
            Some(name) => format!(" signed with {name}"),
            None => String::new(),
        }
    );
    let registered = spec.clone();
    let handle = tokio::spawn(secondary_loop(
        spec,
        key,
        replication.clone(),
        wake.clone(),
        lifecycle.clone(),
    ));
    let zone = registered.zone.clone();
    secondaries.register(
        zone.as_ref(),
        RefreshTask {
            spec: registered,
            wake,
            handle: Some(handle),
        },
    );
}

/// Keep one zone in step with one master, forever.
///
/// RFC 1035 §4.3.5's cycle: ask for the SOA, compare serials, transfer if
/// behind, then sleep on REFRESH — or RETRY after a failure, with a NOTIFY
/// cutting the wait short. Out of contact past EXPIRE the zone stops being
/// served, which is what makes this a replica and not a cache.
///
/// The [`Busy`] is held across a refresh and never across the sleep: the sleep
/// is hours long and would burn the whole drain budget. Held across the refresh
/// because `refresh_once` writes the zone file, and `persist` cleans up its
/// `.zone.tmpNNN` sibling on error but not on being killed.
async fn secondary_loop(
    spec: MasterSpec,
    key: Option<TsigKey>,
    replication: ReplicationContext,
    wake: Arc<Notify>,
    lifecycle: Lifecycle,
) {
    let Lifecycle { stop, busy } = lifecycle;
    // What EXPIRE counts from before the master is ever reached. Not "forever
    // ago", which withdraws a held zone before the first attempt, and not
    // "never", which serves a copy of unknown age because we restarted.
    let started_at = current_unix_timestamp();

    loop {
        if stop.is_set() {
            return;
        }
        let result = {
            let _busy = busy.clone();
            refresh_once(&spec, key.as_ref(), &replication, &busy).await
        };

        // After the refresh, not before: the refresh may have just installed
        // the zone that defines them. Read first, a zone's first transfer is
        // followed by the default hour instead of its own REFRESH.
        let timers = zone_timers(&replication.served.zone_map, spec.zone.as_ref()).await;

        let wait = match result {
            Ok(outcome) => {
                tracing::info!("secondary {}: {outcome} (from {})", spec.zone, spec.master);
                // If this zone is a catalog, what it now lists is what this
                // server should hold (RFC 9432 §5.1). A no-op for every other
                // zone, and for a catalog whose serial has not moved. Held
                // `Busy`: provisioning writes the membership sidecar.
                let _busy = busy.clone();
                replication
                    .catalogs
                    .reconcile(
                        spec.zone.as_ref(),
                        &replication,
                        &Lifecycle {
                            stop: stop.clone(),
                            busy: busy.clone(),
                        },
                    )
                    .await;
                timers.after_success()
            }
            Err(e) => {
                tracing::warn!("secondary {} from {}: {e}", spec.zone, spec.master);
                expire_if_out_of_contact(&spec, &replication, started_at, timers).await;
                timers.after_failure()
            }
        };

        // No `Busy` across this: a refresh timer is hours long.
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = wake.notified() => {}
            _ = stop.wait() => return,
        }
    }
}

/// The timers the zone we currently hold asks for, or the defaults if we hold
/// none — a zone we have never fetched has no SOA to obey.
async fn zone_timers(zone_map: &Arc<RwLock<Zones>>, zone: NameRef<'_>) -> RefreshTimers {
    zone_map
        .read()
        .await
        .matching(zone)
        .and_then(RefreshTimers::from_zone)
        .unwrap_or_default()
}

/// One refresh: probe, compare, and transfer if there is anything to transfer.
pub(crate) async fn refresh_once(
    spec: &MasterSpec,
    key: Option<&TsigKey>,
    replication: &ReplicationContext,
    busy: &Busy,
) -> Result<String> {
    let ReplicationContext {
        served,
        state,
        zone_dir,
        notify,
        readiness,
        catalogs: _,
        xot: _,
    } = replication;
    let ZoneContext {
        zone_map, metrics, ..
    } = served;
    // A clone, not a borrow: holding the read lock across a network round trip
    // blocks every reload and swap for the length of the transfer.
    let base = zone_map.read().await.matching(spec.zone.as_ref()).cloned();
    let held = base.as_ref().and_then(Zone::serial);

    let master = replication.master(spec)?;
    let remote = xfr::fetch_soa(&master, spec.zone.as_ref(), key).await?;
    let now = current_unix_timestamp();

    // EXPIRE resets on contact, not on a transfer: a zone confirmed current is
    // exactly what "not stale" means.
    if let Some(held) = held {
        if !remote.is_newer_than(held) {
            record_state(state, spec, held, now, metrics).await?;
            return Ok(format!("serial {held} is current"));
        }
    }

    // A preference, not a demand: the master may answer either request with the
    // whole zone (RFC 1995 §4).
    let mut note = String::new();
    let fetched = match &base {
        Some(base) => match xfr::fetch_changes(&master, base, key).await? {
            xfr::IxfrOutcome::UpToDate(serial) => {
                // The SOA probe said otherwise a moment ago: the master changed
                // its mind between the two questions.
                record_state(state, spec, serial, now, metrics).await?;
                return Ok(format!("serial {serial} is current (the master says so)"));
            }
            xfr::IxfrOutcome::Updated {
                zone,
                steps,
                missing_deletions,
            } => {
                note = format!(", {steps} incremental step(s)");
                if missing_deletions > 0 {
                    // Our copy and the master's had already diverged. Not worth
                    // failing over: the records are meant to be gone either way.
                    note.push_str(&format!(
                        ", {missing_deletions} deletion(s) we did not hold"
                    ));
                }
                zone
            }
            xfr::IxfrOutcome::FullTransfer(zone) => {
                note = ", sent in full".to_string();
                zone
            }
        },
        None => xfr::fetch_zone(&master, spec.zone.as_ref(), key).await?,
    };

    let serial = fetched
        .serial()
        .ok_or_else(|| anyhow!("the transferred zone has no SOA"))?;

    // Persist before serving, so the state line written last is only true once
    // the file and memory agree. Either order costs at most a refetch.
    let path = zone_file_path(zone_dir, &spec.zone.as_ref().to_presentation());
    write_zone_file(&fetched, &path)?;

    let count = fetched.records().len();
    // A whole-zone replacement under the write lock: readers see the old zone
    // or the new one, never a half-applied transfer. The delta is computed here
    // because this is the only moment both versions exist, and it is what lets
    // us answer an IXFR for this step to our own downstream secondaries.
    let soa = fetched.apex_soa_record();
    install_zone(served, fetched).await;
    record_state(state, spec, serial, now, metrics).await?;

    // Idempotent, and a no-op for a zone already there at startup, so the
    // ordinary hourly refresh reports nothing.
    if readiness.arrived(&spec.zone.as_ref().to_presentation()) {
        tracing::info!(
            "{}: first transfer since startup{}",
            spec.zone,
            if readiness.is_ready() {
                " — every zone is now being served, /readyz passes"
            } else {
                ""
            }
        );
    }

    // We are this zone's master to whoever replicates it from us.
    announce_transfer(spec.zone.as_ref(), serial, soa, notify, busy);

    Ok(match held {
        Some(held) => format!("transferred serial {held} -> {serial}, {count} records{note}"),
        None => format!("transferred serial {serial}, {count} records{note}"),
    })
}

pub(crate) async fn record_state(
    state: &Arc<Mutex<StateFile>>,
    spec: &MasterSpec,
    serial: Serial,
    now: u64,
    metrics: &DnsMetrics,
) -> Result<()> {
    // Contact, not transfer: all three callers mean "reached the master", and
    // contact is what EXPIRE counts from. A replica in contact with nothing new
    // to fetch is healthy, and a gauge moving only on a transfer calls it stale.
    metrics.note_zone_transfer(spec.zone.as_ref(), now);

    // Update in memory under the guard, write outside it. `StateFile::record`
    // does both, and its write ends in an fsync of the file and its directory —
    // holding a `std::sync::Mutex` that every other refresh loop then spins on,
    // on a worker also answering queries.
    let (path, text) = {
        let mut file = state.lock().expect("state mutex");
        file.set(TransferState {
            zone: spec.zone.as_ref().to_presentation(),
            serial,
            refreshed_at: now,
            master: spec.master,
        });
        file.snapshot()
    };

    // `spawn_blocking`: the fsync is the point of the write, and not something
    // to do on a worker with queries queued behind it.
    tokio::task::spawn_blocking(move || rdns::secondary::write_snapshot(&path, &text))
        .await
        .context("the task writing the transfer state")?
        .map_err(|e| anyhow!("recording the transfer state: {e}"))
}

/// Stop serving a zone unreachable for longer than its EXPIRE.
///
/// A zone served with AA set claims to be current, so serving one indefinitely
/// turns a primary's outage into wrong answers nobody can see are wrong.
/// Withdrawn, the query gets REFUSED and the resolver tries the delegation's
/// other nameservers.
///
/// The state line stays behind: it records when contact was last made, so a
/// restart sees the zone is still expired rather than reading "nothing known"
/// as "fetch and serve".
pub(crate) async fn expire_if_out_of_contact(
    spec: &MasterSpec,
    replication: &ReplicationContext,
    started_at: u64,
    timers: RefreshTimers,
) {
    let ReplicationContext { served, state, .. } = replication;
    let last_contact = state
        .lock()
        .expect("state mutex")
        .get(&spec.zone.as_ref().to_presentation(), spec.master)
        .map(|s| s.refreshed_at)
        .unwrap_or(started_at);

    if !timers.has_expired(last_contact, current_unix_timestamp()) {
        return;
    }

    if withdraw(served, spec.zone.as_ref()).await {
        // WARN, not INFO: this is what the alert is built on.
        tracing::warn!(
            "secondary {}: EXPIRE ({}s) passed with no contact — no longer serving this zone",
            spec.zone,
            timers.expire
        );
    }
}

/// Stop serving a zone, and forget everything derived from holding it.
///
/// Three callers — EXPIRE, an unvouched copy at startup, a catalog dropping a
/// member — and three copies of it until `TODO.md` #44a, which is how the
/// metrics half came to be missing from one of them once already
/// (`CLAUDE.md` §7, §14). Returns whether the zone was there to withdraw.
pub(crate) async fn withdraw(served: &ZoneContext, zone: NameRef<'_>) -> bool {
    let ZoneContext {
        zone_map,
        deltas,
        metrics,
        journal: _,
    } = served;
    let mut zones = zone_map.write().await;
    if !zones.remove(zone) {
        return false;
    }
    // The increments go with it: offering a chain for a withdrawn zone is
    // answering for something we stopped serving.
    deltas.write().await.forget(zone);
    // And the gauges: a frozen serial shows a withdrawn zone as healthy.
    metrics.forget_zone(zone);
    true
}

/// Withdraw every replicated zone whose age we cannot vouch for.
///
/// Called after each fill of the zone map from disk — startup and every reload,
/// since that is when an expired file can come back. Called from `main` alone,
/// a SIGHUP re-reads every `.zone` file and serves it with AA set again.
///
/// Two ways a zone fails to earn an answer:
///
/// - Its last successful contact is older than the SOA's EXPIRE.
/// - There is no record of contact at all, so the zone came off disk — a
///   missing sidecar, an unreadable one, or an entry for another master.
///   `StateFile::load` returns empty and never fails, so unknown age has to mean
///   "do not serve". The zone returns at the first successful transfer.
///
/// A zone we hold but do not replicate is untouched: the loop is over the
/// `--secondary` specs.
pub(crate) async fn withdraw_unvouched_zones(
    specs: &[MasterSpec],
    served: &ZoneContext,
    zone_dir: &Path,
) {
    let ZoneContext { zone_map, .. } = served;
    let state = StateFile::load(&state_file_path(zone_dir));
    let now = current_unix_timestamp();

    for spec in specs {
        let timers = zone_timers(zone_map, spec.zone.as_ref()).await;
        let why = match state.get(&spec.zone.as_ref().to_presentation(), spec.master) {
            Some(entry) if timers.has_expired(entry.refreshed_at, now) => format!(
                "the copy on disk expired {}s ago",
                now.saturating_sub(entry.refreshed_at + timers.expire)
            ),
            Some(_) => continue,
            None => "there is no record of ever having transferred it, so its age is \
                     unknown"
                .to_string(),
        };

        if withdraw(served, spec.zone.as_ref()).await {
            tracing::warn!(
                "secondary {}: {why} — not serving it until {} answers",
                spec.zone,
                spec.master
            );
        }
    }
}

/// Parse every `--secondary`, or stop.
///
/// A spec that does not parse is an error, not a skip: a secondary silently not
/// replicating a zone is a failure nobody notices until the primary is gone.
pub(crate) fn parse_secondary_specs(specs: &[String]) -> Result<Vec<MasterSpec>> {
    specs
        .iter()
        .filter(|spec| !spec.trim().is_empty())
        .map(|spec| MasterSpec::parse(spec).map_err(|e| anyhow!("--secondary {e}")))
        .collect()
}
