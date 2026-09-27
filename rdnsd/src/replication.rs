//! The secondary role: fetching a zone from a master and keeping it.
//!
//! Everything here belongs to a refresh task — one per zone-and-master pair —
//! and shares state with the rest of the process only through [`ReplicationContext`]
//! and `ZoneContext`.
//!
//! The three timers are the whole protocol (RFC 1035 §3.3.13): REFRESH when to
//! ask again, RETRY when to ask again after a failure, EXPIRE when to stop
//! answering. When each is due is `rdns::secondary::refresh_cycle`'s; what is
//! here is the zone. `recorded_contact` asks about the *zone*, not about any
//! one master, because "no contact in too long" is a question about the zone.
//!
//! Forgetting a last-contact time is not a degraded cache: it is the difference
//! between a withdrawn zone and a stale one served with AA set. So `record_state`
//! writes through to a sidecar, and a state file that will not read stops the
//! server, where `rdns::journal` — which loses nothing but a full transfer —
//! only warns.
//!
//! A secondary test needs a live primary, which `testutil::spawn_primary`
//! builds out of `dispatch`'s own transfer path.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use tokio::sync::{Notify, RwLock};

use rdns::clock::{current_unix_timestamp, Clock};
use rdns::metrics::DnsMetrics;
use rdns::name_keys::NameKeyBuf;
use rdns::notify::NotifyPolicy;
use rdns::secondary::{
    refresh_cycle, state_file_path, zone_file_path, Contact, MasterSpec, RefreshTimers, Replica,
    StateFile, TransferState,
};
use rdns::shutdown::{Busy, Lifecycle};
use rdns::tsig::{TsigKey, TsigKeyring};
use rdns::xfr::{self, Master};
use rdns::xot::{XotClient, XotTrust};
use rdns::zone::Zone;
use rdns::zone_writer::write_zone_file;
use rdns::NameRef;
use rdns::Serial;
use rdns_transport::readiness::Readiness;

use crate::notify_out::announce_transfer;
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

    /// Every master `zone` is replicated from right now.
    fn masters(&self, zone: NameRef<'_>) -> Vec<SocketAddr> {
        self.read()
            .get(&*zone.folded())
            .map(|replicated| {
                replicated
                    .tasks
                    .iter()
                    .map(|task| task.spec.master)
                    .collect()
            })
            .unwrap_or_default()
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
    /// What contact and EXPIRE are measured on, so a test can move past an
    /// EXPIRE without waiting it out (`TODO.md` #128).
    pub(crate) clock: Clock,
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
        secondaries.clone(),
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

/// Keep one zone in step with one master, until the stop.
///
/// The timing is [`refresh_cycle`]'s. Out of contact past EXPIRE the zone stops
/// being served, which is what makes this a replica and not a cache.
async fn secondary_loop(
    spec: MasterSpec,
    key: Option<TsigKey>,
    replication: ReplicationContext,
    wake: Arc<Notify>,
    lifecycle: Lifecycle,
    secondaries: Arc<Secondaries>,
) {
    let clock = replication.clock.clone();
    let replica = ZoneReplica {
        spec,
        key,
        replication,
        secondaries,
        lifecycle: lifecycle.clone(),
    };
    refresh_cycle(replica, &wake, &clock, lifecycle).await;
}

/// `rdnsd`'s half of [`refresh_cycle`]: a zone in the zone map, its file, and
/// the sidecar recording contact.
struct ZoneReplica {
    spec: MasterSpec,
    key: Option<TsigKey>,
    replication: ReplicationContext,
    secondaries: Arc<Secondaries>,
    /// For the catalog reconcile after a refresh, which provisions members
    /// and so spawns tasks of its own.
    lifecycle: Lifecycle,
}

impl Replica for ZoneReplica {
    /// Held [`Busy`] by the cycle, because `refresh_once` writes the zone file
    /// and `persist` cleans up its `.zone.tmpNNN` sibling on error but not on
    /// being killed.
    async fn refresh(&mut self) -> Contact {
        let spec = &self.spec;
        let refreshed = refresh_once(
            spec,
            self.key.as_ref(),
            &self.replication,
            &self.lifecycle.busy,
        )
        .await;
        match refreshed {
            Ok(outcome) => {
                tracing::info!("secondary {}: {outcome} (from {})", spec.zone, spec.master);
                Contact::Made(self.held_timers().await)
            }
            Err(e) => {
                tracing::warn!("secondary {} from {}: {e}", spec.zone, spec.master);
                Contact::Lost
            }
        }
    }

    async fn held_timers(&self) -> RefreshTimers {
        zone_timers(&self.replication.served.zone_map, self.spec.zone.as_ref()).await
    }

    fn recorded_contact(&self) -> Option<u64> {
        // Every master of the zone, this one included: the spawn runs before
        // the registration, so the first pass may not find it.
        let mut masters = self.secondaries.masters(self.spec.zone.as_ref());
        if !masters.contains(&self.spec.master) {
            masters.push(self.spec.master);
        }
        recorded_contact(&self.spec, &masters, &self.replication)
    }

    async fn in_contact(&mut self, _after_expiry: bool) {
        // If this zone is a catalog, what it now lists is what this server
        // should hold (RFC 9432 §5.1). A no-op for every other zone, and for a
        // catalog whose serial has not moved.
        self.replication
            .catalogs
            .reconcile(self.spec.zone.as_ref(), &self.replication, &self.lifecycle)
            .await;
    }

    async fn expired(&mut self, timers: RefreshTimers) {
        withdraw_expired(&self.spec, &self.replication.served, timers).await;
    }
}

// The timers the zone we currently hold asks for, or the defaults if we hold
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
        clock: _,
    } = replication;
    let ZoneContext {
        zone_map, metrics, ..
    } = served;
    // A clone, not a borrow: holding the read lock across a network round trip
    // blocks every reload and swap for the length of the transfer.
    let base = zone_map.read().await.matching(spec.zone.as_ref()).cloned();
    let held = base.as_ref().and_then(Zone::serial);

    let master = replication.master(spec)?;
    let refreshed = xfr::refresh_zone(&master, spec.zone.as_ref(), key, base.as_ref()).await?;
    let now = replication.clock.now();

    // EXPIRE resets on contact, not on a transfer: a zone confirmed current is
    // exactly what "not stale" means.
    let fetched = match refreshed {
        xfr::Refresh::Current {
            serial,
            answering_the_transfer,
        } => {
            record_state(state, spec, serial, now, metrics).await?;
            return Ok(if answering_the_transfer {
                format!("serial {serial} is current (the master says so)")
            } else {
                format!("serial {serial} is current")
            });
        }
        xfr::Refresh::Fetched(fetched) => fetched,
    };
    let note = fetched.how();
    let fetched = fetched.zone;

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

/// When the zone last had contact with any of `masters`, per the sidecar.
///
/// Contact is with the zone, not with `spec`'s master: one of them answering
/// keeps it served (`StateFile::last_contact`, `TODO.md` #131). The line
/// outlives the process, so a restart sees an expired zone as expired rather
/// than reading "nothing known" as "fetch and serve".
pub(crate) fn recorded_contact(
    spec: &MasterSpec,
    masters: &[SocketAddr],
    replication: &ReplicationContext,
) -> Option<u64> {
    replication
        .state
        .lock()
        .expect("state mutex")
        .last_contact(&spec.zone.as_ref().to_presentation(), masters)
}

/// Stop serving a zone unreachable for longer than its EXPIRE.
///
/// A zone served with AA set claims to be current, so serving one indefinitely
/// turns a primary's outage into wrong answers nobody can see are wrong.
/// Withdrawn, the query gets REFUSED and the resolver tries the delegation's
/// other nameservers.
pub(crate) async fn withdraw_expired(
    spec: &MasterSpec,
    served: &ZoneContext,
    timers: RefreshTimers,
) {
    if withdraw(served, spec.zone.as_ref()).await {
        // WARN, not INFO: this is what the alert is built on.
        tracing::warn!(
            "secondary {}: EXPIRE ({}s) passed with no contact — no longer serving this zone",
            spec.zone,
            timers.expire
        );
    }
}

// Stop serving a zone, and forget everything derived from holding it.
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
///   missing sidecar, an unreadable one, or lines only for masters no longer
///   configured. `StateFile::load` returns empty and never fails, so unknown
///   age has to mean "do not serve". The zone returns at the first successful
///   transfer.
///
/// Asked per zone over all of its masters in `specs`, not per spec: one master
/// in contact vouches for the zone (`TODO.md` #131).
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

    let mut zones: Vec<(&rdns::Name, Vec<SocketAddr>)> = Vec::new();
    for spec in specs {
        match zones.iter_mut().find(|(zone, _)| **zone == spec.zone) {
            Some((_, masters)) => masters.push(spec.master),
            None => zones.push((&spec.zone, vec![spec.master])),
        }
    }

    for (zone, masters) in zones {
        let timers = zone_timers(zone_map, zone.as_ref()).await;
        let why = match state.last_contact(&zone.as_ref().to_presentation(), &masters) {
            Some(last) if timers.has_expired(last, now) => format!(
                "the copy on disk expired {}s ago",
                now.saturating_sub(last.saturating_add(timers.expire))
            ),
            Some(_) => continue,
            None => "there is no record of ever having transferred it, so its age is \
                     unknown"
                .to_string(),
        };

        if withdraw(served, zone.as_ref()).await {
            tracing::warn!(
                "secondary {zone}: {why} — not serving it until {} answers",
                masters
                    .iter()
                    .map(SocketAddr::to_string)
                    .collect::<Vec<_>>()
                    .join(" or ")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{
        nm, spawn_primary, spawn_primary_full, spawn_primary_with_acl, spawn_primary_with_history,
        test_shutdown, zkey, zone_at_serial, ScratchDir,
    };
    use crate::zones::{zone_key, ZoneContext, Zones};
    use rdns::clock::current_unix_timestamp;
    use rdns::ixfr::DeltaLog;
    use rdns::metrics::DnsMetrics;
    use rdns::notify::{self, NotifyPeer, NotifyPolicy};
    use rdns::secondary::{
        state_file_path, zone_file_path, MasterSpec, RefreshTimers, StateFile, TransferState,
    };
    use rdns::tsig::{self, TsigAlgorithm, TsigKey, TsigKeyring};
    use rdns::validation::{Arrival, PeerCertificate, TlsVersion};
    use rdns::zone::{parse_zone_file_at, Zone};
    use rdns::{record_types, DnsMessage, OpCode, Qtype, ResponseCode, Serial};
    use rdns_transport::readiness::Readiness;
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UdpSocket};
    use tokio::sync::RwLock;

    #[test]
    fn test_secondary_specs_are_parsed_or_refused() {
        let specs = parse_secondary_specs(&[
            "example.com@127.0.0.1:5353".to_string(),
            "  ".to_string(), // an empty repetition is not a zone
        ])
        .expect("parse");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].zone, nm("example.com."));

        let err = parse_secondary_specs(&["nonsense".to_string()])
            .unwrap_err()
            .to_string();
        assert!(
            err.to_string().contains("--secondary"),
            "the error names the flag: {err}"
        );
    }

    /// A consumer of no catalogs, for the refresh tests: they are about the
    /// transfer, and `--catalog` adds nothing to it until a catalog arrives.
    fn no_catalogs() -> Arc<crate::catalog::Catalogs> {
        crate::catalog::Catalogs::new(
            Vec::new(),
            &TsigKeyring::default(),
            std::collections::HashSet::new(),
            Vec::new(),
            Path::new("."),
            Arc::new(Secondaries::default()),
            &std::collections::BTreeMap::new(),
        )
        .expect("no specs, nothing to resolve")
    }

    /// The replication context a refresh runs in, over a scratch directory.
    fn replication(dir: &ScratchDir, notify: NotifyPolicy) -> ReplicationContext {
        ReplicationContext {
            served: ZoneContext {
                zone_map: Arc::new(RwLock::new(Zones::default())),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
                metrics: Arc::new(DnsMetrics::new()),
                journal: None,
            },
            state: Arc::new(Mutex::new(StateFile::load(&state_file_path(dir.path())))),
            zone_dir: dir.path().to_path_buf(),
            notify: Arc::new(notify),
            // Nothing here probes `/readyz`; `readiness::tests` is where the
            // latch itself is checked.
            readiness: Readiness::ready(),
            catalogs: no_catalogs(),
            xot: None,
            clock: Clock::system(),
        }
    }

    /// The whole of step 3 in one test: a zone this server has never seen is
    /// fetched, served, written down, and remembered.
    #[tokio::test]
    async fn test_a_secondary_fetches_serves_and_persists_a_zone() {
        let dir = ScratchDir::new("fetch");
        let master = spawn_primary(&zone_at_serial(7)).await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        let r = replication(&dir, NotifyPolicy::default());

        let outcome = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("refresh");
        assert!(outcome.contains("transferred serial 7"), "got: {outcome}");

        // Served from memory...
        let zones = r.served.zone_map.read().await;
        let held = zones
            .get(nm("example.com.").as_ref().folded().as_ref())
            .expect("the zone is now served");
        assert_eq!(held.serial(), Some(Serial::new(7)));
        assert_eq!(
            held.query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A))
                .len(),
            1
        );
        drop(zones);

        // ...written to disk, in the form the ordinary load path reads...
        let path = zone_file_path(dir.path(), "example.com.");
        let reloaded = parse_zone_file_at(&path, "example.com.").expect("reload from disk");
        assert_eq!(reloaded.serial(), Some(Serial::new(7)));
        assert_eq!(reloaded.records().len(), 4);

        // ...and remembered, so a restart knows when contact was last made.
        let entry = r
            .state
            .lock()
            .unwrap()
            .get("example.com.", master)
            .cloned()
            .expect("state recorded");
        assert_eq!(entry.serial, Serial::new(7));
        assert!(entry.refreshed_at > 0);

        // ...*on disk*, and not only in the copy held in memory. The assertion
        // above passes whether or not the sidecar was ever written, which is
        // exactly what a restart depends on — and the half a refactor of the
        // write path can break in silence. `record_state` updates under the
        // mutex and writes after dropping it, so "the entry is there" and "the
        // file has it" became two separate claims.
        let on_disk = StateFile::load(&state_file_path(dir.path()))
            .get("example.com.", master)
            .cloned()
            .expect("the sidecar on disk has the entry, not just the copy in memory");
        assert_eq!(on_disk.serial, Serial::new(7));
        assert_eq!(on_disk.refreshed_at, entry.refreshed_at);
    }

    /// The serial comparison is the point of the SOA probe: an unchanged zone
    /// must not be transferred again, or every refresh interval would move the
    /// whole zone for nothing.
    #[tokio::test]
    async fn test_an_unchanged_serial_is_not_transferred_again() {
        let dir = ScratchDir::new("unchanged");
        let master = spawn_primary(&zone_at_serial(7)).await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        let r = replication(&dir, NotifyPolicy::default());

        refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("first refresh");
        let second = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("second refresh");

        assert!(second.contains("current"), "got: {second}");
        assert_eq!(
            r.served
                .zone_map
                .read()
                .await
                .get(zkey("example.com.").as_slice())
                .unwrap()
                .serial(),
            Some(Serial::new(7))
        );
    }

    /// And a serial that moved forward *is* transferred, replacing the zone
    /// wholesale rather than merging into it.
    #[tokio::test]
    async fn test_a_bumped_serial_replaces_the_zone() {
        let dir = ScratchDir::new("bumped");
        let spec_zone = "example.com.".to_string();
        let r = replication(&dir, NotifyPolicy::default());

        let old = spawn_primary(&zone_at_serial(7)).await;
        refresh_once(
            &MasterSpec {
                zone: nm(&spec_zone.clone()),
                master: old,
                key_name: None,
                tls: None,
            },
            None,
            &r,
            &test_shutdown().busy(),
        )
        .await
        .expect("first");

        // A primary whose zone has moved on — and lost a record, which is what
        // proves the zone is replaced rather than added to.
        let new = spawn_primary(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n",
        )
        .await;
        let outcome = refresh_once(
            &MasterSpec {
                zone: nm(&spec_zone),
                master: new,
                key_name: None,
                tls: None,
            },
            None,
            &r,
            &test_shutdown().busy(),
        )
        .await
        .expect("second");

        assert!(outcome.contains("serial 7 -> 8"), "got: {outcome}");
        let zones = r.served.zone_map.read().await;
        let held = zones.get(zkey("example.com.").as_slice()).unwrap();
        assert_eq!(held.serial(), Some(Serial::new(8)));
        assert!(
            held.query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A))
                .is_empty(),
            "a record the new zone does not have must be gone, not merged"
        );
    }

    /// EXPIRE is the timer with teeth: out of contact past it, the zone stops
    /// being served rather than being answered for with stale data and AA set.
    #[tokio::test]
    async fn test_a_zone_out_of_contact_past_expire_is_withdrawn() {
        let dir = ScratchDir::new("expire");
        let master = "127.0.0.1:1"
            .parse()
            .expect("an address nothing answers on");
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };

        let zone = rdns::zone::parse_zone_file(&zone_at_serial(7), "example.com.").expect("zone");
        let timers = RefreshTimers::from_zone(&zone).expect("timers");
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
        let zone_map = Arc::new(RwLock::new(Zones::new(zones)));

        let mut state_file = StateFile::load(&state_file_path(dir.path()));
        // Contact was made, a very long time ago.
        state_file
            .record(TransferState {
                zone: "example.com.".to_string(),
                serial: Serial::new(7),
                refreshed_at: current_unix_timestamp() - timers.expire - 1,
                master,
            })
            .expect("record");
        let state = Arc::new(Mutex::new(state_file));

        let r = ReplicationContext {
            served: ZoneContext {
                zone_map: zone_map.clone(),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
                metrics: Arc::new(DnsMetrics::new()),
                journal: None,
            },
            state: state.clone(),
            zone_dir: dir.path().to_path_buf(),
            notify: Arc::new(NotifyPolicy::default()),
            readiness: Readiness::ready(),
            catalogs: no_catalogs(),
            xot: None,
            clock: Clock::system(),
        };
        let last = recorded_contact(&spec, &[master], &r).expect("contact was recorded");
        assert!(timers.has_expired(last, current_unix_timestamp()));
        withdraw_expired(&spec, &r.served, timers).await;
        assert!(
            zone_map.read().await.is_empty(),
            "an expired zone is no longer served"
        );

        // And the state line survives, so a restart still knows it is expired
        // rather than reading "nothing known" as "fetch and serve".
        assert!(state.lock().unwrap().get("example.com.", master).is_some());
    }

    /// Within EXPIRE, a failure to reach the master changes nothing: that is the
    /// whole point of having three timers rather than one.
    #[tokio::test]
    async fn test_a_recent_failure_does_not_withdraw_the_zone() {
        let dir = ScratchDir::new("still-good");
        let master = "127.0.0.1:1".parse().unwrap();
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };

        let zone = rdns::zone::parse_zone_file(&zone_at_serial(7), "example.com.").expect("zone");
        let timers = RefreshTimers::from_zone(&zone).expect("timers");
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
        let zone_map = Arc::new(RwLock::new(Zones::new(zones)));

        let mut state_file = StateFile::load(&state_file_path(dir.path()));
        state_file
            .record(TransferState {
                zone: "example.com.".to_string(),
                serial: Serial::new(7),
                refreshed_at: current_unix_timestamp() - 60,
                master,
            })
            .expect("record");
        let state = Arc::new(Mutex::new(state_file));

        let r = ReplicationContext {
            served: ZoneContext {
                zone_map: zone_map.clone(),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
                metrics: Arc::new(DnsMetrics::new()),
                journal: None,
            },
            state: state.clone(),
            zone_dir: dir.path().to_path_buf(),
            notify: Arc::new(NotifyPolicy::default()),
            readiness: Readiness::ready(),
            catalogs: no_catalogs(),
            xot: None,
            clock: Clock::system(),
        };
        let last = recorded_contact(&spec, &[master], &r).expect("contact was recorded");
        assert!(
            !timers.has_expired(last, current_unix_timestamp()),
            "still served"
        );
    }

    /// A zone replicated from two masters, `dead` never having answered and
    /// `live` having answered a minute ago, with the zone held.
    struct TwoMasters {
        _dir: ScratchDir,
        dead: MasterSpec,
        live: MasterSpec,
        timers: RefreshTimers,
        replication: ReplicationContext,
    }

    fn two_masters(name: &str) -> TwoMasters {
        let dir = ScratchDir::new(name);
        let spec = |master: &str| MasterSpec {
            zone: nm("example.com."),
            master: master.parse().expect("an address"),
            key_name: None,
            tls: None,
        };
        let (dead, live) = (spec("127.0.0.1:1"), spec("127.0.0.1:2"));

        let zone = rdns::zone::parse_zone_file(&zone_at_serial(7), "example.com.").expect("zone");
        let timers = RefreshTimers::from_zone(&zone).expect("timers");
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));

        let mut state = StateFile::load(&state_file_path(dir.path()));
        state
            .record(TransferState {
                zone: "example.com.".to_string(),
                serial: Serial::new(7),
                refreshed_at: current_unix_timestamp() - 60,
                master: live.master,
            })
            .expect("record");

        let replication = ReplicationContext {
            served: ZoneContext {
                zone_map: Arc::new(RwLock::new(Zones::new(zones))),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
                metrics: Arc::new(DnsMetrics::new()),
                journal: None,
            },
            state: Arc::new(Mutex::new(state)),
            zone_dir: dir.path().to_path_buf(),
            notify: Arc::new(NotifyPolicy::default()),
            readiness: Readiness::ready(),
            catalogs: no_catalogs(),
            xot: None,
            clock: Clock::system(),
        };
        TwoMasters {
            _dir: dir,
            dead,
            live,
            timers,
            replication,
        }
    }

    /// One master in contact keeps a zone served, however long the other has
    /// been silent. RFC 1034 §4.3.5 discards a copy only when "the secondary
    /// finds it impossible to perform a serial check for the EXPIRE interval"
    /// (`TODO.md` #131). Watched failing with contact looked up per master:
    /// the zone was withdrawn.
    #[tokio::test]
    async fn one_dead_master_of_two_does_not_expire_the_zone() {
        let t = two_masters("two-masters-expire");
        let masters = [t.dead.master, t.live.master];

        let last = recorded_contact(&t.dead, &masters, &t.replication);
        assert!(
            last.is_some_and(|last| !t.timers.has_expired(last, current_unix_timestamp())),
            "the live master vouches for the zone"
        );

        // The control: with only the dead master configured, nothing vouches,
        // and the cycle counts from its own start.
        assert_eq!(
            recorded_contact(&t.dead, &[t.dead.master], &t.replication),
            None
        );
    }

    /// The same at startup and on every reload: a master with no line in the
    /// sidecar does not unvouch a zone another master has one for
    /// (`TODO.md` #131). Watched failing against the per-spec loop: the zone
    /// was withdrawn.
    #[tokio::test]
    async fn one_unreached_master_of_two_does_not_unvouch_the_zone() {
        let t = two_masters("two-masters-unvouched");
        let specs = [t.dead.clone(), t.live.clone()];

        withdraw_unvouched_zones(&specs, &t.replication.served, &t.replication.zone_dir).await;
        assert_eq!(t.replication.served.zone_map.read().await.len(), 1);

        withdraw_unvouched_zones(&specs[..1], &t.replication.served, &t.replication.zone_dir).await;
        assert!(
            t.replication.served.zone_map.read().await.is_empty(),
            "and alone, the unreached master vouches for nothing"
        );
    }

    /// A refresh against a master that remembers the change moves only the
    /// difference — and lands on the same zone a full transfer would have.
    ///
    /// The equality is the assertion that matters: an incremental transfer that
    /// produces a *nearly* right zone is the failure mode this whole path has,
    /// and no serial comparison afterwards would ever notice it.
    #[tokio::test]
    async fn test_a_refresh_takes_the_increment_when_the_master_has_one() {
        let dir = ScratchDir::new("ixfr-in");
        let old_text = zone_at_serial(7);
        let new_text = "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.250\n\
             extra IN TXT \"added in version 8\"\n";

        let r = replication(&dir, NotifyPolicy::default());

        // Start from version 7, fetched in full because we hold nothing yet.
        let first = spawn_primary(&old_text).await;
        let spec = |master| MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        refresh_once(&spec(first), None, &r, &test_shutdown().busy())
            .await
            .expect("initial transfer");

        // Now a master that knows how to get from 7 to 8.
        let master = spawn_primary_with_history(&old_text, new_text).await;
        let outcome = refresh_once(&spec(master), None, &r, &test_shutdown().busy())
            .await
            .expect("incremental refresh");
        assert!(
            outcome.contains("1 incremental step(s)"),
            "expected an increment, got: {outcome}"
        );

        let zones = r.served.zone_map.read().await;
        let held = zones
            .get(zkey("example.com.").as_slice())
            .expect("still served");
        assert_eq!(held.serial(), Some(Serial::new(8)));
        assert_eq!(
            held.query(
                nm("extra.example.com.").as_ref(),
                Qtype::of(record_types::TXT)
            )
            .len(),
            1
        );
        assert!(
            held.query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A))
                .iter()
                .all(|r| r
                    .rdata
                    .parse()
                    .map(
                        |p| matches!(p, rdns::ParsedRecord::A(a) if a.octets() == [192, 0, 2, 250])
                    )
                    .unwrap_or(false)),
            "the old address must be gone, not merged"
        );

        // Record for record, the zone the master serves.
        let expected = rdns::zone::parse_zone_file(new_text, "example.com.").unwrap();
        let key = |z: &Zone| {
            let mut rows: Vec<_> = z
                .records()
                .iter()
                .map(|r| (r.name.to_folded().to_string(), r.ttl, r.rdata.to_owned()))
                .collect();
            rows.sort_by_key(|r| (r.0.clone(), r.2.rtype()));
            rows
        };
        assert_eq!(
            key(held),
            key(&expected),
            "the increment reproduced the zone"
        );
    }

    /// A secondary that takes a transfer tells its own secondaries at once.
    ///
    /// Without this, only a *primary* ever announces — at startup and on SIGHUP —
    /// so the first level of a replication tree updates immediately and every
    /// level below it waits out a refresh timer. RFC 1996 §3.2's "master" is
    /// whoever serves the zone to someone, which a secondary in the middle is.
    #[tokio::test]
    async fn test_a_secondary_announces_what_it_transferred() {
        let dir = ScratchDir::new("announce");
        let master = spawn_primary(&zone_at_serial(11)).await;

        // A socket standing in for a downstream secondary, so the NOTIFY is
        // caught on the wire rather than inferred from a log line.
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");

        let r = replication(
            &dir,
            NotifyPolicy::new(vec![NotifyPeer {
                addr: target,
                key: None,
            }]),
        );
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };

        refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("transfer");

        let mut buf = vec![0u8; 4096];
        let (n, _from) =
            tokio::time::timeout(Duration::from_secs(5), downstream.recv_from(&mut buf))
                .await
                .expect("a NOTIFY should arrive")
                .expect("recv");

        let msg = DnsMessage::try_from_bytes(&buf[..n]).expect("parse the NOTIFY");
        assert_eq!(msg.opcode, OpCode::Notify, "a NOTIFY, not a query");
        assert!(!msg.response);
        assert_eq!(
            notify::notified_zone(&msg),
            Some(nm("example.com.")),
            "for the zone that moved"
        );
        assert_eq!(
            notify::notified_serial(&msg),
            Some(Serial::new(11)),
            "carrying the serial we just transferred, so the downstream \
             secondary need not ask"
        );
    }

    /// Nothing is announced when nothing moved: a refresh that confirms the
    /// serial is unchanged is not news, and telling anyone would cost them a
    /// pointless SOA probe every refresh interval.
    #[tokio::test]
    async fn test_an_unchanged_refresh_announces_nothing() {
        let dir = ScratchDir::new("announce-quiet");
        let master = spawn_primary(&zone_at_serial(11)).await;
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");

        let r = replication(
            &dir,
            NotifyPolicy::new(vec![NotifyPeer {
                addr: target,
                key: None,
            }]),
        );
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };

        // The first transfer announces; answer it. Unanswered, it is resent
        // after `NOTIFY_RETRY_SECS` (RFC 1996 §3.6), and under load that resend
        // landed in the silence window below (`TODO.md` #68b).
        refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("transfer");
        let mut buf = vec![0u8; 4096];
        let (n, from) =
            tokio::time::timeout(Duration::from_secs(5), downstream.recv_from(&mut buf))
                .await
                .expect("the first NOTIFY")
                .expect("recv");
        let request = DnsMessage::try_from_bytes(&buf[..n]).expect("parse the NOTIFY");
        let ack = notify::notify_response(&request, ResponseCode::Ok, 1232, None);
        downstream
            .send_to(&ack.to_bytes_within(512).expect("serialize"), from)
            .await
            .expect("acknowledge");

        // The second finds the same serial and must say nothing.
        let outcome = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("second refresh");
        assert!(outcome.contains("current"), "got: {outcome}");
        assert!(
            tokio::time::timeout(Duration::from_millis(500), downstream.recv_from(&mut buf))
                .await
                .is_err(),
            "an unchanged zone is not news"
        );
    }

    /// A secondary that receives a change can answer an IXFR for it — which is
    /// what makes one of these an interior node of a replication tree rather than
    /// a leaf. The delta only exists if the swap recorded it, so this is really a
    /// test that the zone map and the delta log move together.
    #[tokio::test]
    async fn test_a_transferred_change_becomes_an_increment_we_can_serve() {
        let dir = ScratchDir::new("ixfr-out");
        let r = replication(&dir, NotifyPolicy::default());
        let spec = |master| MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };

        let first = spawn_primary(&zone_at_serial(7)).await;
        refresh_once(&spec(first), None, &r, &test_shutdown().busy())
            .await
            .expect("first transfer");
        assert_eq!(
            r.served
                .deltas
                .read()
                .await
                .len(nm("example.com.").as_ref()),
            0,
            "a first fetch has no previous version to differ from"
        );

        let second = spawn_primary(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 8 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.250\n",
        )
        .await;
        refresh_once(&spec(second), None, &r, &test_shutdown().busy())
            .await
            .expect("second transfer");

        let log = r.served.deltas.read().await;
        assert_eq!(
            log.len(nm("example.com.").as_ref()),
            1,
            "the change was recorded"
        );
        let chain = log
            .chain_from(nm("example.com.").as_ref(), Serial::new(7))
            .expect("a chain from 7");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].to_serial, Serial::new(8));
        // www's address changed: one deletion, one addition.
        assert_eq!(chain[0].deleted.len(), 1);
        assert_eq!(chain[0].added.len(), 1);
    }

    /// RFC 9103 §11's server half: with `--transfer-tls-only` a transfer that
    /// arrived in clear is refused, whatever the ACL says about the peer.
    ///
    /// The ACL here *allows* 127.0.0.1, so the only thing that can refuse this
    /// is the transport policy — which is what makes it a test of the policy
    /// and not of the ACL.
    #[tokio::test]
    async fn a_transfer_in_clear_is_refused_when_tls_is_required() {
        let zone = rdns::zone::parse_zone_file(&zone_at_serial(7), "example.com.").expect("zone");
        let master = spawn_primary_full(
            zone,
            &["127.0.0.1".to_string()],
            DeltaLog::new(),
            TsigKeyring::new(Vec::new()),
            true,
            Arrival::Tcp,
        )
        .await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        let dir = ScratchDir::new("xot-required");
        let r = replication(&dir, NotifyPolicy::default());

        let err = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Refused"), "got: {err}");
    }

    /// And the same server answers the same request when the connection is one
    /// RFC 9103 §7.2 accepts. Without this the test above is equally consistent
    /// with a server that refuses every transfer.
    #[tokio::test]
    async fn the_same_transfer_is_answered_over_tls() {
        let zone = rdns::zone::parse_zone_file(&zone_at_serial(7), "example.com.").expect("zone");
        let master = spawn_primary_full(
            zone,
            &["127.0.0.1".to_string()],
            DeltaLog::new(),
            TsigKeyring::new(Vec::new()),
            true,
            Arrival::Dot(TlsVersion::Tls13, PeerCertificate::none()),
        )
        .await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        let dir = ScratchDir::new("xot-allowed");
        let r = replication(&dir, NotifyPolicy::default());

        refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("a transfer over an encrypted connection");
        assert!(
            r.served
                .zone_map
                .read()
                .await
                .matching(nm("example.com.").as_ref())
                .is_some(),
            "the zone should have been installed"
        );
    }

    /// TLS 1.2 is a fine way to ask a question and not a way to take a zone:
    /// RFC 9103 §7.2 is "MUST use only TLS 1.3 [RFC8446] or later", where
    /// RFC 7858 §4.1 asks only for 1.2. A bool in place of [`Privacy`] would
    /// have made this case invisible.
    #[tokio::test]
    async fn tls_older_than_1_3_does_not_satisfy_the_transfer_policy() {
        let zone = rdns::zone::parse_zone_file(&zone_at_serial(7), "example.com.").expect("zone");
        let master = spawn_primary_full(
            zone,
            &["127.0.0.1".to_string()],
            DeltaLog::new(),
            TsigKeyring::new(Vec::new()),
            true,
            Arrival::Dot(TlsVersion::Older, PeerCertificate::none()),
        )
        .await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        let dir = ScratchDir::new("xot-tls12");
        let r = replication(&dir, NotifyPolicy::default());

        let err = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Refused"), "got: {err}");
    }

    /// An IXFR is gated by the same ACL as an AXFR, and it has to be: it may
    /// *answer* with the whole zone (RFC 1995 §4), so a policy that let it
    /// through would be no policy at all. The default is to refuse everyone, and
    /// this is the test that a new transfer type did not quietly escape it.
    #[tokio::test]
    async fn test_an_ixfr_is_refused_by_the_same_default_that_refuses_an_axfr() {
        let master = spawn_primary_with_acl(&zone_at_serial(7), &[]).await;
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        let dir = ScratchDir::new("refused");
        let r = replication(&dir, NotifyPolicy::default());

        // The AXFR our own client makes is refused, which is the baseline.
        let err = refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Refused"), "got: {err}");

        // And so is an IXFR, over the same connection path.
        let request = {
            let mut msg = rdns::xfr::axfr_request(nm("example.com.").as_ref(), 0x33);
            msg.queries[0].qtype = Qtype::of(record_types::IXFR);
            msg
        };
        let mut buf = vec![0u8; 512];
        let n = request.to_bytes(&mut buf).expect("serialize");
        let mut framed = (n as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&buf[..n]);

        let mut stream = TcpStream::connect(master).await.expect("connect");
        stream.write_all(&framed).await.expect("send");
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.expect("length");
        let mut packet = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut packet).await.expect("reply");

        let reply = DnsMessage::try_from_bytes(&packet).expect("parse");
        assert_eq!(reply.rcode, ResponseCode::Refused);
        assert!(reply.answers.is_empty(), "a refusal carries no zone");
    }

    /// #46a: a NOTIFY signed, and verified by the *reader* rather than by
    /// looking at it. `check_request` is the same function the answering path
    /// runs on an inbound message, so this is the check a real secondary makes.
    ///
    /// Against the old code this fails at `TsigCheck::Unsigned`: `notify.rs`
    /// mentioned TSIG nowhere and `--also-notify` had no way to name a key.
    #[tokio::test]
    async fn test_a_notify_can_be_signed_and_verifies_as_a_request() {
        let dir = ScratchDir::new("announce-signed");
        let master = spawn_primary(&zone_at_serial(11)).await;
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");

        let key = TsigKey::new("notify.key.", TsigAlgorithm::HmacSha256, vec![0x2b; 32]);
        let r = replication(
            &dir,
            NotifyPolicy::new(vec![NotifyPeer {
                addr: target,
                key: Some(key.clone()),
            }]),
        );
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        refresh_once(&spec, None, &r, &test_shutdown().busy())
            .await
            .expect("transfer");

        let mut buf = vec![0u8; 4096];
        let (n, _from) =
            tokio::time::timeout(Duration::from_secs(5), downstream.recv_from(&mut buf))
                .await
                .expect("a NOTIFY should arrive")
                .expect("recv");

        let keyring = TsigKeyring::new(vec![key]);
        match tsig::check_request(&buf[..n], &keyring, tsig::now()) {
            rdns::tsig::TsigCheck::Verified(session) => {
                assert_eq!(session.key_name(), "notify.key.");
            }
            rdns::tsig::TsigCheck::Unsigned => panic!("the NOTIFY went out unsigned"),
            rdns::tsig::TsigCheck::Rejected(r) => {
                panic!("the NOTIFY did not verify: {}", r.error.reason())
            }
        }

        let msg = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");
        assert_eq!(msg.opcode, OpCode::Notify, "still a NOTIFY, signed or not");
        assert_eq!(notify::notified_zone(&msg), Some(nm("example.com.")));
    }

    /// Yield without letting paused time move until `done`, or panic. An idle
    /// runtime auto-advances paused time past loopback I/O still in flight, so
    /// a `sleep` here would fire the transfer's own timeouts.
    async fn settle(done: impl Fn() -> bool) {
        // Real time, not paused: an fsync on the blocking pool is the slow part.
        let give_up = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !done() {
            assert!(std::time::Instant::now() < give_up, "did not settle");
            tokio::task::yield_now().await;
        }
    }

    /// Let loopback I/O happen for a moment of real time without moving paused
    /// time: what a "nothing happened" assertion has to wait out first.
    async fn quiet() {
        let until = std::time::Instant::now() + std::time::Duration::from_millis(200);
        while std::time::Instant::now() < until {
            tokio::task::yield_now().await;
        }
    }

    /// A TCP front for `upstream` counting connections, one per question.
    async fn counting_front(upstream: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let asked = Arc::new(AtomicUsize::new(0));
        let counting = asked.clone();
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                counting.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        (addr, asked)
    }

    /// Through the real loop and a real primary: after the first transfer the
    /// zone's own REFRESH applies, not the default hour. The cycle's tests
    /// cannot see this, because `ZoneReplica::refresh` is what reads the timers
    /// after installing; read before, a zone's first transfer is followed by
    /// the default hour. That bug was only ever caught by a live run.
    #[tokio::test(start_paused = true)]
    async fn the_first_transfer_is_followed_by_the_zones_refresh() {
        // REFRESH 7200, so it cannot be mistaken for the default hour.
        let zone = zone_at_serial(7).replace(" 3600 1800 ", " 7200 1800 ");
        let (master, asked) = counting_front(spawn_primary(&zone).await).await;
        let asked = || asked.load(Ordering::Relaxed);
        let dir = ScratchDir::new("cycle-refresh");
        let mut r = replication(&dir, NotifyPolicy::default());
        r.clock = Clock::fixed(1_000_000_000);
        let zone_map = r.served.zone_map.clone();
        let spec = MasterSpec {
            zone: nm("example.com."),
            master,
            key_name: None,
            tls: None,
        };
        let _task = tokio::spawn(secondary_loop(
            spec,
            None,
            r,
            Arc::new(Notify::new()),
            test_shutdown().lifecycle(),
            Arc::new(Secondaries::default()),
        ));

        settle(|| zone_map.try_read().is_ok_and(|zones| zones.len() == 1)).await;
        let first = asked();
        tokio::time::sleep(Duration::from_secs(3650)).await;
        quiet().await;
        assert_eq!(asked(), first, "the default hour is not the zone's REFRESH");
        tokio::time::sleep(Duration::from_secs(3551)).await;
        settle(|| asked() > first).await;
    }
}
