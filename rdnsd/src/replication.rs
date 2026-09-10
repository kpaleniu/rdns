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
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use tokio::sync::{Notify, RwLock};

use rdns::clock::current_unix_timestamp;
use rdns::metrics::DnsMetrics;
use rdns::readiness::Readiness;
use rdns::secondary::{
    state_file_path, zone_file_path, MasterSpec, RefreshTimers, StateFile, TransferState,
};
use rdns::shutdown::{Busy, Lifecycle};
use rdns::tsig::{TsigAlgorithm, TsigKey, TsigKeyring};
use rdns::xfr;
use rdns::zone::Zone;
use rdns::zone_writer::write_zone_file;
use rdns::NameRef;
use rdns::Serial;

use crate::zones::{install_zone, ZoneContext, Zones};
use crate::{absolute_name, announce_transfer};

/// One replicated zone, as a NOTIFY needs to see it.
pub(crate) struct ReplicatedZone {
    /// The only addresses a NOTIFY for this zone is believed from.
    pub(crate) masters: Vec<IpAddr>,
    /// One per refresh task, since a zone may have several masters and each is
    /// checked on its own timer.
    pub(crate) wake: Vec<Arc<Notify>>,
}

/// Replicated zones by lowercased origin.
pub(crate) type Secondaries = Arc<HashMap<Vec<u8>, ReplicatedZone>>;

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
    pub(crate) notify_targets: Vec<SocketAddr>,
    /// Ticked off when a zone this server had nothing for arrives, taking a
    /// cold-started secondary from "listening" to "ready".
    pub(crate) readiness: Readiness,
}

/// Start a refresh task per (zone, master), and return what a NOTIFY needs to
/// find them.
pub(crate) fn spawn_secondaries(
    specs: Vec<MasterSpec>,
    keys: &TsigKeyring,
    replication: ReplicationContext,
    lifecycle: Lifecycle,
) -> Result<Secondaries> {
    let Lifecycle { stop, busy } = lifecycle;
    let mut registry: HashMap<Vec<u8>, ReplicatedZone> = HashMap::new();

    for spec in specs {
        // A key named but not defined is a configuration error, not a reason to
        // transfer unsigned: the operator asked for authentication and could
        // not see that they did not get it.
        let key = match &spec.key_name {
            Some(name) => Some(
                keys.get(&absolute_name(name), TsigAlgorithm::HmacSha256)
                    .or_else(|| {
                        [
                            TsigAlgorithm::HmacSha1,
                            TsigAlgorithm::HmacSha384,
                            TsigAlgorithm::HmacSha512,
                        ]
                        .into_iter()
                        .find_map(|alg| keys.get(&absolute_name(name), alg))
                    })
                    .ok_or_else(|| {
                        anyhow!("--secondary names TSIG key {name:?}, which no --tsig-key defines")
                    })?
                    .clone(),
            ),
            None => None,
        };

        let wake = Arc::new(Notify::new());
        let entry = registry
            // Folded the same way as the lookup in `notify_reply`.
            .entry(spec.zone.as_ref().folded().into_owned())
            .or_insert_with(|| ReplicatedZone {
                masters: Vec::new(),
                wake: Vec::new(),
            });
        entry.masters.push(spec.master.ip());
        entry.wake.push(wake.clone());

        tracing::info!(
            "secondary for {} from {}{}",
            spec.zone,
            spec.master,
            match &spec.key_name {
                Some(name) => format!(" signed with {name}"),
                None => String::new(),
            }
        );

        tokio::spawn(secondary_loop(
            spec,
            key,
            replication.clone(),
            wake,
            Lifecycle {
                stop: stop.clone(),
                busy: busy.clone(),
            },
        ));
    }

    Ok(Arc::new(registry))
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
        notify_targets,
        readiness,
    } = replication;
    let ZoneContext {
        zone_map, metrics, ..
    } = served;
    // A clone, not a borrow: holding the read lock across a network round trip
    // blocks every reload and swap for the length of the transfer.
    let base = zone_map.read().await.matching(spec.zone.as_ref()).cloned();
    let held = base.as_ref().and_then(Zone::serial);

    let remote = xfr::fetch_soa(spec.master, spec.zone.as_ref(), key).await?;
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
        Some(base) => match xfr::fetch_changes(spec.master, base, key).await? {
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
        None => xfr::fetch_zone(spec.master, spec.zone.as_ref(), key).await?,
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
    announce_transfer(spec.zone.as_ref(), serial, soa, notify_targets, busy);

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
    let ZoneContext {
        zone_map,
        deltas,
        metrics,
        journal: _,
    } = served;
    let last_contact = state
        .lock()
        .expect("state mutex")
        .get(&spec.zone.as_ref().to_presentation(), spec.master)
        .map(|s| s.refreshed_at)
        .unwrap_or(started_at);

    if !timers.has_expired(last_contact, current_unix_timestamp()) {
        return;
    }

    let mut zones = zone_map.write().await;
    if zones.remove(spec.zone.as_ref()) {
        // The increments go with it: offering a chain for a withdrawn zone is
        // answering for something we stopped serving.
        deltas.write().await.forget(spec.zone.as_ref());
        // And the gauges: a frozen serial shows a withdrawn zone as healthy.
        metrics.forget_zone(spec.zone.as_ref());
        // WARN, not INFO: this is what the alert is built on.
        tracing::warn!(
            "secondary {}: EXPIRE ({}s) passed with no contact — no longer serving this zone",
            spec.zone,
            timers.expire
        );
    }
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
    let ZoneContext {
        zone_map,
        deltas,
        metrics,
        journal: _,
    } = served;
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

        let mut zones = zone_map.write().await;
        if zones.remove(spec.zone.as_ref()) {
            // As in `expire_if_out_of_contact`: the increments and the gauges
            // go with the zone.
            deltas.write().await.forget(spec.zone.as_ref());
            metrics.forget_zone(spec.zone.as_ref());
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
