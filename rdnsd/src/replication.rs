//! The secondary role: fetching a zone from a master and keeping it.
//!
//! One owner and one lifetime, which is what makes this a module rather than a
//! region. Everything here belongs to a refresh task — there is one per
//! zone-and-master pair — and everything it shares with the rest of the process
//! goes through [`Replication`] and `Served`, which existed as one struct each
//! precisely so this boundary could be drawn.
//!
//! **The three timers are the whole of the protocol** (RFC 1035 §3.3.13):
//! REFRESH says when to ask again, RETRY says when to ask again after a failure,
//! and EXPIRE says when to stop answering. The third is the one implementations
//! get wrong, and `expire_if_out_of_contact` is here rather than folded into the
//! refresh loop because "we have not heard from anyone in too long" is a
//! question about the *zone*, not about any one master.
//!
//! **Forgetting a last-contact time is not a degraded cache, it is a
//! correctness bug** (`CLAUDE.md` §4): the difference between a withdrawn zone
//! and a stale one served with AA set. That is why `record_state` writes through
//! to a sidecar and why a state file that will not read stops the server, where
//! `rdns::journal` — which loses nothing but a full transfer — only warns.

//! **Its tests are in `main.rs`, and that is a finding rather than an
//! oversight.** `TODO.md` #20 says a test module should travel with its subject,
//! and the other two seams' did. These could not: a secondary test needs a live
//! primary to fetch from, so it is built on `spawn_primary`, `served` and
//! `test_shutdown` — scaffolding that constructs a `Server`, which is `main`'s
//! type and is shared with the transfer and dynamic-UPDATE tests. Moving the
//! tests would have meant moving that harness to a third place used by three
//! clusters, which is a bigger change than this one and wants its own decision.
//! Recorded here so a reader of this file does not conclude it is untested;
//! `ScratchDir` is in `testutil` for the same reason `query` is.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use tokio::sync::{Notify, RwLock};

use rdns::metrics::DnsMetrics;
use rdns::notify;
use rdns::readiness::Readiness;
use rdns::secondary::{
    state_file_path, zone_file_path, MasterSpec, RefreshTimers, StateFile, TransferState,
};
use rdns::shutdown::{Busy, Lifecycle};
use rdns::tsig::{TsigAlgorithm, TsigKey, TsigKeyring};
use rdns::utils::current_unix_timestamp;
use rdns::xfr;
use rdns::zone::Zone;
use rdns::zone_writer::write_zone_file;
use rdns::Serial;

use crate::zones::{install_zone, Served, Zones};
use crate::{absolute_name, announce_transfer};

// ---------------------------------------------------------------------------
// The secondary role
// ---------------------------------------------------------------------------

/// One replicated zone, as a NOTIFY needs to see it.
pub(crate) struct ReplicatedZone {
    /// The addresses a NOTIFY for this zone is believed from — the masters it is
    /// configured to come from, and nobody else.
    pub(crate) masters: Vec<IpAddr>,
    /// One per refresh task, since a zone may have several masters and each is
    /// checked on its own timer.
    pub(crate) wake: Vec<Arc<Notify>>,
}

/// Replicated zones by lowercased origin.
pub(crate) type Secondaries = Arc<HashMap<String, ReplicatedZone>>;

/// What every refresh task shares with the server and with each other.
///
/// Bundled rather than passed as six parameters because they are one thing —
/// the state a replicated zone is maintained *in* — and because the pieces are
/// not independently choosable: the delta log is derived from the zone map, and
/// the sidecar lives in the zone directory. A signature that let a caller supply
/// four of them and forget the fifth would be inviting exactly the drift the
/// swap helpers exist to prevent.
#[derive(Clone)]
pub(crate) struct Replication {
    pub(crate) served: Served,
    /// One file, so one mutex: the rule that made step 1 of #7 necessary applies
    /// inside a process too.
    pub(crate) state: Arc<Mutex<StateFile>>,
    pub(crate) zone_dir: PathBuf,
    /// Who to tell when a zone we replicate moves — we are its master to them.
    pub(crate) notify_targets: Vec<SocketAddr>,
    /// Ticked off when a zone this server had nothing for arrives, which is what
    /// takes a cold-started secondary from "listening" to "ready".
    pub(crate) readiness: Readiness,
}

/// Start a refresh task per (zone, master), and return what a NOTIFY needs to
/// find them.
///
/// The state file is shared behind one mutex because it is one file, and the
/// rule that made step 1 of this work necessary applies just as much inside a
/// process: one writer.
pub(crate) fn spawn_secondaries(
    specs: Vec<MasterSpec>,
    keys: &TsigKeyring,
    replication: Replication,
    lifecycle: Lifecycle,
) -> Result<Secondaries> {
    let Lifecycle { stop, busy } = lifecycle;
    let mut registry: HashMap<String, ReplicatedZone> = HashMap::new();

    for spec in specs {
        // A key named but not defined is a configuration error, not a reason to
        // transfer unsigned: the operator asked for authentication and would
        // have no way to see that they did not get it.
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
            // The matching insert for the lookup in `notify_reply`, and folded
            // the same way for the same reason (`TODO.md` #19a). The two agreed
            // with each other before, which is what kept the table
            // self-consistent while both were wrong.
            .entry(rdns::utils::absolute_lowered(&spec.zone).into_owned())
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
/// The cycle is RFC 1035 §4.3.5's: ask for the SOA, compare serials, transfer if
/// behind, then sleep on REFRESH — or on RETRY if anything failed, with a NOTIFY
/// cutting the wait short. What makes it a *replica* rather than a cache is the
/// third timer: out of contact past EXPIRE, the zone stops being served at all.
/// On shutdown it stops between refreshes, and holds a [`Busy`] only across a
/// refresh — never across the sleep, which is where it spends almost all of its
/// life and would otherwise burn the whole drain budget doing nothing.
///
/// Holding it across the refresh is the point: `refresh_once` writes the zone
/// file, and `persist` cleans up its `.zone.tmpNNN` sibling on *error* and not
/// on being killed. Finishing the write is what stops a stopped server from
/// leaving temporary files behind.
async fn secondary_loop(
    spec: MasterSpec,
    key: Option<TsigKey>,
    replication: Replication,
    wake: Arc<Notify>,
    lifecycle: Lifecycle,
) {
    let Lifecycle { stop, busy } = lifecycle;
    // What the EXPIRE clock counts from when we have never reached the master:
    // process start. Not "forever ago", which would withdraw a zone we hold
    // before ever trying, and not "never expires", which would serve a copy of
    // unknown age indefinitely because we happened to restart.
    let started_at = current_unix_timestamp();

    loop {
        if stop.is_set() {
            return;
        }
        let result = {
            let _busy = busy.clone();
            refresh_once(&spec, key.as_ref(), &replication, &busy).await
        };

        // The timers are read *after* the refresh, not before, because the
        // refresh may have just installed the zone that defines them. Read first,
        // the very first transfer of a zone is followed by the default hour's
        // wait instead of the REFRESH the zone actually asks for — which is
        // invisible in a test that only checks the transfer happened, and was
        // caught by watching a zone with a one-minute REFRESH sit there for an
        // hour.
        let timers = zone_timers(&replication.served.zone_map, &spec.zone).await;

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

        // No `Busy` is held across this, deliberately: a refresh timer is hours
        // long and the drain must not wait on one.
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = wake.notified() => {}
            _ = stop.wait() => return,
        }
    }
}

/// The timers the zone we currently hold asks for, or the defaults if we hold
/// none — a zone we have never fetched has no SOA to obey.
async fn zone_timers(zone_map: &Arc<RwLock<Zones>>, zone: &str) -> RefreshTimers {
    zone_map
        .read()
        .await
        .values()
        .find(|z| z.origin().eq_ignore_ascii_case(zone))
        .and_then(RefreshTimers::from_zone)
        .unwrap_or_default()
}

/// One refresh: probe, compare, and transfer if there is anything to transfer.
pub(crate) async fn refresh_once(
    spec: &MasterSpec,
    key: Option<&TsigKey>,
    replication: &Replication,
    busy: &Busy,
) -> Result<String> {
    let Replication {
        served,
        state,
        zone_dir,
        notify_targets,
        readiness,
    } = replication;
    let Served {
        zone_map, metrics, ..
    } = served;
    // A clone rather than a borrow: an incremental transfer applies its changes
    // to this version, and holding the read lock across a network round trip
    // would block every reload and every swap for the length of the transfer.
    let base = zone_map
        .read()
        .await
        .values()
        .find(|z| z.origin().eq_ignore_ascii_case(&spec.zone))
        .cloned();
    let held = base.as_ref().and_then(Zone::serial);

    let remote = xfr::fetch_soa(spec.master, &spec.zone, key).await?;
    let now = current_unix_timestamp();

    // Reaching the master is what the EXPIRE clock resets on, whether or not
    // there was anything new to fetch — the zone is confirmed current, which is
    // exactly what "not stale" means.
    if let Some(held) = held {
        if !remote.is_newer_than(held) {
            record_state(state, spec, held, now, metrics).await?;
            return Ok(format!("serial {held} is current"));
        }
    }

    // Ask for the difference when we have a version to differ from, and for the
    // whole zone when we do not. The master may answer either request with the
    // whole zone (RFC 1995 §4), so this is a preference rather than a demand —
    // which is why there is one code path below and not two.
    let mut note = String::new();
    let fetched = match &base {
        Some(base) => match xfr::fetch_changes(spec.master, base, key).await? {
            xfr::IxfrOutcome::UpToDate(serial) => {
                // The SOA probe said otherwise a moment ago, so the master
                // changed its mind between the two questions. Nothing to do, and
                // the next refresh will see the newer serial.
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
                    // Worth saying out loud: it means our copy and the master's
                    // had already diverged. Not worth failing over — the records
                    // are meant to be gone either way.
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
        None => xfr::fetch_zone(spec.master, &spec.zone, key).await?,
    };

    let serial = fetched
        .serial()
        .ok_or_else(|| anyhow!("the transferred zone has no SOA"))?;

    // Persist before serving. Both orders are safe — a crash between them costs
    // at most a refetch — but this way the state line, written last, is only ever
    // true after both the file and memory agree with it.
    let path = zone_file_path(zone_dir, &spec.zone);
    write_zone_file(&fetched, &path)?;

    let count = fetched.records().len();
    // The swap is a whole-zone replacement under the write lock: readers see the
    // old zone or the new one and never a half-applied transfer. Nothing removes
    // records one at a time, which is also why `Zone` has no API to.
    //
    // The delta is computed here, while both versions are in hand — this is the
    // only moment they both exist, and the difference is what lets us answer an
    // IXFR for this step to our own downstream secondaries. That composition is
    // the point: a secondary that can serve increments of a zone it received is
    // an interior node of a replication tree rather than a leaf.
    let soa = notify::soa_record(&fetched);
    install_zone(served, fetched).await;
    record_state(state, spec, serial, now, metrics).await?;

    // The zone is in the map, so if this server was started without it — a cold
    // secondary, or one whose copy on disk could not be vouched for — that is one
    // fewer thing standing between it and `/readyz`. Idempotent, and a no-op for
    // every zone that was already there at startup, so the ordinary hourly
    // refresh reports nothing.
    if readiness.arrived(&spec.zone) {
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

    // We are this zone's master to whoever replicates it from us, and the serial
    // just moved forward — which is the whole of what a NOTIFY says.
    announce_transfer(&spec.zone, serial, soa, notify_targets, busy);

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
    // The same fact the state file records, exposed where an operator can see it
    // without reading a sidecar off the box.
    //
    // **Contact, not transfer.** All three of this function's callers are
    // "reached the master" — including the one where the serial was already
    // current and nothing moved — and contact is the operationally meaningful
    // one: it is what EXPIRE counts from, and it is what decides whether a zone
    // is withdrawn. A replica in contact with nothing new to fetch is healthy,
    // and a gauge that only moved on an actual transfer would call it stale.
    // #9d asked for "last successful transfer"; this is the same question asked
    // more precisely.
    metrics.note_zone_transfer(&spec.zone, now);

    // Update in memory under the guard, write outside it. `StateFile::record`
    // would do both, and the write ends in an fsync of the file and then of its
    // directory — so it would hold this `std::sync::Mutex` across the fsync,
    // which every other zone's refresh loop then *spins* on rather than
    // yielding, and it would do it on a runtime worker that is also answering
    // queries (`CLAUDE.md` §9). The guard is dropped by the end of this block.
    let (path, text) = {
        let mut file = state.lock().expect("state mutex");
        file.set(TransferState {
            zone: spec.zone.clone(),
            serial,
            refreshed_at: now,
            master: spec.master,
        });
        file.snapshot()
    };

    // `spawn_blocking` because the fsync is the point of the write: it is what
    // makes "we transferred this" survive the power going out, and it is not
    // something to do on a worker with queries queued behind it.
    tokio::task::spawn_blocking(move || rdns::secondary::write_snapshot(&path, &text))
        .await
        .context("the task writing the transfer state")?
        .map_err(|e| anyhow!("recording the transfer state: {e}"))
}

/// Stop serving a zone we have not been able to reach for longer than its
/// EXPIRE.
///
/// This is the one place a secondary is *required* to make things worse for its
/// clients, and the reason is that the alternative is worse still: a zone served
/// with AA set is a claim to be current, and a server that keeps making that
/// claim indefinitely turns a primary's outage into permanently wrong answers
/// nobody can see is wrong. Withdrawn, the same query gets REFUSED, which sends
/// a resolver to the other nameservers in the delegation.
///
/// The state line is deliberately left behind: it records when contact was last
/// made, which is what lets a restart notice the zone is still expired instead of
/// reading "nothing known" as "fetch and serve".
pub(crate) async fn expire_if_out_of_contact(
    spec: &MasterSpec,
    replication: &Replication,
    started_at: u64,
    timers: RefreshTimers,
) {
    let Replication { served, state, .. } = replication;
    let Served {
        zone_map,
        deltas,
        metrics,
        journal: _,
    } = served;
    let last_contact = state
        .lock()
        .expect("state mutex")
        .get(&spec.zone, spec.master)
        .map(|s| s.refreshed_at)
        .unwrap_or(started_at);

    if !timers.has_expired(last_contact, current_unix_timestamp()) {
        return;
    }

    let mut zones = zone_map.write().await;
    if zones.remove(&spec.zone) {
        // The increments go with it: offering a chain for a zone we have
        // withdrawn would be answering for something we just stopped serving.
        deltas.write().await.forget(&spec.zone);
        // And the gauges, for the same reason as at startup: a serial left
        // frozen at whatever it last was shows a zone this server has stopped
        // answering for as perfectly healthy.
        metrics.forget_zone(&spec.zone);
        // WARN: a zone has just gone out of service. This is the one an alert
        // is built on, and it must not need a level turned up to be seen.
        tracing::warn!(
            "secondary {}: EXPIRE ({}s) passed with no contact — no longer serving this zone",
            spec.zone,
            timers.expire
        );
    }
}

/// Withdraw every replicated zone whose age we cannot vouch for.
///
/// **Called after each time the zone map is filled from disk** — at startup and
/// after every reload — because that is exactly when a file whose contents
/// expired can come back. It used to run from `main` only, so a `SIGHUP` re-read
/// every `.zone` file and served it again without consulting the sidecar: a zone
/// correctly withdrawn because its primary had been unreachable for a week came
/// straight back, **with AA set**, which is the "permanently wrong answers nobody
/// can see are wrong" the withdrawal exists to prevent. Expiry that lasts only
/// until the next deploy is not expiry.
///
/// Two ways a zone fails to earn an answer, and the second one was the hole:
///
/// - Its last successful contact is older than the SOA's EXPIRE. The plain case.
/// - **There is no record of contact at all**, while the zone is loaded — so it
///   came off disk. A missing sidecar, an unreadable one, or an entry for another
///   master all land here. `StateFile::load` returns empty by design and never
///   fails, which is right for a cache and wrong for expiry: forgetting the
///   last-contact time *is* the difference between withdrawn and served, so
///   unknown age has to mean "do not serve" rather than "serve and hope". The
///   zone comes back at the first successful transfer, which is seconds away and
///   is the thing that makes it ours to answer for.
///
/// A zone we hold but do not replicate is never touched: the loop is over the
/// `--secondary` specs, so a primary zone sharing the directory is not this
/// function's business.
pub(crate) async fn withdraw_unvouched_zones(
    specs: &[MasterSpec],
    served: &Served,
    zone_dir: &Path,
) {
    let Served {
        zone_map,
        deltas,
        metrics,
        journal: _,
    } = served;
    let state = StateFile::load(&state_file_path(zone_dir));
    let now = current_unix_timestamp();

    for spec in specs {
        let timers = zone_timers(zone_map, &spec.zone).await;
        let why = match state.get(&spec.zone, spec.master) {
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
        if zones.remove(&spec.zone) {
            // The increments go with it, for the same reason as in `expire_zone`:
            // offering a chain for a zone we have withdrawn would be answering
            // for something we just stopped serving.
            deltas.write().await.forget(&spec.zone);
            // And its gauges. A withdrawn zone whose serial sat frozen at
            // whatever it last was would read as a perfectly healthy replica;
            // an absent series is a question a dashboard can ask about.
            metrics.forget_zone(&spec.zone);
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
/// A spec that does not parse is an error rather than a skip, for the same
/// reason a malformed ACL rule is: a secondary that silently is not replicating
/// a zone it was told to replicate is a failure nobody notices until the day the
/// primary is gone.
pub(crate) fn parse_secondary_specs(specs: &[String]) -> Result<Vec<MasterSpec>> {
    specs
        .iter()
        .filter(|spec| !spec.trim().is_empty())
        .map(|spec| MasterSpec::parse(spec).map_err(|e| anyhow!("--secondary {e}")))
        .collect()
}
