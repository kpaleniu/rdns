//! Replicating a policy zone into the file it is already read from —
//! `TODO.md` #57d, shape A.
//!
//! One task per transferred feed, on the zone's own SOA timers. What arrives is
//! a [`rdns::zone::Zone`]; it is serialized, written where `[[rpz.feeds]].file`
//! says, and the existing reload path reads it back. Nothing in `rdns::rpz`
//! changes, nothing in the answer path changes, and `PolicyStore` never learns
//! that a transfer exists.
//!
//! **What that costs, measured** (`rdns/tests/rpz_install.rs`, a million QNAME
//! rules, release): 1 894 ms per refresh against shape B's 32.8 — 495 ms to
//! serialize, 635 to write, 756 to read back and index a zone this process had
//! already parsed once. And because the reload path is all-or-nothing over
//! every feed, one feed's refresh re-reads all of them.
//!
//! **What it buys**, and the reason the row called it the one that argues for
//! itself: the file is the thing that survives a restart. A resolver that
//! transferred a blocklist yesterday and is restarted today begins with
//! yesterday's rules in force rather than with none, and nothing had to be
//! designed for that — it is the same file an operator's cron job writes.
//!
//! The transfer is signed when the feed's master names a key with `#name`
//! (`TODO.md` #57f). The key is resolved out of `[keys]` at startup, so a name
//! that defines nothing stops the process rather than sending an unsigned
//! request — an unauthenticated blocklist is one anybody on the path can
//! replace. Unsigned is still allowed, because a feed reached over a private
//! link is a real deployment; what is refused is *asking* for a key and not
//! getting one.
//!
//! EXPIRE is obeyed as the operator asked, per feed: `on-expire = "enforce"`
//! keeps a feed's rules in force past it, `"lift"` stops enforcing them. There
//! is no safe default derivable from a zone — `rpz-passthru` rules make a feed
//! an allowlist, where the two directions swap — so the key is per feed and
//! `enforce` is the default on the asymmetry `TODO.md` #57d argues: lifting
//! hits every client behind the resolver and is triggerable by anyone who can
//! blackhole the publisher, while enforcing hits the listed names and is
//! visible to whoever is blocked.

use std::path::PathBuf;
use std::sync::Arc;

use rdns::clock::current_unix_timestamp;
use rdns::metrics::DnsMetrics;
use rdns::secondary::{MasterSpec, RefreshTimers};
use rdns::shutdown::{Busy, Stop};
use rdns::tsig::TsigKey;
use rdns::xfr::{self, Master};
use rdns::zone_writer::write_zone_file;
use tokio::sync::Notify;

use crate::reload::PolicyReload;

/// One feed that is transferred rather than written by somebody else.
#[derive(Debug, Clone)]
pub(crate) struct TransferredFeed {
    pub(crate) spec: MasterSpec,
    /// The key this feed's transfer is signed with, resolved from the keyring
    /// at startup so a name that defines nothing is a startup error and not a
    /// transfer that silently goes out unsigned (`TODO.md` #57f).
    pub(crate) key: Option<TsigKey>,
    /// Where to write what arrives — the same path the feed is read from.
    pub(crate) file: PathBuf,
    /// What to do when EXPIRE passes with no contact (`TODO.md` #57d).
    pub(crate) on_expire: OnExpire,
}

/// What an unrefreshed feed means.
///
/// Not derivable from the zone: a feed of `rpz-passthru` rules is an allowlist,
/// and a stale allowlist fails open for exactly what it exempts, where a stale
/// blocklist fails closed. So the operator says, per feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum OnExpire {
    /// Keep the rules in force. The default, because lifting is the failure an
    /// off-path attacker can cause by blackholing the publisher, and it is
    /// invisible.
    #[default]
    Enforce,
    /// Stop enforcing, as `rdnsd` withdraws an authoritative zone whose EXPIRE
    /// passed.
    Lift,
}

impl std::str::FromStr for OnExpire {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "enforce" => Ok(OnExpire::Enforce),
            "lift" => Ok(OnExpire::Lift),
            other => Err(format!(
                "unknown on-expire {other:?}: enforce keeps a feed's rules past \
                 EXPIRE, lift stops applying them"
            )),
        }
    }
}

/// A handle for telling one feed's task that its zone has changed.
///
/// Per feed, where [`PolicyReload`] is per process: a NOTIFY names a zone, and
/// waking every transfer because one master spoke would let one feed's
/// publisher pull every other feed. One permit each, for the reason the
/// process-wide one has one (`CLAUDE.md` §5).
#[derive(Clone)]
pub(crate) struct FeedWake {
    pub(crate) zone: rdns::Name,
    notify: Arc<Notify>,
}

impl FeedWake {
    pub(crate) fn new(zone: rdns::Name) -> FeedWake {
        FeedWake {
            zone,
            notify: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn request(&self) {
        self.notify.notify_one();
    }
}

/// Fetch this feed's zone, write it where the feed is read from, ask for a
/// reload, and wait for the refresh timer, a NOTIFY for this zone, or the stop
/// signal.
pub(crate) async fn refresh_task(
    feed: TransferredFeed,
    reload: PolicyReload,
    wake: FeedWake,
    metrics: Arc<DnsMetrics>,
    stop: Stop,
    busy: Busy,
) {
    let master = Master::plain(feed.spec.master);
    let mut timers = RefreshTimers::default();
    // The age `on-expire` acts on, and the only one this process has: `rdnsd`'s
    // sidecar and its refresh gauge belong to the other daemon (`TODO.md`
    // #57d). Started at "now" rather than at zero, so a resolver that has never
    // reached its master expires on the same clock as one that lost contact.
    let mut last_contact = current_unix_timestamp();
    let mut lifted = false;

    loop {
        // The claim is held across the transfer and dropped before the wait: a
        // refresh interval is hours long and holding it over one would keep the
        // drain open for the life of the process (`CLAUDE.md` §9).
        let wait = {
            let _working = busy.clone();
            match fetch_and_write(&master, &feed, &reload).await {
                Ok(fetched) => {
                    timers = fetched;
                    last_contact = current_unix_timestamp();
                    // The same gauge `rdnsd` sets for a replicated zone, because
                    // a policy feed is one: same name, same shape, same alert
                    // (`CLAUDE.md` §7, §14). `TODO.md` #57g.
                    metrics.note_zone_transfer(feed.spec.zone.as_ref(), last_contact);
                    if lifted {
                        // Back in contact: the rules go back into force, and it
                        // is said out loud because the lifting was.
                        lifted = false;
                        tracing::warn!(
                            "policy zone {}: back in contact, its rules are enforced again",
                            feed.spec.zone
                        );
                    }
                    timers.after_success()
                }
                Err(e) => {
                    tracing::warn!(
                        "policy zone {}: transfer from {master} failed, the file on disk \
                         stays in force: {e}",
                        feed.spec.zone
                    );
                    expire_if_out_of_contact(
                        &feed,
                        &timers,
                        last_contact,
                        &mut lifted,
                        &reload,
                        &metrics,
                    );
                    timers.after_failure()
                }
            }
        };

        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = wake.notify.notified() => {
                tracing::info!("policy zone {}: a NOTIFY cut the wait short", feed.spec.zone);
            }
            () = stop.wait() => break,
        }
    }
}

/// Act on EXPIRE having passed with no contact, once.
///
/// `Enforce` says so and changes nothing: the file stays and its rules stay in
/// force, which is what the shipped two-process arrangement does by accident
/// and this does on purpose. `Lift` removes the file and asks for a re-read,
/// which is how one feed stops being enforced without disturbing the others.
///
/// WARN either way and only on the transition: this is what an alert is built
/// on, and a line per RETRY would bury it.
fn expire_if_out_of_contact(
    feed: &TransferredFeed,
    timers: &RefreshTimers,
    last_contact: u64,
    lifted: &mut bool,
    reload: &PolicyReload,
    metrics: &DnsMetrics,
) {
    if *lifted || !timers.has_expired(last_contact, current_unix_timestamp()) {
        return;
    }
    *lifted = true;
    let zone = &feed.spec.zone;
    let expire = timers.expire;
    match feed.on_expire {
        OnExpire::Enforce => tracing::warn!(
            "policy zone {zone}: EXPIRE ({expire}s) passed with no contact. Its rules \
             stay in force — on-expire is enforce"
        ),
        OnExpire::Lift => {
            // A failure to remove is not a failure to report: the WARN below is
            // the operator's signal either way, and the next transfer rewrites
            // the file regardless.
            if let Err(e) = std::fs::remove_file(&feed.file) {
                tracing::warn!(
                    "policy zone {zone}: could not remove {}: {e}",
                    feed.file.display()
                );
            }
            tracing::warn!(
                "policy zone {zone}: EXPIRE ({expire}s) passed with no contact. Its rules \
                 are no longer enforced — on-expire is lift"
            );
            // Forgotten, not frozen: the feed is no longer enforced, and a
            // gauge left at its last value shows a policy nobody applies as
            // perfectly healthy (§14). Under `enforce` the series deliberately
            // stays and goes stale — that staleness *is* the alert.
            metrics.forget_zone(feed.spec.zone.as_ref());
            reload.request();
        }
    }
}

/// One transfer, written to the feed's file. Returns the timers the zone itself
/// asks for.
async fn fetch_and_write(
    master: &Master,
    feed: &TransferredFeed,
    reload: &PolicyReload,
) -> anyhow::Result<RefreshTimers> {
    let zone = xfr::fetch_zone(master, feed.spec.zone.as_ref(), feed.key.as_ref()).await?;
    let timers = RefreshTimers::from_zone(&zone).unwrap_or_default();
    let records = zone.records().len();

    // Serializing and writing is 1 130 ms of the 1 894 a millon-rule refresh
    // costs here, and both halves are blocking — the write especially, which is
    // an fsync and a rename (`rdns::persist`). Off the workers, as the reload
    // itself has been since #57b.
    let path = feed.file.clone();
    tokio::task::spawn_blocking(move || write_zone_file(&zone, &path)).await??;

    tracing::info!(
        "policy zone {} transferred from {master}: {records} records written to {}",
        feed.spec.zone,
        feed.file.display()
    );
    // The file is on disk; the rules are not in force until somebody reads it.
    // `PolicyReload` coalesces, so several feeds refreshing at once ask for one
    // re-read of all of them — which is also the shape's cost, since a feed
    // that did not change is re-read anyway.
    reload.request();
    Ok(timers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdns::Name;

    fn feed(on_expire: OnExpire) -> TransferredFeed {
        TransferredFeed {
            spec: MasterSpec::parse("block.example.@192.0.2.9").expect("a spec"),
            file: std::path::PathBuf::from("nonexistent-on-purpose.zone"),
            on_expire,
            key: None,
        }
    }

    fn gauge_lines(metrics: &DnsMetrics) -> Vec<String> {
        metrics
            .to_prometheus_format()
            .lines()
            .filter(|l| l.starts_with("dns_zone_last_refresh_timestamp_seconds{"))
            .map(str::to_string)
            .collect()
    }

    /// A feed that has never transferred has no age, and says so by being
    /// absent rather than by reading 1970 (`CLAUDE.md` §14).
    ///
    /// Fails against a gauge initialised to zero, which is the shape that fires
    /// every staleness alert there is on a resolver that just started.
    #[test]
    fn a_feed_that_never_transferred_is_absent_not_zero() {
        let metrics = DnsMetrics::new();
        assert!(
            gauge_lines(&metrics).is_empty(),
            "nothing transferred, so there is no age to report"
        );

        let zone = Name::from_presentation("block.example.").expect("a name");
        metrics.note_zone_transfer(zone.as_ref(), 1_700_000_000);
        assert_eq!(
            gauge_lines(&metrics),
            ["dns_zone_last_refresh_timestamp_seconds{zone=\"block.example.\"} 1700000000"]
        );
    }

    /// Lifting stops reporting the feed; enforcing deliberately does not.
    ///
    /// The second half is the point of the pair: under `enforce` the series
    /// stays and goes stale, and that staleness is what
    /// `time() - dns_zone_last_refresh_timestamp_seconds > EXPIRE` fires on.
    /// A gauge forgotten there would hide exactly the condition #57d is about.
    #[test]
    fn lifting_forgets_the_feed_and_enforcing_keeps_it_stale() {
        let expired = RefreshTimers::from_soa(3600, 600, 1);
        let long_ago = current_unix_timestamp() - 10_000;
        let reload = PolicyReload::default();

        for (way, expected) in [(OnExpire::Enforce, 1), (OnExpire::Lift, 0)] {
            let metrics = DnsMetrics::new();
            let feed = feed(way);
            metrics.note_zone_transfer(feed.spec.zone.as_ref(), long_ago);
            let mut lifted = false;
            expire_if_out_of_contact(&feed, &expired, long_ago, &mut lifted, &reload, &metrics);

            assert!(lifted, "{way:?}: the transition happened");
            assert_eq!(
                gauge_lines(&metrics).len(),
                expected,
                "{way:?}: a feed still enforced keeps its age; a lifted one stops being reported"
            );
        }
    }

    /// The transition fires once, not once per RETRY.
    #[test]
    fn the_expiry_warning_is_a_transition_and_not_a_repeat() {
        let expired = RefreshTimers::from_soa(3600, 600, 1);
        let long_ago = current_unix_timestamp() - 10_000;
        let metrics = DnsMetrics::new();
        let reload = PolicyReload::default();
        let feed = feed(OnExpire::Lift);

        let mut lifted = false;
        expire_if_out_of_contact(&feed, &expired, long_ago, &mut lifted, &reload, &metrics);
        assert!(lifted);
        // Called again with the same state: nothing to say and nothing to do.
        expire_if_out_of_contact(&feed, &expired, long_ago, &mut lifted, &reload, &metrics);
        assert!(lifted);
    }
}
