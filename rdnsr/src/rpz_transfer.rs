//! Replicating a policy zone into the file it is already read from —
//! `TODO.md` #57d, shape A.
//!
//! One task per transferred feed, on the zone's own SOA timers. A refresh asks
//! the master for its serial first and stops there unless it moved; what
//! arrives otherwise is a [`rdns::zone::Zone`], serialized, written where
//! `[[rpz.feeds]].file` says, and read back by the existing reload path.
//! Nothing in the answer path changes, and `PolicyStore` learns of a transfer
//! only by being asked which version it holds.
//!
//! **What a refresh costs, measured** (`rdns/tests/rpz_install.rs`, a million
//! QNAME rules, release, the development machine, `TODO.md` #57e):
//!
//! | | ms |
//! |---|---|
//! | the serial probe, which is all an unchanged feed costs | 0.3 |
//! | a whole zone (AXFR) | 1 160 |
//! | the difference from the version in force (IXFR) | 453 |
//! | writing the file and reading it back | 1 200-1 420 |
//!
//! Re-measured 2026-09-16. The first figures — 1 596, 808 and 1 351 — were
//! taken with three million-rule measurements running at once (`TODO.md` #71's
//! head); the transfer rows then halved again when #71c gave the zone rebuild
//! the record count it already had. The last row is a band because it writes
//! 38 MB to disk.
//!
//! So an unchanged million-rule feed costs one round trip where it used to cost
//! a transfer and a reload, and a changed one asks for what changed. The
//! install is the half that is still zone-sized whatever arrives, because the
//! file is the store (`TODO.md` #57d's shape A). It is that feed's size and no
//! more: a reload keeps every feed whose file has not moved, so one publisher
//! no longer re-reads the others (`TODO.md` #71b). What is left zone-sized is
//! #71a.
//!
//! **What it buys**, and the reason the row called it the one that argues for
//! itself: the file is the thing that survives a restart. A resolver that
//! transferred a blocklist yesterday and is restarted today begins with
//! yesterday's rules in force rather than with none, and nothing had to be
//! designed for that — it is the same file an operator's cron job writes.
//!
//! The version an IXFR brings forward from is the one in force, read back out
//! of [`PolicyStore`] rather than kept beside it: that zone is the file's
//! contents, already parsed for the answer path, so a refresh holds no second
//! copy of a feed. It can be one reload behind the file — a transfer installs
//! by writing and asking for a re-read — which only means asking from an older
//! serial, and RFC 1995 §4 lets a master answer that with a longer chain or
//! with the whole zone.
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
use rdns::rpz::{PolicyStore, PolicyZone};
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
    policy: Arc<PolicyStore>,
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
            match fetch_and_write(&master, &feed, &policy, &reload).await {
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

/// One refresh, written to the feed's file if the master had anything new.
/// Returns the timers the zone itself asks for.
///
/// The version in force is the base: it is the file's contents, already parsed
/// and already in memory for the answer path, so asking the master to bring
/// *that* forward costs no second copy of the feed. It can be one reload behind
/// the file — a transfer installs by writing and asking for a re-read — which
/// only means asking from an older serial, and a master answers that with a
/// longer chain or with the whole zone (RFC 1995 §4).
async fn fetch_and_write(
    master: &Master,
    feed: &TransferredFeed,
    policy: &Arc<PolicyStore>,
    reload: &PolicyReload,
) -> anyhow::Result<RefreshTimers> {
    let in_force = policy.in_force();
    let base = in_force.held(feed.spec.zone.as_ref()).map(PolicyZone::zone);

    let fetched =
        match xfr::refresh_zone(master, feed.spec.zone.as_ref(), feed.key.as_ref(), base).await? {
            // Nothing to write and nothing to re-read: an unchanged million-rule
            // feed costs one round trip here and 2.5 s of serialize-write-reparse
            // if this probe is skipped (`TODO.md` #57e). The contact still counts,
            // because EXPIRE runs on contact and not on transfers.
            xfr::Refresh::Current { serial, .. } => {
                tracing::info!(
                    "policy zone {}: serial {serial} is current, nothing transferred",
                    feed.spec.zone
                );
                return Ok(base.and_then(RefreshTimers::from_zone).unwrap_or_default());
            }
            xfr::Refresh::Fetched(fetched) => fetched,
        };
    if fetched.missing_deletions > 0 {
        // Our file and the master's zone had already diverged at the serial we
        // asked from: the increments applied, but rules the master dropped are
        // still being enforced here. Not fatal and not fixable from this side —
        // the next full transfer settles it — so it is said out loud with the
        // count.
        tracing::warn!(
            "policy zone {}: {} deletion(s) named records this feed did not hold",
            feed.spec.zone,
            fetched.missing_deletions
        );
    }
    let how = fetched.how();
    let zone = fetched.zone;
    let timers = RefreshTimers::from_zone(&zone).unwrap_or_default();
    let records = zone.records().len();

    // Serializing and writing is 1 130 ms of the 1 894 a millon-rule refresh
    // costs here, and both halves are blocking — the write especially, which is
    // an fsync and a rename (`rdns::persist`). Off the workers, as the reload
    // itself has been since #57b.
    let path = feed.file.clone();
    tokio::task::spawn_blocking(move || write_zone_file(&zone, &path)).await??;

    tracing::info!(
        "policy zone {} transferred from {master}{how}: {records} records written to {}",
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
    use crate::testutil::ScratchDir;
    use rdns::rpz::{Feed, PolicyOverride};
    use rdns::Name;
    use std::net::SocketAddr;

    /// A feed of two rules at `serial`, as a file's text.
    fn feed_text(serial: u32, rules: &[&str]) -> String {
        let mut text = format!(
            "$ORIGIN block.example.\n\
             $TTL 60\n\
             @ IN SOA ns.block.example. hostmaster.block.example. {serial} 3600 600 86400 60\n\
             @ IN NS localhost.\n"
        );
        for rule in rules {
            text.push_str(&format!("{rule} IN CNAME .\n"));
        }
        text
    }

    fn zone_from(text: &str) -> rdns::zone::Zone {
        rdns::zone::parse_zone_file(text, "block.example.").expect("the feed parses")
    }

    /// What the master was asked for, in order — the assertion that says which
    /// protocol this took rather than what it ended up with (`CLAUDE.md` §10).
    type Asked = Arc<std::sync::Mutex<Vec<&'static str>>>;

    /// A master on loopback serving `zone`, with `deltas` so it can answer an
    /// IXFR, recording the question of every request.
    async fn spawn_master(
        zone: rdns::zone::Zone,
        deltas: rdns::ixfr::DeltaLog,
    ) -> (SocketAddr, Asked) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a master");
        let addr = listener.local_addr().expect("local addr");
        let asked: Asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recording = asked.clone();
        let shared = Arc::new((zone, deltas));

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let shared = shared.clone();
                let recording = recording.clone();
                tokio::spawn(async move {
                    let (zone, deltas) = &*shared;
                    let mut length = [0u8; 2];
                    if stream.read_exact(&mut length).await.is_err() {
                        return;
                    }
                    let mut packet = vec![0u8; u16::from_be_bytes(length) as usize];
                    if stream.read_exact(&mut packet).await.is_err() {
                        return;
                    }
                    let request = rdns::DnsMessage::try_from_bytes(&packet).expect("a request");
                    let qtype = request.queries[0].qtype;
                    let replies = if qtype == rdns::Qtype::of(rdns::record_types::AXFR) {
                        recording.lock().expect("the log").push("AXFR");
                        rdns::transfer::axfr_messages(&request, zone).expect("an AXFR")
                    } else if qtype == rdns::Qtype::of(rdns::record_types::IXFR) {
                        recording.lock().expect("the log").push("IXFR");
                        rdns::ixfr::ixfr_response(&request, zone, deltas)
                            .expect("an IXFR")
                            .messages(&request, zone)
                            .expect("its messages")
                    } else {
                        recording.lock().expect("the log").push("SOA");
                        let mut reply = request.clone();
                        reply.response = true;
                        reply.authoritive = true;
                        reply.answers = vec![zone.apex_soa_record().expect("an apex SOA")];
                        vec![reply]
                    };
                    for reply in replies {
                        let mut buf = vec![0u8; 65535];
                        let n = reply.to_bytes(&mut buf).expect("serialize");
                        let mut framed = (n as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&buf[..n]);
                        if stream.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        (addr, asked)
    }

    /// Whether a reload was queued, without waiting for one that never comes.
    async fn reload_queued(reload: &PolicyReload) -> bool {
        tokio::time::timeout(std::time::Duration::from_millis(50), reload.requested())
            .await
            .is_ok()
    }

    /// The store, the feed and the master, all at `serial` and agreeing.
    fn feed_in_force(
        dir: &ScratchDir,
        addr: SocketAddr,
        text: &str,
    ) -> (Arc<PolicyStore>, TransferredFeed) {
        let path = dir.write("block.example.zone", text);
        let store =
            PolicyStore::load(&[Feed::new(&path, PolicyOverride::Given)]).expect("the feed loads");
        let feed = TransferredFeed {
            spec: MasterSpec::parse(&format!("block.example.@{addr}")).expect("a spec"),
            file: path,
            on_expire: OnExpire::Enforce,
            key: None,
        };
        (store, feed)
    }

    /// A master with nothing new is one round trip: no transfer, no file, no
    /// reload.
    ///
    /// Fails against the shape this replaced, which fetched the whole zone
    /// every REFRESH and rewrote the file whatever the master's serial —
    /// 2.5 s of serialize-write-reparse per unchanged million-rule feed, and a
    /// re-read of every *other* feed with it (`TODO.md` #57e). The second half
    /// is gone on its own account as well — #71b — but this test is about the
    /// first: a master with nothing new must not write the file at all.
    #[tokio::test]
    async fn a_master_with_nothing_new_is_asked_and_not_transferred() {
        let dir = ScratchDir::new("rpz-current");
        let text = feed_text(1, &["www.malware.example"]);
        let (addr, asked) = spawn_master(zone_from(&text), rdns::ixfr::DeltaLog::new()).await;
        let (store, feed) = feed_in_force(&dir, addr, &text);
        let reload = PolicyReload::default();

        // A marker the refresh would overwrite if it wrote the file at all.
        std::fs::write(&feed.file, "this file was not rewritten").expect("the marker is written");

        fetch_and_write(&Master::plain(addr), &feed, &store, &reload)
            .await
            .expect("the refresh reaches the master");

        assert_eq!(
            *asked.lock().expect("the log"),
            ["SOA"],
            "an unchanged zone is a serial comparison and nothing else"
        );
        assert_eq!(
            std::fs::read_to_string(&feed.file).expect("the file is there"),
            "this file was not rewritten"
        );
        assert!(
            !reload_queued(&reload).await,
            "nothing changed, so nothing has to be re-read"
        );
    }

    /// A master that has moved on is asked for the difference, and the version
    /// in force is what it is asked to bring forward.
    ///
    /// Fails against a refresh that always sends AXFR: the master records
    /// which question it was asked.
    #[tokio::test]
    async fn a_newer_serial_arrives_as_an_increment_from_the_version_in_force() {
        let dir = ScratchDir::new("rpz-increment");
        let before = feed_text(1, &["www.malware.example"]);
        let after = feed_text(2, &["shop.malware.example"]);
        let mut deltas = rdns::ixfr::DeltaLog::new();
        deltas.note_change(Some(&zone_from(&before)), &zone_from(&after));

        let (addr, asked) = spawn_master(zone_from(&after), deltas).await;
        let (store, feed) = feed_in_force(&dir, addr, &before);
        let reload = PolicyReload::default();

        fetch_and_write(&Master::plain(addr), &feed, &store, &reload)
            .await
            .expect("the refresh reaches the master");

        assert_eq!(*asked.lock().expect("the log"), ["SOA", "IXFR"]);
        let written = std::fs::read_to_string(&feed.file).expect("the file is there");
        assert!(
            written.contains("shop.malware.example"),
            "the new rule is on disk: {written}"
        );
        assert!(
            !written.contains("www.malware.example"),
            "and the withdrawn one is not: {written}"
        );
        assert!(
            reload_queued(&reload).await,
            "a feed that changed has to be re-read before it is in force"
        );
    }

    /// A feed with no version in force — the file could not be read, or this is
    /// the first refresh — asks for the whole zone. There is nothing to bring
    /// forward from.
    #[tokio::test]
    async fn a_feed_with_nothing_in_force_asks_for_the_whole_zone() {
        let dir = ScratchDir::new("rpz-first");
        let text = feed_text(1, &["www.malware.example"]);
        let (addr, asked) = spawn_master(zone_from(&text), rdns::ixfr::DeltaLog::new()).await;
        let store = PolicyStore::in_memory(rdns::rpz::PolicyZones::default());
        let feed = TransferredFeed {
            spec: MasterSpec::parse(&format!("block.example.@{addr}")).expect("a spec"),
            file: dir.write("block.example.zone", ""),
            on_expire: OnExpire::Enforce,
            key: None,
        };
        let reload = PolicyReload::default();

        fetch_and_write(&Master::plain(addr), &feed, &store, &reload)
            .await
            .expect("the refresh reaches the master");

        assert_eq!(*asked.lock().expect("the log"), ["SOA", "AXFR"]);
        assert!(std::fs::read_to_string(&feed.file)
            .expect("the file is there")
            .contains("www.malware.example"));
    }

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
