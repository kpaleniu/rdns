//! The journal's one writer: saves and deletes run here, off every lock an
//! answer takes and off the runtime's workers (`CLAUDE.md` §9).
//!
//! An install records a step under the zone map's write guard and queues the
//! zone's steps; this task renders, writes and fsyncs them afterwards. The
//! journal may therefore lag the delta log by a step, which `restore_journals`
//! already handles: a journal short of the loaded serial is discarded.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use rdns::ixfr::ZoneDelta;
use rdns::journal::Journal;
use rdns::shutdown::Lifecycle;
use rdns::{Name, NameRef};
use tokio::sync::Notify;

/// What the journal of one zone should become.
enum Request {
    Save(Vec<Arc<ZoneDelta>>),
    Forget,
}

/// A handle on the writer; cheap to clone.
#[derive(Clone)]
pub(crate) struct JournalWriter(Arc<Shared>);

struct Shared {
    journal: Arc<Journal>,
    /// The newest request per zone. A newer one replaces an older one still
    /// waiting, which is what keeps one zone's writes in order.
    pending: Mutex<HashMap<Name, Request>>,
    wake: Notify,
    /// One batch at a time, so a batch taken later is never written first.
    writing: tokio::sync::Mutex<()>,
}

impl JournalWriter {
    pub(crate) fn new(journal: Arc<Journal>) -> Self {
        JournalWriter(Arc::new(Shared {
            journal,
            pending: Mutex::new(HashMap::new()),
            wake: Notify::new(),
            writing: tokio::sync::Mutex::new(()),
        }))
    }

    /// The journal this writes, for the startup paths that read it directly.
    pub(crate) fn journal(&self) -> &Journal {
        &self.0.journal
    }

    /// Queue `zone`'s steps to be written. Call under the guard that recorded
    /// them, so a newer snapshot is always queued after an older one.
    pub(crate) fn save(&self, zone: NameRef<'_>, steps: Vec<Arc<ZoneDelta>>) {
        self.queue(zone, Request::Save(steps));
    }

    /// Queue `zone`'s journal for deletion.
    pub(crate) fn forget(&self, zone: NameRef<'_>) {
        self.queue(zone, Request::Forget);
    }

    fn queue(&self, zone: NameRef<'_>, request: Request) {
        // A panic under this lock leaves a whole map; the data is still good.
        let mut pending = self
            .0
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        pending.insert(zone.to_owned(), request);
        drop(pending);
        self.0.wake.notify_one();
    }

    /// Write everything queued so far, on a blocking thread.
    pub(crate) async fn write_pending(&self) {
        let _writing = self.0.writing.lock().await;
        let batch = std::mem::take(
            &mut *self
                .0
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        if batch.is_empty() {
            return;
        }
        let shared = Arc::clone(&self.0);
        let written = tokio::task::spawn_blocking(move || {
            for (zone, request) in batch {
                match request {
                    Request::Save(steps) => {
                        let steps: Vec<&ZoneDelta> = steps.iter().map(Arc::as_ref).collect();
                        // A failed write only logs: RFC 1995 §4 permits a full
                        // transfer, and a short journal is discarded at restore.
                        if let Err(e) = shared.journal.save(zone.as_ref(), &steps) {
                            tracing::warn!("could not persist the delta log for {zone}: {e}");
                        }
                    }
                    Request::Forget => shared.journal.forget(zone.as_ref()),
                }
            }
        })
        .await;
        if let Err(e) = written {
            tracing::warn!("the journal writer's task failed: {e}");
        }
    }

    /// Write whatever is queued until the stop, then once more and return.
    ///
    /// Holds the [`Busy`](rdns::shutdown::Busy) for its life and exits on the
    /// stop, as the zone-maintenance task does, so the drain waits for the
    /// last batch. An install racing the stop may miss it: its journal then
    /// lags, and is discarded at the next start.
    pub(crate) fn spawn(&self, lifecycle: Lifecycle) {
        let writer = self.clone();
        tokio::spawn(async move {
            let Lifecycle { stop, busy } = lifecycle;
            let _busy = busy;
            loop {
                tokio::select! {
                    _ = writer.0.wake.notified() => writer.write_pending().await,
                    _ = stop.wait() => break,
                }
            }
            writer.write_pending().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{nm, served, zone_at_serial};
    use crate::zones::{install_zone, ZoneContext, Zones};
    use rdns::ixfr::DeltaLog;
    use rdns::shutdown::Shutdown;
    use rdns::testutil::ScratchDir;
    use rdns::zone::{parse_zone_file, Zone};
    use std::path::Path;
    use std::time::Duration;
    use tokio::sync::RwLock;

    fn zone(serial: u32, extra: &str) -> Zone {
        parse_zone_file(&(zone_at_serial(serial) + extra), "example.com.").expect("parses")
    }

    fn journal_file(dir: &Path) -> std::path::PathBuf {
        dir.join("example.com.journal")
    }

    fn writer(dir: &Path) -> JournalWriter {
        JournalWriter::new(Arc::new(Journal::new(dir)))
    }

    /// One recorded step, as the writer is handed it.
    fn steps() -> Vec<Arc<ZoneDelta>> {
        let mut log = DeltaLog::new();
        log.note_change(Some(&zone(1, "")), &zone(2, "new IN A 192.0.2.3\n"));
        log.steps(nm("example.com.").as_ref())
    }

    /// An install queues its journal and writes nothing itself; the zone is
    /// served at once, and the file appears when the writer runs. Fails if the
    /// install writes the journal under the zone map's write guard.
    #[tokio::test]
    async fn an_install_leaves_the_journal_to_the_writer() {
        let dir = ScratchDir::new("journal-writer-install");
        let writer = writer(dir.path());
        let zone_map = Arc::new(RwLock::new(Zones::default()));
        let deltas = Arc::new(RwLock::new(DeltaLog::new()));
        let served = ZoneContext {
            journal: Some(writer.clone()),
            ..served(&zone_map, &deltas)
        };

        install_zone(&served, zone(1, "")).await;
        install_zone(&served, zone(2, "new IN A 192.0.2.3\n")).await;
        assert_eq!(deltas.read().await.len(nm("example.com.").as_ref()), 1);
        assert!(
            !journal_file(dir.path()).exists(),
            "the install wrote the journal"
        );
        let serial = zone_map
            .read()
            .await
            .matching(nm("example.com.").as_ref())
            .and_then(Zone::serial);
        assert_eq!(
            serial,
            Some(rdns::Serial::new(2)),
            "served before the write"
        );

        writer.write_pending().await;
        let restored = writer
            .journal()
            .load(nm("example.com.").as_ref())
            .expect("reads back");
        assert_eq!(restored.len(), 1);
    }

    /// The newest request for a zone wins: a delete queued after a save leaves
    /// no file, and a save queued after a delete leaves one.
    #[tokio::test]
    async fn the_newest_request_for_a_zone_is_the_one_written() {
        let dir = ScratchDir::new("journal-writer-order");
        let writer = writer(dir.path());
        let zone = nm("example.com.");

        writer.save(zone.as_ref(), steps());
        writer.write_pending().await;
        assert!(journal_file(dir.path()).exists());

        writer.save(zone.as_ref(), steps());
        writer.forget(zone.as_ref());
        writer.write_pending().await;
        assert!(!journal_file(dir.path()).exists(), "the delete came last");

        writer.forget(zone.as_ref());
        writer.save(zone.as_ref(), steps());
        writer.write_pending().await;
        assert!(journal_file(dir.path()).exists(), "the save came last");
    }

    /// The shutdown drain waits for a save queued before the stop. Fails if
    /// the writer does not hold the drain open: on this one-thread runtime the
    /// drain would finish before the writer ever runs.
    #[tokio::test]
    async fn the_drain_waits_for_a_queued_save() {
        let dir = ScratchDir::new("journal-writer-drain");
        let writer = writer(dir.path());
        let shutdown = Shutdown::new();
        writer.spawn(shutdown.lifecycle());

        writer.save(nm("example.com.").as_ref(), steps());
        shutdown.begin();
        assert!(shutdown.drain(Duration::from_secs(5)).await, "drained");
        assert!(
            journal_file(dir.path()).exists(),
            "written before the drain ended"
        );
    }
}
