//! Re-resolving a cached name in the last tenth of its TTL, off the path of
//! the client that noticed (Unbound's `prefetch`).
//!
//! A queue and a pool rather than work done by the task that answered
//! (`TODO.md` #114). That task is `tcp::Handler::handle` on four transports,
//! and two of them take its return as the end of the answer: DoH builds the
//! HTTP response only after the handler task is joined, DoQ sends FIN only once
//! the sink closes. A refresh run there put an upstream resolution in front of
//! the reply it was meant to follow — 1.5 s against an upstream that never
//! answers, for a reply that was ready in under a millisecond.

use std::sync::Arc;

use rdns::metrics::DnsMetrics;
use rdns::shutdown::Stop;
use rdns::QuerySection;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;

use crate::answer::{refresh, Resolving};

/// The answer path's end of the queue.
pub(crate) struct Prefetch(mpsc::Sender<QuerySection>);

/// The pool's end, handed to [`run`].
pub(crate) struct Queue(mpsc::Receiver<QuerySection>);

/// `depth` is floored at 1: tokio refuses a channel of 0, and a mistyped flag
/// should be wrong rather than fatal.
pub(crate) fn channel(depth: usize) -> (Prefetch, Queue) {
    let (tx, rx) = mpsc::channel(depth.max(1));
    (Prefetch(tx), Queue(rx))
}

impl Prefetch {
    /// Never waits: the caller is answering a client.
    ///
    /// A full queue drops the question. The cache has already marked the entry
    /// as being refreshed, so it runs out and the next client resolves it —
    /// which is what a failed refresh costs as well.
    pub(crate) fn offer(&self, query: QuerySection, metrics: &DnsMetrics) {
        // `Closed` is shutdown, and nothing is owed for it.
        if let Err(TrySendError::Full(_)) = self.0.try_send(query) {
            metrics.count(&metrics.prefetches_dropped);
        }
    }
}

/// Resolve queued questions on `workers` tasks until the stop.
///
/// Holds no `Busy`: nobody is waiting on a prefetch, and the cache it would
/// fill goes with the process, so shutdown aborts one part-way (dropping the
/// `JoinSet`) instead of waiting out an upstream's timeout for it.
///
/// In `main`'s listener set, where "the first to end ends the process" is
/// right: this ends only on the stop, as the listeners do.
pub(crate) async fn run(
    queue: Queue,
    serving: Arc<Resolving>,
    workers: usize,
    stop: Stop,
) -> Result<(), std::io::Error> {
    let queue = Arc::new(Mutex::new(queue.0));
    let mut pool = JoinSet::new();
    for _ in 0..workers.max(1) {
        let (queue, serving) = (queue.clone(), serving.clone());
        pool.spawn(async move {
            loop {
                // The lock is held across the wait on purpose: one idle worker
                // waits on the queue, the rest wait on the lock. A statement of
                // its own, not a `while let`, whose scrutinee's guard would live
                // through the refresh and leave one worker doing all of them.
                let next = queue.lock().await.recv().await;
                // `None` cannot happen while `serving` holds the sender.
                let Some(query) = next else { return };
                refresh(&serving, query).await;
            }
        });
    }
    stop.wait().await;
    Ok(())
}

#[cfg(test)]
impl Queue {
    pub(crate) fn try_recv(&mut self) -> Option<QuerySection> {
        self.0.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use rdns::shutdown::Shutdown;
    use rdns::Qtype;

    use super::*;
    use crate::testutil::*;

    fn question(name: &str) -> QuerySection {
        QuerySection {
            qname: nm(name),
            qtype: Qtype::of(rdns::record_types::A),
            qclass: rdns::QueryClass::IN,
        }
    }

    /// Wait until `metrics.prefetches` reads `n`, which `refresh` counts as it
    /// starts. Whether it reaches `n` at all is the assertion.
    async fn started(serving: &Resolving, n: u64) -> bool {
        tokio::time::timeout(Duration::from_secs(5), async {
            while serving.ctx.metrics.prefetches.load(Ordering::Relaxed) < n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok()
    }

    /// Past its depth the queue drops, and says so.
    #[test]
    fn a_full_queue_drops_and_counts() {
        let metrics = DnsMetrics::new();
        let (prefetch, mut queue) = channel(1);
        prefetch.offer(question("a.example."), &metrics);
        prefetch.offer(question("b.example."), &metrics);

        assert_eq!(metrics.prefetches_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(queue.try_recv().map(|q| q.qname), Some(nm("a.example.")));
    }

    /// Two workers resolve two names at once, against an upstream that never
    /// answers, and the stop ends the pool without waiting for either.
    ///
    /// Watched failing with the worker loop written as `while let Some(query) =
    /// queue.lock().await.recv().await`: the guard lives through the body, so
    /// the second refresh waited for the first's timeout.
    #[tokio::test]
    async fn the_workers_run_at_once_and_the_stop_abandons_them() {
        let (resolver, _upstream) = silent_resolver();
        let (prefetch, queue) = channel(4);
        let serving = serving(resolver, test_shell(), rdns::rpz::PolicyZones::default());
        let shutdown = Shutdown::new();
        let pool = tokio::spawn(run(queue, serving.clone(), 2, shutdown.stop_handle()));

        prefetch.offer(question("a.example."), &serving.ctx.metrics);
        prefetch.offer(question("b.example."), &serving.ctx.metrics);
        assert!(started(&serving, 2).await, "both refreshes started");

        shutdown.begin();
        tokio::time::timeout(Duration::from_secs(1), pool)
            .await
            .expect("the pool ends on the stop, not after the upstream's timeout")
            .expect("the pool did not panic")
            .expect("the pool ends cleanly");
    }
}
