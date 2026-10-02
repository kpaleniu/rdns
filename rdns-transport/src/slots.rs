//! A stream listener's connection ceiling, taken before `accept` and visible
//! when it is reached (`TODO.md` #155), and the share of it one source may
//! hold (#156).
//!
//! The four accept loops took a semaphore permit *after* `accept`, so a full
//! listener held the next connection open and unserved and said nothing.
//! Taking it first leaves that connection in the kernel's backlog, where it
//! costs no descriptor.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rdns::metrics::{DnsMetrics, StreamListener};
use rdns::peer::{Peer, Source};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::SourceConnections;

/// How often a refused source is named in the log. A line per refusal would
/// let the source set the log's volume.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(60);

pub(crate) struct Slots(Arc<Shared>);

struct Shared {
    permits: Arc<Semaphore>,
    metrics: DnsMetrics,
    listener: StreamListener,
    limit: usize,
    /// Set by the first wait and cleared when a release leaves a slot free,
    /// so an episode is one warning and one info line however many
    /// connections queue in it.
    full: AtomicBool,
    per_source: SourceConnections,
    /// Open connections per source. An entry lives only while its source holds
    /// one, so the table is bounded by the listener's own ceiling (§5).
    sources: Mutex<HashMap<Source, Held>>,
}

#[derive(Default)]
struct Held {
    open: usize,
    /// When this source was last named for a refusal. On the entry, which a
    /// refused source always has, so the rate limit on the log line needs no
    /// table of its own.
    logged: Option<Instant>,
}

impl Slots {
    /// `limit` slots for `listener`, whose series join the scrape from here.
    pub(crate) fn new(
        limit: usize,
        metrics: &DnsMetrics,
        listener: StreamListener,
        per_source: SourceConnections,
    ) -> Slots {
        metrics.listener(listener).configure();
        Slots(Arc::new(Shared {
            permits: Arc::new(Semaphore::new(limit)),
            metrics: metrics.clone(),
            listener,
            limit,
            full: AtomicBool::new(false),
            per_source,
            sources: Mutex::new(HashMap::new()),
        }))
    }

    /// A slot, waiting for one if every slot is taken.
    pub(crate) async fn take(&self) -> Slot {
        let shared = &self.0;
        let permit = match shared.permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                shared.metrics.listener(shared.listener).waited();
                if !shared.full.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        transport = shared.listener.label(),
                        limit = shared.limit,
                        "listener full; new connections wait in the backlog \
                         (--max-connections)"
                    );
                }
                shared
                    .permits
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("the semaphore is never closed")
            }
        };
        Slot {
            permit: Some(permit),
            shared: shared.clone(),
            open: false,
            source: None,
        }
    }

    #[cfg(test)]
    fn tracked_sources(&self) -> usize {
        self.0.sources.lock().expect("not poisoned").len()
    }
}

/// One slot, released on drop.
pub(crate) struct Slot {
    permit: Option<OwnedSemaphorePermit>,
    shared: Arc<Shared>,
    open: bool,
    /// The source counted for this connection, if it was counted.
    source: Option<Source>,
}

impl Slot {
    /// A connection from `peer` now holds this slot, or `false` if its source
    /// already holds as many as `--max-connections-per-source` allows. The
    /// caller closes a refused connection without a reply, and dropping the
    /// slot releases it.
    ///
    /// After `accept`, not before like [`Slots::take`]: the peer is known only
    /// from `accept`. Separate from `take` too because the accept loop holds a
    /// slot while it waits, and the gauge counts connections, not that.
    pub(crate) fn open(&mut self, peer: Peer) -> bool {
        let per_source = &self.shared.per_source;
        if per_source.limit > 0 && !per_source.exempt.allows(peer) {
            let source = Source::of(peer);
            // Poisoned: nothing panics holding this lock, so state is whole;
            // admitting is the direction the total ceiling still bounds.
            if let Ok(mut sources) = self.shared.sources.lock() {
                let held = sources.entry(source).or_default();
                if held.open >= per_source.limit {
                    self.refuse(source, held);
                    return false;
                }
                held.open += 1;
                self.source = Some(source);
            }
        }
        self.open = true;
        self.shared.metrics.listener(self.shared.listener).opened();
        true
    }

    fn refuse(&self, source: Source, held: &mut Held) {
        let shared = &self.shared;
        shared
            .metrics
            .listener(shared.listener)
            .refused_for_source();
        let now = Instant::now();
        if held
            .logged
            .is_none_or(|at| now.duration_since(at) >= REFUSAL_LOG_INTERVAL)
        {
            held.logged = Some(now);
            tracing::warn!(
                transport = shared.listener.label(),
                %source,
                limit = shared.per_source.limit,
                "connection refused: this source already holds the most it may \
                 (--max-connections-per-source); said once a minute per source"
            );
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(source) = self.source {
            if let Ok(mut sources) = self.shared.sources.lock() {
                if let Some(held) = sources.get_mut(&source) {
                    held.open = held.open.saturating_sub(1);
                    if held.open == 0 {
                        sources.remove(&source);
                    }
                }
            }
        }
        if self.open {
            self.shared.metrics.listener(self.shared.listener).closed();
        }
        drop(self.permit.take());
        // A release goes straight to a queued waiter, so a free permit here
        // means nothing was waiting: the listener has room again.
        if self.shared.permits.available_permits() > 0
            && self.shared.full.swap(false, Ordering::Relaxed)
        {
            tracing::info!(
                transport = self.shared.listener.label(),
                "listener has room again"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use rdns::security::TransferAcl;

    use super::*;

    fn peer(s: &str) -> Peer {
        Peer::from(s.parse::<IpAddr>().expect("an address"))
    }

    fn slots(limit: usize, exempt: &[&str]) -> (Slots, DnsMetrics) {
        let metrics = DnsMetrics::new();
        let exempt = TransferAcl::parse(&exempt.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("acl");
        let slots = Slots::new(
            64,
            &metrics,
            StreamListener::Tcp,
            SourceConnections::new(limit, exempt),
        );
        (slots, metrics)
    }

    /// Opens a slot for each of `peers`, keeping those admitted.
    async fn open(slots: &Slots, peers: &[&str]) -> (Vec<Slot>, usize) {
        let mut held = Vec::new();
        let mut refused = 0;
        for p in peers {
            let mut slot = slots.take().await;
            if slot.open(peer(p)) {
                held.push(slot);
            } else {
                refused += 1;
            }
        }
        (held, refused)
    }

    #[tokio::test]
    async fn a_source_is_counted_by_its_block() {
        let (slots, _) = slots(2, &[]);
        let (_one_56, refused) = open(
            &slots,
            &["2001:db8:0:1::1", "2001:db8:0:2::1", "2001:db8:0:3::1"],
        )
        .await;
        assert_eq!(refused, 1, "three peers in one /56 share a limit of two");

        let (_two_56s, refused) = open(&slots, &["2001:db8:0:100::1", "2001:db8:0:200::1"]).await;
        assert_eq!(refused, 0, "two /56s are two sources");

        let (_one_24, refused) = open(&slots, &["192.0.2.1", "192.0.2.2", "192.0.2.3"]).await;
        assert_eq!(refused, 0, "an IPv4 source is the address, not its /24");
    }

    #[tokio::test]
    async fn an_exempt_source_and_a_limit_of_zero_are_unlimited() {
        let (exempting, _) = slots(1, &["192.0.2.0/24"]);
        let (_held, refused) = open(&exempting, &["192.0.2.1"; 5]).await;
        assert_eq!(refused, 0);
        assert_eq!(
            exempting.tracked_sources(),
            0,
            "an exempt source is not counted"
        );

        let (off, _) = slots(0, &[]);
        let (_held, refused) = open(&off, &["192.0.2.1"; 5]).await;
        assert_eq!(refused, 0);
    }

    /// §5: the table is keyed on something the peer chooses, so an entry
    /// lives only while its source holds a connection.
    #[tokio::test]
    async fn the_table_is_empty_once_every_connection_closes() {
        let (slots, _) = slots(2, &[]);
        let (held, _) = open(
            &slots,
            &["192.0.2.1", "192.0.2.1", "192.0.2.1", "2001:db8::1"],
        )
        .await;
        assert_eq!(slots.tracked_sources(), 2);
        drop(held);
        assert_eq!(slots.tracked_sources(), 0);
    }

    /// The counter moves per refusal; the log names the source once.
    #[tokio::test]
    async fn a_refused_source_is_counted_each_time_and_named_once() {
        let (logs, _guard) = crate::testutil::capture_logs();
        let (slots, metrics) = slots(1, &[]);
        let (_held, refused) = open(&slots, &["192.0.2.9"; 6]).await;
        assert_eq!(refused, 5);
        assert_eq!(
            metrics.listener(StreamListener::Tcp).refused_per_source(),
            5
        );
        let text = String::from_utf8(logs.lock().expect("logs").clone()).expect("utf-8");
        assert_eq!(text.matches("source=192.0.2.9").count(), 1, "{text}");
    }
}
