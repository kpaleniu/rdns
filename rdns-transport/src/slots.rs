//! A stream listener's connection ceiling, taken before `accept` and visible
//! when it is reached (`TODO.md` #155).
//!
//! The four accept loops took a semaphore permit *after* `accept`, so a full
//! listener held the next connection open and unserved and said nothing.
//! Taking it first leaves that connection in the kernel's backlog, where it
//! costs no descriptor.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rdns::metrics::{DnsMetrics, StreamListener};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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
}

impl Slots {
    /// `limit` slots for `listener`, whose series join the scrape from here.
    pub(crate) fn new(limit: usize, metrics: &DnsMetrics, listener: StreamListener) -> Slots {
        metrics.listener(listener).configure();
        Slots(Arc::new(Shared {
            permits: Arc::new(Semaphore::new(limit)),
            metrics: metrics.clone(),
            listener,
            limit,
            full: AtomicBool::new(false),
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
        }
    }
}

/// One slot, released on drop.
pub(crate) struct Slot {
    permit: Option<OwnedSemaphorePermit>,
    shared: Arc<Shared>,
    open: bool,
}

impl Slot {
    /// A connection now holds this slot. Separate from [`Slots::take`]
    /// because the accept loop holds one while it waits in `accept`, and the
    /// gauge counts connections, not that.
    pub(crate) fn open(&mut self) {
        self.open = true;
        self.shared.metrics.listener(self.shared.listener).opened();
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
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
