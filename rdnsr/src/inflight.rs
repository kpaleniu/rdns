//! The UDP loop's places for in-flight queries, and who gives way when every
//! one is held (`TODO.md` #169).
//!
//! Full, the oldest query gives way once it has outlived RFC 8767 §5's client
//! response timer — its client has stopped waiting — and otherwise the
//! newcomer is dropped. Measured against the alternatives with a flood of
//! names under zones that never answer, each delegated to fresh addresses:
//!
//! - Dropping the newest, as a semaphore does, is full at `max / resolution
//!   timer`, ~102 queries a second at the defaults.
//! - Dropping the oldest, BIND's `recursive-clients`, protects up to `max /
//!   legitimate resolution time` and then answers no legitimate client at all,
//!   which is the rate an attacker picks.
//! - A cap per zone, or skipping servers that went silent, did nothing: the
//!   attacker's zones and addresses are new each time.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use rdns::cache::CLIENT_RESPONSE_TIMER;
use tokio::task::AbortHandle;
use tokio::time::Instant;

pub(crate) struct InFlight {
    max: usize,
    /// By admission order: ids only grow, so the first entry is the oldest.
    held: Mutex<Places>,
}

#[derive(Default)]
struct Places {
    next: u64,
    by_id: BTreeMap<u64, Held>,
}

struct Held {
    since: Instant,
    /// `None` only between `admit` and `hold`, which `udp_main` calls in one
    /// iteration of its loop, so the oldest always has one by the next `admit`.
    task: Option<AbortHandle>,
}

pub(crate) enum Admission {
    Free(Place),
    /// The oldest was abandoned for this one.
    Evicted(Place),
    /// Every place is held by a query its client may still be waiting for.
    Full,
}

/// One held place, given back when the task holding it ends, however it ends.
pub(crate) struct Place {
    in_flight: Arc<InFlight>,
    id: u64,
}

impl InFlight {
    pub(crate) fn new(max: usize) -> Arc<Self> {
        Arc::new(InFlight {
            max,
            held: Mutex::default(),
        })
    }

    // A poisoned lock is recovered: every critical section here is a map
    // operation that cannot leave it half-written.
    fn places(&self) -> std::sync::MutexGuard<'_, Places> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn admit(self: &Arc<Self>) -> Admission {
        let mut places = self.places();
        let mut evicted = false;
        if places.by_id.len() >= self.max {
            let Some(entry) = places.by_id.first_entry() else {
                return Admission::Full;
            };
            if entry.get().since.elapsed() <= CLIENT_RESPONSE_TIMER {
                return Admission::Full;
            }
            if let Some(task) = entry.remove().task {
                task.abort();
            }
            evicted = true;
        }
        let id = places.next;
        places.next += 1;
        places.by_id.insert(
            id,
            Held {
                since: Instant::now(),
                task: None,
            },
        );
        let place = Place {
            in_flight: self.clone(),
            id,
        };
        if evicted {
            Admission::Evicted(place)
        } else {
            Admission::Free(place)
        }
    }

    /// The task now holding `place`, so an eviction can abort it.
    pub(crate) fn hold(&self, id: u64, task: AbortHandle) {
        // Absent if the task has already finished and given its place back.
        if let Some(held) = self.places().by_id.get_mut(&id) {
            held.task = Some(task);
        }
    }
}

impl Place {
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        self.in_flight.places().by_id.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A task that never finishes, holding `place` as `udp_main`'s does.
    fn parked(in_flight: &Arc<InFlight>, place: Place) -> tokio::task::JoinHandle<()> {
        let id = place.id();
        let task = tokio::spawn(async move {
            let _place = place;
            std::future::pending::<()>().await
        });
        in_flight.hold(id, task.abort_handle());
        task
    }

    fn admitted(admission: Admission) -> Place {
        match admission {
            Admission::Free(place) => place,
            Admission::Evicted(_) => panic!("evicted"),
            Admission::Full => panic!("full"),
        }
    }

    /// Full, a query younger than the client response timer keeps its place
    /// and the newcomer is refused; past it, the oldest is aborted and the
    /// newcomer takes its place.
    #[tokio::test(start_paused = true)]
    async fn the_oldest_gives_way_only_once_its_client_has_stopped_waiting() {
        let in_flight = InFlight::new(2);
        let oldest = parked(&in_flight, admitted(in_flight.admit()));
        tokio::time::advance(Duration::from_millis(100)).await;
        let newer = parked(&in_flight, admitted(in_flight.admit()));

        tokio::time::advance(CLIENT_RESPONSE_TIMER - Duration::from_millis(100)).await;
        assert!(matches!(in_flight.admit(), Admission::Full), "at the timer");

        tokio::time::advance(Duration::from_millis(1)).await;
        let Admission::Evicted(place) = in_flight.admit() else {
            panic!("the oldest is past the timer");
        };
        assert!(oldest.await.expect_err("aborted").is_cancelled());
        assert!(!newer.is_finished(), "only the oldest");
        assert!(
            matches!(in_flight.admit(), Admission::Full),
            "still two held"
        );
        drop(place);
        newer.abort();
    }

    /// A task that ends gives its place back.
    #[tokio::test(start_paused = true)]
    async fn a_finished_query_frees_its_place() {
        let in_flight = InFlight::new(1);
        let place = admitted(in_flight.admit());
        let id = place.id();
        let task = tokio::spawn(async move { drop(place) });
        in_flight.hold(id, task.abort_handle());
        task.await.expect("ran");
        admitted(in_flight.admit());
    }
}
