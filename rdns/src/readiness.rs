//! Ready is not the same question as alive: `/healthz` is for a supervisor
//! deciding whether to restart, `/readyz` for a load balancer deciding whether to
//! send traffic. A server can be alive and hold none of its zones.
//!
//! Ready here means every configured zone is in the zone map. A primary loads,
//! signs and verifies before the sockets bind, so it is ready as soon as it is
//! alive, with an empty waiting list rather than a special case.
//!
//! A secondary is the case this exists for: `withdraw_unvouched_zones` removes
//! every replicated zone whose age cannot be vouched for — at a cold start with
//! no state sidecar, all of them — and the server then binds and answers REFUSED
//! until the first transfer lands. Nothing else reports that window; the zone
//! gauges are *absent* for a zone we do not hold, and a probe cannot be pointed
//! at an absence.
//!
//! A one-way latch, on purpose. Every replica of a zone expires at the same
//! moment — they share the master's EXPIRE — so a readiness signal following
//! expiry would pull every server out of rotation at once, turning stale data
//! into no server. Staleness is what `dns_zone_last_refresh_timestamp_seconds`
//! and the alert on it are for.
//!
//! No lock: the set of things to wait for is fixed at construction and only ever
//! shrinks, so an atomic per entry plus a counter says everything a mutex would.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::utils::ascii_lowered;

/// One thing that has to arrive before the server is ready.
struct Pending {
    /// ASCII-lowercased at construction, because the only names this holds are
    /// DNS zone names and DNS matching is case-insensitive (RFC 4343). See
    /// [`Readiness::arrived`].
    name: String,
    arrived: AtomicBool,
}

/// Whether this server has finished starting, and what it is still waiting for.
///
/// Cheap to clone (one `Arc`), and every clone reads and writes the same state —
/// the refresh tasks hold one to report arrivals, the metrics endpoint holds one
/// to answer `/readyz`.
#[derive(Clone, Default)]
pub struct Readiness(Arc<Inner>);

#[derive(Default)]
struct Inner {
    waiting: Box<[Pending]>,
    /// How many of `waiting` have not arrived. The counter is the answer;
    /// the names exist to say *what* is missing and to make a repeated arrival
    /// idempotent.
    outstanding: AtomicUsize,
}

impl Readiness {
    /// Ready immediately: there is nothing to wait for.
    ///
    /// This is a primary, and it is not a degenerate case — it is the honest
    /// answer for a server whose zones were all loaded before anything bound a
    /// socket.
    pub fn ready() -> Self {
        Self::default()
    }

    /// Not ready until every one of `names` has [`Self::arrived`].
    ///
    /// Duplicates collapse, because the caller's list does not have to be a set:
    /// a zone replicated from two masters is two `--secondary` specs and one
    /// zone, and counting it twice would leave a server that has the zone
    /// permanently one arrival short of ready.
    pub fn waiting_for<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut waiting: Vec<Pending> = Vec::new();
        for name in names {
            let name = ascii_lowered(name.as_ref());
            if waiting.iter().any(|p| p.name == name) {
                continue;
            }
            waiting.push(Pending {
                name,
                arrived: AtomicBool::new(false),
            });
        }
        let outstanding = AtomicUsize::new(waiting.len());
        Readiness(Arc::new(Inner {
            waiting: waiting.into_boxed_slice(),
            outstanding,
        }))
    }

    /// Record that `name` is now being served. Returns whether this call was the
    /// one that changed anything.
    ///
    /// Idempotent by construction: only the false→true transition decrements the
    /// counter, so a zone that transfers every hour for a year does not count
    /// down past zero. A name that was never waited for is ignored — a primary's
    /// zone reload calls this too, and it has nothing to report.
    pub fn arrived(&self, name: &str) -> bool {
        let name = ascii_lowered(name);
        let Some(entry) = self.0.waiting.iter().find(|p| p.name == name) else {
            return false;
        };
        // `Release` pairs with the `Acquire` in `is_ready`: a reader that sees
        // the counter reach zero sees every flag that got it there.
        if entry
            .arrived
            .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        self.0.outstanding.fetch_sub(1, Ordering::Release);
        true
    }

    /// Whether everything has arrived.
    pub fn is_ready(&self) -> bool {
        self.0.outstanding.load(Ordering::Acquire) == 0
    }

    /// What is still missing, in the order it was registered.
    ///
    /// Empty exactly when [`Self::is_ready`]. This is what `/readyz` puts in its
    /// body: "not ready" with no reason attached is a probe an operator cannot
    /// act on.
    pub fn pending(&self) -> Vec<&str> {
        self.0
            .waiting
            .iter()
            .filter(|p| !p.arrived.load(Ordering::Acquire))
            .map(|p| p.name.as_str())
            .collect()
    }
}

// There is deliberately no `expected()` returning the size of the original set.
// Nothing needs it — the startup banner and `/readyz` both want *what is still
// missing*, which is `pending()` — and a public method whose only caller is a
// test is API surface bought with nothing.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_to_wait_for_is_ready() {
        let readiness = Readiness::ready();
        assert!(readiness.is_ready());
        assert!(readiness.pending().is_empty());
    }

    #[test]
    fn ready_only_once_everything_has_arrived() {
        let readiness = Readiness::waiting_for(["a.example.", "b.example."]);
        assert!(!readiness.is_ready());
        assert_eq!(readiness.pending(), vec!["a.example.", "b.example."]);

        assert!(readiness.arrived("a.example."));
        assert!(!readiness.is_ready(), "one of two is not ready");
        assert_eq!(readiness.pending(), vec!["b.example."]);

        assert!(readiness.arrived("b.example."));
        assert!(readiness.is_ready());
        assert!(readiness.pending().is_empty());
    }

    /// A zone name is matched the way DNS matches names (RFC 4343): the master
    /// sends the origin in whatever case the zone file used, and it does not have
    /// to be the case the `--secondary` flag was written in.
    #[test]
    fn names_match_case_insensitively() {
        let readiness = Readiness::waiting_for(["Example.COM."]);
        assert!(readiness.arrived("example.com."));
        assert!(readiness.is_ready());
    }

    /// A zone with two masters is two specs and one zone. Counting it twice
    /// would leave a server that holds everything permanently not-ready.
    #[test]
    fn a_zone_named_twice_is_waited_for_once() {
        let readiness = Readiness::waiting_for(["example.com.", "example.com."]);
        assert_eq!(readiness.pending(), vec!["example.com."], "registered once");
        assert!(readiness.arrived("example.com."));
        assert!(readiness.is_ready());
    }

    /// The latch does not run backwards, and the counter does not run past zero:
    /// a refresh loop calls this on every successful transfer, which for a zone
    /// with a one-minute refresh is 1,440 calls a day.
    #[test]
    fn arriving_twice_changes_nothing() {
        let readiness = Readiness::waiting_for(["example.com."]);
        assert!(readiness.arrived("example.com."));
        assert!(!readiness.arrived("example.com."), "already counted");
        assert!(readiness.is_ready());
        // The second call must not have wrapped the counter, which would read as
        // `usize::MAX` outstanding and never be ready again.
        assert!(!readiness.arrived("example.com."));
        assert!(readiness.is_ready());
    }

    /// A primary's zones go through the same install path as a secondary's, and
    /// it has an empty waiting list. Reporting an arrival nobody asked about is
    /// not an error.
    #[test]
    fn an_unexpected_arrival_is_ignored() {
        let readiness = Readiness::waiting_for(["example.com."]);
        assert!(!readiness.arrived("other.example."));
        assert!(
            !readiness.is_ready(),
            "the zone we wait for is still missing"
        );
        assert_eq!(readiness.pending(), vec!["example.com."]);
    }

    /// Clones share state — the refresh tasks and the metrics endpoint each hold
    /// one, and they are the same answer.
    #[test]
    fn clones_share_one_answer() {
        let readiness = Readiness::waiting_for(["example.com."]);
        let probe = readiness.clone();
        assert!(!probe.is_ready());
        readiness.arrived("example.com.");
        assert!(probe.is_ready());
    }
}
