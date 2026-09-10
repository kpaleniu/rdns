//! Ready is not alive: `/healthz` is for a supervisor deciding whether to
//! restart, `/readyz` for a load balancer deciding whether to send traffic. A
//! server can be alive and hold none of its zones.
//!
//! Ready means every configured zone is in the zone map. A primary loads, signs
//! and verifies before the sockets bind, so its waiting list is empty. A
//! secondary is the case this exists for: it binds and answers REFUSED until the
//! first transfer lands, and nothing else reports that window — the zone gauges
//! are *absent* for a zone we do not hold, and a probe cannot watch an absence.
//!
//! A one-way latch. Replicas share the master's EXPIRE, so a signal that
//! followed expiry would pull every server out of rotation at once, turning
//! stale data into no server. Staleness is what
//! `dns_zone_last_refresh_timestamp_seconds` and its alert are for.
//!
//! No lock: the waiting set is fixed at construction and only shrinks.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use crate::text_names::ascii_lowered;

/// One thing that has to arrive before the server is ready.
struct Pending {
    /// ASCII-lowercased at construction: these are zone names (RFC 4343).
    name: String,
    arrived: AtomicBool,
}

/// Whether this server has finished starting, and what it is still waiting for.
///
/// Clones share state: the refresh tasks report arrivals, the metrics endpoint
/// answers `/readyz`.
#[derive(Clone, Default)]
pub struct Readiness(Arc<Inner>);

#[derive(Default)]
struct Inner {
    waiting: Box<[Pending]>,
    /// How many of `waiting` have not arrived. The counter is the answer; the
    /// names say *what* is missing and make a repeated arrival idempotent.
    outstanding: AtomicUsize,
}

impl Readiness {
    /// Ready immediately — a primary, whose zones all loaded before any socket
    /// bound.
    pub fn ready() -> Self {
        Self::default()
    }

    /// Not ready until every one of `names` has [`Self::arrived`].
    ///
    /// Duplicates collapse: a zone replicated from two masters is two
    /// `--secondary` specs and one zone, and counting it twice would leave a
    /// server holding it permanently one arrival short.
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

    /// Record that `name` is now being served. Returns whether this call
    /// changed anything.
    ///
    /// Only the false→true transition decrements, so a zone transferring hourly
    /// does not count past zero. A name never waited for is ignored: a
    /// primary's reload calls this too.
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

    /// What is still missing, in registration order — `/readyz`'s body, since
    /// "not ready" with no reason is a probe nobody can act on.
    pub fn pending(&self) -> Vec<&str> {
        self.0
            .waiting
            .iter()
            .filter(|p| !p.arrived.load(Ordering::Acquire))
            .map(|p| p.name.as_str())
            .collect()
    }
}

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

    /// The master sends the origin in the zone file's case, which need not be
    /// the case the `--secondary` flag used (RFC 4343).
    #[test]
    fn names_match_case_insensitively() {
        let readiness = Readiness::waiting_for(["Example.COM."]);
        assert!(readiness.arrived("example.com."));
        assert!(readiness.is_ready());
    }

    /// Counting a two-master zone twice leaves a server holding everything
    /// permanently not-ready.
    #[test]
    fn a_zone_named_twice_is_waited_for_once() {
        let readiness = Readiness::waiting_for(["example.com.", "example.com."]);
        assert_eq!(readiness.pending(), vec!["example.com."], "registered once");
        assert!(readiness.arrived("example.com."));
        assert!(readiness.is_ready());
    }

    /// The counter must not run past zero: a refresh loop calls this on every
    /// successful transfer.
    #[test]
    fn arriving_twice_changes_nothing() {
        let readiness = Readiness::waiting_for(["example.com."]);
        assert!(readiness.arrived("example.com."));
        assert!(!readiness.arrived("example.com."), "already counted");
        assert!(readiness.is_ready());
        // A wrapped counter reads as `usize::MAX` outstanding: never ready.
        assert!(!readiness.arrived("example.com."));
        assert!(readiness.is_ready());
    }

    /// A primary's zones take the same install path with an empty waiting list.
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

    #[test]
    fn clones_share_one_answer() {
        let readiness = Readiness::waiting_for(["example.com."]);
        let probe = readiness.clone();
        assert!(!probe.is_ready());
        readiness.arrived("example.com.");
        assert!(probe.is_ready());
    }
}
