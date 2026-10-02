//! When a cache entry stops being an answer, in one place.
//!
//! Every cache stored `expires_at: u64` and wrote the arithmetic itself: eight
//! constructions of which one saturated, eleven liveness tests against one
//! spelled the other way round, four copies of the clamp to a TTL (`TODO.md`
//! #154). §2 and §6 say `saturating_add` onto a timestamp; a rule applied per
//! call site was missed at seven of eight, so it lives in the type.
//!
//! Each cache still caps its TTL with its own constant before building one: the
//! caps are per-cache policy, and this type only does the arithmetic.

use crate::cache::STALE_REFRESH_INTERVAL;

/// A moment in Unix seconds after which a cache entry is no longer live.
///
/// Ordered, so [`crate::eviction::Halving`] can rank by it. `Default` is the
/// epoch: already past, which is what a stale-refresh moment on a new entry
/// wants (due at once).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Deadline(u64);

impl Deadline {
    /// `secs` after `now`, saturating: a clock near the end of `u64` keeps the
    /// entry rather than overflowing (a debug panic with a cache lock held).
    pub(crate) fn after(now: u64, secs: u64) -> Deadline {
        Deadline(now.saturating_add(secs))
    }

    /// Whether `now` is still before it.
    pub(crate) fn is_live(self, now: u64) -> bool {
        now < self.0
    }

    /// Seconds left at `now`, zero once past.
    pub(crate) fn remaining(self, now: u64) -> u64 {
        self.0.saturating_sub(now)
    }

    /// Seconds left at `now` as a TTL, which is 32 bits on the wire.
    pub(crate) fn remaining_ttl(self, now: u64) -> u32 {
        u32::try_from(self.remaining(now)).unwrap_or(u32::MAX)
    }

    /// The same moment `secs` later, saturating.
    pub(crate) fn extended_by(self, secs: u64) -> Deadline {
        Deadline(self.0.saturating_add(secs))
    }

    /// The instant itself, for a ranking that takes a bare `u64`.
    pub(crate) fn unix_secs(self) -> u64 {
        self.0
    }

    /// Claim the stale refresh RFC 8767 §5 allows "no more frequently than
    /// every 30 seconds": true when `refreshing` and this moment has come,
    /// which also moves it [`STALE_REFRESH_INTERVAL`] on. Both caches that
    /// serve stale call this under the lock their lookup already holds.
    pub(crate) fn claim_stale_refresh(&mut self, refreshing: bool, now: u64) -> bool {
        let refresh = refreshing && !self.is_live(now);
        if refresh {
            *self = Deadline::after(now, STALE_REFRESH_INTERVAL);
        }
        refresh
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_until_the_second_it_names() {
        let d = Deadline::after(1_000, 60);
        assert!(d.is_live(1_059));
        assert!(!d.is_live(1_060));
        assert_eq!(d.remaining(1_059), 1);
        assert_eq!(d.remaining(2_000), 0);
    }

    #[test]
    fn the_end_of_time_saturates() {
        let d = Deadline::after(u64::MAX - 10, 3600);
        assert!(d.is_live(u64::MAX - 1));
        assert_eq!(d.remaining_ttl(0), u32::MAX);
        assert_eq!(d.extended_by(1), d);
    }

    #[test]
    fn a_stale_refresh_is_claimed_once_per_interval() {
        let mut moment = Deadline::default();
        assert!(!moment.claim_stale_refresh(false, 100), "not refreshing");
        assert!(moment.claim_stale_refresh(true, 100), "due at once");
        assert!(!moment.claim_stale_refresh(true, 100 + STALE_REFRESH_INTERVAL - 1));
        assert!(moment.claim_stale_refresh(true, 100 + STALE_REFRESH_INTERVAL));
    }
}
