//! The wall clock, and the one rule about it.
//!
//! `SystemTime`, so it can step backwards: an NTP correction makes a
//! `now - last_refill` underflow, which is a debug panic with a mutex held, and
//! every later call on that poisoned mutex panics too — a clock correction
//! taking the process off the air permanently (`CLAUDE.md` §6). **Every
//! subtraction of two of these is `saturating_sub`.** Anything measuring an
//! interval rather than naming an instant wants `Instant` instead.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The current Unix timestamp in seconds, or 0 if the clock is before the epoch.
///
/// # Examples
/// ```ignore
/// let now = current_unix_timestamp();
/// assert!(now > 0);
/// ```
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Where a caller reads the wall clock.
///
/// An enum so a test can fix and move the instant, where a rate limit against
/// the system clock tosses a coin on a second boundary (`CLAUDE.md` §10). A
/// request path reads through a `Clock`; which reads do not, and why, is
/// `TODO.md` #92 and #107.
#[derive(Clone, Debug)]
pub enum Clock {
    /// [`current_unix_timestamp`].
    System,
    /// A time the holder sets. Shared, so a clone advances with the original.
    Fixed(Arc<AtomicU64>),
}

impl Clock {
    pub fn system() -> Clock {
        Clock::System
    }

    /// A clock stopped at `secs`, which [`Clock::advance`] moves.
    pub fn fixed(secs: u64) -> Clock {
        Clock::Fixed(Arc::new(AtomicU64::new(secs)))
    }

    pub fn now(&self) -> u64 {
        match self {
            Clock::System => current_unix_timestamp(),
            // `Relaxed`: a test sets this from the thread that then reads it,
            // or across an await that already ordered them.
            Clock::Fixed(at) => at.load(Ordering::Relaxed),
        }
    }

    /// Move a fixed clock forward. A no-op on [`Clock::System`], which nothing
    /// may set.
    pub fn advance(&self, secs: u64) {
        if let Clock::Fixed(at) = self {
            at.fetch_add(secs, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_unix_timestamp() {
        let ts = current_unix_timestamp();
        assert!(ts > 0);

        let ts2 = current_unix_timestamp();
        assert!(ts2 >= ts);
    }
    #[test]
    fn a_fixed_clock_does_not_move_until_it_is_told_to() {
        let clock = Clock::fixed(1_000);
        let same = clock.clone();
        assert_eq!(clock.now(), 1_000);
        assert_eq!(clock.now(), 1_000);
        clock.advance(5);
        // The clone shares the instant: a `ServeContext` is cloned into every
        // task, so a test that advanced only its own copy would prove nothing.
        assert_eq!(same.now(), 1_005);
    }

    #[test]
    fn a_system_clock_cannot_be_set() {
        let clock = Clock::system();
        let before = clock.now();
        clock.advance(3_600);
        assert!(clock.now().saturating_sub(before) < 3_600);
    }
}
