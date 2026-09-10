//! The wall clock, and the one rule about it.
//!
//! `SystemTime`, so it can step backwards: an NTP correction made a
//! `now - last_refill` underflow, which was a debug panic with a mutex held,
//! and every later call on that poisoned mutex panicked too — a clock
//! correction taking the process off the air permanently (`CLAUDE.md` §6).
//! **Every subtraction of two of these is `saturating_sub`.** Anything
//! measuring an interval rather than naming an instant wants `Instant`
//! instead.

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
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
}
