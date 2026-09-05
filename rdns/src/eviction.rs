//! Halving a bounded cache, in one place.
//!
//! Three of this crate's five bounded maps evict on expiry, and they got it
//! right in different orders: [`crate::cache`] halves with `select_nth_unstable`
//! and admits ties, [`crate::negative_cache`] and [`crate::nsec_cache`] each
//! took a `min_by_key` scan plus a key clone per victim — O(n²) with the global
//! lock held, measured at 14.6 µs per insert against 0.26 for the fixed sibling,
//! at `rdnsr`'s default bound (`TODO.md` #33a). This is that halving, moved
//! (`CLAUDE.md` §7), and the reason is here so the next copy is not written:
//!
//! - **One victim per insert is the quadratic.** Once a bounded cache is full it
//!   is full forever, so a scan per insert is a scan per query. Halving pays
//!   O(n) once per n/2 inserts.
//! - **Yield a value, not an entry**, so no key is cloned to find the boundary.
//! - **Admit ties.** Expiries are whole seconds, so a cache filled in one burst
//!   at one TTL has every entry on the same value, and a plain
//!   `retain(|e| e.expires_at > cutoff)` empties it instead of halving it.

/// One eviction pass, planned before anything is removed: the expiry that is
/// the boundary, and how many entries sitting exactly on it may stay.
///
/// Two phases because a bound can span several maps — [`crate::negative_cache`]
/// holds NXDOMAIN and NODATA in separate ones under one limit — so the plan
/// counts every expiry and each map is then `retain`ed with the same plan.
pub(crate) struct Halving {
    cutoff: u64,
    ties_to_keep: usize,
}

impl Halving {
    /// Plan a pass leaving `target` of `expiries` alive, soonest to expire going
    /// first. `None` when nothing has to go.
    ///
    /// `expiries` is consumed: [`slice::select_nth_unstable`] partitions in O(n)
    /// average, in place, without sorting.
    pub(crate) fn plan(mut expiries: Vec<u64>, target: usize) -> Option<Self> {
        if expiries.len() <= target {
            return None;
        }
        if target == 0 {
            // `select_nth_unstable(len)` panics — and would panic holding the
            // cache lock, which poisons it and stops the cache for the life of
            // the process (§6). Reachable: `rdnsr --cache-size 1` halves to a
            // target of zero on its second answer.
            return Some(Halving {
                cutoff: u64::MAX,
                ties_to_keep: 0,
            });
        }

        let remove = expiries.len() - target;
        let (_, &mut cutoff, _) = expiries.select_nth_unstable(remove);
        let strictly_newer = expiries.iter().filter(|&&e| e > cutoff).count();
        Some(Halving {
            cutoff,
            ties_to_keep: target.saturating_sub(strictly_newer),
        })
    }

    /// Whether the entry expiring at `expires_at` survives. Call once per entry,
    /// from a `retain`, over every map the plan counted and no other.
    pub(crate) fn keep(&mut self, expires_at: u64) -> bool {
        if expires_at > self.cutoff {
            true
        } else if expires_at == self.cutoff && self.ties_to_keep > 0 {
            self.ties_to_keep -= 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plan applied to one map, which is what a single-map caller does.
    fn survivors(expiries: &[u64], target: usize) -> Vec<u64> {
        let Some(mut plan) = Halving::plan(expiries.to_vec(), target) else {
            return expiries.to_vec();
        };
        expiries
            .iter()
            .copied()
            .filter(|&e| plan.keep(e))
            .collect::<Vec<_>>()
    }

    #[test]
    fn nothing_to_do_below_the_target() {
        assert!(Halving::plan(vec![1, 2, 3], 3).is_none());
        assert!(Halving::plan(vec![], 0).is_none());
    }

    #[test]
    fn the_soonest_to_expire_go_first() {
        let mut kept = survivors(&[10, 40, 20, 50, 30], 2);
        kept.sort_unstable();
        assert_eq!(kept, vec![40, 50]);
    }

    /// A cache filled in one burst at one TTL. A strict `>` comparison drops
    /// every entry here; the count has to land on the target however they tie.
    #[test]
    fn all_expiries_equal_lands_on_the_target() {
        assert_eq!(survivors(&[100; 9], 4).len(), 4);
        assert_eq!(survivors(&[100; 9], 0).len(), 0);
    }

    /// `--cache-size 1`: the target is zero and the old arithmetic asked
    /// `select_nth_unstable` for an index one past the end.
    #[test]
    fn a_target_of_zero_empties_rather_than_panicking() {
        assert_eq!(survivors(&[7], 0), Vec::<u64>::new());
        assert_eq!(survivors(&[1, 2, 3], 0), Vec::<u64>::new());
    }
}
