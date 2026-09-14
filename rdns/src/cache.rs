//! The positive answer cache: records that exist, keyed by the question that
//! found them.
//!
//! The membership rule is that there is something to store. A "no" has no records
//! to key on and takes its TTL from the SOA rather than from itself, so it is
//! [`crate::negative_cache`]; a *validated* denial covers names nobody has asked
//! about yet and is searched by range, so it is [`crate::nsec_cache`]. Three
//! caches because a lookup in each asks a different question, not because one
//! grew too large.
//!
//! Two invariants this file owns, both of which have been got wrong here or in a
//! sibling:
//!
//! - **`secure` is what validation concluded**, never what the cache assumed. It
//!   is the AD bit surviving the cache, so an answer stored as validated tells
//!   every later client it was authentic.
//! - **The TTL is the shortest in the RRset, capped at a day** (RFC 8767 §4), and
//!   not clamped here: [`crate::Ttl`] clamps at the parse boundary, which is the
//!   only place a negative wire TTL can be stopped from widening to `u64::MAX`
//!   and winning the `min` (`CLAUDE.md` §2).
//!
//! - **An entry has two lifetimes**, once serve-stale is on (RFC 8767): the TTL,
//!   after which it stops being an answer, and the stale window after that, in
//!   which it is still the last thing known and better than SERVFAIL. See
//!   [`StalePolicy`]; with no policy the two are the same instant and nothing
//!   changes.
//!
//! Eviction is `crate::eviction`, shared with the other two: one victim per
//! insert is a scan per query once a bounded cache is full.

use crate::clock::Clock;
use crate::eviction::Halving;
use crate::name_keys::{NameType, NameTypeKey};
use crate::NameRef;
use crate::Qtype;
use crate::ResourceRecord;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The longest anything is cached, whatever the record says (RFC 8767 §4).
///
/// A nonsense TTL then costs a day rather than the life of the process.
const MAX_CACHE_TTL: u64 = 86_400;

/// How long past its TTL an answer may still be served, and with what TTL on it
/// (RFC 8767, "Serving Stale Data to Improve DNS Resiliency").
///
/// One type for both caches, because the window and the TTL are one policy and
/// two copies of it would disagree (`CLAUDE.md` §7). `Copy` and eight bytes: it
/// is passed, not shared.
///
/// Off by default, which is what `max_stale` of zero means. Serving stale is a
/// deliberate decision to answer with something known to be out of date, and
/// RFC 8767 §6 is explicit that it can keep a withdrawn name alive for as long
/// as the window — so it is the operator's to turn on. BIND and Unbound both
/// default it off for the same reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StalePolicy {
    max_stale: u64,
}

/// The TTL a stale answer carries (RFC 8767 §4, recommended 30 seconds).
///
/// Not the TTL that is left — there is none — and not zero, which some clients
/// refuse to cache at all and which would make every client re-ask at once, on
/// exactly the resolution path that is already failing.
pub const STALE_ANSWER_TTL: u32 = 30;

/// How long a client waits before RFC 8767 §4's *client response timer* gives
/// it what this resolver last knew and lets the resolution finish behind it
/// (§4, recommended 1.8 seconds).
///
/// Nothing answers on this yet — `TODO.md` #58 is the feature, and the reason
/// it is a constant here first is that the number it needs is "how often would
/// this fire", which cannot be asked without a threshold to ask it about. It is
/// the bound of one latency bucket ([`crate::metrics`]) and the comparison
/// behind `dns_slow_resolutions_total`; when #58 lands it is the default of the
/// flag, in one place rather than three (`CLAUDE.md` §7).
///
/// Distinct from the *query resolution* timer, which is the one already in
/// place: that one answers from the stale window after a resolution has failed,
/// and this one answers while it is still running.
pub const CLIENT_RESPONSE_TIMER: Duration = Duration::from_millis(1800);

impl StalePolicy {
    /// Serve nothing stale. The default, and what `--serve-stale 0` means.
    pub const OFF: StalePolicy = StalePolicy { max_stale: 0 };

    /// Serve an expired answer for up to `seconds` past its TTL.
    ///
    /// RFC 8767 §4 recommends between one and three days for this "maximum
    /// stale timer": long enough to cover an outage nobody is awake for, short
    /// enough that a name really withdrawn stops being answered.
    pub const fn seconds(seconds: u64) -> StalePolicy {
        StalePolicy { max_stale: seconds }
    }

    pub const fn is_on(self) -> bool {
        self.max_stale > 0
    }

    pub const fn max_stale(self) -> u64 {
        self.max_stale
    }

    /// Whether an entry that expired at `expires_at` is still worth keeping.
    ///
    /// The one place the window is arithmetic, so no call site re-derives it.
    /// With the policy off this is exactly "has not expired", which is what
    /// makes one predicate serve both caches in both modes.
    pub(crate) fn keeps(self, expires_at: u64, now: u64) -> bool {
        expires_at.saturating_add(self.max_stale) > now
    }
}

/// The fraction of an entry's TTL that has to be left for a prefetch to fire:
/// a tenth, which is Unbound's `prefetch`.
///
/// Low enough that a name asked for once an hour never triggers one, high
/// enough that a name under steady load is refreshed before any client waits
/// for the walk.
const PREFETCH_AT: u64 = 10;

/// DNS cache entry with TTL expiration
#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<ResourceRecord>,
    expires_at: u64, // Unix timestamp
    /// What the TTL was, so "nearly expired" is a fraction of it rather than a
    /// fixed number of seconds — a minute left is nothing on a day's TTL and
    /// everything on two minutes'.
    ttl: u64,
    /// Whether this answer was DNSSEC-validated when stored. The AD bit has to
    /// survive the cache, and must never be picked up here by an answer that
    /// arrived without it.
    secure: bool,
    /// Whether a prefetch has already been handed out for this entry.
    ///
    /// Set by the lookup that hands it out, so a popular name in the last tenth
    /// of its TTL costs one refresh and not one per query — which is the whole
    /// difference between prefetching and a stampede. Not reset on failure: the
    /// entry then expires and the next query resolves the ordinary way.
    refreshing: bool,
}

impl CacheEntry {
    fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Whether less than [`PREFETCH_AT`]'s share of the TTL is left.
    fn nearly_expired(&self, now: u64) -> bool {
        self.expires_at.saturating_sub(now) <= self.ttl / PREFETCH_AT
    }
}

/// A cache hit, and what the caller may want to do about it besides answer.
#[derive(Debug, Clone)]
pub struct Cached {
    pub records: Vec<ResourceRecord>,
    /// What validation concluded when this was stored — the AD bit surviving
    /// the cache.
    pub secure: bool,
    /// The entry is in the last tenth of its TTL and no refresh has been handed
    /// out for it yet, so this caller is the one to re-resolve the name once its
    /// own answer is on its way (Unbound's `prefetch`).
    ///
    /// True at most once per entry: whoever is told carries the obligation.
    pub refresh: bool,
}

/// DNS response cache with TTL support.
///
/// Keyed by (domain_name, record_type), and *answers* only: a negative answer
/// has no records to key on and takes its TTL from the SOA, so it lives in
/// [`crate::negative_cache::NegativeCache`].
pub struct DnsCache {
    cache: Arc<Mutex<HashMap<NameTypeKey, CacheEntry>>>,
    max_entries: usize,
    stale: StalePolicy,
    /// Where "now" comes from. [`Clock::System`] everywhere but in a test, which
    /// needs one it can move: a TTL is measured in seconds, so asserting
    /// anything about expiry against the wall clock is a test that waits
    /// (`TODO.md` #52, `CLAUDE.md` §10).
    clock: Clock,
}

impl DnsCache {
    /// Create a new cache with maximum entry count
    pub fn new(max_entries: usize) -> Self {
        DnsCache {
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_entries,
            stale: StalePolicy::OFF,
            clock: Clock::system(),
        }
    }

    /// The same, holding expired entries for [`StalePolicy`]'s window and
    /// reading the time from `clock`.
    pub fn with_stale(max_entries: usize, stale: StalePolicy, clock: Clock) -> Self {
        DnsCache {
            stale,
            clock,
            ..DnsCache::new(max_entries)
        }
    }

    /// Default cache: 10,000 entries
    pub fn with_defaults() -> Self {
        Self::new(10_000)
    }

    /// Get cached records for a query (domain_name, record_type)
    pub fn get(&self, name: NameRef<'_>, qtype: Qtype) -> Option<Vec<ResourceRecord>> {
        self.get_validated(name, qtype).map(|(records, _)| records)
    }

    /// As [`DnsCache::get`], but also reporting whether the answer was
    /// DNSSEC-validated when it was stored.
    pub fn get_validated(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
    ) -> Option<(Vec<ResourceRecord>, bool)> {
        self.lookup(name, qtype, false)
            .map(|hit| (hit.records, hit.secure))
    }

    /// The whole of a cache hit: the records, what validation concluded, and
    /// whether this caller owes the name a prefetch.
    ///
    /// `prefetching` is the operator's switch, passed in rather than stored,
    /// because the cache has no opinion about it and a second copy of the
    /// setting is a second thing to get out of step (`CLAUDE.md` §7). With it
    /// false nothing is ever marked and `refresh` is always false.
    pub fn lookup(&self, name: NameRef<'_>, qtype: Qtype, prefetching: bool) -> Option<Cached> {
        let now = self.clock.now();
        // A poisoned lock reads as a cache miss. Poisoning is permanent, so
        // `.lock().unwrap()` on `rdnsr`'s query path would take the resolver off
        // the air for good after one panic; a miss costs a round trip.
        let Ok(mut cache) = self.cache.lock() else {
            return None;
        };

        // ASCII fold only (RFC 4343), and borrowed: a name that arrived
        // lower-case — most of them — is looked up as the octets it already is.
        let folded = name.folded();
        let key: &dyn NameType = &(folded.as_ref(), qtype);

        if let Some(entry) = cache.get_mut(key) {
            if !entry.is_expired(now) {
                // The flag is flipped here, under the lock the lookup already
                // holds: the caller that is told is the caller that refreshes.
                let refresh = prefetching && !entry.refreshing && entry.nearly_expired(now);
                if refresh {
                    entry.refreshing = true;
                }
                return Some(Cached {
                    records: entry.records.clone(),
                    secure: entry.secure,
                    refresh,
                });
            } else if !self.stale.keeps(entry.expires_at, now) {
                // Expired and past its stale window: nothing will ask for it
                // again. Inside the window it stays for `get_stale`.
                cache.remove(key);
            }
        }

        None
    }

    /// An answer that has expired but is still inside the stale window
    /// (RFC 8767), with [`STALE_ANSWER_TTL`] on every record.
    ///
    /// Only for the caller that has already failed to refresh it: §4 has the
    /// resolver try the authoritative servers first and serve this when that
    /// does not work, so a cache that can answer normally must not come here.
    /// `None` when the policy is off, so the check is this function's and not
    /// every call site's.
    pub fn get_stale(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
    ) -> Option<(Vec<ResourceRecord>, bool)> {
        if !self.stale.is_on() {
            return None;
        }
        let now = self.clock.now();
        let cache = self.cache.lock().ok()?;
        let folded = name.folded();
        let key: &dyn NameType = &(folded.as_ref(), qtype);
        let entry = cache
            .get(key)
            .filter(|entry| entry.is_expired(now) && self.stale.keeps(entry.expires_at, now))?;
        let records = entry
            .records
            .iter()
            .map(|rr| ResourceRecord {
                ttl: crate::Ttl::from_secs(STALE_ANSWER_TTL),
                ..rr.clone()
            })
            .collect();
        Some((records, entry.secure))
    }

    /// Put records in cache with TTL, unvalidated.
    pub fn put(&self, name: NameRef<'_>, qtype: Qtype, records: Vec<ResourceRecord>) {
        self.put_validated(name, qtype, records, false)
    }

    /// Put records in cache, remembering whether they were DNSSEC-validated.
    ///
    /// `secure` must be what validation concluded: storing an unvalidated answer
    /// as validated tells every later client it is authentic.
    pub fn put_validated(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
        records: Vec<ResourceRecord>,
        secure: bool,
    ) {
        if records.is_empty() || self.max_entries == 0 {
            return;
        }

        let now = self.clock.now();

        // An RRset is cached for the shortest TTL in it. No clamp here: `Ttl`
        // clamps at the parse boundary (RFC 2181 §8), so a negative wire TTL
        // cannot widen to `u64::MAX` and win the `min`.
        let min_ttl = records
            .iter()
            .map(|r| r.ttl.capped_at(MAX_CACHE_TTL as u32).as_u64())
            .min()
            .unwrap_or(300); // Default 5 minutes if no TTL

        // Saturating: a wrapped expiry is an entry that already expired, or one
        // that never does.
        let expires_at = now.saturating_add(min_ttl);

        // Poisoned lock: store nothing, as [`DnsCache::get_validated`].
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };

        if cache.len() >= self.max_entries {
            self.evict_oldest(&mut cache);
        }

        cache.insert(
            NameTypeKey::new(name, qtype),
            CacheEntry {
                records,
                expires_at,
                ttl: min_ttl,
                secure,
                refreshing: false,
            },
        );
    }

    /// Evict expired entries, and then the soonest-to-expire until the cache is
    /// down to half its limit.
    ///
    /// Three linear passes and one `Vec<u64>`; the halving and the reason for it
    /// are in [`crate::eviction`].
    fn evict_oldest(&self, cache: &mut HashMap<NameTypeKey, CacheEntry>) {
        let now = self.clock.now();

        // Usable, not fresh: with serve-stale on, an expired entry is still the
        // last thing known and dropping it here would make the window a lie
        // under any load that fills the cache.
        cache.retain(|_, entry| self.stale.keeps(entry.expires_at, now));

        let expiries = cache.values().map(|entry| entry.expires_at).collect();
        let Some(mut plan) = Halving::plan(expiries, self.max_entries / 2) else {
            return;
        };
        cache.retain(|_, entry| plan.keep(entry.expires_at));
    }

    /// Get cache statistics.
    ///
    /// Zeros for a poisoned lock. Misleading — it reads as an unused cache — but
    /// this feeds the metrics endpoint, where panicking costs all observability.
    pub fn get_stats(&self) -> CacheStats {
        let Ok(cache) = self.cache.lock() else {
            return CacheStats {
                total_entries: 0,
                valid_entries: 0,
                expired_entries: 0,
            };
        };
        let now = self.clock.now();

        let mut expired_count = 0;
        let mut valid_count = 0;

        for entry in cache.values() {
            if entry.is_expired(now) {
                expired_count += 1;
            } else {
                valid_count += 1;
            }
        }

        CacheStats {
            total_entries: cache.len(),
            valid_entries: valid_count,
            expired_entries: expired_count,
        }
    }

    /// Clear all cache entries.
    ///
    /// A poisoned lock is left alone; the entries expire on their own.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub valid_entries: usize,
    pub expired_entries: usize,
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::clock::current_unix_timestamp;
    use crate::record_types as rt;
    use crate::test_records::nm;
    use crate::Class;
    use crate::Ttl;
    use crate::{ParsedRecord, RecordData, ResourceRecord};
    use std::net::Ipv4Addr;

    fn create_test_record(name: &str, ttl: Ttl) -> ResourceRecord {
        ResourceRecord {
            name: nm(name),
            class: Class::new(1),
            ttl,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        }
    }

    #[test]
    fn test_cache_put_and_get() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", Ttl::from_secs(300))];

        cache.put(
            nm("example.com.").as_ref(),
            Qtype::of(rt::A),
            records.clone(),
        );

        let retrieved = cache.get(nm("example.com.").as_ref(), Qtype::of(rt::A));
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().len(), 1);
    }

    #[test]
    fn test_cache_miss() {
        let cache = DnsCache::with_defaults();

        let result = cache.get(nm("notcached.com.").as_ref(), Qtype::of(rt::A));
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_case_insensitive() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", Ttl::from_secs(300))];

        cache.put(
            nm("EXAMPLE.COM.").as_ref(),
            Qtype::of(rt::A),
            records.clone(),
        );

        let retrieved = cache.get(nm("example.com.").as_ref(), Qtype::of(rt::A));
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_cache_different_types() {
        let cache = DnsCache::with_defaults();
        let a_records = vec![create_test_record("example.com.", Ttl::from_secs(300))];
        let aaaa_records = vec![create_test_record("example.com.", Ttl::from_secs(300))];

        cache.put(nm("example.com.").as_ref(), Qtype::of(rt::A), a_records);
        cache.put(
            nm("example.com.").as_ref(),
            Qtype::of(rt::AAAA),
            aaaa_records,
        );

        assert!(cache
            .get(nm("example.com.").as_ref(), Qtype::of(rt::A))
            .is_some());
        assert!(cache
            .get(nm("example.com.").as_ref(), Qtype::of(rt::AAAA))
            .is_some());
        assert!(cache
            .get(nm("example.com.").as_ref(), Qtype::of(rt::CNAME))
            .is_none()); // CNAME not cached
    }

    #[test]
    fn test_cache_stats() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", Ttl::from_secs(300))];

        cache.put(nm("example.com.").as_ref(), Qtype::of(rt::A), records);

        let stats = cache.get_stats();
        assert!(stats.total_entries > 0);
        assert_eq!(
            stats.valid_entries,
            stats.total_entries - stats.expired_entries
        );
    }

    #[test]
    fn test_cache_clear() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", Ttl::from_secs(300))];

        cache.put(nm("example.com.").as_ref(), Qtype::of(rt::A), records);
        assert!(cache
            .get(nm("example.com.").as_ref(), Qtype::of(rt::A))
            .is_some());

        cache.clear();
        assert!(cache
            .get(nm("example.com.").as_ref(), Qtype::of(rt::A))
            .is_none());
    }

    #[test]
    fn test_cache_uses_minimum_ttl() {
        let cache = DnsCache::with_defaults();
        let records = vec![
            create_test_record("example.com.", Ttl::from_secs(300)),
            create_test_record("example.com.", Ttl::from_secs(100)), // Lower TTL
        ];

        cache.put(nm("example.com.").as_ref(), Qtype::of(rt::A), records);

        let retrieved = cache.get(nm("example.com.").as_ref(), Qtype::of(rt::A));
        assert!(retrieved.is_some()); // Still valid within 100 seconds
    }

    /// A TTL with the high bit set parses negative; widened it is `u64::MAX` and
    /// wins the `min`, pinning the entry forever. RFC 2181 §8: treat it as zero.
    #[test]
    fn a_negative_ttl_does_not_pin_an_entry_forever() {
        for ttl in [-1, i32::MIN, -3600] {
            let cache = DnsCache::with_defaults();
            cache.put(
                nm("example.com.").as_ref(),
                Qtype::of(rt::A),
                vec![create_test_record("example.com.", Ttl::from_wire(ttl))],
            );
            assert!(
                cache
                    .get(nm("example.com.").as_ref(), Qtype::of(rt::A))
                    .is_none(),
                "a TTL of {ttl} means zero seconds, not forever"
            );
        }
    }

    /// An absurd TTL is capped, not honoured: `i32::MAX` seconds is 68 years.
    #[test]
    fn an_absurd_ttl_is_capped() {
        let cache = DnsCache::with_defaults();
        cache.put(
            nm("example.com.").as_ref(),
            Qtype::of(rt::A),
            vec![create_test_record("example.com.", Ttl::from_wire(i32::MAX))],
        );
        let expires_at = cache.cache.lock().unwrap()
            [&NameTypeKey::new(nm("example.com.").as_ref(), Qtype::of(rt::A))]
            .expires_at;
        assert!(
            expires_at <= current_unix_timestamp() + MAX_CACHE_TTL,
            "an entry may not outlive the ceiling"
        );
    }

    /// A name and the same name without its trailing dot are one name, so they
    /// are one entry — which they were not while the key was `ascii_lowered`,
    /// the one fold in this crate that does not absolutize (`TODO.md` #25e).
    #[test]
    fn the_trailing_dot_does_not_make_a_second_entry() {
        let cache = DnsCache::with_defaults();
        cache.put(
            nm("example.com.").as_ref(),
            Qtype::of(rt::A),
            vec![create_test_record("example.com.", Ttl::from_secs(3600))],
        );
        assert!(
            cache
                .get(nm("example.com").as_ref(), Qtype::of(rt::A))
                .is_some(),
            "the relative spelling of a name we hold must hit"
        );
        assert_eq!(cache.get_stats().total_entries, 1);
    }

    /// DNS folds case over ASCII only (RFC 4343). U+212A KELVIN SIGN lowercases
    /// to `k` under Unicode, which would merge two owner names into one entry.
    #[test]
    fn distinct_names_that_unicode_would_fold_together_stay_distinct() {
        let cache = DnsCache::with_defaults();
        let kelvin = nm("\u{212A}.example.com.");
        cache.put(
            kelvin.as_ref(),
            Qtype::of(rt::A),
            vec![create_test_record(&kelvin.to_string(), Ttl::from_secs(300))],
        );

        assert!(
            cache.get(kelvin.as_ref(), Qtype::of(rt::A)).is_some(),
            "its own name still finds it"
        );
        assert!(
            cache
                .get(nm("k.example.com.").as_ref(), Qtype::of(rt::A))
                .is_none(),
            "a different owner name must not share the entry"
        );
    }

    /// A cache whose clock the test moves, so expiry is asserted rather than
    /// waited for (`TODO.md` #52): a TTL is whole seconds, and every other way
    /// of reaching one is a sleep or a zero.
    fn fixed_cache(max_entries: usize, stale: StalePolicy) -> (DnsCache, Clock) {
        let clock = Clock::fixed(1_000_000_000);
        (
            DnsCache::with_stale(max_entries, stale, clock.clone()),
            clock,
        )
    }

    fn put_a(cache: &DnsCache, name: &str, ttl: u32) {
        cache.put(
            nm(name).as_ref(),
            Qtype::of(rt::A),
            vec![create_test_record(name, Ttl::from_secs(ttl))],
        );
    }

    /// The window is one piece of arithmetic and both caches read it, so its
    /// two edges are asserted directly.
    #[test]
    fn the_stale_window_ends_exactly_where_it_says() {
        let policy = StalePolicy::seconds(3600);
        assert!(
            policy.keeps(1_000, 1_000),
            "expired this second, still usable"
        );
        assert!(policy.keeps(1_000, 1_000 + 3599));
        assert!(
            !policy.keeps(1_000, 1_000 + 3600),
            "a window of an hour ends an hour after the TTL did"
        );
        assert!(
            !StalePolicy::OFF.keeps(1_000, 1_000),
            "with the policy off, usable and unexpired are the same thing"
        );
        // A window past the end of time must not wrap into the past.
        assert!(StalePolicy::seconds(u64::MAX).keeps(1_000, u64::MAX - 1));
    }

    /// RFC 8767 §4: an expired answer is not an answer — the resolver tries the
    /// authoritative servers first — so `get` must still miss. It is `get_stale`
    /// that hands it over, and only to a caller that has already failed.
    #[test]
    fn an_expired_entry_is_a_miss_and_a_stale_hit() {
        let (cache, clock) = fixed_cache(16, StalePolicy::seconds(3600));
        put_a(&cache, "example.com.", 300);
        clock.advance(301);

        assert!(
            cache
                .get(nm("example.com.").as_ref(), Qtype::of(rt::A))
                .is_none(),
            "an expired entry is not an answer"
        );
        let (records, secure) = cache
            .get_stale(nm("example.com.").as_ref(), Qtype::of(rt::A))
            .expect("but it is still the last thing known");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].ttl.as_secs(),
            STALE_ANSWER_TTL,
            "the TTL a stale answer carries is chosen, not counted down (§4)"
        );
        assert!(!secure, "and AD is what validation concluded, unchanged");

        // Past the window it is gone, and the lookup that finds it says so.
        clock.advance(3600);
        assert!(cache
            .get_stale(nm("example.com.").as_ref(), Qtype::of(rt::A))
            .is_none());
    }

    /// With the policy off nothing is stale, and the expired entry is dropped on
    /// the lookup that found it — which is what the cache did before RFC 8767
    /// and must still do.
    #[test]
    fn with_the_policy_off_an_expired_entry_is_dropped_on_lookup() {
        let (cache, clock) = fixed_cache(16, StalePolicy::OFF);
        put_a(&cache, "example.com.", 300);
        clock.advance(301);
        assert_eq!(cache.get_stats().total_entries, 1);
        assert!(cache
            .get(nm("example.com.").as_ref(), Qtype::of(rt::A))
            .is_none());
        assert_eq!(
            cache.get_stats().total_entries,
            0,
            "nothing will ask for it again"
        );
        assert!(cache
            .get_stale(nm("example.com.").as_ref(), Qtype::of(rt::A))
            .is_none());
    }

    /// The lookup keeps it, and so must eviction: a window the cache empties
    /// under load is a window only a quiet resolver has.
    ///
    /// Eleven entries into a cache of ten, all of them expired and all inside
    /// the window, so the one insert that triggers eviction has to halve rather
    /// than sweep. Watched failing against `retain(|_, e| !e.is_expired(now))`:
    /// **1** entry survived, being the one that arrived after the sweep.
    #[test]
    fn eviction_keeps_what_is_still_inside_the_stale_window() {
        let (cache, clock) = fixed_cache(10, StalePolicy::seconds(3600));
        for i in 0..10 {
            put_a(&cache, &format!("example{i}.com."), 300);
        }
        clock.advance(301);
        put_a(&cache, "eleventh.example.com.", 300);

        let held = cache.get_stats().total_entries;
        assert!(
            held >= 5,
            "halved to five and one more inserted, not swept: {held} survived"
        );
        assert!(held <= 10, "still bounded, got {held}");
    }

    /// The prefetch obligation is handed to exactly one caller (Unbound's
    /// `prefetch`, at a tenth of the TTL). Handing it to every caller is the
    /// difference between refreshing a popular name and stampeding it.
    #[test]
    fn a_prefetch_is_offered_once_per_entry() {
        let (cache, clock) = fixed_cache(16, StalePolicy::OFF);
        put_a(&cache, "hot.example.com.", 100);
        clock.advance(95);

        let first = cache
            .lookup(nm("hot.example.com.").as_ref(), Qtype::of(rt::A), true)
            .expect("still a hit");
        assert!(first.refresh, "five seconds left of a hundred");
        let second = cache
            .lookup(nm("hot.example.com.").as_ref(), Qtype::of(rt::A), true)
            .expect("still a hit");
        assert!(
            !second.refresh,
            "the second client in the same tenth must not start a second walk"
        );
    }

    #[test]
    fn an_entry_with_life_left_is_not_prefetched() {
        let (cache, clock) = fixed_cache(16, StalePolicy::OFF);
        put_a(&cache, "cold.example.com.", 100);
        clock.advance(10);
        let hit = cache
            .lookup(nm("cold.example.com.").as_ref(), Qtype::of(rt::A), true)
            .expect("a hit");
        assert!(!hit.refresh, "ninety seconds left of a hundred");
    }

    /// Off means off, and it must also leave the entry unmarked: a resolver
    /// restarted with the switch on would otherwise find its whole cache
    /// already claimed.
    #[test]
    fn with_prefetching_off_nothing_is_offered_or_marked() {
        let (cache, clock) = fixed_cache(16, StalePolicy::OFF);
        put_a(&cache, "hot.example.com.", 100);
        clock.advance(95);
        assert!(
            !cache
                .lookup(nm("hot.example.com.").as_ref(), Qtype::of(rt::A), false)
                .expect("a hit")
                .refresh
        );
        assert!(
            cache
                .lookup(nm("hot.example.com.").as_ref(), Qtype::of(rt::A), true)
                .expect("a hit")
                .refresh,
            "and the entry was left unclaimed"
        );
    }

    #[test]
    fn test_cache_capacity() {
        let cache = DnsCache::new(10);

        for i in 0..20 {
            let name = format!("example{}.com.", i);
            let records = vec![create_test_record(&name, Ttl::from_secs(300))];
            cache.put(nm(&name).as_ref(), Qtype::of(rt::A), records);
        }

        let stats = cache.get_stats();
        assert!(stats.total_entries <= 10, "cache exceeded max capacity");
    }

    /// Expiries are whole seconds, so a cache filled in one burst at one TTL has
    /// every entry on the same `expires_at` and a strict comparison empties it
    /// instead of halving it.
    ///
    /// Fails against the naive rewrite (1 of 100 survives), not against a
    /// quadratic eviction, which gets ties right one entry at a time.
    #[test]
    fn evicting_a_cache_whose_entries_all_expire_together_halves_it() {
        let cache = DnsCache::new(100);
        for i in 0..101 {
            let name = format!("example{i}.com.");
            cache.put(
                nm(&name).as_ref(),
                Qtype::of(rt::A),
                vec![create_test_record(&name, Ttl::from_secs(300))],
            );
        }

        let total = cache.get_stats().total_entries;
        assert!(total <= 100, "still bounded, got {total}");
        assert!(
            total >= 50,
            "half the cache is the eviction policy; {total} entries survived, \
             so the tie on expires_at swept entries it was not asked to"
        );
    }

    /// A panic under the cache mutex costs the cache, not the process: poisoning
    /// is permanent, so `.lock().unwrap()` on the query path would make every
    /// later query panic too.
    #[test]
    fn a_poisoned_lock_costs_the_cache_and_not_the_process() {
        let cache = DnsCache::with_defaults();
        cache.put(
            nm("example.com.").as_ref(),
            Qtype::of(rt::A),
            vec![create_test_record("example.com.", Ttl::from_secs(300))],
        );
        assert!(
            cache
                .get(nm("example.com.").as_ref(), Qtype::of(rt::A))
                .is_some(),
            "cached to begin with"
        );

        let guarded = Arc::clone(&cache.cache);
        let panicked = std::thread::spawn(move || {
            let _held = guarded.lock().expect("not poisoned yet");
            panic!("a panic under the cache lock");
        })
        .join();
        assert!(panicked.is_err(), "the thread did panic");
        assert!(cache.cache.lock().is_err(), "so the mutex is poisoned");

        assert!(
            cache
                .get(nm("example.com.").as_ref(), Qtype::of(rt::A))
                .is_none(),
            "a poisoned cache reads as a miss"
        );
        cache.put(
            nm("other.example.com.").as_ref(),
            Qtype::of(rt::A),
            vec![create_test_record(
                "other.example.com.",
                Ttl::from_secs(300),
            )],
        );
        assert_eq!(
            cache.get_stats().total_entries,
            0,
            "and reports nothing rather than panicking in the metrics endpoint"
        );
        cache.clear();
    }

    /// `--cache-size 1` halves to a target of zero, and the arithmetic asked
    /// `select_nth_unstable` for an index one past the end: a panic on the
    /// second answer cached, holding the lock, which poisons it — after which
    /// every `get` and `put` is a silent no-op for the life of the process
    /// (`CLAUDE.md` §6). Found by moving the halving into [`crate::eviction`].
    #[test]
    fn a_cache_of_one_evicts_rather_than_panicking() {
        let cache = DnsCache::new(1);
        for name in ["a.example.com.", "b.example.com."] {
            cache.put(
                nm(name).as_ref(),
                Qtype::of(rt::A),
                vec![create_test_record(name, Ttl::from_secs(300))],
            );
        }
        assert_eq!(cache.get_stats().total_entries, 1);
        assert!(cache
            .get(nm("b.example.com.").as_ref(), Qtype::of(rt::A))
            .is_some());
    }

    /// A ceiling, not a floor: this measures ~0.2 s in a debug build, where a
    /// quadratic eviction takes tens of seconds at 20k entries.
    #[test]
    fn evicting_a_large_cache_is_linear_not_quadratic() {
        use std::time::Instant;

        let cache = DnsCache::new(20_000);
        let start = Instant::now();
        // Past the bound and then some, so eviction runs more than once.
        for i in 0..40_000 {
            let name = format!("example{i}.com.");
            cache.put(
                nm(&name).as_ref(),
                Qtype::of(rt::A),
                vec![create_test_record(&name, Ttl::from_secs(300))],
            );
        }
        let elapsed = start.elapsed();

        assert!(cache.get_stats().total_entries <= 20_000);
        assert!(
            elapsed.as_secs_f64() < 5.0,
            "filling a 20k cache twice over took {elapsed:?}; eviction is \
             scaling with the cache size again"
        );
    }
}
