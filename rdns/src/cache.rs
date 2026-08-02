use crate::utils::{ascii_lowered, current_unix_timestamp};
use crate::Qtype;
use crate::ResourceRecord;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The longest anything is cached, whatever the record says.
///
/// RFC 8767 §4 suggests a day as the ceiling, and the reason to have one at all
/// is that a TTL is a promise about how long an answer stays *correct*, made by
/// whoever wrote the zone — and a wrong one is how a stale answer outlives the
/// fix. It is also the second line of defence behind the clamp below: a bug that
/// lets a nonsense TTL through can then cost a day rather than the life of the
/// process.
const MAX_CACHE_TTL: u64 = 86_400;

/// DNS cache entry with TTL expiration
#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<ResourceRecord>,
    expires_at: u64, // Unix timestamp
    /// Whether this answer was DNSSEC-validated when it was stored.
    ///
    /// Cached alongside the records because the AD bit has to survive the
    /// cache: an answer served from here is the same answer, and dropping the
    /// flag would make the first client see AD and every later one not. The
    /// converse matters more — an unvalidated answer must never pick the bit up
    /// on its way back out.
    secure: bool,
}

impl CacheEntry {
    fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// DNS response cache with TTL support.
///
/// Caches responses keyed by (domain_name, record_type) — *answers* only. A
/// negative answer has no records to key on and takes its TTL from the SOA
/// instead, so it lives in [`crate::negative_cache::NegativeCache`]. There used
/// to be a `put_negative` here that stored an empty entry under type 0; it
/// recorded neither the rcode nor the SOA, could not tell NXDOMAIN from NODATA,
/// and nothing ever called it.
pub struct DnsCache {
    cache: Arc<Mutex<HashMap<(String, Qtype), CacheEntry>>>,
    max_entries: usize,
}

impl DnsCache {
    /// Create a new cache with maximum entry count
    pub fn new(max_entries: usize) -> Self {
        DnsCache {
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_entries,
        }
    }

    /// Default cache: 10,000 entries
    pub fn with_defaults() -> Self {
        Self::new(10_000)
    }

    /// Get cached records for a query (domain_name, record_type)
    pub fn get(&self, name: &str, qtype: Qtype) -> Option<Vec<ResourceRecord>> {
        self.get_validated(name, qtype).map(|(records, _)| records)
    }

    /// As [`DnsCache::get`], but also reporting whether the answer was
    /// DNSSEC-validated when it was stored.
    pub fn get_validated(&self, name: &str, qtype: Qtype) -> Option<(Vec<ResourceRecord>, bool)> {
        let now = current_unix_timestamp();
        // A poisoned lock reads as a cache miss (`CLAUDE.md` §6, §4). This is on
        // `rdnsr`'s query path, and `.lock().unwrap()` here meant that one panic
        // anywhere under this mutex — ever — would make every later query panic
        // too, because poisoning is permanent: a resolver taken off the air by a
        // fault it had already survived. Degrading is the right failure for a
        // cache and only a cache; the missing state costs a round trip and
        // nothing else, which is exactly what §4 says a cache may do and a
        // last-contact time may not.
        let Ok(mut cache) = self.cache.lock() else {
            return None;
        };

        // ASCII case folding, not Unicode. DNS is case-insensitive over ASCII
        // and nothing else (RFC 4343), and `str::to_lowercase` applies the full
        // Unicode mapping — which folds codepoints *into* ASCII. U+212A KELVIN
        // SIGN lowercases to `k`, so it and `k.example.com.` shared one entry:
        // two different owner names, different bytes on the wire, one cache
        // slot. `zone.rs` had the comment explaining this and the cache drifted
        // from it, so the helper now lives in `utils` where both reach it.
        let key = (ascii_lowered(name), qtype);

        // Check if entry exists and is not expired
        if let Some(entry) = cache.get(&key) {
            if !entry.is_expired(now) {
                return Some((entry.records.clone(), entry.secure));
            } else {
                // Remove expired entry
                cache.remove(&key);
            }
        }

        None
    }

    /// Put records in cache with TTL, unvalidated.
    pub fn put(&self, name: &str, qtype: Qtype, records: Vec<ResourceRecord>) {
        self.put_validated(name, qtype, records, false)
    }

    /// Put records in cache, remembering whether they were DNSSEC-validated.
    ///
    /// `secure` must be what validation actually concluded. Storing an answer
    /// as validated that was not is the one mistake a cache can make that
    /// outlives the query: every later client is told the data is authentic on
    /// the strength of a check that never happened.
    pub fn put_validated(
        &self,
        name: &str,
        qtype: Qtype,
        records: Vec<ResourceRecord>,
        secure: bool,
    ) {
        if records.is_empty() || self.max_entries == 0 {
            return;
        }

        let now = current_unix_timestamp();

        // An RRset is cached for the shortest TTL in it, and every step of
        // getting there is a place this went wrong.
        //
        // `ResourceRecord::ttl` used to be an `i32` straight off the wire, so a
        // TTL with the high bit set parsed *negative*. `-1 as u64` is
        // `u64::MAX`, `min` then picked it as the smallest, and `is_expired` was
        // false for the life of the process: an entry pinned forever, immune to
        // the re-query that would otherwise correct it. Poison one answer and it
        // stays poisoned until the daemon restarts.
        //
        // It is a [`Ttl`] now, clamped by `Ttl::from_wire` where the bytes are
        // read (RFC 2181 §8), so this site no longer clamps and no longer can
        // forget to. That is the point of the type: `negative_cache` and
        // `nsec_cache` already clamped, this cache and the two `rr.ttl.max(0)`
        // sites in `resolver` that write into it did not agree about whose job
        // it was, and a check that existed three times over was still missing in
        // one place (`TODO.md` #13d, `CLAUDE.md` §2).
        let min_ttl = records
            .iter()
            .map(|r| r.ttl.capped_at(MAX_CACHE_TTL as u32).as_u64())
            .min()
            .unwrap_or(300); // Default 5 minutes if no TTL

        // Saturating because `now + ttl` on a clock far in the future is a debug
        // panic and a release wrap, and a wrapped expiry is an entry that has
        // already expired — or never does.
        let expires_at = now.saturating_add(min_ttl);

        // And the write side degrades the same way: nothing is stored, the next
        // client asks upstream again. See [`DnsCache::get_validated`].
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };

        // Evict oldest entries if cache is full
        if cache.len() >= self.max_entries {
            self.evict_oldest(&mut cache);
        }

        let key = (ascii_lowered(name), qtype);
        cache.insert(
            key,
            CacheEntry {
                records,
                expires_at,
                secure,
            },
        );
    }

    /// Evict expired entries, and then the soonest-to-expire until the cache is
    /// down to half its limit.
    ///
    /// Three passes over the map and one `Vec<u64>`, all linear. It used to be a
    /// `while` loop calling `min_by_key` over the *whole* map to find one victim
    /// and `clone()` its `String` key to remove it — O(n²) with an allocation
    /// per removal, under the global cache lock, with every reader blocked for
    /// the duration. At the default `max_entries = 10_000` that is ~37 million
    /// `HashMap` iterations and 5,000 `String` allocations in one uninterruptible
    /// stall, repeated every time the cache refilled.
    ///
    /// The policy is unchanged — keep the entries with the most life left — so
    /// this is a rewrite of how, not of what.
    fn evict_oldest(&self, cache: &mut HashMap<(String, Qtype), CacheEntry>) {
        let now = current_unix_timestamp();

        // First remove all expired entries
        cache.retain(|_, entry| !entry.is_expired(now));

        let target = self.max_entries / 2;
        if cache.len() <= target {
            return;
        }

        // `select_nth_unstable` partitions in O(n) average without sorting: the
        // element at `remove` lands where it would be in sorted order, and
        // everything before it is no greater. That value is the eviction
        // boundary, and it is a *value*, so no key is cloned to find it.
        let mut expiries: Vec<u64> = cache.values().map(|entry| entry.expires_at).collect();
        let remove = expiries.len() - target;
        let (_, &mut cutoff, _) = expiries.select_nth_unstable(remove);

        // Ties are the case that matters and the reason this is not a plain
        // `retain(|e| e.expires_at > cutoff)`. Expiries are whole seconds, so a
        // cache filled in one burst at one TTL has *every* entry on the same
        // value — and a strict comparison would then evict the entire cache
        // rather than half of it, turning a bounded cache into no cache. Keep
        // entries strictly past the boundary, then admit ties until the target
        // is met, which lands on exactly `target` entries however they tie.
        let strictly_newer = expiries.iter().filter(|&&e| e > cutoff).count();
        let mut ties_to_keep = target.saturating_sub(strictly_newer);
        cache.retain(|_, entry| {
            if entry.expires_at > cutoff {
                true
            } else if entry.expires_at == cutoff && ties_to_keep > 0 {
                ties_to_keep -= 1;
                true
            } else {
                false
            }
        });
    }

    /// Get cache statistics
    ///
    /// Zeros for a poisoned lock, and this is the one place in the file where
    /// that could mislead — a cache reporting no entries looks like a cache that
    /// is not being used. It is still better than the alternative: this is read
    /// by the metrics endpoint, and panicking there turns a cache that failed
    /// once into a server with no observability at all, at the exact moment an
    /// operator needs some.
    pub fn get_stats(&self) -> CacheStats {
        let Ok(cache) = self.cache.lock() else {
            return CacheStats {
                total_entries: 0,
                valid_entries: 0,
                expired_entries: 0,
            };
        };
        let now = current_unix_timestamp();

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

    /// Clear all cache entries
    ///
    /// A poisoned lock is left alone: there is nothing to clear that a caller
    /// could then rely on being clear, and the entries expire on their own.
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
    use crate::utils::record_types as rt;
    use crate::Class;
    use crate::Ttl;
    use crate::{ParsedRecord, RecordData, ResourceRecord};
    use std::net::Ipv4Addr;

    fn create_test_record(name: &str, ttl: Ttl) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            class: Class::new(1),
            ttl,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        }
    }

    #[test]
    fn test_cache_put_and_get() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", Ttl::from_secs(300))];

        cache.put("example.com.", Qtype::of(rt::A), records.clone());

        let retrieved = cache.get("example.com.", Qtype::of(rt::A));
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().len(), 1);
    }

    #[test]
    fn test_cache_miss() {
        let cache = DnsCache::with_defaults();

        let result = cache.get("notcached.com.", Qtype::of(rt::A));
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_case_insensitive() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", Ttl::from_secs(300))];

        cache.put("EXAMPLE.COM.", Qtype::of(rt::A), records.clone());

        let retrieved = cache.get("example.com.", Qtype::of(rt::A));
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_cache_different_types() {
        let cache = DnsCache::with_defaults();
        let a_records = vec![create_test_record("example.com.", Ttl::from_secs(300))];
        let aaaa_records = vec![create_test_record("example.com.", Ttl::from_secs(300))];

        cache.put("example.com.", Qtype::of(rt::A), a_records);
        cache.put("example.com.", Qtype::of(rt::AAAA), aaaa_records);

        assert!(cache.get("example.com.", Qtype::of(rt::A)).is_some());
        assert!(cache.get("example.com.", Qtype::of(rt::AAAA)).is_some());
        assert!(cache.get("example.com.", Qtype::of(rt::CNAME)).is_none()); // CNAME not cached
    }

    #[test]
    fn test_cache_stats() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", Ttl::from_secs(300))];

        cache.put("example.com.", Qtype::of(rt::A), records);

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

        cache.put("example.com.", Qtype::of(rt::A), records);
        assert!(cache.get("example.com.", Qtype::of(rt::A)).is_some());

        cache.clear();
        assert!(cache.get("example.com.", Qtype::of(rt::A)).is_none());
    }

    #[test]
    fn test_cache_uses_minimum_ttl() {
        let cache = DnsCache::with_defaults();
        let records = vec![
            create_test_record("example.com.", Ttl::from_secs(300)),
            create_test_record("example.com.", Ttl::from_secs(100)), // Lower TTL
        ];

        cache.put("example.com.", Qtype::of(rt::A), records);

        let retrieved = cache.get("example.com.", Qtype::of(rt::A));
        assert!(retrieved.is_some()); // Still valid within 100 seconds
    }

    /// A TTL with the high bit set parses negative off the wire, and the widening
    /// to `u64` used to sign-extend it into `u64::MAX` — an entry that never
    /// expires, in a cache that exists so answers *do*. RFC 2181 §8: treat it as
    /// zero.
    ///
    /// Written as an expiry check rather than by reading the private field,
    /// because "never expires" is the bug and the field is only how it happened.
    #[test]
    fn a_negative_ttl_does_not_pin_an_entry_forever() {
        for ttl in [-1, i32::MIN, -3600] {
            let cache = DnsCache::with_defaults();
            cache.put(
                "example.com.",
                Qtype::of(rt::A),
                vec![create_test_record("example.com.", Ttl::from_wire(ttl))],
            );
            assert!(
                cache.get("example.com.", Qtype::of(rt::A)).is_none(),
                "a TTL of {ttl} means zero seconds, not forever"
            );
        }
    }

    /// And a TTL nobody should be believed about is capped rather than honoured.
    /// `i32::MAX` seconds is 68 years.
    #[test]
    fn an_absurd_ttl_is_capped() {
        let cache = DnsCache::with_defaults();
        cache.put(
            "example.com.",
            Qtype::of(rt::A),
            vec![create_test_record("example.com.", Ttl::from_wire(i32::MAX))],
        );
        let expires_at =
            cache.cache.lock().unwrap()[&("example.com.".to_string(), Qtype::of(rt::A))].expires_at;
        assert!(
            expires_at <= current_unix_timestamp() + MAX_CACHE_TTL,
            "an entry may not outlive the ceiling"
        );
    }

    /// DNS folds case over ASCII and nothing else (RFC 4343). U+212A KELVIN SIGN
    /// lowercases to `k` under Unicode rules, so a Unicode-folded key merged two
    /// names that are different bytes on the wire into one cache entry — and the
    /// second name's owner then answered for the first.
    #[test]
    fn distinct_names_that_unicode_would_fold_together_stay_distinct() {
        let cache = DnsCache::with_defaults();
        let kelvin = "\u{212A}.example.com.";
        cache.put(
            kelvin,
            Qtype::of(rt::A),
            vec![create_test_record(kelvin, Ttl::from_secs(300))],
        );

        assert!(
            cache.get(kelvin, Qtype::of(rt::A)).is_some(),
            "its own name still finds it"
        );
        assert!(
            cache.get("k.example.com.", Qtype::of(rt::A)).is_none(),
            "a different owner name must not share the entry"
        );
    }

    #[test]
    fn test_cache_capacity() {
        let cache = DnsCache::new(10);

        // Fill cache beyond capacity
        for i in 0..20 {
            let name = format!("example{}.com.", i);
            let records = vec![create_test_record(&name, Ttl::from_secs(300))];
            cache.put(&name, Qtype::of(rt::A), records);
        }

        let stats = cache.get_stats();
        assert!(stats.total_entries <= 10, "cache exceeded max capacity");
    }

    /// The case the one-line version of this eviction gets wrong. Expiries are
    /// whole seconds, so a cache filled in a burst at a single TTL — which is
    /// what a resolver warming up actually looks like — has **every** entry on
    /// the same `expires_at`. Evicting "everything not strictly newer than the
    /// boundary" then empties the entire cache instead of halving it, and the
    /// server does it again on the next fill: a bounded cache that is really no
    /// cache, with nothing to see but a miss rate.
    ///
    /// Note what this test is and is not: it fails against the *naive* rewrite
    /// (1 of 100 entries survives), not against the old quadratic, which got
    /// ties right by removing one entry at a time. It guards the fix, not the
    /// bug — the regression test for the bug is the one below.
    #[test]
    fn evicting_a_cache_whose_entries_all_expire_together_halves_it() {
        let cache = DnsCache::new(100);
        for i in 0..101 {
            let name = format!("example{i}.com.");
            cache.put(
                &name,
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

    /// Eviction used to re-scan the whole map with `min_by_key` to find **one**
    /// victim and clone its `String` key to remove it, looping until half the
    /// entries were gone: O(n²) plus an allocation per removal, under the global
    /// cache lock with every reader blocked, repeated each time the cache
    /// refilled. At the default of 10,000 entries that is ~37 million `HashMap`
    /// iterations per stall.
    ///
    /// A ceiling rather than a floor, and a very loose one: this measures ~0.2 s
    /// in a debug build, so five seconds is more than the factor of ten of
    /// headroom `CLAUDE.md` §10 asks for and still nowhere near the tens of
    /// seconds the quadratic needs at this size. `bench_cache_throughput` cannot
    /// see any of this — it only ever calls `get` on an empty cache.
    /// A panic under the cache mutex must cost the cache, not the process.
    ///
    /// `.lock().unwrap()` was on all four of this type's lock sites, two of them
    /// on `rdnsr`'s query path — and mutex poisoning is *permanent*, so one
    /// panic under that lock, ever, would have made every later query panic as
    /// well. A resolver taken off the air by a fault it had already survived,
    /// which is `CLAUDE.md` §6's "one reachable panic under a shared lock takes
    /// the whole process off the air permanently".
    ///
    /// Degrading is what a cache may do (§4): the answers are gone, the next
    /// client pays a round trip, and the process keeps serving. Against the old
    /// code every assertion below panics instead of failing.
    #[test]
    fn a_poisoned_lock_costs_the_cache_and_not_the_process() {
        let cache = DnsCache::with_defaults();
        cache.put(
            "example.com.",
            Qtype::of(rt::A),
            vec![create_test_record("example.com.", Ttl::from_secs(300))],
        );
        assert!(
            cache.get("example.com.", Qtype::of(rt::A)).is_some(),
            "cached to begin with"
        );

        // Poison it the only way a mutex is poisoned: panic while holding it.
        let guarded = Arc::clone(&cache.cache);
        let panicked = std::thread::spawn(move || {
            let _held = guarded.lock().expect("not poisoned yet");
            panic!("a panic under the cache lock");
        })
        .join();
        assert!(panicked.is_err(), "the thread did panic");
        assert!(cache.cache.lock().is_err(), "so the mutex is poisoned");

        assert!(
            cache.get("example.com.", Qtype::of(rt::A)).is_none(),
            "a poisoned cache reads as a miss"
        );
        cache.put(
            "other.example.com.",
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

    #[test]
    fn evicting_a_large_cache_is_linear_not_quadratic() {
        use std::time::Instant;

        let cache = DnsCache::new(20_000);
        let start = Instant::now();
        // Past the bound and then some, so eviction runs more than once.
        for i in 0..40_000 {
            let name = format!("example{i}.com.");
            cache.put(
                &name,
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
