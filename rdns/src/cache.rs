use crate::eviction::Halving;
use crate::utils::{absolute_lowered, current_unix_timestamp, NameType, NameTypeKey};
use crate::Qtype;
use crate::ResourceRecord;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The longest anything is cached, whatever the record says (RFC 8767 §4).
///
/// A nonsense TTL then costs a day rather than the life of the process.
const MAX_CACHE_TTL: u64 = 86_400;

/// DNS cache entry with TTL expiration
#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<ResourceRecord>,
    expires_at: u64, // Unix timestamp
    /// Whether this answer was DNSSEC-validated when stored. The AD bit has to
    /// survive the cache, and must never be picked up here by an answer that
    /// arrived without it.
    secure: bool,
}

impl CacheEntry {
    fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// DNS response cache with TTL support.
///
/// Keyed by (domain_name, record_type), and *answers* only: a negative answer
/// has no records to key on and takes its TTL from the SOA, so it lives in
/// [`crate::negative_cache::NegativeCache`].
pub struct DnsCache {
    cache: Arc<Mutex<HashMap<NameTypeKey, CacheEntry>>>,
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
        // A poisoned lock reads as a cache miss. Poisoning is permanent, so
        // `.lock().unwrap()` on `rdnsr`'s query path would take the resolver off
        // the air for good after one panic; a miss costs a round trip.
        let Ok(mut cache) = self.cache.lock() else {
            return None;
        };

        // ASCII fold only (RFC 4343): `str::to_lowercase` folds U+212A KELVIN
        // SIGN to `k`, merging two names that differ on the wire. Borrowed, so
        // a lookup allocates only when the name was not already in key form.
        let folded = absolute_lowered(name);
        let key: &dyn NameType = &(folded.as_ref(), qtype);

        if let Some(entry) = cache.get(key) {
            if !entry.is_expired(now) {
                return Some((entry.records.clone(), entry.secure));
            } else {
                cache.remove(key);
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
    /// `secure` must be what validation concluded: storing an unvalidated answer
    /// as validated tells every later client it is authentic.
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
                secure,
            },
        );
    }

    /// Evict expired entries, and then the soonest-to-expire until the cache is
    /// down to half its limit.
    ///
    /// Three linear passes and one `Vec<u64>`; the halving and the reason for it
    /// are in [`crate::eviction`].
    fn evict_oldest(&self, cache: &mut HashMap<NameTypeKey, CacheEntry>) {
        let now = current_unix_timestamp();

        cache.retain(|_, entry| !entry.is_expired(now));

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
    use crate::test_records::nm;
    use crate::utils::record_types as rt;
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

    /// A TTL with the high bit set parses negative; widened it is `u64::MAX` and
    /// wins the `min`, pinning the entry forever. RFC 2181 §8: treat it as zero.
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

    /// An absurd TTL is capped, not honoured: `i32::MAX` seconds is 68 years.
    #[test]
    fn an_absurd_ttl_is_capped() {
        let cache = DnsCache::with_defaults();
        cache.put(
            "example.com.",
            Qtype::of(rt::A),
            vec![create_test_record("example.com.", Ttl::from_wire(i32::MAX))],
        );
        let expires_at = cache.cache.lock().unwrap()
            [&NameTypeKey::new("example.com.", Qtype::of(rt::A))]
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
            "example.com.",
            Qtype::of(rt::A),
            vec![create_test_record("example.com.", Ttl::from_secs(3600))],
        );
        assert!(
            cache.get("example.com", Qtype::of(rt::A)).is_some(),
            "the relative spelling of a name we hold must hit"
        );
        assert_eq!(cache.get_stats().total_entries, 1);
    }

    /// DNS folds case over ASCII only (RFC 4343). U+212A KELVIN SIGN lowercases
    /// to `k` under Unicode, which would merge two owner names into one entry.
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

        for i in 0..20 {
            let name = format!("example{}.com.", i);
            let records = vec![create_test_record(&name, Ttl::from_secs(300))];
            cache.put(&name, Qtype::of(rt::A), records);
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

    /// A panic under the cache mutex costs the cache, not the process: poisoning
    /// is permanent, so `.lock().unwrap()` on the query path would make every
    /// later query panic too.
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
                name,
                Qtype::of(rt::A),
                vec![create_test_record(name, Ttl::from_secs(300))],
            );
        }
        assert_eq!(cache.get_stats().total_entries, 1);
        assert!(cache.get("b.example.com.", Qtype::of(rt::A)).is_some());
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
