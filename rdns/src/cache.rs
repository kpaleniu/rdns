use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::ResourceRecord;
use crate::utils::{ascii_lowered, current_unix_timestamp};

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
    cache: Arc<Mutex<HashMap<(String, u16), CacheEntry>>>,
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
    pub fn get(&self, name: &str, qtype: u16) -> Option<Vec<ResourceRecord>> {
        self.get_validated(name, qtype).map(|(records, _)| records)
    }

    /// As [`DnsCache::get`], but also reporting whether the answer was
    /// DNSSEC-validated when it was stored.
    pub fn get_validated(&self, name: &str, qtype: u16) -> Option<(Vec<ResourceRecord>, bool)> {
        let now = current_unix_timestamp();
        let mut cache = self.cache.lock().unwrap();

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
    pub fn put(&self, name: &str, qtype: u16, records: Vec<ResourceRecord>) {
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
        qtype: u16,
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
        // `ResourceRecord::ttl` is an `i32` straight off the wire, so a TTL with
        // the high bit set parses *negative*. `-1 as u64` is `u64::MAX`, `min`
        // then picked it as the smallest, and `is_expired` was false for the
        // life of the process: an entry pinned forever, immune to the re-query
        // that would otherwise correct it. Poison one answer and it stays
        // poisoned until the daemon restarts. RFC 2181 §8 says to treat a
        // received TTL with the high bit set as zero, which `.max(0)` does
        // *before* the widening rather than after.
        //
        // `negative_cache` and `nsec_cache` already clamped; this cache and the
        // two `rr.ttl.max(0)` sites in `resolver` that write into it did not
        // agree about whose job it was, which is how a check that exists three
        // times over is still missing in one place.
        let min_ttl = records
            .iter()
            .map(|r| (r.ttl.max(0) as u64).min(MAX_CACHE_TTL))
            .min()
            .unwrap_or(300); // Default 5 minutes if no TTL

        // Saturating because `now + ttl` on a clock far in the future is a debug
        // panic and a release wrap, and a wrapped expiry is an entry that has
        // already expired — or never does.
        let expires_at = now.saturating_add(min_ttl);

        let mut cache = self.cache.lock().unwrap();
        
        // Evict oldest entries if cache is full
        if cache.len() >= self.max_entries {
            self.evict_oldest(&mut cache);
        }

        let key = (ascii_lowered(name), qtype);
        cache.insert(key, CacheEntry {
            records,
            expires_at,
            secure,
        });
    }

    /// Evict expired and oldest entries
    fn evict_oldest(&self, cache: &mut HashMap<(String, u16), CacheEntry>) {
        let now = current_unix_timestamp();
        
        // First remove all expired entries
        cache.retain(|_, entry| !entry.is_expired(now));
        
        // If still over limit, remove oldest entries
        while cache.len() > self.max_entries / 2 {
            if let Some(key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&key);
            } else {
                break;
            }
        }
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        let cache = self.cache.lock().unwrap();
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
    pub fn clear(&self) {
        self.cache.lock().unwrap().clear();
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
    use std::net::Ipv4Addr;
    use crate::{ResourceRecord, RecordData, ParsedRecord};

    fn create_test_record(name: &str, ttl: i32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            class: 1,
            ttl,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        }
    }

    #[test]
    fn test_cache_put_and_get() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", 300)];

        cache.put("example.com.", 1, records.clone());
        
        let retrieved = cache.get("example.com.", 1);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().len(), 1);
    }

    #[test]
    fn test_cache_miss() {
        let cache = DnsCache::with_defaults();
        
        let result = cache.get("notcached.com.", 1);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_case_insensitive() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", 300)];

        cache.put("EXAMPLE.COM.", 1, records.clone());
        
        let retrieved = cache.get("example.com.", 1);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_cache_different_types() {
        let cache = DnsCache::with_defaults();
        let a_records = vec![create_test_record("example.com.", 300)];
        let aaaa_records = vec![create_test_record("example.com.", 300)];

        cache.put("example.com.", 1, a_records);
        cache.put("example.com.", 28, aaaa_records);
        
        assert!(cache.get("example.com.", 1).is_some());
        assert!(cache.get("example.com.", 28).is_some());
        assert!(cache.get("example.com.", 5).is_none()); // CNAME not cached
    }

    #[test]
    fn test_cache_stats() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", 300)];

        cache.put("example.com.", 1, records);
        
        let stats = cache.get_stats();
        assert!(stats.total_entries > 0);
        assert_eq!(stats.valid_entries, stats.total_entries - stats.expired_entries);
    }

    #[test]
    fn test_cache_clear() {
        let cache = DnsCache::with_defaults();
        let records = vec![create_test_record("example.com.", 300)];

        cache.put("example.com.", 1, records);
        assert!(cache.get("example.com.", 1).is_some());
        
        cache.clear();
        assert!(cache.get("example.com.", 1).is_none());
    }

    #[test]
    fn test_cache_uses_minimum_ttl() {
        let cache = DnsCache::with_defaults();
        let records = vec![
            create_test_record("example.com.", 300),
            create_test_record("example.com.", 100), // Lower TTL
        ];

        cache.put("example.com.", 1, records);
        
        let retrieved = cache.get("example.com.", 1);
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
            cache.put("example.com.", 1, vec![create_test_record("example.com.", ttl)]);
            assert!(
                cache.get("example.com.", 1).is_none(),
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
            1,
            vec![create_test_record("example.com.", i32::MAX)],
        );
        let expires_at = cache.cache.lock().unwrap()[&("example.com.".to_string(), 1)].expires_at;
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
        cache.put(kelvin, 1, vec![create_test_record(kelvin, 300)]);

        assert!(cache.get(kelvin, 1).is_some(), "its own name still finds it");
        assert!(
            cache.get("k.example.com.", 1).is_none(),
            "a different owner name must not share the entry"
        );
    }

    #[test]
    fn test_cache_capacity() {
        let cache = DnsCache::new(10);
        
        // Fill cache beyond capacity
        for i in 0..20 {
            let name = format!("example{}.com.", i);
            let records = vec![create_test_record(&name, 300)];
            cache.put(&name, 1, records);
        }
        
        let stats = cache.get_stats();
        assert!(stats.total_entries <= 10, "cache exceeded max capacity");
    }
}
