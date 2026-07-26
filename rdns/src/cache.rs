use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::ResourceRecord;
use crate::utils::current_unix_timestamp;

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

        let key = (name.to_lowercase(), qtype);

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
        
        // Find minimum TTL from records
        let min_ttl = records.iter()
            .map(|r| r.ttl as u64)
            .min()
            .unwrap_or(300); // Default 5 minutes if no TTL

        let expires_at = now + min_ttl;
        
        let mut cache = self.cache.lock().unwrap();
        
        // Evict oldest entries if cache is full
        if cache.len() >= self.max_entries {
            self.evict_oldest(&mut cache);
        }

        let key = (name.to_lowercase(), qtype);
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
