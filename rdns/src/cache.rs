use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::ResourceRecord;

/// DNS cache entry with TTL expiration
#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<ResourceRecord>,
    expires_at: u64, // Unix timestamp
}

impl CacheEntry {
    fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// DNS response cache with TTL support
/// Caches responses keyed by (domain_name, record_type)
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
        let now = Self::current_time();
        let mut cache = self.cache.lock().unwrap();
        
        let key = (name.to_lowercase(), qtype);
        
        // Check if entry exists and is not expired
        if let Some(entry) = cache.get(&key) {
            if !entry.is_expired(now) {
                return Some(entry.records.clone());
            } else {
                // Remove expired entry
                cache.remove(&key);
            }
        }
        
        None
    }

    /// Put records in cache with TTL
    pub fn put(&self, name: &str, qtype: u16, records: Vec<ResourceRecord>) {
        if records.is_empty() {
            return;
        }

        let now = Self::current_time();
        
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
        });
    }

    /// Evict expired and oldest entries
    fn evict_oldest(&self, cache: &mut HashMap<(String, u16), CacheEntry>) {
        let now = Self::current_time();
        
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

    /// Clear negative cache entries (NXDOMAIN responses)
    pub fn put_negative(&self, name: &str, ttl: u64) {
        let now = Self::current_time();
        let expires_at = now + ttl;
        
        let mut cache = self.cache.lock().unwrap();
        
        if cache.len() >= self.max_entries {
            self.evict_oldest(&mut cache);
        }

        // Use type 0 to indicate negative cache entry
        let key = (name.to_lowercase(), 0u16);
        cache.insert(key, CacheEntry {
            records: Vec::new(),
            expires_at,
        });
    }

    /// Check if domain has negative cache entry
    pub fn is_negative_cached(&self, name: &str) -> bool {
        let now = Self::current_time();
        let cache = self.cache.lock().unwrap();
        
        let key = (name.to_lowercase(), 0u16);
        if let Some(entry) = cache.get(&key) {
            !entry.is_expired(now)
        } else {
            false
        }
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        let cache = self.cache.lock().unwrap();
        let now = Self::current_time();
        
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

    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
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
    use crate::{ResourceRecord, RecordData, StandardRecord};

    fn create_test_record(name: &str, ttl: i32) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            class: 1,
            ttl,
            rdata: RecordData::Standard(StandardRecord::A(Ipv4Addr::new(192, 0, 2, 1))),
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
    fn test_negative_cache() {
        let cache = DnsCache::with_defaults();
        
        cache.put_negative("notexist.com.", 300);
        assert!(cache.is_negative_cached("notexist.com."));
        
        // Case insensitive
        assert!(cache.is_negative_cached("NOTEXIST.COM."));
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
