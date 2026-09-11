//! What the resolver remembers about the *servers*, as opposed to the answers.
//!
//! Three maps, and the membership rule is the key: a zone or a server address,
//! never a question. `DelegationCache` says which servers a zone was last known
//! to have, `KeyCache` which DNSKEYs it was last seen to publish, and `RttStore`
//! how fast each individual server answered. All three are hints — dropping one
//! costs a round trip and never an answer, which is why a poisoned lock here
//! returns `None` rather than failing the query.
//!
//! Answers keyed by the *question* are elsewhere and shared with the daemon:
//! [`crate::cache`], [`crate::negative_cache`], [`crate::nsec_cache`]. A hint
//! that goes stale is a restart from the root (`resolve_from_root`); a cached
//! answer that goes stale is a wrong answer, which is why those three are
//! bounded and timed and these are bounded and cheap.

// The parent's `use` block, not a copy per file: these three are continuations
// of one `impl Resolver`, and a second import list is a second thing to drift.
use super::*;

/// Servers already learned for a zone, so a resolution can start partway down
/// the tree rather than paying a root round trip per client query.
#[derive(Debug)]
pub(super) struct DelegationCache {
    entries: Mutex<HashMap<Box<[u8]>, CachedDelegation>>,
    capacity: usize,
}

#[derive(Debug, Clone)]
struct CachedDelegation {
    servers: Vec<SocketAddr>,
    expires_at: u64,
}

/// Never cache a delegation for longer than this, whatever the record says.
const MAX_DELEGATION_TTL: u64 = 86_400;

impl DelegationCache {
    pub(super) fn new(capacity: usize) -> Self {
        DelegationCache {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// The deepest cached zone that encloses `qname` and has not expired.
    /// Deepest wins: it skips a round trip.
    pub(super) fn best_match(&self, qname: NameRef<'_>) -> Option<(Name, Vec<SocketAddr>)> {
        self.best_match_where(qname, |_| true)
    }

    /// As [`DelegationCache::best_match`], but only considering zones that
    /// `accept` approves of. A validating resolver uses this to refuse a
    /// shortcut that would skip past a zone cut it has not authenticated.
    pub(super) fn best_match_where(
        &self,
        qname: NameRef<'_>,
        accept: impl Fn(NameRef<'_>) -> bool,
    ) -> Option<(Name, Vec<SocketAddr>)> {
        let now = current_unix_timestamp();
        let mut entries = self.entries.lock().ok()?;

        // Keys are folded, so the *walk* is over the folded name; folding once
        // costs at most one copy for the whole walk, where the lowercased
        // per-label copy it replaces cost one each (`TODO.md` #26f).
        // Case folding moves no length octet, so the two walks step together.
        let mut buf = Vec::new();
        let folded = qname.folded_in(&mut buf);
        for (candidate, key) in qname.ancestors().zip(folded.ancestors()) {
            match entries.get(key.as_wire()) {
                Some(entry) if entry.expires_at > now && accept(candidate) => {
                    return Some((candidate.to_owned(), entry.servers.clone()));
                }
                // Live, but the caller does not want to start here.
                Some(entry) if entry.expires_at > now => {}
                Some(_) => {
                    entries.remove(key.as_wire());
                }
                None => {}
            }
        }
        None
    }

    pub(super) fn insert(&self, zone: NameRef<'_>, servers: Vec<SocketAddr>, ttl: u64) {
        // A zero TTL means "do not cache this", and a zero-capacity cache is
        // how callers turn the whole thing off.
        if servers.is_empty() || ttl == 0 || self.capacity == 0 {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };

        if entries.len() >= self.capacity {
            let now = current_unix_timestamp();
            entries.retain(|_, e| e.expires_at > now);
            // Still full of live entries: drop whichever expires soonest, since
            // it is the one we lose the least by re-learning.
            if entries.len() >= self.capacity {
                if let Some(soonest) = entries
                    .iter()
                    .min_by_key(|(_, e)| e.expires_at)
                    .map(|(k, _)| k.clone())
                {
                    entries.remove(&soonest);
                }
            }
        }

        entries.insert(
            zone.folded().into_owned().into_boxed_slice(),
            CachedDelegation {
                servers,
                expires_at: current_unix_timestamp() + ttl.min(MAX_DELEGATION_TTL),
            },
        );
    }

    /// Drop a zone's entry, for when the servers in it turn out not to work.
    pub(super) fn forget(&self, zone: NameRef<'_>) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(zone.folded().as_ref());
        }
    }
}

/// A smoothed round-trip time per nameserver, so a zone's servers are tried
/// fastest-first. An EWMA, as BIND and Unbound track SRTT: one bad sample
/// demotes a server rather than banishing it.
#[derive(Debug)]
pub(super) struct RttStore {
    rtts: Mutex<HashMap<SocketAddr, f64>>,
    capacity: usize,
}

/// Weight of the newest sample in the moving average; the SRTT smoothing factor
/// of RFC 6298.
const RTT_ALPHA: f64 = 0.25;

/// Assumed cost of an unmeasured server, in milliseconds. Sorts between a
/// measured-fast server and one that has been timing out.
const UNKNOWN_RTT_MS: f64 = 100.0;

impl RttStore {
    pub(super) fn new(capacity: usize) -> Self {
        RttStore {
            rtts: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// The stored SRTT, or [`UNKNOWN_RTT_MS`] if untimed.
    fn get(&self, server: &SocketAddr) -> f64 {
        self.rtts
            .lock()
            .ok()
            .and_then(|m| m.get(server).copied())
            .unwrap_or(UNKNOWN_RTT_MS)
    }

    /// Fold a new round-trip sample (or a timeout, on failure) into a server's
    /// average. The first sample is taken as-is; later ones are smoothed.
    pub(super) fn record(&self, server: &SocketAddr, sample_ms: f64) {
        if self.capacity == 0 {
            return;
        }
        let Ok(mut m) = self.rtts.lock() else {
            return;
        };
        match m.get_mut(server) {
            Some(srtt) => *srtt = (1.0 - RTT_ALPHA) * *srtt + RTT_ALPHA * sample_ms,
            None => {
                // At capacity, drop the slowest entry: least lost by
                // re-learning it as unknown.
                if m.len() >= self.capacity {
                    if let Some(worst) = m.iter().max_by(|a, b| a.1.total_cmp(b.1)).map(|(k, _)| *k)
                    {
                        m.remove(&worst);
                    }
                }
                m.insert(*server, sample_ms);
            }
        }
    }

    /// `servers` reordered fastest-known-first, ties keeping their input order
    /// (so a freshly learned, all-unmeasured set is tried as given).
    pub(super) fn order(&self, servers: &[SocketAddr]) -> Vec<SocketAddr> {
        let mut ranked: Vec<(usize, SocketAddr, f64)> = servers
            .iter()
            .enumerate()
            .map(|(i, s)| (i, *s, self.get(s)))
            .collect();
        ranked.sort_by(|a, b| a.2.total_cmp(&b.2).then(a.0.cmp(&b.0)));
        ranked.into_iter().map(|(_, s, _)| s).collect()
    }
}

/// DNSKEY sets already validated up to a trust anchor, so the chain walk is
/// paid once per zone per TTL. What is stored is the *conclusion* — nothing
/// re-checks these against their DS — which is what makes the TTL cap
/// load-bearing.
#[derive(Debug)]
pub(super) struct KeyCache {
    entries: Mutex<HashMap<Box<[u8]>, CachedKeys>>,
    capacity: usize,
}

#[derive(Debug, Clone)]
struct CachedKeys {
    keys: Vec<Dnskey>,
    expires_at: u64,
}

/// Never hold a validated key set longer than this, whatever the TTL says: a
/// withdrawn key must stop being trusted within the day.
const MAX_KEY_TTL: u64 = 86_400;

impl KeyCache {
    pub(super) fn new(capacity: usize) -> Self {
        KeyCache {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    pub(super) fn get(&self, zone: NameRef<'_>) -> Option<Vec<Dnskey>> {
        let now = current_unix_timestamp();
        let mut entries = self.entries.lock().ok()?;
        // Folded, because `insert` folds: RFC 4343 names differing only in case
        // are one entry, and looking one up unfolded would miss its own write.
        let key = zone.folded();
        match entries.get(key.as_ref()) {
            Some(entry) if entry.expires_at > now => Some(entry.keys.clone()),
            Some(_) => {
                entries.remove(key.as_ref());
                None
            }
            None => None,
        }
    }

    pub(super) fn insert(&self, zone: NameRef<'_>, keys: Vec<Dnskey>, ttl: u64) {
        if self.capacity == 0 || keys.is_empty() || ttl == 0 {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() >= self.capacity {
            let now = current_unix_timestamp();
            entries.retain(|_, e| e.expires_at > now);
            if entries.len() >= self.capacity {
                if let Some(soonest) = entries
                    .iter()
                    .min_by_key(|(_, e)| e.expires_at)
                    .map(|(k, _)| k.clone())
                {
                    entries.remove(&soonest);
                }
            }
        }
        entries.insert(
            zone.folded().into_owned().into_boxed_slice(),
            CachedKeys {
                keys,
                expires_at: current_unix_timestamp() + ttl.min(MAX_KEY_TTL),
            },
        );
    }

    pub(super) fn holds(&self, zone: NameRef<'_>) -> bool {
        self.get(zone).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_records::nm;

    /// A cache key as the caches build one: the folded wire form.
    fn key_of(text: &str) -> Box<[u8]> {
        nm(text).as_ref().folded().into_owned().into_boxed_slice()
    }

    #[test]
    fn test_rtt_store_orders_fastest_first() {
        let store = RttStore::new(16);
        let a: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let b: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let c: SocketAddr = "192.0.2.3:53".parse().unwrap();

        // All unmeasured: the input order is kept.
        assert_eq!(store.order(&[a, b, c]), vec![a, b, c]);

        store.record(&a, 200.0);
        store.record(&b, 5.0);
        // c is still unknown (100), so: b(5) < c(100) < a(200).
        assert_eq!(store.order(&[a, b, c]), vec![b, c, a]);
    }

    #[test]
    fn test_rtt_store_smooths_samples() {
        let store = RttStore::new(16);
        let s: SocketAddr = "192.0.2.1:53".parse().unwrap();

        store.record(&s, 10.0); // first sample taken as-is
        assert!((store.get(&s) - 10.0).abs() < 1e-9);
        store.record(&s, 20.0); // EWMA: 0.75*10 + 0.25*20 = 12.5
        assert!((store.get(&s) - 12.5).abs() < 1e-9);

        // An unmeasured server reads back the default.
        let u: SocketAddr = "192.0.2.9:53".parse().unwrap();
        assert_eq!(store.get(&u), UNKNOWN_RTT_MS);
    }

    #[test]
    fn test_rtt_store_evicts_the_slowest_at_capacity() {
        let store = RttStore::new(2);
        let a: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let b: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let c: SocketAddr = "192.0.2.3:53".parse().unwrap();

        store.record(&a, 500.0); // slowest
        store.record(&b, 5.0);
        store.record(&c, 10.0); // over capacity: evicts the slowest (a)

        let m = store.rtts.lock().unwrap();
        assert_eq!(m.len(), 2);
        assert!(!m.contains_key(&a), "the slowest entry is dropped");
        assert!(m.contains_key(&b) && m.contains_key(&c));
    }

    #[test]
    fn test_rtt_store_zero_capacity_is_off() {
        let store = RttStore::new(0);
        let a: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let b: SocketAddr = "192.0.2.2:53".parse().unwrap();

        store.record(&a, 5.0);
        assert_eq!(store.get(&a), UNKNOWN_RTT_MS, "nothing is stored");
        // Ordering still works, and with no data it is just the input order.
        assert_eq!(store.order(&[b, a]), vec![b, a]);
    }

    /// The deepest cached zone wins, because it skips the most round trips.
    #[test]
    fn test_delegation_cache_prefers_the_deepest_match() {
        let cache = DelegationCache::new(16);
        let com: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let example: SocketAddr = "192.0.2.2:53".parse().unwrap();

        cache.insert(nm("com.").as_ref(), vec![com], 3600);
        assert_eq!(
            cache.best_match(nm("www.example.com.").as_ref()).unwrap(),
            (nm("com."), vec![com])
        );

        cache.insert(nm("example.com.").as_ref(), vec![example], 3600);
        assert_eq!(
            cache.best_match(nm("www.example.com.").as_ref()).unwrap(),
            (nm("example.com."), vec![example])
        );

        // An unrelated name still falls back to nothing.
        assert!(cache.best_match(nm("example.org.").as_ref()).is_none());
    }

    #[test]
    fn test_delegation_cache_expiry_and_limits() {
        let cache = DelegationCache::new(16);
        let server: SocketAddr = "192.0.2.1:53".parse().unwrap();

        // A zero TTL means "don't cache".
        cache.insert(nm("zero.test.").as_ref(), vec![server], 0);
        assert!(cache.best_match(nm("zero.test.").as_ref()).is_none());

        // An entry already expired is not returned.
        {
            let mut entries = cache.entries.lock().unwrap();
            entries.insert(
                key_of("stale.test."),
                CachedDelegation {
                    servers: vec![server],
                    expires_at: current_unix_timestamp().saturating_sub(1),
                },
            );
        }
        assert!(cache.best_match(nm("stale.test.").as_ref()).is_none());

        // forget() drops a live entry.
        cache.insert(nm("live.test.").as_ref(), vec![server], 3600);
        assert!(cache.best_match(nm("live.test.").as_ref()).is_some());
        cache.forget(nm("live.test.").as_ref());
        assert!(cache.best_match(nm("live.test.").as_ref()).is_none());

        // A zero-capacity cache stores nothing.
        let off = DelegationCache::new(0);
        off.insert(nm("any.test.").as_ref(), vec![server], 3600);
        assert!(off.best_match(nm("any.test.").as_ref()).is_none());
    }

    #[test]
    fn test_delegation_cache_evicts_at_capacity() {
        let cache = DelegationCache::new(2);
        let server: SocketAddr = "192.0.2.1:53".parse().unwrap();

        cache.insert(nm("a.test.").as_ref(), vec![server], 3600);
        cache.insert(nm("b.test.").as_ref(), vec![server], 7200);
        cache.insert(nm("c.test.").as_ref(), vec![server], 7200);

        let entries = cache.entries.lock().unwrap();
        assert!(entries.len() <= 2, "cache must stay within capacity");
        // The soonest-to-expire entry is the one dropped.
        assert!(!entries.contains_key(&key_of("a.test.")));
    }
}
