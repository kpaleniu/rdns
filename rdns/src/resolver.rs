//! The resolver: obtains an answer for a query, either by walking the
//! delegation chain from the root ourselves or by forwarding to a configured
//! upstream. See [`ResolverMode`].

use crate::dnssec::{Dnskey, Rrsig};
use crate::dnssec_chain::{
    cname_chain_shape, ChainShape, ChainValidator, DelegationEvidence, DelegationVerdict, KeyStore,
    TrustAnchors, ValidationState,
};
use crate::dnssec_denial::{nsec3s_in, nsecs_in, proves_nodata, proves_nxdomain, Denial};
use crate::error::{ResolveError, ResolveResult};
use crate::utils::{
    absolute_lowered, current_unix_timestamp, is_at_or_under, label_count, names_equal,
    record_types as rt, NameKeyBuf,
};
use crate::Qtype;
use crate::Rtype;
use crate::{DnsMessage, Edns, ParsedRecord, QuerySection, ResourceRecord, ResponseCode};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// A DNS message sent over TCP is prefixed with a 2-byte big-endian length
/// (RFC 1035 §4.2.2), so no message can exceed what that field can express.
const TCP_MAX_MESSAGE: usize = u16::MAX as usize;

/// The record type an intermediate QNAME-minimized probe asks for: A, the QTYPE
/// least likely to trip middleboxes (RFC 9156 §2.3), not RFC 7816's NS.
const MINIMIZED_PROBE_TYPE: Qtype = Qtype::of(rt::A);

/// MAX_MINIMISE_COUNT (RFC 9156 §2.3, recommended 10). Past it the full QNAME
/// goes out, so a deep name degrades instead of exhausting `query_budget`.
const MAX_MINIMISE_COUNT: usize = 10;

/// IPv4 addresses of the 13 root servers, used to prime recursion.
///
/// A fallback only; these change, so load the published hints file with
/// [`parse_root_hints`] into `root_hints`. A stale entry degrades: servers are
/// tried until one answers and RTT selection demotes the rest.
const ROOT_HINTS: [Ipv4Addr; 13] = [
    Ipv4Addr::new(198, 41, 0, 4),     // a.root-servers.net
    Ipv4Addr::new(170, 247, 170, 2),  // b
    Ipv4Addr::new(192, 33, 4, 12),    // c
    Ipv4Addr::new(199, 7, 91, 13),    // d
    Ipv4Addr::new(192, 203, 230, 10), // e
    Ipv4Addr::new(192, 5, 5, 241),    // f
    Ipv4Addr::new(192, 112, 36, 4),   // g
    Ipv4Addr::new(198, 97, 190, 53),  // h
    Ipv4Addr::new(192, 36, 148, 17),  // i
    Ipv4Addr::new(192, 58, 128, 30),  // j
    Ipv4Addr::new(193, 0, 14, 129),   // k
    Ipv4Addr::new(199, 7, 83, 42),    // l
    Ipv4Addr::new(202, 12, 27, 33),   // m
];

/// The IPv6 (AAAA) addresses of the same 13 root servers, in the same order.
const ROOT_HINTS_V6: [Ipv6Addr; 13] = [
    Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30), // a
    Ipv6Addr::new(0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb),      // b
    Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc),       // c
    Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd),      // d
    Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe),      // e
    Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf),      // f
    Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d),    // g
    Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53),      // h
    Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53),        // i
    Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30),  // j
    Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1),         // k
    Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42),     // l
    Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35),        // m
];

/// Parse root hints in the published `named.root` format, returning every A and
/// AAAA address it lists (port 53). An unparsable line is skipped rather than
/// failing the file; the caller decides what an empty result means.
pub fn parse_root_hints(text: &str) -> Vec<SocketAddr> {
    let mut hints = Vec::new();
    for line in text.lines() {
        let line = line.split(';').next().unwrap_or("");
        // Layout is NAME TTL [CLASS] TYPE RDATA. Scanning for the type token
        // tolerates the optional class and any spacing. The owner name
        // "A.ROOT-SERVERS.NET." does not equal the bare type "A".
        let mut tokens = line.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok.eq_ignore_ascii_case("A") || tok.eq_ignore_ascii_case("AAAA") {
                if let Some(Ok(ip)) = tokens.next().map(str::parse::<IpAddr>) {
                    hints.push(SocketAddr::new(ip, 53));
                }
                break;
            }
        }
    }
    hints
}

/// How the resolver obtains an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverMode {
    /// Walk the delegation chain ourselves: root → TLD → authoritative.
    Recurse,
    /// Ask a configured upstream resolver and return what it says. Cheaper and
    /// simpler, but it makes that upstream a trusted third party.
    Forward,
}

/// Configuration for the resolver.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Whether to recurse from the root or forward to `upstream_servers`.
    pub mode: ResolverMode,
    /// Upstream resolvers for [`ResolverMode::Forward`] (e.g. "8.8.8.8:53").
    pub upstream_servers: Vec<SocketAddr>,
    /// Where recursion starts. Defaults to the built-in [`ROOT_HINTS`].
    pub root_hints: Vec<SocketAddr>,
    /// Per-query timeout in milliseconds.
    pub timeout_ms: u64,
    /// Referrals to follow before giving up. Bounds how deep a delegation chain
    /// may be; real ones are a handful of labels.
    pub max_delegations: usize,
    /// CNAME hops to follow before declaring a loop.
    pub max_cname_hops: usize,
    /// Total upstream queries one `resolve` may spend, across delegations,
    /// CNAME hops and nameserver-address lookups. The NXNSAttack defence: a
    /// referral naming dozens of glueless nameservers costs a resolution each.
    pub query_budget: usize,
    /// EDNS0 UDP payload size to advertise upstream (RFC 6891).
    pub udp_payload_size: u16,
    /// How many zone delegations to remember. 0 disables the cache, which makes
    /// every query restart at the root — correct, but only acceptable in tests.
    pub delegation_cache_size: usize,
    /// Whether to minimize the query name sent up the delegation chain
    /// (RFC 9156). On by default; off sends the full name at every hop.
    pub qname_minimization: bool,
    /// Whether to randomize the case of the outgoing query name
    /// (draft-vixie-dnsext-dns0x20): entropy an off-path spoofer must guess on
    /// top of the transaction id and source port. Off for peers that do not
    /// preserve case.
    pub zero_x20: bool,
    /// Port to contact a nameserver on. Always 53 in practice — glue carries no
    /// port; configurable only so tests can run an unprivileged hierarchy.
    pub server_port: u16,
    /// Trust anchors to validate against, or `None` for no DNSSEC validation.
    ///
    /// On, every query carries DO and CD: an upstream that validates for us and
    /// returns SERVFAIL leaves nothing to check, which is the same as trusting
    /// it.
    pub dnssec: Option<SharedAnchors>,
}

/// Trust anchors the resolver validates against, replaceable while it runs
/// (RFC 5011 key rolls).
///
/// A `std::sync::RwLock` rather than tokio's: every use is a clone-and-release
/// with no await inside.
#[derive(Clone, Debug)]
pub struct SharedAnchors(Arc<std::sync::RwLock<TrustAnchors>>);

impl SharedAnchors {
    pub fn new(anchors: TrustAnchors) -> Self {
        SharedAnchors(Arc::new(std::sync::RwLock::new(anchors)))
    }

    /// The anchors as they stand. A poisoned lock is recovered rather than
    /// propagated: an anchor swap is a whole-value assignment, so the caller
    /// sees one of the two versions either way.
    pub fn get(&self) -> TrustAnchors {
        match self.0.read() {
            Ok(anchors) => anchors.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Put a new set in place.
    pub fn replace(&self, anchors: TrustAnchors) {
        match self.0.write() {
            Ok(mut held) => *held = anchors,
            Err(poisoned) => *poisoned.into_inner() = anchors,
        }
    }
}

impl From<TrustAnchors> for SharedAnchors {
    fn from(anchors: TrustAnchors) -> Self {
        SharedAnchors::new(anchors)
    }
}

impl Default for ResolverConfig {
    fn default() -> Self {
        ResolverConfig {
            mode: ResolverMode::Recurse,
            // Google and Cloudflare public DNS, used only in Forward mode.
            upstream_servers: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            ],
            // Interleaved v4/v6 so whichever family the host has is reached in
            // the first hop or two, before RTT selection has anything to go on.
            root_hints: ROOT_HINTS
                .iter()
                .zip(ROOT_HINTS_V6.iter())
                .flat_map(|(v4, v6)| {
                    [
                        SocketAddr::new(IpAddr::V4(*v4), 53),
                        SocketAddr::new(IpAddr::V6(*v6), 53),
                    ]
                })
                .collect(),
            timeout_ms: 5000,
            max_delegations: 16,
            max_cname_hops: 8,
            query_budget: 64,
            udp_payload_size: 4096,
            delegation_cache_size: 10_000,
            qname_minimization: true,
            zero_x20: true,
            server_port: 53,
            // Off by default: validation costs round trips and turns a
            // misconfigured zone into a failure, so it is the operator's call.
            dnssec: None,
        }
    }
}

/// Servers already learned for a zone, so a resolution can start partway down
/// the tree rather than paying a root round trip per client query.
#[derive(Debug)]
struct DelegationCache {
    entries: Mutex<HashMap<NameKeyBuf, CachedDelegation>>,
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
    fn new(capacity: usize) -> Self {
        DelegationCache {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// The deepest cached zone that encloses `qname` and has not expired.
    /// Deepest wins: it skips a round trip.
    fn best_match(&self, qname: &str) -> Option<(String, Vec<SocketAddr>)> {
        self.best_match_where(qname, |_| true)
    }

    /// As [`DelegationCache::best_match`], but only considering zones that
    /// `accept` approves of. A validating resolver uses this to refuse a
    /// shortcut that would skip past a zone cut it has not authenticated.
    fn best_match_where(
        &self,
        qname: &str,
        accept: impl Fn(&str) -> bool,
    ) -> Option<(String, Vec<SocketAddr>)> {
        let name = normalize(qname);
        let now = current_unix_timestamp();
        let mut entries = self.entries.lock().ok()?;

        for candidate in ancestors(&name) {
            match entries.get(candidate.as_str()) {
                Some(entry) if entry.expires_at > now && accept(&candidate) => {
                    return Some((candidate, entry.servers.clone()));
                }
                // Live, but the caller does not want to start here.
                Some(entry) if entry.expires_at > now => {}
                Some(_) => {
                    entries.remove(candidate.as_str());
                }
                None => {}
            }
        }
        None
    }

    fn insert(&self, zone: &str, servers: Vec<SocketAddr>, ttl: u64) {
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
            NameKeyBuf::new(zone),
            CachedDelegation {
                servers,
                expires_at: current_unix_timestamp() + ttl.min(MAX_DELEGATION_TTL),
            },
        );
    }

    /// Drop a zone's entry, for when the servers in it turn out not to work.
    fn forget(&self, zone: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(normalize(zone).as_str());
        }
    }
}

/// A smoothed round-trip time per nameserver, so a zone's servers are tried
/// fastest-first. An EWMA, as BIND and Unbound track SRTT: one bad sample
/// demotes a server rather than banishing it.
#[derive(Debug)]
struct RttStore {
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
    fn new(capacity: usize) -> Self {
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
    fn record(&self, server: &SocketAddr, sample_ms: f64) {
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
    fn order(&self, servers: &[SocketAddr]) -> Vec<SocketAddr> {
        let mut ranked: Vec<(usize, SocketAddr, f64)> = servers
            .iter()
            .enumerate()
            .map(|(i, s)| (i, *s, self.get(s)))
            .collect();
        ranked.sort_by(|a, b| a.2.total_cmp(&b.2).then(a.0.cmp(&b.0)));
        ranked.into_iter().map(|(_, s, _)| s).collect()
    }
}

/// A name and every zone above it, deepest first: `www.example.com.` yields
/// `www.example.com.`, `example.com.`, `com.`, `.`.
fn ancestors(name: &str) -> Vec<String> {
    let name = normalize(name);
    let mut out = vec![name.clone()];
    let mut rest = name.as_str();
    while let Some(dot) = rest.find('.') {
        rest = &rest[dot + 1..];
        if rest.is_empty() {
            break;
        }
        out.push(rest.to_string());
    }
    if out.last().map(|s| s != ".").unwrap_or(true) {
        out.push(".".to_string());
    }
    out
}

/// What a referral told us.
struct Referral {
    zone: String,
    ns_names: Vec<String>,
    glue: Vec<SocketAddr>,
    /// Shortest TTL among the records the delegation rests on.
    ttl: u64,
}

/// A serialized query, kept alongside the two things a reply must match to be
/// accepted: the transaction id and the exact (possibly 0x20-cased) question
/// name we put on the wire.
struct OutgoingQuery {
    buf: Vec<u8>,
    id: u16,
    qname: String,
}

/// Tracks how much work one client query has cost us.
struct Budget {
    remaining: usize,
}

impl Budget {
    fn new(total: usize) -> Self {
        Budget { remaining: total }
    }

    /// Charge one upstream query, or fail if the query has spent its budget.
    fn spend(&mut self) -> ResolveResult<()> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(ResolveError::BudgetExhausted)?;
        Ok(())
    }
}

/// The mutable state of one client query, threaded through the whole walk.
///
/// A referral is the only sight of the *parent's* side of a zone cut, where the
/// DS lives; asking the child for its own DS lets it answer about itself. So
/// `cuts` collects DS and NSEC evidence in passing and validation consumes it.
struct Resolution {
    budget: Budget,
    cuts: Vec<DelegationEvidence>,
    denials: Vec<ResourceRecord>,
}

impl Resolution {
    fn new(budget: usize) -> Self {
        Resolution {
            budget: Budget::new(budget),
            cuts: Vec::new(),
            denials: Vec::new(),
        }
    }

    /// Keep the NSEC/NSEC3 records, and their RRSIGs, from an authority
    /// section. Only the last response of a CNAME chase survives into the
    /// message returned, so an earlier hop's wildcard proof would be lost.
    fn record_denials(&mut self, authorities: &[ResourceRecord]) {
        self.denials.extend(
            authorities
                .iter()
                .filter(|rr| matches!(rr.rdata.rtype(), rt::NSEC | rt::NSEC3 | rt::RRSIG))
                .cloned(),
        );
    }

    /// Remember what a referral to `zone` said about that zone's security.
    fn record_cut(&mut self, zone: &str, authorities: &[ResourceRecord]) {
        let evidence = DelegationEvidence::from_authority(zone, authorities);
        // A zone can be crossed more than once in one resolution. Keep the
        // first sighting that carried evidence; a later referral may be thinner.
        if let Some(existing) = self.cuts.iter_mut().find(|c| c.zone == evidence.zone) {
            if existing.ds.is_empty() && existing.nsecs.is_empty() && existing.nsec3s.is_empty() {
                *existing = evidence;
            }
            return;
        }
        self.cuts.push(evidence);
    }

    /// The next zone cut below `zone` on the way to `target`. Shallowest first:
    /// each zone's keys authenticate the DS of the zone beneath it.
    fn next_cut_below(&self, zone: &str, target: &str) -> Option<&DelegationEvidence> {
        self.cuts
            .iter()
            .filter(|c| {
                !names_equal(&c.zone, zone)
                    && is_at_or_under(&c.zone, zone)
                    && is_at_or_under(target, &c.zone)
            })
            .min_by_key(|c| label_count(&c.zone))
    }
}

/// DNSKEY sets already validated up to a trust anchor, so the chain walk is
/// paid once per zone per TTL. What is stored is the *conclusion* — nothing
/// re-checks these against their DS — which is what makes the TTL cap
/// load-bearing.
#[derive(Debug)]
struct KeyCache {
    entries: Mutex<HashMap<NameKeyBuf, CachedKeys>>,
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
    fn new(capacity: usize) -> Self {
        KeyCache {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    fn get(&self, zone: &str) -> Option<Vec<Dnskey>> {
        let now = current_unix_timestamp();
        let mut entries = self.entries.lock().ok()?;
        match entries.get(zone) {
            Some(entry) if entry.expires_at > now => Some(entry.keys.clone()),
            Some(_) => {
                entries.remove(zone);
                None
            }
            None => None,
        }
    }

    fn insert(&self, zone: &str, keys: Vec<Dnskey>, ttl: u64) {
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
            NameKeyBuf::new(zone),
            CachedKeys {
                keys,
                expires_at: current_unix_timestamp() + ttl.min(MAX_KEY_TTL),
            },
        );
    }

    fn holds(&self, zone: &str) -> bool {
        self.get(zone).is_some()
    }
}

/// A DNS resolver. See [`ResolverMode`].
pub struct Resolver {
    config: ResolverConfig,
    /// Shared across concurrent resolutions.
    delegations: DelegationCache,
    /// Per-server round-trip times. Shares its bound with the delegation cache;
    /// 0 disables recording, and `order` then keeps the input order.
    rtt: RttStore,
    /// Zones whose DNSKEY set we have already validated.
    keys: KeyCache,
}

impl Resolver {
    pub fn new(config: ResolverConfig) -> Self {
        let delegations = DelegationCache::new(config.delegation_cache_size);
        let rtt = RttStore::new(config.delegation_cache_size);
        let keys = KeyCache::new(config.delegation_cache_size);
        Resolver {
            config,
            delegations,
            rtt,
            keys,
        }
    }

    /// A recursing resolver with the built-in root hints.
    pub fn with_defaults() -> Self {
        Self::new(ResolverConfig::default())
    }

    /// A resolver that forwards to `upstreams` instead of recursing.
    pub fn forwarding_to(upstreams: Vec<SocketAddr>) -> Self {
        Self::new(ResolverConfig {
            mode: ResolverMode::Forward,
            upstream_servers: upstreams,
            ..ResolverConfig::default()
        })
    }

    pub fn mode(&self) -> ResolverMode {
        self.config.mode
    }

    /// Resolve a query. The answer only; [`Resolver::resolve_validated`] also
    /// reports whether it was authenticated.
    pub async fn resolve(&self, query: &QuerySection) -> ResolveResult<DnsMessage> {
        self.resolve_validated(query).await.map(|(msg, _)| msg)
    }

    /// Resolve a query and say how much the answer can be trusted.
    ///
    /// With no trust anchors the state is [`ValidationState::Indeterminate`],
    /// not `Insecure`: nothing established that anything is unsigned.
    pub async fn resolve_validated(
        &self,
        query: &QuerySection,
    ) -> Result<(DnsMessage, ValidationState), ResolveError> {
        let mut state = Resolution::new(self.config.query_budget);
        let response = match self.config.mode {
            ResolverMode::Forward => self.forward(query, &mut state).await?,
            ResolverMode::Recurse => self.recurse(query, &mut state).await?,
        };

        let Some(anchors) = &self.config.dnssec else {
            return Ok((
                response,
                ValidationState::Indeterminate("DNSSEC validation is not enabled".into()),
            ));
        };
        // Taken once for the whole resolve: anchors changing mid-walk would
        // trust a key for one step and not the next.
        let anchors = anchors.get();
        let verdict = self.validate(query, &response, &mut state, &anchors).await;
        Ok((response, verdict))
    }

    /// Forward the query to each upstream in turn and return the first answer.
    async fn forward(
        &self,
        query: &QuerySection,
        state: &mut Resolution,
    ) -> ResolveResult<DnsMessage> {
        // RD=1: the upstream does the recursion.
        let out = self.build_query(query, true)?;
        self.ask_any(&self.config.upstream_servers, &out, &mut state.budget)
            .await
            .ok_or_else(|| {
                ResolveError::no_response(format!(
                    "failed to resolve {} with all upstream servers",
                    query.qname
                ))
            })
    }

    /// Serialize a query message. `recursion_desired` is false while walking the
    /// delegation chain ourselves. The returned [`OutgoingQuery`] carries the id
    /// and the exact wire question name, so a reply can be checked against them.
    fn build_query(
        &self,
        query: &QuerySection,
        recursion_desired: bool,
    ) -> ResolveResult<OutgoingQuery> {
        let id = rand::random::<u16>();
        // Only the wire bytes and the reply check see the scrambled case;
        // resolution logic elsewhere normalizes.
        let sent_qname = if self.config.zero_x20 {
            randomize_case(&query.qname)
        } else {
            query.qname.clone()
        };
        let mut wire_query = query.clone();
        wire_query.qname = sent_qname.clone();

        let mut msg = DnsMessage {
            id,
            response: false,
            opcode: crate::OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: recursion_desired,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![wire_query],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        };
        // EDNS0 to exceed 512 bytes, DO to get signatures. CD goes with DO: we
        // do the checking, so the upstream must not withhold what it judged
        // bogus.
        let mut edns = Edns::with_payload_size(self.config.udp_payload_size);
        edns.do_bit = self.config.dnssec.is_some();
        msg.cd = self.config.dnssec.is_some();
        msg.set_edns(edns);

        let mut buf = vec![0; 512];
        let len = msg.to_bytes(&mut buf)?;
        buf.truncate(len);
        Ok(OutgoingQuery {
            buf,
            id,
            qname: sent_qname,
        })
    }

    /// Whether a reply answers the query sent: same id, echoed question matches.
    /// With 0x20 on the name compare is case-sensitive, which is what makes the
    /// random casing an anti-spoofing signal. A mismatch counts as no answer.
    fn response_matches(&self, response: &DnsMessage, sent: &OutgoingQuery) -> bool {
        if response.id != sent.id {
            return false;
        }
        let Some(question) = response.queries.first() else {
            return false;
        };
        if self.config.zero_x20 {
            question.qname == sent.qname
        } else {
            names_equal(&question.qname, &sent.qname)
        }
    }

    /// Resolve by walking the delegation chain, following any CNAME chain the
    /// answer leads through.
    async fn recurse(
        &self,
        query: &QuerySection,
        state: &mut Resolution,
    ) -> ResolveResult<DnsMessage> {
        let mut qname = normalize(&query.qname);
        let mut answers = Vec::new();
        // Names we have already asked about — asking twice means a CNAME loop.
        let mut queried: HashSet<String> = HashSet::new();
        // Names whose records we are willing to accept: the original question
        // plus every CNAME target we have followed to get here.
        let mut chain: HashSet<String> = HashSet::from([qname.clone()]);
        let mut last = None;

        for hop in 0..=self.config.max_cname_hops {
            if !queried.insert(qname.clone()) {
                return Err(ResolveError::no_response(format!("CNAME loop at {qname}")));
            }
            if hop == self.config.max_cname_hops {
                return Err(ResolveError::no_response(format!(
                    "CNAME chain longer than {} hops",
                    self.config.max_cname_hops
                )));
            }

            let step = QuerySection {
                qname: qname.clone(),
                qtype: query.qtype,
                qclass: query.qclass,
            };
            let response = self.resolve_from_root(&step, state, 0).await?;

            // Only the last hop's authority section is returned, but a
            // wildcard-expanded CNAME earlier in the chain still owes its NSEC.
            if self.config.dnssec.is_some() {
                state.record_denials(&response.authorities);
            }

            // Keep only records on the chain asked about. Records volunteered
            // for unrelated names are cache-poisoning attempts, and `rdnsr`
            // caches whatever is returned here.
            for rr in &response.answers {
                if !chain.contains(&normalize(&rr.name)) {
                    continue;
                }
                answers.push(rr.clone());
                if rr.rdata.rtype() == rt::CNAME {
                    if let Ok(ParsedRecord::CNAME(target)) = rr.rdata.parse() {
                        chain.insert(normalize(&target));
                    }
                }
            }

            // Done if we got the type we asked for, or if there is no CNAME to
            // follow (an empty answer is NODATA/NXDOMAIN, which is an answer).
            let got_type = response
                .answers
                .iter()
                .any(|rr| query.qtype.matches(rr.rdata.rtype()) && names_equal(&rr.name, &qname));
            let cname = response
                .answers
                .iter()
                .filter(|rr| rr.rdata.rtype() == rt::CNAME && names_equal(&rr.name, &qname))
                .find_map(|rr| match rr.rdata.parse() {
                    Ok(ParsedRecord::CNAME(target)) => Some(normalize(&target)),
                    _ => None,
                });

            last = Some(response);
            if got_type || cname.is_none() || query.qtype.is(rt::CNAME) {
                break;
            }
            qname = cname.expect("checked is_none above");
        }

        let mut response = last
            .ok_or_else(|| ResolveError::no_response(format!("no response for {}", query.qname)))?;
        // Present the whole chain under the question the client actually asked.
        response.queries = vec![query.clone()];
        response.answers = answers;
        response.authoritive = false;
        Ok(response)
    }

    /// One name's worth of delegation walking: start at the root hints and
    /// follow referrals until a server answers authoritatively.
    ///
    /// `depth` counts *nested* resolutions — a nameserver address lookup
    /// re-enters here — capped separately so glueless chains cannot recurse
    /// without bound.
    async fn resolve_from_root(
        &self,
        query: &QuerySection,
        state: &mut Resolution,
        depth: usize,
    ) -> ResolveResult<DnsMessage> {
        const MAX_NESTED: usize = 4;
        if depth > MAX_NESTED {
            return Err(ResolveError::no_response(format!(
                "nameserver lookup nested deeper than {MAX_NESTED}"
            )));
        }

        // Start as far down the tree as already known. Validating narrows that:
        // a shortcut past a zone cut skips its DS records, so only zones whose
        // keys are already validated may be jumped to.
        if let Some((zone, servers)) = self.best_start(&query.qname) {
            match self.walk(query, state, depth, zone.clone(), servers).await {
                Ok(response) => return Ok(response),
                Err(_) => {
                    // Cached delegations go stale; restart from the root rather
                    // than fail a query on our own bookkeeping.
                    self.delegations.forget(&zone);
                }
            }
        }

        self.walk(
            query,
            state,
            depth,
            ".".to_string(),
            self.config.root_hints.clone(),
        )
        .await
    }

    /// The deepest cached delegation we are willing to start from.
    fn best_start(&self, qname: &str) -> Option<(String, Vec<SocketAddr>)> {
        if self.config.dnssec.is_some() {
            self.delegations
                .best_match_where(qname, |zone| self.keys.holds(zone))
        } else {
            self.delegations.best_match(qname)
        }
    }

    /// The delegation walk proper, from a known starting point.
    async fn walk(
        &self,
        query: &QuerySection,
        state: &mut Resolution,
        depth: usize,
        start_zone: String,
        start_servers: Vec<SocketAddr>,
    ) -> ResolveResult<DnsMessage> {
        let qname = normalize(&query.qname);
        let qname_labels = label_count(&qname);

        // The zone whose servers we are talking to; bailiwick is judged against
        // it. A server for `com.` may delegate `example.com.` but may not
        // answer for `example.org.`.
        let mut zone = start_zone;
        let mut servers = start_servers;

        // Labels of `qname` the next minimized query reveals: one below the
        // starting zone, deepening a label at a time.
        let mut sent_labels = label_count(&zone) + 1;

        // The budget is the real limit; this only bounds a pathological spin.
        // Minimization can add a probe per empty-non-terminal label, hence
        // `+ qname_labels`.
        let max_steps = self.config.max_delegations + qname_labels + 1;
        // Counted rather than derived from `sent_labels`: a referral can move
        // `zone` several labels at once, and MAX_MINIMISE_COUNT bounds round
        // trips spent minimizing.
        let mut minimized_probes = 0usize;
        for _ in 0..max_steps {
            let minimizing =
                self.config.qname_minimization && minimized_probes < MAX_MINIMISE_COUNT;
            let labels = if minimizing {
                sent_labels.min(qname_labels)
            } else {
                qname_labels
            };
            // `qname` is normalized above, so the minimized name is a slice of
            // it and only the copy the question carries is paid for.
            let sname = crate::utils::suffix_labels(&qname, labels);
            let is_final = names_equal(sname, &qname);
            if !is_final {
                minimized_probes += 1;
            }

            // A zone cut answers the A probe with a referral, a plain in-zone
            // name with NODATA — telling the two apart without disclosing the
            // leaf.
            let step = QuerySection {
                qname: sname.to_string(),
                qtype: if is_final {
                    query.qtype
                } else {
                    MINIMIZED_PROBE_TYPE
                },
                qclass: query.qclass,
            };
            let out = self.build_query(&step, false)?;

            let Some(response) = self.ask_any(&servers, &out, &mut state.budget).await else {
                return Err(ResolveError::no_response(format!(
                    "no server for {zone} answered while resolving {qname}"
                )));
            };

            // Bailiwick is judged against the full `qname` even when a shorter
            // name was asked.
            if let Some(Referral {
                zone: child_zone,
                ns_names,
                glue,
                ttl,
            }) = self.extract_referral(&response, &zone, &qname)?
            {
                // The only pass where the parent's DS — or the NSEC proving
                // there is none — is in front of us.
                if self.config.dnssec.is_some() {
                    state.record_cut(&child_zone, &response.authorities);
                }

                servers = if glue.is_empty() {
                    // Glueless: each named server costs a resolution of its own.
                    self.resolve_nameserver_addresses(&ns_names, state, depth + 1)
                        .await?
                } else {
                    glue
                };

                if servers.is_empty() {
                    return Err(ResolveError::no_response(format!(
                        "no reachable nameserver for {child_zone}"
                    )));
                }
                self.delegations.insert(&child_zone, servers.clone(), ttl);
                // A referral may jump more than one label at once.
                sent_labels = label_count(&child_zone) + 1;
                zone = child_zone;
                continue;
            }

            if is_final {
                // No answer, not authoritative and no referral is a lame
                // delegation: an empty NOERROR would read as a definitive "no
                // such record", so fail into SERVFAIL instead.
                if !response.answers.is_empty() || response.authoritive {
                    return Ok(response);
                }
                return Err(ResolveError::no_response(format!(
                    "lame delegation: {zone} gave no answer and no usable referral for {qname}"
                )));
            }

            // No referral on an intermediate probe.
            if response.rcode == ResponseCode::NoSuchDomain {
                // The ancestor does not exist, so neither does the full name
                // (RFC 8020).
                return Ok(response);
            }
            // The label exists in this zone but is not a cut; go one deeper.
            sent_labels = labels + 1;
        }

        Err(ResolveError::no_response(format!(
            "more than {} referrals while resolving {qname}",
            self.config.max_delegations
        )))
    }

    /// Try the servers fastest-known-first, returning the first usable response
    /// and folding each round trip (or failure) back into the RTT estimates.
    async fn ask_any(
        &self,
        servers: &[SocketAddr],
        out: &OutgoingQuery,
        budget: &mut Budget,
    ) -> Option<DnsMessage> {
        for server in self.rtt.order(servers) {
            if budget.spend().is_err() {
                return None;
            }
            let started = std::time::Instant::now();
            if let Ok(response) = self.query_server(&server, out).await {
                self.rtt
                    .record(&server, started.elapsed().as_secs_f64() * 1000.0);
                return Some(response);
            }
            // A server that failed or timed out is charged the full timeout, so
            // the next query for this zone tries a different one ahead of it.
            self.rtt.record(&server, self.config.timeout_ms as f64);
        }
        None
    }

    /// Pull a delegation out of a referral response, enforcing bailiwick.
    ///
    /// Returns the delegated zone, the NS names, and whatever glue addresses
    /// were usable. `Ok(None)` means the response contained no delegation we are
    /// willing to follow.
    fn extract_referral(
        &self,
        response: &DnsMessage,
        zone: &str,
        qname: &str,
    ) -> ResolveResult<Option<Referral>> {
        // The NS records in the authority section name the child zone.
        let mut child_zone: Option<String> = None;
        let mut ns_names = Vec::new();
        // How long the delegation may be cached: the shortest TTL among the
        // records it rests on.
        let mut ttl = u64::MAX;

        for rr in &response.authorities {
            if rr.rdata.rtype() != rt::NS {
                continue; // only NS records delegate
            }
            let owner = normalize(&rr.name);

            // Bailiwick, the rule that keeps a hostile server in its lane: a
            // referral must be *below* the zone we asked (otherwise `com.` could
            // hand us the servers for `bank.example.`) and must be *at or above*
            // the name we are chasing (otherwise it is not progress toward it).
            if !is_at_or_under(&owner, zone) || owner == *zone {
                continue;
            }
            if !is_at_or_under(qname, &owner) {
                continue;
            }
            match &child_zone {
                None => child_zone = Some(owner.clone()),
                // A single referral names one zone; ignore any others.
                Some(z) if !names_equal(z, &owner) => continue,
                _ => {}
            }
            if let Ok(ParsedRecord::NS(target)) = rr.rdata.parse() {
                ns_names.push(normalize(&target));
                ttl = ttl.min(rr.ttl.as_u64());
            }
        }

        let Some(child_zone) = child_zone else {
            return Ok(None);
        };

        // Glue is trusted only where the responder has standing: names under
        // the zone *it* serves, not the zone it delegates to. The root's `com.`
        // referral carries glue for `a.gtld-servers.net.`, which is under
        // neither `com.` nor resolvable without it.
        let mut glue = Vec::new();
        for rr in &response.additionals {
            let owner = normalize(&rr.name);
            if !ns_names.iter().any(|ns| names_equal(ns, &owner)) {
                continue;
            }
            if !is_at_or_under(&owner, zone) {
                continue;
            }
            let port = self.config.server_port;
            match rr.rdata.parse() {
                Ok(ParsedRecord::A(addr)) => {
                    glue.push(SocketAddr::new(IpAddr::V4(addr), port));
                    ttl = ttl.min(rr.ttl.as_u64());
                }
                Ok(ParsedRecord::AAAA(addr)) => {
                    glue.push(SocketAddr::new(IpAddr::V6(addr), port));
                    ttl = ttl.min(rr.ttl.as_u64());
                }
                _ => {}
            }
        }

        Ok(Some(Referral {
            zone: child_zone,
            ns_names,
            glue,
            ttl: if ttl == u64::MAX { 0 } else { ttl },
        }))
    }

    /// Resolve nameserver names to addresses, for delegations that came without
    /// usable glue. Stops at the first name that yields an address; each lookup
    /// is charged to the budget.
    ///
    /// A first, then AAAA only if A found nothing: a dual-stacked nameserver
    /// costs one query, and an IPv6-only glueless delegation still resolves.
    async fn resolve_nameserver_addresses(
        &self,
        ns_names: &[String],
        state: &mut Resolution,
        depth: usize,
    ) -> ResolveResult<Vec<SocketAddr>> {
        const A: u16 = 1;
        const AAAA: u16 = 28;
        for name in ns_names {
            let mut addrs: Vec<SocketAddr> = Vec::new();
            for qtype in [Qtype::of(Rtype::new(A)), Qtype::of(Rtype::new(AAAA))] {
                let lookup = QuerySection {
                    qname: name.clone(),
                    qtype,
                    qclass: crate::QueryClass::IN,
                };
                // Boxed: this closes the resolution cycle, and an `async fn`
                // future may not contain itself by value.
                let Ok(response) = Box::pin(self.resolve_from_root(&lookup, state, depth)).await
                else {
                    continue;
                };
                addrs.extend(
                    response
                        .answers
                        .iter()
                        .filter_map(|rr| match rr.rdata.parse() {
                            Ok(ParsedRecord::A(addr)) => {
                                Some(SocketAddr::new(IpAddr::V4(addr), self.config.server_port))
                            }
                            Ok(ParsedRecord::AAAA(addr)) => {
                                Some(SocketAddr::new(IpAddr::V6(addr), self.config.server_port))
                            }
                            _ => None,
                        }),
                );
                if !addrs.is_empty() {
                    break;
                }
            }
            if !addrs.is_empty() {
                return Ok(addrs);
            }
        }
        Ok(Vec::new())
    }

    async fn query_server(
        &self,
        upstream: &SocketAddr,
        out: &OutgoingQuery,
    ) -> ResolveResult<DnsMessage> {
        // tokio's UdpSocket has no read timeout of its own.
        let read_timeout = Duration::from_millis(self.config.timeout_ms / 2);
        // Same family as the target: a v4-wildcard socket cannot connect to a v6
        // address. Port 0 keeps the source port random — that is anti-spoofing.
        let bind_addr = if upstream.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(upstream).await?;

        socket.send(&out.buf).await?;

        // Sized to the payload advertised via EDNS.
        let mut response_buf = vec![0; self.config.udp_payload_size as usize];
        let n = tokio::time::timeout(read_timeout, socket.recv(&mut response_buf)).await??;

        response_buf.truncate(n);
        let response = DnsMessage::try_from_bytes(&response_buf)?;

        // The connected socket filters by source address; the id and the echoed
        // (0x20-cased) name are the entropy an off-path spoofer must also match.
        if !self.response_matches(&response, out) {
            return Err(ResolveError::no_response(format!(
                "reply from {upstream} did not match the query"
            )));
        }

        // RFC 1035 §4.2.1: retry a truncated answer over TCP, on the *same*
        // upstream — TC is about the datagram, not the server's health.
        if response.truncation {
            return self.query_upstream_tcp(upstream, out).await;
        }

        Ok(response)
    }

    /// Re-issue a query over TCP, length-prefixed (RFC 1035 §4.2.2).
    ///
    /// A still-truncated response is returned as-is: TCP is the last resort, so
    /// the partial answer plus TC beats a hard failure.
    async fn query_upstream_tcp(
        &self,
        upstream: &SocketAddr,
        out: &OutgoingQuery,
    ) -> ResolveResult<DnsMessage> {
        if out.buf.len() > TCP_MAX_MESSAGE {
            return Err(ResolveError::no_response(format!(
                "query of {} bytes exceeds the 2-byte TCP length prefix",
                out.buf.len()
            )));
        }

        // Applied to each of connect, write and read.
        let timeout = Duration::from_millis(self.config.timeout_ms / 2);
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(upstream)).await??;

        // One write so prefix and message share a segment. The length is checked
        // rather than cast: a wrapped prefix reads as a broken stream.
        let framed = crate::framed(&out.buf)?;
        tokio::time::timeout(timeout, stream.write_all(&framed)).await??;

        let mut len_buf = [0u8; 2];
        tokio::time::timeout(timeout, stream.read_exact(&mut len_buf)).await??;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Err(ResolveError::no_response(format!(
                "upstream {} sent a zero-length TCP message",
                upstream
            )));
        }

        let mut response_buf = vec![0; len];
        tokio::time::timeout(timeout, stream.read_exact(&mut response_buf)).await??;
        let response = DnsMessage::try_from_bytes(&response_buf)?;

        // TCP is not off-path spoofable, but a mismatched id or question still
        // means a confused peer, not an answer to trust.
        if !self.response_matches(&response, out) {
            return Err(ResolveError::no_response(format!(
                "TCP reply from {upstream} did not match the query"
            )));
        }
        Ok(response)
    }

    /// Decide how much of `response` is authentic.
    ///
    /// Chain of trust first, signatures second. Checking signatures first and
    /// chasing the chain only if they pass lets an attacker choose the key that
    /// validates their own data.
    async fn validate(
        &self,
        query: &QuerySection,
        response: &DnsMessage,
        state: &mut Resolution,
        anchors: &TrustAnchors,
    ) -> ValidationState {
        let now = current_unix_timestamp();

        // "Negative" is not `answers.is_empty()`: a CNAME chain ending without
        // the queried type is a negative answer with a non-empty answer section.
        // RFC 4035 §5.4 keys the proof to the name actually denied, which after a
        // chain is the end of the chain, not the name asked about.
        let shape = cname_chain_shape(&query.qname, query.qtype, &response.answers);
        let denied_name = match &shape {
            ChainShape::Intact { final_name } => final_name.clone(),
            // Judged after the signatures, so an unsigned zone still reads
            // Insecure rather than Bogus.
            ChainShape::Broken(_) => normalize(&query.qname),
        };
        let holds_the_answer = response
            .answers
            .iter()
            .any(|rr| query.qtype.matches(rr.rdata.rtype()) && names_equal(&rr.name, &denied_name));
        let negative = !holds_the_answer;

        // Both sections: the proof is in the authority section, but a
        // CNAME-terminated "no" also hands the client real records.
        let mut records: Vec<ResourceRecord> = response.answers.clone();
        if negative {
            records.extend(response.authorities.iter().cloned());
        }

        // Every zone that put its name to something here.
        let mut signers: Vec<String> = Vec::new();
        for sig in records.iter().filter_map(Rrsig::from_record) {
            if !signers.contains(&sig.signer_name) {
                signers.push(sig.signer_name);
            }
        }

        // Nothing signed is either an unsigned zone or a signed one stripped in
        // flight; only the chain walk tells the two apart.
        if signers.is_empty() {
            let mut keys = KeyStore::new();
            return match self
                .establish_chain(&query.qname, state, anchors, now, &mut keys)
                .await
            {
                ValidationState::Secure => ValidationState::Bogus(format!(
                    "{} lies in a signed zone but nothing in the answer is signed",
                    query.qname
                )),
                other => other,
            };
        }

        let mut keys = KeyStore::new();
        for signer in &signers {
            match self
                .establish_chain(signer, state, anchors, now, &mut keys)
                .await
            {
                ValidationState::Secure => {}
                // The chain ends in an unsigned zone, so the signature means
                // nothing and cannot be held against it either.
                other => return other,
            }
        }

        let validator = ChainValidator::new(anchors, now);
        let verdict = validator.validate_records(&records, &keys);
        if !verdict.state.is_secure() {
            return verdict.state;
        }

        // A signature over a denial says the records are authentic, not that
        // they deny what was asked; without this check a valid NSEC from
        // elsewhere in the zone stands in for a proof it does not make.
        if negative {
            // A chain that is not a chain must not be laundered into a denial:
            // its "final name" is not one we asked about.
            if let ChainShape::Broken(why) = shape {
                return ValidationState::Bogus(why);
            }
            return self.check_denial(query, &denied_name, response);
        }

        // Shape, independently of signatures: a genuine CNAME beside a genuine A
        // for an unrelated name is two valid RRsets and no chain. Checked here
        // rather than in `recurse`'s per-hop filter so it also covers an answer
        // that arrived whole from a forwarder.
        if let ChainShape::Broken(why) = shape {
            return ValidationState::Bogus(why);
        }

        // A wildcard's signature verifies at every name it could expand to, so a
        // verified answer is not yet an answer *about* the name asked. The denial
        // that makes it one may have arrived on an earlier hop of a CNAME chase.
        if !verdict.wildcards.is_empty() {
            let mut proofs = response.authorities.clone();
            proofs.extend(state.denials.iter().cloned());
            return validator.validate_wildcard_proofs(&verdict.wildcards, &proofs, &keys);
        }
        ValidationState::Secure
    }

    /// Walk from a trust anchor down to `target`, filling `keys` with the
    /// validated DNSKEY set of every zone on the way.
    ///
    /// Returns [`ValidationState::Secure`] when `target`'s own zone was
    /// reached and is signed, `Insecure` when the chain provably ends above it,
    /// and `Bogus` when it breaks.
    async fn establish_chain(
        &self,
        target: &str,
        state: &mut Resolution,
        anchors: &TrustAnchors,
        now: u64,
        keys: &mut KeyStore,
    ) -> ValidationState {
        let validator = ChainValidator::new(anchors, now);
        let Some((anchor_zone, anchor_ds)) = validator.start(target) else {
            return ValidationState::Indeterminate(format!("no trust anchor covers {target}"));
        };

        // Resume as deep as already trusted, by the same rule `best_start` used
        // to pick where the resolution began. Disagreeing makes the walk skip a
        // zone cut whose DS this loop then goes looking for.
        let (mut zone, mut ds_set) = (anchor_zone.clone(), anchor_ds);
        for candidate in ancestors(&normalize(target)) {
            if is_at_or_under(&candidate, &anchor_zone) && self.keys.holds(&candidate) {
                // Cached keys were validated to the anchor already, so the DS
                // that got us there is not needed again.
                zone = candidate;
                ds_set = Vec::new();
                break;
            }
        }

        // A chain is at most one zone cut per label, plus the anchor.
        let max_steps = label_count(target) + 2;
        for _ in 0..max_steps {
            let zone_keys = match self.keys.get(&zone) {
                Some(cached) => cached,
                None => {
                    let (records, ttl) = match self.fetch_dnskeys(&zone, state).await {
                        Ok(found) => found,
                        Err(e) => {
                            return ValidationState::Bogus(format!(
                                "could not fetch the DNSKEY RRset for {zone}: {e:#}"
                            ))
                        }
                    };
                    match validator.validate_dnskeys(&zone, &records, &ds_set) {
                        Ok(validated) => {
                            self.keys.insert(&zone, validated.clone(), ttl);
                            validated
                        }
                        Err(other) => return other,
                    }
                }
            };
            keys.insert(zone.clone(), zone_keys.clone());

            if names_equal(&zone, target) {
                return ValidationState::Secure;
            }

            let Some(evidence) = state.next_cut_below(&zone, target).cloned() else {
                // No cut below: the target is served out of this zone, so these
                // keys are the ones that signed it.
                return ValidationState::Secure;
            };

            match validator.validate_delegation(&evidence, &zone, &zone_keys) {
                DelegationVerdict::Secure(ds) => {
                    ds_set = ds;
                    zone = evidence.zone.clone();
                }
                DelegationVerdict::Insecure(_) => return ValidationState::Insecure,
                DelegationVerdict::Bogus(why) => return ValidationState::Bogus(why),
            }
        }

        ValidationState::Bogus(format!("the chain of trust to {target} does not terminate"))
    }

    /// Fetch a zone's DNSKEY RRset, returning the records and the TTL to cache
    /// the conclusion for.
    async fn fetch_dnskeys(
        &self,
        zone: &str,
        state: &mut Resolution,
    ) -> Result<(Vec<ResourceRecord>, u64), ResolveError> {
        let query = QuerySection {
            qname: zone.to_string(),
            qtype: Qtype::of(rt::DNSKEY),
            qclass: crate::QueryClass::IN,
        };
        let response = match self.config.mode {
            ResolverMode::Forward => Box::pin(self.forward(&query, state)).await?,
            ResolverMode::Recurse => Box::pin(self.resolve_from_root(&query, state, 0)).await?,
        };
        let ttl = response
            .answers
            .iter()
            .filter(|rr| rr.rdata.rtype() == rt::DNSKEY)
            .map(|rr| rr.ttl.as_u64())
            .min()
            .unwrap_or(0);
        Ok((response.answers, ttl))
    }

    /// Check that the NSEC/NSEC3 records deny what was asked, not merely that
    /// they are correctly signed. `denied_name` is the end of the CNAME chain,
    /// not the name asked about (RFC 4035 §5.4).
    fn check_denial(
        &self,
        query: &QuerySection,
        denied_name: &str,
        response: &DnsMessage,
    ) -> ValidationState {
        let nsecs = nsecs_in(&response.authorities);
        let nsec3s = nsec3s_in(&response.authorities);
        if nsecs.is_empty() && nsec3s.is_empty() {
            // A signed zone answering "no" without proof; common from a
            // middlebox, but not something to pass on as authenticated.
            return ValidationState::Bogus(format!(
                "{denied_name} was denied without an NSEC or NSEC3 proof"
            ));
        }

        // The zone the proof came from — the SOA in the authority section names
        // it, and failing that the shallowest NSEC owner we were given.
        let zone = response
            .authorities
            .iter()
            .find(|rr| rr.rdata.rtype() == rt::SOA)
            .map(|rr| normalize(&rr.name))
            .unwrap_or_else(|| denied_name.to_string());

        let denial = if response.rcode == ResponseCode::NoSuchDomain {
            proves_nxdomain(denied_name, &zone, &nsecs, &nsec3s)
        } else {
            proves_nodata(
                denied_name,
                &zone,
                Rtype::new(query.qtype.to_u16()),
                &nsecs,
                &nsec3s,
            )
        };

        match denial {
            Denial::Proved => ValidationState::Secure,
            Denial::NotProved(why) => ValidationState::Bogus(format!(
                "the denial of {denied_name} does not prove it: {why}"
            )),
        }
    }
}

/// Absolute, lowercased form — the shape every comparison here assumes.
///
/// The owning spelling of [`crate::utils::absolute_lowered`], for call sites
/// that keep the result as a map key or set member. To merely *compare* two
/// names use [`crate::utils::names_equal`], which does not allocate.
fn normalize(name: &str) -> String {
    absolute_lowered(name).into_owned()
}

/// Scramble the case of each ASCII letter in `name`. Names are compared
/// case-insensitively (RFC 4343), so this changes only the bit pattern on the
/// wire — which a reply must echo back (0x20).
fn randomize_case(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() && rand::random::<bool>() {
                c.to_ascii_uppercase()
            } else if c.is_ascii_alphabetic() {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Class;
    use crate::Serial;
    use crate::Ttl;
    use crate::{ParsedRecord, QueryClass, RecordData, ResourceRecord};
    // The fake servers below are blocking `std::net` on their own OS threads;
    // these shadow the async tokio `UdpSocket`/`TcpStream` from `super::*`.
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn test_query() -> QuerySection {
        QuerySection {
            qname: "example.com.".to_string(),
            qtype: Qtype::of(rt::A),
            qclass: QueryClass::IN,
        }
    }

    /// Forwarding to one fake upstream.
    fn test_config(upstream: SocketAddr) -> ResolverConfig {
        ResolverConfig {
            mode: ResolverMode::Forward,
            upstream_servers: vec![upstream],
            timeout_ms: 4000,
            ..ResolverConfig::default()
        }
    }

    /// Recursing from a fake root. The whole fake hierarchy shares
    /// `root.port()` — see [`bind_hierarchy`].
    fn recursing_config(root: SocketAddr) -> ResolverConfig {
        ResolverConfig {
            mode: ResolverMode::Recurse,
            root_hints: vec![root],
            timeout_ms: 4000,
            server_port: root.port(),
            ..ResolverConfig::default()
        }
    }

    /// A minimal NOERROR response echoing `query`'s id and question.
    fn response_to(query: &DnsMessage) -> DnsMessage {
        DnsMessage {
            id: query.id,
            response: true,
            opcode: crate::OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: true,
            recursion_ok: true,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: query.queries.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        }
    }

    fn a_record(name: &str, addr: [u8; 4]) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::from(addr))).unwrap(),
        }
    }

    /// Bind a UDP socket and a TCP listener on the *same* 127.0.0.1 port, so one
    /// `SocketAddr` stands in for an upstream on both transports.
    ///
    /// Scans fixed ports rather than asking for port 0: Windows carves
    /// per-protocol exclusion blocks out of the ephemeral range, so "bind 0 on
    /// one protocol, match it on the other" can fail every attempt in a row.
    fn bind_fake_upstream() -> (UdpSocket, TcpListener, SocketAddr) {
        let start = 20_000 + (rand::random::<u16>() % 20_000);
        for offset in 0..500u16 {
            let port = 20_000 + (start - 20_000 + offset) % 20_000;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            if let Ok(udp) = UdpSocket::bind(addr) {
                if let Ok(tcp) = TcpListener::bind(addr) {
                    return (udp, tcp, addr);
                }
            }
        }
        panic!("could not bind a matching UDP/TCP port pair");
    }

    #[test]
    fn test_resolver_config_default() {
        let config = ResolverConfig::default();
        // Recursion is the default; forwarding is opt-in by naming an upstream.
        assert_eq!(config.mode, ResolverMode::Recurse);
        assert_eq!(
            config.root_hints.len(),
            26,
            "v4 and v6 for each of the 13 root servers"
        );
        // Interleaved: the first two are a.root-servers.net v4 then v6.
        assert!(config.root_hints[0].is_ipv4());
        assert!(config.root_hints[1].is_ipv6());
        assert!(!config.upstream_servers.is_empty());
        assert!(config.timeout_ms > 0);
        assert!(config.max_delegations > 0);
        assert!(config.query_budget > 0);
        // QNAME minimization is on by default (RFC 9156 §2.1).
        assert!(config.qname_minimization);
        // 0x20 case randomization is on by default too.
        assert!(config.zero_x20);
    }

    #[test]
    fn test_label_count_and_suffix() {
        assert_eq!(label_count("."), 0);
        assert_eq!(label_count("com."), 1);
        assert_eq!(label_count("example.com"), 2);
        assert_eq!(label_count("www.example.com."), 3);

        // The minimized name is [`crate::utils::suffix_labels`] now, which is
        // tested there; this holds the shape this walk asks it for.
        assert_eq!(crate::utils::suffix_labels("www.example.com.", 0), ".");
        assert_eq!(crate::utils::suffix_labels("www.example.com.", 1), "com.");
        assert_eq!(
            crate::utils::suffix_labels("www.example.com.", 2),
            "example.com."
        );
        assert_eq!(
            crate::utils::suffix_labels("www.example.com.", 3),
            "www.example.com."
        );
        // Asking for more labels than the name has yields the whole name.
        assert_eq!(
            crate::utils::suffix_labels("www.example.com.", 9),
            "www.example.com."
        );
    }

    #[test]
    fn test_randomize_case_changes_only_case() {
        let name = "www.Example.com.";
        for _ in 0..64 {
            let scrambled = randomize_case(name);
            // Same name, just different casing: structure and letters preserved.
            assert_eq!(scrambled.to_ascii_lowercase(), name.to_ascii_lowercase());
            assert_eq!(scrambled.len(), name.len());
            assert!(names_equal(&scrambled, name));
        }
        // Digits, hyphens and dots are untouched.
        let mixed = "9-a.b.";
        assert_eq!(randomize_case(mixed).to_ascii_lowercase(), mixed);
        for c in randomize_case(mixed)
            .chars()
            .filter(|c| !c.is_ascii_alphabetic())
        {
            assert!("9-.".contains(c));
        }
    }

    #[test]
    fn test_parse_root_hints() {
        let sample = "\
; sample named.root hints
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
B.ROOT-SERVERS.NET.      3600000  IN  A     170.247.170.2
this line has no record and is skipped
";
        assert_eq!(
            parse_root_hints(sample),
            vec![
                "198.41.0.4:53".parse().unwrap(),
                "[2001:503:ba3e::2:30]:53".parse().unwrap(),
                "170.247.170.2:53".parse().unwrap(),
            ]
        );

        // NS-only and empty input yield no addresses.
        assert!(parse_root_hints("").is_empty());
        assert!(parse_root_hints(".  3600000  NS  A.ROOT-SERVERS.NET.").is_empty());
    }

    #[test]
    fn test_resolver_creation() {
        let resolver = Resolver::with_defaults();
        assert_eq!(resolver.mode(), ResolverMode::Recurse);

        let forwarding = Resolver::forwarding_to(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        )]);
        assert_eq!(forwarding.mode(), ResolverMode::Forward);
        assert_eq!(forwarding.config.upstream_servers.len(), 1);
    }

    /// The budget is what stops one client query becoming unbounded upstream
    /// work; at zero, nothing is asked at all.
    #[tokio::test]
    async fn test_query_budget_is_enforced() {
        let config = ResolverConfig {
            mode: ResolverMode::Forward,
            upstream_servers: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)],
            timeout_ms: 1000,
            query_budget: 0,
            ..ResolverConfig::default()
        };
        let resolver = Resolver::new(config);

        let result = resolver.resolve(&test_query()).await;
        assert!(result.is_err());
    }

    /// A UDP server that answers with whatever the closure builds. Stops when
    /// the returned guard is dropped, so tests don't leak threads.
    struct FakeServer {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Drop for FakeServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    /// Bind `count` sockets on distinct loopback addresses that all share one
    /// port.
    ///
    /// One port because glue carries no port: the resolver always dials
    /// `server_port`, so the fake servers differ only by address.
    fn bind_hierarchy(count: usize) -> Vec<UdpSocket> {
        assert!(count <= 8, "loopback aliases used here stop at 127.0.0.8");
        let start = 20_000 + (rand::random::<u16>() % 20_000);

        for offset in 0..500u16 {
            let port = 20_000 + (start - 20_000 + offset) % 20_000;
            let mut socks = Vec::with_capacity(count);
            let bound =
                (0..count).all(
                    |i| match UdpSocket::bind(format!("127.0.0.{}:{}", i + 1, port)) {
                        Ok(s) => {
                            socks.push(s);
                            true
                        }
                        Err(_) => false,
                    },
                );
            if bound {
                return socks;
            }
        }
        panic!("could not bind a shared port across loopback addresses");
    }

    fn spawn_server<F>(socket: UdpSocket, answer: F) -> FakeServer
    where
        F: Fn(&DnsMessage) -> DnsMessage + Send + 'static,
    {
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();

        let handle = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while !flag.load(Ordering::Relaxed) {
                let Ok((n, peer)) = socket.recv_from(&mut buf) else {
                    continue; // read timeout; re-check the stop flag
                };
                let Ok(query) = DnsMessage::try_from_bytes(&buf[..n]) else {
                    continue;
                };
                let response = answer(&query);
                let mut out = vec![0u8; 4096];
                if let Ok(len) = response.to_bytes(&mut out) {
                    let _ = socket.send_to(&out[..len], peer);
                }
            }
        });

        FakeServer {
            addr,
            stop,
            handle: Some(handle),
        }
    }

    fn ns_record(owner: &str, target: &str) -> ResourceRecord {
        ResourceRecord {
            name: owner.to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NS(target.to_string())).unwrap(),
        }
    }

    fn cname_record(owner: &str, target: &str) -> ResourceRecord {
        ResourceRecord {
            name: owner.to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::CNAME(target.to_string())).unwrap(),
        }
    }

    /// A referral: no answer, NS in authority, optional glue in additional.
    fn referral(
        query: &DnsMessage,
        zone: &str,
        ns_name: &str,
        glue: Option<(&str, SocketAddr)>,
    ) -> DnsMessage {
        let mut resp = response_to(query);
        resp.authoritive = false;
        resp.authorities = vec![ns_record(zone, ns_name)];
        if let Some((glue_name, addr)) = glue {
            let IpAddr::V4(v4) = addr.ip() else {
                panic!("test glue must be IPv4")
            };
            resp.additionals = vec![a_record(glue_name, v4.octets())];
        }
        resp
    }

    fn authoritative(query: &DnsMessage, answers: Vec<ResourceRecord>) -> DnsMessage {
        let mut resp = response_to(query);
        resp.authoritive = true;
        resp.answers = answers;
        resp
    }

    fn qname_of(query: &DnsMessage) -> String {
        query
            .queries
            .first()
            .map(|q| normalize(&q.qname))
            .unwrap_or_default()
    }

    /// Root → TLD → authoritative, following glue at each step.
    #[tokio::test]
    async fn test_recursion_follows_the_delegation_chain() {
        let mut socks = bind_hierarchy(3).into_iter();
        let (root_sock, tld_sock, auth_sock) = (
            socks.next().unwrap(),
            socks.next().unwrap(),
            socks.next().unwrap(),
        );
        let tld_addr = tld_sock.local_addr().unwrap();
        let auth_addr = auth_sock.local_addr().unwrap();

        let _auth = spawn_server(auth_sock, |q| {
            authoritative(q, vec![a_record("www.example.test.", [192, 0, 2, 1])])
        });
        let _tld = spawn_server(tld_sock, move |q| {
            referral(
                q,
                "example.test.",
                "ns.example.test.",
                Some(("ns.example.test.", auth_addr)),
            )
        });
        let root = spawn_server(root_sock, move |q| {
            referral(q, "test.", "ns.test.", Some(("ns.test.", tld_addr)))
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        let answer = resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("recursion should reach the authoritative server");

        assert_eq!(answer.answers.len(), 1);
        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))
        );
    }

    /// A referral to a zone that is not an ancestor of the name we are chasing
    /// is a hijack attempt and must not be followed. The root here tries to
    /// hand off `evil.test.` while we are asking for `www.example.test.`.
    #[tokio::test]
    async fn test_out_of_bailiwick_referral_is_not_followed() {
        let mut socks = bind_hierarchy(2).into_iter();
        let (root_sock, evil_sock) = (socks.next().unwrap(), socks.next().unwrap());
        let evil_addr = evil_sock.local_addr().unwrap();

        let _evil = spawn_server(evil_sock, |q| {
            authoritative(q, vec![a_record(&qname_of(q), [6, 6, 6, 6])])
        });
        let root = spawn_server(root_sock, move |q| {
            referral(
                q,
                "evil.test.",
                "ns.evil.test.",
                Some(("ns.evil.test.", evil_addr)),
            )
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        let result = resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await;

        // The referral is ignored, so the walk ends at the root's own (empty)
        // response rather than reaching the attacker's server.
        let answers = result.map(|r| r.answers).unwrap_or_default();
        assert!(
            answers.is_empty(),
            "must not accept an answer from an out-of-bailiwick delegation"
        );
    }

    /// Glue is trusted only for names inside the responding server's own zone.
    /// Demonstrated below the root, which is authoritative for `.` and so has
    /// everything in bailiwick.
    #[tokio::test]
    async fn test_out_of_bailiwick_glue_is_ignored() {
        let mut socks = bind_hierarchy(3).into_iter();
        let (root_sock, tld_sock, attacker_sock) = (
            socks.next().unwrap(),
            socks.next().unwrap(),
            socks.next().unwrap(),
        );
        let tld_addr = tld_sock.local_addr().unwrap();
        let attacker_addr = attacker_sock.local_addr().unwrap();

        let _attacker = spawn_server(attacker_sock, |q| {
            authoritative(q, vec![a_record(&qname_of(q), [6, 6, 6, 6])])
        });

        // The `test.` server delegates example.test. but supplies glue for a
        // name outside `test.` entirely, pointing at the attacker.
        let _tld = spawn_server(tld_sock, move |q| {
            referral(
                q,
                "example.test.",
                "ns.example.test.",
                Some(("ns.elsewhere.invalid.", attacker_addr)),
            )
        });
        let root = spawn_server(root_sock, move |q| {
            referral(q, "test.", "ns.test.", Some(("ns.test.", tld_addr)))
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        let result = resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await;

        // With that glue rejected the delegation is glueless, and resolving
        // ns.example.test. goes nowhere in this fake hierarchy — so the resolve
        // fails rather than returning the attacker's address.
        let answers = result.map(|r| r.answers).unwrap_or_default();
        assert!(
            !answers.iter().any(|rr| {
                matches!(rr.rdata.parse(), Ok(ParsedRecord::A(a)) if a == Ipv4Addr::new(6, 6, 6, 6))
            }),
            "must not follow out-of-bailiwick glue"
        );
    }

    /// A CNAME is followed, and every record along the chain is returned.
    #[tokio::test]
    async fn test_cname_chain_is_followed() {
        let mut socks = bind_hierarchy(2).into_iter();
        let (root_sock, auth_sock) = (socks.next().unwrap(), socks.next().unwrap());
        let auth_addr = auth_sock.local_addr().unwrap();

        let _auth = spawn_server(auth_sock, |q| {
            let name = qname_of(q);
            if name == "www.example.test." {
                authoritative(
                    q,
                    vec![cname_record("www.example.test.", "real.example.test.")],
                )
            } else {
                authoritative(q, vec![a_record("real.example.test.", [192, 0, 2, 9])])
            }
        });
        let root = spawn_server(root_sock, move |q| {
            referral(
                q,
                "example.test.",
                "ns.example.test.",
                Some(("ns.example.test.", auth_addr)),
            )
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        let answer = resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("CNAME should be chased to the address");

        assert_eq!(answer.answers.len(), 2, "CNAME and the A it leads to");
        assert_eq!(answer.answers[0].rdata.rtype(), rt::CNAME);
        assert_eq!(
            answer.answers[1].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 9))
        );
    }

    /// A CNAME pointing back at itself must terminate, not spin.
    #[tokio::test]
    async fn test_cname_loop_is_detected() {
        let mut socks = bind_hierarchy(2).into_iter();
        let (root_sock, auth_sock) = (socks.next().unwrap(), socks.next().unwrap());
        let auth_addr = auth_sock.local_addr().unwrap();

        let _auth = spawn_server(auth_sock, |q| {
            let name = qname_of(q);
            let next = if name == "a.example.test." {
                "b.example.test."
            } else {
                "a.example.test."
            };
            authoritative(q, vec![cname_record(&name, next)])
        });
        let root = spawn_server(root_sock, move |q| {
            referral(
                q,
                "example.test.",
                "ns.example.test.",
                Some(("ns.example.test.", auth_addr)),
            )
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        let result = resolver
            .resolve(&QuerySection {
                qname: "a.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await;

        let err = result
            .expect_err("a CNAME loop must be an error")
            .to_string();
        assert!(
            err.to_string().contains("loop")
                || err.to_string().contains("budget")
                || err.to_string().contains("hops"),
            "unexpected error: {err}"
        );
    }

    /// A delegation with no glue costs a nested resolution of the nameserver's
    /// own name — which must work, and must be charged to the same budget.
    #[tokio::test]
    async fn test_glueless_delegation_is_resolved() {
        let mut socks = bind_hierarchy(3).into_iter();
        let (root_sock, tld_sock, auth_sock) = (
            socks.next().unwrap(),
            socks.next().unwrap(),
            socks.next().unwrap(),
        );
        let tld_addr = tld_sock.local_addr().unwrap();
        let auth_addr = auth_sock.local_addr().unwrap();

        // Authoritative for example.test., and also holds the A for
        // ns.hoster.test. — which must be this server's real address, since the
        // resolver dials whatever the A says.
        let IpAddr::V4(auth_ip) = auth_addr.ip() else {
            unreachable!("bound on IPv4 loopback")
        };
        let _auth = spawn_server(auth_sock, move |q| {
            let name = qname_of(q);
            if name == "ns.hoster.test." {
                authoritative(q, vec![a_record(&name, auth_ip.octets())])
            } else {
                authoritative(q, vec![a_record(&name, [192, 0, 2, 7])])
            }
        });
        // `example.test.` glueless (its nameserver is outside that zone) and
        // `hoster.test.` with glue, so the nameserver lookup can succeed.
        let _tld = spawn_server(tld_sock, move |q| {
            let name = qname_of(q);
            if name.ends_with("hoster.test.") {
                referral(
                    q,
                    "hoster.test.",
                    "ns.hoster.test.",
                    Some(("ns.hoster.test.", auth_addr)),
                )
            } else {
                referral(q, "example.test.", "ns.hoster.test.", None)
            }
        });
        let root = spawn_server(root_sock, move |q| {
            referral(q, "test.", "ns.test.", Some(("ns.test.", tld_addr)))
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        let answer = resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("glueless delegation should resolve via the nameserver's name");

        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 7))
        );
    }

    /// A server that refers to itself forever must be stopped by the budget
    /// rather than looping until the client times out.
    #[tokio::test]
    async fn test_referral_loop_is_bounded() {
        let root_sock = bind_hierarchy(1).into_iter().next().unwrap();
        let self_addr = root_sock.local_addr().unwrap();

        // Refers `example.test.` to a nameserver whose glue points back at this
        // same server, so the walk never makes progress.
        let root = spawn_server(root_sock, move |q| {
            referral(
                q,
                "example.test.",
                "ns.example.test.",
                Some(("ns.example.test.", self_addr)),
            )
        });

        let resolver = Resolver::new(ResolverConfig {
            query_budget: 12,
            ..recursing_config(root.addr)
        });
        let result = resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await;

        assert!(
            result.is_err(),
            "a referral loop must terminate in an error"
        );
    }

    /// A shared log of the QNAMEs a fake server was asked.
    type SeenLog = Arc<Mutex<Vec<String>>>;

    /// A root/TLD/auth hierarchy where each server records the QNAME it was
    /// asked. All three ignore the QTYPE, so the minimized probes and the final
    /// query share one server.
    fn recording_hierarchy() -> (
        FakeServer,
        FakeServer,
        FakeServer,
        SeenLog,
        SeenLog,
        SeenLog,
    ) {
        let mut socks = bind_hierarchy(3).into_iter();
        let (root_sock, tld_sock, auth_sock) = (
            socks.next().unwrap(),
            socks.next().unwrap(),
            socks.next().unwrap(),
        );
        let tld_addr = tld_sock.local_addr().unwrap();
        let auth_addr = auth_sock.local_addr().unwrap();

        let (root_seen, tld_seen, auth_seen) = (
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(Mutex::new(Vec::new())),
        );

        let a = auth_seen.clone();
        let auth = spawn_server(auth_sock, move |q| {
            a.lock().unwrap().push(qname_of(q));
            authoritative(q, vec![a_record("www.example.test.", [192, 0, 2, 1])])
        });
        let t = tld_seen.clone();
        let tld = spawn_server(tld_sock, move |q| {
            t.lock().unwrap().push(qname_of(q));
            referral(
                q,
                "example.test.",
                "ns.example.test.",
                Some(("ns.example.test.", auth_addr)),
            )
        });
        let r = root_seen.clone();
        let root = spawn_server(root_sock, move |q| {
            r.lock().unwrap().push(qname_of(q));
            referral(q, "test.", "ns.test.", Some(("ns.test.", tld_addr)))
        });

        (root, tld, auth, root_seen, tld_seen, auth_seen)
    }

    /// With minimization on (the default), the root is asked only for the TLD
    /// and the TLD only for the delegated zone; the leaf name reaches only the
    /// server authoritative for it.
    #[tokio::test]
    async fn test_qname_minimization_reveals_only_the_delegated_label() {
        let (root, _tld, _auth, root_seen, tld_seen, auth_seen) = recording_hierarchy();

        let resolver = Resolver::new(recursing_config(root.addr));
        let answer = resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("minimized recursion should still reach the answer");

        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(root_seen.lock().unwrap().as_slice(), ["test.".to_string()]);
        assert_eq!(
            tld_seen.lock().unwrap().as_slice(),
            ["example.test.".to_string()]
        );
        assert_eq!(
            auth_seen.lock().unwrap().as_slice(),
            ["www.example.test.".to_string()]
        );
    }

    /// With minimization off, the full name goes to every server up the chain.
    #[tokio::test]
    async fn test_minimization_disabled_sends_the_full_name() {
        let (root, _tld, _auth, root_seen, tld_seen, _auth_seen) = recording_hierarchy();

        let resolver = Resolver::new(ResolverConfig {
            qname_minimization: false,
            ..recursing_config(root.addr)
        });
        resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("recursion should reach the answer without minimization");

        assert_eq!(
            root_seen.lock().unwrap().as_slice(),
            ["www.example.test.".to_string()]
        );
        assert_eq!(
            tld_seen.lock().unwrap().as_slice(),
            ["www.example.test.".to_string()]
        );
    }

    /// An empty non-terminal — a name with no records of its own but with
    /// descendants — costs one extra probe: the intermediate NS query returns
    /// NODATA (not a referral), so the resolver deepens by a label and asks the
    /// same server again, rather than mistaking NODATA for a final answer.
    #[tokio::test]
    async fn test_qname_minimization_probes_an_empty_non_terminal() {
        let mut socks = bind_hierarchy(3).into_iter();
        let (root_sock, tld_sock, auth_sock) = (
            socks.next().unwrap(),
            socks.next().unwrap(),
            socks.next().unwrap(),
        );
        let tld_addr = tld_sock.local_addr().unwrap();
        let auth_addr = auth_sock.local_addr().unwrap();

        // The leaf www.sub.example.test. has an A; its parent is an empty
        // non-terminal, so everything else gets an authoritative NODATA.
        let auth_seen = Arc::new(Mutex::new(Vec::new()));
        let a = auth_seen.clone();
        let _auth = spawn_server(auth_sock, move |q| {
            let name = qname_of(q);
            a.lock().unwrap().push(name.clone());
            if name == "www.sub.example.test." {
                authoritative(q, vec![a_record(&name, [192, 0, 2, 8])])
            } else {
                authoritative(q, vec![])
            }
        });
        let _tld = spawn_server(tld_sock, move |q| {
            referral(
                q,
                "example.test.",
                "ns.example.test.",
                Some(("ns.example.test.", auth_addr)),
            )
        });
        let root = spawn_server(root_sock, move |q| {
            referral(q, "test.", "ns.test.", Some(("ns.test.", tld_addr)))
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        let answer = resolver
            .resolve(&QuerySection {
                qname: "www.sub.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("the empty non-terminal must be probed through, not stopped at");

        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 8))
        );
        // The empty non-terminal was probed first, then the leaf.
        assert_eq!(
            auth_seen.lock().unwrap().as_slice(),
            [
                "sub.example.test.".to_string(),
                "www.sub.example.test.".to_string()
            ]
        );
    }

    /// Past MAX_MINIMISE_COUNT (RFC 9156 §2.3, recommended 10) a deep name falls
    /// back to the full QNAME rather than spending the budget one label at a
    /// time. Also pins the probe QTYPE at A, not RFC 7816's superseded NS.
    #[tokio::test]
    async fn deep_names_stop_minimizing_at_the_rfc_9156_ceiling() {
        let mut socks = bind_hierarchy(3).into_iter();
        let (root_sock, tld_sock, auth_sock) = (
            socks.next().unwrap(),
            socks.next().unwrap(),
            socks.next().unwrap(),
        );
        let tld_addr = tld_sock.local_addr().unwrap();
        let auth_addr = auth_sock.local_addr().unwrap();

        // Twelve empty non-terminals below the apex, then the leaf: deeper than
        // the ceiling, so the fallback has to happen for this to resolve.
        let leaf = "a.b.c.d.e.f.g.h.i.j.k.l.example.test.";

        // Recorded at every server: the ceiling bounds minimized probes for the
        // whole resolution, not per zone.
        let seen: Arc<Mutex<Vec<(String, Qtype)>>> = Arc::new(Mutex::new(Vec::new()));

        let a = seen.clone();
        let _auth = spawn_server(auth_sock, move |q| {
            let name = qname_of(q);
            let qtype = q
                .queries
                .first()
                .map(|q| q.qtype)
                .unwrap_or(Qtype::of(Rtype::new(0)));
            a.lock().unwrap().push((name.clone(), qtype));
            if name == "a.b.c.d.e.f.g.h.i.j.k.l.example.test." && qtype == Qtype::of(rt::A) {
                authoritative(q, vec![a_record(&name, [192, 0, 2, 9])])
            } else {
                authoritative(q, vec![])
            }
        });
        let t = seen.clone();
        let _tld = spawn_server(tld_sock, move |q| {
            t.lock().unwrap().push((
                qname_of(q),
                q.queries
                    .first()
                    .map(|q| q.qtype)
                    .unwrap_or(Qtype::of(Rtype::new(0))),
            ));
            referral(
                q,
                "example.test.",
                "ns.example.test.",
                Some(("ns.example.test.", auth_addr)),
            )
        });
        let r = seen.clone();
        let root = spawn_server(root_sock, move |q| {
            r.lock().unwrap().push((
                qname_of(q),
                q.queries
                    .first()
                    .map(|q| q.qtype)
                    .unwrap_or(Qtype::of(Rtype::new(0))),
            ));
            referral(q, "test.", "ns.test.", Some(("ns.test.", tld_addr)))
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        let answer = resolver
            .resolve(&QuerySection {
                qname: leaf.to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("a deep name must fall back to the full QNAME, not fail");

        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 9))
        );

        let seen = seen.lock().unwrap();
        let minimized: Vec<&(String, Qtype)> =
            seen.iter().filter(|(name, _)| name != leaf).collect();
        assert_eq!(
            minimized.len(),
            MAX_MINIMISE_COUNT,
            "the ceiling bounds the minimized probes, and every one of them \
             counts: {seen:?}"
        );
        assert!(
            minimized
                .iter()
                .all(|(_, qtype)| *qtype == MINIMIZED_PROBE_TYPE),
            "an intermediate probe asks for A, not NS (RFC 9156 §2.3): {minimized:?}"
        );
        // Fourteen labels deep: without the ceiling, thirteen probes.
        assert!(minimized.len() < 13, "no fallback happened: {minimized:?}");
        // Then the full name, once, with the type actually wanted.
        assert_eq!(seen.iter().filter(|(name, _)| name == leaf).count(), 1);
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

    /// A zone with two nameservers, one of which is unusable: the failing one is
    /// tried once, demoted, and then skipped — later queries go straight to the
    /// server that answered.
    #[tokio::test]
    async fn test_rtt_selection_skips_a_failing_server_after_the_first_try() {
        let mut socks = bind_hierarchy(3).into_iter();
        let (root_sock, bad_sock, good_sock) = (
            socks.next().unwrap(),
            socks.next().unwrap(),
            socks.next().unwrap(),
        );
        let bad_addr = bad_sock.local_addr().unwrap();
        let good_addr = good_sock.local_addr().unwrap();
        let IpAddr::V4(bad_ip) = bad_addr.ip() else {
            unreachable!("bound on IPv4 loopback")
        };
        let IpAddr::V4(good_ip) = good_addr.ip() else {
            unreachable!("bound on IPv4 loopback")
        };

        // Answers instantly with the wrong transaction id, so its replies are
        // rejected without costing a timeout. Counts how often it is asked.
        let bad_hits = Arc::new(AtomicUsize::new(0));
        let bh = bad_hits.clone();
        let _bad = spawn_server(bad_sock, move |q| {
            bh.fetch_add(1, Ordering::Relaxed);
            let mut r = response_to(q);
            r.id = q.id.wrapping_add(1);
            r
        });
        let _good = spawn_server(good_sock, move |q| {
            authoritative(q, vec![a_record(&qname_of(q), [192, 0, 2, 1])])
        });
        // Bad server listed first, so it is the one tried before any RTT is
        // known.
        let root = spawn_server(root_sock, move |q| {
            let mut resp = response_to(q);
            resp.authorities = vec![
                ns_record("example.test.", "ns1.example.test."),
                ns_record("example.test.", "ns2.example.test."),
            ];
            resp.additionals = vec![
                a_record("ns1.example.test.", bad_ip.octets()),
                a_record("ns2.example.test.", good_ip.octets()),
            ];
            resp
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        for name in [
            "one.example.test.",
            "two.example.test.",
            "three.example.test.",
        ] {
            let answer = resolver
                .resolve(&QuerySection {
                    qname: name.to_string(),
                    qtype: Qtype::of(rt::A),
                    qclass: QueryClass::IN,
                })
                .await
                .unwrap_or_else(|e| panic!("resolving {name}: {e}"));
            assert_eq!(
                answer.answers[0].rdata.parse().unwrap(),
                ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))
            );
        }

        assert_eq!(
            bad_hits.load(Ordering::Relaxed),
            1,
            "the failing server should be tried once, then skipped on later queries"
        );
    }

    #[test]
    fn test_ancestors_are_deepest_first() {
        assert_eq!(
            ancestors("www.example.com."),
            vec!["www.example.com.", "example.com.", "com.", "."]
        );
        assert_eq!(ancestors("com."), vec!["com.", "."]);
        assert_eq!(ancestors("."), vec!["."]);
    }

    /// The deepest cached zone wins, because it skips the most round trips.
    #[test]
    fn test_delegation_cache_prefers_the_deepest_match() {
        let cache = DelegationCache::new(16);
        let com: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let example: SocketAddr = "192.0.2.2:53".parse().unwrap();

        cache.insert("com.", vec![com], 3600);
        assert_eq!(
            cache.best_match("www.example.com.").unwrap(),
            ("com.".to_string(), vec![com])
        );

        cache.insert("example.com.", vec![example], 3600);
        assert_eq!(
            cache.best_match("www.example.com.").unwrap(),
            ("example.com.".to_string(), vec![example])
        );

        // An unrelated name still falls back to nothing.
        assert!(cache.best_match("example.org.").is_none());
    }

    #[test]
    fn test_delegation_cache_expiry_and_limits() {
        let cache = DelegationCache::new(16);
        let server: SocketAddr = "192.0.2.1:53".parse().unwrap();

        // A zero TTL means "don't cache".
        cache.insert("zero.test.", vec![server], 0);
        assert!(cache.best_match("zero.test.").is_none());

        // An entry already expired is not returned.
        {
            let mut entries = cache.entries.lock().unwrap();
            entries.insert(
                NameKeyBuf::new("stale.test."),
                CachedDelegation {
                    servers: vec![server],
                    expires_at: current_unix_timestamp().saturating_sub(1),
                },
            );
        }
        assert!(cache.best_match("stale.test.").is_none());

        // forget() drops a live entry.
        cache.insert("live.test.", vec![server], 3600);
        assert!(cache.best_match("live.test.").is_some());
        cache.forget("live.test.");
        assert!(cache.best_match("live.test.").is_none());

        // A zero-capacity cache stores nothing.
        let off = DelegationCache::new(0);
        off.insert("any.test.", vec![server], 3600);
        assert!(off.best_match("any.test.").is_none());
    }

    #[test]
    fn test_delegation_cache_evicts_at_capacity() {
        let cache = DelegationCache::new(2);
        let server: SocketAddr = "192.0.2.1:53".parse().unwrap();

        cache.insert("a.test.", vec![server], 3600);
        cache.insert("b.test.", vec![server], 7200);
        cache.insert("c.test.", vec![server], 7200);

        let entries = cache.entries.lock().unwrap();
        assert!(entries.len() <= 2, "cache must stay within capacity");
        // The soonest-to-expire entry is the one dropped.
        assert!(!entries.contains_key("a.test."));
    }

    /// A second query for the same zone must not go back to the root.
    #[tokio::test]
    async fn test_second_query_does_not_revisit_the_root() {
        let mut socks = bind_hierarchy(2).into_iter();
        let (root_sock, auth_sock) = (socks.next().unwrap(), socks.next().unwrap());
        let auth_addr = auth_sock.local_addr().unwrap();

        let _auth = spawn_server(auth_sock, |q| {
            authoritative(q, vec![a_record(&qname_of(q), [192, 0, 2, 5])])
        });

        let root_hits = Arc::new(AtomicUsize::new(0));
        let counter = root_hits.clone();
        let root = spawn_server(root_sock, move |q| {
            counter.fetch_add(1, Ordering::Relaxed);
            referral(
                q,
                "example.test.",
                "ns.example.test.",
                Some(("ns.example.test.", auth_addr)),
            )
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        for name in [
            "one.example.test.",
            "two.example.test.",
            "three.example.test.",
        ] {
            let answer = resolver
                .resolve(&QuerySection {
                    qname: name.to_string(),
                    qtype: Qtype::of(rt::A),
                    qclass: QueryClass::IN,
                })
                .await
                .unwrap_or_else(|e| panic!("resolving {name}: {e}"));
            assert_eq!(
                answer.answers[0].rdata.parse().unwrap(),
                ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 5))
            );
        }

        assert_eq!(
            root_hits.load(Ordering::Relaxed),
            1,
            "the root should be consulted once, then served from the delegation cache"
        );
    }

    /// A cached delegation that has gone stale must not fail the query: the
    /// resolver drops it and starts again from the root.
    #[tokio::test]
    async fn test_stale_delegation_falls_back_to_the_root() {
        let mut socks = bind_hierarchy(2).into_iter();
        let (root_sock, auth_sock) = (socks.next().unwrap(), socks.next().unwrap());
        let auth_addr = auth_sock.local_addr().unwrap();

        let _auth = spawn_server(auth_sock, |q| {
            authoritative(q, vec![a_record(&qname_of(q), [192, 0, 2, 6])])
        });
        let root = spawn_server(root_sock, move |q| {
            referral(
                q,
                "example.test.",
                "ns.example.test.",
                Some(("ns.example.test.", auth_addr)),
            )
        });

        // Short timeout: this deliberately talks to a black hole.
        let resolver = Resolver::new(ResolverConfig {
            timeout_ms: 300,
            ..recursing_config(root.addr)
        });

        // Poison the cache with a server that will never answer.
        let dead: SocketAddr = format!("192.0.2.99:{}", root.addr.port()).parse().unwrap();
        resolver
            .delegations
            .insert("example.test.", vec![dead], 3600);

        let answer = resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("a stale delegation must fall back to the root, not fail");

        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 6))
        );
    }

    /// A TC=1 UDP answer must be retried over TCP, and the TCP answer is what
    /// the caller gets (RFC 1035 §4.2.1).
    #[tokio::test]
    async fn test_tcp_fallback_on_truncated_udp_response() {
        let (udp, tcp, addr) = bind_fake_upstream();

        // UDP half: always truncate, never answer.
        let udp_thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, peer) = udp.recv_from(&mut buf).unwrap();
            let query = DnsMessage::try_from_bytes(&buf[..n]).unwrap();

            let mut resp = response_to(&query);
            resp.truncation = true;
            let mut out = vec![0u8; 512];
            let len = resp.to_bytes(&mut out).unwrap();
            udp.send_to(&out[..len], peer).unwrap();
        });

        // TCP half: the real answer, length-prefixed. Returns the length the
        // client claimed, so the test can check framing.
        let tcp_thread = thread::spawn(move || {
            let (mut stream, _) = tcp.accept().unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).unwrap();
            let claimed = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; claimed];
            stream.read_exact(&mut buf).unwrap();
            let query = DnsMessage::try_from_bytes(&buf).unwrap();

            let mut resp = response_to(&query);
            resp.answers
                .push(a_record("example.com.", [93, 184, 216, 34]));
            let mut out = vec![0u8; 4096];
            let n = resp.to_bytes(&mut out).unwrap();

            let mut framed = Vec::with_capacity(2 + n);
            framed.extend_from_slice(&(n as u16).to_be_bytes());
            framed.extend_from_slice(&out[..n]);
            stream.write_all(&framed).unwrap();

            (claimed, query.queries.first().map(|q| q.qname.clone()))
        });

        let resolver = Resolver::new(test_config(addr));
        let answer = resolver.resolve(&test_query()).await.unwrap();

        udp_thread.join().unwrap();
        let (claimed, tcp_qname) = tcp_thread.join().unwrap();

        // Compared case-insensitively: 0x20 randomizes the casing on the wire.
        assert!(
            claimed >= 12,
            "TCP length prefix {} is below a DNS header",
            claimed
        );
        assert_eq!(
            tcp_qname.as_deref().map(|n| n.to_ascii_lowercase()),
            Some("example.com.".to_string())
        );

        assert!(!answer.truncation);
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    /// A response that fits in a datagram must not touch TCP: nothing listens on
    /// the TCP side here, so a stray fallback would fail the connect.
    #[tokio::test]
    async fn test_no_tcp_fallback_when_response_fits() {
        let (udp, tcp, addr) = bind_fake_upstream();
        drop(tcp);

        let udp_thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, peer) = udp.recv_from(&mut buf).unwrap();
            let query = DnsMessage::try_from_bytes(&buf[..n]).unwrap();

            let mut resp = response_to(&query);
            resp.answers.push(a_record("example.com.", [10, 0, 0, 1]));
            let mut out = vec![0u8; 512];
            let len = resp.to_bytes(&mut out).unwrap();
            udp.send_to(&out[..len], peer).unwrap();
        });

        let resolver = Resolver::new(test_config(addr));
        let answer = resolver.resolve(&test_query()).await.unwrap();
        udp_thread.join().unwrap();

        assert_eq!(answer.answers.len(), 1);
        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    /// A TCP answer that is *itself* truncated is passed through, not rejected.
    #[tokio::test]
    async fn test_still_truncated_tcp_response_is_returned() {
        let (udp, tcp, addr) = bind_fake_upstream();

        let udp_thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, peer) = udp.recv_from(&mut buf).unwrap();
            let query = DnsMessage::try_from_bytes(&buf[..n]).unwrap();
            let mut resp = response_to(&query);
            resp.truncation = true;
            let mut out = vec![0u8; 512];
            let len = resp.to_bytes(&mut out).unwrap();
            udp.send_to(&out[..len], peer).unwrap();
        });

        let tcp_thread = thread::spawn(move || {
            let (mut stream, _) = tcp.accept().unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).unwrap();
            let mut buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            stream.read_exact(&mut buf).unwrap();
            let query = DnsMessage::try_from_bytes(&buf).unwrap();

            let mut resp = response_to(&query);
            resp.truncation = true;
            resp.answers.push(a_record("example.com.", [10, 0, 0, 2]));
            let mut out = vec![0u8; 4096];
            let n = resp.to_bytes(&mut out).unwrap();
            let mut framed = Vec::with_capacity(2 + n);
            framed.extend_from_slice(&(n as u16).to_be_bytes());
            framed.extend_from_slice(&out[..n]);
            stream.write_all(&framed).unwrap();
        });

        let resolver = Resolver::new(test_config(addr));
        let answer = resolver.resolve(&test_query()).await.unwrap();

        udp_thread.join().unwrap();
        tcp_thread.join().unwrap();

        assert!(answer.truncation);
        assert_eq!(answer.answers.len(), 1);
    }

    /// A zero-length TCP frame is a protocol error, not an empty message.
    #[tokio::test]
    async fn test_zero_length_tcp_frame_is_an_error() {
        let (udp, tcp, addr) = bind_fake_upstream();

        let udp_thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, peer) = udp.recv_from(&mut buf).unwrap();
            let query = DnsMessage::try_from_bytes(&buf[..n]).unwrap();
            let mut resp = response_to(&query);
            resp.truncation = true;
            let mut out = vec![0u8; 512];
            let len = resp.to_bytes(&mut out).unwrap();
            udp.send_to(&out[..len], peer).unwrap();
        });

        let tcp_thread = thread::spawn(move || {
            let (mut stream, _) = tcp.accept().unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).unwrap();
            let mut buf = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            stream.read_exact(&mut buf).unwrap();
            stream.write_all(&0u16.to_be_bytes()).unwrap();
        });

        let resolver = Resolver::new(test_config(addr));
        let result = resolver.resolve(&test_query()).await;

        udp_thread.join().unwrap();
        tcp_thread.join().unwrap();

        // The single upstream failed, so the resolve as a whole fails.
        assert!(result.is_err());
    }

    /// Flip the case of every ASCII letter, so the result differs from any
    /// input with at least one letter.
    fn flip_case(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect()
    }

    /// A fake upstream that answers `example.com.` but rewrites the echoed
    /// question with `mangle`, and optionally perturbs the id. Returns the
    /// resolve result so a test can assert accept/reject.
    async fn resolve_against_mangling_upstream(
        config: impl FnOnce(SocketAddr) -> ResolverConfig,
        mangle: fn(&str) -> String,
        break_id: bool,
    ) -> ResolveResult<DnsMessage> {
        let (udp, _tcp, addr) = bind_fake_upstream();
        let udp_thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, peer) = udp.recv_from(&mut buf).unwrap();
            let query = DnsMessage::try_from_bytes(&buf[..n]).unwrap();
            let mut resp = response_to(&query);
            if break_id {
                resp.id = query.id.wrapping_add(1);
            }
            if let Some(q) = resp.queries.first_mut() {
                q.qname = mangle(&q.qname);
            }
            resp.answers.push(a_record("example.com.", [10, 0, 0, 5]));
            let mut out = vec![0u8; 512];
            let len = resp.to_bytes(&mut out).unwrap();
            udp.send_to(&out[..len], peer).unwrap();
        });

        let resolver = Resolver::new(config(addr));
        let result = resolver.resolve(&test_query()).await;
        udp_thread.join().unwrap();
        result
    }

    /// With 0x20 on, a reply that does not echo the exact casing sent is
    /// rejected — a case-mangling middlebox, or an off-path spoofer.
    #[tokio::test]
    async fn test_zero_x20_rejects_a_reply_with_mangled_case() {
        let result = resolve_against_mangling_upstream(test_config, flip_case, false).await;
        assert!(
            result.is_err(),
            "a reply that doesn't echo the 0x20 casing must be rejected"
        );
    }

    /// With 0x20 off, the same case difference is fine: the question is compared
    /// case-insensitively (RFC 4343), as it always was.
    #[tokio::test]
    async fn test_zero_x20_disabled_accepts_a_case_insensitive_reply() {
        let config = |addr| ResolverConfig {
            zero_x20: false,
            ..test_config(addr)
        };
        let answer = resolve_against_mangling_upstream(config, flip_case, false)
            .await
            .expect("case-insensitive match must be accepted when 0x20 is off");
        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    /// A reply that echoes the question perfectly but carries the wrong
    /// transaction id is not an answer to our query, 0x20 or not.
    #[tokio::test]
    async fn test_reply_with_wrong_transaction_id_is_rejected() {
        // `mangle` leaves the case alone, so only the id is wrong.
        let result = resolve_against_mangling_upstream(test_config, |s| s.to_string(), true).await;
        assert!(
            result.is_err(),
            "a mismatched transaction id must be rejected"
        );
    }

    /// Reaching a server over IPv6 works only because `query_server` binds a
    /// socket of the target's family — the same thing that makes AAAA glue and
    /// the v6 root hints usable.
    #[tokio::test]
    async fn test_forwarding_reaches_an_ipv6_upstream() {
        let udp = UdpSocket::bind("[::1]:0").expect("IPv6 loopback should be available");
        let addr = udp.local_addr().unwrap();

        let udp_thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, peer) = udp.recv_from(&mut buf).unwrap();
            let query = DnsMessage::try_from_bytes(&buf[..n]).unwrap();
            let mut resp = response_to(&query);
            resp.answers
                .push(a_record("example.com.", [203, 0, 113, 5]));
            let mut out = vec![0u8; 512];
            let len = resp.to_bytes(&mut out).unwrap();
            udp.send_to(&out[..len], peer).unwrap();
        });

        let resolver = Resolver::new(test_config(addr));
        let answer = resolver.resolve(&test_query()).await.unwrap();
        udp_thread.join().unwrap();

        assert!(
            addr.is_ipv6(),
            "the upstream must be a v6 address for this test"
        );
        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(203, 0, 113, 5))
        );
    }

    // A signed hierarchy in-process: the tests below sign with `ring` at run
    // time and put the whole resolve path through it — root KSK/ZSK, a DS in
    // each parent, and a signature over the answer.

    use crate::dnssec_denial::build_type_bitmap;
    use crate::dnssec_test_util::{ds_record, TestZone};

    /// Root → `test.` → `example.test.`, every zone signed and every
    /// delegation carrying a DS.
    struct SignedHierarchy {
        root_addr: SocketAddr,
        anchors: TrustAnchors,
        // Held so the servers stay alive for the test's lifetime.
        _servers: Vec<FakeServer>,
    }

    /// A referral that also carries the parent's DNSSEC statement about the
    /// child — the DS RRset and its signature, or whatever `extra` supplies
    /// instead (an NSEC denial, or nothing at all, for the attack cases).
    fn signed_referral(
        query: &DnsMessage,
        zone: &str,
        ns_name: &str,
        glue: SocketAddr,
        extra: &[ResourceRecord],
    ) -> DnsMessage {
        let mut resp = referral(query, zone, ns_name, Some((ns_name, glue)));
        resp.authorities.extend_from_slice(extra);
        resp
    }

    /// A DS RRset for `child`, signed by `parent`.
    fn signed_ds(parent: &TestZone, child: &TestZone) -> Vec<ResourceRecord> {
        let ds = ds_record(&child.ds(2), Ttl::from_secs(3600));
        let sig = parent.sign_records(std::slice::from_ref(&ds));
        vec![ds, sig]
    }

    /// A signed NSEC at `name` proving there is no DS there, so the delegation
    /// is genuinely to an unsigned zone.
    fn signed_no_ds_proof(parent: &TestZone, name: &str) -> Vec<ResourceRecord> {
        let nsec = ResourceRecord {
            name: name.to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC {
                next_domain_name: "zz.test.".to_string(),
                type_bitmap: build_type_bitmap(&[rt::NS, rt::RRSIG, rt::NSEC]),
            })
            .unwrap(),
        };
        let sig = parent.sign_records(std::slice::from_ref(&nsec));
        vec![nsec, sig]
    }

    /// Stand up the hierarchy. `delegation` decides what the TLD says about
    /// `example.test.`, and `leaf` produces the authoritative server's answer
    /// for `www.example.test.` — the two knobs every test here turns.
    fn signed_hierarchy(
        delegation: impl Fn(&TestZone, &TestZone) -> Vec<ResourceRecord>,
        leaf: impl Fn(&TestZone) -> Vec<ResourceRecord> + Send + 'static,
    ) -> SignedHierarchy {
        signed_hierarchy_with(delegation, move |auth| (leaf(auth), Vec::new()))
    }

    /// As [`signed_hierarchy`], but the leaf's answer arrives with an authority
    /// section of its own — which is where a wildcard answer carries the NSEC
    /// that says the name it was expanded to has nothing of its own.
    fn signed_hierarchy_with(
        delegation: impl Fn(&TestZone, &TestZone) -> Vec<ResourceRecord>,
        leaf: impl Fn(&TestZone) -> (Vec<ResourceRecord>, Vec<ResourceRecord>) + Send + 'static,
    ) -> SignedHierarchy {
        let root = TestZone::new(".");
        let tld = TestZone::new("test.");
        let auth = TestZone::new("example.test.");

        let mut socks = bind_hierarchy(3).into_iter();
        let (root_sock, tld_sock, auth_sock) = (
            socks.next().unwrap(),
            socks.next().unwrap(),
            socks.next().unwrap(),
        );
        let tld_addr = tld_sock.local_addr().unwrap();
        let auth_addr = auth_sock.local_addr().unwrap();

        let anchors = TrustAnchors::new(vec![root.ds(2)]);

        // Everything each server will ever say is computed and signed up front,
        // so the closures below need only clone — the keys themselves never
        // cross a thread boundary.
        let root_keys = root.dnskey_records();
        let tld_keys = tld.dnskey_records();
        let auth_keys = auth.dnskey_records();
        let tld_ds = signed_ds(&root, &tld);
        let example_delegation = delegation(&tld, &auth);
        let (answers, leaf_authority) = leaf(&auth);
        let denial = signed_nxdomain_authority(&auth);
        let nsec3_denial = signed_nsec3_nxdomain_authority(&auth);
        // The same proof with the closest-encloser record removed. It still
        // *covers* the queried name, so a validator that only checked coverage
        // would call it proved.
        let nsec3_incomplete: Vec<ResourceRecord> = {
            let full = signed_nsec3_nxdomain_authority(&auth);
            // Keep the SOA (and its signature) and the covering record (and
            // its signature); drop the matching one.
            let mut kept = full[0..2].to_vec();
            kept.extend_from_slice(&full[4..6]);
            kept
        };
        let wildcard_nodata = signed_wildcard_nodata_authority(&auth, true);
        let stripped_wildcard = signed_wildcard_nodata_authority(&auth, false);
        let aliased_nodata = signed_nodata_authority(&auth, "chased.example.test.");
        // Signed up front like everything else here, so the closure below only
        // has to pick which of the two aliases was asked for.
        let alias_cname = cname_records(&auth, "chase.example.test.", "chased.example.test.");
        let stripped_alias_cname = cname_records(
            &auth,
            "stripped-chase.example.test.",
            "unproved.example.test.",
        );

        let auth_server = spawn_server(auth_sock, move |q| {
            let name = qname_of(q);
            let qtype = q
                .queries
                .first()
                .map(|x| x.qtype)
                .unwrap_or(Qtype::of(Rtype::new(0)));
            if name == "example.test." && qtype == Qtype::of(rt::DNSKEY) {
                authoritative(q, auth_keys.clone())
            } else if name == "www.example.test." {
                let mut resp = authoritative(q, answers.clone());
                resp.authorities = leaf_authority.clone();
                resp
            } else if name == "gone.example.test." {
                // A signed "no": SOA and an NSEC whose gap runs from the apex to
                // www, which covers both the name and the wildcard position.
                let mut resp = response_to(q);
                resp.authoritive = true;
                resp.rcode = ResponseCode::NoSuchDomain;
                resp.authorities = denial.clone();
                resp
            } else if name == "nsec3-gone.example.test." {
                // The same "no", proved with NSEC3 instead: a record matching the
                // closest encloser and one covering both the next closer name and
                // the wildcard position.
                let mut resp = response_to(q);
                resp.authoritive = true;
                resp.rcode = ResponseCode::NoSuchDomain;
                resp.authorities = nsec3_denial.clone();
                resp
            } else if name == "nsec3-incomplete.example.test." {
                let mut resp = response_to(q);
                resp.authoritive = true;
                resp.rcode = ResponseCode::NoSuchDomain;
                resp.authorities = nsec3_incomplete.clone();
                resp
            } else if name == "wild-nodata.example.test." && qtype == Qtype::of(rt::AAAA) {
                // A wildcard NODATA: the name does not exist, `*.example.test.`
                // answered, and it has an A but no AAAA. NOERROR with an empty
                // answer section.
                let mut resp = response_to(q);
                resp.authoritive = true;
                resp.authorities = wildcard_nodata.clone();
                resp
            } else if name == "stripped-wildcard.example.test." && qtype == Qtype::of(rt::AAAA) {
                // The same, with the record at the wildcard removed: what is
                // left covers the name but says nothing about what a wildcard
                // would have answered with.
                let mut resp = response_to(q);
                resp.authoritive = true;
                resp.authorities = stripped_wildcard.clone();
                resp
            } else if name == "chase.example.test." || name == "stripped-chase.example.test." {
                // An alias, answered with the CNAME alone — which is what makes
                // the response's answer section non-empty while holding none of
                // the data that was asked for.
                let records = if name == "chase.example.test." {
                    alias_cname.clone()
                } else {
                    stripped_alias_cname.clone()
                };
                authoritative(q, records)
            } else if name == "chased.example.test." && qtype == Qtype::of(rt::AAAA) {
                // The end of the chain: an A record but no AAAA, denied properly.
                let mut resp = response_to(q);
                resp.authoritive = true;
                resp.authorities = aliased_nodata.clone();
                resp
            } else if name == "unproved.example.test." && qtype == Qtype::of(rt::AAAA) {
                // The same NODATA with the proof stripped out, which is what an
                // attacker who cannot forge a signature does instead.
                let mut resp = response_to(q);
                resp.authoritive = true;
                resp
            } else {
                // Any other probe (the QNAME-minimized NS step) is answered
                // NODATA from the apex, which deepens the walk by a label.
                authoritative(q, Vec::new())
            }
        });

        let tld_server = spawn_server(tld_sock, move |q| {
            let name = qname_of(q);
            let qtype = q
                .queries
                .first()
                .map(|x| x.qtype)
                .unwrap_or(Qtype::of(Rtype::new(0)));
            if name == "test." && qtype == Qtype::of(rt::DNSKEY) {
                authoritative(q, tld_keys.clone())
            } else {
                signed_referral(
                    q,
                    "example.test.",
                    "ns.example.test.",
                    auth_addr,
                    &example_delegation,
                )
            }
        });

        let root_server = spawn_server(root_sock, move |q| {
            let name = qname_of(q);
            let qtype = q
                .queries
                .first()
                .map(|x| x.qtype)
                .unwrap_or(Qtype::of(Rtype::new(0)));
            if name == "." && qtype == Qtype::of(rt::DNSKEY) {
                authoritative(q, root_keys.clone())
            } else {
                signed_referral(q, "test.", "ns.test.", tld_addr, &tld_ds)
            }
        });

        SignedHierarchy {
            root_addr: root_server.addr,
            anchors,
            _servers: vec![root_server, tld_server, auth_server],
        }
    }

    /// A signed CNAME RRset at `owner` pointing at `target`.
    fn cname_records(auth: &TestZone, owner: &str, target: &str) -> Vec<ResourceRecord> {
        let cname = ResourceRecord {
            name: owner.to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::CNAME(target.to_string())).unwrap(),
        };
        let sig = auth.sign_records(std::slice::from_ref(&cname));
        vec![cname, sig]
    }

    /// The authority section of a signed NODATA at `name`: the SOA, and an NSEC
    /// *at* the name whose bitmap lists A but not AAAA — so it proves the name
    /// exists and has no AAAA, which is what a NODATA owes (RFC 4035 §5.4).
    fn signed_nodata_authority(auth: &TestZone, name: &str) -> Vec<ResourceRecord> {
        let soa = ResourceRecord {
            name: "example.test.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::SOA {
                mname: "ns.example.test.".to_string(),
                rname: "admin.example.test.".to_string(),
                serial: Serial::new(1),
                refresh: 10800,
                retry: 3600,
                expire: 604800,
                minimum: 300,
            })
            .unwrap(),
        };
        let nsec = ResourceRecord {
            name: name.to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC {
                next_domain_name: "zz.example.test.".to_string(),
                type_bitmap: build_type_bitmap(&[rt::A, rt::RRSIG, rt::NSEC]),
            })
            .unwrap(),
        };
        let soa_sig = auth.sign_records(std::slice::from_ref(&soa));
        let nsec_sig = auth.sign_records(std::slice::from_ref(&nsec));
        vec![soa, soa_sig, nsec, nsec_sig]
    }

    /// The authority section of a signed NXDOMAIN: the SOA, and one NSEC whose
    /// gap runs from the apex to `www` — which covers `gone.example.test.` and
    /// the `*.example.test.` wildcard position at once, so a single record
    /// makes the whole proof.
    fn signed_nxdomain_authority(auth: &TestZone) -> Vec<ResourceRecord> {
        let soa = ResourceRecord {
            name: "example.test.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::SOA {
                mname: "ns.example.test.".to_string(),
                rname: "admin.example.test.".to_string(),
                serial: Serial::new(1),
                refresh: 10800,
                retry: 3600,
                expire: 604800,
                minimum: 300,
            })
            .unwrap(),
        };
        let nsec = ResourceRecord {
            name: "example.test.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC {
                next_domain_name: "www.example.test.".to_string(),
                type_bitmap: build_type_bitmap(&[rt::SOA, rt::NS, rt::RRSIG, rt::NSEC]),
            })
            .unwrap(),
        };
        let soa_sig = auth.sign_records(std::slice::from_ref(&soa));
        let nsec_sig = auth.sign_records(std::slice::from_ref(&nsec));
        vec![soa, soa_sig, nsec, nsec_sig]
    }

    /// The authority section of a signed NXDOMAIN proved with NSEC3.
    ///
    /// Worth having end to end, because every NSEC3 test in this repo until now
    /// built its own records and handed them straight to the denial functions.
    /// That checks the proof logic and nothing about the path to it — whether the
    /// resolver collects NSEC3 records across hops, whether they survive being
    /// parsed off the wire, whether their signatures verify as an RRset at their
    /// hashed owner names. The NSEC side has been resolved end to end since it was
    /// written; this closes the gap for NSEC3 (an open item under #1).
    ///
    /// RFC 5155 §7.2.2 wants three things proved, and two records do it here:
    ///
    /// - an NSEC3 matching the closest encloser, `example.test.`;
    /// - an NSEC3 covering the next closer name, the queried name itself;
    /// - an NSEC3 covering `*.example.test.`, since a wildcard could
    ///   otherwise have answered.
    ///
    /// The covering record spans everything between an all-zero and an all-ones
    /// hash, so it covers the last two at once. Opt-out is deliberately clear: set,
    /// it would make this Insecure rather than Secure, which is a different test.
    fn signed_nsec3_nxdomain_authority(auth: &TestZone) -> Vec<ResourceRecord> {
        use crate::dnssec_denial::{base32hex_encode, nsec3_hash};

        let salt = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let iterations = 10u16;
        let zone = "example.test.";

        let soa = ResourceRecord {
            name: zone.to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::SOA {
                mname: "ns.example.test.".to_string(),
                rname: "admin.example.test.".to_string(),
                serial: Serial::new(1),
                refresh: 10800,
                retry: 3600,
                expire: 604800,
                minimum: 300,
            })
            .unwrap(),
        };

        let nsec3 = |owner_hash: &[u8], next: &[u8], types: &[Rtype]| ResourceRecord {
            // An NSEC3's owner name is the base32hex of the hash, under the zone
            // — which is why nothing about this shape can be checked without
            // hashing for real.
            name: format!("{}.{zone}", base32hex_encode(owner_hash)),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC3 {
                hash_algorithm: 1,
                flags: 0,
                iterations,
                salt: salt.clone(),
                next_hashed_owner: next.to_vec(),
                type_bitmap: build_type_bitmap(types),
            })
            .unwrap(),
        };

        let encloser = nsec3_hash(zone, &salt, iterations).expect("hash the encloser");
        let matching = nsec3(&encloser, &[0xff; 20], &[rt::SOA, rt::NS, rt::RRSIG]);
        let covering = nsec3(&[0x00; 20], &[0xff; 20], &[rt::RRSIG]);

        let soa_sig = auth.sign_records(std::slice::from_ref(&soa));
        let matching_sig = auth.sign_records(std::slice::from_ref(&matching));
        let covering_sig = auth.sign_records(std::slice::from_ref(&covering));
        vec![soa, soa_sig, matching, matching_sig, covering, covering_sig]
    }

    /// The authority section of a signed wildcard NODATA: the SOA, and the NSEC
    /// at `*.example.test.` whose bitmap carries A but not AAAA — and which also
    /// covers the queried name, since `*` sorts before every ordinary label, so
    /// one record shows both that the name does not exist and what the wildcard
    /// that answered for it holds.
    ///
    /// With `at_wildcard` false the record is moved off the wildcard to
    /// `m.example.test.`: it still covers the queried names, and proves nothing
    /// about what a wildcard would have answered.
    fn signed_wildcard_nodata_authority(auth: &TestZone, at_wildcard: bool) -> Vec<ResourceRecord> {
        let soa = ResourceRecord {
            name: "example.test.".to_string(),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::SOA {
                mname: "ns.example.test.".to_string(),
                rname: "admin.example.test.".to_string(),
                serial: Serial::new(1),
                refresh: 10800,
                retry: 3600,
                expire: 604800,
                minimum: 300,
            })
            .unwrap(),
        };
        let nsec = ResourceRecord {
            name: if at_wildcard {
                "*.example.test.".to_string()
            } else {
                "m.example.test.".to_string()
            },
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NSEC {
                next_domain_name: "zzz.example.test.".to_string(),
                type_bitmap: build_type_bitmap(&[rt::A, rt::RRSIG, rt::NSEC]),
            })
            .unwrap(),
        };
        let soa_sig = auth.sign_records(std::slice::from_ref(&soa));
        let nsec_sig = auth.sign_records(std::slice::from_ref(&nsec));
        vec![soa, soa_sig, nsec, nsec_sig]
    }

    /// A correctly signed A record, the ordinary case.
    fn signed_answer(auth: &TestZone) -> Vec<ResourceRecord> {
        let a = a_record("www.example.test.", [192, 0, 2, 1]);
        let sig = auth.sign_records(std::slice::from_ref(&a));
        vec![a, sig]
    }

    fn validating_config(h: &SignedHierarchy) -> ResolverConfig {
        ResolverConfig {
            dnssec: Some(h.anchors.clone().into()),
            ..recursing_config(h.root_addr)
        }
    }

    async fn resolve_www(config: ResolverConfig) -> (DnsMessage, ValidationState) {
        resolve_www_qtype(config, Qtype::of(rt::A)).await
    }

    async fn resolve_www_qtype(
        config: ResolverConfig,
        qtype: Qtype,
    ) -> (DnsMessage, ValidationState) {
        Resolver::new(config)
            .resolve_validated(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype,
                qclass: QueryClass::IN,
            })
            .await
            .expect("the resolution itself should succeed")
    }

    /// QTYPE=ANY is a *question* value, not a type any record has (RFC 1035
    /// §3.2.3), so `rr.rdata.rtype() == query.qtype` is false for every record in
    /// a perfectly good answer. The validator reads that as "the answer does not
    /// hold what was asked for", sets `negative`, and goes looking for a denial
    /// proof that a positive answer has no reason to carry — so an answer that
    /// verifies is reported Bogus, and `rdnsr --dnssec-validate` fails closed
    /// and returns SERVFAIL.
    ///
    /// Nothing on this path rejects or special-cases ANY, so a client asking
    /// for it reaches the comparison. The answer is the same signed A RRset
    /// `test_signed_hierarchy_validates_as_secure` calls Secure; only the QTYPE
    /// on the question changed.
    #[tokio::test]
    async fn an_any_query_is_a_positive_answer_and_must_not_be_read_as_a_denial() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let (answer, state) = resolve_www_qtype(validating_config(&h), Qtype::of(rt::ANY)).await;

        assert!(
            answer.answers.iter().any(|rr| matches!(
                rr.rdata.parse(),
                Ok(ParsedRecord::A(a)) if a == Ipv4Addr::new(192, 0, 2, 1)
            )),
            "the answer holds the A record ANY asked for"
        );
        assert_eq!(
            state,
            ValidationState::Secure,
            "an ANY answer that verifies is Secure, not {state}"
        );
    }

    /// The whole chain, end to end: the trust anchor vouches for the root's
    /// KSK, each zone's DS vouches for the next, and the answer's signature
    /// verifies under the keys that walk establishes.
    #[tokio::test]
    async fn test_signed_hierarchy_validates_as_secure() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let (answer, state) = resolve_www(validating_config(&h)).await;

        assert_eq!(state, ValidationState::Secure, "{state}");
        assert!(
            answer.answers.iter().any(|rr| matches!(
                rr.rdata.parse(),
                Ok(ParsedRecord::A(a)) if a == Ipv4Addr::new(192, 0, 2, 1)
            )),
            "the validated answer must still carry the address"
        );
        assert!(
            answer
                .answers
                .iter()
                .any(|rr| rr.rdata.rtype() == rt::RRSIG),
            "DO was set, so the signatures come back with the answer"
        );
    }

    /// The attack the whole apparatus exists to stop: the authoritative server
    /// hands over a different address alongside a perfectly genuine signature
    /// for the original one.
    #[tokio::test]
    async fn test_substituted_answer_is_bogus() {
        let h = signed_hierarchy(signed_ds, |auth| {
            let real = a_record("www.example.test.", [192, 0, 2, 1]);
            let sig = auth.sign_records(std::slice::from_ref(&real));
            // Same signature, different address.
            vec![a_record("www.example.test.", [6, 6, 6, 6]), sig]
        });

        let (_, state) = resolve_www(validating_config(&h)).await;
        assert!(state.is_bogus(), "expected bogus, got {state}");
    }

    /// A signature from a key the parent never vouched for. The zone's own
    /// DNSKEY RRset is what the DS commits to, so a substituted ZSK breaks
    /// that signature and the chain stops at the DNSKEY step.
    #[tokio::test]
    async fn test_answer_signed_by_an_unvouched_key_is_bogus() {
        let impostor = TestZone::new("example.test.");
        let h = signed_hierarchy(signed_ds, move |_auth| {
            let a = a_record("www.example.test.", [192, 0, 2, 1]);
            let sig = impostor.sign_records(std::slice::from_ref(&a));
            vec![a, sig]
        });

        let (_, state) = resolve_www(validating_config(&h)).await;
        assert!(state.is_bogus(), "expected bogus, got {state}");
    }

    /// The downgrade: strip the DS from the referral and serve the zone
    /// unsigned. Without a proof that there is no DS, "unsigned" is just a
    /// claim by whoever is answering.
    #[tokio::test]
    async fn test_stripped_ds_is_bogus_not_insecure() {
        let h = signed_hierarchy(
            |_parent, _child| Vec::new(),
            |_auth| vec![a_record("www.example.test.", [6, 6, 6, 6])],
        );

        let (_, state) = resolve_www(validating_config(&h)).await;
        assert!(
            state.is_bogus(),
            "a missing DS with nothing to back it must not read as unsigned: {state}"
        );
    }

    /// And the legitimate version of the same shape: the parent signs an NSEC
    /// saying there is no DS, so the child really is unsigned. The answer is
    /// served, without the AD bit.
    #[tokio::test]
    async fn test_proven_unsigned_delegation_is_insecure_and_still_answers() {
        let h = signed_hierarchy(
            |parent, _child| signed_no_ds_proof(parent, "example.test."),
            |_auth| vec![a_record("www.example.test.", [192, 0, 2, 4])],
        );

        let (answer, state) = resolve_www(validating_config(&h)).await;
        assert_eq!(state, ValidationState::Insecure, "{state}");
        assert!(
            answer.answers.iter().any(|rr| matches!(
                rr.rdata.parse(),
                Ok(ParsedRecord::A(a)) if a == Ipv4Addr::new(192, 0, 2, 4)
            )),
            "an insecure answer is still an answer — most of the internet is unsigned"
        );
    }

    /// An unsigned answer from a zone the chain says *is* signed is bogus: the
    /// signatures did not go missing by accident.
    #[tokio::test]
    async fn test_missing_signature_in_a_signed_zone_is_bogus() {
        let h = signed_hierarchy(signed_ds, |_auth| {
            vec![a_record("www.example.test.", [192, 0, 2, 1])]
        });

        let (_, state) = resolve_www(validating_config(&h)).await;
        assert!(state.is_bogus(), "expected bogus, got {state}");
    }

    /// With no anchors configured nothing is checked, and the state says so —
    /// "indeterminate", not "insecure": we did not establish that anything is
    /// unsigned, we simply never looked.
    #[tokio::test]
    async fn test_validation_disabled_is_indeterminate() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let (_, state) = resolve_www(recursing_config(h.root_addr)).await;
        assert!(
            matches!(state, ValidationState::Indeterminate(_)),
            "got {state}"
        );
    }

    /// A name outside every island of trust cannot be judged either way.
    #[tokio::test]
    async fn test_name_outside_the_anchors_is_indeterminate() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let config = ResolverConfig {
            // An anchor for an unrelated zone, and none for the root.
            dnssec: Some(
                TrustAnchors::parse("other.invalid. IN DS 1 13 2 AABB")
                    .unwrap()
                    .into(),
            ),
            ..recursing_config(h.root_addr)
        };
        let (_, state) = resolve_www(config).await;
        assert!(
            matches!(state, ValidationState::Indeterminate(_)),
            "got {state}"
        );
    }

    /// A signed "no" has to validate as thoroughly as a signed "yes" — and it
    /// is a different code path: the proof lives in the authority section, and
    /// being correctly signed is only half of it. The records must also *deny
    /// the thing that was asked*, which is what `check_denial` adds on top.
    #[tokio::test]
    async fn test_signed_nxdomain_validates_as_secure() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let (answer, state) = Resolver::new(validating_config(&h))
            .resolve_validated(&QuerySection {
                qname: "gone.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("the resolution itself should succeed");

        assert_eq!(state, ValidationState::Secure, "{state}");
        assert_eq!(answer.rcode, ResponseCode::NoSuchDomain);
        assert!(answer
            .authorities
            .iter()
            .any(|rr| rr.rdata.rtype() == rt::NSEC));
    }

    /// The NSEC3 denial path, end to end — the gap this closes is that every
    /// other NSEC3 test here builds its records and calls the proof functions
    /// directly, so nothing established that a hashed denial survives the trip
    /// through a real resolve: collected across hops, parsed off the wire, and
    /// verified as an RRset at owner names that are base32hex of a hash.
    #[tokio::test]
    async fn test_signed_nsec3_nxdomain_validates_as_secure() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let (answer, state) = Resolver::new(validating_config(&h))
            .resolve_validated(&QuerySection {
                qname: "nsec3-gone.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("the resolution itself should succeed");

        assert_eq!(state, ValidationState::Secure, "{state}");
        assert_eq!(answer.rcode, ResponseCode::NoSuchDomain);
        assert!(
            answer
                .authorities
                .iter()
                .any(|rr| rr.rdata.rtype() == rt::NSEC3),
            "the proof that came back is the hashed kind"
        );
        assert!(
            !answer
                .authorities
                .iter()
                .any(|rr| rr.rdata.rtype() == rt::NSEC),
            "and only the hashed kind — this zone has no plain NSEC to fall back on"
        );
    }

    /// And the test that the test means something: the same denial with the
    /// closest-encloser record taken out must not validate.
    ///
    /// It still *covers* the queried name and the wildcard, so a validator that
    /// checked coverage and stopped would call this proved — and would then accept
    /// a denial for any name in a zone from an attacker holding one covering
    /// record. RFC 5155 §7.2.2 wants the encloser shown to exist as well, which is
    /// what makes the span meaningful.
    #[tokio::test]
    async fn test_an_nsec3_denial_missing_its_closest_encloser_is_not_secure() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let (_, state) = Resolver::new(validating_config(&h))
            .resolve_validated(&QuerySection {
                qname: "nsec3-incomplete.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("the resolution itself should succeed");

        assert_ne!(
            state,
            ValidationState::Secure,
            "an incomplete NSEC3 proof must not read as proved"
        );
    }

    /// The point of RFC 8198, end to end: the NSEC that denied one name is a
    /// signed statement about a whole *range* of them, so once it is validated
    /// and cached, every other name in that gap is answered without asking
    /// anyone. This is the test that ties the resolver's validation to the
    /// denial cache — each is well covered alone, and the join is where a
    /// mistake would let unvalidated material through.
    #[tokio::test]
    async fn test_a_validated_denial_answers_other_names_in_its_gap() {
        use crate::nsec_cache::NsecCache;

        let h = signed_hierarchy(signed_ds, signed_answer);
        let (denial, state) = Resolver::new(validating_config(&h))
            .resolve_validated(&QuerySection {
                qname: "gone.example.test.".to_string(),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            })
            .await
            .expect("resolution should succeed");
        assert_eq!(state, ValidationState::Secure, "{state}");

        // Exactly what rdnsr does with a Secure negative answer.
        let cache = NsecCache::new(16);
        cache.insert_validated(&denial);

        // A name nobody has ever asked about, answered from the cached gap.
        let synthesized = cache
            .synthesize("never-queried.example.test.", Qtype::of(rt::A))
            .expect("the cached gap covers this name too");
        assert_eq!(synthesized.rcode, ResponseCode::NoSuchDomain);
        assert!(
            synthesized
                .authority
                .iter()
                .any(|rr| rr.rdata.rtype() == rt::SOA),
            "RFC 2308 §2.1 wants the SOA on a negative answer"
        );
        assert!(synthesized.ttl <= 300, "bounded by the SOA MINIMUM");

        // But a name outside the gap still has to be resolved.
        assert!(
            cache
                .synthesize("zzz.example.test.", Qtype::of(rt::A))
                .is_none(),
            "the gap ends at www.example.test."
        );
    }

    /// A wildcard NODATA, end to end: the name does not exist, `*.example.test.`
    /// is what answered, and it has no AAAA. The proof is a different pair of
    /// records from an ordinary NODATA — nothing sits at the name to carry a type
    /// bitmap — and insisting on the ordinary shape refused this outright.
    #[tokio::test]
    async fn test_wildcard_nodata_validates_as_secure() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let (answer, state) = Resolver::new(validating_config(&h))
            .resolve_validated(&QuerySection {
                qname: "wild-nodata.example.test.".to_string(),
                qtype: Qtype::of(rt::AAAA),
                qclass: QueryClass::IN,
            })
            .await
            .expect("the resolution itself should succeed");

        assert_eq!(state, ValidationState::Secure, "{state}");
        assert_eq!(
            answer.rcode,
            ResponseCode::Ok,
            "NODATA is NOERROR with no answer"
        );
        assert!(answer.answers.is_empty());
    }

    /// The same query with the record at the wildcard removed. What is left still
    /// covers the name, so a check that only asked "does the name exist" would
    /// pass it — but nothing says what a wildcard would have answered with, and
    /// the honest answer may have been an address.
    #[tokio::test]
    async fn test_wildcard_nodata_without_the_wildcards_own_nsec_is_bogus() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let (_, state) = Resolver::new(validating_config(&h))
            .resolve_validated(&QuerySection {
                qname: "stripped-wildcard.example.test.".to_string(),
                qtype: Qtype::of(rt::AAAA),
                qclass: QueryClass::IN,
            })
            .await
            .expect("the resolution itself should succeed");

        assert!(state.is_bogus(), "expected bogus, got {state}");
        assert!(
            state.reason().contains("*.example.test."),
            "it must fail for the missing wildcard record rather than by accident: {state}"
        );
    }

    /// A wildcard answer, end to end. The zone holds `*.example.test.` and no
    /// `www`, so the answer's signature is made at the wildcard — and the same
    /// signature would verify at any other name under `example.test.`, which is
    /// why the NSEC in the authority section is part of the answer rather than
    /// decoration.
    #[tokio::test]
    async fn test_wildcard_answer_with_its_nsec_is_secure() {
        let h = signed_hierarchy_with(signed_ds, |auth| wildcard_answer(auth, true));
        let (answer, state) = resolve_www(validating_config(&h)).await;

        assert_eq!(state, ValidationState::Secure, "{state}");
        assert!(
            answer.answers.iter().any(|rr| matches!(
                rr.rdata.parse(),
                Ok(ParsedRecord::A(a)) if a == Ipv4Addr::new(192, 0, 2, 9)
            )),
            "a validated wildcard answer is still an answer"
        );
    }

    /// The same answer with the proof left out. Nothing about the cryptography
    /// changed — this is the case that validated as Secure on the signature
    /// alone before the proof was demanded.
    #[tokio::test]
    async fn test_wildcard_answer_without_its_nsec_is_bogus() {
        let h = signed_hierarchy_with(signed_ds, |auth| wildcard_answer(auth, false));
        let (_, state) = resolve_www(validating_config(&h)).await;
        assert!(
            state.is_bogus(),
            "a wildcard answer with no denial of the queried name must not be served \
             as authentic: {state}"
        );
    }

    /// `www.example.test.` answered from `*.example.test.`, with or without the
    /// NSEC that completes the proof.
    ///
    /// The NSEC gap runs from the wildcard to `zzz.example.test.`, which covers
    /// `www` — `*` sorts before every ordinary label, so the wildcard's own NSEC
    /// is usually the record that covers the names it answers for.
    fn wildcard_answer(
        auth: &TestZone,
        with_proof: bool,
    ) -> (Vec<ResourceRecord>, Vec<ResourceRecord>) {
        let a = a_record("www.example.test.", [192, 0, 2, 9]);
        let sig = auth.sign_as_wildcard(std::slice::from_ref(&a), "*.example.test.");

        let mut authority = Vec::new();
        if with_proof {
            let nsec = ResourceRecord {
                name: "*.example.test.".to_string(),
                class: Class::new(1),
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::NSEC {
                    next_domain_name: "zzz.example.test.".to_string(),
                    type_bitmap: build_type_bitmap(&[rt::A, rt::RRSIG, rt::NSEC]),
                })
                .unwrap(),
            };
            let nsec_sig = auth.sign_records(std::slice::from_ref(&nsec));
            authority = vec![nsec, nsec_sig];
        }
        (vec![a, sig], authority)
    }

    /// A NODATA reached through a CNAME is validated like any other NODATA.
    ///
    /// The control for the test below: the terminal denial is there and correct,
    /// so the verdict is Secure — which has to be established separately, because
    /// the bug was that *everything* here came back Secure.
    #[tokio::test]
    async fn a_negative_answer_after_a_cname_is_validated() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let (answer, state) = Resolver::new(validating_config(&h))
            .resolve_validated(&QuerySection {
                qname: "chase.example.test.".to_string(),
                qtype: Qtype::of(rt::AAAA),
                qclass: QueryClass::IN,
            })
            .await
            .expect("the resolution itself should succeed");

        assert_eq!(state, ValidationState::Secure, "{state}");
        assert!(
            answer
                .answers
                .iter()
                .any(|rr| rr.rdata.rtype() == rt::CNAME),
            "the chain is still handed to the client"
        );
        assert!(
            !answer.answers.iter().any(|rr| rr.rdata.rtype() == rt::AAAA),
            "and it holds no AAAA, which is what makes this a negative answer"
        );
    }

    /// Strip the terminal denial after a legitimate CNAME and the answer used
    /// to be handed to clients as authenticated.
    ///
    /// `let negative = response.answers.is_empty()` was the test, and a CNAME
    /// chain is not empty: `negative` was false, so the authority section was
    /// never signature-verified, `check_denial` never ran, and `validate` fell
    /// through to Secure. `rdnsr` then set AD and cached it as validated. It was
    /// a downgrade relative to the non-CNAME path, which handled the same attack
    /// correctly — and it needed no forged signature, only deletion.
    ///
    /// RFC 4035 §5 requires a validator to authenticate negative responses;
    /// §5.4 keys the proof to the name actually denied, which after a chain is
    /// the end of the chain.
    #[tokio::test]
    async fn a_stripped_denial_after_a_cname_is_bogus() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let (_, state) = Resolver::new(validating_config(&h))
            .resolve_validated(&QuerySection {
                qname: "stripped-chase.example.test.".to_string(),
                qtype: Qtype::of(rt::AAAA),
                qclass: QueryClass::IN,
            })
            .await
            .expect("the resolution itself should succeed");

        assert!(
            state.is_bogus(),
            "a NODATA with its proof removed is not authentic, whatever led to it: {state}"
        );
    }

    /// A signed CNAME chain, end to end. There was no CNAME anywhere in these
    /// tests before, which mattered once the answer's *shape* became part of the
    /// verdict: a check that rejects incoherent answers is only useful if it
    /// accepts coherent ones, and the way to find out is to resolve one.
    ///
    /// Both RRsets come in a single response, which is what an authoritative
    /// server sends for a CNAME whose target it also holds.
    #[tokio::test]
    async fn test_a_signed_cname_chain_validates_as_secure() {
        let h = signed_hierarchy_with(signed_ds, |auth| {
            let cname = ResourceRecord {
                name: "www.example.test.".to_string(),
                class: Class::new(1),
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::CNAME(
                    "alias.example.test.".to_string(),
                ))
                .unwrap(),
            };
            let cname_sig = auth.sign_records(std::slice::from_ref(&cname));
            let target = a_record("alias.example.test.", [192, 0, 2, 44]);
            let target_sig = auth.sign_records(std::slice::from_ref(&target));
            (vec![cname, cname_sig, target, target_sig], Vec::new())
        });

        let (answer, state) = resolve_www(validating_config(&h)).await;
        assert_eq!(state, ValidationState::Secure, "{state}");
        assert!(
            answer
                .answers
                .iter()
                .any(|rr| rr.rdata.rtype() == rt::CNAME),
            "the chain itself comes back"
        );
        assert!(
            answer.answers.iter().any(|rr| matches!(
                rr.rdata.parse(),
                Ok(ParsedRecord::A(a)) if a == Ipv4Addr::new(192, 0, 2, 44)
            )),
            "and the address at the end of it"
        );
    }

    /// The positive half of RFC 8198 (section 5.3), end to end: a validated
    /// wildcard answer is a signed statement about every name the wildcard
    /// reaches, so once it is cached, another such name is answered without
    /// asking anyone.
    ///
    /// The counterpart to `test_a_validated_denial_answers_other_names_in_its_gap`
    /// and, like it, the test of the *join* — validation and the cache are each
    /// well covered alone, and a mistake between them is what would let a
    /// wildcard answer for a name it does not govern.
    #[tokio::test]
    async fn test_a_validated_wildcard_answers_other_names_it_reaches() {
        use crate::nsec_cache::NsecCache;

        let h = signed_hierarchy_with(signed_ds, |auth| wildcard_answer(auth, true));
        let (answer, state) = resolve_www(validating_config(&h)).await;
        assert_eq!(state, ValidationState::Secure, "{state}");

        // Exactly what rdnsr does with a Secure positive answer.
        let cache = NsecCache::new(16);
        cache.insert_validated_wildcard(&answer);

        // A name nobody has asked about, answered from the cached wildcard. The
        // gap in the proof runs from `*.example.test.` to `zzz.example.test.`, so
        // this name is inside it and provably absent.
        let synthesized = cache
            .synthesize_wildcard("never-asked.example.test.", Qtype::of(rt::A))
            .expect("the cached wildcard reaches this name too");
        assert!(
            synthesized.answers.iter().any(|rr| matches!(
                rr.rdata.parse(),
                Ok(ParsedRecord::A(a)) if a == Ipv4Addr::new(192, 0, 2, 9)
            )),
            "the address the wildcard holds"
        );
        for rr in &synthesized.answers {
            assert_eq!(
                rr.name, "never-asked.example.test.",
                "owned at the name asked for, as the zone would have sent it"
            );
        }
        assert!(
            synthesized
                .authority
                .iter()
                .any(|rr| rr.rdata.rtype() == rt::NSEC),
            "with the denial that makes the wildcard apply"
        );

        // And a name the wildcard does not govern is refused, however tempting
        // the covering NSEC looks: a wildcard reaches exactly one label.
        assert!(
            cache
                .synthesize_wildcard("deeper.never-asked.example.test.", Qtype::of(rt::A))
                .is_none(),
            "*.example.test. does not reach two labels down"
        );
    }

    /// The validated-key cache: a second query into the same zone must not
    /// re-walk the chain, or every answer costs a full revalidation.
    #[tokio::test]
    async fn test_validated_keys_are_cached_across_queries() {
        let h = signed_hierarchy(signed_ds, signed_answer);
        let resolver = Resolver::new(validating_config(&h));
        let query = QuerySection {
            qname: "www.example.test.".to_string(),
            qtype: Qtype::of(rt::A),
            qclass: QueryClass::IN,
        };

        let (_, first) = resolver.resolve_validated(&query).await.unwrap();
        assert_eq!(first, ValidationState::Secure, "{first}");
        assert!(
            resolver.keys.holds("example.test."),
            "the leaf zone's keys should be cached after one validated query"
        );
        assert!(resolver.keys.holds("."), "and the root's");

        let (_, second) = resolver.resolve_validated(&query).await.unwrap();
        assert_eq!(second, ValidationState::Secure, "{second}");
    }
}
