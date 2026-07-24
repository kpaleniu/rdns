//! The resolver: obtains an answer for a query, either by walking the
//! delegation chain from the root ourselves, or by asking a configured upstream
//! resolver to do it for us.
//!
//! These are two modes of one resolver rather than two programs, which is how
//! BIND, Unbound, Knot Resolver and PowerDNS Recursor all model it: the
//! client-facing half is identical, only the means of obtaining an answer
//! differs, and mixed deployments (forward one zone, recurse the rest) are
//! ordinary. See [`ResolverMode`].
//!
//! Everything here is synchronous `std::net`. `rdnsr` drives it from
//! `spawn_blocking`, so a resolution that takes several round trips occupies a
//! blocking thread rather than an async task. That is a deliberate trade for
//! now — see the note on [`Resolver::recurse`].

use crate::utils::current_unix_timestamp;
use crate::{DnsMessage, Edns, ParsedRecord, QuerySection, ResponseCode};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Mutex;
use std::time::Duration;
use anyhow::anyhow;

/// A DNS message sent over TCP is prefixed with a 2-byte big-endian length
/// (RFC 1035 §4.2.2), so no message can exceed what that field can express.
const TCP_MAX_MESSAGE: usize = u16::MAX as usize;

/// The IPv4 addresses of the 13 root servers, used to prime recursion.
///
/// Hard-coded as a fallback the way every resolver ships one; these do change
/// (b.root-servers.net moved to 170.247.170.2 in 2023), so a deployment that
/// cares should load the published hints file instead — `root_hints` in
/// [`ResolverConfig`] is what to override. A stale entry degrades rather than
/// breaks: servers are tried in turn until one answers.
const ROOT_HINTS: [Ipv4Addr; 13] = [
    Ipv4Addr::new(198, 41, 0, 4),      // a.root-servers.net
    Ipv4Addr::new(170, 247, 170, 2),   // b
    Ipv4Addr::new(192, 33, 4, 12),     // c
    Ipv4Addr::new(199, 7, 91, 13),     // d
    Ipv4Addr::new(192, 203, 230, 10),  // e
    Ipv4Addr::new(192, 5, 5, 241),     // f
    Ipv4Addr::new(192, 112, 36, 4),    // g
    Ipv4Addr::new(198, 97, 190, 53),   // h
    Ipv4Addr::new(192, 36, 148, 17),   // i
    Ipv4Addr::new(192, 58, 128, 30),   // j
    Ipv4Addr::new(193, 0, 14, 129),    // k
    Ipv4Addr::new(199, 7, 83, 42),     // l
    Ipv4Addr::new(202, 12, 27, 33),    // m
];

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
    /// CNAME hops and nameserver-address lookups.
    ///
    /// This is the NXNSAttack (2020) defence: a hostile zone can answer with a
    /// referral naming dozens of nameservers that have no glue, each of which
    /// costs us a full resolution to look up. Bounding the *total* work is what
    /// stops one client query from becoming hundreds of upstream ones.
    pub query_budget: usize,
    /// EDNS0 UDP payload size to advertise upstream (RFC 6891).
    pub udp_payload_size: u16,
    /// How many zone delegations to remember. 0 disables the cache, which makes
    /// every query restart at the root — correct, but only acceptable in tests.
    pub delegation_cache_size: usize,
    /// Port to contact a nameserver on once we have learned its address.
    ///
    /// Always 53 in practice — glue and address records carry an address but no
    /// port, so there is nothing else to go on. Configurable only so a test can
    /// stand up a fake root/TLD/authoritative hierarchy on an unprivileged one.
    pub server_port: u16,
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
            root_hints: ROOT_HINTS
                .iter()
                .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 53))
                .collect(),
            timeout_ms: 5000,
            max_delegations: 16,
            max_cname_hops: 8,
            query_budget: 64,
            udp_payload_size: 4096,
            delegation_cache_size: 10_000,
            server_port: 53,
        }
    }
}

/// Servers we have already learned for a zone, so a resolution can start
/// partway down the tree instead of at the root every time.
///
/// This is the difference between a toy recursor and a usable one. Without it
/// every client query costs a root round trip before it can even begin, which
/// is slow for us and — at any volume — abusive enough that root operators
/// rate-limit it. With it, the root is consulted roughly once per TLD per TTL.
#[derive(Debug)]
struct DelegationCache {
    entries: Mutex<HashMap<String, CachedDelegation>>,
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
    ///
    /// Deepest wins: knowing the servers for `example.com.` is worth more than
    /// knowing the ones for `com.`, because it skips a round trip.
    fn best_match(&self, qname: &str) -> Option<(String, Vec<SocketAddr>)> {
        let name = normalize(qname);
        let now = current_unix_timestamp();
        let mut entries = self.entries.lock().ok()?;

        for candidate in ancestors(&name) {
            match entries.get(&candidate) {
                Some(entry) if entry.expires_at > now => {
                    return Some((candidate, entry.servers.clone()));
                }
                Some(_) => {
                    entries.remove(&candidate);
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
            normalize(zone),
            CachedDelegation {
                servers,
                expires_at: current_unix_timestamp() + ttl.min(MAX_DELEGATION_TTL),
            },
        );
    }

    /// Drop a zone's entry, for when the servers in it turn out not to work.
    fn forget(&self, zone: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(&normalize(zone));
        }
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

/// Tracks how much work one client query has cost us.
struct Budget {
    remaining: usize,
}

impl Budget {
    fn new(total: usize) -> Self {
        Budget { remaining: total }
    }

    /// Charge one upstream query, or fail if the query has spent its budget.
    fn spend(&mut self) -> Result<(), anyhow::Error> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or_else(|| anyhow!("query budget exhausted"))?;
        Ok(())
    }
}

/// A DNS resolver. See [`ResolverMode`] for what it actually does.
pub struct Resolver {
    config: ResolverConfig,
    /// Shared across concurrent resolutions — `rdnsr` holds one `Resolver` in an
    /// `Arc` and resolves from many threads at once.
    delegations: DelegationCache,
}

impl Resolver {
    pub fn new(config: ResolverConfig) -> Self {
        let delegations = DelegationCache::new(config.delegation_cache_size);
        Resolver {
            config,
            delegations,
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

    /// Resolve a query (blocking).
    pub fn resolve(&self, query: &QuerySection) -> Result<DnsMessage, anyhow::Error> {
        let mut budget = Budget::new(self.config.query_budget);
        match self.config.mode {
            ResolverMode::Forward => self.forward(query, &mut budget),
            ResolverMode::Recurse => self.recurse(query, &mut budget),
        }
    }

    /// Forward the query to each upstream in turn and return the first answer.
    fn forward(
        &self,
        query: &QuerySection,
        budget: &mut Budget,
    ) -> Result<DnsMessage, anyhow::Error> {
        // RD=1: we are asking the upstream to do the recursion for us.
        let query_buf = self.build_query(query, true)?;

        for upstream in &self.config.upstream_servers {
            if budget.spend().is_err() {
                break;
            }
            match self.query_server(upstream, &query_buf) {
                Ok(response) => return Ok(response),
                Err(_) => continue, // Try next upstream
            }
        }

        Err(anyhow!(
            "failed to resolve {} with all upstream servers",
            query.qname
        ))
    }

    /// Serialize a query message. `recursion_desired` is false when we are
    /// walking the delegation chain ourselves — an authoritative server has no
    /// business recursing on our behalf, and asking it to is how open resolvers
    /// get abused.
    fn build_query(
        &self,
        query: &QuerySection,
        recursion_desired: bool,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let mut msg = DnsMessage {
            id: rand::random::<u16>(),
            response: false,
            opcode: crate::OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: recursion_desired,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![query.clone()],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        // Advertise EDNS0 so the responder may exceed 512 bytes.
        msg.set_edns(Edns::with_payload_size(self.config.udp_payload_size))?;

        let mut buf = vec![0; 512];
        let len = msg.to_bytes(&mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Resolve by walking the delegation chain, following any CNAME chain the
    /// answer leads through.
    ///
    /// Note on threading: each hop is a blocking round trip, so a resolution
    /// from cold occupies its thread for the sum of them (root + TLD +
    /// authoritative, more with glueless delegations). `rdnsr` runs this under
    /// `spawn_blocking`, which is correct but not free — converting the
    /// resolver to async is the obvious follow-up once this is proven.
    fn recurse(
        &self,
        query: &QuerySection,
        budget: &mut Budget,
    ) -> Result<DnsMessage, anyhow::Error> {
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
                return Err(anyhow!("CNAME loop at {qname}"));
            }
            if hop == self.config.max_cname_hops {
                return Err(anyhow!(
                    "CNAME chain longer than {} hops",
                    self.config.max_cname_hops
                ));
            }

            let step = QuerySection {
                qname: qname.clone(),
                qtype: query.qtype,
                qclass: query.qclass.clone(),
            };
            let response = self.resolve_from_root(&step, budget, 0)?;

            // Keep only records that belong to the chain we actually asked
            // about — the name in hand, plus whatever a CNAME we have accepted
            // points at. A server volunteering records for unrelated names is
            // trying to get them into our cache, and `rdnsr` caches whatever we
            // return here.
            for rr in &response.answers {
                if !chain.contains(&normalize(&rr.name)) {
                    continue;
                }
                answers.push(rr.clone());
                if rr.rdata.rtype == 5 {
                    if let Ok(ParsedRecord::CNAME(target)) = rr.rdata.parse() {
                        // Extends the chain within this same response.
                        chain.insert(normalize(&target));
                    }
                }
            }

            // Done if we got the type we asked for, or if there is no CNAME to
            // follow (an empty answer is NODATA/NXDOMAIN, which is an answer).
            let got_type = response
                .answers
                .iter()
                .any(|rr| rr.rdata.rtype == query.qtype && names_equal(&rr.name, &qname));
            let cname = response
                .answers
                .iter()
                .filter(|rr| rr.rdata.rtype == 5 && names_equal(&rr.name, &qname))
                .find_map(|rr| match rr.rdata.parse() {
                    Ok(ParsedRecord::CNAME(target)) => Some(normalize(&target)),
                    _ => None,
                });

            last = Some(response);
            if got_type || cname.is_none() || query.qtype == 5 {
                break;
            }
            qname = cname.expect("checked is_none above");
        }

        let mut response = last.ok_or_else(|| anyhow!("no response for {}", query.qname))?;
        // Present the whole chain under the question the client actually asked.
        response.queries = vec![query.clone()];
        response.answers = answers;
        response.authoritive = false;
        Ok(response)
    }

    /// One name's worth of delegation walking: start at the root hints and
    /// follow referrals until a server answers authoritatively.
    ///
    /// `depth` counts *nested* resolutions — looking up a nameserver's address
    /// re-enters here — and is capped separately from the query budget so a
    /// chain of glueless delegations cannot recurse without bound.
    fn resolve_from_root(
        &self,
        query: &QuerySection,
        budget: &mut Budget,
        depth: usize,
    ) -> Result<DnsMessage, anyhow::Error> {
        const MAX_NESTED: usize = 4;
        if depth > MAX_NESTED {
            return Err(anyhow!("nameserver lookup nested deeper than {MAX_NESTED}"));
        }

        // Start as far down the tree as we already know how to, rather than at
        // the root every time.
        if let Some((zone, servers)) = self.delegations.best_match(&query.qname) {
            match self.walk(query, budget, depth, zone.clone(), servers) {
                Ok(response) => return Ok(response),
                Err(_) => {
                    // A cached delegation goes stale: servers get renumbered,
                    // zones move. Drop it and start over from the root rather
                    // than failing a query on our own bookkeeping.
                    self.delegations.forget(&zone);
                }
            }
        }

        self.walk(
            query,
            budget,
            depth,
            ".".to_string(),
            self.config.root_hints.clone(),
        )
    }

    /// The delegation walk proper, from a known starting point.
    fn walk(
        &self,
        query: &QuerySection,
        budget: &mut Budget,
        depth: usize,
        start_zone: String,
        start_servers: Vec<SocketAddr>,
    ) -> Result<DnsMessage, anyhow::Error> {
        let qname = normalize(&query.qname);
        let query_buf = self.build_query(query, false)?;

        // The zone whose servers we are currently talking to. Everything they
        // tell us is judged against this: a server for `com.` may delegate
        // `example.com.` but may not answer for `example.org.`.
        let mut zone = start_zone;
        let mut servers = start_servers;

        for _ in 0..self.config.max_delegations {
            let Some(response) = self.ask_any(&servers, &query_buf, budget) else {
                return Err(anyhow!("no server for {zone} answered while resolving {qname}"));
            };

            // An answer, or an authoritative "no" (NXDOMAIN / NODATA), ends the
            // walk. Both are results; only a referral continues it.
            if !response.answers.is_empty() || response.authoritive {
                return Ok(response);
            }

            let referral = self.extract_referral(&response, &zone, &qname)?;
            let Some(Referral {
                zone: child_zone,
                ns_names,
                glue,
                ttl,
            }) = referral
            else {
                // No answer, not authoritative, and nothing we are willing to
                // follow. That is a lame delegation (or a referral that doesn't
                // advance, e.g. a server pointing at its own zone), and it must
                // not be passed off to the client: an empty NOERROR reads as a
                // definitive "no such record", which this is not. Failing here
                // becomes SERVFAIL, which is the honest answer.
                return Err(anyhow!(
                    "lame delegation: {zone} gave no answer and no usable referral for {qname}"
                ));
            };

            servers = if glue.is_empty() {
                // Glueless delegation: the referral named servers but gave no
                // usable addresses, so each one costs a resolution of its own.
                self.resolve_nameserver_addresses(&ns_names, budget, depth + 1)?
            } else {
                glue
            };

            if servers.is_empty() {
                return Err(anyhow!("no reachable nameserver for {child_zone}"));
            }
            // Remember it so the next query for anything in this zone can start
            // here instead of at the root.
            self.delegations.insert(&child_zone, servers.clone(), ttl);
            zone = child_zone;
        }

        Err(anyhow!(
            "more than {} referrals while resolving {qname}",
            self.config.max_delegations
        ))
    }

    /// Try each server in turn, returning the first usable response.
    fn ask_any(
        &self,
        servers: &[SocketAddr],
        query_buf: &[u8],
        budget: &mut Budget,
    ) -> Option<DnsMessage> {
        for server in servers {
            if budget.spend().is_err() {
                return None;
            }
            if let Ok(response) = self.query_server(server, query_buf) {
                return Some(response);
            }
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
    ) -> Result<Option<Referral>, anyhow::Error> {
        // The NS records in the authority section name the child zone.
        let mut child_zone: Option<String> = None;
        let mut ns_names = Vec::new();
        // How long the delegation may be cached: the shortest TTL among the
        // records it rests on.
        let mut ttl = u64::MAX;

        for rr in &response.authorities {
            if rr.rdata.rtype != 2 {
                continue; // only NS records delegate
            }
            let owner = normalize(&rr.name);

            // Bailiwick, the rule that keeps a hostile server in its lane: a
            // referral must be *below* the zone we asked (otherwise `com.` could
            // hand us the servers for `bank.example.`) and must be *at or above*
            // the name we are chasing (otherwise it is not progress toward it).
            if !is_subdomain(&owner, zone) || owner == *zone {
                continue;
            }
            if !is_subdomain(qname, &owner) {
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
                ttl = ttl.min(rr.ttl.max(0) as u64);
            }
        }

        let Some(child_zone) = child_zone else {
            return Ok(None);
        };

        // Glue: addresses for those nameservers, carried in the additional
        // section. Trust it only where the responder has standing to speak —
        // that is, for names inside the zone *it* is authoritative for, not the
        // zone it is delegating to.
        //
        // The distinction matters at the root: the referral to `com.` carries
        // glue for `a.gtld-servers.net.`, which is not under `com.` at all.
        // Requiring glue to be under the child zone would reject it, and the
        // whole system would fail to bootstrap — resolving `gtld-servers.net.`
        // needs `net.`, whose glue is also `gtld-servers.net.`. Judged against
        // the responder's own zone (`.`, here) it is properly in bailiwick.
        // A `com.` server, by contrast, may not hand us an address for
        // `ns.example.org.`; that has to be resolved independently.
        let mut glue = Vec::new();
        for rr in &response.additionals {
            let owner = normalize(&rr.name);
            if !ns_names.iter().any(|ns| names_equal(ns, &owner)) {
                continue;
            }
            if !is_subdomain(&owner, zone) {
                continue;
            }
            let port = self.config.server_port;
            match rr.rdata.parse() {
                Ok(ParsedRecord::A(addr)) => {
                    glue.push(SocketAddr::new(IpAddr::V4(addr), port));
                    ttl = ttl.min(rr.ttl.max(0) as u64);
                }
                Ok(ParsedRecord::AAAA(addr)) => {
                    glue.push(SocketAddr::new(IpAddr::V6(addr), port));
                    ttl = ttl.min(rr.ttl.max(0) as u64);
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
    /// usable glue. Stops at the first name that yields an address: one working
    /// nameserver is enough, and each extra lookup is charged to the budget.
    fn resolve_nameserver_addresses(
        &self,
        ns_names: &[String],
        budget: &mut Budget,
        depth: usize,
    ) -> Result<Vec<SocketAddr>, anyhow::Error> {
        for name in ns_names {
            let lookup = QuerySection {
                qname: name.clone(),
                qtype: 1, // A
                qclass: crate::QueryClass::IN,
            };
            let Ok(response) = self.resolve_from_root(&lookup, budget, depth) else {
                continue;
            };
            let addrs: Vec<SocketAddr> = response
                .answers
                .iter()
                .filter_map(|rr| match rr.rdata.parse() {
                    Ok(ParsedRecord::A(addr)) => {
                        Some(SocketAddr::new(IpAddr::V4(addr), self.config.server_port))
                    }
                    _ => None,
                })
                .collect();
            if !addrs.is_empty() {
                return Ok(addrs);
            }
        }
        Ok(Vec::new())
    }

    fn query_server(
        &self,
        upstream: &SocketAddr,
        query: &[u8],
    ) -> Result<DnsMessage, anyhow::Error> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(self.config.timeout_ms / 2)))?;
        socket.connect(upstream)?;

        // Send query
        socket.send(query)?;

        // Receive response, sized to the payload we advertised via EDNS.
        let mut response_buf = vec![0; self.config.udp_payload_size as usize];
        let n = socket.recv(&mut response_buf)?;

        response_buf.truncate(n);
        let response = DnsMessage::try_from_bytes(&response_buf)?;

        // RFC 1035 §4.2.1: a truncated answer must be retried over TCP. The
        // retry stays on the *same* upstream — TC says "this answer doesn't fit
        // in a datagram", not "this server is unhealthy", so moving on would
        // just collect the same TC=1 from the next one. If the TCP attempt
        // fails, the error propagates and `resolve_internal` tries the next
        // upstream with a fresh UDP query.
        if response.truncation {
            return self.query_upstream_tcp(upstream, query);
        }

        Ok(response)
    }

    /// Re-issue a query over TCP, using the RFC 1035 §4.2.2 length-prefixed
    /// framing.
    ///
    /// A response that is *still* truncated is returned as-is rather than
    /// treated as an error: TCP is the last resort, so a TC=1 here means the
    /// upstream genuinely cannot express the full RRset and the partial answer
    /// plus the flag is more useful to the caller than a hard failure.
    fn query_upstream_tcp(
        &self,
        upstream: &SocketAddr,
        query: &[u8],
    ) -> Result<DnsMessage, anyhow::Error> {
        if query.len() > TCP_MAX_MESSAGE {
            return Err(anyhow!(
                "query of {} bytes exceeds the 2-byte TCP length prefix",
                query.len()
            ));
        }

        // Same budget as the UDP half, applied to connect, write and read.
        let timeout = Duration::from_millis(self.config.timeout_ms / 2);
        let stream = TcpStream::connect_timeout(upstream, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        // Prefix and message go out in one write so they share a segment.
        let mut framed = Vec::with_capacity(2 + query.len());
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(query);
        (&stream).write_all(&framed)?;

        let mut len_buf = [0u8; 2];
        (&stream).read_exact(&mut len_buf)?;
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Err(anyhow!("upstream {} sent a zero-length TCP message", upstream));
        }

        let mut response_buf = vec![0; len];
        (&stream).read_exact(&mut response_buf)?;
        DnsMessage::try_from_bytes(&response_buf)
    }
}

/// Absolute, lowercased form — the shape every comparison here assumes.
/// DNS names compare case-insensitively (RFC 4343).
fn normalize(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    if lowered.ends_with('.') {
        lowered
    } else {
        format!("{lowered}.")
    }
}

fn names_equal(a: &str, b: &str) -> bool {
    normalize(a) == normalize(b)
}

/// Whether `name` is at or below `ancestor` in the tree. Everything is below
/// the root, and a name is trivially below itself.
fn is_subdomain(name: &str, ancestor: &str) -> bool {
    let name = normalize(name);
    let ancestor = normalize(ancestor);
    if ancestor == "." || name == ancestor {
        return true;
    }
    name.ends_with(&format!(".{ancestor}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ParsedRecord, QueryClass, RecordData, ResourceRecord};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn test_query() -> QuerySection {
        QuerySection {
            qname: "example.com.".to_string(),
            qtype: 1,
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

    /// Recursing, but starting from a fake root instead of the real one. The
    /// whole fake hierarchy shares `root.port()` — see [`bind_hierarchy`].
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
        }
    }

    fn a_record(name: &str, addr: [u8; 4]) -> ResourceRecord {
        ResourceRecord {
            name: name.to_string(),
            class: 1,
            ttl: 300,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::from(addr))).unwrap(),
        }
    }

    /// Bind a UDP socket and a TCP listener on the *same* 127.0.0.1 port, so one
    /// `SocketAddr` can stand in for a real upstream on both transports.
    ///
    /// Deliberately scans fixed ports below the ephemeral range rather than
    /// asking for port 0: Windows hands out ephemeral ports sequentially from a
    /// rotating cursor and carves exclusion blocks (hundreds of ports wide, and
    /// different ones per protocol) out of that range, so "bind 0 on one
    /// protocol, match it on the other" can fail for every attempt in a row.
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
        assert_eq!(config.root_hints.len(), 13, "one per root server");
        assert!(!config.upstream_servers.is_empty());
        assert!(config.timeout_ms > 0);
        assert!(config.max_delegations > 0);
        assert!(config.query_budget > 0);
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
    #[test]
    fn test_query_budget_is_enforced() {
        let config = ResolverConfig {
            mode: ResolverMode::Forward,
            upstream_servers: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)],
            timeout_ms: 1000,
            query_budget: 0,
            ..ResolverConfig::default()
        };
        let resolver = Resolver::new(config);

        let result = resolver.resolve(&test_query());
        assert!(result.is_err());
    }

    #[test]
    fn test_bailiwick_helpers() {
        assert!(is_subdomain("www.example.com.", "example.com."));
        assert!(is_subdomain("example.com.", "com."));
        assert!(is_subdomain("anything.", "."), "everything is under the root");
        assert!(is_subdomain("example.com.", "example.com."), "reflexive");

        // The attack these guard against: a name that merely *ends with* the
        // zone's text is not inside the zone.
        assert!(!is_subdomain("notexample.com.", "example.com."));
        assert!(!is_subdomain("example.com.", "www.example.com."));
        assert!(!is_subdomain("example.org.", "example.com."));

        // Case and trailing dots do not change the answer (RFC 4343).
        assert!(is_subdomain("WWW.Example.COM", "example.com."));
        assert!(names_equal("Example.COM.", "example.com"));
    }

    // ---------------------------------------------------------------------
    // Recursion: a fake root / TLD / authoritative hierarchy in-process.
    // ---------------------------------------------------------------------

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
    /// They have to share a port because glue records carry an address and no
    /// port: a resolver always dials `server_port`, so a fake hierarchy can only
    /// be distinguished by address. Windows does allow binding 127.0.0.2 and up.
    fn bind_hierarchy(count: usize) -> Vec<UdpSocket> {
        assert!(count <= 8, "loopback aliases used here stop at 127.0.0.8");
        let start = 20_000 + (rand::random::<u16>() % 20_000);

        for offset in 0..500u16 {
            let port = 20_000 + (start - 20_000 + offset) % 20_000;
            let mut socks = Vec::with_capacity(count);
            let bound = (0..count).all(|i| {
                match UdpSocket::bind(format!("127.0.0.{}:{}", i + 1, port)) {
                    Ok(s) => {
                        socks.push(s);
                        true
                    }
                    Err(_) => false,
                }
            });
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
            class: 1,
            ttl: 3600,
            rdata: RecordData::from_parsed(&ParsedRecord::NS(target.to_string())).unwrap(),
        }
    }

    fn cname_record(owner: &str, target: &str) -> ResourceRecord {
        ResourceRecord {
            name: owner.to_string(),
            class: 1,
            ttl: 3600,
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

    /// The whole point: root → TLD → authoritative, following glue at each step.
    #[test]
    fn test_recursion_follows_the_delegation_chain() {
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
                qtype: 1,
                qclass: QueryClass::IN,
            })
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
    #[test]
    fn test_out_of_bailiwick_referral_is_not_followed() {
        let mut socks = bind_hierarchy(2).into_iter();
        let (root_sock, evil_sock) = (socks.next().unwrap(), socks.next().unwrap());
        let evil_addr = evil_sock.local_addr().unwrap();

        let _evil = spawn_server(evil_sock, |q| {
            authoritative(q, vec![a_record(&qname_of(q), [6, 6, 6, 6])])
        });
        let root = spawn_server(root_sock, move |q| {
            referral(q, "evil.test.", "ns.evil.test.", Some(("ns.evil.test.", evil_addr)))
        });

        let resolver = Resolver::new(recursing_config(root.addr));
        let result = resolver.resolve(&QuerySection {
            qname: "www.example.test.".to_string(),
            qtype: 1,
            qclass: QueryClass::IN,
        });

        // The referral is ignored, so the walk ends at the root's own (empty)
        // response rather than reaching the attacker's server.
        let answers = result.map(|r| r.answers).unwrap_or_default();
        assert!(
            answers.is_empty(),
            "must not accept an answer from an out-of-bailiwick delegation"
        );
    }

    /// Glue is trusted only for names inside the responding server's own zone.
    ///
    /// Demonstrated below the root, because the root is authoritative for `.`
    /// and so *everything* it offers is in bailiwick — that is exactly what lets
    /// the root hand out `a.gtld-servers.net.` addresses for the `com.`
    /// delegation. A TLD server has no such latitude.
    #[test]
    fn test_out_of_bailiwick_glue_is_ignored() {
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
        let result = resolver.resolve(&QuerySection {
            qname: "www.example.test.".to_string(),
            qtype: 1,
            qclass: QueryClass::IN,
        });

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
    #[test]
    fn test_cname_chain_is_followed() {
        let mut socks = bind_hierarchy(2).into_iter();
        let (root_sock, auth_sock) = (socks.next().unwrap(), socks.next().unwrap());
        let auth_addr = auth_sock.local_addr().unwrap();

        let _auth = spawn_server(auth_sock, |q| {
            let name = qname_of(q);
            if name == "www.example.test." {
                authoritative(q, vec![cname_record("www.example.test.", "real.example.test.")])
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
                qtype: 1,
                qclass: QueryClass::IN,
            })
            .expect("CNAME should be chased to the address");

        assert_eq!(answer.answers.len(), 2, "CNAME and the A it leads to");
        assert_eq!(answer.answers[0].rdata.rtype, 5);
        assert_eq!(
            answer.answers[1].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 9))
        );
    }

    /// A CNAME pointing back at itself must terminate, not spin.
    #[test]
    fn test_cname_loop_is_detected() {
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
        let result = resolver.resolve(&QuerySection {
            qname: "a.example.test.".to_string(),
            qtype: 1,
            qclass: QueryClass::IN,
        });

        let err = result.expect_err("a CNAME loop must be an error").to_string();
        assert!(
            err.contains("loop") || err.contains("budget") || err.contains("hops"),
            "unexpected error: {err}"
        );
    }

    /// A delegation with no glue costs a nested resolution of the nameserver's
    /// own name — which must work, and must be charged to the same budget.
    #[test]
    fn test_glueless_delegation_is_resolved() {
        let mut socks = bind_hierarchy(2).into_iter();
        let (root_sock, auth_sock) = (socks.next().unwrap(), socks.next().unwrap());
        let auth_addr = auth_sock.local_addr().unwrap();

        // Authoritative for example.test., and also holds the address of the
        // nameserver name (which lives in a different zone: ns.hoster.test.).
        // The nameserver lookup has to answer with this server's *real* address
        // — the resolver dials whatever the A record says.
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
        // The root delegates both `example.test.` (glueless) and `hoster.test.`
        // (with glue), so looking up the nameserver's address can succeed.
        let root = spawn_server(root_sock, move |q| {
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

        let resolver = Resolver::new(recursing_config(root.addr));
        let answer = resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: 1,
                qclass: QueryClass::IN,
            })
            .expect("glueless delegation should resolve via the nameserver's name");

        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 7))
        );
    }

    /// A server that refers to itself forever must be stopped by the budget
    /// rather than looping until the client times out.
    #[test]
    fn test_referral_loop_is_bounded() {
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
        let result = resolver.resolve(&QuerySection {
            qname: "www.example.test.".to_string(),
            qtype: 1,
            qclass: QueryClass::IN,
        });

        assert!(result.is_err(), "a referral loop must terminate in an error");
    }

    // ---------------------------------------------------------------------
    // Delegation cache
    // ---------------------------------------------------------------------

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
                "stale.test.".to_string(),
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

    /// The point of the whole exercise: a second query for the same zone must
    /// not go back to the root.
    #[test]
    fn test_second_query_does_not_revisit_the_root() {
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
        for name in ["one.example.test.", "two.example.test.", "three.example.test."] {
            let answer = resolver
                .resolve(&QuerySection {
                    qname: name.to_string(),
                    qtype: 1,
                    qclass: QueryClass::IN,
                })
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
    #[test]
    fn test_stale_delegation_falls_back_to_the_root() {
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

        // Short timeout: this test deliberately talks to a black hole, and the
        // point is the fallback, not how long we wait for the dead server.
        let resolver = Resolver::new(ResolverConfig {
            timeout_ms: 300,
            ..recursing_config(root.addr)
        });

        // Poison the cache with a server that will never answer: a discard
        // address on the same port the fake hierarchy uses.
        let dead: SocketAddr = format!("192.0.2.99:{}", root.addr.port()).parse().unwrap();
        resolver
            .delegations
            .insert("example.test.", vec![dead], 3600);

        let answer = resolver
            .resolve(&QuerySection {
                qname: "www.example.test.".to_string(),
                qtype: 1,
                qclass: QueryClass::IN,
            })
            .expect("a stale delegation must fall back to the root, not fail");

        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 6))
        );
    }

    /// A TC=1 UDP answer must be retried over TCP, and the TCP answer is what
    /// the caller gets (RFC 1035 §4.2.1).
    #[test]
    fn test_tcp_fallback_on_truncated_udp_response() {
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

        // TCP half: the real answer, length-prefixed. Returns the prefix the
        // client sent and the length it claimed, so the test can check framing.
        let tcp_thread = thread::spawn(move || {
            let (mut stream, _) = tcp.accept().unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).unwrap();
            let claimed = u16::from_be_bytes(len_buf) as usize;
            let mut buf = vec![0u8; claimed];
            stream.read_exact(&mut buf).unwrap();
            let query = DnsMessage::try_from_bytes(&buf).unwrap();

            let mut resp = response_to(&query);
            resp.answers.push(a_record("example.com.", [93, 184, 216, 34]));
            let mut out = vec![0u8; 4096];
            let n = resp.to_bytes(&mut out).unwrap();

            let mut framed = Vec::with_capacity(2 + n);
            framed.extend_from_slice(&(n as u16).to_be_bytes());
            framed.extend_from_slice(&out[..n]);
            stream.write_all(&framed).unwrap();

            (claimed, query.queries.first().map(|q| q.qname.clone()))
        });

        let resolver = Resolver::new(test_config(addr));
        let answer = resolver.resolve(&test_query()).unwrap();

        udp_thread.join().unwrap();
        let (claimed, tcp_qname) = tcp_thread.join().unwrap();

        // The TCP retry carried the same question, correctly framed.
        assert!(claimed >= 12, "TCP length prefix {} is below a DNS header", claimed);
        assert_eq!(tcp_qname.as_deref(), Some("example.com."));

        // And its answer, not the truncated one, is what came back.
        assert!(!answer.truncation);
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    /// The inverse: a response that fits in a datagram must not touch TCP.
    /// Nothing is listening on the TCP side of this port, so an attempted
    /// fallback would fail the connect and turn into a resolve error.
    #[test]
    fn test_no_tcp_fallback_when_response_fits() {
        // Take the pair and immediately release the TCP half, so we know for
        // certain nothing is listening there to accept a stray fallback.
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
        let answer = resolver.resolve(&test_query()).unwrap();
        udp_thread.join().unwrap();

        assert_eq!(answer.answers.len(), 1);
        assert_eq!(
            answer.answers[0].rdata.parse().unwrap(),
            ParsedRecord::A(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    /// A TCP answer that is *itself* truncated is passed through, not rejected.
    #[test]
    fn test_still_truncated_tcp_response_is_returned() {
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
        let answer = resolver.resolve(&test_query()).unwrap();

        udp_thread.join().unwrap();
        tcp_thread.join().unwrap();

        assert!(answer.truncation);
        assert_eq!(answer.answers.len(), 1);
    }

    /// A zero-length TCP frame is a protocol error, not an empty message.
    #[test]
    fn test_zero_length_tcp_frame_is_an_error() {
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
        let result = resolver.resolve(&test_query());

        udp_thread.join().unwrap();
        tcp_thread.join().unwrap();

        // The single upstream failed, so the resolve as a whole fails.
        assert!(result.is_err());
    }
}
