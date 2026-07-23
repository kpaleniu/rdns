use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use rdns::resolver::{RecursiveResolver, ResolverConfig};
use rdns::{DnsCache, DnsMessage, OpCode, QuerySection, ResourceRecord, ResponseCode};
use tokio::net::UdpSocket;

/// Forwarding DNS resolver with caching.
///
/// Unlike the authoritative server (`rdnsd`), `rdnsr` answers by forwarding
/// queries to upstream resolvers and caching the results by (name, type) + TTL.
/// It binds to localhost by default so it is not accidentally exposed as an open
/// recursive resolver (an amplification vector).
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Address to listen on. Defaults to localhost to avoid an open resolver.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value = "53")]
    port: u16,
    /// Upstream resolver to forward to, e.g. 8.8.8.8:53 (repeatable).
    /// Defaults to 8.8.8.8:53 and 1.1.1.1:53.
    #[arg(long)]
    upstream: Vec<SocketAddr>,
    /// Maximum number of cached RRsets.
    #[arg(long, default_value = "10000")]
    cache_size: usize,
    /// Disable caching entirely.
    #[arg(long)]
    no_cache: bool,
    /// Validate DNSSEC on resolved answers. Accepted but not yet enforced
    /// (validation is not wired into the resolve path — see TODO Part B #6).
    #[arg(long)]
    dnssec_validate: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let mut config = ResolverConfig::default();
    if !cli.upstream.is_empty() {
        config.upstream_servers = cli.upstream.clone();
    }
    let upstreams = config.upstream_servers.clone();
    let resolver = Arc::new(RecursiveResolver::new(config));

    // A zero-capacity cache never stores (DnsCache::put is a no-op at 0), so
    // --no-cache is just a cache sized to hold nothing.
    let capacity = if cli.no_cache { 0 } else { cli.cache_size };
    let cache = Arc::new(DnsCache::new(capacity));

    if cli.dnssec_validate {
        eprintln!("warning: --dnssec-validate is accepted but not yet enforced");
    }

    let addr = format!("{}:{}", cli.host, cli.port);
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    println!(
        "rdnsr forwarding resolver listening on {} (upstreams: {:?}, cache: {})",
        addr,
        upstreams,
        if capacity == 0 { "disabled".to_string() } else { format!("{capacity} entries") },
    );

    let mut buf = [0u8; 512];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let data = buf[..n].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            if let Some(reply) = handle_query(data, &resolver, &cache).await {
                let _ = socket.send_to(&reply, peer).await;
            }
        });
    }
}

/// Resolve one datagram: cache lookup, else forward upstream and cache-store.
/// Returns the wire bytes to send back, or `None` if the query was unparseable
/// (in which case we simply drop it, as a resolver should).
async fn handle_query(
    data: Vec<u8>,
    resolver: &Arc<RecursiveResolver>,
    cache: &Arc<DnsCache>,
) -> Option<Vec<u8>> {
    let msg = DnsMessage::try_from_bytes(&data).ok()?;
    let query = msg.queries.first()?.clone();
    let id = msg.id;
    let recursion = msg.recursion;

    // Cache hit: reconstruct a response from the cached RRset.
    if let Some(records) = cache.get(&query.qname, query.qtype) {
        let resp = build_response(id, &query, records, ResponseCode::Ok, recursion);
        return serialize(&resp);
    }

    // Cache miss: forward upstream. RecursiveResolver::resolve is blocking, so
    // run it off the async runtime's worker threads.
    let resolver = resolver.clone();
    let q = query.clone();
    let resolved = tokio::task::spawn_blocking(move || resolver.resolve(&q))
        .await
        .ok()?;

    match resolved {
        Ok(mut upstream) => {
            // The resolver used its own random transaction id; the reply must
            // echo the client's id and advertise recursion availability.
            upstream.id = id;
            upstream.response = true;
            upstream.recursion = recursion;
            upstream.recursion_ok = true;
            if !upstream.answers.is_empty() {
                cache.put(&query.qname, query.qtype, upstream.answers.clone());
            }
            serialize(&upstream)
        }
        // Upstream failed / timed out: return SERVFAIL rather than nothing.
        Err(_) => {
            let resp = build_response(id, &query, Vec::new(), ResponseCode::ServerFailure, recursion);
            serialize(&resp)
        }
    }
}

/// Build a minimal response message echoing the question section.
fn build_response(
    id: u16,
    query: &QuerySection,
    answers: Vec<ResourceRecord>,
    rcode: ResponseCode,
    recursion: bool,
) -> DnsMessage {
    DnsMessage {
        id,
        response: true,
        opcode: OpCode::Query,
        authoritive: false,
        truncation: false,
        recursion,
        recursion_ok: true,
        ad: false,
        cd: false,
        rcode,
        queries: vec![query.clone()],
        answers,
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

/// Serialize a message to wire bytes. Uses a generous buffer since we don't do
/// EDNS0 negotiation yet (TODO Part B #1); returns `None` on serialization error.
fn serialize(msg: &DnsMessage) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let n = msg.to_bytes(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}
