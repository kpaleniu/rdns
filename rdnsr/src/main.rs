use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use rdns::resolver::{RecursiveResolver, ResolverConfig};
use rdns::{
    DnsCache, DnsMessage, Edns, OpCode, QuerySection, ResourceRecord, ResponseCode, EDNS_VERSION,
    OPT_RECORD_TYPE,
};
use tokio::net::UdpSocket;

/// UDP payload size rdnsr advertises to clients via EDNS0.
const RDNSR_PAYLOAD_SIZE: u16 = 4096;

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

    let mut buf = [0u8; 4096];
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
    // Classic 512 unless the client advertised a larger size via EDNS0.
    let client_max = msg.udp_payload_size() as usize;

    // Reject bad EDNS before doing any work on the client's behalf: a malformed
    // option list is a FORMERR, and an EDNS version we don't implement is
    // BADVERS (RFC 6891 §6.1.3). Both replies carry a bare version-0 OPT.
    match msg.edns() {
        Err(_) => {
            return edns_error(id, &query, ResponseCode::FormatError, recursion, client_max)
        }
        Ok(Some(edns)) if edns.version > EDNS_VERSION => {
            return edns_error(id, &query, ResponseCode::BadOptVersion, recursion, client_max)
        }
        _ => {}
    }
    let client_uses_edns = msg.has_edns();

    // Build the response: from cache if we have it, else by forwarding upstream.
    let mut resp = if let Some(records) = cache.get(&query.qname, query.qtype) {
        build_response(id, &query, records, ResponseCode::Ok, recursion)
    } else {
        // RecursiveResolver::resolve is blocking, so run it off the async
        // runtime's worker threads.
        let resolver = resolver.clone();
        let q = query.clone();
        let resolved = tokio::task::spawn_blocking(move || resolver.resolve(&q))
            .await
            .ok()?;
        match resolved {
            Ok(mut upstream) => {
                // The resolver used its own random transaction id; the reply
                // must echo the client's id and advertise recursion.
                upstream.id = id;
                upstream.response = true;
                upstream.recursion = recursion;
                upstream.recursion_ok = true;
                if !upstream.answers.is_empty() {
                    cache.put(&query.qname, query.qtype, upstream.answers.clone());
                }
                upstream
            }
            // Upstream failed / timed out: return SERVFAIL rather than nothing.
            Err(_) => {
                build_response(id, &query, Vec::new(), ResponseCode::ServerFailure, recursion)
            }
        }
    };

    // Only include an OPT record when the client used EDNS (RFC 6891 §6.1.1);
    // otherwise strip any OPT the upstream added so we don't reply with
    // unsolicited EDNS.
    if client_uses_edns {
        resp.set_edns(Edns::with_payload_size(RDNSR_PAYLOAD_SIZE)).ok()?;
    } else {
        resp.additionals.retain(|rr| rr.rdata.rtype != OPT_RECORD_TYPE);
    }

    // Honor the client's advertised UDP size: truncates (TC=1) if it overflows.
    resp.to_bytes_within(client_max).ok()
}

/// An empty error response carrying a version-0 OPT record, for the EDNS-level
/// rejections (FORMERR / BADVERS) that must be signalled before resolving.
fn edns_error(
    id: u16,
    query: &QuerySection,
    rcode: ResponseCode,
    recursion: bool,
    client_max: usize,
) -> Option<Vec<u8>> {
    let mut resp = build_response(id, query, Vec::new(), rcode, recursion);
    // BADVERS is an extended RCODE, so the OPT record isn't optional here — it
    // carries the code's high bits.
    resp.set_edns(Edns::with_payload_size(RDNSR_PAYLOAD_SIZE)).ok()?;
    resp.to_bytes_within(client_max).ok()
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
