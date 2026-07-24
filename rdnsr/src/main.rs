use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use rdns::resolver::{RecursiveResolver, ResolverConfig};
use rdns::{
    DnsCache, DnsMessage, Edns, OpCode, QuerySection, ResourceRecord, ResponseCode, EDNS_VERSION,
    OPT_RECORD_TYPE,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Semaphore};

/// UDP payload size rdnsr advertises to clients via EDNS0.
const RDNSR_PAYLOAD_SIZE: u16 = 4096;

/// How long a TCP connection may sit idle between queries before we close it.
/// RFC 7766 §6.2.3 wants connections reused rather than reopened, but an idle
/// one still costs a socket, so this is the compromise the RFC asks for.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long we wait for the rest of a message once its length prefix arrived.
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on concurrent TCP connections. Without one, an accept loop that
/// spawns per connection is a free file-descriptor exhaustion vector.
const MAX_TCP_CONNECTIONS: usize = 128;

/// Queries a single connection may have in flight at once. Doubles as the reply
/// channel's depth, so a client that pipelines faster than it reads eventually
/// pushes back on our read loop instead of growing a queue in memory.
const MAX_INFLIGHT_PER_CONNECTION: usize = 16;

/// Which transport a query arrived on.
///
/// This decides the size limit on the answer: a UDP reply must fit the
/// requestor's advertised payload size, whereas a TCP reply is framed by a
/// 2-byte length and so is bounded only by that field (RFC 6891 §6.2.2 — the
/// EDNS payload size applies to UDP only).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp,
}

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
    // Both transports are mandatory for a resolver: when an answer overflows the
    // client's UDP payload size we reply TC=1, and RFC 1035 §4.2.1 has the client
    // retry the same query over TCP. Without a TCP listener that retry is
    // refused and the query simply fails.
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    let listener = TcpListener::bind(&addr).await?;
    println!(
        "rdnsr forwarding resolver listening on {} (UDP+TCP) (upstreams: {:?}, cache: {})",
        addr,
        upstreams,
        if capacity == 0 { "disabled".to_string() } else { format!("{capacity} entries") },
    );

    let udp = tokio::spawn(udp_main(socket, resolver.clone(), cache.clone()));
    let tcp = tokio::spawn(tcp_main(listener, resolver, cache));

    // Neither loop returns in normal operation; whichever fails first takes the
    // process down rather than leaving us serving one transport.
    tokio::select! {
        r = udp => r??,
        r = tcp => r??,
    }
    Ok(())
}

/// Accept datagrams and answer each in its own task.
async fn udp_main(
    socket: Arc<UdpSocket>,
    resolver: Arc<RecursiveResolver>,
    cache: Arc<DnsCache>,
) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let data = buf[..n].to_vec();
        let socket = socket.clone();
        let resolver = resolver.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            if let Some(reply) = handle_query(data, &resolver, &cache, Transport::Udp).await {
                let _ = socket.send_to(&reply, peer).await;
            }
        });
    }
}

/// Accept TCP connections, bounded by [`MAX_TCP_CONNECTIONS`].
async fn tcp_main(
    listener: TcpListener,
    resolver: Arc<RecursiveResolver>,
    cache: Arc<DnsCache>,
) -> Result<(), std::io::Error> {
    let permits = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, _peer) = listener.accept().await?;
        // The semaphore is never closed, so acquiring only fails if we drop it.
        let Ok(permit) = permits.clone().acquire_owned().await else {
            continue;
        };
        let resolver = resolver.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            serve_connection(stream, resolver, cache).await;
            drop(permit);
        });
    }
}

/// Serve one TCP connection until it goes idle, closes, or misbehaves.
///
/// Each message is framed by a 2-byte big-endian length (RFC 1035 §4.2.2), and a
/// connection may carry any number of queries (RFC 7766 §6.2.1), answered
/// **concurrently** (§6.2.1.1). Concurrency earns its keep here: a cache miss
/// costs an upstream round trip, so answering in lock-step would make every
/// query on a connection wait out the slowest one ahead of it.
async fn serve_connection(
    stream: TcpStream,
    resolver: Arc<RecursiveResolver>,
    cache: Arc<DnsCache>,
) {
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MAX_INFLIGHT_PER_CONNECTION);

    // One task owns the write half. Answers may complete out of order — RFC 7766
    // §6.2.1.1 allows that, and clients match on the transaction id — but two
    // framed messages must never interleave on the wire, so every reply funnels
    // through here.
    let writer_task = tokio::spawn(async move {
        while let Some(framed) = rx.recv().await {
            if writer.write_all(&framed).await.is_err() {
                break;
            }
        }
    });

    let in_flight = Arc::new(Semaphore::new(MAX_INFLIGHT_PER_CONNECTION));

    loop {
        // Between messages the peer may legitimately be idle, so a timeout here
        // is a normal close rather than an error.
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE_TIMEOUT, reader.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            break; // Can't even hold a header; treat as a broken peer.
        }

        // Mid-message the peer has committed to sending `len` bytes, so a stall
        // here gets a much shorter leash than an idle connection does.
        let mut buf = vec![0u8; len];
        match tokio::time::timeout(TCP_READ_TIMEOUT, reader.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }

        // Cap in-flight work per connection: this await is what stops a
        // pipelining client from spawning tasks faster than we retire them.
        let Ok(permit) = in_flight.clone().acquire_owned().await else {
            break;
        };
        let resolver = resolver.clone();
        let cache = cache.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Some(reply) = handle_query(buf, &resolver, &cache, Transport::Tcp).await {
                // Length prefix and message in one buffer, so the writer emits
                // them in a single call.
                let mut framed = Vec::with_capacity(2 + reply.len());
                framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
                framed.extend_from_slice(&reply);
                // A send error means the writer is gone (the peer hung up);
                // there is nowhere left to put the reply.
                let _ = tx.send(framed).await;
            }
            drop(permit);
        });
    }

    // Dropping our sender lets the writer drain the replies still in flight —
    // the clones held by running tasks keep the channel open — and then exit.
    drop(tx);
    let _ = writer_task.await;
}

/// Resolve one datagram: cache lookup, else forward upstream and cache-store.
/// Returns the wire bytes to send back, or `None` if the query was unparseable
/// (in which case we simply drop it, as a resolver should).
async fn handle_query(
    data: Vec<u8>,
    resolver: &Arc<RecursiveResolver>,
    cache: &Arc<DnsCache>,
    transport: Transport,
) -> Option<Vec<u8>> {
    let msg = DnsMessage::try_from_bytes(&data).ok()?;
    let query = msg.queries.first()?.clone();
    let id = msg.id;
    let recursion = msg.recursion;
    // Over UDP: the classic 512, unless the client advertised more via EDNS0.
    // Over TCP: the length prefix is the only limit, and truncating there would
    // strand the client — TCP *is* the fallback it was sent to.
    let client_max = match transport {
        Transport::Udp => msg.udp_payload_size() as usize,
        Transport::Tcp => u16::MAX as usize,
    };

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
