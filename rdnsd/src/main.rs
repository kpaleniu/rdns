use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use rdns::{
    logging::QueryLogger,
    notify,
    security::{RateLimiter, ResponseLimiter, ResponseVerdict, TransferAcl},
    transfer::axfr_messages,
    tsig::{self, TsigCheck, TsigKeyring, TsigSession},
    OpCode,
    telemetry::{instrumentation, DnsMetrics, LatencyTimer},
    utils::record_types,
    validation::RequestValidator,
    zone::{parse_zone_file_at, Zone},
    DnsMessage, Edns, ResourceRecord, ResponseCode, EDNS_VERSION,
};

/// UDP payload size rdnsd advertises to clients via EDNS0.
const RDNSD_PAYLOAD_SIZE: u16 = 4096;

/// How long a TCP connection may sit idle between queries before we close it.
/// RFC 7766 §6.2.3 wants connections reused rather than reopened; an idle one
/// still costs a socket, so this is the compromise.
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

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock, Semaphore};

#[cfg(unix)]
use signal_hook::consts::signal::SIGHUP;
#[cfg(unix)]
use signal_hook_tokio::Signals;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    commands: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Tcp {
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        #[arg(long, default_value = "53")]
        port: u16,
        #[arg(long)]
        zone_file: Option<String>,
        #[arg(long)]
        zone_dir: Option<String>,
        /// Who may request a zone transfer: an address or CIDR prefix, repeatable.
        ///
        /// Nobody, unless this says otherwise. An AXFR is the whole zone in one
        /// answer, so it is the one query that has to be allowed by list. Only
        /// on the TCP subcommand, because AXFR is defined over TCP alone
        /// (RFC 5936 §4.2).
        #[arg(long, value_name = "ADDR|CIDR")]
        allow_transfer: Vec<String>,
        /// A TSIG key, `[algorithm:]name:base64secret`, repeatable.
        ///
        /// Holding the key is an identity; coming from an address is not. A
        /// request signed with a key named here may transfer a zone whatever its
        /// source address, and any signed request gets a signed answer
        /// (RFC 8945). Algorithm defaults to hmac-sha256.
        #[arg(long, value_name = "[ALG:]NAME:SECRET")]
        tsig_key: Vec<String>,
        /// A secondary to notify when a zone changes: `addr[:port]`, repeatable.
        ///
        /// Without this a secondary hears about a change when its refresh timer
        /// next goes off, which for a typical SOA is hours later. A NOTIFY says so
        /// at once (RFC 1996). Sent on zone load — at startup and on SIGHUP — for
        /// every zone whose serial moved forward.
        #[arg(long, value_name = "ADDR[:PORT]")]
        also_notify: Vec<String>,
    },
    Udp {
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        #[arg(long, default_value = "53")]
        port: u16,
        #[arg(long)]
        zone_file: Option<String>,
        #[arg(long)]
        zone_dir: Option<String>,
        /// Response bytes per second, per client address. 0 turns the budget off.
        ///
        /// Meters what leaves rather than what arrives, because that is what an
        /// amplification attack is made of. Only on the UDP subcommand: a TCP
        /// query has completed a handshake, so there is nobody to reflect at.
        #[arg(long, value_name = "BYTES_PER_SEC", default_value = "8192")]
        response_rate: u32,
        /// A TSIG key, `[algorithm:]name:base64secret`, repeatable.
        ///
        /// A signed query gets a signed answer (RFC 8945), which is what lets a
        /// client know the reply came from someone holding the key rather than
        /// from whatever answered first.
        #[arg(long, value_name = "[ALG:]NAME:SECRET")]
        tsig_key: Vec<String>,
        /// A secondary to notify when a zone changes: `addr[:port]`, repeatable.
        ///
        /// Without this a secondary hears about a change when its refresh timer
        /// next goes off, which for a typical SOA is hours later. A NOTIFY says so
        /// at once (RFC 1996). Sent on zone load — at startup and on SIGHUP — for
        /// every zone whose serial moved forward.
        #[arg(long, value_name = "ADDR[:PORT]")]
        also_notify: Vec<String>,
    },
}

/// Zone source: either a single file or a directory of zone files
#[derive(Clone)]
enum ZoneSource {
    SingleFile(String),
    Directory(String),
}

/// Build a DNS response for the given query message
/// 
/// Looks up the zone based on the query name and returns appropriate response
fn make_response(
    msg: &DnsMessage,
    zone_map: &HashMap<String, Zone>,
    metrics: &DnsMetrics,
) -> DnsMessage {
    let timer = LatencyTimer::new();
    let mut response = DnsMessage {
        id: msg.id,
        response: true,
        opcode: msg.opcode,
        authoritive: true,
        truncation: false,
        recursion: msg.recursion,
        recursion_ok: false,
        ad: false,
        cd: msg.cd,
        rcode: ResponseCode::Ok,
        queries: msg.queries.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    // EDNS-level rejections take precedence over any zone lookup: a malformed
    // option list is FORMERR, and an EDNS version we don't implement is BADVERS
    // (RFC 6891 §6.1.3). Both replies carry a bare version-0 OPT — BADVERS is an
    // extended RCODE, so the OPT record is what carries its high bits.
    let edns_rejection = match msg.edns() {
        Err(_) => Some(ResponseCode::FormatError),
        Ok(Some(edns)) if edns.version > EDNS_VERSION => Some(ResponseCode::BadOptVersion),
        _ => None,
    };
    if let Some(rcode) = edns_rejection {
        response.rcode = rcode;
        // `with_payload_size` carries no options, so encoding it cannot fail.
        let _ = response.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
        return response;
    }

    // Only QUERY reaches the zone lookup. NOTIFY is answered by the caller,
    // which knows the peer's address; anything else — UPDATE, STATUS, the
    // obsolete IQUERY — is something this server does not implement, and saying
    // so is more useful than treating it as a lookup (RFC 1035 §4.1.1).
    if msg.opcode != OpCode::Query {
        response.rcode = ResponseCode::NotImplemented;
        response.authoritive = false;
        return response;
    }

    // Process each query
    for query in &msg.queries {
        // A transfer over UDP is not a transfer. AXFR is defined over TCP alone
        // (RFC 5936 §4.2) — a whole zone does not fit a datagram and the protocol
        // has no way to say "there is more" — so a UDP request for it is
        // malformed rather than merely refused. The TCP server answers AXFR
        // itself, before ever reaching here, so this is the UDP path speaking.
        if query.qtype == record_types::AXFR {
            response.rcode = ResponseCode::FormatError;
            continue;
        }

        // Find the matching zone for this query
        let zone = find_zone_for_query(&query.qname, zone_map);
        
        if let Some(zone) = zone {
            let matching_records = zone.query(&query.qname, query.qtype);

            if matching_records.is_empty() {
                // Nothing of this type here. NXDOMAIN only if the *name* doesn't
                // exist either; otherwise it's NOERROR with an empty answer
                // (NODATA). `Zone::name_exists` is what expands `@` and relative
                // owner names against the origin and accounts for a wildcard —
                // comparing the stored names raw never matches.
                if !zone.name_exists(&query.qname) {
                    response.rcode = ResponseCode::NoSuchDomain;
                }

                // Both kinds of "no" carry the zone's SOA in the authority
                // section (RFC 2308 §2.1 and §2.2). It is not decoration: the
                // SOA's MINIMUM and its own TTL are what tell the client, and
                // every resolver in between, how long the answer may be cached.
                // Without it a negative answer is uncacheable, so each repeat of
                // a failing lookup comes back to us.
                for soa in zone.query(zone.origin(), record_types::SOA) {
                    response.authorities.push(ResourceRecord {
                        name: zone.origin().to_string(),
                        class: soa.class,
                        ttl: soa.ttl,
                        rdata: soa.rdata.clone(),
                    });
                }

                metrics.increment_cache_misses();
            } else {
                // Add matching records to answer section. The answer echoes the
                // queried name rather than the stored one, which may be `@` or
                // relative — and for a wildcard match the queried name is what
                // the client must see (RFC 1034 §4.3.3).
                for record in matching_records {
                    response.answers.push(ResourceRecord {
                        name: query.qname.clone(),
                        class: record.class,
                        ttl: record.ttl,
                        rdata: record.rdata.clone(),
                    });
                }

                metrics.increment_cache_hits();
            }

            metrics.increment_query_counter();
        } else {
            // No zone found for this query - NXDOMAIN
            response.rcode = ResponseCode::NoSuchDomain;
            metrics.increment_cache_misses();
        }
    }

    // Log query response with latency
    let query_name = msg
        .queries
        .first()
        .map(|q| q.qname.as_str())
        .unwrap_or("unknown");
    let query_type = msg.queries.first().map(|q| q.qtype).unwrap_or(0);
    instrumentation::trace_query_response(query_name, query_type, timer.elapsed_ms(), None);

    // Mirror EDNS0: only include an OPT record when the client used EDNS
    // (RFC 6891 §6.1.1), advertising our own UDP payload size.
    if msg.has_edns() {
        let _ = response.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
    }

    response
}

/// Find the zone that should handle this query
/// 
/// Matches the query name against zone origins, preferring the most specific (longest) match
fn find_zone_for_query<'a>(qname: &str, zone_map: &'a HashMap<String, Zone>) -> Option<&'a Zone> {
    // Wire-format query names are absolute ("www.example.com."), so the trailing
    // dot has to come off both sides before comparing — otherwise nothing ever
    // matches an origin and every query is an NXDOMAIN.
    let qname_lower = qname.to_lowercase();
    let qname_lower = qname_lower.trim_end_matches('.');

    // Find all zones that could handle this query
    let mut candidates: Vec<_> = zone_map
        .values()
        .filter(|zone| {
            let zone_origin = zone.origin().trim_end_matches('.').to_lowercase();
            // The root zone serves everything; otherwise the query must be the
            // origin or sit under it *at a label boundary*, so that a zone for
            // "example.com" doesn't capture "notexample.com".
            zone_origin.is_empty()
                || qname_lower == zone_origin
                || qname_lower
                    .strip_suffix(&zone_origin)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
        .collect();
    
    // Sort by zone origin length (longest first, most specific)
    candidates.sort_by(|a, b| {
        b.origin().len().cmp(&a.origin().len())
    });
    
    candidates.first().copied()
}

/// The shared state a TCP connection needs to answer queries. Bundled so a
/// connection task clones one `Arc` instead of five.
struct TcpServer {
    zone_map: Arc<RwLock<HashMap<String, Zone>>>,
    rate_limiter: Arc<RateLimiter>,
    validator: Arc<RequestValidator>,
    logger: Arc<QueryLogger>,
    metrics: Arc<DnsMetrics>,
    /// Who may ask for a zone transfer. Empty by default, which refuses everyone.
    transfer_acl: Arc<TransferAcl>,
    /// The TSIG keys we know. Holding one is an identity; an address is not.
    tsig_keys: Arc<TsigKeyring>,
}

async fn tcp_main(
    addr: &str,
    zone_map: Arc<RwLock<HashMap<String, Zone>>>,
    transfer_acl: TransferAcl,
    tsig_keys: TsigKeyring,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    let transfers = if transfer_acl.is_empty() && tsig_keys.is_empty() {
        "refused (no --allow-transfer, no --tsig-key)".to_string()
    } else {
        format!(
            "allowed for {} address rule(s) and {} key(s)",
            transfer_acl.len(),
            tsig_keys.len()
        )
    };
    let server = Arc::new(TcpServer {
        zone_map,
        rate_limiter: Arc::new(RateLimiter::with_defaults()),
        validator: Arc::new(RequestValidator::with_defaults()),
        logger: Arc::new(QueryLogger::new()),
        metrics: Arc::new(DnsMetrics::new()),
        transfer_acl: Arc::new(transfer_acl),
        tsig_keys: Arc::new(tsig_keys),
    });
    println!("TCP DNS server listening on {addr}, zone transfer: {transfers}");

    let permits = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    loop {
        let (stream, peer) = listener.accept().await?;
        // Back-pressure on accept: at the ceiling we simply stop taking new
        // connections until one finishes, rather than spawning unboundedly.
        // The semaphore is never closed, so this only fails if we drop it.
        let Ok(permit) = permits.clone().acquire_owned().await else {
            continue;
        };
        let server = server.clone();
        tokio::spawn(async move {
            server.serve_connection(stream, peer).await;
            drop(permit);
        });
    }
}

impl TcpServer {
    /// Serve one connection until it goes idle, closes, or misbehaves.
    ///
    /// A connection carries any number of queries (RFC 7766 §6.2.1), and they
    /// are answered **concurrently**: reading, answering and writing are three
    /// separate jobs, so one slow query cannot stall the queries behind it
    /// (§6.2.1.1).
    async fn serve_connection(self: Arc<Self>, stream: TcpStream, peer: SocketAddr) {
        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(MAX_INFLIGHT_PER_CONNECTION);

        // One task owns the write half. Answers may complete out of order —
        // RFC 7766 §6.2.1.1 allows that, and clients match on the transaction
        // id — but two framed messages must never interleave on the wire, so
        // every reply funnels through here.
        let writer_logger = self.logger.clone();
        let writer_task = tokio::spawn(async move {
            while let Some(framed) = rx.recv().await {
                if let Err(e) = writer.write_all(&framed).await {
                    writer_logger.log_error(peer.ip(), &format!("socket write error: {}", e));
                    break;
                }
            }
        });

        let in_flight = Arc::new(Semaphore::new(MAX_INFLIGHT_PER_CONNECTION));

        loop {
            // DNS over TCP frames every message with a 2-byte big-endian length
            // prefix (RFC 1035 §4.2.2). Read the prefix first, then exactly that
            // many bytes — a single `read` can return a short or coalesced chunk.
            //
            // Between messages the peer may legitimately be idle, so a timeout
            // here (like EOF) is an ordinary end to a connection, not an error.
            let mut len_buf = [0u8; 2];
            match tokio::time::timeout(TCP_IDLE_TIMEOUT, reader.read_exact(&mut len_buf)).await {
                Ok(Ok(_)) => {}
                _ => break,
            }

            let len = u16::from_be_bytes(len_buf) as usize;
            if len == 0 {
                self.logger.log_error(peer.ip(), "zero-length TCP message");
                break;
            }

            // Mid-message the peer has committed to sending `len` bytes, so a
            // stall here gets a much shorter leash than an idle connection.
            let mut packet = vec![0u8; len];
            match tokio::time::timeout(TCP_READ_TIMEOUT, reader.read_exact(&mut packet)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    self.logger
                        .log_error(peer.ip(), &format!("socket read error: {}", e));
                    break;
                }
                Err(_) => {
                    self.logger
                        .log_error(peer.ip(), "timed out mid-message on TCP");
                    break;
                }
            }

            // Cap in-flight work per connection: this await is what stops a
            // pipelining client from spawning tasks faster than we retire them.
            let Ok(permit) = in_flight.clone().acquire_owned().await else {
                break;
            };
            let server = self.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                // A reply is a sequence, because a zone transfer is: several
                // messages that must reach the wire in the order they were built.
                // One sender keeps that order; another query's reply may land
                // between them, which is legal — a client demultiplexes on the
                // transaction id.
                for framed in server.answer(&packet, peer).await {
                    // A send error means the writer is gone (the peer hung up);
                    // there is nowhere left to put the rest.
                    if tx.send(framed).await.is_err() {
                        break;
                    }
                }
                drop(permit);
            });
        }

        // Dropping our sender lets the writer drain the replies still in flight
        // — the clones held by running tasks keep the channel open — and then
        // exit on its own.
        drop(tx);
        let _ = writer_task.await;
    }

    /// Answer one query, returning the length-prefixed messages to write back.
    ///
    /// A list rather than one message, because an AXFR response is a sequence
    /// (RFC 5936 §2.2). Empty means the query earned no response at all.
    async fn answer(&self, packet: &[u8], peer: SocketAddr) -> Vec<Vec<u8>> {
        let ip = peer.ip();

        if !self.rate_limiter.should_allow(ip) {
            self.logger.log_rate_limited(ip);
            instrumentation::trace_rate_limit_check(&ip, false);
            return Vec::new();
        }
        instrumentation::trace_rate_limit_check(&ip, true);

        let validation = self.validator.validate_packet(packet, true);
        if !validation.is_valid() {
            self.logger.log_error(
                ip,
                &format!(
                    "invalid query: {}",
                    validation.error_message().unwrap_or("unknown error")
                ),
            );
            instrumentation::trace_validation(&ip, false, validation.error_message());
            return Vec::new();
        }
        instrumentation::trace_validation(&ip, true, None);

        let Ok(msg) = DnsMessage::try_from_bytes(packet) else {
            self.logger.log_error(ip, "failed to parse DNS message");
            return Vec::new();
        };

        let qtype = msg.queries.first().map(|q| q.qtype);
        self.logger.log_query(ip, qtype);
        let query_name = msg
            .queries
            .first()
            .map(|q| q.qname.as_str())
            .unwrap_or("unknown");
        instrumentation::trace_query_received(&ip, query_name, qtype.unwrap_or(0));

        // TSIG before anything else that could answer: a signed message is
        // either authentic or it is not, and a server that answered the question
        // first and checked the signature afterwards would be answering questions
        // for whoever asked (RFC 8945 §5.2).
        let now = tsig::now();
        let mut session = match tsig::check_request(packet, &self.tsig_keys, now) {
            TsigCheck::Unsigned => None,
            TsigCheck::Verified(session) => Some(session),
            TsigCheck::Rejected(rejection) => {
                self.logger.log_error(
                    ip,
                    &format!(
                        "TSIG rejected (key {}): {}",
                        rejection.key_name(),
                        rejection.error.reason()
                    ),
                );
                let response = match self.error_bytes(&msg, ResponseCode::NotAuthorized) {
                    Some(bytes) => bytes,
                    None => return Vec::new(),
                };
                return match rejection.attach(response, now) {
                    Ok(bytes) => vec![frame(&bytes)],
                    Err(e) => {
                        self.logger.log_error(ip, &format!("TSIG error reply: {e}"));
                        Vec::new()
                    }
                };
            }
        };

        // A transfer is answered here rather than in `make_response`: it is a
        // sequence of messages, it is gated on an ACL, and it is the only query
        // whose answer is the entire zone.
        if msg.queries.first().map(|q| q.qtype) == Some(record_types::AXFR) {
            return self.answer_axfr(&msg, peer, session.as_mut(), now).await;
        }

        // Hold the zone lock only as long as it takes to build and serialize the
        // response — never across a socket write, or a SIGHUP zone reload would
        // queue behind a slow client for the life of its connection.
        let bytes = {
            let zones = self.zone_map.read().await;
            let resp = if msg.opcode == OpCode::Notify {
                notify_reply(&msg, &zones, peer)
            } else {
                make_response(&msg, &zones, &self.metrics)
            };
            // Over TCP the 2-byte length prefix is the only size limit, so the
            // EDNS UDP payload size does not apply (RFC 6891 §6.2.2).
            match resp.to_bytes_within(u16::MAX as usize) {
                Ok(bytes) => bytes,
                Err(e) => {
                    self.logger
                        .log_error(ip, &format!("serialization error: {}", e));
                    return Vec::new();
                }
            }
        };

        // A signed question earns a signed answer, and it is the same session,
        // so the reply's MAC covers the request's — which is what stops a reply
        // to one question being replayed as the reply to another.
        match session.as_mut() {
            Some(session) => match session.sign(bytes, now) {
                Ok(signed) => vec![frame(&signed)],
                Err(e) => {
                    self.logger.log_error(ip, &format!("TSIG signing failed: {e}"));
                    Vec::new()
                }
            },
            None => vec![frame(&bytes)],
        }
    }

    /// Answer an AXFR: the whole zone, or a refusal.
    ///
    /// Every attempt is logged, allowed or not. This is the one request where
    /// knowing it happened matters as much as whether it was permitted — a
    /// refused one is a probe, and an allowed one is a copy of the zone leaving
    /// the building.
    async fn answer_axfr(
        &self,
        msg: &DnsMessage,
        peer: SocketAddr,
        mut session: Option<&mut TsigSession>,
        now: u64,
    ) -> Vec<Vec<u8>> {
        let ip = peer.ip();
        let qname = msg
            .queries
            .first()
            .map(|q| q.qname.clone())
            .unwrap_or_default();

        // Two ways to be allowed, and they are not equivalent. A verified TSIG is
        // proof that the peer holds a secret we gave it; an address is a claim the
        // network makes on its behalf. Either grants the transfer, and which one
        // did is worth writing down.
        let authenticated_by = session.as_ref().map(|s| s.key_name().to_string());
        if authenticated_by.is_none() && !self.transfer_acl.allows(ip) {
            self.logger.log_error(
                ip,
                &format!("AXFR of {qname} refused: {ip} has no key and is not in --allow-transfer"),
            );
            println!("AXFR of {qname} from {ip}: REFUSED (no TSIG key, not in --allow-transfer)");
            return self.transfer_error(msg, ResponseCode::Refused, ip);
        }

        // An AXFR names a zone apex, not any name within it: transferring
        // example.com. because www.example.com. was asked for would hand over a
        // zone nobody named. So this is an exact match on the origin, not the
        // enclosing-zone lookup an ordinary query does.
        let messages = {
            let zones = self.zone_map.read().await;
            let apex = absolute_name(&qname);
            let Some(zone) = zones.values().find(|z| z.origin().eq_ignore_ascii_case(&apex)) else {
                println!("AXFR of {qname} from {ip}: NOTAUTH (not a zone served here)");
                return self.transfer_error(msg, ResponseCode::NotAuthorized, ip);
            };
            match axfr_messages(msg, zone) {
                Ok(messages) => messages,
                Err(e) => {
                    self.logger.log_error(ip, &format!("AXFR of {qname}: {e}"));
                    return self.transfer_error(msg, ResponseCode::ServerFailure, ip);
                }
            }
        };

        let mut frames = Vec::with_capacity(messages.len());
        let mut records = 0;
        for message in &messages {
            records += message.answers.len();
            let bytes = match message.to_bytes_within(u16::MAX as usize) {
                Ok(bytes) => bytes,
                Err(e) => {
                    // Half a transfer is worse than none: the client cannot tell
                    // a stream that stopped early from one that finished, so give
                    // up on the whole thing rather than send a prefix of it.
                    self.logger
                        .log_error(ip, &format!("AXFR of {qname}: serialization error: {e}"));
                    return self.transfer_error(msg, ResponseCode::ServerFailure, ip);
                }
            };
            // Every envelope is signed, and the MACs chain (RFC 8945 §5.3.1): a
            // dropped or reordered message then fails at the client instead of
            // passing for a complete zone.
            let bytes = match session.as_mut() {
                Some(session) => match session.sign(bytes, now) {
                    Ok(signed) => signed,
                    Err(e) => {
                        self.logger
                            .log_error(ip, &format!("AXFR of {qname}: TSIG signing failed: {e}"));
                        return self.transfer_error(msg, ResponseCode::ServerFailure, ip);
                    }
                },
                None => bytes,
            };
            frames.push(frame(&bytes));
        }
        self.metrics.increment_query_counter();
        let how = match &authenticated_by {
            Some(key) => format!("key {key}"),
            None => format!("address {ip}"),
        };
        println!(
            "AXFR of {qname} to {ip}: {records} records in {} message(s), authenticated by {how}",
            frames.len()
        );
        frames
    }

    /// One framed error response to a transfer request.
    fn transfer_error(&self, msg: &DnsMessage, rcode: ResponseCode, ip: IpAddr) -> Vec<Vec<u8>> {
        match self.error_bytes(msg, rcode) {
            Some(bytes) => vec![frame(&bytes)],
            None => {
                self.logger.log_error(ip, "could not serialize an error response");
                Vec::new()
            }
        }
    }

    /// An empty response to `msg` carrying `rcode`, serialized.
    fn error_bytes(&self, msg: &DnsMessage, rcode: ResponseCode) -> Option<Vec<u8>> {
        let mut resp = DnsMessage {
            id: msg.id,
            response: true,
            opcode: msg.opcode,
            authoritive: false,
            truncation: false,
            recursion: msg.recursion,
            recursion_ok: false,
            ad: false,
            cd: msg.cd,
            rcode,
            queries: msg.queries.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        if msg.has_edns() {
            let _ = resp.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
        }
        resp.to_bytes_within(u16::MAX as usize).ok()
    }
}

/// A message with its RFC 1035 §4.2.2 length prefix, in one buffer so the writer
/// emits both in a single call.
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(2 + bytes.len());
    framed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    framed.extend_from_slice(bytes);
    framed
}

/// An empty TC=1 answer to `request`: the question echoed, no records.
///
/// This is what a client over its response budget gets instead of the answer.
/// It is smaller than the query that asked for it, so it is useless for
/// amplification, and RFC 1035 §4.2.1 has the client retry over TCP — where the
/// handshake proves the source address and the budget no longer applies. Going
/// silent instead would leave a legitimate client with a timeout and no idea that
/// TCP would work.
fn truncated_reply(request: &DnsMessage) -> Option<Vec<u8>> {
    let mut resp = DnsMessage {
        id: request.id,
        response: true,
        opcode: request.opcode,
        authoritive: true,
        truncation: true,
        recursion: request.recursion,
        recursion_ok: false,
        ad: false,
        cd: request.cd,
        rcode: ResponseCode::Ok,
        queries: request.queries.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    if request.has_edns() {
        let _ = resp.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
    }
    resp.to_bytes_within(512).ok()
}

/// Answer a NOTIFY (RFC 1996).
///
/// This server is a primary: it serves zone files, has no secondary role, no
/// master to be told by, and nothing to fetch if it were. So the honest answer is
/// NOTAUTH — *I am not a secondary for that zone* — whether or not the zone is one
/// we serve, and the attempt is logged either way. A NOTIFY arriving from an
/// unexpected source is worth seeing; RFC 1996 §3.10 has a secondary log exactly
/// that, and the same reasoning applies to a primary being told news about its own
/// zone.
///
/// What matters as much is that it is answered *as a NOTIFY*: same opcode, the
/// question echoed, no data (§4.7). Before the opcode decode was fixed this
/// arrived as an `Unknown` opcode and was answered as though it were a lookup for
/// the zone's SOA — a plausible-looking reply to a message that asked nothing.
fn notify_reply(
    msg: &DnsMessage,
    zone_map: &HashMap<String, Zone>,
    peer: SocketAddr,
) -> DnsMessage {
    let zone = notify::notified_zone(msg).unwrap_or_default();
    let ours = zone_map
        .values()
        .any(|z| z.origin().eq_ignore_ascii_case(&absolute_name(&zone)));
    let why = if ours {
        "this server is its primary, not a secondary"
    } else {
        "not a zone served here"
    };
    println!("NOTIFY for {zone} from {peer}: NOTAUTH ({why})");
    notify::notify_response(msg, ResponseCode::NotAuthorized)
}

/// A name in absolute form, so it can be compared with a zone origin.
fn absolute_name(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

async fn udp_main(
    addr: &str,
    zone_map: Arc<RwLock<HashMap<String, Zone>>>,
    response_rate: u32,
    tsig_keys: TsigKeyring,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    let rate_limiter = Arc::new(RateLimiter::with_defaults());
    // The query limiter counts requests; this one counts the bytes going back,
    // which is what an amplification attack is measured in.
    let response_limiter = Arc::new(if response_rate == 0 {
        ResponseLimiter::disabled()
    } else {
        ResponseLimiter::new(response_rate, response_rate.saturating_mul(4), 2)
    });
    let validator = Arc::new(RequestValidator::with_defaults());
    let logger = Arc::new(QueryLogger::new());
    let metrics = Arc::new(DnsMetrics::new());
    let tsig_keys = Arc::new(tsig_keys);
    let budget = if response_rate == 0 {
        "off".to_string()
    } else {
        format!("{response_rate} bytes/s per client")
    };
    println!(
        "UDP DNS server listening on {addr}, response budget: {budget}, TSIG keys: {}",
        tsig_keys.len()
    );

    let mut buf = vec![0; 4096];

    loop {
        let (size, peer) = socket.recv_from(&mut buf).await?;
        let zone_map = zone_map.clone();
        let socket = socket.clone();
        let rate_limiter = rate_limiter.clone();
        let response_limiter = response_limiter.clone();
        let tsig_keys = tsig_keys.clone();
        let validator = validator.clone();
        let logger = logger.clone();
        let metrics = metrics.clone();
        let packet = buf[0..size].to_vec();

        tokio::spawn(async move {
            // Rate limiting check
            if !rate_limiter.should_allow(peer.ip()) {
                logger.log_rate_limited(peer.ip());
                instrumentation::trace_rate_limit_check(&peer.ip(), false);
                return;
            }
            instrumentation::trace_rate_limit_check(&peer.ip(), true);

            // Validation check
            let validation = validator.validate_packet(&packet, false);
            if !validation.is_valid() {
                logger.log_error(
                    peer.ip(),
                    &format!(
                        "invalid query: {}",
                        validation.error_message().unwrap_or("unknown error")
                    ),
                );
                instrumentation::trace_validation(&peer.ip(), false, validation.error_message());
                return;
            }
            instrumentation::trace_validation(&peer.ip(), true, None);

            if let Ok(msg) = DnsMessage::try_from_bytes(&packet) {
                // Log successful query parsing
                let qtype = msg.queries.first().map(|q| q.qtype);
                logger.log_query(peer.ip(), qtype);

                // A signed query is checked before it is answered, and its answer
                // is signed back (RFC 8945). A rejected one gets NOTAUTH and a
                // TSIG saying which of BADKEY/BADSIG/BADTIME it was.
                let now = tsig::now();
                let mut session = match tsig::check_request(&packet, &tsig_keys, now) {
                    TsigCheck::Unsigned => None,
                    TsigCheck::Verified(session) => Some(session),
                    TsigCheck::Rejected(rejection) => {
                        logger.log_error(
                            peer.ip(),
                            &format!(
                                "TSIG rejected (key {}): {}",
                                rejection.key_name(),
                                rejection.error.reason()
                            ),
                        );
                        let mut resp = DnsMessage {
                            id: msg.id,
                            response: true,
                            opcode: msg.opcode,
                            authoritive: false,
                            truncation: false,
                            recursion: msg.recursion,
                            recursion_ok: false,
                            ad: false,
                            cd: msg.cd,
                            rcode: ResponseCode::NotAuthorized,
                            queries: msg.queries.clone(),
                            answers: Vec::new(),
                            authorities: Vec::new(),
                            additionals: Vec::new(),
                        };
                        if msg.has_edns() {
                            let _ = resp.set_edns(Edns::with_payload_size(RDNSD_PAYLOAD_SIZE));
                        }
                        if let Ok(bytes) = resp.to_bytes_within(msg.udp_payload_size() as usize) {
                            if let Ok(bytes) = rejection.attach(bytes, now) {
                                let _ = socket.send_to(&bytes, peer).await;
                            }
                        }
                        return;
                    }
                };

                let query_name = msg
                    .queries
                    .first()
                    .map(|q| q.qname.as_str())
                    .unwrap_or("unknown");
                instrumentation::trace_query_received(&peer.ip(), query_name, qtype.unwrap_or(0));

                // Build the response under the zone lock, then drop it before
                // touching the socket: a read guard held across `send_to` would
                // stall a SIGHUP zone reload behind the network.
                let serialized = {
                    let zones = zone_map.read().await;
                    let resp = if msg.opcode == OpCode::Notify {
                        notify_reply(&msg, &zones, peer)
                    } else {
                        make_response(&msg, &zones, &metrics)
                    };
                    // Honor the client's EDNS0 UDP payload size (512 if no EDNS);
                    // truncates with TC=1 if the response is larger.
                    resp.to_bytes_within(msg.udp_payload_size() as usize)
                };
                match serialized {
                    Ok(bytes) => {
                        // Charge the response, not the query. Over budget, a
                        // truncated reply is the useful refusal: it carries no
                        // records, so it cannot amplify, and a real client reads
                        // TC=1 and asks again over TCP where the handshake proves
                        // who it is. Dropping is for the rest.
                        let reply = match response_limiter.admit(peer.ip(), bytes.len()) {
                            ResponseVerdict::Send => Some(bytes),
                            ResponseVerdict::Truncate => {
                                logger.log_rate_limited(peer.ip());
                                metrics.increment_cache_misses();
                                truncated_reply(&msg)
                            }
                            ResponseVerdict::Drop => {
                                logger.log_rate_limited(peer.ip());
                                instrumentation::trace_rate_limit_check(&peer.ip(), false);
                                None
                            }
                        };
                        // Sign whatever we ended up sending — including a
                        // truncated one, since that is still our answer to a
                        // question someone authenticated.
                        let reply = match (reply, session.as_mut()) {
                            (Some(reply), Some(session)) => match session.sign(reply, now) {
                                Ok(signed) => Some(signed),
                                Err(e) => {
                                    logger.log_error(
                                        peer.ip(),
                                        &format!("TSIG signing failed: {e}"),
                                    );
                                    None
                                }
                            },
                            (reply, _) => reply,
                        };
                        if let Some(reply) = reply {
                            if let Err(e) = socket.send_to(&reply, peer).await {
                                logger.log_error(peer.ip(), &format!("socket send error: {}", e));
                                instrumentation::trace_error(
                                    "socket_send",
                                    Some(&peer.ip()),
                                    &e.to_string(),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        logger.log_error(peer.ip(), &format!("serialization error: {}", e));
                        instrumentation::trace_error(
                            "serialization",
                            Some(&peer.ip()),
                            &e.to_string(),
                        );
                    }
                }
            } else {
                logger.log_error(peer.ip(), "failed to parse DNS message");
                instrumentation::trace_error(
                    "parse_dns_message",
                    Some(&peer.ip()),
                    "failed to parse DNS message",
                );
            }
        });
    }
}

/// Spawn a signal handler task to reload zones on SIGHUP (Unix only)
#[cfg(unix)]
fn spawn_signal_handler(
    zone_map: Arc<RwLock<HashMap<String, Zone>>>,
    source: ZoneSource,
    notify_targets: Vec<SocketAddr>,
    announced: Vec<(String, u32)>,
) {
    let zone_map_clone = Arc::clone(&zone_map);
    let source_clone = source.clone();
    tokio::spawn(async move {
        let mut announced = announced;
        if let Ok(mut signals) = Signals::new(&[SIGHUP]) {
            while signals.next().await.is_some() {
                match load_zones_from_source(&source_clone).await {
                    Ok(new_zones) => {
                        *zone_map_clone.write().await = new_zones;
                        println!("Zones reloaded via SIGHUP");
                        instrumentation::trace_info("zones_reloaded", "SIGHUP signal");
                        // The point of reloading is that something changed, so
                        // this is exactly when a secondary wants to hear about it.
                        announced =
                            announce_zones(&zone_map_clone, &announced, &notify_targets).await;
                    }
                    Err(e) => {
                        eprintln!("Failed to reload zones: {}", e);
                        instrumentation::trace_error("zone_reload_failed", None, &e.to_string());
                    }
                }
            }
        }
    });
}

/// No-op signal handler for non-Unix platforms
#[cfg(not(unix))]
fn spawn_signal_handler(
    _zone_map: Arc<RwLock<HashMap<String, Zone>>>,
    _source: ZoneSource,
    _notify_targets: Vec<SocketAddr>,
    _announced: Vec<(String, u32)>,
) {
    // Signal handling not supported on this platform, so a zone change is only
    // announced at startup here.
}

/// `addr` or `addr:port` for a secondary, defaulting to port 53.
///
/// A bare IPv6 address has colons of its own, so `[::1]:5353` is the only
/// unambiguous way to give one a port — which is what `SocketAddr` already
/// parses, so the shape is the familiar one rather than a new convention.
fn parse_notify_targets(specs: &[String]) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error>> {
    let mut targets = Vec::new();
    for spec in specs {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        if let Ok(addr) = spec.parse::<SocketAddr>() {
            targets.push(addr);
            continue;
        }
        match spec.parse::<IpAddr>() {
            Ok(ip) => targets.push(SocketAddr::new(ip, 53)),
            Err(e) => {
                return Err(Box::from(format!(
                    "--also-notify {spec:?} is not an address or address:port: {e}"
                )))
            }
        }
    }
    Ok(targets)
}

/// Tell every secondary about the zones whose serial moved since `announced`,
/// and return the serials now announced.
///
/// Called after each load. A zone whose serial did not move is not news, and one
/// that went backwards is not either — a secondary compares serials and would
/// ignore it, so sending would be noise.
async fn announce_zones(
    zone_map: &Arc<RwLock<HashMap<String, Zone>>>,
    announced: &[(String, u32)],
    targets: &[SocketAddr],
) -> Vec<(String, u32)> {
    let (current, pending) = {
        let zones = zone_map.read().await;
        let all: Vec<&Zone> = zones.values().collect();
        let current = notify::zone_serials(&all);
        let changed = notify::changed_zones(announced, &current);
        // Build the messages under the lock, send them outside it: a NOTIFY that
        // goes unanswered takes seconds to retry, and holding the zone map that
        // long would block a reload behind the network.
        let pending: Vec<(String, u32, Option<rdns::ResourceRecord>)> = changed
            .iter()
            .filter_map(|(name, serial)| {
                zones
                    .get(name)
                    .map(|zone| (name.clone(), *serial, notify::soa_record(zone)))
            })
            .collect();
        (current, pending)
    };

    if targets.is_empty() || pending.is_empty() {
        return current;
    }
    for (zone, serial, soa) in pending {
        for target in targets {
            let target = *target;
            let zone = zone.clone();
            let soa = soa.clone();
            tokio::spawn(async move {
                send_notify(&zone, serial, soa, target).await;
            });
        }
    }
    current
}

/// Send one NOTIFY, retrying until it is acknowledged (RFC 1996 §3.6).
///
/// Any rcode is an acknowledgement: a secondary answering NOTAUTH has still
/// received the message, and repeating it would not change its mind. Giving up
/// after [`notify::NOTIFY_ATTEMPTS`] is safe because the secondary's refresh timer
/// is the backstop this is an optimisation over.
async fn send_notify(
    zone: &str,
    serial: u32,
    soa: Option<rdns::ResourceRecord>,
    target: SocketAddr,
) {
    let bind: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid bind address")
    } else {
        "[::]:0".parse().expect("valid bind address")
    };
    let Ok(socket) = UdpSocket::bind(bind).await else {
        eprintln!("NOTIFY {zone} to {target}: could not open a socket");
        return;
    };

    let mut wait = Duration::from_secs(notify::NOTIFY_RETRY_SECS);
    for attempt in 1..=notify::NOTIFY_ATTEMPTS {
        let id = rand_id();
        let msg = notify::notify_request(zone, soa.clone(), id);
        let mut buf = vec![0u8; 512];
        let Ok(len) = msg.to_bytes(&mut buf) else {
            eprintln!("NOTIFY {zone}: could not serialize");
            return;
        };
        if socket.send_to(&buf[..len], target).await.is_err() {
            eprintln!("NOTIFY {zone} to {target}: send failed");
            return;
        }

        let mut reply = vec![0u8; 512];
        // Something answered, but not this? Treat it as no answer rather than as
        // an acknowledgement: an off-path reply should not be able to silence a
        // notification.
        if let Ok(Ok((n, _))) = tokio::time::timeout(wait, socket.recv_from(&mut reply)).await {
            if let Ok(parsed) = DnsMessage::try_from_bytes(&reply[..n]) {
                if notify::acknowledges(&parsed, id) {
                    println!(
                        "NOTIFY {zone} serial {serial} to {target}: acknowledged ({:?})",
                        parsed.rcode
                    );
                    return;
                }
            }
        }
        if attempt < notify::NOTIFY_ATTEMPTS {
            wait *= 2;
        }
    }
    eprintln!(
        "NOTIFY {zone} serial {serial} to {target}: no acknowledgement after {} attempts",
        notify::NOTIFY_ATTEMPTS
    );
}

/// A transaction id for a NOTIFY. Random, for the same reason a query's is.
fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // A full CSPRNG is overkill for a message we also match by source and opcode,
    // and the workspace's `rand` is a library dependency rather than this crate's.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ (nanos >> 16)) as u16
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    match args.commands {
        Some(Commands::Tcp {
            host,
            port,
            zone_file,
            zone_dir,
            allow_transfer,
            tsig_key,
            also_notify,
        }) => {
            validate_cli_args(&host, port)?;
            // A typo in the transfer list stops the server rather than quietly
            // narrowing it — or, worse, being read as something wider.
            let transfer_acl = TransferAcl::parse(&allow_transfer).map_err(Box::<dyn std::error::Error>::from)?;
            let tsig_keys =
                TsigKeyring::parse(&tsig_key).map_err(Box::<dyn std::error::Error>::from)?;
            let notify_targets = parse_notify_targets(&also_notify)?;
            let source = validate_zone_source(zone_file, zone_dir)?;
            let zones = load_zones_from_source(&source).await?;
            let zone_map = Arc::new(RwLock::new(zones));
            let addr = format!("{}:{}", host, port);
            
            // Spawn signal handler task for zone reload (SIGHUP on Unix)
            // A zone that has just been loaded is news to every secondary, which
            // is why this runs at startup and not only on reload.
            let announced = announce_zones(&zone_map, &[], &notify_targets).await;
            spawn_signal_handler(zone_map.clone(), source, notify_targets, announced);
            
            tcp_main(&addr, zone_map, transfer_acl, tsig_keys).await?;
        }
        Some(Commands::Udp {
            host,
            port,
            zone_file,
            zone_dir,
            response_rate,
            tsig_key,
            also_notify,
        }) => {
            validate_cli_args(&host, port)?;
            let tsig_keys =
                TsigKeyring::parse(&tsig_key).map_err(Box::<dyn std::error::Error>::from)?;
            let notify_targets = parse_notify_targets(&also_notify)?;
            let source = validate_zone_source(zone_file, zone_dir)?;
            let zones = load_zones_from_source(&source).await?;
            let zone_map = Arc::new(RwLock::new(zones));
            let addr = format!("{}:{}", host, port);
            
            // Spawn signal handler task for zone reload (SIGHUP on Unix)
            // A zone that has just been loaded is news to every secondary, which
            // is why this runs at startup and not only on reload.
            let announced = announce_zones(&zone_map, &[], &notify_targets).await;
            spawn_signal_handler(zone_map.clone(), source, notify_targets, announced);
            
            udp_main(&addr, zone_map, response_rate, tsig_keys).await?;
        }
        None => {
            return Err(Box::from(
                "usage: rdnsd <tcp|udp> [--host HOST] [--port PORT] [--zone-file FILE|--zone-dir DIR]",
            ));
        }
    }
    Ok(())
}

/// Validate CLI arguments: host and port
fn validate_cli_args(host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    // Port must be 1-65535 (0 is reserved)
    if port == 0 {
        return Err(Box::from("Port must be in range 1-65535"));
    }
    
    // Host must be valid IP or hostname (basic validation)
    // This is a simple check; more complex validation could parse as IP
    if host.is_empty() {
        return Err(Box::from("Host cannot be empty"));
    }
    
    // Very basic hostname/IP validation - just check for invalid characters
    // Valid hostnames: alphanumeric, dots, hyphens, colons (for IPv6)
    if !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '%') {
        return Err(Box::from(format!("Invalid host format: {}", host)));
    }
    
    Ok(())
}

/// Validate that exactly one of zone_file or zone_dir is specified
fn validate_zone_source(
    zone_file: Option<String>,
    zone_dir: Option<String>,
) -> Result<ZoneSource, Box<dyn std::error::Error>> {
    match (zone_file, zone_dir) {
        (Some(file), None) => {
            // Check if file exists
            if !Path::new(&file).exists() {
                return Err(Box::from(format!("Zone file not found: {}", file)));
            }
            Ok(ZoneSource::SingleFile(file))
        }
        (None, Some(dir)) => {
            // Check if directory exists
            if !Path::new(&dir).is_dir() {
                return Err(Box::from(format!("Zone directory not found or not a directory: {}", dir)));
            }
            Ok(ZoneSource::Directory(dir))
        }
        (Some(_), Some(_)) => {
            Err(Box::from("Cannot specify both --zone-file and --zone-dir"))
        }
        (None, None) => {
            Err(Box::from("Must specify either --zone-file or --zone-dir"))
        }
    }
}

/// Load zones from source (single file or directory)
async fn load_zones_from_source(
    source: &ZoneSource,
) -> Result<HashMap<String, Zone>, Box<dyn std::error::Error>> {
    match source {
        ZoneSource::SingleFile(path) => {
            // Path-aware, so a `$INCLUDE` in the file resolves next to it rather
            // than against whatever directory the daemon happens to run in.
            let zone_origin = extract_zone_origin_from_path(path);
            let zone = parse_zone_file_at(Path::new(path), &zone_origin)?;
            let mut map = HashMap::new();
            map.insert(zone.origin().to_string(), zone);
            println!("Loaded zone from {}", path);
            Ok(map)
        }
        ZoneSource::Directory(dir) => {
            enumerate_zone_files(dir)
        }
    }
}

/// Extract zone origin from zone file path
/// Example: "example.com.zone" -> "example.com."
fn extract_zone_origin_from_path(path: &str) -> String {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("zone");
    
    // Remove .zone extension if present
    let origin = if let Some(stripped) = file_name.strip_suffix(".zone") {
        stripped
    } else {
        file_name
    };
    
    // Ensure it ends with a dot
    if origin.ends_with('.') {
        origin.to_string()
    } else {
        format!("{}.", origin)
    }
}

/// Enumerate all .zone files in a directory and load them
fn enumerate_zone_files(dir: &str) -> Result<HashMap<String, Zone>, Box<dyn std::error::Error>> {
    let mut zones = HashMap::new();
    let entries = std::fs::read_dir(dir)?;
    
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        
        if path.extension().and_then(|s| s.to_str()) == Some("zone") {
            let path_str = path.to_string_lossy();
            let zone_origin = extract_zone_origin_from_path(&path_str);
            match parse_zone_file_at(&path, &zone_origin) {
                Ok(zone) => {
                    println!("Loaded zone from {}", path_str);
                    zones.insert(zone.origin().to_string(), zone);
                }
                Err(e) => {
                    eprintln!("Error loading zone file {}: {}", path_str, e);
                    // Continue with next file
                }
            }
        }
    }
    
    if zones.is_empty() {
        return Err(Box::from(format!("No .zone files found in directory: {}", dir)));
    }
    
    println!("Loaded {} zones from directory {}", zones.len(), dir);
    Ok(zones)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cli_args_valid() {
        // Test CLI argument validation with valid args
        let result = validate_cli_args("0.0.0.0", 53);
        assert!(result.is_ok(), "Valid host and port should pass validation");
    }

    #[test]
    fn test_validate_cli_args_invalid_port_too_high() {
        // Test CLI argument validation with port > 65535
        // Since port is u16, we can only test with maximum valid value
        // This test documents the port range constraint
        let result = validate_cli_args("0.0.0.0", 65535);
        assert!(result.is_ok(), "Max port (65535) should pass validation");
    }

    #[test]
    fn test_validate_cli_args_invalid_port_zero() {
        // Test CLI argument validation with port 0
        let result = validate_cli_args("0.0.0.0", 0);
        assert!(result.is_err(), "Port 0 should fail validation");
    }

    #[test]
    fn test_validate_cli_args_localhost() {
        // Test CLI argument validation with localhost (valid for local dev)
        let result = validate_cli_args("127.0.0.1", 5353);
        assert!(result.is_ok(), "Localhost with custom port should pass validation");
    }

    #[test]
    fn test_validate_cli_args_custom_host() {
        // Test CLI argument validation with custom host
        let result = validate_cli_args("192.168.1.1", 8053);
        assert!(result.is_ok(), "Custom host and port should pass validation");
    }

    #[test]
    fn test_validate_cli_args_ipv6() {
        // Test CLI argument validation with IPv6 address (without brackets for validation)
        let result = validate_cli_args("::1", 53);
        assert!(result.is_ok(), "IPv6 address should pass validation");
    }

    #[test]
    fn test_extract_zone_origin_with_extension() {
        // Test zone origin extraction from filename with .zone extension
        let origin = extract_zone_origin_from_path("example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_with_path() {
        // Test zone origin extraction from full path
        let origin = extract_zone_origin_from_path("/etc/dns/example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_already_dotted() {
        // Test zone origin extraction when filename already has trailing dot
        let origin = extract_zone_origin_from_path("example.com..zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_no_extension() {
        // Test zone origin extraction from filename without .zone extension
        let origin = extract_zone_origin_from_path("example.com");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_extract_zone_origin_deep_path() {
        // Test zone origin extraction from deep directory path
        let origin = extract_zone_origin_from_path("/var/lib/dns/zones/example.com.zone");
        assert_eq!(origin, "example.com.");
    }

    #[test]
    fn test_validate_zone_source_file_present() {
        // Test zone source validation error when file doesn't exist
        // This documents that validate_zone_source checks file existence
        let result = validate_zone_source(Some("nonexistent.zone".to_string()), None);
        assert!(result.is_err(), "Non-existent file should fail validation");
    }

    #[test]
    fn test_validate_zone_source_dir_present() {
        // Test zone source validation error when directory doesn't exist
        // This documents that validate_zone_source checks directory existence
        let result = validate_zone_source(None, Some("/nonexistent/path".to_string()));
        assert!(result.is_err(), "Non-existent directory should fail validation");
    }

    #[test]
    fn test_validate_zone_source_both_present_error() {
        // Test zone source validation rejects when both file and dir provided
        let result = validate_zone_source(Some("test.zone".to_string()), Some("/etc/dns".to_string()));
        assert!(result.is_err(), "Should reject when both file and dir specified");
    }

    #[test]
    fn test_validate_zone_source_neither_present_error() {
        // Test zone source validation rejects when neither file nor dir provided
        let result = validate_zone_source(None, None);
        assert!(result.is_err(), "Should reject when neither file nor dir specified");
    }
}
