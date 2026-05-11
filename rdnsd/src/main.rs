use std::sync::Arc;

use clap::{Parser, Subcommand};
use rdns::{
    logging::QueryLogger,
    security::RateLimiter,
    telemetry::{instrumentation, DnsMetrics, LatencyTimer},
    validation::RequestValidator,
    zone::{parse_zone_file, Zone},
    DnsMessage, ResourceRecord, ResponseCode,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    commands: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Tcp {
        addr: String,
        #[arg(long)]
        zone_file: Option<String>,
    },
    Udp {
        addr: String,
        #[arg(long)]
        zone_file: Option<String>,
    },
}

/// Build a DNS response for the given query message
fn make_response(msg: &DnsMessage, zone: &Zone, metrics: &DnsMetrics) -> DnsMessage {
    let timer = LatencyTimer::new();
    let mut response = DnsMessage {
        id: msg.id,
        response: true,
        opcode: msg.opcode.clone(),
        authoritive: true,
        truncation: false,
        recursion: msg.recursion,
        recursion_ok: false,
        rcode: ResponseCode::Ok,
        queries: msg.queries.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };

    // Process each query
    for query in &msg.queries {
        let matching_records = zone.query(&query.qname, query.qtype);

        if matching_records.is_empty() {
            // No records found - return NXDOMAIN if no other records for this domain
            let any_records = zone.records.iter().any(|r| {
                r.name.to_lowercase().trim_end_matches('.')
                    == query.qname.to_lowercase().trim_end_matches('.')
            });

            if !any_records {
                response.rcode = ResponseCode::NoSuchDomain;
            }

            metrics.increment_cache_misses();
        } else {
            // Add matching records to answer section
            for record in matching_records {
                response.answers.push(ResourceRecord {
                    name: record.name.clone(),
                    class: record.class,
                    ttl: record.ttl,
                    rdata: record.rdata.clone(),
                });
            }

            metrics.increment_cache_hits();
        }

        metrics.increment_query_counter();
    }

    // Log query response with latency
    let query_name = msg
        .queries
        .first()
        .map(|q| q.qname.as_str())
        .unwrap_or("unknown");
    let query_type = msg.queries.first().map(|q| q.qtype).unwrap_or(0);
    instrumentation::trace_query_response(query_name, query_type, timer.elapsed_ms(), None);

    response
}

async fn tcp_main(addr: &str, zone: Arc<Zone>) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    let rate_limiter = Arc::new(RateLimiter::with_defaults());
    let validator = Arc::new(RequestValidator::with_defaults());
    let logger = Arc::new(QueryLogger::new());
    let metrics = Arc::new(DnsMetrics::new());
    println!("TCP DNS server listening on {}", addr);

    loop {
        let (mut socket, peer_addr) = listener.accept().await?;
        let zone = zone.clone();
        let rate_limiter = rate_limiter.clone();
        let validator = validator.clone();
        let logger = logger.clone();
        let metrics = metrics.clone();

        tokio::spawn(async move {
            let mut buf = [0; 16384]; // 16KB for TCP

            let n = match socket.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    logger.log_error(peer_addr.ip(), &format!("socket read error: {}", e));
                    return;
                }
            };

            // Rate limiting check
            if !rate_limiter.should_allow(peer_addr.ip()) {
                logger.log_rate_limited(peer_addr.ip());
                instrumentation::trace_rate_limit_check(&peer_addr.ip(), false);
                return;
            }
            instrumentation::trace_rate_limit_check(&peer_addr.ip(), true);

            // Validation check
            let validation = validator.validate_packet(&buf[0..n], true);
            if !validation.is_valid() {
                logger.log_error(
                    peer_addr.ip(),
                    &format!(
                        "invalid query: {}",
                        validation.error_message().unwrap_or("unknown error")
                    ),
                );
                instrumentation::trace_validation(
                    &peer_addr.ip(),
                    false,
                    validation.error_message(),
                );
                return;
            }
            instrumentation::trace_validation(&peer_addr.ip(), true, None);

            if let Ok(msg) = DnsMessage::try_from_bytes(&buf[0..n]) {
                // Log successful query parsing
                let qtype = msg.queries.first().map(|q| q.qtype);
                logger.log_query(peer_addr.ip(), qtype);

                let query_name = msg
                    .queries
                    .first()
                    .map(|q| q.qname.as_str())
                    .unwrap_or("unknown");
                instrumentation::trace_query_received(
                    &peer_addr.ip(),
                    query_name,
                    qtype.unwrap_or(0),
                );

                let resp = make_response(&msg, &zone, &metrics);
                let mut response_buf = [0; 16384];
                match resp.to_bytes(&mut response_buf) {
                    Ok(n) => {
                        if let Err(e) = socket.write_all(&response_buf[0..n]).await {
                            logger.log_error(peer_addr.ip(), &format!("socket write error: {}", e));
                        }
                    }
                    Err(e) => {
                        logger.log_error(peer_addr.ip(), &format!("serialization error: {}", e));
                    }
                }
            } else {
                logger.log_error(peer_addr.ip(), "failed to parse DNS message");
            }
        });
    }
}

async fn udp_main(addr: &str, zone: Arc<Zone>) -> Result<(), Box<dyn std::error::Error>> {
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    let rate_limiter = Arc::new(RateLimiter::with_defaults());
    let validator = Arc::new(RequestValidator::with_defaults());
    let logger = Arc::new(QueryLogger::new());
    let metrics = Arc::new(DnsMetrics::new());
    println!("UDP DNS server listening on {}", addr);

    let mut buf = vec![0; 512];

    loop {
        let (size, peer) = socket.recv_from(&mut buf).await?;
        let zone = zone.clone();
        let socket = socket.clone();
        let rate_limiter = rate_limiter.clone();
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

                let query_name = msg
                    .queries
                    .first()
                    .map(|q| q.qname.as_str())
                    .unwrap_or("unknown");
                instrumentation::trace_query_received(&peer.ip(), query_name, qtype.unwrap_or(0));

                let resp = make_response(&msg, &zone, &metrics);
                let mut response_buf = [0; 512];
                match resp.to_bytes(&mut response_buf) {
                    Ok(n) => {
                        if let Err(e) = socket.send_to(&response_buf[0..n], peer).await {
                            logger.log_error(peer.ip(), &format!("socket send error: {}", e));
                            instrumentation::trace_error(
                                "socket_send",
                                Some(&peer.ip()),
                                &e.to_string(),
                            );
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    match args.commands {
        Some(Commands::Tcp { addr, zone_file }) => {
            let zone = load_zone(zone_file.as_deref())?;
            tcp_main(&addr, Arc::new(zone)).await?;
        }
        Some(Commands::Udp { addr, zone_file }) => {
            let zone = load_zone(zone_file.as_deref())?;
            udp_main(&addr, Arc::new(zone)).await?;
        }
        None => {
            return Err(Box::from("usage: <address> <zonefile>"));
        }
    }
    Ok(())
}

/// Load a zone from a file, or create an empty example zone if no file is provided
fn load_zone(zone_file: Option<&str>) -> Result<Zone, Box<dyn std::error::Error>> {
    match zone_file {
        Some(path) => {
            let content = std::fs::read_to_string(path)?;
            let zone = parse_zone_file(&content, "example.com.")?;
            println!("Loaded zone from {}", path);
            Ok(zone)
        }
        None => {
            // Create an example zone
            println!("No zone file specified, creating example zone");
            let mut zone = Zone::new("example.com.".to_string());
            zone.add_record(rdns::zone::ZoneRecord {
                name: "example.com.".to_string(),
                ttl: 300,
                class: 1, // IN
                rdata: rdns::ResourceRecordKind::A("192.0.2.1".parse()?),
            });
            zone.add_record(rdns::zone::ZoneRecord {
                name: "www.example.com.".to_string(),
                ttl: 300,
                class: 1, // IN
                rdata: rdns::ResourceRecordKind::A("192.0.2.2".parse()?),
            });
            Ok(zone)
        }
    }
}
