use std::collections::HashMap;
use std::path::Path;
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
use tokio::sync::RwLock;

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
        // Find the matching zone for this query
        let zone = find_zone_for_query(&query.qname, zone_map);
        
        if let Some(zone) = zone {
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

    response
}

/// Find the zone that should handle this query
/// 
/// Matches the query name against zone origins, preferring the most specific (longest) match
fn find_zone_for_query<'a>(qname: &str, zone_map: &'a HashMap<String, Zone>) -> Option<&'a Zone> {
    let qname_lower = qname.to_lowercase();
    
    // Find all zones that could handle this query
    let mut candidates: Vec<_> = zone_map
        .values()
        .filter(|zone| {
            let zone_origin = zone.origin.trim_end_matches('.').to_lowercase();
            qname_lower.ends_with(&zone_origin) || qname_lower == zone_origin
        })
        .collect();
    
    // Sort by zone origin length (longest first, most specific)
    candidates.sort_by(|a, b| {
        b.origin.len().cmp(&a.origin.len())
    });
    
    candidates.first().copied()
}

async fn tcp_main(
    addr: &str,
    zone_map: Arc<RwLock<HashMap<String, Zone>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(addr).await?;
    let rate_limiter = Arc::new(RateLimiter::with_defaults());
    let validator = Arc::new(RequestValidator::with_defaults());
    let logger = Arc::new(QueryLogger::new());
    let metrics = Arc::new(DnsMetrics::new());
    println!("TCP DNS server listening on {}", addr);

    loop {
        let (mut socket, peer_addr) = listener.accept().await?;
        let zone_map = zone_map.clone();
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

                // Read zone map and generate response
                let zone_map = zone_map.read().await;
                let resp = make_response(&msg, &zone_map, &metrics);
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

async fn udp_main(
    addr: &str,
    zone_map: Arc<RwLock<HashMap<String, Zone>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    let rate_limiter = Arc::new(RateLimiter::with_defaults());
    let validator = Arc::new(RequestValidator::with_defaults());
    let logger = Arc::new(QueryLogger::new());
    let metrics = Arc::new(DnsMetrics::new());
    println!("UDP DNS server listening on {}", addr);

    let mut buf = vec![0; 512];

    loop {
        let (size, peer) = socket.recv_from(&mut buf).await?;
        let zone_map = zone_map.clone();
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

                // Read zone map and generate response
                let zone_map = zone_map.read().await;
                let resp = make_response(&msg, &zone_map, &metrics);
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

/// Spawn a signal handler task to reload zones on SIGHUP (Unix only)
#[cfg(unix)]
fn spawn_signal_handler(zone_map: Arc<RwLock<HashMap<String, Zone>>>, source: ZoneSource) {
    let zone_map_clone = Arc::clone(&zone_map);
    let source_clone = source.clone();
    tokio::spawn(async move {
        if let Ok(mut signals) = Signals::new(&[SIGHUP]) {
            while signals.next().await.is_some() {
                match load_zones_from_source(&source_clone).await {
                    Ok(new_zones) => {
                        *zone_map_clone.write().await = new_zones;
                        println!("Zones reloaded via SIGHUP");
                        instrumentation::trace_info("zones_reloaded", "SIGHUP signal");
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
fn spawn_signal_handler(_zone_map: Arc<RwLock<HashMap<String, Zone>>>, _source: ZoneSource) {
    // Signal handling not supported on this platform
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    match args.commands {
        Some(Commands::Tcp { host, port, zone_file, zone_dir }) => {
            validate_cli_args(&host, port)?;
            let source = validate_zone_source(zone_file, zone_dir)?;
            let zones = load_zones_from_source(&source).await?;
            let zone_map = Arc::new(RwLock::new(zones));
            let addr = format!("{}:{}", host, port);
            
            // Spawn signal handler task for zone reload (SIGHUP on Unix)
            spawn_signal_handler(zone_map.clone(), source);
            
            tcp_main(&addr, zone_map).await?;
        }
        Some(Commands::Udp { host, port, zone_file, zone_dir }) => {
            validate_cli_args(&host, port)?;
            let source = validate_zone_source(zone_file, zone_dir)?;
            let zones = load_zones_from_source(&source).await?;
            let zone_map = Arc::new(RwLock::new(zones));
            let addr = format!("{}:{}", host, port);
            
            // Spawn signal handler task for zone reload (SIGHUP on Unix)
            spawn_signal_handler(zone_map.clone(), source);
            
            udp_main(&addr, zone_map).await?;
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
            let content = std::fs::read_to_string(path)?;
            let zone_origin = extract_zone_origin_from_path(path);
            let zone = parse_zone_file(&content, &zone_origin)?;
            let mut map = HashMap::new();
            map.insert(zone.origin.clone(), zone);
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
            match std::fs::read_to_string(&path) {
                Ok(content) => {
                    let zone_origin = extract_zone_origin_from_path(&path_str);
                    match parse_zone_file(&content, &zone_origin) {
                        Ok(zone) => {
                            println!("Loaded zone from {}", path_str);
                            zones.insert(zone.origin.clone(), zone);
                        }
                        Err(e) => {
                            eprintln!("Error parsing zone file {}: {}", path_str, e);
                            // Continue with next file
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error reading zone file {}: {}", path_str, e);
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
