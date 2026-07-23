use crate::{DnsMessage, QuerySection, ResponseCode};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use anyhow::anyhow;

/// Configuration for recursive resolver
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Upstream DNS servers (e.g., "8.8.8.8:53")
    pub upstream_servers: Vec<SocketAddr>,
    /// Query timeout in milliseconds
    pub timeout_ms: u64,
    /// Maximum recursion depth
    pub max_depth: usize,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        ResolverConfig {
            // Google and Cloudflare public DNS
            upstream_servers: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            ],
            timeout_ms: 5000,
            max_depth: 3,
        }
    }
}

/// Recursive DNS resolver (synchronous version for library)
pub struct RecursiveResolver {
    config: ResolverConfig,
}

impl RecursiveResolver {
    pub fn new(config: ResolverConfig) -> Self {
        RecursiveResolver { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(ResolverConfig::default())
    }

    /// Resolve a DNS query recursively using upstream servers (blocking)
    pub fn resolve(&self, query: &QuerySection) -> Result<DnsMessage, anyhow::Error> {
        self.resolve_internal(query, 0)
    }

    fn resolve_internal(
        &self,
        query: &QuerySection,
        depth: usize,
    ) -> Result<DnsMessage, anyhow::Error> {
        if depth >= self.config.max_depth {
            return Err(anyhow!(
                "recursion depth limit ({}) exceeded",
                self.config.max_depth
            ));
        }

        // Create query message
        let msg = DnsMessage {
            id: rand::random::<u16>(),
            response: false,
            opcode: crate::OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: true,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![query.clone()],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };

        // Serialize query
        let mut query_buf = vec![0; 512];
        let query_len = msg.to_bytes(&mut query_buf)?;
        query_buf.truncate(query_len);

        // Try each upstream server
        for upstream in &self.config.upstream_servers {
            match self.query_upstream(upstream, &query_buf) {
                Ok(response) => return Ok(response),
                Err(_) => continue, // Try next upstream
            }
        }

        Err(anyhow!(
            "failed to resolve {} with all upstream servers",
            query.qname
        ))
    }

    fn query_upstream(
        &self,
        upstream: &SocketAddr,
        query: &[u8],
    ) -> Result<DnsMessage, anyhow::Error> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(self.config.timeout_ms / 2)))?;
        socket.connect(upstream)?;

        // Send query
        socket.send(query)?;

        // Receive response
        let mut response_buf = vec![0; 512];
        let n = socket.recv(&mut response_buf)?;

        response_buf.truncate(n);
        DnsMessage::try_from_bytes(&response_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_config_default() {
        let config = ResolverConfig::default();
        assert!(!config.upstream_servers.is_empty());
        assert!(config.timeout_ms > 0);
        assert!(config.max_depth > 0);
    }

    #[test]
    fn test_resolver_creation() {
        let resolver = RecursiveResolver::with_defaults();
        assert_eq!(resolver.config.upstream_servers.len(), 2);
    }

    #[test]
    fn test_resolver_max_depth_limit() {
        let config = ResolverConfig {
            upstream_servers: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)],
            timeout_ms: 1000,
            max_depth: 0,
        };
        let resolver = RecursiveResolver::new(config);
        assert_eq!(resolver.config.max_depth, 0);
    }

    #[test]
    fn test_resolver_depth_exceeded() {
        let config = ResolverConfig {
            upstream_servers: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)],
            timeout_ms: 1000,
            max_depth: 0,
        };
        let resolver = RecursiveResolver::new(config);

        let query = QuerySection {
            qname: "example.com.".to_string(),
            qtype: 1,
            qclass: crate::QueryClass::IN,
        };

        let result = resolver.resolve_internal(&query, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("depth"));
    }
}
