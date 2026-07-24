use crate::{DnsMessage, Edns, QuerySection, ResponseCode};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;
use anyhow::anyhow;

/// A DNS message sent over TCP is prefixed with a 2-byte big-endian length
/// (RFC 1035 §4.2.2), so no message can exceed what that field can express.
const TCP_MAX_MESSAGE: usize = u16::MAX as usize;

/// Configuration for recursive resolver
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Upstream DNS servers (e.g., "8.8.8.8:53")
    pub upstream_servers: Vec<SocketAddr>,
    /// Query timeout in milliseconds
    pub timeout_ms: u64,
    /// Maximum recursion depth
    pub max_depth: usize,
    /// EDNS0 UDP payload size to advertise to upstream (RFC 6891).
    pub udp_payload_size: u16,
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
            udp_payload_size: 4096,
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
        let mut msg = DnsMessage {
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
        // Advertise EDNS0 so upstream may return responses larger than 512 bytes.
        msg.set_edns(Edns::with_payload_size(self.config.udp_payload_size))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ParsedRecord, QueryClass, RecordData, ResourceRecord};
    use std::net::TcpListener;
    use std::thread;

    fn test_query() -> QuerySection {
        QuerySection {
            qname: "example.com.".to_string(),
            qtype: 1,
            qclass: QueryClass::IN,
        }
    }

    fn test_config(upstream: SocketAddr) -> ResolverConfig {
        ResolverConfig {
            upstream_servers: vec![upstream],
            timeout_ms: 4000,
            max_depth: 3,
            udp_payload_size: 4096,
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
            udp_payload_size: 4096,
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
            udp_payload_size: 4096,
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

        let resolver = RecursiveResolver::new(test_config(addr));
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

        let resolver = RecursiveResolver::new(test_config(addr));
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

        let resolver = RecursiveResolver::new(test_config(addr));
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

        let resolver = RecursiveResolver::new(test_config(addr));
        let result = resolver.resolve(&test_query());

        udp_thread.join().unwrap();
        tcp_thread.join().unwrap();

        // The single upstream failed, so the resolve as a whole fails.
        assert!(result.is_err());
    }
}
