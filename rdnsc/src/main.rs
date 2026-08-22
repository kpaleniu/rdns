//! A command-line DNS query client.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rdns::{DnsMessage, DnsMessageBuilder};

const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Re-sends of a lost datagram before giving up. Two is `dig`'s default.
const ATTEMPTS: usize = 2;

#[derive(Parser)]
#[command(version = rdns::VERSION, about, long_about = None)]
struct Cli {
    /// The server to ask: an address, optionally with `:port` (default 53).
    pub dns_server: String,
    pub record: String,
    pub hostname: String,
    /// Ask for DNSSEC records: EDNS0 with the DO bit set (RFC 4035 §3.2.1).
    /// Without it a server is required not to send RRSIG, NSEC or NSEC3.
    #[arg(long)]
    pub dnssec: bool,
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let server = resolve_server(&args.dns_server)
        .with_context(|| format!("server address {:?}", args.dns_server))?;

    let request = DnsMessageBuilder::new()
        .with_url(&args.hostname, &args.record)
        .with_dnssec(args.dnssec)
        .build();
    if request.queries.is_empty() {
        bail!(
            "{:?} is not a record type this client knows how to ask for",
            args.record
        );
    }

    // Send `len` bytes, not the whole buffer: trailing zeros are extra records
    // as far as the receiver is concerned, and count against its request cap.
    let mut buf = [0u8; 512];
    let len = request
        .to_bytes(&mut buf)
        .context("serializing the query")?;
    let query = &buf[..len];

    let response = ask_over_udp(server, query, &request)?;
    let response = if response.truncation {
        // TC: the rest is not coming over UDP (RFC 1035 §4.2.1), so printing
        // what arrived would silently drop records.
        eprintln!("answer truncated over UDP, retrying over TCP");
        ask_over_tcp(server, query, &request)?
    } else {
        response
    };

    print_message(&response);
    Ok(())
}

/// `host`, `host:port`, or a bare IPv6 literal — resolved to one address.
fn resolve_server(spec: &str) -> Result<SocketAddr> {
    // A bare IPv6 literal has colons, so a colon does not mean a port is
    // present. Try the full socket address first, then append the default.
    if let Ok(mut addrs) = spec.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return Ok(addr);
        }
    }
    (spec, 53u16)
        .to_socket_addrs()
        .context("not an address this client can parse")?
        .next()
        .ok_or_else(|| anyhow!("resolved to no addresses"))
}

/// Send `query` and return the first reply that answers *this* request.
fn ask_over_udp(server: SocketAddr, query: &[u8], request: &DnsMessage) -> Result<DnsMessage> {
    // Bind the family the server is in: a v4 socket cannot reach a v6 server.
    let bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().expect("a literal")
    } else {
        "0.0.0.0:0".parse().expect("a literal")
    };
    let sock = UdpSocket::bind(bind).context("binding a local UDP socket")?;
    sock.set_read_timeout(Some(READ_TIMEOUT))
        .context("setting the read timeout")?;
    // `connect` makes the kernel drop datagrams from anywhere else — the cheap
    // half of off-path spoofing resistance.
    sock.connect(server)
        .with_context(|| format!("connecting to {server}"))?;

    // 4096: an EDNS server may answer larger than we would ever ask.
    let mut buf = vec![0u8; 4096];
    for attempt in 1..=ATTEMPTS {
        sock.send(query)
            .with_context(|| format!("sending the query to {server}"))?;

        match sock.recv(&mut buf) {
            // `&buf[..n]`: the unused tail would parse as further records.
            Ok(n) => match DnsMessage::try_from_bytes(&buf[..n]) {
                Ok(message) => match matches_request(&message, request) {
                    // Someone else's question, or a forgery that lost the
                    // race. Keep waiting (RFC 5452 §9.1).
                    Err(why) => eprintln!("ignoring a reply that is not ours: {why}"),
                    Ok(()) => return Ok(message),
                },
                Err(e) => eprintln!("ignoring an unparseable reply: {e}"),
            },
            Err(e) if attempt < ATTEMPTS => {
                eprintln!("no reply from {server} ({e}), retrying");
            }
            Err(e) => return Err(e).with_context(|| format!("no reply from {server}")),
        }
    }
    bail!("no usable reply from {server} after {ATTEMPTS} attempts")
}

/// The same exchange over TCP, with the RFC 1035 §4.2.2 length prefix.
fn ask_over_tcp(server: SocketAddr, query: &[u8], request: &DnsMessage) -> Result<DnsMessage> {
    let mut stream = TcpStream::connect_timeout(&server, READ_TIMEOUT)
        .with_context(|| format!("connecting to {server} over TCP"))?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .context("setting the read timeout")?;

    let framed = rdns::framed(query).context("framing the query")?;
    stream.write_all(&framed).context("sending over TCP")?;

    let mut prefix = [0u8; 2];
    stream
        .read_exact(&mut prefix)
        .context("reading the length prefix")?;
    let mut body = vec![0u8; u16::from_be_bytes(prefix) as usize];
    stream
        .read_exact(&mut body)
        .context("reading the response body")?;

    let message = DnsMessage::try_from_bytes(&body).context("parsing the TCP response")?;
    // The connection identifies the peer, but the id and question still catch
    // a stale message left in the stream.
    matches_request(&message, request).map_err(|why| anyhow!("TCP reply is not ours: {why}"))?;
    Ok(message)
}

/// Whether `message` is a response to `request`.
///
/// The id, the QR bit and the echoed question are all that tie a datagram to
/// the query it claims to answer.
fn matches_request(message: &DnsMessage, request: &DnsMessage) -> Result<(), String> {
    if !message.response {
        return Err("QR is clear, so it is a query and not an answer".to_string());
    }
    if message.id != request.id {
        return Err(format!(
            "id {:#06x} does not match the {:#06x} we asked with",
            message.id, request.id
        ));
    }
    let (Some(asked), Some(echoed)) = (request.queries.first(), message.queries.first()) else {
        return Err("no question section to compare".to_string());
    };
    if !echoed.qname.eq_ignore_ascii_case(&asked.qname)
        || echoed.qtype != asked.qtype
        || echoed.qclass != asked.qclass
    {
        return Err(format!(
            "answers {} {} {:?}, not the {} {} {:?} we asked",
            echoed.qname, echoed.qtype, echoed.qclass, asked.qname, asked.qtype, asked.qclass
        ));
    }
    Ok(())
}

fn print_message(msg: &DnsMessage) {
    println!("rcode: {:?}, authoritative: {}", msg.rcode, msg.authoritive);
    for q in &msg.queries {
        println!("{q:?}");
    }
    for r in msg
        .answers
        .iter()
        .chain(&msg.authorities)
        .chain(&msg.additionals)
    {
        println!("{r:?}");
    }
}
