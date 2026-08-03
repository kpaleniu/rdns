//! A command-line DNS query client.
//!
//! Small on purpose, but it has to be *right* about the things a client is for:
//! sending the bytes it built and no others, reading back the bytes it received
//! and no others, and refusing to print an answer it cannot tell was an answer
//! to its own question.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rdns::{DnsMessage, DnsMessageBuilder};

/// How long to wait for a reply before giving up.
///
/// There was no timeout at all, so a query to an address that does not answer —
/// a firewall dropping it, a port with nothing behind it — hung forever with no
/// output and no way to tell that from a slow server.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// How many times a lost datagram is re-sent before giving up.
///
/// UDP loses packets, and a client with no retry reports "no answer" for one
/// dropped datagram. Two attempts is what `dig` does by default.
const ATTEMPTS: usize = 2;

#[derive(Parser)]
#[command(version = rdns::VERSION, about, long_about = None)]
struct Cli {
    /// The server to ask: an address, optionally with `:port` (default 53).
    ///
    /// This used to parse as a bare `Ipv4Addr`, so `rdnsc 127.0.0.1:15353 SOA
    /// example.com` failed with "invalid IPv4 address syntax" — and this
    /// project's own documentation tells you to develop against a non-53 port,
    /// so our own client could not query our own server. That is why every
    /// verification recipe in `TODO.md` reaches for dnspython or Node.
    pub dns_server: String,
    pub record: String,
    pub hostname: String,
    /// Ask for DNSSEC records: EDNS0 with the DO bit set (RFC 4035 §3.2.1).
    ///
    /// Without it a server is *required* not to send RRSIG, NSEC or NSEC3, so
    /// this client could not see any of the signing `rdnsd` does — which is why
    /// every DNSSEC recipe in `TODO.md` reaches for dnspython (`TODO.md` #19h).
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

    // Serialize once and send exactly what was written. `to_bytes` returns the
    // length and it used to be discarded — `sock.send_to(&buf, ..)` on a
    // `[u8; 512]` sent a 31-byte query as 512 bytes with 481 trailing zeros.
    // This project's own `AdmissionCheck` caps a UDP request at exactly 512,
    // so the client was one EDNS option byte away from being rejected by the
    // server it ships with.
    let mut buf = [0u8; 512];
    let len = request
        .to_bytes(&mut buf)
        .context("serializing the query")?;
    let query = &buf[..len];

    let response = ask_over_udp(server, query, &request)?;
    let response = if response.truncation {
        // TC means the answer did not fit and the rest is not coming over UDP
        // (RFC 1035 §4.2.1). Printing what arrived would be printing a subset of
        // the answer as if it were the answer — silently dropping records, which
        // is the one failure a lookup tool must not have.
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
    // A bare IPv6 literal has colons in it, so "does it contain a colon" cannot
    // decide whether a port is present. Try it as a full socket address first
    // and fall back to appending the default port.
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
    // `connect` makes the kernel drop datagrams from anywhere else, which is the
    // cheapest half of off-path spoofing resistance and costs nothing here.
    sock.connect(server)
        .with_context(|| format!("connecting to {server}"))?;

    // 4096 rather than 512: a request is not bound by the classic limit, and an
    // EDNS server may answer larger than we would ever ask.
    let mut buf = vec![0u8; 4096];
    for attempt in 1..=ATTEMPTS {
        sock.send(query)
            .with_context(|| format!("sending the query to {server}"))?;

        match sock.recv(&mut buf) {
            // Parse only the bytes that arrived. This was
            // `try_from_bytes(&buf)` over the whole 512-byte array, so every
            // reply was parsed with the unused tail of the buffer appended —
            // which the parser is entitled to read as more records.
            Ok(n) => match DnsMessage::try_from_bytes(&buf[..n]) {
                Ok(message) => match matches_request(&message, request) {
                    // A reply for someone else's question, or an off-path
                    // forgery that lost the race, is not this answer. Keep
                    // waiting rather than printing it (RFC 5452 §9.1).
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
    // Over TCP the connection identifies the peer, but the id and question are
    // still the check that this is a reply to what was asked rather than a
    // stale message left in the stream.
    matches_request(&message, request).map_err(|why| anyhow!("TCP reply is not ours: {why}"))?;
    Ok(message)
}

/// Whether `message` is a response to `request`.
///
/// None of this was checked. The id, the QR bit and the echoed question are the
/// only things tying a datagram to the query it claims to answer, and a client
/// that prints whatever arrives will print an off-path forgery — or, more often
/// in practice, a late reply to the *previous* query and blame the server.
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
