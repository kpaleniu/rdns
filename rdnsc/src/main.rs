//! A command-line DNS query client.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rdns_core::error::AnswerMismatch;
use rdns_core::record_types::{self as rt, qtype_name_to_code};
use rdns_core::socket::bind_addr_for;
use rdns_core::validation::{answers_query, SentQuery};
use rdns_core::Name;
use rdns_core::{DnsMessage, DnsMessageBuilder, Qtype, ResponseCode};

const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Re-sends of a lost datagram before giving up. Two is `dig`'s default.
const ATTEMPTS: usize = 2;

#[derive(Parser)]
#[command(version = rdns_core::VERSION, about, long_about = None)]
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

    // A QTYPE, not an RTYPE: ANY, AXFR and IXFR are questions no record is the
    // answer to, and asking for a record type made them unaskable (#33b).
    let qtype = qtype_name_to_code(&args.record).ok_or_else(|| {
        anyhow!(
            "{:?} is not a type this client can ask for; TYPEnnn asks for a number",
            args.record
        )
    })?;
    if qtype == Qtype::IXFR {
        // RFC 1995 §3: the request carries the client's SOA, saying which
        // version it holds. This client holds no zone, so it has nothing to say.
        bail!("IXFR asks for the changes since a serial this client does not have; use AXFR");
    }
    let transfer = qtype == Qtype::AXFR;

    let request = DnsMessageBuilder::new()
        .with_query(
            Name::from_presentation(&args.hostname)
                .with_context(|| format!("{:?} is not a domain name", args.hostname))?,
            qtype,
        )
        // RFC 5936 §4.1.1: RD SHOULD be clear in an AXFR request.
        .with_recursion(!transfer)
        .with_dnssec(args.dnssec)
        .build();

    // Send `len` bytes, not the whole buffer: trailing zeros are extra records
    // as far as the receiver is concerned, and count against its request cap.
    let mut buf = [0u8; 512];
    let len = request
        .to_bytes(&mut buf)
        .context("serializing the query")?;
    let query = &buf[..len];

    if transfer {
        // RFC 5936 §4.2: AXFR is TCP only, and a zone is not one message.
        return read_transfer(server, query, &request);
    }

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
    let sock = UdpSocket::bind(bind_addr_for(server)).context("binding a local UDP socket")?;
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
    let mut stream = send_over_tcp(server, query)?;
    let message = read_framed(&mut stream)?
        .ok_or_else(|| anyhow!("{server} closed the connection without answering"))?;
    // The connection identifies the peer, but the id and question still catch
    // a stale message left in the stream.
    matches_request(&message, request).map_err(|why| anyhow!("TCP reply is not ours: {why}"))?;
    Ok(message)
}

/// A whole zone, printed as it arrives.
///
/// AXFR is TCP only and a zone is not one message (RFC 5936 §2.2): the answer
/// section starts with the zone's SOA and ends with the same SOA again, and
/// that second copy is the only end marker there is. Records are printed rather
/// than assembled — a client that held the zone would be `rdns::xfr`, which
/// `rdnsc` does not link (it takes `rdns-core` alone).
fn read_transfer(server: SocketAddr, query: &[u8], request: &DnsMessage) -> Result<()> {
    let mut stream = send_over_tcp(server, query)?;
    let mut soas = 0;
    let mut records = 0;
    let mut first = true;

    while soas < 2 {
        let Some(message) = read_framed(&mut stream)? else {
            bail!("the transfer stopped after {records} records, with no closing SOA");
        };
        // A refusal is one message with an rcode and no records, and looking for
        // the SOA first would wait out the read timeout instead of saying so.
        if message.rcode != ResponseCode::Ok {
            bail!("the server refused the transfer: {:?}", message.rcode);
        }
        if first {
            matches_request(&message, request)
                .map_err(|why| anyhow!("the first reply is not ours: {why}"))?;
            first = false;
        } else if message.id != request.id {
            // Later messages need not repeat the question (RFC 5936 §2.2), so
            // the id is all there is to tie them to this transfer.
            bail!("a message in the stream carries id {:#06x}", message.id);
        }

        for rr in &message.answers {
            if rr.rdata.rtype() == rt::SOA {
                soas += 1;
            }
            records += 1;
            println!("{rr:?}");
        }
    }
    eprintln!("transfer complete: {records} records");
    Ok(())
}

/// Connect and send one framed message.
fn send_over_tcp(server: SocketAddr, query: &[u8]) -> Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(&server, READ_TIMEOUT)
        .with_context(|| format!("connecting to {server} over TCP"))?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .context("setting the read timeout")?;

    let framed = rdns_core::framed(query).context("framing the query")?;
    stream.write_all(&framed).context("sending over TCP")?;
    Ok(stream)
}

/// One length-prefixed message, or `None` when the peer closed cleanly between
/// messages — which is the end of a stream and not a failure to report.
fn read_framed(stream: &mut TcpStream) -> Result<Option<DnsMessage>> {
    let mut prefix = [0u8; 2];
    match stream.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading the length prefix"),
    }
    let mut body = vec![0u8; u16::from_be_bytes(prefix) as usize];
    stream
        .read_exact(&mut body)
        .context("reading the response body")?;
    Ok(Some(
        DnsMessage::try_from_bytes(&body).context("parsing the TCP response")?,
    ))
}

/// Whether `message` is a response to `request`.
///
/// The id, the QR bit and the echoed question are all that tie a datagram to
/// the query it claims to answer. `rdns_core::validation::answers_query` is the
/// check; the resolver makes the same one (`TODO.md` #30o). No DNS-0x20 here,
/// so the name compare folds ASCII case.
fn matches_request(message: &DnsMessage, request: &DnsMessage) -> Result<(), AnswerMismatch> {
    let Some(asked) = request.queries.first() else {
        return Err(AnswerMismatch::NoQuestion);
    };
    answers_query(
        message,
        &SentQuery {
            id: request.id,
            qname: asked.qname.as_ref(),
            qtype: asked.qtype,
            qclass: asked.qclass,
            case_sensitive: false,
        },
    )
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
