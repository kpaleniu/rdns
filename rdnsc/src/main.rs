//! A command-line DNS query client.

// `TODO.md` #82b's ratchet; the reason is at the top of `rdns/src/lib.rs`.
#![warn(unreachable_pub)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rdns_core::error::AnswerMismatch;
use rdns_core::record_types::{self as rt, qtype_name_to_code};
use rdns_core::socket::bind_addr_for;
use rdns_core::validation::{answers_query, SentQuery};
use rdns_core::Name;
use rdns_core::{DnsMessage, DnsMessageBuilder, ExtendedError, Qtype, ResponseCode};
use rdns_present::record_text;
use rdns_tsig::{self as tsig, TsigKey};

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
    /// Write a transfer to this path instead of stdout, atomically: a
    /// temporary beside it, fsynced, then renamed over.
    ///
    /// For the file a running resolver re-reads. `> file` truncates in place,
    /// so a reader that loads it mid-write sees half a zone; a rename is
    /// either the old file or the new one (`rdns_core::persist`).
    #[arg(long, value_name = "PATH")]
    pub write: Option<String>,
    /// Sign the request with a TSIG key: `[algorithm:]name:secret`
    /// (RFC 8945). The default algorithm is hmac-sha256.
    ///
    /// The secret is in `argv`, where anyone on the machine can read it out of
    /// `ps` — use `--tsig-file` for anything but a test.
    #[arg(short = 'y', long, value_name = "SPEC", conflicts_with = "tsig_file")]
    pub tsig: Option<String>,
    /// The same, with the secret read from a file rather than from `argv`.
    /// Needs `--tsig-name`; the file holds the base64 secret and nothing else.
    ///
    /// The file must not be readable by anyone but its owner, and is refused
    /// if it is — a secret in a file is only better than one in `argv` if the
    /// file is private (`CLAUDE.md` §15). Windows has no equivalent of the
    /// mode, so there it is not checked and nothing pretends it was.
    ///
    /// A separate flag from the name, and not `name:path`: a Windows path
    /// carries a colon, so a colon-separated spec with a path in it parses
    /// differently on the two platforms.
    #[arg(long, value_name = "PATH", requires = "tsig_name")]
    pub tsig_file: Option<String>,
    /// The key `--tsig-file`'s secret belongs to: `[algorithm:]name`.
    #[arg(long, value_name = "NAME", requires = "tsig_file")]
    pub tsig_name: Option<String>,
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
        // An OPT on every query, not only with --dnssec. A server may only put
        // an Extended DNS Error in a reply to a query that carried one
        // (RFC 8914 §2), so a probe that sends none cannot see the diagnostic
        // this tree emits — and `dig` and every resolver send one anyway.
        // --dnssec now moves DO alone. 1232 is what the reply is bounded by;
        // the 4096 receive buffer below is unchanged and still larger.
        .with_edns(rdns_core::FLAG_DAY_UDP_SIZE, args.dnssec)
        .build();

    // Send `len` bytes, not the whole buffer: trailing zeros are extra records
    // as far as the receiver is concerned, and count against its request cap.
    let mut buf = [0u8; 512];
    let len = request
        .to_bytes(&mut buf)
        .context("serializing the query")?;
    // Signed before anything else touches it: TSIG covers the bytes that go on
    // the wire, and the MAC of the request is what the reply's signature is
    // computed over (RFC 8945 §5.4.1).
    let key = signing_key(&args)?;
    let signed;
    let query: &[u8] = match &key {
        Some(key) => {
            signed = tsig::sign_request(buf[..len].to_vec(), key, tsig::now())
                .context("signing the query")?;
            &signed
        }
        None => &buf[..len],
    };
    let request_mac = key
        .as_ref()
        .map(|_| {
            tsig::request_mac(query)
                .ok_or_else(|| anyhow!("the signed query carries no TSIG to bind the reply to"))
        })
        .transpose()?;

    if transfer {
        // RFC 5936 §4.2: AXFR is TCP only, and a zone is not one message.
        return read_transfer(
            server,
            query,
            &request,
            key.as_ref(),
            request_mac.as_deref(),
            args.write.as_deref(),
        );
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
    let (_packet, message) = read_framed(&mut stream)?
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
/// `rdnsc` does not link.
///
/// What is printed is the zone-file presentation format, so `rdnsc … AXFR
/// example.com > example.com.zone` produces a file this tree's own parser
/// reads. Every line carries an absolute owner name, its own TTL and its class,
/// so no `$ORIGIN` or `$TTL` is needed and no line depends on another
/// (`TODO.md` #66b).
///
/// **It is not a secondary.** There is no SOA probe, so every run is a full
/// transfer; no IXFR; no NOTIFY, so whatever calls this is on its own timer;
/// and no TSIG yet (#66c). A feed refreshed this way is refreshed when cron
/// says so, not when the publisher does.
fn read_transfer(
    server: SocketAddr,
    query: &[u8],
    request: &DnsMessage,
    key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
    write_to: Option<&str>,
) -> Result<()> {
    let mut stream = send_over_tcp(server, query)?;
    // Held rather than streamed when a file is being written: the rename is
    // what makes a reader safe, and a rename needs the whole thing first.
    let mut held = String::new();
    // The reply's signature is over the request's MAC; every envelope after the
    // first is over the one before it (RFC 8945 §5.3.1).
    let mut previous_mac = request_mac.map(|m| m.to_vec()).unwrap_or_default();
    let mut soas = 0;
    let mut records = 0;
    let mut first = true;

    while soas < 2 {
        let Some((packet, message)) = read_framed(&mut stream)? else {
            bail!("the transfer stopped after {records} records, with no closing SOA");
        };
        // A refusal is one message with an rcode and no records, and looking for
        // the SOA first would wait out the read timeout instead of saying so.
        if message.rcode != ResponseCode::Ok {
            bail!(
                "the server refused the transfer: {:?}{}",
                message.rcode,
                extended_errors(&message)
            );
        }
        if let Some(key) = key {
            // Refused rather than accepted unauthenticated: RFC 8945 §5.3.1
            // lets an intermediate envelope go unsigned, but it still enters
            // the next signed digest, which `check_response` cannot see. This
            // is `rdns::xfr`'s rule, and the same sentence (`CLAUDE.md` §7).
            previous_mac = tsig::check_response(&packet, key, &previous_mac, first, tsig::now())
                .map_err(|e| {
                    anyhow!(
                        "the transfer's signature failed: {}. A configured key \
                         means every envelope must be signed",
                        e.reason()
                    )
                })?;
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

        for line in transfer_lines(&message, &mut soas)? {
            records += 1;
            if write_to.is_some() {
                held.push_str(&line);
                held.push('\n');
            } else {
                println!("{line}");
            }
        }
    }
    if let Some(path) = write_to {
        rdns_core::persist::write_atomically_str(Path::new(path), &held)
            .with_context(|| format!("writing {path}"))?;
        eprintln!("transfer complete: {records} records written to {path}");
    } else {
        eprintln!("transfer complete: {records} records");
    }
    Ok(())
}

/// The key to sign with, from whichever flag named one.
///
/// `--tsig-file` takes `[algorithm:]name:path` and reads the secret out of the
/// file, which is refused unless it is private to its owner — the check is
/// `rdns_core::persist::ensure_private`, the same one `rdnsd` applies to a
/// secret and to a DNSSEC private key (`CLAUDE.md` §7, §15). Both forms end at
/// `TsigKey::parse`, so the two cannot disagree about what a spec means.
fn signing_key(args: &Cli) -> Result<Option<TsigKey>> {
    if let Some(spec) = &args.tsig {
        return Ok(Some(TsigKey::parse(spec).context("--tsig")?));
    }
    let Some(path) = &args.tsig_file else {
        return Ok(None);
    };
    // clap's `requires` makes this unreachable, and saying so beats an
    // `expect` that claims the parser checked something it did not.
    let name = args
        .tsig_name
        .as_deref()
        .ok_or_else(|| anyhow!("--tsig-file needs --tsig-name to say which key the secret is"))?;
    let secret = read_secret(Path::new(path))?;
    Ok(Some(
        TsigKey::parse(&format!("{name}:{secret}")).context("--tsig-file")?,
    ))
}

/// The secret in `path`, refusing a file anyone else can read.
fn read_secret(path: &Path) -> Result<String> {
    rdns_core::persist::read_secret(path, "a TSIG secret")
        .with_context(|| format!("{}", path.display()))
}

/// One message's answer section as zone-file lines, counting the SOAs that
/// frame the stream.
///
/// The closing SOA is RFC 5936 §2.2's end marker and not a second record: a
/// zone file carrying the apex SOA twice is not the zone that was transferred,
/// and this tree's own parser refuses it. Separate from the read loop so that
/// is testable without a socket.
fn transfer_lines(message: &DnsMessage, soas: &mut usize) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    for rr in &message.answers {
        if rr.rdata.rtype() == rt::SOA {
            *soas += 1;
            if *soas == 2 {
                break;
            }
        }
        lines.push(record_text::resource_record_line(rr)?);
    }
    Ok(lines)
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
fn read_framed(stream: &mut TcpStream) -> Result<Option<(Vec<u8>, DnsMessage)>> {
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
    // The bytes as well as the message: TSIG is computed over what was sent,
    // and a re-serialized message is not those bytes — name compression is a
    // choice (`rdns_tsig`'s own header).
    let message = DnsMessage::try_from_bytes(&body).context("parsing the TCP response")?;
    Ok(Some((body, message)))
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

/// The reasons a reply gives for its RCODE (RFC 8914), as text to append to a
/// line that has already named the RCODE.
///
/// Empty when there are none, which is every reply from a server that does not
/// send them and every reply to a query that carried no OPT (§2).
///
/// A function because the two callers are a printed answer and a refused
/// transfer, and a refused transfer is the reply an operator is most likely to
/// be holding when they want one (`TODO.md` #44b). An unreadable option list is
/// reported rather than dropped: it is FORMERR for the message, and the parse
/// that produced it let it through.
fn extended_errors(msg: &DnsMessage) -> String {
    let Some(edns) = msg.edns.as_ref() else {
        return String::new();
    };
    match ExtendedError::all_in(edns) {
        Ok(errors) => errors
            .iter()
            .map(|(code, text)| format!("\nextended error {code}: {text}"))
            .collect(),
        Err(e) => format!("\nextended errors: unreadable option list: {e}"),
    }
}

fn print_message(msg: &DnsMessage) {
    println!(
        "rcode: {:?}, authoritative: {}{}",
        msg.rcode,
        msg.authoritive,
        extended_errors(msg)
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use rdns_core::record_types::record_type_name;

    /// An AXFR as it arrives: the zone's SOA, its records, then the SOA again
    /// as the end marker (RFC 5936 §2.2), split across two messages.
    fn transferred() -> (Vec<DnsMessage>, rdns::zone::Zone) {
        // Column zero on purpose: a leading space makes the parser read the
        // owner name as omitted, which is `TODO.md` #60's defect arriving in a
        // fixture rather than in a message.
        let text = concat!(
            "$ORIGIN example.com.\n",
            "$TTL 3600\n",
            "@    IN SOA ns1.example.com. admin.example.com. ( 7 3600 600 604800 300 )\n",
            "@    IN NS  ns1.example.com.\n",
            "ns1  IN A   192.0.2.1\n",
            "www  IN AAAA 2001:db8::10\n",
            "txt  IN TXT \"one\" \"two\"\n",
            "mail IN MX  10 mx.example.com.\n",
        );
        let zone = rdns::zone::parse_zone_file(text, "example.com.").expect("the zone parses");

        let soa = zone
            .records()
            .iter()
            .find(|r| r.rdata.rtype() == rt::SOA)
            .expect("an apex SOA");
        let as_wire = |r: rdns::zone::ZoneRecordRef<'_>| rdns_core::ResourceRecord {
            name: r.name.to_owned(),
            class: r.class,
            ttl: r.ttl,
            rdata: r.rdata.to_owned(),
        };

        let mut first = DnsMessageBuilder::new().build();
        first.answers.push(as_wire(soa));
        for r in zone.records().iter().filter(|r| r.rdata.rtype() != rt::SOA) {
            first.answers.push(as_wire(r));
        }
        let mut last = DnsMessageBuilder::new().build();
        // The end marker, and a record after it that a correct reader never
        // sees — if the loop kept going it would be in the output.
        last.answers.push(as_wire(soa));
        last.answers.push(as_wire(soa));
        (vec![first, last], zone)
    }

    /// What a transfer prints is what this tree's parser reads back.
    ///
    /// Fails against the shape this replaced, which printed `{:?}`: Rust's
    /// `Debug` is not a zone file and `parse_zone_file` rejects the first line.
    #[test]
    fn a_transfer_prints_a_zone_file_that_loads() {
        let (messages, original) = transferred();
        let mut soas = 0;
        let mut out = String::new();
        for message in &messages {
            for line in transfer_lines(message, &mut soas).expect("every record is spellable") {
                out.push_str(&line);
                out.push('\n');
            }
        }

        let reloaded = rdns::zone::parse_zone_file(&out, "example.com.").unwrap_or_else(|e| {
            panic!(
                "what was printed does not load: {e}
{out}"
            )
        });
        assert_eq!(
            reloaded.records().len(),
            original.records().len(),
            "every record survived the round trip"
        );
        for before in original.records() {
            assert!(
                reloaded
                    .records()
                    .iter()
                    .any(|after| after.name == before.name
                        && after.rdata.rtype() == before.rdata.rtype()
                        && after.rdata.bytes() == before.rdata.bytes()),
                "{} {} did not survive",
                before.name.to_presentation(),
                record_type_name(before.rdata.rtype())
            );
        }
    }

    /// The closing SOA is the end marker, not a record.
    ///
    /// Fails against a loop that prints every answer: the zone would carry its
    /// apex SOA twice, which `parse_zone_file` refuses — so this is the reason
    /// the test above passes at all.
    #[test]
    fn the_end_marker_is_not_written_as_a_record() {
        let (messages, _) = transferred();
        let mut soas = 0;
        let soa_lines: usize = messages
            .iter()
            .map(|m| {
                transfer_lines(m, &mut soas)
                    .expect("spellable")
                    .iter()
                    .filter(|l| l.contains(" SOA "))
                    .count()
            })
            .sum();
        assert_eq!(
            soa_lines, 1,
            "one SOA in the file, whatever the stream sent"
        );
        assert_eq!(
            soas, 2,
            "and both were counted, which is what ends the read"
        );
    }

    /// A flag-supplied key parses through `TsigKey::parse`, so `rdnsc` and
    /// `rdnsd` cannot disagree about what a spec means.
    #[test]
    fn a_key_can_come_from_the_flag() {
        let args = Cli::parse_from([
            "rdnsc",
            "-y",
            "hmac-sha512:key.name.:c2VjcmV0",
            "ns",
            "A",
            "h",
        ]);
        let key = signing_key(&args).expect("it parses").expect("a key");
        assert_eq!(key.name, "key.name.");

        let bad = Cli::parse_from(["rdnsc", "-y", "nosuchalg:n:c2VjcmV0", "ns", "A", "h"]);
        let err = signing_key(&bad).expect_err("an unknown algorithm");
        assert!(err.to_string().contains("--tsig"), "got: {err}");
    }

    /// The file form reads the secret out of the file rather than `argv`, which
    /// is the only reason it exists.
    #[test]
    fn a_key_can_come_from_a_file() {
        let dir = rdns_core::testutil::ScratchDir::new("rdnsc-tsig");
        let path = dir.write(
            "secret",
            "c2VjcmV0
",
        );
        rdns_core::persist::restrict_to_owner(&path).expect("private");

        let file = path.display().to_string();
        let args = Cli::parse_from([
            "rdnsc",
            "--tsig-file",
            &file,
            "--tsig-name",
            "hmac-sha256:key.name.",
            "ns",
            "A",
            "h",
        ]);
        let key = signing_key(&args).expect("it reads").expect("a key");
        assert_eq!(key.name, "key.name.");

        // The same key by either route, or the two flags mean different things.
        let inline = Cli::parse_from([
            "rdnsc",
            "-y",
            "hmac-sha256:key.name.:c2VjcmV0",
            "ns",
            "A",
            "h",
        ]);
        let inline = signing_key(&inline).expect("parses").expect("a key");
        let mut buf = [0u8; 512];
        let query = DnsMessageBuilder::new()
            .with_query(
                Name::from_presentation("example.com.").expect("a name"),
                Qtype::AXFR,
            )
            .with_id(0x4242)
            .build();
        let len = query.to_bytes(&mut buf).expect("serializes");
        let now = 1_700_000_000;
        let one = tsig::sign_request(buf[..len].to_vec(), &key, now).expect("signs");
        let two = tsig::sign_request(buf[..len].to_vec(), &inline, now).expect("signs");
        assert_eq!(one, two, "the file and the flag name the same key");
        assert!(
            tsig::request_mac(&one).is_some(),
            "a signed request carries the MAC the reply is bound to"
        );
    }

    /// A secret anyone can read is refused, which is what makes the file form
    /// better than `argv` at all (`CLAUDE.md` §15).
    ///
    /// Unix only: Windows has no equivalent of the mode, so there the check
    /// does not apply and this asserts nothing rather than asserting something
    /// false.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_secret_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = rdns_core::testutil::ScratchDir::new("rdnsc-tsig-mode");
        let path = dir.write(
            "secret",
            "c2VjcmV0
",
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let file = path.display().to_string();
        let args = Cli::parse_from([
            "rdnsc",
            "--tsig-file",
            &file,
            "--tsig-name",
            "key.name.",
            "ns",
            "A",
            "h",
        ]);
        let err = signing_key(&args).expect_err("a readable secret");
        let text = format!("{err:#}");
        assert!(text.contains("TSIG secret"), "got: {text}");
    }

    /// The two flags are mutually exclusive: two secrets for one query is two
    /// answers to one question, and clap refuses it rather than picking.
    #[test]
    fn the_two_key_flags_are_exclusive() {
        let both = Cli::try_parse_from([
            "rdnsc",
            "-y",
            "n:c2VjcmV0",
            "--tsig-file",
            "/tmp/s",
            "--tsig-name",
            "n",
            "ns",
            "A",
            "h",
        ]);
        assert!(both.is_err(), "naming a key twice is refused");
    }
}
