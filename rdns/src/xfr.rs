//! The client half of a zone transfer: asking for a zone and assembling it.
//!
//! [`crate::transfer`] turns a zone into the messages an AXFR is; this turns
//! those messages back into a zone. They are deliberately separate, and not only
//! because one is a server and the other a client: the server's half is handed a
//! zone it already trusts, while this half is handed a stream by somebody else
//! and has to decide what of it to believe.
//!
//! **What it refuses is the interesting part.** A transfer that is merely
//! *received* is not a zone:
//!
//! - **It must open and close with the apex SOA** (RFC 5936 §2.2). The closing
//!   SOA is the only thing that distinguishes a complete transfer from a
//!   connection that was cut, and a secondary that swapped in a truncated zone
//!   would start answering NXDOMAIN for everything the stream did not reach.
//! - **Every record must be in bailiwick.** A master for `example.com.` has no
//!   business sending records for anything outside it, and accepting them would
//!   let one zone's master write into a name it is not authoritative for.
//! - **The stream is bounded.** A master that never sends the closing SOA is
//!   otherwise a slow way to run this process out of memory.
//!
//! Nothing here opens a socket except [`fetch_zone`] and [`fetch_soa`]; the
//! assembling is a state machine so it can be tested without one.

use crate::error::{TransferError, TransferResult};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::tsig::{self, TsigError, TsigKey};
use crate::utils::record_types as rt;
use crate::zone::{Zone, ZoneRecord};
use crate::{
    DnsMessage, OpCode, ParsedRecord, QueryClass, QuerySection, ResourceRecord, ResponseCode,
};

/// How long a transfer may take from connect to closing SOA.
///
/// A master that accepts the connection and then stalls is otherwise a task that
/// never finishes and a zone that never refreshes.
pub const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for a single SOA probe.
pub const SOA_TIMEOUT: Duration = Duration::from_secs(5);

/// The most records a transfer may carry before we stop believing it is one.
///
/// Every bound in this codebase exists because the alternative is unbounded, and
/// this one is the memory a hostile or broken master can make us allocate before
/// it has proved anything by closing the stream.
pub const MAX_TRANSFER_RECORDS: usize = 5_000_000;

/// A request for the zone's SOA — the refresh check (RFC 1035 §4.3.5).
pub fn soa_query(zone: &str, id: u16) -> DnsMessage {
    question(zone, rt::SOA, id)
}

/// A request for the whole zone.
pub fn axfr_request(zone: &str, id: u16) -> DnsMessage {
    question(zone, rt::AXFR, id)
}

fn question(zone: &str, qtype: u16, id: u16) -> DnsMessage {
    DnsMessage {
        id,
        response: false,
        opcode: OpCode::Query,
        authoritive: false,
        truncation: false,
        // A master is authoritative for the zone being asked about; asking it to
        // recurse would be asking the wrong question of the wrong server.
        recursion: false,
        recursion_ok: false,
        ad: false,
        cd: false,
        rcode: ResponseCode::Ok,
        queries: vec![QuerySection {
            qname: zone.to_string(),
            qtype,
            qclass: QueryClass::IN,
        }],
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}

/// The serial in a response's SOA answer, if it has one.
pub fn soa_serial(msg: &DnsMessage) -> Option<u32> {
    msg.answers
        .iter()
        .chain(msg.authorities.iter())
        .filter(|rr| rr.rdata.rtype == rt::SOA)
        .find_map(|rr| match rr.rdata.parse() {
            Ok(ParsedRecord::SOA { serial, .. }) => Some(serial),
            _ => None,
        })
}

/// Where a transfer has got to.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    /// The closing SOA has not arrived; keep reading.
    More,
    /// The transfer is complete. [`AxfrAssembler::into_zone`] has the zone.
    Complete,
}

/// Assembles the messages of an AXFR into a zone, refusing what is not one.
///
/// Fed one message at a time so the caller can stop reading as soon as the
/// transfer closes — and so that all of this is testable without a socket.
pub struct AxfrAssembler {
    zone: String,
    records: Vec<ResourceRecord>,
    /// The apex SOA that opened the transfer, and the serial it carried.
    opening_soa: Option<(ResourceRecord, u32)>,
    complete: bool,
}

impl AxfrAssembler {
    pub fn new(zone: &str) -> Self {
        AxfrAssembler {
            zone: absolute(zone),
            records: Vec::new(),
            opening_soa: None,
            complete: false,
        }
    }

    /// The serial the transfer opened with, once the first record has arrived.
    pub fn serial(&self) -> Option<u32> {
        self.opening_soa.as_ref().map(|(_, serial)| *serial)
    }

    /// Take one message of the transfer.
    pub fn accept(&mut self, msg: &DnsMessage) -> TransferResult<Progress> {
        if self.complete {
            return Err(TransferError::malformed("a record arrived after the transfer closed"));
        }
        if msg.rcode != ResponseCode::Ok {
            return Err(TransferError::malformed(format!("master answered {:?}", msg.rcode)));
        }
        if !msg.authoritive {
            // AA is how the master says the zone is its to hand out. Without it
            // this is some other server's idea of the zone.
            return Err(TransferError::malformed("transfer message is not authoritative"));
        }

        for rr in &msg.answers {
            match self.accept_record(rr)? {
                Progress::Complete => return Ok(Progress::Complete),
                Progress::More => {}
            }
        }
        Ok(Progress::More)
    }

    fn accept_record(&mut self, rr: &ResourceRecord) -> TransferResult<Progress> {
        let name = absolute(&rr.name);
        if !in_bailiwick(&name, &self.zone) {
            return Err(TransferError::malformed(format!("master sent {name}, which is not in {}: a transfer may only carry \
                 the zone it is a transfer of",
                self.zone)));
        }

        let is_apex_soa = rr.rdata.rtype == rt::SOA && name.eq_ignore_ascii_case(&self.zone);

        match &self.opening_soa {
            // RFC 5936 §2.2: the first record is the zone's SOA. Anything else
            // and this is not a transfer we can bracket.
            None => {
                if !is_apex_soa {
                    return Err(TransferError::malformed(format!("transfer does not open with the SOA of {}, but with {name} type {}",
                        self.zone, rr.rdata.rtype)));
                }
                let Ok(ParsedRecord::SOA { serial, .. }) = rr.rdata.parse() else {
                    return Err(TransferError::malformed("the opening SOA does not parse"));
                };
                self.opening_soa = Some((rr.clone(), serial));
                self.records.push(rr.clone());
                Ok(Progress::More)
            }
            // The same SOA again closes it. Everything after is not ours to keep.
            Some(_) if is_apex_soa => {
                self.complete = true;
                Ok(Progress::Complete)
            }
            Some(_) => {
                if self.records.len() >= MAX_TRANSFER_RECORDS {
                    return Err(TransferError::malformed(format!("transfer exceeded {MAX_TRANSFER_RECORDS} records without closing")));
                }
                self.records.push(rr.clone());
                Ok(Progress::More)
            }
        }
    }

    /// The assembled zone, if the transfer closed properly.
    ///
    /// A stream that stopped early is an error rather than a short zone: the
    /// whole purpose of the closing SOA is that the difference is visible.
    pub fn into_zone(self) -> TransferResult<Zone> {
        if !self.complete {
            return Err(TransferError::malformed(format!("transfer of {} ended without its closing SOA — the stream was cut",
                self.zone)));
        }
        let mut zone = Zone::new(self.zone.clone());
        for rr in self.records {
            zone.add_record(ZoneRecord {
                name: absolute(&rr.name),
                ttl: rr.ttl,
                class: rr.class,
                rdata: rr.rdata,
            });
        }
        Ok(zone)
    }
}

/// A request for the changes since the version we hold (RFC 1995 §3).
///
/// `current_soa` goes in the *authority* section, and that is the whole of what
/// distinguishes an IXFR request from an AXFR one: it says which version the
/// client already has, so the server can answer with the difference.
pub fn ixfr_request(zone: &str, current_soa: ResourceRecord, id: u16) -> DnsMessage {
    let mut msg = question(zone, rt::IXFR, id);
    msg.authorities = vec![current_soa];
    msg
}

/// What an incremental transfer turned out to be.
pub enum IxfrOutcome {
    /// The server answered with a single SOA: we are already current.
    UpToDate(u32),
    /// Difference sequences, applied in order.
    Updated {
        zone: Zone,
        /// How many version steps were applied.
        steps: usize,
        /// Deletions the zone did not actually hold — a disagreement worth
        /// logging, never worth failing over.
        missing_deletions: usize,
    },
    /// The server sent the whole zone instead, which it may always do
    /// (RFC 1995 §4). Not a failure and not something to retry differently.
    FullTransfer(Zone),
}

/// One difference sequence as it arrives.
#[derive(Default)]
struct Sequence {
    to_soa: Option<ResourceRecord>,
    deleted: Vec<ResourceRecord>,
    added: Vec<ResourceRecord>,
}

/// Where the parser is in the stream.
#[derive(PartialEq, Eq)]
enum IxfrState {
    /// Nothing yet. The first record is the server's current SOA.
    AwaitingFirstSoa,
    /// After the first SOA, and after each completed sequence. What comes next
    /// decides everything: an SOA whose serial is the current one closes the
    /// transfer, another SOA opens a sequence, and *anything else* means the
    /// server chose to send the whole zone.
    BetweenSequences,
    /// Inside a sequence's deletions; the next SOA ends them.
    Deletions,
    /// Inside its additions; the next SOA ends the sequence.
    Additions,
    /// The server is sending the whole zone AXFR-style.
    FullTransfer,
    Complete,
}

/// Assembles the answer to an IXFR, whichever of the three shapes it takes.
///
/// **A client cannot ask for an incremental transfer and assume it gets one.**
/// RFC 1995 §4 lets a server answer with the entire zone at any time and for any
/// reason, and the signal is positional rather than flagged: the *second* record
/// of the stream. Another SOA means difference sequences follow; anything else
/// means this is a full transfer wearing an IXFR's question. A client that
/// assumed the first shape would read a zone's first ordinary record as the
/// header of a delete section and start deleting things.
pub struct IxfrAssembler {
    zone: String,
    current_serial: Option<u32>,
    state: IxfrState,
    records_seen: usize,
    sequences: Vec<Sequence>,
    /// The AXFR-style path, reusing the assembler that already knows how to
    /// refuse a bad one rather than growing a second copy of those rules.
    full: AxfrAssembler,
}

impl IxfrAssembler {
    pub fn new(zone: &str) -> Self {
        IxfrAssembler {
            zone: absolute(zone),
            current_serial: None,
            state: IxfrState::AwaitingFirstSoa,
            records_seen: 0,
            sequences: Vec::new(),
            full: AxfrAssembler::new(zone),
        }
    }

    /// Take one message of the answer.
    pub fn accept(&mut self, msg: &DnsMessage) -> TransferResult<Progress> {
        if self.state == IxfrState::Complete {
            return Err(TransferError::malformed("a record arrived after the transfer closed"));
        }
        if msg.rcode != ResponseCode::Ok {
            return Err(TransferError::malformed(format!("master answered {:?}", msg.rcode)));
        }
        if !msg.authoritive {
            return Err(TransferError::malformed("transfer message is not authoritative"));
        }

        for rr in &msg.answers {
            if self.state == IxfrState::FullTransfer {
                if self.full.accept_record(rr)? == Progress::Complete {
                    self.state = IxfrState::Complete;
                    return Ok(Progress::Complete);
                }
                continue;
            }
            if self.accept_record(rr)? == Progress::Complete {
                return Ok(Progress::Complete);
            }
        }

        // A lone SOA and nothing else is RFC 1995 §2's "you are already current".
        // It is the one answer with no terminator of its own, so it is recognised
        // by being the whole of the first message: a server with sequences to send
        // packs them into the same message rather than sending one record and
        // pausing.
        if self.state == IxfrState::BetweenSequences && self.records_seen == 1 {
            self.state = IxfrState::Complete;
            return Ok(Progress::Complete);
        }
        Ok(Progress::More)
    }

    fn accept_record(&mut self, rr: &ResourceRecord) -> TransferResult<Progress> {
        let name = absolute(&rr.name);
        if !in_bailiwick(&name, &self.zone) {
            return Err(TransferError::malformed(format!("master sent {name}, which is not in {}: a transfer may only carry \
                 the zone it is a transfer of",
                self.zone)));
        }
        self.records_seen += 1;

        let soa_serial = if rr.rdata.rtype == rt::SOA && name.eq_ignore_ascii_case(&self.zone) {
            match rr.rdata.parse() {
                Ok(ParsedRecord::SOA { serial, .. }) => Some(serial),
                _ => return Err(TransferError::malformed("an SOA in the transfer does not parse")),
            }
        } else {
            None
        };

        match (&self.state, soa_serial) {
            (IxfrState::AwaitingFirstSoa, Some(serial)) => {
                self.current_serial = Some(serial);
                // The full-transfer path needs this record too, since it is the
                // SOA that opens an AXFR — replayed rather than re-derived, so
                // the two readings of the stream see the same bytes.
                self.full.accept_record(rr)?;
                self.state = IxfrState::BetweenSequences;
            }
            (IxfrState::AwaitingFirstSoa, None) => {
                return Err(TransferError::malformed(format!("the answer does not open with the SOA of {}",
                    self.zone)))
            }

            // The second record decides which shape this is.
            (IxfrState::BetweenSequences, None) => {
                self.state = IxfrState::FullTransfer;
                return self.full.accept_record(rr);
            }
            (IxfrState::BetweenSequences, Some(serial)) => {
                if Some(serial) == self.current_serial && !self.sequences.is_empty() {
                    self.state = IxfrState::Complete;
                    return Ok(Progress::Complete);
                }
                self.sequences.push(Sequence::default());
                self.state = IxfrState::Deletions;
            }

            (IxfrState::Deletions, Some(_)) => {
                self.current_sequence().to_soa = Some(rr.clone());
                self.state = IxfrState::Additions;
            }
            (IxfrState::Deletions, None) => self.current_sequence().deleted.push(rr.clone()),

            // An SOA here is either this sequence's successor or the closing
            // record. The distinction is the serial: a following sequence starts
            // where this one ended, which is only the current serial once there
            // is nothing left to send.
            (IxfrState::Additions, Some(serial)) => {
                if Some(serial) == self.current_serial {
                    self.state = IxfrState::Complete;
                    return Ok(Progress::Complete);
                }
                self.sequences.push(Sequence::default());
                self.state = IxfrState::Deletions;
            }
            (IxfrState::Additions, None) => self.current_sequence().added.push(rr.clone()),

            (IxfrState::FullTransfer, _) | (IxfrState::Complete, _) => unreachable!(
                "the full-transfer and completed states are handled before this point"
            ),
        }
        Ok(Progress::More)
    }

    fn current_sequence(&mut self) -> &mut Sequence {
        self.sequences
            .last_mut()
            .expect("a sequence is pushed before any record is put in one")
    }

    /// Apply what arrived to `base`, the zone we already hold.
    ///
    /// `base` must be the version whose serial was sent in the request — the
    /// sequences describe changes *from* it, and applying them to anything else
    /// produces a zone that never existed.
    pub fn into_outcome(self, base: &Zone) -> TransferResult<IxfrOutcome> {
        if self.state != IxfrState::Complete {
            return Err(TransferError::malformed(format!("the answer for {} ended without its closing SOA — the stream was cut",
                self.zone)));
        }
        if !self.sequences.is_empty() {
            let steps = self.sequences.len();
            let mut zone = base.clone();
            let mut missing_deletions = 0;
            for sequence in self.sequences {
                let to_soa = sequence
                    .to_soa
                    .ok_or_else(|| TransferError::malformed("a difference sequence has no SOA for the version it produces"))?;
                let (next, removed) =
                    crate::ixfr::apply_changes(&zone, &sequence.deleted, &sequence.added, &to_soa);
                missing_deletions += sequence.deleted.len() - removed;
                zone = next;
            }
            return Ok(IxfrOutcome::Updated {
                zone,
                steps,
                missing_deletions,
            });
        }
        if self.records_seen > 1 {
            return Ok(IxfrOutcome::FullTransfer(self.full.into_zone()?));
        }
        Ok(IxfrOutcome::UpToDate(
            self.current_serial.unwrap_or_default(),
        ))
    }
}

/// Whether `name` is the zone apex or below it.
fn in_bailiwick(name: &str, zone: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let zone = zone.to_ascii_lowercase();
    name == zone
        || zone == "."
        || name
            .strip_suffix(&zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn absolute(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

// ---------------------------------------------------------------------------
// The socket half
// ---------------------------------------------------------------------------

/// Ask `master` for the zone's SOA serial, over TCP.
///
/// The refresh check is usually a UDP query, and this uses the connection it
/// would need anyway if the answer says a transfer is due: one round trip either
/// way, no truncation to handle, and the handshake means the reply came from the
/// address we asked rather than from whoever guessed the transaction id first.
pub async fn fetch_soa(
    master: std::net::SocketAddr,
    zone: &str,
    key: Option<&TsigKey>,
) -> TransferResult<u32> {
    let deadline = tokio::time::timeout(SOA_TIMEOUT, async {
        let mut stream = connect(master).await?;
        let id = rand_id();
        let request = soa_query(zone, id);
        let signed = send_request(&mut stream, &request, key, id).await?;

        let (reply, _mac) = read_reply(&mut stream, id, key, &signed, true).await?;
        if reply.rcode != ResponseCode::Ok {
            return Err(TransferError::malformed(format!("master answered {:?} to the SOA probe", reply.rcode)));
        }
        soa_serial(&reply)
            .ok_or_else(|| TransferError::malformed("master's answer carried no SOA"))
    });

    deadline
        .await
        .map_err(|_| TransferError::timeout(format!("SOA probe to {master} timed out")))?
}

/// Transfer the zone from `master`, verifying it as it arrives.
pub async fn fetch_zone(
    master: std::net::SocketAddr,
    zone: &str,
    key: Option<&TsigKey>,
) -> TransferResult<Zone> {
    let transfer = tokio::time::timeout(TRANSFER_TIMEOUT, async {
        let mut stream = connect(master).await?;
        let id = rand_id();
        let request = axfr_request(zone, id);
        let signed = send_request(&mut stream, &request, key, id).await?;

        let mut assembler = AxfrAssembler::new(zone);
        // The first envelope's MAC is computed over the request's; after that
        // each is computed over the one before (RFC 8945 §5.3.1), so a dropped
        // or reordered envelope fails here rather than passing for a zone.
        let mut previous_mac = signed.clone();
        let mut first = true;
        loop {
            let (msg, mac) = read_reply(&mut stream, id, key, &previous_mac, first).await?;
            if let Some(mac) = mac {
                previous_mac = mac;
            }
            first = false;
            if assembler.accept(&msg)? == Progress::Complete {
                return assembler.into_zone();
            }
        }
    });

    transfer
        .await
        .map_err(|_| TransferError::timeout(format!("transfer of {zone} from {master} timed out")))?
}

/// Ask `master` only for what changed since `base`, over TCP.
///
/// TCP rather than UDP even though RFC 1995 §2 suggests trying UDP first: the
/// answer may be the whole zone at the server's discretion, so a UDP attempt is a
/// round trip that has to be prepared to be told to come back over TCP anyway.
/// One connection, one answer, no second code path — and the same connection an
/// AXFR would have needed.
pub async fn fetch_changes(
    master: std::net::SocketAddr,
    base: &Zone,
    key: Option<&TsigKey>,
) -> TransferResult<IxfrOutcome> {
    let zone = base.origin().to_string();
    let soa = apex_soa(base).ok_or_else(|| TransferError::malformed(format!("zone {zone} has no SOA to ask from")))?;

    let transfer = tokio::time::timeout(TRANSFER_TIMEOUT, async {
        let mut stream = connect(master).await?;
        let id = rand_id();
        let request = ixfr_request(&zone, soa, id);
        let signed = send_request(&mut stream, &request, key, id).await?;

        let mut assembler = IxfrAssembler::new(&zone);
        let mut previous_mac = signed.clone();
        let mut first = true;
        loop {
            let (msg, mac) = read_reply(&mut stream, id, key, &previous_mac, first).await?;
            if let Some(mac) = mac {
                previous_mac = mac;
            }
            first = false;
            if assembler.accept(&msg)? == Progress::Complete {
                return assembler.into_outcome(base);
            }
        }
    });

    transfer
        .await
        .map_err(|_| TransferError::timeout(format!(
            "incremental transfer of {zone} from {master} timed out"
        )))?
}

/// The apex SOA of a zone as a resource record.
fn apex_soa(zone: &Zone) -> Option<ResourceRecord> {
    zone.query(zone.origin(), rt::SOA)
        .first()
        .map(|soa| ResourceRecord {
            name: zone.origin().to_string(),
            class: soa.class,
            ttl: soa.ttl,
            rdata: soa.rdata.clone(),
        })
}

async fn connect(master: std::net::SocketAddr) -> TransferResult<TcpStream> {
    TcpStream::connect(master)
        .await
        .map_err(|e| TransferError::malformed(format!("connecting to {master}: {e}")))
}

/// Serialize, sign if there is a key, and send. Returns the request's MAC, which
/// is what the first reply's signature is computed over.
async fn send_request(
    stream: &mut TcpStream,
    request: &DnsMessage,
    key: Option<&TsigKey>,
    _id: u16,
) -> TransferResult<Vec<u8>> {
    let mut buf = vec![0u8; 512];
    let n = request
        .to_bytes(&mut buf)
        .map_err(|e| TransferError::malformed(format!("serializing the request: {e}")))?;
    let mut packet = buf[..n].to_vec();

    let mut mac = Vec::new();
    if let Some(key) = key {
        packet = tsig::sign_request(packet, key, tsig::now())?;
        mac = tsig::request_mac(&packet)
            .ok_or_else(|| TransferError::tsig("just-signed request has no TSIG"))?;
    }

    let mut framed = (packet.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&packet);
    stream
        .write_all(&framed)
        .await
        .map_err(|e| TransferError::malformed(format!("sending the request: {e}")))?;
    Ok(mac)
}

/// Read one framed reply, check its TSIG if there is a key, and parse it.
///
/// Returns the message and, when signed, the MAC to carry into the next one.
async fn read_reply(
    stream: &mut TcpStream,
    id: u16,
    key: Option<&TsigKey>,
    previous_mac: &[u8],
    first: bool,
) -> TransferResult<(DnsMessage, Option<Vec<u8>>)> {
    let mut length = [0u8; 2];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|e| TransferError::malformed(format!("reading the reply's length: {e}")))?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(TransferError::malformed("master closed the transfer with an empty frame"));
    }
    let mut packet = vec![0u8; length];
    stream
        .read_exact(&mut packet)
        .await
        .map_err(|e| TransferError::malformed(format!("reading the reply: {e}")))?;

    let mut mac = None;
    if let Some(key) = key {
        match tsig::check_response(&packet, key, previous_mac, first, tsig::now()) {
            Ok(next) => mac = Some(next),
            Err(TsigError::FormErr) if !first => {
                // An intermediate envelope may go unsigned (RFC 8945 §5.3.1
                // requires only the first and last). It still enters the digest
                // of the next signed one, which `check_response` cannot see — so
                // rather than accept a gap we cannot account for, this is where
                // an unsigned intermediate would have to be handled. Refusing is
                // the honest position: a message we did not authenticate is not
                // one to build a zone from.
                return Err(TransferError::tsig(
                    "an envelope of the transfer carried no TSIG, and a key was configured",
                ));
            }
            Err(e) => {
                return Err(TransferError::tsig(format!(
                    "the transfer's signature failed: {}",
                    e.reason()
                )))
            }
        }
    }

    let msg = DnsMessage::try_from_bytes(&packet).map_err(|e| TransferError::malformed(format!("parsing the reply: {e}")))?;
    if msg.id != id {
        return Err(TransferError::malformed(format!("reply has transaction id {:#06x}, not the {id:#06x} we sent",
            msg.id)));
    }
    if !msg.response {
        return Err(TransferError::malformed("master sent a query where a response belongs"));
    }
    Ok((msg, mac))
}

fn rand_id() -> u16 {
    use rand::Rng;
    rand::thread_rng().gen()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::axfr_messages;
    use crate::tsig::TsigAlgorithm;
    use crate::zone::parse_zone_file;

    fn source_zone() -> Zone {
        parse_zone_file(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 42 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.2\n\
             www  IN AAAA 2001:db8::2\n\
             *    IN A   192.0.2.9\n",
            "example.com.",
        )
        .expect("zone should parse")
    }

    fn transfer_of(zone: &Zone) -> Vec<DnsMessage> {
        axfr_messages(&axfr_request("example.com.", 1).clone(), zone)
            .expect("build the transfer")
            .into_iter()
            .map(|mut m| {
                m.response = true;
                m
            })
            .collect()
    }

    /// The whole point: what the server sends is what the client reconstructs.
    #[test]
    fn test_a_transfer_reassembles_into_the_zone_it_came_from() {
        let source = source_zone();
        let mut assembler = AxfrAssembler::new("example.com.");
        let mut progress = Progress::More;
        for msg in transfer_of(&source) {
            progress = assembler.accept(&msg).expect("accept");
        }
        assert_eq!(progress, Progress::Complete, "the closing SOA arrived");
        assert_eq!(assembler.serial(), Some(42));

        let received = assembler.into_zone().expect("assemble");
        assert_eq!(received.origin(), source.origin());
        assert_eq!(received.serial(), Some(42));
        assert_eq!(received.records().len(), source.records().len());
        assert_eq!(received.query("www.example.com.", rt::A).len(), 1);
        assert_eq!(received.query("www.example.com.", rt::AAAA).len(), 1);
        assert_eq!(
            received.query("anything.example.com.", rt::A).len(),
            1,
            "the wildcard transferred too"
        );
    }

    /// A stream that stops before the closing SOA is not a short zone, it is a
    /// cut connection — and swapping it in would answer NXDOMAIN for whatever it
    /// did not reach.
    #[test]
    fn test_a_transfer_without_its_closing_soa_is_refused() {
        let source = source_zone();
        let messages = transfer_of(&source);
        let mut assembler = AxfrAssembler::new("example.com.");

        // Everything but the closing SOA.
        let mut truncated = messages[0].clone();
        truncated.answers.pop();
        assert_eq!(assembler.accept(&truncated).unwrap(), Progress::More);

        let err = assembler.into_zone().unwrap_err();
        assert!(err.to_string().contains("without its closing SOA"), "got: {err}");
    }

    #[test]
    fn test_a_transfer_must_open_with_the_apex_soa() {
        let mut assembler = AxfrAssembler::new("example.com.");
        let mut msg = transfer_of(&source_zone())[0].clone();
        msg.answers.remove(0); // drop the opening SOA

        let err = assembler.accept(&msg).unwrap_err();
        assert!(err.to_string().contains("does not open with the SOA"), "got: {err}");
    }

    /// A master for one zone must not be able to write into another. The records
    /// go into a zone we then answer from, so this is the transfer's bailiwick
    /// rule — the same argument as the resolver's, for the same reason.
    #[test]
    fn test_out_of_bailiwick_records_are_refused() {
        let mut assembler = AxfrAssembler::new("example.com.");
        let mut msg = transfer_of(&source_zone())[0].clone();
        msg.answers.insert(
            1,
            ResourceRecord {
                name: "www.other-zone.test.".to_string(),
                class: 1,
                ttl: 300,
                rdata: crate::RecordData::from_parsed(&ParsedRecord::A("192.0.2.66".parse().unwrap()))
                    .unwrap(),
            },
        );

        let err = assembler.accept(&msg).unwrap_err();
        assert!(err.to_string().contains("not in example.com."), "got: {err}");
    }

    #[test]
    fn test_records_after_the_closing_soa_are_refused() {
        let source = source_zone();
        let mut assembler = AxfrAssembler::new("example.com.");
        for msg in transfer_of(&source) {
            let _ = assembler.accept(&msg);
        }
        let err = assembler.accept(&transfer_of(&source)[0]).unwrap_err();
        assert!(err.to_string().contains("after the transfer closed"), "got: {err}");
    }

    #[test]
    fn test_an_error_rcode_is_not_a_transfer() {
        let mut assembler = AxfrAssembler::new("example.com.");
        let mut msg = transfer_of(&source_zone())[0].clone();
        msg.rcode = ResponseCode::Refused;
        assert!(assembler.accept(&msg).unwrap_err().to_string().contains("Refused"));

        // Nor is a non-authoritative one: AA is how the master says the zone is
        // its to hand out.
        let mut not_auth = transfer_of(&source_zone())[0].clone();
        not_auth.authoritive = false;
        let mut assembler = AxfrAssembler::new("example.com.");
        assert!(assembler
            .accept(&not_auth)
            .unwrap_err()
            .to_string()
            .contains("not authoritative"));
    }

    #[test]
    fn test_bailiwick() {
        assert!(in_bailiwick("example.com.", "example.com."));
        assert!(in_bailiwick("www.example.com.", "example.com."));
        assert!(in_bailiwick("a.b.example.com.", "example.com."));
        assert!(!in_bailiwick("notexample.com.", "example.com."));
        assert!(!in_bailiwick("com.", "example.com."));
        assert!(in_bailiwick("anything.", "."), "the root zone holds everything");
    }

    #[test]
    fn test_soa_serial_reads_the_answer_or_the_authority() {
        let zone = source_zone();
        let mut reply = soa_query("example.com.", 1);
        reply.response = true;
        reply.answers = vec![crate::notify::soa_record(&zone).unwrap()];
        assert_eq!(soa_serial(&reply), Some(42));

        let mut in_authority = soa_query("example.com.", 1);
        in_authority.response = true;
        in_authority.authorities = vec![crate::notify::soa_record(&zone).unwrap()];
        assert_eq!(soa_serial(&in_authority), Some(42));

        assert_eq!(soa_serial(&soa_query("example.com.", 1)), None);
    }

    // -----------------------------------------------------------------
    // Incremental transfer, client side
    // -----------------------------------------------------------------

    /// The two versions the incremental tests move between, and the server-side
    /// delta that connects them.
    fn versions() -> (Zone, Zone, crate::ixfr::DeltaLog) {
        let v1 = parse_zone_file(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.2\n\
             keep IN A   192.0.2.50\n\
             gone IN A   192.0.2.60\n",
            "example.com.",
        )
        .unwrap();
        let v2 = parse_zone_file(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 2 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.222\n\
             keep IN A   192.0.2.50\n\
             fresh IN TXT \"new in version 2\"\n",
            "example.com.",
        )
        .unwrap();
        let mut log = crate::ixfr::DeltaLog::new();
        log.note_change(Some(&v1), &v2);
        (v1, v2, log)
    }

    /// Feed the server's own IXFR answer to the client and see what it makes of
    /// it — the two halves against each other, which is the only way the
    /// positional format gets checked rather than assumed.
    fn assemble(request: &DnsMessage, serving: &Zone, log: &crate::ixfr::DeltaLog) -> IxfrAssembler {
        let response = crate::ixfr::ixfr_response(request, serving, log).expect("build a response");
        let mut assembler = IxfrAssembler::new("example.com.");
        for msg in response.messages() {
            if assembler.accept(&msg).expect("accept") == Progress::Complete {
                break;
            }
        }
        assembler
    }

    fn ixfr_from(zone: &Zone) -> DnsMessage {
        ixfr_request("example.com.", apex_soa(zone).unwrap(), 0x77)
    }

    #[test]
    fn test_an_increment_is_applied_to_the_zone_we_hold() {
        let (v1, v2, log) = versions();
        let outcome = assemble(&ixfr_from(&v1), &v2, &log)
            .into_outcome(&v1)
            .expect("outcome");

        let IxfrOutcome::Updated { zone, steps, missing_deletions } = outcome else {
            panic!("expected an incremental update");
        };
        assert_eq!(steps, 1);
        assert_eq!(missing_deletions, 0);
        assert_eq!(zone.serial(), Some(2), "the SOA moved with it");

        // What changed, changed; what did not, did not.
        assert_eq!(
            zone.query("www.example.com.", rt::A)[0].rdata,
            v2.query("www.example.com.", rt::A)[0].rdata
        );
        assert_eq!(zone.query("fresh.example.com.", rt::TXT).len(), 1, "added");
        assert!(zone.query("gone.example.com.", rt::A).is_empty(), "deleted");
        assert_eq!(zone.query("keep.example.com.", rt::A).len(), 1, "untouched");

        // And the result is the zone the master is serving, record for record.
        let mut got: Vec<_> = zone
            .records()
            .iter()
            .map(|r| (r.name.to_lowercase(), r.rdata.clone()))
            .collect();
        let mut want: Vec<_> = v2
            .records()
            .iter()
            .map(|r| (r.name.to_lowercase(), r.rdata.clone()))
            .collect();
        got.sort_by_key(|r| (r.0.clone(), r.1.rtype));
        want.sort_by_key(|r| (r.0.clone(), r.1.rtype));
        assert_eq!(got, want, "the increment reproduced the master's zone exactly");
    }

    /// Several steps at once, applied in order — the case where applying them as
    /// a set rather than a sequence would silently produce a different zone.
    #[test]
    fn test_several_steps_are_applied_in_order() {
        // Padded, so the two steps stay smaller than the zone — otherwise the
        // server is right to send the whole thing and this tests nothing.
        let make = |serial: u32, address: &str| {
            parse_zone_file(
                &format!(
                    "$TTL 3600\n\
                     @   IN SOA ns1.example.com. admin.example.com. {serial} 3600 1800 604800 86400\n\
                     @   IN NS  ns1.example.com.\n\
                     a   IN A   192.0.2.101\n\
                     b   IN A   192.0.2.102\n\
                     c   IN A   192.0.2.103\n\
                     d   IN A   192.0.2.104\n\
                     e   IN A   192.0.2.105\n\
                     www IN A   {address}\n"
                ),
                "example.com.",
            )
            .unwrap()
        };
        let (v1, v2, v3) = (make(1, "192.0.2.1"), make(2, "192.0.2.2"), make(3, "192.0.2.3"));
        let mut log = crate::ixfr::DeltaLog::new();
        log.note_change(Some(&v1), &v2);
        log.note_change(Some(&v2), &v3);

        let outcome = assemble(&ixfr_from(&v1), &v3, &log)
            .into_outcome(&v1)
            .expect("outcome");
        let IxfrOutcome::Updated { zone, steps, .. } = outcome else {
            panic!("expected an incremental update");
        };
        assert_eq!(steps, 2);
        assert_eq!(zone.serial(), Some(3));
        assert_eq!(
            zone.query("www.example.com.", rt::A)[0].rdata,
            v3.query("www.example.com.", rt::A)[0].rdata,
            "the last step's value, not the first's"
        );
        assert_eq!(zone.query("www.example.com.", rt::A).len(), 1, "not accumulated");
    }

    /// A server may answer an IXFR with the whole zone whenever it likes
    /// (RFC 1995 §4), and the signal is the *second* record. A client that
    /// assumed sequences would read the zone's first ordinary record as the
    /// header of a delete section.
    #[test]
    fn test_a_full_transfer_in_answer_to_an_ixfr_is_recognised() {
        let (v1, v2, _) = versions();
        // An empty log: the server has no chain and falls back.
        let empty = crate::ixfr::DeltaLog::new();
        let outcome = assemble(&ixfr_from(&v1), &v2, &empty)
            .into_outcome(&v1)
            .expect("outcome");

        let IxfrOutcome::FullTransfer(zone) = outcome else {
            panic!("expected a full transfer");
        };
        assert_eq!(zone.serial(), Some(2));
        assert_eq!(zone.records().len(), v2.records().len());
        assert!(zone.query("gone.example.com.", rt::A).is_empty());
    }

    #[test]
    fn test_a_single_soa_means_we_are_already_current() {
        let (_, v2, log) = versions();
        let outcome = assemble(&ixfr_from(&v2), &v2, &log)
            .into_outcome(&v2)
            .expect("outcome");
        assert!(matches!(outcome, IxfrOutcome::UpToDate(2)), "expected up to date");
    }

    /// A deletion for a record we do not hold is a disagreement, not a reason to
    /// refuse: the record is meant to be gone either way, and failing would
    /// strand the secondary on a version it can never leave.
    #[test]
    fn test_a_deletion_we_cannot_make_is_counted_not_fatal() {
        let (v1, v2, log) = versions();
        // Apply to a base that is missing one of the records the delta deletes.
        let thinner = parse_zone_file(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.2\n\
             keep IN A   192.0.2.50\n",
            "example.com.",
        )
        .unwrap();

        let outcome = assemble(&ixfr_from(&v1), &v2, &log)
            .into_outcome(&thinner)
            .expect("outcome");
        let IxfrOutcome::Updated { zone, missing_deletions, .. } = outcome else {
            panic!("expected an incremental update");
        };
        assert_eq!(missing_deletions, 1, "`gone` was already absent");
        assert_eq!(zone.serial(), Some(2), "and the update still applied");
        assert_eq!(zone.query("fresh.example.com.", rt::TXT).len(), 1);
    }

    /// The same refusals as an AXFR: a cut stream is not a short zone, and a
    /// master may not write outside the zone it is sending.
    #[test]
    fn test_an_incremental_answer_is_checked_like_any_other() {
        let (v1, v2, log) = versions();

        // Cut the stream before the closing SOA.
        let response = crate::ixfr::ixfr_response(&ixfr_from(&v1), &v2, &log).unwrap();
        let mut messages = response.messages();
        messages[0].answers.pop();
        let mut assembler = IxfrAssembler::new("example.com.");
        for msg in &messages {
            let _ = assembler.accept(msg);
        }
        let Err(err) = assembler.into_outcome(&v1) else {
            panic!("a stream cut before its closing SOA is not a transfer");
        };
        assert!(err.to_string().contains("without its closing SOA"), "got: {err}");

        // A record from another zone.
        let mut out_of_bailiwick = crate::ixfr::ixfr_response(&ixfr_from(&v1), &v2, &log)
            .unwrap()
            .messages();
        out_of_bailiwick[0].answers.insert(
            2,
            ResourceRecord {
                name: "www.elsewhere.test.".to_string(),
                class: 1,
                ttl: 300,
                rdata: crate::RecordData::from_parsed(&ParsedRecord::A("192.0.2.66".parse().unwrap()))
                    .unwrap(),
            },
        );
        let mut assembler = IxfrAssembler::new("example.com.");
        let err = out_of_bailiwick
            .iter()
            .find_map(|msg| assembler.accept(msg).err())
            .expect("the foreign record should be refused");
        assert!(err.to_string().contains("not in example.com."), "got: {err}");

        // And an answer that does not open with the zone's SOA at all. Note that
        // simply dropping the first record would *not* be caught: the second
        // record of an increment is an SOA too, so the stream still looks like
        // one that opens correctly — just from the wrong version. The serial is
        // what makes that safe, since it is the base we apply against.
        let mut assembler = IxfrAssembler::new("example.com.");
        let mut headless = crate::ixfr::ixfr_response(&ixfr_from(&v1), &v2, &log)
            .unwrap()
            .messages();
        headless[0].answers[0] = ResourceRecord {
            name: "www.example.com.".to_string(),
            class: 1,
            ttl: 300,
            rdata: crate::RecordData::from_parsed(&ParsedRecord::A("192.0.2.77".parse().unwrap()))
                .unwrap(),
        };
        let Err(err) = assembler.accept(&headless[0]) else {
            panic!("an answer that does not open with an SOA is not a transfer");
        };
        assert!(err.to_string().contains("does not open with the SOA"), "got: {err}");
    }

    // -----------------------------------------------------------------
    // Over a real socket, against a server that speaks the other half
    // -----------------------------------------------------------------

    /// Serve one AXFR on a loopback port and hand back its address.
    ///
    /// Deliberately built from `transfer::axfr_messages` — the same code `rdnsd`
    /// answers a transfer with — so this exercises the two halves against each
    /// other rather than against a mock of one of them.
    async fn spawn_master(zone: Zone, key: Option<TsigKey>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a master");
        let addr = listener.local_addr().expect("local addr");

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let zone = zone.clone();
                let key = key.clone();
                tokio::spawn(async move {
                    let mut length = [0u8; 2];
                    if stream.read_exact(&mut length).await.is_err() {
                        return;
                    }
                    let mut packet = vec![0u8; u16::from_be_bytes(length) as usize];
                    if stream.read_exact(&mut packet).await.is_err() {
                        return;
                    }

                    let request = DnsMessage::try_from_bytes(&packet).expect("parse the request");

                    // A request that does not verify is answered with the
                    // rejection, as a real master does — not by hanging up,
                    // which would test the client's error handling for a
                    // different failure than the one intended.
                    let mut session = None;
                    if let Some(k) = key.as_ref() {
                        let keyring = crate::tsig::TsigKeyring::new(vec![k.clone()]);
                        match tsig::check_request(&packet, &keyring, tsig::now()) {
                            tsig::TsigCheck::Verified(verified) => session = Some(verified),
                            tsig::TsigCheck::Rejected(rejection) => {
                                let mut refusal = request.clone();
                                refusal.response = true;
                                refusal.rcode = ResponseCode::NotAuthorized;
                                let mut buf = vec![0u8; 512];
                                let n = refusal.to_bytes(&mut buf).expect("serialize");
                                let bytes = rejection
                                    .attach(buf[..n].to_vec(), tsig::now())
                                    .expect("attach the rejection");
                                let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
                                framed.extend_from_slice(&bytes);
                                let _ = stream.write_all(&framed).await;
                                return;
                            }
                            tsig::TsigCheck::Unsigned => return,
                        }
                    }
                    let replies: Vec<DnsMessage> = if request.queries[0].qtype == rt::AXFR {
                        axfr_messages(&request, &zone).expect("build the transfer")
                    } else {
                        let mut reply = request.clone();
                        reply.response = true;
                        reply.authoritive = true;
                        reply.answers = vec![crate::notify::soa_record(&zone).unwrap()];
                        vec![reply]
                    };

                    for reply in replies {
                        let mut buf = vec![0u8; 65535];
                        let n = reply.to_bytes(&mut buf).expect("serialize");
                        let mut bytes = buf[..n].to_vec();
                        if let Some(session) = session.as_mut() {
                            bytes = session.sign(bytes, tsig::now()).expect("sign");
                        }
                        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&bytes);
                        if stream.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        addr
    }

    #[tokio::test]
    async fn test_fetches_a_zone_over_tcp() {
        let source = source_zone();
        let master = spawn_master(source.clone(), None).await;

        let received = fetch_zone(master, "example.com.", None)
            .await
            .expect("transfer");
        assert_eq!(received.serial(), Some(42));
        assert_eq!(received.records().len(), source.records().len());
        assert_eq!(received.query("www.example.com.", rt::A).len(), 1);
    }

    #[tokio::test]
    async fn test_fetches_the_soa_serial_over_tcp() {
        let master = spawn_master(source_zone(), None).await;
        assert_eq!(
            fetch_soa(master, "example.com.", None).await.unwrap(),
            42,
            "the master's apex SOA carries serial 42"
        );
    }

    /// A signed transfer, MACs chained across every envelope — the case a
    /// hand-rolled client gets wrong silently, since an unverified stream still
    /// parses into a perfectly good-looking zone.
    #[tokio::test]
    async fn test_a_signed_transfer_verifies_end_to_end() {
        let key = TsigKey::new(
            "transfer.key.",
            TsigAlgorithm::HmacSha256,
            b"0123456789012345678901234567890123456789".to_vec(),
        );
        let master = spawn_master(source_zone(), Some(key.clone())).await;

        let received = fetch_zone(master, "example.com.", Some(&key))
            .await
            .expect("signed transfer");
        assert_eq!(received.serial(), Some(42));
    }

    /// The signature has to be *checked*, not merely present: a client holding
    /// the wrong key must not end up with a zone.
    #[tokio::test]
    async fn test_a_transfer_signed_with_another_key_is_refused() {
        let master_key = TsigKey::new(
            "transfer.key.",
            TsigAlgorithm::HmacSha256,
            b"0123456789012345678901234567890123456789".to_vec(),
        );
        let ours = TsigKey::new(
            "transfer.key.",
            TsigAlgorithm::HmacSha256,
            b"9876543210987654321098765432109876543210".to_vec(),
        );
        let master = spawn_master(source_zone(), Some(master_key)).await;

        let err = fetch_zone(master, "example.com.", Some(&ours))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("signature failed"), "got: {err}");
    }

    #[tokio::test]
    async fn test_a_master_that_is_not_there_is_an_error_not_a_hang() {
        // Bind and drop, so the port is one nothing is listening on.
        let addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        assert!(fetch_zone(addr, "example.com.", None).await.is_err());
    }
}
