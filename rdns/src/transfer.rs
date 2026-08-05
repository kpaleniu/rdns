//! Zone transfer: building an AXFR response (RFC 5936).
//!
//! An AXFR is the one query whose answer is the entire zone, which makes it two
//! things at once: the mechanism every secondary nameserver is built on, and a
//! whole-database disclosure to anyone allowed to ask. This module does the
//! first part — turning a zone into the sequence of messages a transfer is —
//! and knows nothing about who may ask. That decision is
//! [`crate::security::TransferAcl`]'s, and it defaults to nobody.
//!
//! The shape of the response is the part worth stating. A transfer is not one
//! message: it is a series, and RFC 5936 §2.2 requires the first to begin with
//! the zone's SOA and the last to end with the same SOA. That framing is how the
//! client knows where the transfer starts and, more importantly, that it
//! finished — a truncated stream is otherwise indistinguishable from a small
//! zone.

use crate::error::{TransferError, TransferResult};
use crate::utils::record_types as rt;
use crate::zone::Zone;
use crate::Qtype;
use crate::{DnsMessage, Edns, ResourceRecord, ResponseCode};

/// How much of a message to fill before starting the next one.
///
/// Not a protocol limit — the TCP length prefix allows 64 KiB (RFC 1035 §4.2.2)
/// and RFC 5936 §2.2 leaves the split to the server. This is a size that keeps
/// every message comfortably inside the frame even though the estimate used to
/// pack them ignores name compression, which can only make the result smaller.
pub const AXFR_TARGET_MESSAGE_SIZE: usize = 16 * 1024;

/// The messages of an AXFR response for `zone`, **one at a time**.
///
/// The caller decides how many exist at once, and a caller that serializes and
/// writes each envelope before asking for the next holds one. That is the whole
/// of `TODO.md` #24c: this used to clone every record of the zone into a `Vec`,
/// move that into a `Vec<DnsMessage>`, and hand both to a caller that then built
/// every frame before writing any — the zone three times over, per concurrent
/// transfer, for a zone that is already in memory.
///
/// `Err` when the zone has no SOA at its apex: without one there is nothing to
/// open and close the transfer with, and a client cannot tell that what it
/// received is complete. That is a broken zone rather than a bad request, so the
/// caller should answer SERVFAIL. It is checked here, before the first envelope,
/// so a caller that is streaming has not sent anything yet when it fails.
pub fn axfr_envelopes<'a>(
    request: &'a DnsMessage,
    zone: &'a Zone,
) -> TransferResult<impl Iterator<Item = DnsMessage> + 'a> {
    let apex = zone.origin();
    let soa = zone
        .query(apex, Qtype::of(rt::SOA))
        .first()
        .map(|zr| ResourceRecord {
            name: apex.to_string(),
            class: zr.class,
            ttl: zr.ttl,
            rdata: zr.rdata.clone(),
        })
        .ok_or_else(|| TransferError::malformed(format!("zone {apex} has no SOA at its apex")))?;

    Ok(Envelopes::new(request, AxfrRecords::new(zone, soa)))
}

/// The whole of an AXFR response, materialized.
///
/// [`axfr_envelopes`] collected, for the callers that want the sequence in hand:
/// the tests, and [`crate::ixfr`]'s fallback to a full transfer. A caller serving
/// a real zone to a socket should pull the iterator instead.
pub fn axfr_messages(request: &DnsMessage, zone: &Zone) -> TransferResult<Vec<DnsMessage>> {
    Ok(axfr_envelopes(request, zone)?.collect())
}

/// The records of an AXFR in wire order: the apex SOA, the zone in load order
/// without that SOA, then the apex SOA again (RFC 5936 §2.2).
///
/// The middle SOA is skipped so the record appears exactly twice — a client that
/// saw the closing SOA early would stop reading there.
struct AxfrRecords<'a> {
    zone: &'a Zone,
    soa: ResourceRecord,
    next: usize,
    opened: bool,
    closed: bool,
}

impl<'a> AxfrRecords<'a> {
    fn new(zone: &'a Zone, soa: ResourceRecord) -> Self {
        AxfrRecords {
            zone,
            soa,
            next: 0,
            opened: false,
            closed: false,
        }
    }
}

impl Iterator for AxfrRecords<'_> {
    type Item = ResourceRecord;

    fn next(&mut self) -> Option<ResourceRecord> {
        if !self.opened {
            self.opened = true;
            return Some(self.soa.clone());
        }
        while let Some(zr) = self.zone.records().get(self.next) {
            self.next += 1;
            let name = self.zone.normalize_name(&zr.name);
            if zr.rdata.rtype() == rt::SOA && name.eq_ignore_ascii_case(self.zone.origin()) {
                continue;
            }
            return Some(ResourceRecord {
                name: name.into_owned(),
                class: zr.class,
                ttl: zr.ttl,
                rdata: zr.rdata.clone(),
            });
        }
        if !self.closed {
            self.closed = true;
            return Some(self.soa.clone());
        }
        None
    }
}

/// A transfer's records, split into messages that each fit a TCP frame.
///
/// Shared with the incremental transfer in [`crate::ixfr`], because the framing
/// is a property of a transfer rather than of which kind it is: same target size,
/// same estimate, same one-well-formed-answer-per-message rule.
///
/// The estimate is by wire size and ignores name compression: the encoded name is
/// at most its text length plus two, and the fixed part of a record is ten bytes.
/// An estimate that can only be too large is the safe direction, since the real
/// limit is the 64 KiB length prefix.
pub(crate) struct Envelopes<'a, I> {
    request: &'a DnsMessage,
    records: I,
    /// The record that did not fit the envelope just yielded. Held rather than
    /// re-read, because the source is an iterator with no way back.
    carried: Option<ResourceRecord>,
    first: bool,
}

impl<'a, I> Envelopes<'a, I> {
    pub(crate) fn new(request: &'a DnsMessage, records: I) -> Self {
        Envelopes {
            request,
            records,
            carried: None,
            first: true,
        }
    }
}

impl<I: Iterator<Item = ResourceRecord>> Iterator for Envelopes<'_, I> {
    type Item = DnsMessage;

    fn next(&mut self) -> Option<DnsMessage> {
        let cost = |rr: &ResourceRecord| rr.name.len() + 2 + 10 + rr.rdata.bytes().len();
        let mut current: Vec<ResourceRecord> = Vec::new();
        let mut estimated = 0usize;
        if let Some(rr) = self.carried.take() {
            estimated += cost(&rr);
            current.push(rr);
        }
        for rr in self.records.by_ref() {
            let rr_cost = cost(&rr);
            if !current.is_empty() && estimated + rr_cost > AXFR_TARGET_MESSAGE_SIZE {
                self.carried = Some(rr);
                break;
            }
            estimated += rr_cost;
            current.push(rr);
        }
        if current.is_empty() {
            return None;
        }

        let mut message = transfer_message(self.request, current);
        // RFC 6891 §6.1.1 — a response to a request that carried an OPT record
        // carries one — applies to a transfer as much as to a lookup, and the
        // transfer path was the one that never did it. On the *first* message
        // only: a multi-message transfer is one response, BIND puts the OPT there
        // and nowhere else, and repeating it would put a second OPT in what
        // §6.1.1 treats as a single exchange.
        //
        // Before the TSIG, if one follows: RFC 8945 §5.1 requires the TSIG to be
        // the last record in the additional section, and the signer appends after
        // this.
        if std::mem::take(&mut self.first) && self.request.has_edns() {
            // `with_payload_size` carries no options, so this cannot fail. The
            // size is the client's own, echoed: a transfer is framed by the TCP
            // length prefix, so our UDP payload size says nothing useful here.
            message.set_edns(Edns::with_payload_size(self.request.udp_payload_size()));
        }
        Some(message)
    }
}

pub(crate) fn pack_transfer_messages(
    request: &DnsMessage,
    records: Vec<ResourceRecord>,
) -> Vec<DnsMessage> {
    Envelopes::new(request, records.into_iter()).collect()
}

/// One message of a transfer: the request's id and question, authoritative, with
/// this slice of the zone in the answer section.
///
/// Every message repeats the question. RFC 5936 §2.2.1 allows omitting it after
/// the first and requires accepting either, so the simpler of the two is fine —
/// and it means each message is a well-formed response on its own.
pub(crate) fn transfer_message(request: &DnsMessage, answers: Vec<ResourceRecord>) -> DnsMessage {
    DnsMessage {
        id: request.id,
        response: true,
        opcode: request.opcode,
        authoritive: true,
        truncation: false,
        recursion: request.recursion,
        recursion_ok: false,
        ad: false,
        cd: request.cd,
        rcode: ResponseCode::Ok,
        queries: request.queries.clone(),
        answers,
        authorities: Vec::new(),
        additionals: Vec::new(),
        edns: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::parse_zone_file;
    use crate::{OpCode, QueryClass, QuerySection};

    fn request_for(qname: &str) -> DnsMessage {
        DnsMessage {
            id: 0x1234,
            response: false,
            opcode: OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: qname.to_string(),
                qtype: Qtype::of(rt::AXFR),
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        }
    }

    fn small_zone() -> Zone {
        parse_zone_file(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n\
             www  IN A   192.0.2.2\n\
             *    IN A   192.0.2.9\n",
            "example.com.",
        )
        .expect("zone should parse")
    }

    /// RFC 5936 §2.2: the transfer opens and closes with the same SOA. A client
    /// that does not see the closing SOA has to assume the stream was cut.
    #[test]
    fn test_transfer_begins_and_ends_with_the_soa() {
        let zone = small_zone();
        let messages = axfr_messages(&request_for("example.com."), &zone).unwrap();

        let all: Vec<&ResourceRecord> = messages.iter().flat_map(|m| m.answers.iter()).collect();
        assert!(all.len() >= 2);
        assert_eq!(
            all.first().unwrap().rdata.rtype(),
            rt::SOA,
            "opens with the SOA"
        );
        assert_eq!(all.last().unwrap().rdata.rtype(), rt::SOA, "closes with it");
        assert_eq!(
            all.iter().filter(|rr| rr.rdata.rtype() == rt::SOA).count(),
            2,
            "and exactly twice — an SOA in the middle would end the transfer early"
        );
    }

    /// Everything in the zone goes across, under its absolute name, wildcard
    /// records included — a secondary has to be able to answer for them too.
    #[test]
    fn test_every_record_is_transferred_under_its_absolute_name() {
        let zone = small_zone();
        let messages = axfr_messages(&request_for("example.com."), &zone).unwrap();
        let names: Vec<String> = messages
            .iter()
            .flat_map(|m| m.answers.iter())
            .map(|rr| rr.name.clone())
            .collect();

        for expected in [
            "example.com.",
            "ns1.example.com.",
            "www.example.com.",
            "*.example.com.",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing {expected}: {names:?}"
            );
        }
        // The SOA twice plus the four other records.
        assert_eq!(
            messages.iter().map(|m| m.answers.len()).sum::<usize>(),
            6,
            "{names:?}"
        );
    }

    #[test]
    fn test_every_message_is_a_well_formed_authoritative_answer() {
        let zone = small_zone();
        let request = request_for("example.com.");
        for message in axfr_messages(&request, &zone).unwrap() {
            assert_eq!(
                message.id, request.id,
                "the transfer keeps the request's id"
            );
            assert!(message.response && message.authoritive);
            assert_eq!(message.rcode, ResponseCode::Ok);
            assert_eq!(message.queries.len(), 1, "the question is echoed");
            assert_eq!(message.queries[0].qname, request.queries[0].qname);
            assert_eq!(message.queries[0].qtype, Qtype::of(rt::AXFR));
        }
    }

    /// A zone too big for one message becomes several, each still framed as a
    /// complete answer — and the first and last of the *series* carry the SOA.
    #[test]
    fn test_a_large_zone_is_split_across_messages() {
        let mut text = String::from(
            "$TTL 3600\n@ IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400\n",
        );
        // Long names, so the estimate crosses the target well before this
        // becomes a slow test.
        for i in 0..2_000 {
            text.push_str(&format!(
                "host-with-a-fairly-long-name-{i} IN TXT \"padding padding padding\"\n"
            ));
        }
        let zone = parse_zone_file(&text, "example.com.").unwrap();

        let messages = axfr_messages(&request_for("example.com."), &zone).unwrap();
        assert!(
            messages.len() > 1,
            "expected a split, got {} message(s)",
            messages.len()
        );
        assert_eq!(
            messages
                .first()
                .unwrap()
                .answers
                .first()
                .unwrap()
                .rdata
                .rtype(),
            rt::SOA
        );
        assert_eq!(
            messages
                .last()
                .unwrap()
                .answers
                .last()
                .unwrap()
                .rdata
                .rtype(),
            rt::SOA
        );
        // Every record made it exactly once, plus the SOA twice.
        assert_eq!(
            messages.iter().map(|m| m.answers.len()).sum::<usize>(),
            2_002
        );

        // And each message fits a TCP frame, which is the point of splitting.
        for message in &messages {
            assert!(message.to_bytes_within(u16::MAX as usize).unwrap().len() <= u16::MAX as usize);
        }
    }

    /// No SOA, no transfer: there is nothing to bracket the stream with, so the
    /// client could not tell a complete transfer from a cut one.
    #[test]
    fn test_a_zone_without_an_soa_cannot_be_transferred() {
        let zone = parse_zone_file("www IN A 192.0.2.1\n", "example.com.").unwrap();
        let err = axfr_messages(&request_for("example.com."), &zone).unwrap_err();
        assert!(err.to_string().contains("no SOA"), "got: {err}");
    }
}
