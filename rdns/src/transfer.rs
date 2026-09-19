//! Zone transfer: building an AXFR response (RFC 5936).
//!
//! Who may ask is [`crate::security::TransferAcl`]'s decision, not this module's.
//!
//! A transfer is a series of messages, the first beginning and the last ending
//! with the zone's SOA (RFC 5936 §2.2). Without that framing a truncated stream
//! is indistinguishable from a small zone.

use crate::error::{TransferError, TransferResult};
use crate::record_types as rt;
use crate::response::ClientEdns;
use crate::zone::Zone;
#[cfg(test)]
use crate::Name;
use crate::Qtype;
use crate::{DnsMessage, ResourceRecord};

/// How much of a message to fill before starting the next one.
///
/// Not a protocol limit — the TCP length prefix allows 64 KiB (RFC 1035 §4.2.2)
/// and RFC 5936 §2.2 leaves the split to the server. Small enough that the
/// packing estimate, which ignores name compression, stays inside the frame.
pub const AXFR_TARGET_MESSAGE_SIZE: usize = 16 * 1024;

/// The messages of an AXFR response for `zone`, one at a time, so a caller that
/// writes each envelope before asking for the next holds only one.
///
/// `Err` when the zone has no SOA at its apex — a broken zone, so SERVFAIL.
/// Checked before the first envelope, so a streaming caller has sent nothing yet
/// when it fails.
pub fn axfr_envelopes<'a>(
    request: &'a DnsMessage,
    zone: &'a Zone,
) -> TransferResult<impl Iterator<Item = DnsMessage> + 'a> {
    let apex = zone.origin();
    let soa = zone
        .query(apex, Qtype::of(rt::SOA))
        .first()
        .map(|zr| ResourceRecord {
            name: apex.to_owned(),
            class: zr.class,
            ttl: zr.ttl,
            rdata: zr.rdata.clone(),
        })
        .ok_or_else(|| TransferError::malformed(format!("zone {apex} has no SOA at its apex")))?;

    Ok(Envelopes::new(request, AxfrRecords::new(zone, soa)))
}

/// [`axfr_envelopes`] collected, for callers that want the sequence in hand. A
/// caller serving a real zone to a socket should pull the iterator instead.
pub fn axfr_messages(request: &DnsMessage, zone: &Zone) -> TransferResult<Vec<DnsMessage>> {
    Ok(axfr_envelopes(request, zone)?.collect())
}

/// The records of an AXFR in wire order: the apex SOA, the zone's own order
/// without that SOA, then the apex SOA again (RFC 5936 §2.2), which puts no
/// constraint on the middle.
///
/// Skipping the middle one keeps the count at two; a client that saw the closing
/// SOA early would stop reading there.
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
            // The apex SOA is sent first and last by this iterator, never from
            // the middle of the zone (RFC 5936 §2.2).
            if self.zone.is_apex_soa(zr) {
                continue;
            }
            return Some(ResourceRecord {
                name: zr.name.clone(),
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

/// A transfer's records, split into messages that each fit a TCP frame. Shared
/// with [`crate::ixfr`]: the framing belongs to a transfer, not to its kind.
///
/// The estimate ignores name compression — a name costs at most its text length
/// plus two, a record's fixed part ten bytes — so it can only be too large,
/// which is the safe direction against the 64 KiB length prefix.
pub(crate) struct Envelopes<'a, I> {
    request: &'a DnsMessage,
    records: I,
    /// The record that did not fit the envelope just yielded; the source is an
    /// iterator with no way back.
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
        // The name's wire length exactly, now that a name is its wire form.
        let cost =
            |rr: &ResourceRecord| rr.name.as_ref().as_wire().len() + 10 + rr.rdata.bytes().len();
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
        // Mirror the client's OPT on the first message only — RFC 5936 §2.2.5:
        // "it SHOULD include one OPT RR in the first response message and MAY do
        // so in subsequent response messages". Before any TSIG, which must be
        // last in the additional section (RFC 8945 §5.1) and is appended by the
        // signer.
        //
        // Through [`ClientEdns`] rather than `has_edns()` plus a fresh `Edns`,
        // which is what dropped DO here: RFC 3225 §3's "the DO bit of the query
        // MUST be copied in the response" is not about queries only, and this
        // was the fourth site to read it that way (`TODO.md` #38, #47). The two
        // agree on *whether* to mirror — they differ only for an option list
        // that does not parse, which never reaches a transfer.
        if std::mem::take(&mut self.first) {
            // The client's own size, echoed: a transfer is framed by the TCP
            // length prefix, so ours says nothing useful here.
            if let Some(edns) = ClientEdns::of(self.request).mirror(self.request.udp_payload_size())
            {
                message.set_edns(edns);
            }
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
/// Every message repeats the question, which RFC 5936 §2.2.1 permits, so each is
/// a well-formed response on its own.
pub(crate) fn transfer_message(request: &DnsMessage, answers: Vec<ResourceRecord>) -> DnsMessage {
    let mut msg = DnsMessage::reply_to(request);
    msg.authoritive = true;
    msg.answers = answers;
    msg
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_records::nm;
    use crate::zone::parse_zone_file;
    use crate::{DnsMessageBuilder, ResponseCode};

    fn request_for(qname: &str) -> DnsMessage {
        DnsMessageBuilder::new()
            .with_id(0x1234)
            .with_query(nm(qname), Qtype::of(rt::AXFR))
            .with_recursion(false)
            .build()
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

    /// RFC 5936 §2.2: the transfer opens and closes with the same SOA.
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

    /// Everything goes across under its absolute name, wildcards included — a
    /// secondary has to answer for those too.
    #[test]
    fn test_every_record_is_transferred_under_its_absolute_name() {
        let zone = small_zone();
        let messages = axfr_messages(&request_for("example.com."), &zone).unwrap();
        let names: Vec<Name> = messages
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
                names.iter().any(|n| *n == nm(expected)),
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

    /// RFC 5936 §2.2.5: "it SHOULD include one OPT RR in the first response
    /// message and MAY do so in subsequent response messages" — and RFC 3225
    /// §3: "the DO bit of the query MUST be copied in the response", which this
    /// dropped until #47. Nothing asserted either before.
    ///
    /// The DO bit changes nothing about what a transfer carries — §3 says the
    /// security records "are part of the zone data for an AXFR or IXFR query"
    /// and go whether it was set or not — so what a cleared bit says is that
    /// this server stopped doing DNSSEC, which is exactly how the same slip
    /// read on three reply paths in #38.
    #[test]
    fn the_first_envelope_mirrors_the_clients_opt_and_its_do_bit() {
        let zone = small_zone();

        for do_bit in [false, true] {
            let mut request = request_for("example.com.");
            let mut edns = crate::Edns::with_payload_size(1232);
            edns.do_bit = do_bit;
            request.set_edns(edns);

            let messages = axfr_messages(&request, &zone).expect("a transfer");
            let first = messages.first().expect("at least one envelope");
            let opt = first.edns().expect("the first message carries an OPT");
            assert_eq!(opt.do_bit, do_bit, "DO is the client's");
            assert_eq!(
                opt.udp_payload_size,
                request.udp_payload_size(),
                "the client's own size: a transfer is framed by the TCP length \
                 prefix, so ours says nothing here"
            );
        }

        // And no OPT at all when the client sent none (RFC 6891 §6.2.2).
        let plain = request_for("example.com.");
        assert!(plain.edns().is_none(), "the fixture sends no OPT");
        let messages = axfr_messages(&plain, &zone).expect("a transfer");
        assert!(
            messages.iter().all(|m| m.edns().is_none()),
            "an unsolicited OPT is not a mirror"
        );
    }

    /// The "first message only" half of §2.2.5, which needs a zone that splits.
    #[test]
    fn only_the_first_envelope_of_a_split_transfer_carries_the_opt() {
        let mut text = String::from(
            "$TTL 3600
@ IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400
",
        );
        for i in 0..2_000 {
            text.push_str(&format!(
                "host-with-a-fairly-long-name-{i} IN TXT \"padding padding padding\"
"
            ));
        }
        let zone = parse_zone_file(&text, "example.com.").unwrap();

        let mut request = request_for("example.com.");
        let mut edns = crate::Edns::with_payload_size(1232);
        edns.do_bit = true;
        request.set_edns(edns);

        let messages = axfr_messages(&request, &zone).expect("a transfer");
        assert!(messages.len() > 1, "expected a split");
        assert!(messages[0].edns().is_some(), "the first message has it");
        assert!(
            messages[1..].iter().all(|m| m.edns().is_none()),
            "a multi-message transfer is one exchange, so the rest do not"
        );
    }

    /// A zone too big for one message becomes several, each a complete answer,
    /// with the SOA at each end of the series.
    #[test]
    fn test_a_large_zone_is_split_across_messages() {
        let mut text = String::from(
            "$TTL 3600\n@ IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400\n",
        );
        // Long names, so the estimate crosses the target without a slow test.
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

        // And each message fits a TCP frame.
        for message in &messages {
            assert!(message.to_bytes_within(u16::MAX as usize).unwrap().len() <= u16::MAX as usize);
        }
    }

    /// No SOA, no transfer: nothing brackets the stream.
    #[test]
    fn test_a_zone_without_an_soa_cannot_be_transferred() {
        let zone = parse_zone_file("www IN A 192.0.2.1\n", "example.com.").unwrap();
        let err = axfr_messages(&request_for("example.com."), &zone).unwrap_err();
        assert!(err.to_string().contains("no SOA"), "got: {err}");
    }
}
