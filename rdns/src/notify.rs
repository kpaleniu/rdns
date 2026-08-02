//! DNS NOTIFY: telling a secondary that a zone changed (RFC 1996).
//!
//! Without it a secondary finds out about a change when its refresh timer next
//! goes off, which for a typical SOA is hours after the fact. NOTIFY makes the
//! primary say so immediately: one small message per secondary, and the
//! secondary decides what to do about it.
//!
//! It is not a query, and that is the whole of what makes it different. The
//! opcode is NOTIFY (4) rather than QUERY (0), so a server that dispatches on
//! nothing but the question section will cheerfully answer it as a lookup for the
//! zone's SOA — which is a plausible-looking reply to a message that was not
//! asking anything.
//!
//! The shape (RFC 1996 §3.7): the question names the zone with QTYPE=SOA, AA is
//! set because the sender is authoritative for what it is talking about, and the
//! answer section carries the zone's SOA. That last part is optional in the RFC
//! and worth including: it is how the secondary learns the new serial without
//! having to ask a second question.

use crate::utils::record_types as rt;
use crate::zone::Zone;
use crate::{
    DnsMessage, OpCode, ParsedRecord, Qtype, QueryClass, QuerySection, ResourceRecord, ResponseCode,
};

/// How many times a NOTIFY is sent before giving up on a secondary.
///
/// RFC 1996 §3.6 wants retries until a response arrives, bounded. Losing one is
/// not a catastrophe — the secondary's refresh timer is still there as the
/// backstop, which is exactly what NOTIFY is an optimisation over.
pub const NOTIFY_ATTEMPTS: usize = 3;

/// Seconds before the second attempt; it doubles after that.
pub const NOTIFY_RETRY_SECS: u64 = 2;

/// Build the NOTIFY to send for `zone`.
///
/// `soa` is the zone's SOA record, included in the answer section so the
/// secondary can see the new serial from the notification itself.
pub fn notify_request(zone: &str, soa: Option<ResourceRecord>, id: u16) -> DnsMessage {
    DnsMessage {
        id,
        response: false,
        opcode: OpCode::Notify,
        // The sender is authoritative for the zone it is reporting on.
        authoritive: true,
        truncation: false,
        // A NOTIFY is not a request for recursion, and no secondary should read
        // it as one.
        recursion: false,
        recursion_ok: false,
        ad: false,
        cd: false,
        rcode: ResponseCode::Ok,
        queries: vec![QuerySection {
            qname: zone.to_string(),
            qtype: Qtype::of(rt::SOA),
            qclass: QueryClass::IN,
        }],
        answers: soa.into_iter().collect(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        edns: None,
    }
}

/// The reply to a NOTIFY: the same opcode, the question echoed, and nothing else
/// (RFC 1996 §4.7 — a NOTIFY response carries no data, it is an acknowledgement).
pub fn notify_response(request: &DnsMessage, rcode: ResponseCode) -> DnsMessage {
    DnsMessage {
        id: request.id,
        response: true,
        opcode: OpCode::Notify,
        authoritive: true,
        truncation: false,
        recursion: request.recursion,
        recursion_ok: false,
        ad: false,
        cd: request.cd,
        rcode,
        queries: request.queries.clone(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        edns: None,
    }
}

/// The zone a NOTIFY is about, if the message is one and names a zone.
pub fn notified_zone(msg: &DnsMessage) -> Option<String> {
    if msg.opcode != OpCode::Notify || msg.response {
        return None;
    }
    msg.queries
        .first()
        .filter(|q| q.qtype.is(rt::SOA))
        .map(|q| q.qname.clone())
}

/// Whether a reply is an acknowledgement of the NOTIFY we sent with `id`.
///
/// Any rcode counts. A secondary answering NOTAUTH has still told us it received
/// the message, which is all a retry loop needs to know — and repeating it would
/// not change its mind.
pub fn acknowledges(reply: &DnsMessage, id: u16) -> bool {
    reply.response && reply.id == id && reply.opcode == OpCode::Notify
}

/// Which zones changed between two loads, as (zone, new serial).
///
/// A zone whose serial is unchanged is not news, and a zone that has gone
/// backwards is not either — a secondary compares serials with RFC 1982 serial
/// arithmetic and would ignore it, so sending is just noise. A zone that is new
/// since the last load *is* news: nobody has heard about it yet.
pub fn changed_zones(before: &[(String, u32)], after: &[(String, u32)]) -> Vec<(String, u32)> {
    after
        .iter()
        .filter(
            |(zone, serial)| match before.iter().find(|(z, _)| z == zone) {
                // RFC 1982 §3.2: `new` is later than `old` when the difference,
                // taken in 32-bit wrapping arithmetic, is in the first half of the
                // space. That is what makes a serial that wraps past 2^32 still read
                // as an increment.
                Some((_, previous)) => {
                    serial.wrapping_sub(*previous) != 0
                        && serial.wrapping_sub(*previous) < 0x8000_0000
                }
                None => true,
            },
        )
        .cloned()
        .collect()
}

/// Every zone's name and serial, for comparing one load against the next.
pub fn zone_serials(zones: &[&Zone]) -> Vec<(String, u32)> {
    zones
        .iter()
        .filter_map(|zone| {
            zone.serial()
                .map(|serial| (zone.origin().to_string(), serial))
        })
        .collect()
}

/// The apex SOA of `zone` as a resource record, ready for a NOTIFY's answer
/// section.
pub fn soa_record(zone: &Zone) -> Option<ResourceRecord> {
    zone.query(zone.origin(), Qtype::of(rt::SOA))
        .first()
        .map(|soa| ResourceRecord {
            name: zone.origin().to_string(),
            class: soa.class,
            ttl: soa.ttl,
            rdata: soa.rdata.clone(),
        })
}

/// The serial in a NOTIFY's answer section, if it carried its SOA.
pub fn notified_serial(msg: &DnsMessage) -> Option<u32> {
    msg.answers
        .iter()
        .filter(|rr| rr.rdata.rtype == rt::SOA)
        .find_map(|rr| match rr.rdata.parse() {
            Ok(ParsedRecord::SOA { serial, .. }) => Some(serial),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::parse_zone_file;

    fn zone_with_serial(serial: u32) -> Zone {
        parse_zone_file(
            &format!(
                "$TTL 3600\n\
                 @ IN SOA ns1.example.com. admin.example.com. {serial} 3600 1800 604800 86400\n\
                 @ IN NS  ns1.example.com.\n"
            ),
            "example.com.",
        )
        .expect("zone should parse")
    }

    /// The opcode is the point: a NOTIFY that goes out as a QUERY is a request
    /// for the zone's SOA, which is a different message with a plausible reply.
    #[test]
    fn test_a_notify_is_a_notify_on_the_wire() {
        let zone = zone_with_serial(7);
        let msg = notify_request("example.com.", soa_record(&zone), 0x1234);

        let mut buf = vec![0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("serialize");
        let parsed = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");

        assert_eq!(parsed.opcode, OpCode::Notify, "opcode 4, not 0");
        assert!(!parsed.response, "a NOTIFY request is not a response");
        assert!(
            parsed.authoritive,
            "the sender is authoritative for the zone"
        );
        assert!(!parsed.recursion, "and is not asking anyone to recurse");
        assert_eq!(parsed.queries[0].qname, "example.com.");
        assert_eq!(parsed.queries[0].qtype, Qtype::of(rt::SOA));
        assert_eq!(
            notified_serial(&parsed),
            Some(7),
            "the SOA rides along so the secondary sees the new serial at once"
        );
        assert_eq!(notified_zone(&parsed).as_deref(), Some("example.com."));
    }

    #[test]
    fn test_a_notify_response_acknowledges_it() {
        let request = notify_request("example.com.", None, 0x4321);
        let reply = notify_response(&request, ResponseCode::Ok);

        let mut buf = vec![0u8; 512];
        let n = reply.to_bytes(&mut buf).expect("serialize");
        let parsed = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");

        assert!(acknowledges(&parsed, 0x4321));
        assert_eq!(parsed.opcode, OpCode::Notify, "the reply keeps the opcode");
        assert!(
            parsed.answers.is_empty(),
            "an acknowledgement carries no data"
        );
        assert_eq!(parsed.queries[0].qname, "example.com.");

        // A different transaction, or an answer to something else, is not it.
        assert!(!acknowledges(&parsed, 0x9999));
        let mut wrong_opcode = parsed.clone();
        wrong_opcode.opcode = OpCode::Query;
        assert!(!acknowledges(&wrong_opcode, 0x4321));
    }

    /// Even a refusal ends the retries: the secondary plainly received it, and
    /// asking again would get the same answer.
    #[test]
    fn test_any_rcode_acknowledges() {
        let request = notify_request("example.com.", None, 5);
        for rcode in [
            ResponseCode::Ok,
            ResponseCode::NotAuthorized,
            ResponseCode::Refused,
            ResponseCode::ServerFailure,
        ] {
            assert!(acknowledges(&notify_response(&request, rcode), 5));
        }
    }

    #[test]
    fn test_only_changed_zones_are_news() {
        let before = vec![("a.test.".to_string(), 10), ("b.test.".to_string(), 20)];
        let after = vec![
            ("a.test.".to_string(), 11), // bumped
            ("b.test.".to_string(), 20), // unchanged
            ("c.test.".to_string(), 1),  // new zone
        ];
        let changed = changed_zones(&before, &after);
        assert_eq!(
            changed,
            vec![("a.test.".to_string(), 11), ("c.test.".to_string(), 1)]
        );
    }

    /// A serial that has gone *backwards* is not an update: a secondary comparing
    /// serials would ignore it, so telling it would be noise.
    #[test]
    fn test_a_serial_that_went_backwards_is_not_news() {
        let before = vec![("a.test.".to_string(), 10)];
        let after = vec![("a.test.".to_string(), 9)];
        assert!(changed_zones(&before, &after).is_empty());
    }

    /// RFC 1982 serial arithmetic: a serial that wraps past 2^32 is still an
    /// increment, and a naive `>` comparison would call it a rollback and stay
    /// silent for the rest of the zone's life.
    #[test]
    fn test_a_wrapped_serial_is_still_an_increment() {
        let before = vec![("a.test.".to_string(), u32::MAX - 1)];
        let after = vec![("a.test.".to_string(), 3)];
        assert_eq!(
            changed_zones(&before, &after),
            vec![("a.test.".to_string(), 3)],
            "3 is four ahead of 0xfffffffe in serial arithmetic"
        );
    }

    #[test]
    fn test_zone_serials_reads_the_apex_soa() {
        let zone = zone_with_serial(20260726);
        assert_eq!(
            zone_serials(&[&zone]),
            vec![("example.com.".to_string(), 20260726)]
        );

        // A zone with no SOA has no serial to compare, so it is never news.
        let no_soa = parse_zone_file("www IN A 192.0.2.1\n", "example.com.").unwrap();
        assert!(zone_serials(&[&no_soa]).is_empty());
    }

    #[test]
    fn test_a_query_is_not_a_notification() {
        let mut msg = notify_request("example.com.", None, 1);
        msg.opcode = OpCode::Query;
        assert!(notified_zone(&msg).is_none());

        // Nor is a NOTIFY *response* something to act on as a notification.
        let reply = notify_response(&notify_request("example.com.", None, 1), ResponseCode::Ok);
        assert!(notified_zone(&reply).is_none());
    }
}
