//! DNS NOTIFY: telling a secondary that a zone changed (RFC 1996).
//!
//! Not a query: the opcode is NOTIFY (4), so a server dispatching on nothing but
//! the question section answers it as a lookup for the zone's SOA.
//!
//! The shape (RFC 1996 §3.7): question names the zone with QTYPE=SOA, AA set,
//! and the zone's SOA in the answer section. That last is optional in the RFC and
//! is how the secondary learns the new serial without asking again.

use crate::record_types as rt;
use crate::zone::Zone;
use crate::{
    DnsMessage, Name, NameRef, OpCode, ParsedRecord, Qtype, QueryClass, QuerySection,
    ResourceRecord, ResponseCode, Serial,
};

/// How many times a NOTIFY is sent before giving up on a secondary.
///
/// RFC 1996 §3.6 wants bounded retries. Losing one only costs the secondary its
/// refresh timer, which NOTIFY is an optimisation over.
pub const NOTIFY_ATTEMPTS: usize = 3;

/// Seconds before the second attempt; it doubles after that.
pub const NOTIFY_RETRY_SECS: u64 = 2;

/// Build the NOTIFY to send for `zone`.
///
/// `soa` is the zone's SOA record, included in the answer section so the
/// secondary can see the new serial from the notification itself.
pub fn notify_request(zone: NameRef<'_>, soa: Option<ResourceRecord>, id: u16) -> DnsMessage {
    DnsMessage {
        id,
        response: false,
        opcode: OpCode::Notify,
        authoritive: true,
        truncation: false,
        recursion: false,
        recursion_ok: false,
        ad: false,
        cd: false,
        rcode: ResponseCode::Ok,
        queries: vec![QuerySection {
            qname: zone.to_owned(),
            qtype: Qtype::of(rt::SOA),
            qclass: QueryClass::IN,
        }],
        answers: soa.into_iter().collect(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        edns: None,
    }
}

/// The reply to a NOTIFY: same opcode, question echoed, no data (RFC 1996 §4.7).
pub fn notify_response(request: &DnsMessage, rcode: ResponseCode) -> DnsMessage {
    let mut msg = DnsMessage::reply_to(request);
    msg.authoritive = true;
    msg.rcode = rcode;
    msg
}

/// The zone a NOTIFY is about, if the message is one and names a zone.
pub fn notified_zone(msg: &DnsMessage) -> Option<Name> {
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
/// Any rcode counts: a secondary answering NOTAUTH still received it, and
/// repeating would not change its mind.
pub fn acknowledges(reply: &DnsMessage, id: u16) -> bool {
    reply.response && reply.id == id && reply.opcode == OpCode::Notify
}

/// Which zones changed between two loads, as (zone, new serial).
///
/// A serial that is unchanged or has gone backwards is not news — a secondary
/// compares the same way and would ignore it. A zone new since the last load is.
pub fn changed_zones(before: &[(Name, Serial)], after: &[(Name, Serial)]) -> Vec<(Name, Serial)> {
    after
        .iter()
        .filter(
            |(zone, serial)| match before.iter().find(|(z, _)| z == zone) {
                Some((_, previous)) => serial.is_newer_than(*previous),
                None => true,
            },
        )
        .cloned()
        .collect()
}

/// Every zone's name and serial, for comparing one load against the next.
pub fn zone_serials(zones: &[&Zone]) -> Vec<(Name, Serial)> {
    zones
        .iter()
        .filter_map(|zone| {
            zone.serial()
                .map(|serial| (zone.origin().to_owned(), serial))
        })
        .collect()
}

/// The serial in a NOTIFY's answer section, if it carried its SOA.
pub fn notified_serial(msg: &DnsMessage) -> Option<Serial> {
    msg.answers
        .iter()
        .filter(|rr| rr.rdata.rtype() == rt::SOA)
        .find_map(|rr| match rr.rdata.parse() {
            Ok(ParsedRecord::SOA { serial, .. }) => Some(serial),
            _ => None,
        })
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_records::nm;
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

    /// A NOTIFY that goes out as a QUERY is a request for the zone's SOA — a
    /// different message with a plausible reply.
    #[test]
    fn test_a_notify_is_a_notify_on_the_wire() {
        let zone = zone_with_serial(7);
        let msg = notify_request(nm("example.com.").as_ref(), zone.apex_soa_record(), 0x1234);

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
        assert_eq!(parsed.queries[0].qname, nm("example.com."));
        assert_eq!(parsed.queries[0].qtype, Qtype::of(rt::SOA));
        assert_eq!(
            notified_serial(&parsed),
            Some(Serial::new(7)),
            "the SOA rides along so the secondary sees the new serial at once"
        );
        assert_eq!(notified_zone(&parsed), Some(nm("example.com.")));
    }

    #[test]
    fn test_a_notify_response_acknowledges_it() {
        let request = notify_request(nm("example.com.").as_ref(), None, 0x4321);
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
        assert_eq!(parsed.queries[0].qname, nm("example.com."));

        assert!(!acknowledges(&parsed, 0x9999));
        let mut wrong_opcode = parsed.clone();
        wrong_opcode.opcode = OpCode::Query;
        assert!(!acknowledges(&wrong_opcode, 0x4321));
    }

    /// Even a refusal ends the retries: the secondary received it.
    #[test]
    fn test_any_rcode_acknowledges() {
        let request = notify_request(nm("example.com.").as_ref(), None, 5);
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
        let at = |zone: &str, serial: u32| (nm(zone), Serial::new(serial));
        let before = vec![at("a.test.", 10), at("b.test.", 20)];
        let after = vec![
            at("a.test.", 11), // bumped
            at("b.test.", 20), // unchanged
            at("c.test.", 1),  // new zone
        ];
        let changed = changed_zones(&before, &after);
        assert_eq!(changed, vec![at("a.test.", 11), at("c.test.", 1)]);
    }

    /// A serial that has gone backwards is not an update.
    #[test]
    fn test_a_serial_that_went_backwards_is_not_news() {
        let before = vec![(nm("a.test."), Serial::new(10))];
        let after = vec![(nm("a.test."), Serial::new(9))];
        assert!(changed_zones(&before, &after).is_empty());
    }

    /// A wrapped serial is still an increment (RFC 1982); a naive `>` would call
    /// it a rollback. The arithmetic itself is tested beside [`Serial`] — this is
    /// that *this* function uses it.
    #[test]
    fn test_a_wrapped_serial_is_still_an_increment() {
        let before = vec![(nm("a.test."), Serial::new(u32::MAX - 1))];
        let after = vec![(nm("a.test."), Serial::new(3))];
        assert_eq!(
            changed_zones(&before, &after),
            vec![(nm("a.test."), Serial::new(3))],
            "3 is four ahead of 0xfffffffe in serial arithmetic"
        );
    }

    #[test]
    fn test_zone_serials_reads_the_apex_soa() {
        let zone = zone_with_serial(20260726);
        assert_eq!(
            zone_serials(&[&zone]),
            vec![(nm("example.com."), Serial::new(20260726))]
        );

        // No SOA, no serial to compare, so never news.
        let no_soa = parse_zone_file("www IN A 192.0.2.1\n", "example.com.").unwrap();
        assert!(zone_serials(&[&no_soa]).is_empty());
    }

    #[test]
    fn test_a_query_is_not_a_notification() {
        let mut msg = notify_request(nm("example.com.").as_ref(), None, 1);
        msg.opcode = OpCode::Query;
        assert!(notified_zone(&msg).is_none());

        // Nor is a NOTIFY response.
        let reply = notify_response(
            &notify_request(nm("example.com.").as_ref(), None, 1),
            ResponseCode::Ok,
        );
        assert!(notified_zone(&reply).is_none());
    }
}
