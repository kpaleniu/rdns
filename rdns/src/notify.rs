//! DNS NOTIFY: telling a secondary that a zone changed (RFC 1996).
//!
//! Not a query: the opcode is NOTIFY (4), so a server dispatching on nothing but
//! the question section answers it as a lookup for the zone's SOA.
//!
//! The shape (RFC 1996 §3.7): question names the zone with QTYPE=SOA, AA set,
//! and the zone's SOA in the answer section. That last is optional in the RFC and
//! is how the secondary learns the new serial without asking again.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::error::{ConfigError, ConfigResult};
use crate::record_types as rt;
use crate::tsig::{TsigKey, TsigKeyring};
use crate::zone::Zone;
use crate::{
    name_keys::NameKeyBuf, DnsMessage, Name, NameRef, OpCode, ParsedRecord, Qtype, QueryClass,
    QuerySection, ResourceRecord, ResponseCode, Serial,
};

/// A secondary to tell, and the key to tell it with: `addr[:port][#keyname]`.
///
/// The key half exists because a secondary's notify ACL can demand one, and two
/// of the three this tree is tested against do when asked: NSD's
/// `allow-notify: <addr> <key>` answers REFUSED to an unsigned NOTIFY and
/// Knot's `acl: { key: ..., action: notify }` answers NOTAUTH. BIND does not,
/// because it accepts a NOTIFY from anything in the zone's `primaries` list
/// whatever `allow-notify` says — which is worth knowing before concluding from
/// a BIND secondary that unsigned is good enough (`TODO.md` #46).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyTarget {
    pub addr: SocketAddr,
    /// By name, looked up in the keys `--tsig-key` defines, so a secret is
    /// written down in one place.
    pub key_name: Option<String>,
}

impl NotifyTarget {
    pub fn parse(spec: &str) -> ConfigResult<Self> {
        let spec = spec.trim();
        let parsed = crate::endpoint::parse_endpoint(spec, spec)?;
        // The endpoint syntax carries `+tls=` for `--secondary` (`TODO.md`
        // #44d). RFC 9103 is about the transfer and says nothing about NOTIFY,
        // and this server has no TLS client for one, so accepting the suffix
        // here would be a flag that changes nothing — which is the shape
        // `CLAUDE.md` §15 refuses in a config key.
        if parsed.tls.is_some() {
            return Err(ConfigError::new(format!(
                "--also-notify {spec:?}: '+tls=' is for --secondary, where it is                  RFC 9103's zone transfer over TLS. A NOTIFY here is sent in                  clear whatever this says, so it is refused rather than ignored"
            )));
        }
        Ok(NotifyTarget {
            addr: parsed.addr,
            key_name: parsed.key_name,
        })
    }

    /// Look the key name up in `keys`.
    ///
    /// A key named but not defined is a configuration error, not a reason to
    /// notify unsigned: the operator asked for authentication and would
    /// otherwise not be able to see that they did not get it. That is the same
    /// rule `--secondary` applies to the same syntax, and now the same sentence.
    pub fn resolve(&self, keys: &TsigKeyring) -> ConfigResult<NotifyPeer> {
        let key = match &self.key_name {
            Some(name) => Some(
                keys.by_name(name)
                    .ok_or_else(|| {
                        ConfigError::new(format!(
                            "--also-notify {self} names TSIG key {name:?}, which no \
                             --tsig-key defines"
                        ))
                    })?
                    .clone(),
            ),
            None => None,
        };
        Ok(NotifyPeer {
            addr: self.addr,
            key,
        })
    }
}

impl std::fmt::Display for NotifyTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.key_name {
            Some(key) => write!(f, "{}#{key}", self.addr),
            None => write!(f, "{}", self.addr),
        }
    }
}

/// A notify target with its key looked up: what the sender needs.
#[derive(Debug, Clone)]
pub struct NotifyPeer {
    pub addr: SocketAddr,
    pub key: Option<TsigKey>,
}

impl std::fmt::Display for NotifyPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.key {
            Some(key) => write!(f, "{}#{}", self.addr, key.name),
            None => write!(f, "{}", self.addr),
        }
    }
}

/// Who is told about which zone.
///
/// Two settings feed this: `--also-notify` / `[server].also-notify`, which
/// applies to every zone, and `[zones."x"].also-notify`, which *adds* to it for
/// one zone — "in addition to", which is what `ZoneConfig::also_notify`'s doc
/// comment has always said it meant.
///
/// It says it for the first time here. The per-zone list was parsed into
/// `PerZone::notify` and read by nothing, so both `docs/spec/` files documented
/// a setting that a `deny_unknown_fields` config accepted and silently dropped
/// (`TODO.md` #46c, and `CLAUDE.md` §4's shape: the operator believes it is in
/// force and it is not).
///
/// The union is built once, at startup, so a zone's list is a slice rather than
/// something allocated per announcement — and deduplicated, because naming the
/// same secondary globally and again per zone should not send it two NOTIFYs.
#[derive(Debug, Clone, Default)]
pub struct NotifyPolicy {
    global: Vec<NotifyPeer>,
    per_zone: HashMap<NameKeyBuf, Vec<NotifyPeer>>,
}

impl NotifyPolicy {
    pub fn new(global: Vec<NotifyPeer>) -> Self {
        NotifyPolicy {
            global: deduped(global),
            per_zone: HashMap::new(),
        }
    }

    /// Add `extra` for one zone, on top of the global list.
    pub fn add_zone(&mut self, zone: NameRef<'_>, extra: Vec<NotifyPeer>) {
        let mut all = self.global.clone();
        all.extend(extra);
        self.per_zone.insert(NameKeyBuf::new(zone), deduped(all));
    }

    /// Who to tell about `zone`.
    pub fn targets_for(&self, zone: NameRef<'_>) -> &[NotifyPeer] {
        self.per_zone
            .get(&*zone.folded())
            .map(Vec::as_slice)
            .unwrap_or(&self.global)
    }

    /// Whether anything would ever be sent, so a caller can skip the work of
    /// building messages nobody is listening for.
    pub fn is_empty(&self) -> bool {
        self.global.is_empty() && self.per_zone.values().all(Vec::is_empty)
    }

    /// Every distinct peer, for the startup banner.
    pub fn describe(&self) -> String {
        let mut all: Vec<String> = self
            .global
            .iter()
            .chain(self.per_zone.values().flatten())
            .map(NotifyPeer::to_string)
            .collect();
        all.sort();
        all.dedup();
        all.join(", ")
    }
}

/// Same address and same key named twice is one secondary.
fn deduped(peers: Vec<NotifyPeer>) -> Vec<NotifyPeer> {
    let mut seen: Vec<NotifyPeer> = Vec::with_capacity(peers.len());
    for peer in peers {
        let already = seen.iter().any(|s| {
            s.addr == peer.addr
                && s.key.as_ref().map(|k| &k.name) == peer.key.as_ref().map(|k| &k.name)
        });
        if !already {
            seen.push(peer);
        }
    }
    seen
}

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

/// What the secondary did with a NOTIFY, once one answered.
///
/// Both variants end the retries — the message arrived, and sending it again
/// would not change the answer. They differ in whether anything is going to
/// happen as a result, which is the distinction `TODO.md` #46b existed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyOutcome {
    /// NOERROR: the secondary has it and will refresh.
    Accepted,
    /// It arrived and was refused. Nothing will refresh, and the zone is stale
    /// on that secondary until its REFRESH timer fires — hours, for an ordinary
    /// SOA. The caller says so out loud rather than at INFO.
    Rejected(ResponseCode),
}

/// What a reply to the NOTIFY sent with `id` says, or `None` if it is not one.
///
/// `None` for anything that is not this message's answer, so an off-path reply
/// cannot silence a notification by arriving first.
///
/// This returned a bare `bool` until #46b, under a comment saying any rcode
/// counts because the secondary received it either way. That is true and was
/// not the whole answer: a secondary whose notify ACL names a key refuses every
/// unsigned NOTIFY, which the bool reported as `acknowledged (Refused)` at INFO
/// — a permanently broken notification path with nothing in a failed state
/// (`CLAUDE.md` §4).
pub fn outcome(reply: &DnsMessage, id: u16) -> Option<NotifyOutcome> {
    if !(reply.response && reply.id == id && reply.opcode == OpCode::Notify) {
        return None;
    }
    Some(match reply.rcode {
        ResponseCode::Ok => NotifyOutcome::Accepted,
        rcode => NotifyOutcome::Rejected(rcode),
    })
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

        assert_eq!(outcome(&parsed, 0x4321), Some(NotifyOutcome::Accepted));
        assert_eq!(parsed.opcode, OpCode::Notify, "the reply keeps the opcode");
        assert!(
            parsed.answers.is_empty(),
            "an acknowledgement carries no data"
        );
        assert_eq!(parsed.queries[0].qname, nm("example.com."));

        assert_eq!(outcome(&parsed, 0x9999), None, "not our transaction");
        let mut wrong_opcode = parsed.clone();
        wrong_opcode.opcode = OpCode::Query;
        assert_eq!(outcome(&wrong_opcode, 0x4321), None, "not a NOTIFY reply");
    }

    /// Every rcode ends the retries — the secondary received it either way —
    /// but only NOERROR means it is going to do anything about it. #46b: these
    /// were one answer, and a keyed notify ACL refusing every NOTIFY read as
    /// `acknowledged` at INFO.
    #[test]
    fn test_a_refusal_ends_the_retries_without_being_an_acceptance() {
        let request = notify_request(nm("example.com.").as_ref(), None, 5);
        assert_eq!(
            outcome(&notify_response(&request, ResponseCode::Ok), 5),
            Some(NotifyOutcome::Accepted)
        );
        for rcode in [
            ResponseCode::NotAuthorized,
            ResponseCode::Refused,
            ResponseCode::ServerFailure,
        ] {
            assert_eq!(
                outcome(&notify_response(&request, rcode), 5),
                Some(NotifyOutcome::Rejected(rcode)),
                "{rcode:?} arrived, so stop retrying, but nothing will refresh"
            );
        }
    }

    /// The spellings an operator writes, and the one that is a typo.
    #[test]
    fn test_a_notify_target_carries_an_optional_key() {
        let plain = NotifyTarget::parse("192.0.2.10").expect("an address alone");
        assert_eq!(plain.addr, "192.0.2.10:53".parse().unwrap());
        assert_eq!(plain.key_name, None);
        assert_eq!(plain.to_string(), "192.0.2.10:53");

        let keyed = NotifyTarget::parse("192.0.2.10:5353#partner.key.").expect("with a key");
        assert_eq!(keyed.addr, "192.0.2.10:5353".parse().unwrap());
        assert_eq!(keyed.key_name.as_deref(), Some("partner.key."));
        assert_eq!(keyed.to_string(), "192.0.2.10:5353#partner.key.");

        assert_eq!(
            NotifyTarget::parse("[2001:db8::1]:5353#k.")
                .expect("a bracketed v6 address with a port and a key")
                .addr,
            "[2001:db8::1]:5353".parse().unwrap()
        );

        assert!(
            NotifyTarget::parse("192.0.2.10#").is_err(),
            "a trailing '#' is a typo, not a request for no key"
        );
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
    /// `+tls=` is `--secondary`'s, and a NOTIFY is sent in clear whatever the
    /// flag says — so it is refused rather than silently doing nothing
    /// (`CLAUDE.md` §15).
    #[test]
    fn a_notify_target_refuses_the_transfer_tls_suffix() {
        let err =
            NotifyTarget::parse("192.0.2.1+tls=ns1.example.com.").expect_err("not a notify option");
        assert!(err.to_string().contains("is for --secondary"), "got: {err}");
    }
}
