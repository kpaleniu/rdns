//! Names that must never leave the machine (RFC 6761, RFC 6762, RFC 6303).
//!
//! Consulted before the caches and before any resolution. Answering from the
//! table is the requirement, not an optimisation: RFC 6761 §6.3 for `localhost`,
//! §6.4 for `invalid`, RFC 6762 §3 for `.local`, RFC 6303 §4 for the private
//! reverse zones.
//!
//! Not here on purpose: `example.`, `example.com.`, `example.net.`,
//! `example.org.`. RFC 6761 reserves them as *ordinary* names, delegated and
//! resolvable, which is the one thing they exist for.

use crate::utils::{is_at_or_under, record_types as rt};
use crate::Class;
use crate::Serial;
use crate::Ttl;
use crate::{Name, NameRef, ParsedRecord, RecordData, ResourceRecord, ResponseCode};
use crate::{Qtype, Rtype};

/// What the table says to answer.
pub struct LocalAnswer {
    pub rcode: ResponseCode,
    /// The answer section, empty for a negative answer.
    pub answers: Vec<ResourceRecord>,
    /// A synthetic SOA, so a downstream resolver can cache the answer
    /// (RFC 2308 §5 takes the negative TTL from it).
    pub authority: Vec<ResourceRecord>,
    /// Why, for the log: these answers are invisible otherwise.
    pub why: &'static str,
}

/// TTL on everything synthesized here. Fixed by specification, so the only
/// reason it is not longer is that a client should notice a reconfiguration.
const LOCAL_TTL: Ttl = Ttl::from_secs(3600);

/// The answer for `qname`/`qtype` if it is a name we must not send upstream.
///
/// `None` means "an ordinary name": resolve it as usual.
pub fn lookup(qname: NameRef<'_>, qtype: Qtype) -> Option<LocalAnswer> {
    // These are matched as text: the list is written as text, in this file.
    let name = qname.to_presentation().to_ascii_lowercase();

    // RFC 6761 §6.3: `localhost.` and the whole subtree under it is the loopback
    // interface, and must never be sent to a DNS server.
    if name == "localhost." || name.ends_with(".localhost.") {
        return Some(match Rtype::new(qtype.to_u16()) {
            rt::A => positive(
                qname,
                loopback_v4(),
                "localhost is the loopback address (RFC 6761 §6.3)",
            ),
            rt::AAAA => positive(
                qname,
                loopback_v6(),
                "localhost is the loopback address (RFC 6761 §6.3)",
            ),
            // NODATA, not NXDOMAIN: the name exists on every machine.
            _ => nodata(
                "localhost.",
                "localhost exists but has only loopback addresses (RFC 6761 §6.3)",
            ),
        });
    }

    // RFC 6303 §4.2: 127.0.0.1 is `localhost.`; the rest of 127/8 is ours to
    // answer for, and the answer is that nothing is there.
    if name == "1.0.0.127.in-addr.arpa." && qtype.is(rt::PTR) {
        return Some(positive(
            qname,
            RecordData::from_parsed(&ParsedRecord::PTR(
                Name::from_presentation("localhost.").ok()?,
            ))
            .ok()?,
            "127.0.0.1 is localhost (RFC 6303 §4.2)",
        ));
    }
    if is_at_or_under(&name, "127.in-addr.arpa.") {
        return Some(nxdomain(
            "127.in-addr.arpa.",
            "the loopback reverse zone is answered locally (RFC 6303 §4.2)",
        ));
    }

    // RFC 6762 §3: `.local` is mDNS, not a DNS namespace, so NXDOMAIN is the
    // literal truth rather than a policy.
    if is_at_or_under(&name, "local.") {
        return Some(nxdomain(
            "local.",
            "`.local` is mDNS, not DNS (RFC 6762 §3)",
        ));
    }

    // RFC 6761 §6.4: `invalid.` is reserved to be unresolvable.
    if is_at_or_under(&name, "invalid.") {
        return Some(nxdomain(
            "invalid.",
            "`invalid.` is reserved to not exist (RFC 6761 §6.4)",
        ));
    }

    // RFC 6303 §4: a PTR for non-globally-unique space describes part of
    // somebody's internal network.
    for zone in PRIVATE_REVERSE_ZONES {
        if is_at_or_under(&name, zone) {
            return Some(nxdomain(
                zone,
                "a private-address reverse lookup is answered locally (RFC 6303 §4)",
            ));
        }
    }

    None
}

/// Reverse zones for address space that is not globally unique, so a name in one
/// cannot have a globally meaningful answer (RFC 6303 §4.3–§4.6, §4.8).
///
/// 172.16/12 is sixteen zones: `in-addr.arpa` splits on octet boundaries and the
/// block does not.
const PRIVATE_REVERSE_ZONES: &[&str] = &[
    // RFC 1918 private space.
    "10.in-addr.arpa.",
    "16.172.in-addr.arpa.",
    "17.172.in-addr.arpa.",
    "18.172.in-addr.arpa.",
    "19.172.in-addr.arpa.",
    "20.172.in-addr.arpa.",
    "21.172.in-addr.arpa.",
    "22.172.in-addr.arpa.",
    "23.172.in-addr.arpa.",
    "24.172.in-addr.arpa.",
    "25.172.in-addr.arpa.",
    "26.172.in-addr.arpa.",
    "27.172.in-addr.arpa.",
    "28.172.in-addr.arpa.",
    "29.172.in-addr.arpa.",
    "30.172.in-addr.arpa.",
    "31.172.in-addr.arpa.",
    "168.192.in-addr.arpa.",
    // Link-local (RFC 3927) — 169.254/16.
    "254.169.in-addr.arpa.",
    // "This host on this network" (RFC 1122 §3.2.1.3) — 0/8.
    "0.in-addr.arpa.",
    // Link-local (fe80::/10) and unique-local (fc00::/7), in nibble form.
    "8.e.f.ip6.arpa.",
    "9.e.f.ip6.arpa.",
    "a.e.f.ip6.arpa.",
    "b.e.f.ip6.arpa.",
    "c.f.ip6.arpa.",
    "d.f.ip6.arpa.",
    // The IPv6 loopback, ::1, and the unspecified address (RFC 6303 §4.7).
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
];

fn loopback_v4() -> RecordData {
    RecordData::from_parsed(&ParsedRecord::A(std::net::Ipv4Addr::LOCALHOST))
        .expect("the loopback address encodes")
}

fn loopback_v6() -> RecordData {
    RecordData::from_parsed(&ParsedRecord::AAAA(std::net::Ipv6Addr::LOCALHOST))
        .expect("the loopback address encodes")
}

fn positive(qname: NameRef<'_>, rdata: RecordData, why: &'static str) -> LocalAnswer {
    LocalAnswer {
        rcode: ResponseCode::Ok,
        answers: vec![ResourceRecord {
            name: qname.to_owned(),
            class: Class::new(1),
            ttl: LOCAL_TTL,
            rdata,
        }],
        authority: Vec::new(),
        why,
    }
}

fn nodata(zone: &str, why: &'static str) -> LocalAnswer {
    LocalAnswer {
        rcode: ResponseCode::Ok,
        answers: Vec::new(),
        authority: Name::from_presentation(zone)
            .ok()
            .and_then(|z| synthetic_soa(z.as_ref()))
            .into_iter()
            .collect(),
        why,
    }
}

fn nxdomain(zone: &str, why: &'static str) -> LocalAnswer {
    LocalAnswer {
        rcode: ResponseCode::NoSuchDomain,
        answers: Vec::new(),
        authority: Name::from_presentation(zone)
            .ok()
            .and_then(|z| synthetic_soa(z.as_ref()))
            .into_iter()
            .collect(),
        why,
    }
}

/// An SOA for a zone that does not really have one.
///
/// These zones exist by specification rather than delegation, so there is no real
/// SOA to quote — but a negative answer without one cannot be cached at all
/// (RFC 2308 §5). The shape follows Unbound's `local-zone`, `nobody.invalid.`
/// included: unmistakably synthetic and guaranteed not to resolve.
fn synthetic_soa(zone: NameRef<'_>) -> Option<ResourceRecord> {
    let rdata = RecordData::from_parsed(&ParsedRecord::SOA {
        mname: zone.to_owned(),
        rname: Name::from_presentation("nobody.invalid.").ok()?,
        serial: Serial::new(1),
        refresh: 3600,
        retry: 1200,
        expire: 604_800,
        minimum: LOCAL_TTL.as_secs(),
    })
    .ok()?;
    Some(ResourceRecord {
        name: zone.to_owned(),
        class: Class::new(1),
        ttl: LOCAL_TTL,
        rdata,
    })
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_records::nm;

    fn answer(qname: &str, qtype: Qtype) -> LocalAnswer {
        lookup(nm(qname).as_ref(), qtype)
            .unwrap_or_else(|| panic!("{qname} should be answered locally"))
    }

    fn parsed(record: &ResourceRecord) -> ParsedRecord {
        record.rdata.parse().expect("the record parses")
    }

    #[test]
    fn test_localhost_is_the_loopback_address() {
        let v4 = answer("localhost.", Qtype::of(rt::A));
        assert_eq!(v4.rcode, ResponseCode::Ok);
        assert!(
            matches!(parsed(&v4.answers[0]), ParsedRecord::A(a) if a == std::net::Ipv4Addr::LOCALHOST)
        );

        let v6 = answer("localhost.", Qtype::of(rt::AAAA));
        assert!(
            matches!(parsed(&v6.answers[0]), ParsedRecord::AAAA(a) if a == std::net::Ipv6Addr::LOCALHOST)
        );

        // Case and the trailing dot do not make a name ordinary.
        assert!(lookup(nm("LocalHost").as_ref(), Qtype::of(rt::A)).is_some());
        assert!(lookup(nm("LOCALHOST.").as_ref(), Qtype::of(rt::A)).is_some());
    }

    /// RFC 6761 §6.3 reserves the whole subtree, and software relies on it.
    #[test]
    fn test_names_under_localhost_are_local_too() {
        let a = answer("api.dev.localhost.", Qtype::of(rt::A));
        assert!(
            matches!(parsed(&a.answers[0]), ParsedRecord::A(a) if a == std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            a.answers[0].name,
            nm("api.dev.localhost."),
            "echoed as asked"
        );

        // A name that merely ends in those letters is somebody's real host.
        assert!(lookup(nm("notlocalhost.").as_ref(), Qtype::of(rt::A)).is_none());
        assert!(lookup(nm("localhost.example.com.").as_ref(), Qtype::of(rt::A)).is_none());
    }

    /// The name exists and has nothing but addresses.
    #[test]
    fn test_localhost_has_no_other_types() {
        let mx = answer("localhost.", Qtype::of(rt::MX));
        assert_eq!(mx.rcode, ResponseCode::Ok, "NODATA, not NXDOMAIN");
        assert!(mx.answers.is_empty());
        assert_eq!(mx.authority.len(), 1, "with an SOA, so it can be cached");
    }

    #[test]
    fn test_the_loopback_reverse_lookup() {
        let ptr = answer("1.0.0.127.in-addr.arpa.", Qtype::of(rt::PTR));
        assert!(matches!(parsed(&ptr.answers[0]), ParsedRecord::PTR(n) if n == nm("localhost.")));

        // The rest of 127/8 is ours, and the answer is nothing.
        let other = answer("2.0.0.127.in-addr.arpa.", Qtype::of(rt::PTR));
        assert_eq!(other.rcode, ResponseCode::NoSuchDomain);
    }

    /// `.local` is mDNS (RFC 6762 §3).
    #[test]
    fn test_local_is_mdns_and_never_leaves() {
        for name in ["printer.local.", "a.b.local.", "local."] {
            let a = answer(name, Qtype::of(rt::A));
            assert_eq!(a.rcode, ResponseCode::NoSuchDomain, "{name}");
            assert!(a.why.contains("mDNS"), "{}", a.why);
        }
        assert!(
            lookup(nm("mylocal.").as_ref(), Qtype::of(rt::A)).is_none(),
            "not a label boundary"
        );
    }

    #[test]
    fn test_invalid_is_reserved_to_not_exist() {
        assert_eq!(
            answer("nope.invalid.", Qtype::of(rt::A)).rcode,
            ResponseCode::NoSuchDomain
        );
        assert_eq!(
            answer("invalid.", Qtype::of(rt::A)).rcode,
            ResponseCode::NoSuchDomain
        );
    }

    /// A PTR for private space describes somebody's internal network.
    #[test]
    fn test_private_reverse_lookups_are_answered_locally() {
        for name in [
            "1.1.168.192.in-addr.arpa.",
            "5.4.3.10.in-addr.arpa.",
            "1.1.16.172.in-addr.arpa.",
            "1.1.31.172.in-addr.arpa.",
            "1.1.254.169.in-addr.arpa.",
            "1.0.in-addr.arpa.",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.f.ip6.arpa.",
        ] {
            let a = answer(name, Qtype::of(rt::PTR));
            assert_eq!(a.rcode, ResponseCode::NoSuchDomain, "{name}");
            assert_eq!(a.authority.len(), 1, "{name} should carry an SOA");
        }
    }

    /// 172.16/12 is sixteen zones; either side is ordinary public space. A wrong
    /// boundary leaks private lookups or black-holes real ones.
    #[test]
    fn test_the_172_boundary_is_exact() {
        for private in 16..=31 {
            let name = nm(&format!("1.1.{private}.172.in-addr.arpa."));
            assert!(
                lookup(name.as_ref(), Qtype::of(rt::PTR)).is_some(),
                "172.{private} is private"
            );
        }
        for public in [15, 32] {
            let name = nm(&format!("1.1.{public}.172.in-addr.arpa."));
            assert!(
                lookup(name.as_ref(), Qtype::of(rt::PTR)).is_none(),
                "172.{public} is not"
            );
        }
    }

    /// RFC 6761 reserves the `example` names as *ordinary* ones: delegated and
    /// resolvable.
    #[test]
    fn test_the_example_names_are_ordinary() {
        for name in [
            "example.",
            "example.com.",
            "www.example.com.",
            "example.net.",
            "example.org.",
        ] {
            assert!(
                lookup(nm(name).as_ref(), Qtype::of(rt::A)).is_none(),
                "{name} resolves normally"
            );
        }
    }

    /// Nothing else is intercepted: a wrong entry is a name that silently stops
    /// working.
    #[test]
    fn test_ordinary_names_are_left_alone() {
        for name in [
            ".",
            "com.",
            "arpa.",
            "in-addr.arpa.",
            "ip6.arpa.",
            "1.1.1.1.in-addr.arpa.", // 1.1.1.1 is public
            "8.8.8.8.in-addr.arpa.",
            "9.9.9.9.in-addr.arpa.",
            "localdomain.",
            "onion.", // reserved, but not ours to answer (RFC 7686)
        ] {
            assert!(
                lookup(nm(name).as_ref(), Qtype::of(rt::A)).is_none(),
                "{name}"
            );
            assert!(
                lookup(nm(name).as_ref(), Qtype::of(rt::PTR)).is_none(),
                "{name}"
            );
        }
    }

    /// A malformed SOA is one a downstream resolver throws away, so it asks again.
    #[test]
    fn test_the_synthetic_soa_is_well_formed() {
        let a = answer("printer.local.", Qtype::of(rt::A));
        let soa = &a.authority[0];
        assert_eq!(
            soa.name,
            nm("local."),
            "owned by the zone, not the queried name"
        );
        assert_eq!(soa.rdata.rtype(), rt::SOA);
        let ParsedRecord::SOA { rname, minimum, .. } = parsed(soa) else {
            panic!("not an SOA");
        };
        assert_eq!(rname, nm("nobody.invalid."), "unmistakably synthetic");
        assert_eq!(minimum, LOCAL_TTL.as_secs());
    }
}
