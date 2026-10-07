//! Names answered on this machine rather than resolved (RFC 6761, RFC 6762,
//! RFC 6303).
//!
//! Two tables, and the difference is whether the operator may switch an entry
//! off. **Special-use names** cannot be: `localhost` (RFC 6761 §6.3) and its
//! reverse names, `invalid` (§6.4) and `.local` (RFC 6762 §3) are answered
//! here whatever is configured, because each is a protocol requirement. **Empty
//! zones** are RFC 6303's private-address reverse zones, and §3 says "an
//! implementation of this recommendation MUST provide a mechanism to disable
//! this new behaviour, and SHOULD allow this decision on a zone-by-zone basis":
//! a site with its own `10.in-addr.arpa.` has to be able to reach it
//! (`TODO.md` #173). [`EmptyZones`] is that mechanism.
//!
//! Not here on purpose: `example.`, `example.com.`, `example.net.`,
//! `example.org.`. RFC 6761 reserves them as *ordinary* names, delegated and
//! resolvable, which is the one thing they exist for.

use crate::error::{ConfigError, ConfigResult};
use crate::record_types as rt;
use crate::Class;
use crate::Serial;
use crate::Ttl;
use crate::{Name, NameRef, ParsedRecord, RecordData, ResourceRecord, ResponseCode};
use crate::{Qtype, Rtype};

/// What the table says to answer.
///
/// Every one is authoritative (AA=1). RFC 6303 §3 asks for that of an empty
/// zone — "return authoritatively (AA=1) name errors" — because the zone is
/// defined to be empty, so the subtree claim RFC 8020 reads into AA is the
/// intended one; the special-use names are the same kind of claim.
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

/// Reverse zones for address space that is not globally unique, so a name in
/// one cannot have a globally meaningful answer (RFC 6303 §4.3–§4.6, §4.8).
///
/// 172.16/12 is sixteen zones: `in-addr.arpa` splits on octet boundaries and
/// the block does not. Not `127.in-addr.arpa.` or the `::1` reverse, which
/// RFC 6303 lists too (§4.2, §4.7) but which describe `localhost`, so they are
/// special-use names and cannot be switched off.
pub const EMPTY_ZONES: &[&str] = &[
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
];

/// The IPv6 loopback's reverse zone (RFC 6303 §4.7), one name deep.
const LOOPBACK_V6_REVERSE: &str =
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.";

/// Which [`EMPTY_ZONES`] are answered here. All of them by default.
///
/// A set of indexes into the table rather than names: a name the table does
/// not hold cannot be in it, which is [`EmptyZones::configure`]'s refusal
/// rather than a lookup that silently matches nothing.
#[derive(Debug, Clone)]
pub struct EmptyZones {
    on: [bool; EMPTY_ZONES.len()],
}

impl Default for EmptyZones {
    fn default() -> Self {
        EmptyZones {
            on: [true; EMPTY_ZONES.len()],
        }
    }
}

impl EmptyZones {
    /// `--no-empty-zones` is `all_off`; `--disable-empty-zone` is `disabled`.
    ///
    /// Refused, naming the entry: both together, which is two ways to say one
    /// thing and a precedence rule nobody would remember (`CLAUDE.md` §15); a
    /// special-use name, which is fixed; a name inside an empty zone, which
    /// RFC 6303 §3's "zone-by-zone" does not reach; and any other name, which
    /// would otherwise switch nothing off while the operator believes it had.
    pub fn configure(all_off: bool, disabled: &[String]) -> ConfigResult<Self> {
        if all_off && !disabled.is_empty() {
            return Err(ConfigError::new(
                "--no-empty-zones switches every empty zone off, so --disable-empty-zone \
                 has nothing left to do; give one or the other"
                    .to_string(),
            ));
        }
        if all_off {
            return Ok(EmptyZones {
                on: [false; EMPTY_ZONES.len()],
            });
        }
        let table = table();
        let mut zones = EmptyZones::default();
        for text in disabled {
            let name = Name::from_presentation(text)
                .map_err(|e| ConfigError::new(format!("--disable-empty-zone {text:?}: {e}")))?;
            if let Some(i) = table.empty.iter().position(|z| *z == name) {
                zones.on[i] = false;
                continue;
            }
            if table.special_use().any(|s| name.as_ref().is_at_or_under(s)) {
                return Err(ConfigError::new(format!(
                    "--disable-empty-zone {text}: a special-use name (RFC 6761, RFC 6762), \
                     answered locally whatever is configured"
                )));
            }
            if let Some(i) = table
                .empty
                .iter()
                .position(|z| name.as_ref().is_at_or_under(z.as_ref()))
            {
                return Err(ConfigError::new(format!(
                    "--disable-empty-zone {text}: inside the empty zone {}, which is \
                     switched off whole or not at all",
                    EMPTY_ZONES[i]
                )));
            }
            return Err(ConfigError::new(format!(
                "--disable-empty-zone {text}: not an empty zone; the empty zones are \
                 RFC 6303's private-address reverse zones, such as 10.in-addr.arpa."
            )));
        }
        Ok(zones)
    }

    /// The empty zones switched off, for the startup line.
    pub fn off(&self) -> impl Iterator<Item = &'static str> + '_ {
        EMPTY_ZONES
            .iter()
            .zip(self.on)
            .filter(|(_, on)| !on)
            .map(|(zone, _)| *zone)
    }

    /// For the startup line.
    pub fn describe(&self) -> String {
        match self.off().count() {
            0 => "all on".to_string(),
            n if n == EMPTY_ZONES.len() => "all off".to_string(),
            _ => format!("off: {}", self.off().collect::<Vec<_>>().join(", ")),
        }
    }
}

/// The answer for `qname`/`qtype` if it is a name we must not send upstream.
///
/// `None` means "an ordinary name": resolve it as usual. An empty zone that
/// `empty` has switched off is an ordinary name.
pub fn lookup(qname: NameRef<'_>, qtype: Qtype, empty: &EmptyZones) -> Option<LocalAnswer> {
    let table = table();

    // RFC 6761 §6.3: `localhost.` and the whole subtree under it is the loopback
    // interface, and must never be sent to a DNS server.
    if qname.is_at_or_under(table.localhost.as_ref()) {
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
                table.localhost.as_ref(),
                "localhost exists but has only loopback addresses (RFC 6761 §6.3)",
            ),
        });
    }

    // RFC 6303 §4.2: 127.0.0.1 is `localhost.`; the rest of 127/8 is ours to
    // answer for, and the answer is that nothing is there.
    if qname == table.loopback_ptr.as_ref() && qtype.is(rt::PTR) {
        return Some(positive(
            qname,
            RecordData::from_parsed(&ParsedRecord::PTR(table.localhost.clone())).ok()?,
            "127.0.0.1 is localhost (RFC 6303 §4.2)",
        ));
    }
    for zone in [&table.loopback_reverse, &table.loopback_v6_reverse] {
        if qname.is_at_or_under(zone.as_ref()) {
            return Some(in_zone(
                qname,
                qtype,
                zone.as_ref(),
                "the loopback reverse zones are answered locally (RFC 6303 §4.2, §4.7)",
            ));
        }
    }

    // RFC 6762 §3: `.local` is mDNS, not a DNS namespace, so NXDOMAIN is the
    // literal truth rather than a policy.
    if qname.is_at_or_under(table.mdns.as_ref()) {
        return Some(nxdomain(
            table.mdns.as_ref(),
            "`.local` is mDNS, not DNS (RFC 6762 §3)",
        ));
    }

    // RFC 6761 §6.4: `invalid.` is reserved to be unresolvable.
    if qname.is_at_or_under(table.invalid.as_ref()) {
        return Some(nxdomain(
            table.invalid.as_ref(),
            "`invalid.` is reserved to not exist (RFC 6761 §6.4)",
        ));
    }

    // RFC 6303 §4: a PTR for non-globally-unique space describes part of
    // somebody's internal network — unless the operator said this one is not.
    for (zone, on) in table.empty.iter().zip(empty.on) {
        if on && qname.is_at_or_under(zone.as_ref()) {
            return Some(in_zone(
                qname,
                qtype,
                zone.as_ref(),
                "a private-address reverse lookup is answered locally (RFC 6303 §4)",
            ));
        }
    }

    None
}

/// The table's names, parsed once.
///
/// A query used to pay `to_presentation()` and a down-casing `String` to be
/// compared against text — on every name a resolver is asked for, since this is
/// consulted before the caches. The names are the same on every call, so they
/// are built once and the comparison is [`NameRef::is_at_or_under`]'s, which
/// folds case as it walks (RFC 4343) and allocates nothing.
struct Table {
    localhost: Name,
    loopback_ptr: Name,
    loopback_reverse: Name,
    loopback_v6_reverse: Name,
    mdns: Name,
    invalid: Name,
    /// In the order of [`EMPTY_ZONES`], whose text is what a message names.
    empty: Vec<Name>,
}

impl Table {
    /// Every name no setting reaches.
    fn special_use(&self) -> impl Iterator<Item = NameRef<'_>> {
        [
            &self.localhost,
            &self.loopback_reverse,
            &self.loopback_v6_reverse,
            &self.mdns,
            &self.invalid,
        ]
        .into_iter()
        .map(Name::as_ref)
    }
}

fn table() -> &'static Table {
    static TABLE: std::sync::LazyLock<Table> = std::sync::LazyLock::new(|| {
        let parse = |text: &str| {
            Name::from_presentation(text).expect("a name written out in this file parses")
        };
        Table {
            localhost: parse("localhost."),
            loopback_ptr: parse("1.0.0.127.in-addr.arpa."),
            loopback_reverse: parse("127.in-addr.arpa."),
            loopback_v6_reverse: parse(LOOPBACK_V6_REVERSE),
            mdns: parse("local."),
            invalid: parse("invalid."),
            empty: EMPTY_ZONES.iter().copied().map(parse).collect(),
        }
    });
    &TABLE
}

/// A name in a locally answered reverse zone: RFC 6303 §3's zone, which has
/// an SOA and an NS at its apex and nothing else anywhere.
///
/// The apex was NXDOMAIN, with an SOA for that same name beside it — a name
/// denied by the record proving it exists.
fn in_zone(qname: NameRef<'_>, qtype: Qtype, zone: NameRef<'_>, why: &'static str) -> LocalAnswer {
    if qname != zone {
        return nxdomain(zone, why);
    }
    match Rtype::new(qtype.to_u16()) {
        rt::SOA => LocalAnswer {
            rcode: ResponseCode::Ok,
            answers: synthetic_soa(zone).into_iter().collect(),
            authority: Vec::new(),
            why,
        },
        // §3: "the name server SHOULD return a single NS record naming the
        // zone itself", which is the SOA's MNAME too.
        rt::NS => match RecordData::from_parsed(&ParsedRecord::NS(zone.to_owned())) {
            Ok(rdata) => positive(qname, rdata, why),
            Err(_) => nodata(zone, why),
        },
        _ => nodata(zone, why),
    }
}

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
            class: Class::IN,
            ttl: LOCAL_TTL,
            rdata,
        }],
        authority: Vec::new(),
        why,
    }
}

fn nodata(zone: NameRef<'_>, why: &'static str) -> LocalAnswer {
    LocalAnswer {
        rcode: ResponseCode::Ok,
        answers: Vec::new(),
        authority: synthetic_soa(zone).into_iter().collect(),
        why,
    }
}

fn nxdomain(zone: NameRef<'_>, why: &'static str) -> LocalAnswer {
    LocalAnswer {
        rcode: ResponseCode::NoSuchDomain,
        answers: Vec::new(),
        authority: synthetic_soa(zone).into_iter().collect(),
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
        class: Class::IN,
        ttl: LOCAL_TTL,
        rdata,
    })
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_records::nm;

    /// The table as it stands with nothing configured.
    fn lookup(qname: NameRef<'_>, qtype: Qtype) -> Option<LocalAnswer> {
        super::lookup(qname, qtype, &EmptyZones::default())
    }

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

    /// RFC 6303 §3's zone has an SOA and an NS at its apex. The apex was
    /// NXDOMAIN beside an SOA for that same name until `TODO.md` #173 — a test
    /// asserting that would have encoded the bug, and none did.
    #[test]
    fn an_empty_zone_apex_has_its_soa_and_ns() {
        for zone in [
            "10.in-addr.arpa.",
            "127.in-addr.arpa.",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
        ] {
            let soa = answer(zone, Qtype::of(rt::SOA));
            assert_eq!(soa.rcode, ResponseCode::Ok, "{zone}");
            assert_eq!(soa.answers.len(), 1, "{zone}");
            assert_eq!(soa.answers[0].rdata.rtype(), rt::SOA);
            assert_eq!(soa.answers[0].name, nm(zone));

            let ns = answer(zone, Qtype::of(rt::NS));
            assert_eq!(ns.rcode, ResponseCode::Ok, "{zone}");
            assert!(
                matches!(parsed(&ns.answers[0]), ParsedRecord::NS(n) if n == nm(zone)),
                "one NS naming the zone itself (§3): {zone}"
            );

            let a = answer(zone, Qtype::of(rt::A));
            assert_eq!(a.rcode, ResponseCode::Ok, "NODATA at {zone}");
            assert!(a.answers.is_empty());
            assert_eq!(a.authority[0].name, nm(zone), "with the zone's SOA");
        }
    }

    /// RFC 6303 §3's "MUST provide a mechanism to disable": one zone off is an
    /// ordinary name, and its neighbours are not touched.
    #[test]
    fn a_switched_off_empty_zone_is_an_ordinary_name() {
        let zones =
            EmptyZones::configure(false, &["10.IN-ADDR.ARPA.".to_string()]).expect("configures");
        let ptr = Qtype::of(rt::PTR);
        assert!(super::lookup(nm("1.2.3.10.in-addr.arpa.").as_ref(), ptr, &zones).is_none());
        assert!(super::lookup(nm("10.in-addr.arpa.").as_ref(), ptr, &zones).is_none());
        assert!(super::lookup(nm("1.1.168.192.in-addr.arpa.").as_ref(), ptr, &zones).is_some());
        assert_eq!(zones.describe(), "off: 10.in-addr.arpa.");
    }

    /// All off leaves every special-use name where it was.
    #[test]
    fn all_empty_zones_off_leaves_the_special_use_names() {
        let zones = EmptyZones::configure(true, &[]).expect("configures");
        assert_eq!(zones.describe(), "all off");
        for zone in EMPTY_ZONES {
            assert!(
                super::lookup(nm(zone).as_ref(), Qtype::of(rt::PTR), &zones).is_none(),
                "{zone}"
            );
        }
        for name in [
            "localhost.",
            "1.0.0.127.in-addr.arpa.",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
            "printer.local.",
            "x.invalid.",
        ] {
            assert!(
                super::lookup(nm(name).as_ref(), Qtype::of(rt::PTR), &zones).is_some(),
                "{name}"
            );
        }
    }

    /// Each refusal names the entry and says what is wrong with it.
    #[test]
    fn a_name_that_is_not_an_empty_zone_is_refused_by_name() {
        let refused = |all: bool, names: &[&str]| {
            let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
            EmptyZones::configure(all, &names)
                .expect_err("refused")
                .to_string()
        };
        let localhost = refused(false, &["localhost."]);
        assert!(
            localhost.contains("localhost") && localhost.contains("special-use"),
            "{localhost}"
        );
        let loopback = refused(false, &["127.in-addr.arpa."]);
        assert!(loopback.contains("special-use"), "{loopback}");
        let inside = refused(false, &["1.10.in-addr.arpa."]);
        assert!(
            inside.contains("1.10.in-addr.arpa.")
                && inside.contains("inside the empty zone 10.in-addr.arpa."),
            "{inside}"
        );
        let other = refused(false, &["example."]);
        assert!(
            other.contains("example.") && other.contains("not an empty zone"),
            "{other}"
        );
        let both = refused(true, &["10.in-addr.arpa."]);
        assert!(
            both.contains("--no-empty-zones") && both.contains("--disable-empty-zone"),
            "{both}"
        );
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
