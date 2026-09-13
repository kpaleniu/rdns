//! DNS64: an AAAA for a name that has none, so an IPv6-only client can reach an
//! IPv4-only server through a NAT64 (RFC 6147).
//!
//! The deal is explicit and this module is where it is written down. A
//! synthesized AAAA is an address that does not exist in the zone, pointing at
//! a translator the operator runs; the client connects to it and the NAT64 box
//! turns the flow into IPv4. It is the only way an IPv6-only mobile network —
//! which is most of them — reaches an IPv4-only name, and it is also a
//! deliberate untruth, which is why RFC 6147 §5.5 stops at a client that said it
//! would check for itself.
//!
//! What is here:
//!
//! - [`Nat64Prefix`], the address arithmetic of RFC 6052 §2.2. Six prefix
//!   lengths, the embedded octets in a different place in each, and bits 64-71
//!   reserved and zero in all but the /96 case where the prefix covers them.
//!   RFC 6052 §2.4's own example table is the test.
//! - [`Dns64`], the policy around it: which prefix, which AAAA answers are to be
//!   read as no answer at all (§5.1.4), and the synthesis itself.
//!
//! What is deliberately not here: *when* to synthesize. That is a property of an
//! answer path — which paths can produce an empty AAAA answer, and which of
//! those are empty for a reason synthesis must not paper over — so it lives in
//! `rdnsr`'s `answer`, beside the paths themselves. Two of them must never
//! synthesize and the reasons are unrelated to DNS64: a name RFC 6761 answers
//! locally is not an IPv4 name behind a translator, and a name a policy zone
//! blocked is blocked (`TODO.md` #45a).

use crate::error::{ConfigError, ConfigResult};
use crate::record_types as rt;
use crate::security::TransferAcl;
use crate::{Name, NameRef, ParsedRecord, RecordData, ResourceRecord, Ttl};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The Well-Known Prefix (RFC 6052 §2.1), used when the operator names none.
pub const WELL_KNOWN_PREFIX: &str = "64:ff9b::/96";

/// AAAA answers to treat as no answer at all, by default (RFC 6147 §5.1.4).
///
/// `::ffff:0:0/96` is the IPv4-mapped range: an address in it is a way of
/// writing an IPv4 address, not a route to one, so a client given it is no
/// better off than with the A record it came from. §5.1.4 asks for this one by
/// name.
pub const DEFAULT_EXCLUSIONS: &str = "::ffff:0:0/96";

/// Where an IPv4 address sits inside an IPv6 one (RFC 6052 §2.2).
///
/// The prefix length is one of six values and each puts the four octets
/// somewhere different, so this is a table rather than a shift: `n` must be 32,
/// 40, 48, 56, 64 or 96, and bits 64-71 — octet 8 — are "reserved for
/// compatibility" and MUST be zero in every form but the /96, whose prefix
/// covers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nat64Prefix {
    octets: [u8; 16],
    len: u8,
}

/// Which octets of the address hold the four of the IPv4 address, for each
/// legal prefix length.
///
/// Read straight off RFC 6052 §2.2's figure: 24 bits at 40-63 and 8 at 72-79
/// for a /40 is octets 5, 6, 7 and 9.
fn embedded_octets(len: u8) -> Option<[usize; 4]> {
    Some(match len {
        32 => [4, 5, 6, 7],
        40 => [5, 6, 7, 9],
        48 => [6, 7, 9, 10],
        56 => [7, 9, 10, 11],
        64 => [9, 10, 11, 12],
        96 => [12, 13, 14, 15],
        _ => return None,
    })
}

impl Nat64Prefix {
    /// Parse `2001:db8::/96`, or the Well-Known Prefix from
    /// [`WELL_KNOWN_PREFIX`].
    ///
    /// The length is checked against RFC 6052 §2.2's six values rather than
    /// against 128: a /97 has nowhere to put the address, and a /95 would put it
    /// somewhere no NAT64 looks.
    pub fn parse(spec: &str) -> ConfigResult<Nat64Prefix> {
        let (addr, len) = spec
            .split_once('/')
            .ok_or_else(|| ConfigError::new(format!("the NAT64 prefix {spec:?} has no /length")))?;
        let addr: Ipv6Addr = addr
            .parse()
            .map_err(|e| ConfigError::new(format!("{addr:?} is not an IPv6 address: {e}")))?;
        let len: u8 = len
            .parse()
            .map_err(|e| ConfigError::new(format!("{len:?} is not a prefix length: {e}")))?;
        if embedded_octets(len).is_none() {
            return Err(ConfigError::new(format!(
                "a NAT64 prefix is /32, /40, /48, /56, /64 or /96, not /{len} (RFC 6052 §2.2)"
            )));
        }
        let octets = addr.octets();
        // Everything past the prefix belongs to the embedded address and the
        // zero suffix; a prefix carrying bits there is one the operator has
        // mistyped, and embedding would silently discard them.
        let tail = (len as usize).div_ceil(8);
        if octets[tail..].iter().any(|&b| b != 0) {
            return Err(ConfigError::new(format!(
                "the NAT64 prefix {spec} has bits set past /{len}"
            )));
        }
        Ok(Nat64Prefix { octets, len })
    }

    /// The Well-Known Prefix, 64:ff9b::/96.
    pub fn well_known() -> Nat64Prefix {
        Nat64Prefix::parse(WELL_KNOWN_PREFIX).expect("the Well-Known Prefix parses")
    }

    /// `v4` embedded in this prefix (RFC 6052 §2.2).
    pub fn embed(&self, v4: Ipv4Addr) -> Ipv6Addr {
        let mut octets = self.octets;
        let at = embedded_octets(self.len).expect("the length was checked at parse");
        for (slot, byte) in at.into_iter().zip(v4.octets()) {
            octets[slot] = byte;
        }
        Ipv6Addr::from(octets)
    }

    /// The IPv4 address `v6` carries, or `None` if it is not in this prefix.
    ///
    /// The inverse of [`Nat64Prefix::embed`], and total: an address that matches
    /// the prefix bits but carries something in the reserved octet is not an
    /// IPv4-embedded address, so it is not one this prefix can speak for.
    pub fn extract(&self, v6: Ipv6Addr) -> Option<Ipv4Addr> {
        let octets = v6.octets();
        let whole = (self.len / 8) as usize;
        if octets[..whole] != self.octets[..whole] {
            return None;
        }
        // Bits 64-71 are reserved and zero (§2.2), except under a /96, whose
        // prefix covers them.
        if self.len < 96 && octets[8] != 0 {
            return None;
        }
        let at = embedded_octets(self.len).expect("the length was checked at parse");
        Some(Ipv4Addr::new(
            octets[at[0]],
            octets[at[1]],
            octets[at[2]],
            octets[at[3]],
        ))
    }

    /// The prefix length in bits — one of RFC 6052 §2.2's six. Not `len` as a
    /// container's: clippy reads that name as one and asks for `is_empty`.
    pub fn bits(&self) -> u8 {
        self.len
    }
}

impl std::fmt::Display for Nat64Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.octets), self.len)
    }
}

/// The DNS64 policy in force: one prefix to synthesize into, and the AAAA
/// answers that are to be read as no answer (RFC 6147 §5.1.4).
#[derive(Debug, Clone)]
pub struct Dns64 {
    prefix: Nat64Prefix,
    /// v6 prefixes whose presence in an answer means "still nothing usable".
    ///
    /// `TransferAcl` because it is the same question — is this address in one of
    /// these prefixes — and a second CIDR parser would disagree about something
    /// eventually (`CLAUDE.md` §7).
    exclude: TransferAcl,
}

impl Dns64 {
    /// `exclude` is added to RFC 6147 §5.1.4's default, never instead of it: the
    /// mapped range is excluded because an address in it is an IPv4 address
    /// written differently, which is true whatever else the operator lists.
    pub fn new(prefix: Nat64Prefix, exclude: &[String]) -> ConfigResult<Dns64> {
        let mut specs = vec![DEFAULT_EXCLUSIONS.to_string()];
        specs.extend(exclude.iter().cloned());
        Ok(Dns64 {
            prefix,
            exclude: TransferAcl::parse_named(&specs, "--dns64-exclude")?,
        })
    }

    pub fn prefix(&self) -> Nat64Prefix {
        self.prefix
    }

    /// Whether an answer already gives the client something it can use.
    ///
    /// An AAAA in an excluded range counts as absent (§5.1.4), so an answer of
    /// nothing but `::ffff:` addresses is an empty answer for this purpose.
    pub fn answered(&self, answers: &[ResourceRecord]) -> bool {
        answers.iter().any(|rr| match rr.rdata.parse() {
            Ok(ParsedRecord::AAAA(addr)) => !self.excluded(addr),
            _ => false,
        })
    }

    fn excluded(&self, addr: Ipv6Addr) -> bool {
        self.exclude.contains(IpAddr::V6(addr))
    }

    /// The AAAA records to answer with, built from an A answer (RFC 6147 §5.1.7).
    ///
    /// A CNAME in the A answer is kept as it stands (§5.1.5: the chain is
    /// followed to the terminating A), and everything else is dropped: only an
    /// address record has an IPv6 representation to give.
    ///
    /// `ttl_cap` is the SOA's TTL from the empty AAAA answer, because §5.1.7
    /// sets the synthesized TTL to "the minimum of the TTL of the original A RR
    /// and the SOA RR for the queried domain" — the name has no AAAA, so the
    /// negative answer's own lifetime bounds how long the invention may live.
    pub fn synthesize(
        &self,
        a_answer: &[ResourceRecord],
        ttl_cap: Option<Ttl>,
    ) -> Vec<ResourceRecord> {
        let mut out = Vec::with_capacity(a_answer.len());
        for record in a_answer {
            match record.rdata.parse() {
                Ok(ParsedRecord::A(v4)) => {
                    let ttl = match ttl_cap {
                        Some(cap) => record.ttl.min(cap),
                        None => record.ttl,
                    };
                    let Ok(rdata) =
                        RecordData::from_parsed(&ParsedRecord::AAAA(self.prefix.embed(v4)))
                    else {
                        continue;
                    };
                    out.push(ResourceRecord {
                        name: record.name.clone(),
                        class: record.class,
                        ttl,
                        rdata,
                    });
                }
                Ok(ParsedRecord::CNAME(_)) => out.push(record.clone()),
                _ => {}
            }
        }
        out
    }

    /// The `in-addr.arpa` name a reverse query under `ip6.arpa` is really about
    /// (RFC 6147 §5.3.1), or `None` if the address is not one of ours.
    ///
    /// §5.3.1 offers two ways to answer such a query; this is the second, "a
    /// CNAME mapping the ip6.arpa namespace to the corresponding in-addr.arpa
    /// name", because the first means inventing PTR data for a translator the
    /// resolver knows nothing about.
    pub fn reverse_target(&self, qname: NameRef<'_>) -> Option<Name> {
        let v6 = address_in_ip6_arpa(qname)?;
        let v4 = self.prefix.extract(v6)?;
        let [a, b, c, d] = v4.octets();
        Name::from_presentation(&format!("{d}.{c}.{b}.{a}.in-addr.arpa.")).ok()
    }
}

/// The address a name under `ip6.arpa` describes: 32 nibbles, least significant
/// first (RFC 3596 §2.5).
///
/// `None` for anything else, a name with the right suffix and the wrong shape
/// included — an attacker picks the QNAME, and 32 labels of hex is a claim to
/// check rather than a format to trust (`CLAUDE.md` §2).
fn address_in_ip6_arpa(qname: NameRef<'_>) -> Option<Ipv6Addr> {
    let labels: Vec<&[u8]> = qname.labels().collect();
    if labels.len() != 34 {
        return None;
    }
    if !labels[32].eq_ignore_ascii_case(b"ip6") || !labels[33].eq_ignore_ascii_case(b"arpa") {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, octet) in octets.iter_mut().enumerate() {
        // Nibbles run least significant first, so octet i is at labels
        // [31 - 2i] (high) and [30 - 2i] (low).
        let high = nibble(labels[31 - 2 * i])?;
        let low = nibble(labels[30 - 2 * i])?;
        *octet = (high << 4) | low;
    }
    Some(Ipv6Addr::from(octets))
}

/// One hexadecimal digit as a label.
fn nibble(label: &[u8]) -> Option<u8> {
    match label {
        [digit] => (*digit as char).to_digit(16).map(|d| d as u8),
        _ => None,
    }
}

/// The type a DNS64 resolver asks for when it has no AAAA: A, because that is
/// the record it can turn into one.
pub const SYNTHESIS_SOURCE: crate::Rtype = rt::A;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_records::nm;
    use crate::Class;

    /// RFC 6052 §2.4's own table, which is the one input the specification has
    /// already committed to an answer for.
    #[test]
    fn rfc_6052_section_2_4s_table() {
        let cases = [
            ("2001:db8::/32", "2001:db8:c000:221::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::"),
            ("2001:db8:122:344::/96", "2001:db8:122:344::192.0.2.33"),
            ("64:ff9b::/96", "64:ff9b::192.0.2.33"),
        ];
        let v4: Ipv4Addr = "192.0.2.33".parse().unwrap();
        for (spec, expected) in cases {
            let prefix = Nat64Prefix::parse(spec).unwrap_or_else(|e| panic!("{spec}: {e}"));
            let expected: Ipv6Addr = expected.parse().unwrap();
            assert_eq!(prefix.embed(v4), expected, "{spec}");
            assert_eq!(
                prefix.extract(expected),
                Some(v4),
                "{spec} round-trips back out"
            );
        }
    }

    #[test]
    fn a_prefix_length_the_format_has_no_room_for_is_refused() {
        for spec in ["64:ff9b::/97", "64:ff9b::/95", "2001:db8::/0", "64:ff9b::"] {
            assert!(Nat64Prefix::parse(spec).is_err(), "{spec}");
        }
    }

    /// Bits past the prefix would be overwritten by the address, so a prefix
    /// carrying any is a typo rather than a longer prefix.
    #[test]
    fn a_prefix_with_bits_past_its_length_is_refused() {
        assert!(Nat64Prefix::parse("2001:db8::1/32").is_err());
    }

    /// RFC 6052 §2.2: bits 64-71 are reserved and zero, so an address with
    /// something there is not an IPv4-embedded address at all.
    #[test]
    fn the_reserved_octet_must_be_zero_to_extract() {
        let prefix = Nat64Prefix::parse("2001:db8:122:344::/64").unwrap();
        let good: Ipv6Addr = "2001:db8:122:344:c0:2:2100::".parse().unwrap();
        assert!(prefix.extract(good).is_some());
        let reserved_set: Ipv6Addr = "2001:db8:122:344:ffc0:2:2100::".parse().unwrap();
        assert_eq!(prefix.extract(reserved_set), None);
    }

    #[test]
    fn an_address_outside_the_prefix_is_not_ours() {
        let prefix = Nat64Prefix::well_known();
        assert_eq!(prefix.extract("2001:db8::1".parse().unwrap()), None);
    }

    fn a(name: &str, addr: &str, ttl: u32) -> ResourceRecord {
        ResourceRecord {
            name: nm(name),
            class: Class::new(1),
            ttl: Ttl::from_secs(ttl),
            rdata: RecordData::from_parsed(&ParsedRecord::A(addr.parse().unwrap())).unwrap(),
        }
    }

    fn aaaa(name: &str, addr: &str) -> ResourceRecord {
        ResourceRecord {
            name: nm(name),
            class: Class::new(1),
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::AAAA(addr.parse().unwrap())).unwrap(),
        }
    }

    /// The 32 hex digits of an address as `ip6.arpa` labels: one per label,
    /// least significant first (RFC 3596 §2.5).
    fn reversed_nibbles(hex: &str) -> String {
        assert_eq!(hex.len(), 32, "an address is 32 nibbles");
        hex.chars().rev().map(|c| format!("{c}.")).collect()
    }

    fn dns64() -> Dns64 {
        Dns64::new(Nat64Prefix::well_known(), &[]).unwrap()
    }

    #[test]
    fn an_a_answer_becomes_an_aaaa_answer_under_the_prefix() {
        let out = dns64().synthesize(&[a("www.example.com.", "192.0.2.33", 300)], None);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, nm("www.example.com."));
        assert_eq!(
            out[0].rdata.parse().unwrap(),
            ParsedRecord::AAAA("64:ff9b::192.0.2.33".parse().unwrap())
        );
        assert_eq!(out[0].ttl.as_secs(), 300);
    }

    /// RFC 6147 §5.1.7: the TTL is the lesser of the A record's and the SOA's,
    /// because the name has no AAAA and the negative answer says for how long.
    #[test]
    fn the_synthesized_ttl_is_bounded_by_the_soa() {
        let out = dns64().synthesize(
            &[a("www.example.com.", "192.0.2.33", 300)],
            Some(Ttl::from_secs(60)),
        );
        assert_eq!(out[0].ttl.as_secs(), 60);
        let out = dns64().synthesize(
            &[a("www.example.com.", "192.0.2.33", 30)],
            Some(Ttl::from_secs(60)),
        );
        assert_eq!(out[0].ttl.as_secs(), 30, "and the lesser is the A record's");
    }

    /// §5.1.5: the chain is followed to the terminating A, so the CNAMEs that
    /// led there stay in the answer — a client that got an AAAA for a name it
    /// did not ask about has an answer it cannot match.
    #[test]
    fn a_cname_chain_is_kept_and_the_rest_is_dropped() {
        let chain = vec![
            ResourceRecord {
                name: nm("www.example.com."),
                class: Class::new(1),
                ttl: Ttl::from_secs(300),
                rdata: RecordData::from_parsed(&ParsedRecord::CNAME(nm("host.example.net.")))
                    .unwrap(),
            },
            a("host.example.net.", "192.0.2.33", 300),
        ];
        let out = dns64().synthesize(&chain, None);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].rdata.rtype(), rt::CNAME);
        assert_eq!(out[1].name, nm("host.example.net."));
    }

    /// §5.1.4: an answer of nothing but IPv4-mapped addresses leaves an
    /// IPv6-only client no better off, so it is an empty answer.
    #[test]
    fn a_mapped_address_is_no_answer_at_all() {
        let d = dns64();
        assert!(!d.answered(&[aaaa("www.example.com.", "::ffff:192.0.2.33")]));
        assert!(d.answered(&[aaaa("www.example.com.", "2001:db8::1")]));
        assert!(
            d.answered(&[
                aaaa("www.example.com.", "::ffff:192.0.2.33"),
                aaaa("www.example.com.", "2001:db8::1"),
            ]),
            "one usable address is an answer"
        );
        assert!(!d.answered(&[]));
    }

    #[test]
    fn an_operators_exclusion_is_added_to_the_default_and_not_instead_of_it() {
        let d = Dns64::new(Nat64Prefix::well_known(), &["2001:db8::/32".to_string()]).unwrap();
        assert!(!d.answered(&[aaaa("www.example.com.", "2001:db8::1")]));
        assert!(
            !d.answered(&[aaaa("www.example.com.", "::ffff:192.0.2.33")]),
            "§5.1.4's own range is still excluded"
        );
    }

    /// RFC 6147 §5.3.1: a PTR under `ip6.arpa` for an address in our prefix is
    /// really a question about the IPv4 address inside it.
    #[test]
    fn a_reverse_query_in_the_prefix_maps_to_in_addr_arpa() {
        let d = dns64();
        // 64:ff9b::192.0.2.33 is 0064:ff9b:0:0:0:0:c000:0221, and RFC 3596 §2.5
        // writes it one nibble per label, least significant first.
        let qname = nm(&format!(
            "{}ip6.arpa.",
            reversed_nibbles("0064ff9b0000000000000000c0000221")
        ));
        assert_eq!(
            d.reverse_target(qname.as_ref()),
            Some(nm("33.2.0.192.in-addr.arpa."))
        );
    }

    #[test]
    fn a_reverse_query_outside_the_prefix_is_not_ours() {
        let d = dns64();
        let qname = nm(&format!(
            "{}ip6.arpa.",
            reversed_nibbles("20010db8000000000000000000000001")
        ));
        assert_eq!(d.reverse_target(qname.as_ref()), None);
        assert_eq!(d.reverse_target(nm("example.com.").as_ref()), None);
        assert_eq!(d.reverse_target(nm("1.2.3.ip6.arpa.").as_ref()), None);
    }
}
