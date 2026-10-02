//! The address blocks a per-client limit counts as one client.
//!
//! `CONTEXT.md` defines both. A **source** is what the query limiter and the
//! query logger count; a **response target** is what a response budget is
//! charged to. Both are built from a peer address and from nothing else, and
//! neither can be built from the other's mask, so a map keyed on one cannot be
//! probed with the other or with a raw [`IpAddr`] (`CLAUDE.md` §17).
//!
//! Keyed on the exact address, an IPv6 host rotating within the /64 it
//! normally holds was a new client to every limiter on every query (`TODO.md`
//! #157): the query limit never bound it, a response budget multiplied by
//! every address spoofed, and past `max_tracked` the query limiter admitted
//! every new address without a bucket.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The IPv6 block both groupings use: BIND's `ipv6-prefix-length` default.
/// A /64 is what one host or one LAN normally holds; a /56 is a common
/// end-site assignment, so rotating inside it gains nothing.
const IPV6_PREFIX: u8 = 56;

/// A source's IPv4 block: the address itself. Over the query budget a query
/// is dropped, so a coarser block silences the innocent neighbours behind
/// shared hosting or carrier NAT along with the flood.
const SOURCE_IPV4_PREFIX: u8 = 32;

/// A response target's IPv4 block: BIND's `ipv4-prefix-length` default. Over
/// the response budget a reply is truncated or slipped and a real client
/// retries over TCP, while a spoofer spreading over a victim's /24 would get
/// 256 budgets at the exact address.
const RESPONSE_TARGET_IPV4_PREFIX: u8 = 24;

/// The block of `peer` at the given prefix lengths.
///
/// An IPv4-mapped IPv6 address is its IPv4 address first: on a dual-stack
/// socket every IPv4 client arrives as `::ffff:a.b.c.d`, and the /56 of
/// `::ffff:0:0/96` would make the whole IPv4 internet one block. `TODO.md`
/// #158 moves this into the one type peers are read as, and deletes it here.
fn block(peer: IpAddr, v4: u8, v6: u8) -> IpAddr {
    match peer.to_canonical() {
        IpAddr::V4(a) => {
            let mask = u32::MAX.checked_shl(u32::from(32 - v4)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX.checked_shl(u32::from(128 - v6)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
    }
}

fn write_block(f: &mut fmt::Formatter<'_>, addr: IpAddr, v4: u8, v6: u8) -> fmt::Result {
    match addr {
        IpAddr::V4(a) if v4 == 32 => write!(f, "{a}"),
        IpAddr::V4(a) => write!(f, "{a}/{v4}"),
        IpAddr::V6(a) => write!(f, "{a}/{v6}"),
    }
}

/// What a per-client query limit counts as one client: an IPv4 address or an
/// IPv6 /56 of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Source(IpAddr);

impl Source {
    pub fn of(peer: IpAddr) -> Source {
        Source(block(peer, SOURCE_IPV4_PREFIX, IPV6_PREFIX))
    }
}

/// A bare IPv4 address, or an IPv6 /56 in prefix notation.
impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_block(f, self.0, SOURCE_IPV4_PREFIX, IPV6_PREFIX)
    }
}

/// What a response budget is charged to: an IPv4 /24 or an IPv6 /56 of a
/// peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResponseTarget(IpAddr);

impl ResponseTarget {
    pub fn of(peer: IpAddr) -> ResponseTarget {
        ResponseTarget(block(peer, RESPONSE_TARGET_IPV4_PREFIX, IPV6_PREFIX))
    }
}

impl fmt::Display for ResponseTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_block(f, self.0, RESPONSE_TARGET_IPV4_PREFIX, IPV6_PREFIX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("an address")
    }

    #[test]
    fn a_source_is_the_ipv4_address_or_the_ipv6_slash_56() {
        assert_ne!(Source::of(ip("192.0.2.1")), Source::of(ip("192.0.2.2")));
        assert_eq!(
            Source::of(ip("2001:db8:0:1::1")),
            Source::of(ip("2001:db8:0:ff:abcd::9"))
        );
        assert_ne!(
            Source::of(ip("2001:db8:0:100::1")),
            Source::of(ip("2001:db8:0:200::1"))
        );
        assert_eq!(Source::of(ip("192.0.2.1")).to_string(), "192.0.2.1");
        assert_eq!(
            Source::of(ip("2001:db8:0:1::1")).to_string(),
            "2001:db8::/56"
        );
    }

    #[test]
    fn a_response_target_is_the_ipv4_slash_24_or_the_ipv6_slash_56() {
        assert_eq!(
            ResponseTarget::of(ip("192.0.2.1")),
            ResponseTarget::of(ip("192.0.2.254"))
        );
        assert_ne!(
            ResponseTarget::of(ip("192.0.2.1")),
            ResponseTarget::of(ip("192.0.3.1"))
        );
        assert_eq!(
            ResponseTarget::of(ip("2001:db8:0:1::1")),
            ResponseTarget::of(ip("2001:db8:0:2::1"))
        );
        assert_eq!(
            ResponseTarget::of(ip("192.0.2.77")).to_string(),
            "192.0.2.0/24"
        );
    }

    /// `::ffff:0:0/96`'s /56 is every IPv4 address there is.
    #[test]
    fn a_mapped_peer_is_its_ipv4_address() {
        assert_eq!(
            Source::of(ip("::ffff:192.0.2.1")),
            Source::of(ip("192.0.2.1"))
        );
        assert_ne!(
            Source::of(ip("::ffff:192.0.2.1")),
            Source::of(ip("::ffff:198.51.100.1"))
        );
        assert_ne!(
            ResponseTarget::of(ip("::ffff:192.0.2.1")),
            ResponseTarget::of(ip("::ffff:198.51.100.1"))
        );
    }
}
