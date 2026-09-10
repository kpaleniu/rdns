//! Which local address to bind before talking to a peer.
//!
//! No I/O and no `tokio`: it is a question about the peer's address, which is
//! why `rdnsc`'s blocking socket, the resolver and `rdnsd` can all ask it.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// The wildcard address to bind before talking to `target`.
///
/// The family has to match: a v4 socket cannot reach a v6 peer, and binding
/// `0.0.0.0` then connecting to a v6 address fails outright. Port 0, because a
/// random source port is half of RFC 5452 §9.2's off-path resistance — the
/// other half is the id.
///
/// Pure and free of I/O, so `rdnsc`'s blocking socket and the resolver's and
/// `rdnsd`'s async ones share it; it was written out three times
/// (`TODO.md` #30p).
pub fn bind_addr_for(target: SocketAddr) -> SocketAddr {
    if target.is_ipv6() {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A socket has to be in the peer's family, and a v4-mapped v6 address is a
    /// v6 peer: binding `0.0.0.0` and connecting to `::ffff:192.0.2.1` fails.
    #[test]
    fn a_socket_binds_the_family_it_will_talk_to() {
        let v4: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:53".parse().unwrap();

        assert_eq!(bind_addr_for(v4), "0.0.0.0:0".parse().unwrap());
        assert_eq!(bind_addr_for(v6), "[::]:0".parse().unwrap());
        assert_eq!(bind_addr_for(mapped), "[::]:0".parse().unwrap());
    }
}
