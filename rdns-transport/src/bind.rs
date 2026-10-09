//! Every listener's bind, so `::` means the same on every platform
//! (`docs/adr/0006`, `TODO.md` #159).
//!
//! An IPv6 wildcard bind took the OS default for `IPV6_V6ONLY`: 0 on Linux,
//! so `--host ::` served IPv4 too, and 1 on Windows, so it did not, with
//! nothing saying which. Every listener binds here and the option is set to 0
//! on every IPv6 socket; a specific IPv6 address cannot receive IPv4 anyway,
//! so it is the IPv6-only choice. The rest is what std's `bind` does, so a
//! listener behaves as it did: `SO_REUSEADDR` on a Unix stream socket, a
//! backlog of 128.
//!
//! Outbound sockets do not come here: `bind_addr_for` binds `[::]:0` only to
//! reach an IPv6 target.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};

use socket2::{Domain, Socket, Type};

/// std's listen backlog everywhere this builds.
const BACKLOG: i32 = 128;

/// Which address families a bound listener serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Families {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl Families {
    /// What a socket at `addr` serves once its `IPV6_V6ONLY` reads `only_v6`.
    fn at(addr: SocketAddr, only_v6: bool) -> Families {
        match addr.ip() {
            IpAddr::V4(_) => Families {
                ipv4: true,
                ipv6: false,
            },
            IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => Families {
                ipv4: true,
                ipv6: false,
            },
            IpAddr::V6(ip) => Families {
                ipv4: ip.is_unspecified() && !only_v6,
                ipv6: true,
            },
        }
    }
}

impl fmt::Display for Families {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match (self.ipv4, self.ipv6) {
            (true, true) => "IPv4 and IPv6",
            (true, false) => "IPv4",
            (false, true) => "IPv6",
            (false, false) => "no address family",
        })
    }
}

/// A bound listener, where it is, and what it serves — read from the socket,
/// not assumed from the request.
pub struct Bound<S> {
    pub socket: S,
    pub local: SocketAddr,
    pub families: Families,
}

impl<S> Bound<S> {
    /// `[::]:53 (IPv4 and IPv6)`, for a startup line.
    pub fn describe(&self) -> String {
        format!("{} ({})", self.local, self.families)
    }

    fn map<T>(self, f: impl FnOnce(S) -> T) -> Bound<T> {
        Bound {
            socket: f(self.socket),
            local: self.local,
            families: self.families,
        }
    }
}

/// What `addr` will serve once bound here, for `--check-config`, which exits
/// before anything binds. `None` for a name rather than an address: what it
/// resolves to is decided at the bind.
pub fn planned(addr: &str) -> Option<String> {
    let parsed = literal(addr)?;
    Some(format!("{parsed} ({})", Families::at(parsed, false)))
}

/// `addr` as an address and port, without a lookup.
///
/// `ToSocketAddrs` accepts `:::53` — host `::`, port 53 — which is what
/// `format!("{host}:{port}")` makes of `--host ::`, so this does too.
fn literal(addr: &str) -> Option<SocketAddr> {
    if let Ok(parsed) = addr.parse() {
        return Some(parsed);
    }
    let (host, port) = addr.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Some(SocketAddr::new(host.parse().ok()?, port.parse().ok()?))
}

fn bind_one(addr: SocketAddr, kind: Type) -> io::Result<Bound<Socket>> {
    let socket = Socket::new(Domain::for_address(addr), kind, None)?;
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    // std's reason: on Windows SO_REUSEADDR lets a second process take the
    // port, which is not what it means on Unix.
    #[cfg(not(windows))]
    if kind == Type::STREAM {
        socket.set_reuse_address(true)?;
    }
    socket.bind(&addr.into())?;
    if kind == Type::STREAM {
        socket.listen(BACKLOG)?;
    }
    socket.set_nonblocking(true)?;
    let local = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("bound to something that is not an IP address"))?;
    let only_v6 = local.is_ipv6() && socket.only_v6()?;
    Ok(Bound {
        local,
        families: Families::at(local, only_v6),
        socket,
    })
}

/// Each address `addr` resolves to in turn, as std's `bind` does, and the
/// last error if none binds.
fn bind_first(
    addrs: impl IntoIterator<Item = SocketAddr>,
    kind: Type,
) -> io::Result<Bound<Socket>> {
    let mut last = None;
    for addr in addrs {
        match bind_one(addr, kind) {
            Ok(bound) => return Ok(bound),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the address resolved to nothing",
        )
    }))
}

pub async fn udp(addr: &str) -> io::Result<Bound<tokio::net::UdpSocket>> {
    let bound = bind_first(tokio::net::lookup_host(addr).await?, Type::DGRAM)?;
    let bound = bound.map(std::net::UdpSocket::from);
    Ok(Bound {
        socket: tokio::net::UdpSocket::from_std(bound.socket)?,
        local: bound.local,
        families: bound.families,
    })
}

pub async fn tcp(addr: &str) -> io::Result<Bound<tokio::net::TcpListener>> {
    let bound = bind_first(tokio::net::lookup_host(addr).await?, Type::STREAM)?;
    let bound = bound.map(std::net::TcpListener::from);
    Ok(Bound {
        socket: tokio::net::TcpListener::from_std(bound.socket)?,
        local: bound.local,
        families: bound.families,
    })
}

/// Whether every address `addr` names is loopback: `127.0.0.0/8` or `::1`.
///
/// Every address and not the first, which is the one a bind takes: a name
/// that resolves to loopback and something else is not a promise about which
/// the bind will get. The wildcards are not loopback — they are every
/// interface.
pub async fn loopback_only(addr: &str) -> io::Result<bool> {
    let mut any = false;
    for resolved in tokio::net::lookup_host(addr).await? {
        if !resolved.ip().to_canonical().is_loopback() {
            return Ok(false);
        }
        any = true;
    }
    Ok(any)
}

/// A std socket, for quinn, which wraps its own.
pub fn udp_std(addr: SocketAddr) -> io::Result<Bound<std::net::UdpSocket>> {
    Ok(bind_one(addr, Type::DGRAM)?.map(std::net::UdpSocket::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `::` serves an IPv4 client over UDP and over TCP, on either platform.
    /// Fails on Windows if `IPV6_V6ONLY` is left at its default, which refuses
    /// both (`TODO.md` #159).
    #[tokio::test]
    async fn the_ipv6_wildcard_serves_ipv4_clients() {
        let udp = udp("[::]:0").await.expect("bind udp");
        let tcp = tcp("[::]:0").await.expect("bind tcp");
        for bound in [udp.families, tcp.families] {
            assert_eq!(
                bound,
                Families {
                    ipv4: true,
                    ipv6: true
                }
            );
        }
        assert_eq!(
            udp.describe(),
            format!("[::]:{} (IPv4 and IPv6)", udp.local.port())
        );

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("client");
        client
            .send_to(
                b"ping",
                SocketAddr::from(([127, 0, 0, 1], udp.local.port())),
            )
            .await
            .expect("send");
        let mut buf = [0u8; 8];
        let (n, from) = udp.socket.recv_from(&mut buf).await.expect("received");
        assert_eq!(&buf[..n], b"ping");
        udp.socket.send_to(b"pong", from).await.expect("reply");
        let (n, _) = client.recv_from(&mut buf).await.expect("the reply");
        assert_eq!(&buf[..n], b"pong");

        let connect =
            tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], tcp.local.port())));
        let (connected, accepted) = tokio::join!(connect, tcp.socket.accept());
        connected.expect("an IPv4 client connects");
        let (_, peer) = accepted.expect("and is accepted");
        assert_eq!(
            rdns::peer::canonical(peer).ip(),
            IpAddr::from([127, 0, 0, 1])
        );
    }

    #[tokio::test]
    async fn a_specific_address_serves_its_own_family() {
        assert_eq!(
            udp("127.0.0.1:0").await.expect("bind").families.to_string(),
            "IPv4"
        );
        // `::1` may be absent on a host with IPv6 off; the claim is about what
        // a bound one serves.
        if let Ok(bound) = tcp("[::1]:0").await {
            assert_eq!(bound.families.to_string(), "IPv6");
        }
    }

    #[test]
    fn the_dry_run_names_what_the_bind_will_serve() {
        assert_eq!(planned(":::53").as_deref(), Some("[::]:53 (IPv4 and IPv6)"));
        assert_eq!(planned("0.0.0.0:53").as_deref(), Some("0.0.0.0:53 (IPv4)"));
        assert_eq!(
            planned("[2001:db8::1]:53").as_deref(),
            Some("[2001:db8::1]:53 (IPv6)")
        );
        assert_eq!(planned("localhost:53"), None);
    }

    #[tokio::test]
    async fn only_loopback_is_loopback() {
        for addr in [
            "127.0.0.1:53",
            "127.9.9.9:53",
            "[::1]:53",
            "[::ffff:127.0.0.1]:53",
        ] {
            assert!(loopback_only(addr).await.expect(addr), "{addr}");
        }
        for addr in [
            "0.0.0.0:53",
            ":::53",
            "[::]:53",
            "192.0.2.1:53",
            "[2001:db8::1]:53",
        ] {
            assert!(!loopback_only(addr).await.expect(addr), "{addr}");
        }
    }
}
