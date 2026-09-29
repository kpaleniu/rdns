//! One query to one server, and the only place the resolver touches a socket.
//!
//! What to send and what to accept stay in the resolver: reply matching
//! (RFC 5452 §9.1), 0x20, the TC→TCP retry (RFC 1035 §4.2.1). An [`Upstream`]
//! carries bytes and reports silence, so a test that swaps it still runs all of
//! that (`TODO.md` #136).

use super::*;
use std::future::Future;
use std::pin::Pin;

/// What one upstream answer is read into, whatever this resolver advertised.
///
/// Not [`ResolverConfig::udp_payload_size`], which is what we told the server we
/// could reassemble: the two were one number until `TODO.md` #41c, so lowering
/// the advertisement to DNS Flag Day's 1232 would also have narrowed the
/// doorway a server that ignores the advertisement has to fit through — and a
/// datagram larger than the buffer is not truncated into a parse error, it is
/// lost, since the receive itself fails on Windows (WSAEMSGSIZE) and silently
/// drops the tail elsewhere.
///
/// Why not 65,535, which is Unbound's `msg-buffer-size` ("Default is 65552
/// bytes, enough for 64 Kb packets, the maximum DNS message size") and the size
/// a peer could in principle send: one of these exists per query in flight, and
/// `rdnsr`'s `--max-inflight-udp` allows 1024 of those. At 64 KiB that ceiling
/// costs 64 MB rather than the ~1.5 MB its own documentation claims — the
/// multiplier is the point (`CLAUDE.md` §5), and Unbound reuses one buffer per
/// thread where this allocates per query. 4,096 is what the coupled number was
/// before #41 lowered the advertisement, so nothing this resolver could read
/// yesterday is unreadable today; it is three times the advertisement, which is
/// the slack a non-conforming server gets.
const UPSTREAM_RECEIVE_BUFFER: usize = 4096;

/// Which transport one exchange goes over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// Answers in place of the network: the server asked, the transport and the
/// query's wire bytes in; the reply's bytes out, or `None` for silence.
///
/// A future so that an answer can take time — a sleep under a paused tokio
/// clock is how a test makes one server slower than another (`TODO.md` #137).
pub type Answering = dyn Fn(SocketAddr, Transport, &[u8]) -> Reply + Send + Sync;

/// What an [`Answering`] upstream hands back.
pub type Reply = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send>>;

/// Where a [`Resolver`]'s queries go.
///
/// An enum rather than a trait, for [`Clock`]'s reason: production holds
/// [`Upstream::Network`] and nothing else, so the ordinary path stays a branch
/// and a direct call rather than a boxed future per exchange.
#[derive(Clone, Default)]
pub enum Upstream {
    /// A socket per exchange.
    #[default]
    Network,
    /// A function, for a test that wants a hierarchy without binding one.
    /// Glue carries no port, so a table keyed by address stands in where
    /// loopback servers needed one shared unprivileged port.
    Answering(Arc<Answering>),
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Upstream::Network => f.write_str("Network"),
            Upstream::Answering(_) => f.write_str("Answering"),
        }
    }
}

impl Upstream {
    /// Answers at once.
    pub fn answering(
        answer: impl Fn(SocketAddr, Transport, &[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) -> Upstream {
        Upstream::Answering(Arc::new(move |server, transport, query| {
            Box::pin(std::future::ready(answer(server, transport, query)))
        }))
    }

    /// Answers when the returned future does, or is silent past the timeout.
    pub fn answering_later<F>(
        answer: impl Fn(SocketAddr, Transport, &[u8]) -> F + Send + Sync + 'static,
    ) -> Upstream
    where
        F: Future<Output = Option<Vec<u8>>> + Send + 'static,
    {
        Upstream::Answering(Arc::new(move |server, transport, query| {
            Box::pin(answer(server, transport, query))
        }))
    }

    /// Send `query` to `server` and return the reply's bytes. `timeout` bounds
    /// each wait on the network; silence is [`ResolveError::NoResponse`].
    pub(super) async fn exchange(
        &self,
        server: SocketAddr,
        transport: Transport,
        query: &[u8],
        timeout: Duration,
    ) -> ResolveResult<Vec<u8>> {
        match self {
            Upstream::Network => match transport {
                Transport::Udp => udp(server, query, timeout).await,
                Transport::Tcp => tcp(server, query, timeout).await,
            },
            Upstream::Answering(answer) => {
                tokio::time::timeout(timeout, answer(server, transport, query))
                    .await
                    .ok()
                    .flatten()
                    .ok_or_else(|| ResolveError::no_response(format!("{server} did not answer")))
            }
        }
    }
}

async fn udp(server: SocketAddr, query: &[u8], timeout: Duration) -> ResolveResult<Vec<u8>> {
    // Connected: the socket then drops datagrams from any other source, the
    // cheap half of off-path resistance; the id and the question are the rest.
    let socket = UdpSocket::bind(bind_addr_for(server)).await?;
    socket.connect(server).await?;
    socket.send(query).await?;

    let mut buf = vec![0; UPSTREAM_RECEIVE_BUFFER];
    // tokio's UdpSocket has no read timeout of its own.
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf)).await??;
    buf.truncate(n);
    Ok(buf)
}

/// Length-prefixed (RFC 1035 §4.2.2). `timeout` applies to each of connect,
/// write and read.
async fn tcp(server: SocketAddr, query: &[u8], timeout: Duration) -> ResolveResult<Vec<u8>> {
    if query.len() > TCP_MAX_MESSAGE {
        return Err(ResolveError::no_response(format!(
            "query of {} bytes exceeds the 2-byte TCP length prefix",
            query.len()
        )));
    }
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(server)).await??;

    // One write so prefix and message share a segment. The length is checked
    // rather than cast: a wrapped prefix reads as a broken stream.
    let framed = crate::framed(query)?;
    tokio::time::timeout(timeout, stream.write_all(&framed)).await??;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf)).await??;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(ResolveError::no_response(format!(
            "upstream {server} sent a zero-length TCP message"
        )));
    }

    let mut buf = vec![0; len];
    tokio::time::timeout(timeout, stream.read_exact(&mut buf)).await??;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply from any address but the one asked is not read: the socket is
    /// connected, so the kernel drops it and the wait runs out. Nothing else in
    /// this crate checks the source — `answers_query` sees only the message.
    #[tokio::test]
    async fn a_reply_from_another_address_is_not_read() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let other = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let replier = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            other.send_to(&buf[..n], peer).unwrap();
        });

        let got = Upstream::Network
            .exchange(addr, Transport::Udp, b"query", Duration::from_millis(300))
            .await;
        replier.join().unwrap();
        assert!(matches!(got, Err(ResolveError::NoResponse(_))), "{got:?}");
    }
}
