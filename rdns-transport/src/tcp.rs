//! DNS over TCP: accept, frame, admit, hand to a handler.
//!
//! Both daemons had written this loop, 21 identical lines in the middle of it
//! (`TODO.md` #30a). What differs between them is the *answering*, which is why
//! the handler is a trait and the loop is not: `rdnsd` sends a sequence of
//! envelopes for an AXFR (RFC 5936 §2.2) and `rdnsr` sends one reply, so the
//! shape that fits both is a sink. `domain` shipped both a `Service` that may
//! emit several responses and a `SingleService` for one rather than choosing;
//! here the sink is the only shape, and a single-reply handler sends once.
//!
//! The UDP loops stay two and are not here. `rdnsd` answers inline on a fixed
//! worker pool with a reused buffer and compressor — #27b measured the
//! alternative at 1 536 bytes per datagram — and `rdnsr` spawns per datagram
//! because a recursion is seconds long and almost all of it waiting. Unifying
//! that loop loses both reasons at once.

use std::net::SocketAddr;
use std::sync::Arc;

use rdns::shutdown::{Busy, Stop};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};

use crate::{ServeContext, Transport, TransportLimits};

/// What a connection's writer task can be handed.
///
/// A transfer is answered one envelope at a time, so a failure can happen with
/// part of the answer already on the wire, where an error response would be
/// read as another envelope.
pub enum Reply {
    /// One length-prefixed message, to be written.
    Frame(Vec<u8>),
    /// Stop writing and close the connection.
    ///
    /// A transfer is complete at its closing SOA (RFC 5936 §2.2), so a stream
    /// that ends first is one the client must discard. Closing says so at once;
    /// falling silent leaves it waiting out a timeout.
    Abort,
}

/// Frame `bytes` (RFC 1035 §4.2.2) and hand them to the writer. `false` if the
/// connection is gone.
///
/// Prefix and message in one buffer, so the writer emits them in a single call.
/// A reply too long to frame is dropped rather than sent with a wrapped prefix,
/// which the peer would read as a broken stream — that wrap was #17.
pub async fn send_framed(out: &mpsc::Sender<Reply>, bytes: &[u8]) -> bool {
    match rdns::framed(bytes) {
        Ok(framed) => out.send(Reply::Frame(framed)).await.is_ok(),
        Err(e) => {
            // ERROR, not DEBUG: a client got no answer at all.
            tracing::error!("could not frame a {}-octet reply: {e}", bytes.len());
            false
        }
    }
}

/// What answers a message that has been admitted.
///
/// Sink-shaped on purpose: see the module docs. `now` is the transport's single
/// clock read for this message, passed down rather than taken again — `rdnsd`
/// wants one instant for the limiter, the query log and the TSIG check
/// (`TODO.md` #28a).
pub trait Handler: Send + Sync + 'static {
    /// The limiter, validator, logger and metrics this handler serves under.
    /// The transport admits messages through it, so it must be the same one the
    /// handler answers with.
    fn context(&self) -> &ServeContext;

    fn handle(
        &self,
        packet: Vec<u8>,
        peer: SocketAddr,
        now: u64,
        out: mpsc::Sender<Reply>,
    ) -> impl std::future::Future<Output = ()> + Send;
}

/// Where the query rate applies on TCP.
///
/// The two daemons disagree and both are defensible, so the shared loop is told
/// rather than deciding (`TODO.md` #30e): a resolver's clients open a connection
/// and ask a few things, an authoritative server's are resolvers that pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimit {
    /// One token per connection accepted.
    PerConnection,
    /// One token per message, whatever it arrived on.
    PerMessage,
}

/// Accept connections and serve each in its own task, until told to stop.
///
/// Bounded by [`TransportLimits::max_connections`]: without a ceiling, an accept
/// loop that spawns per connection is a free file-descriptor exhaustion vector.
pub async fn serve<H: Handler>(
    listener: TcpListener,
    handler: Arc<H>,
    limits: TransportLimits,
    rate: RateLimit,
    stop: Stop,
    busy: Busy,
) -> Result<(), std::io::Error> {
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        // Stop accepting on shutdown; open connections drain in their own tasks.
        // `accept` is cancel-safe, so a connection lost to this race stays in
        // the kernel's backlog.
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = stop.wait() => return Ok(()),
        };
        if rate == RateLimit::PerConnection
            && !handler
                .context()
                .allow_source(peer.ip(), rdns::utils::current_unix_timestamp())
        {
            continue;
        }
        // Back-pressure on accept rather than unbounded spawning. The semaphore
        // is never closed, so this only fails if we drop it.
        let Ok(permit) = permits.clone().acquire_owned().await else {
            continue;
        };
        let handler = handler.clone();
        let stop = stop.clone();
        // Claim the drain for the connection's life: a client cannot tell a
        // truncated AXFR from a complete one.
        let busy = busy.clone();
        tokio::spawn(async move {
            serve_one(stream, peer, handler, limits, rate, stop).await;
            drop(permit);
            drop(busy);
        });
    }
}

/// Serve one already-accepted connection until it goes idle, closes, or
/// misbehaves.
///
/// Messages on one connection are answered concurrently, so a slow one does not
/// stall those behind it (RFC 7766 §6.2.1.1). On shutdown, reading stops but
/// messages already accepted finish and reach the wire.
///
/// Public because a caller with its own accept loop — a test driving one
/// connection, say — wants exactly this and not the listener.
pub async fn serve_one<H: Handler>(
    stream: TcpStream,
    peer: SocketAddr,
    handler: Arc<H>,
    limits: TransportLimits,
    rate: RateLimit,
    stop: Stop,
) {
    let (mut reader, mut writer) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<Reply>(limits.max_inflight_per_connection);

    // One task owns the write half: replies may complete out of order
    // (RFC 7766 §6.2.1.1; clients match on the transaction id), but two framed
    // messages must never interleave on the wire.
    let writer_logger = handler.context().logger.clone();
    let writer_task = tokio::spawn(async move {
        while let Some(reply) = rx.recv().await {
            let Reply::Frame(framed) = reply else {
                // `Reply::Abort`: dropping the write half tells the peer its
                // half-finished transfer will not be completed.
                break;
            };
            if let Err(e) = writer.write_all(&framed).await {
                writer_logger.count_error(peer.ip());
                tracing::debug!(peer = %peer.ip(), "socket write error: {e}");
                break;
            }
        }
    });

    let in_flight = Arc::new(Semaphore::new(limits.max_inflight_per_connection));

    loop {
        // A 2-byte big-endian length prefix frames each message
        // (RFC 1035 §4.2.2); a single `read` can be short or coalesced. Idle
        // between messages is ordinary, so a timeout here ends the connection
        // like EOF. The shutdown check sits here because the peer has committed
        // to nothing yet: `read_exact` is not cancel-safe, but a lost length
        // prefix on a connection we are closing costs nothing.
        let mut len_buf = [0u8; 2];
        let read = tokio::select! {
            r = tokio::time::timeout(limits.idle_timeout, reader.read_exact(&mut len_buf)) => r,
            _ = stop.wait() => break,
        };
        match read {
            Ok(Ok(_)) => {}
            _ => break,
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            handler.context().logger.count_error(peer.ip());
            tracing::debug!(peer = %peer.ip(), "zero-length TCP message");
            break;
        }

        // Mid-message the peer has committed to sending `len` bytes, so a stall
        // here gets a much shorter leash than an idle connection.
        let mut packet = vec![0u8; len];
        match tokio::time::timeout(limits.read_timeout, reader.read_exact(&mut packet)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                handler.context().logger.count_error(peer.ip());
                tracing::debug!(peer = %peer.ip(), "socket read error: {e}");
                break;
            }
            Err(_) => {
                handler.context().logger.count_error(peer.ip());
                tracing::debug!(peer = %peer.ip(), "timed out mid-message on TCP");
                break;
            }
        }

        // Admission before the spawn, not inside it (`CLAUDE.md` §9): paying a
        // task and two `Arc` clones before deciding to drop the message is
        // backwards. One clock read for the message, handed to the handler so
        // the limiter, the log and a TSIG check all name the same instant.
        let now = rdns::utils::current_unix_timestamp();
        if rate == RateLimit::PerMessage && !handler.context().allow_source(peer.ip(), now) {
            continue;
        }
        // The message is skipped, not the connection: a peer that framed it
        // correctly is still speaking the protocol.
        if !handler
            .context()
            .accept_packet(peer.ip(), &packet, Transport::Tcp)
        {
            continue;
        }

        // Cap in-flight work per connection: this await is what stops a
        // pipelining client from spawning tasks faster than we retire them.
        let Ok(permit) = in_flight.clone().acquire_owned().await else {
            break;
        };
        let handler = handler.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            handler.handle(packet, peer, now, tx).await;
            drop(permit);
        });
    }

    // Dropping our sender lets the writer drain what is still in flight — the
    // clones held by running tasks keep the channel open — and then exit.
    drop(tx);
    let _ = writer_task.await;
}
