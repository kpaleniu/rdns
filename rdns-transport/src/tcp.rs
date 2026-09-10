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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rdns::shutdown::Shutdown;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;
    use crate::testutil::{context, id_of, query};

    /// What the test handler does with a message it is given.
    #[derive(Clone, Copy)]
    enum Answer {
        /// Echo it back after pausing for the low octet of its id in
        /// milliseconds, so one connection can carry a slow message and a fast
        /// one.
        AfterIdMillis,
        /// Abort the connection instead of replying, as a transfer that cannot
        /// be finished does.
        Abort,
    }

    struct Echo {
        ctx: ServeContext,
        answer: Answer,
    }

    impl Echo {
        fn new(answer: Answer, rate: u32) -> Arc<Echo> {
            Arc::new(Echo {
                ctx: context(rate),
                answer,
            })
        }
    }

    impl Handler for Echo {
        fn context(&self) -> &ServeContext {
            &self.ctx
        }

        async fn handle(
            &self,
            packet: Vec<u8>,
            _peer: SocketAddr,
            _now: u64,
            out: mpsc::Sender<Reply>,
        ) {
            match self.answer {
                Answer::AfterIdMillis => {
                    let pause = u64::from(id_of(&packet) & 0xff);
                    tokio::time::sleep(Duration::from_millis(pause)).await;
                    send_framed(&out, &packet).await;
                }
                Answer::Abort => {
                    let _ = out.send(Reply::Abort).await;
                }
            }
        }
    }

    /// Connect to `listener`'s address and hand the connection to `serve_one`,
    /// which is what this module exposes for exactly this.
    async fn connected(
        handler: Arc<Echo>,
        limits: TransportLimits,
        stop: Stop,
    ) -> (TcpStream, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).await.expect("connect");
        let (server, peer) = listener.accept().await.expect("accept");
        let task = tokio::spawn(async move {
            serve_one(server, peer, handler, limits, RateLimit::PerMessage, stop).await;
        });
        (client, task)
    }

    /// One framed message off the wire, or `None` at EOF.
    async fn next_reply(client: &mut TcpStream) -> Option<Vec<u8>> {
        let mut prefix = [0u8; 2];
        client.read_exact(&mut prefix).await.ok()?;
        let mut body = vec![0u8; u16::from_be_bytes(prefix) as usize];
        client.read_exact(&mut body).await.ok()?;
        Some(body)
    }

    async fn send(client: &mut TcpStream, message: &[u8]) {
        client
            .write_all(&rdns::framed(message).expect("frames"))
            .await
            .expect("send");
    }

    /// Replies may finish out of order (RFC 7766 §6.2.1.1 — clients match on
    /// the transaction id), and must still reach the wire one whole message at
    /// a time. Both halves are the writer task's reason for existing: two
    /// handlers writing to the socket themselves would interleave, and a peer
    /// reading a length prefix out of the middle of another message has no way
    /// back.
    #[tokio::test]
    async fn replies_may_finish_out_of_order_and_never_interleave() {
        let shutdown = Shutdown::new();
        let (mut client, task) = connected(
            Echo::new(Answer::AfterIdMillis, 0),
            TransportLimits::default(),
            shutdown.stop_handle(),
        )
        .await;

        // 0x0064 pauses 100ms, 0x0001 pauses 1ms, and the slow one is asked
        // first.
        send(&mut client, &query(0x0064)).await;
        send(&mut client, &query(0x0001)).await;

        let first = next_reply(&mut client).await.expect("a reply");
        let second = next_reply(&mut client).await.expect("another");
        assert_eq!(id_of(&first), 0x0001, "the fast one did not wait");
        assert_eq!(id_of(&second), 0x0064);
        assert_eq!(first, query(0x0001), "and each message arrived whole");
        assert_eq!(second, query(0x0064));

        drop(client);
        let _ = task.await;
    }

    /// `Reply::Abort` closes the connection rather than falling silent: a
    /// transfer is complete at its closing SOA (RFC 5936 §2.2), so a stream that
    /// ends early is one the client must discard — and it can only know that if
    /// the socket closes instead of leaving it to time out.
    #[tokio::test]
    async fn an_abort_closes_the_connection_rather_than_going_quiet() {
        let shutdown = Shutdown::new();
        let (mut client, task) = connected(
            Echo::new(Answer::Abort, 0),
            TransportLimits::default(),
            shutdown.stop_handle(),
        )
        .await;

        send(&mut client, &query(0x1234)).await;
        assert!(
            next_reply(&mut client).await.is_none(),
            "the write half is dropped, so the client reads EOF"
        );

        // A real client closes on EOF; without that the read half sits out the
        // idle timeout, which is what this await would then measure.
        drop(client);
        let _ = task.await;
    }

    /// A zero-length prefix is not a message and cannot become one, so the
    /// connection ends and the peer is charged with the error. Left running, it
    /// is a loop that reads two octets and does nothing, forever.
    #[tokio::test]
    async fn a_zero_length_message_ends_the_connection_and_is_counted() {
        let shutdown = Shutdown::new();
        let handler = Echo::new(Answer::AfterIdMillis, 0);
        let logger = handler.ctx.logger.clone();
        let (mut client, task) =
            connected(handler, TransportLimits::default(), shutdown.stop_handle()).await;

        client.write_all(&[0x00, 0x00]).await.expect("send");
        assert!(next_reply(&mut client).await.is_none(), "and closes");
        let _ = task.await;

        assert_eq!(
            logger
                .take_stats(rdns::utils::current_unix_timestamp() + 60)
                .total_errors,
            1,
            "silent on the wire, so it has to be visible in the counters"
        );
    }

    /// Half of the claim in `serve_one`'s own doc comment, which is a claim to
    /// verify (`CLAUDE.md` §4): on shutdown, reading stops but a message
    /// already accepted finishes and reaches the wire. The stop lands while the
    /// handler is still sleeping, which is what makes this the in-flight case
    /// rather than a race with the reply.
    ///
    /// It is not a regression test for the epilogue that drops `tx` and awaits
    /// the writer: the handler and writer tasks are detached, so the reply
    /// arrives even if `serve_one` returns at the stop instead of breaking to
    /// it. What that epilogue is for is the *drain*, which is the test below.
    #[tokio::test]
    async fn a_stop_ends_the_reading_but_not_the_reply_already_in_flight() {
        let shutdown = Shutdown::new();
        let (mut client, task) = connected(
            Echo::new(Answer::AfterIdMillis, 0),
            TransportLimits::default(),
            shutdown.stop_handle(),
        )
        .await;

        // 200ms of handler, stopped after 20.
        send(&mut client, &query(0x00c8)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        shutdown.begin();

        let reply = next_reply(&mut client)
            .await
            .expect("the answer still comes");
        assert_eq!(id_of(&reply), 0x00c8);
        assert!(
            next_reply(&mut client).await.is_none(),
            "and then the connection closes rather than waiting for more"
        );
        let _ = task.await;
    }

    /// The drain waits for a reply still being written, which is what holding
    /// the `Busy` claim for a connection's whole life is for: a client cannot
    /// tell a truncated AXFR from a complete one, so a process that exits with
    /// one half-written has served a lie.
    ///
    /// Watched failing with `serve_one`'s stop arm returning instead of
    /// breaking to the epilogue: the connection task ended at once, its `Busy`
    /// went with it, and the drain finished ~180 ms before the reply reached
    /// the client.
    #[tokio::test]
    async fn the_drain_waits_for_a_reply_still_being_written() {
        let shutdown = Shutdown::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(serve(
            listener,
            Echo::new(Answer::AfterIdMillis, 0),
            TransportLimits::default(),
            RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let mut client = TcpStream::connect(addr).await.expect("connect");
        // 200ms of handler, stopped after 20 — so the drain has 180ms to get
        // the answer wrong in.
        send(&mut client, &query(0x00c8)).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let began = std::time::Instant::now();
        shutdown.begin();
        let waited = tokio::spawn(async move {
            let drained = shutdown.drain(Duration::from_secs(5)).await;
            assert!(drained, "within the budget, not by timing out");
            began.elapsed()
        });

        let reply = next_reply(&mut client).await.expect("the answer");
        assert_eq!(id_of(&reply), 0x00c8);
        // Not a performance floor (`CLAUDE.md` §10): the two outcomes are "did
        // not wait at all" and "waited out the 180ms the handler had left", so
        // anything between them cannot happen.
        let waited = waited.await.expect("the drain task");
        assert!(
            waited >= Duration::from_millis(100),
            "the drain returned in {waited:?}, so it did not wait for the \
             reply the process was still writing"
        );

        let _ = server.await;
    }

    /// An idle connection is closed rather than held: RFC 7766 §6.2.3 wants
    /// connections reused, and an idle one still costs a socket.
    #[tokio::test]
    async fn an_idle_connection_is_closed() {
        let shutdown = Shutdown::new();
        let limits = TransportLimits {
            idle_timeout: Duration::from_millis(50),
            ..TransportLimits::default()
        };
        let (mut client, task) = connected(
            Echo::new(Answer::AfterIdMillis, 0),
            limits,
            shutdown.stop_handle(),
        )
        .await;

        assert!(
            next_reply(&mut client).await.is_none(),
            "nothing was asked, so the timeout ends it like EOF"
        );
        let _ = task.await;
    }

    /// A reply too long to frame is dropped rather than sent with a wrapped
    /// prefix, which the peer would read as a message boundary in the middle of
    /// a message and never recover from. That wrap was `TODO.md` #17.
    #[tokio::test]
    async fn a_reply_too_long_to_frame_is_dropped_rather_than_wrapped() {
        let (tx, mut rx) = mpsc::channel::<Reply>(4);
        assert!(
            !send_framed(&tx, &vec![0u8; u16::MAX as usize + 1]).await,
            "the caller is told, because the client gets no answer at all"
        );
        assert!(rx.try_recv().is_err(), "and nothing reached the writer");

        assert!(send_framed(&tx, &query(0x1234)).await, "the ordinary case");
        assert!(matches!(rx.try_recv(), Ok(Reply::Frame(_))));
    }

    /// Where the query rate applies is the caller's, and the two daemons
    /// disagree on purpose (`TODO.md` #30e). Per connection: a burst of one
    /// admits one connection, and the messages on it are not charged again.
    #[tokio::test]
    async fn the_query_rate_can_be_per_connection_instead_of_per_message() {
        let shutdown = Shutdown::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handler = Echo::new(Answer::AfterIdMillis, 1);
        let server = tokio::spawn(serve(
            listener,
            handler,
            TransportLimits::default(),
            RateLimit::PerConnection,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let mut first = TcpStream::connect(addr).await.expect("connect");
        for id in [0x0001u16, 0x0002] {
            send(&mut first, &query(id)).await;
            let reply = next_reply(&mut first).await.expect("both are answered");
            assert_eq!(id_of(&reply), id, "one token was for the connection");
        }

        // The second connection is over the burst of one. It is accepted by the
        // kernel and then dropped, so the tell is EOF with nothing on it.
        let mut second = TcpStream::connect(addr).await.expect("connect");
        send(&mut second, &query(0x0003)).await;
        assert!(
            next_reply(&mut second).await.is_none(),
            "refused before the connection was served"
        );

        shutdown.begin();
        let _ = server.await;
    }
}
