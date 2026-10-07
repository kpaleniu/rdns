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
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};

use crate::slots::Slots;
use crate::{ServeContext, TransportLimits};
use rdns::metrics::StreamListener;
use rdns::peer::{self, Peer};
use rdns::validation::{Arrival, Transport};

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

/// A stream whose two halves can be owned by two tasks.
///
/// One trait rather than one generic bound, and the reason is the plain-TCP
/// path. `TcpStream::into_split` hands back owned halves with nothing between
/// them; a TLS stream has no such method, so `tokio::io::split` puts a `BiLock`
/// in the way. Making [`serve_one`] generic over `AsyncRead + AsyncWrite` would
/// have been shorter and would have taken that lock on every connection,
/// encrypted or not — a cost paid by the transport that does not need it, to
/// spare fifteen lines here.
pub trait SplitStream: Send + 'static {
    type Reader: tokio::io::AsyncRead + Unpin + Send + 'static;
    type Writer: tokio::io::AsyncWrite + Unpin + Send + 'static;

    fn split_halves(self) -> (Self::Reader, Self::Writer);
}

impl SplitStream for TcpStream {
    type Reader = tokio::net::tcp::OwnedReadHalf;
    type Writer = tokio::net::tcp::OwnedWriteHalf;

    fn split_halves(self) -> (Self::Reader, Self::Writer) {
        self.into_split()
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

    /// `arrival` is what the transport knows about the connection and the
    /// handler cannot ask for afterwards, because by the time it has the bytes
    /// the socket is three layers below it: what the connection hid, which
    /// RFC 9103 §11 needs to decide whether a transfer may be answered, and
    /// which protocol carried it, which a dnstap reader displays.
    ///
    /// Return once the last reply is in `out`. DoH answers when this returns
    /// and DoQ sends FIN when `out` drops, so work done here after the reply is
    /// the client's latency on those two (`TODO.md` #114).
    fn handle(
        &self,
        packet: Vec<u8>,
        peer: SocketAddr,
        now: u64,
        arrival: Arrival,
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

impl RateLimit {
    /// Whether a connection just accepted may be served.
    ///
    /// Asked by all four accept loops, which had the same six lines each
    /// (`CLAUDE.md` §7). `PerMessage` admits every connection, because the
    /// token is spent on the message instead.
    ///
    /// The clock is read here rather than taken, because at accept there is no
    /// message whose instant to reuse — which is the distinction
    /// [`RateLimit::admits_message`] keeps (`TODO.md` #28a).
    pub fn admits_connection(self, ctx: &ServeContext, peer: Peer) -> bool {
        self != RateLimit::PerConnection || ctx.allow_source(peer, ctx.clock.now())
    }

    /// Whether a message on an already admitted connection may be answered.
    ///
    /// The other half, and a pair rather than two spellings of one `if`: a
    /// caller that asks both questions charges once however the policy is set,
    /// where an adapter that asked `allow_source` outright charged a
    /// `PerConnection` client twice for its first message. That was `https`,
    /// the one of the four that was handed `rate` and did not consult it
    /// (`TODO.md` #105).
    ///
    /// `now` is the caller's, for [`ServeContext::allow_source`]'s reason.
    pub fn admits_message(self, ctx: &ServeContext, peer: Peer, now: u64) -> bool {
        self != RateLimit::PerMessage || ctx.allow_source(peer, now)
    }
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
    let slots = Slots::new(
        limits.max_connections,
        &handler.context().metrics,
        StreamListener::Tcp,
        handler.context().per_source.clone(),
    );
    loop {
        // Before `accept`, so a full listener leaves the next connection in
        // the kernel's backlog rather than holding it unserved.
        let mut slot = tokio::select! {
            slot = slots.take() => slot,
            _ = stop.wait() => return Ok(()),
        };
        // Stop accepting on shutdown; open connections drain in their own tasks.
        // `accept` is cancel-safe, so a connection lost to this race stays in
        // the kernel's backlog.
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                // Not `?`: descriptor exhaustion clears on its own, and this
                // loop's death is the whole process's (`survive_accept_error`).
                Err(e) => {
                    crate::survive_accept_error(e, "tcp").await?;
                    continue;
                }
            },
            _ = stop.wait() => return Ok(()),
        };
        // Canonical before anything sees it (`TODO.md` #158). A stream reply
        // goes down the connection, so nothing needs the mapped form.
        let peer = peer::canonical(peer);
        // The query ACL first: a peer it refuses is closed before the rate
        // limiter or the per-source table hears of it (`TODO.md` #171).
        if !handler
            .context()
            .admits_connection(Peer::from(peer), StreamListener::Tcp)
        {
            continue;
        }
        if !rate.admits_connection(handler.context(), Peer::from(peer)) {
            continue;
        }
        // Closed unserved: dropping the stream closes it and dropping the
        // slot releases it.
        if !slot.open(Peer::from(peer)) {
            continue;
        }
        let handler = handler.clone();
        let stop = stop.clone();
        // Claim the drain for the connection's life: a client cannot tell a
        // truncated AXFR from a complete one.
        let busy = busy.clone();
        tokio::spawn(async move {
            serve_one(stream, peer, handler, limits, rate, Arrival::Tcp, stop).await;
            drop(slot);
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
pub async fn serve_one<H: Handler, S: SplitStream>(
    stream: S,
    peer: SocketAddr,
    handler: Arc<H>,
    limits: TransportLimits,
    rate: RateLimit,
    arrival: Arrival,
    stop: Stop,
) {
    let (mut reader, mut writer) = stream.split_halves();
    let (tx, mut rx) = mpsc::channel::<Reply>(limits.max_inflight_per_connection);

    // One task owns the write half: replies may complete out of order
    // (RFC 7766 §6.2.1.1; clients match on the transaction id), but two framed
    // messages must never interleave on the wire.
    //
    // Its end drops `rx`, which is how the read loop learns to stop: past it,
    // nothing asked on this connection can be answered.
    let writer_logger = handler.context().logger.clone();
    let stall = limits.read_timeout;
    let writer_task = tokio::spawn(async move {
        while let Some(reply) = rx.recv().await {
            let Reply::Frame(framed) = reply else {
                // `Reply::Abort`: dropping the write half tells the peer its
                // half-finished transfer will not be completed.
                break;
            };
            if let Err(e) = crate::write_progressing(&mut writer, &framed, stall).await {
                writer_logger.count_error(Peer::from(peer));
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
            _ = tx.closed() => break,
        };
        match read {
            Ok(Ok(_)) => {}
            _ => break,
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            handler.context().logger.count_error(Peer::from(peer));
            tracing::debug!(peer = %peer.ip(), "zero-length TCP message");
            break;
        }

        // Mid-message the peer has committed to sending `len` bytes, so a stall
        // here gets a much shorter leash than an idle connection.
        let mut packet = vec![0u8; len];
        match tokio::time::timeout(limits.read_timeout, reader.read_exact(&mut packet)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                handler.context().logger.count_error(Peer::from(peer));
                tracing::debug!(peer = %peer.ip(), "socket read error: {e}");
                break;
            }
            Err(_) => {
                handler.context().logger.count_error(Peer::from(peer));
                tracing::debug!(peer = %peer.ip(), "timed out mid-message on TCP");
                break;
            }
        }

        // Admission before the spawn, not inside it (`CLAUDE.md` §9): paying a
        // task and two `Arc` clones before deciding to drop the message is
        // backwards. One clock read for the message, handed to the handler so
        // the limiter, the log and a TSIG check all name the same instant.
        let now = handler.context().clock.now();
        if !rate.admits_message(handler.context(), Peer::from(peer), now) {
            continue;
        }
        // The message is skipped, not the connection: a peer that framed it
        // correctly is still speaking the protocol.
        if !handler
            .context()
            .accept_packet(Peer::from(peer), &packet, Transport::Tcp)
        {
            continue;
        }

        // Cap in-flight work per connection: this await is what stops a
        // pipelining client from spawning tasks faster than we retire them.
        // Raced against the writer's end: with it stalled, the permits are held
        // by handlers waiting on a full channel (`TODO.md` #163).
        let permit = tokio::select! {
            permit = in_flight.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
            _ = tx.closed() => break,
        };
        let handler = handler.clone();
        let tx = tx.clone();
        // One `Arc` bump per message since `TODO.md` #59 made an `Arrival`
        // carry what the client proved; the message it rides with cost a round
        // trip to arrive.
        let arrival = arrival.clone();
        tokio::spawn(async move {
            handler.handle(packet, peer, now, arrival, tx).await;
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

    use rdns::clock::Clock;
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
        /// Reply with this many octets, the query's id first: a transfer
        /// envelope's size, so a stalled reader fills the buffers quickly.
        Bulk(usize),
    }

    struct Echo {
        ctx: ServeContext,
        answer: Answer,
        /// Signalled as `handle` starts, for a test that must stop the server
        /// only once a message is in flight. A sleep stood in for it and lost
        /// the race under load (`TODO.md` #120a). `notify_one` keeps a permit
        /// when nobody waits yet, so the order of the two sides does not
        /// matter.
        started: Arc<tokio::sync::Notify>,
    }

    impl Echo {
        fn new(answer: Answer, rate: u32) -> Arc<Echo> {
            Echo::on_clock(answer, rate, Clock::system())
        }

        /// A handler whose limiter reads a clock the test holds, for the one
        /// test that asserts on a refill rather than on an answer.
        fn on_clock(answer: Answer, rate: u32, clock: Clock) -> Arc<Echo> {
            Arc::new(Echo {
                ctx: ServeContext {
                    clock,
                    ..context(rate)
                },
                answer,
                started: Arc::new(tokio::sync::Notify::new()),
            })
        }

        /// Until `handle` has been given a message, or a failure after five
        /// seconds rather than a hang.
        async fn in_flight(&self) {
            tokio::time::timeout(Duration::from_secs(5), self.started.notified())
                .await
                .expect("the handler was given the message");
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
            _arrival: Arrival,
            out: mpsc::Sender<Reply>,
        ) {
            self.started.notify_one();
            match self.answer {
                Answer::AfterIdMillis => {
                    let pause = u64::from(id_of(&packet) & 0xff);
                    tokio::time::sleep(Duration::from_millis(pause)).await;
                    send_framed(&out, &packet).await;
                }
                Answer::Abort => {
                    let _ = out.send(Reply::Abort).await;
                }
                Answer::Bulk(len) => {
                    let mut reply = vec![0u8; len];
                    reply[..2].copy_from_slice(&packet[..2]);
                    send_framed(&out, &reply).await;
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
            serve_one(
                server,
                peer,
                handler,
                limits,
                RateLimit::PerMessage,
                Arrival::Tcp,
                stop,
            )
            .await;
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
                .take_stats(rdns::clock::current_unix_timestamp() + 60)
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
        let echo = Echo::new(Answer::AfterIdMillis, 0);
        let (mut client, task) = connected(
            echo.clone(),
            TransportLimits::default(),
            shutdown.stop_handle(),
        )
        .await;

        // 200ms of handler, stopped once it has started.
        send(&mut client, &query(0x00c8)).await;
        echo.in_flight().await;
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
        let echo = Echo::new(Answer::AfterIdMillis, 0);
        let server = tokio::spawn(serve(
            listener,
            echo.clone(),
            TransportLimits::default(),
            RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let mut client = TcpStream::connect(addr).await.expect("connect");
        // 200ms of handler, stopped once it has started — so the drain has
        // most of 200ms to get the answer wrong in.
        send(&mut client, &query(0x00c8)).await;
        echo.in_flight().await;
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
        // not wait at all" and "waited out the ~200ms the handler had left", so
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

    /// A full listener leaves the next connection unserved until one closes,
    /// and says so once: one warning and one info line for the episode,
    /// however many times the loop waited in it (`TODO.md` #155).
    #[tokio::test]
    async fn a_full_listener_waits_for_a_slot_and_says_so_once() {
        let (logs, _guard) = crate::testutil::capture_logs();
        let shutdown = Shutdown::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let echo = Echo::new(Answer::AfterIdMillis, 0);
        let metrics = echo.ctx.metrics.clone();
        let tcp = || metrics.listener(StreamListener::Tcp);
        let limits = TransportLimits {
            max_connections: 2,
            ..TransportLimits::default()
        };
        let server = tokio::spawn(serve(
            listener,
            echo,
            limits,
            RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let mut open = Vec::new();
        for id in [0x0100u16, 0x0200] {
            let mut client = TcpStream::connect(addr).await.expect("connect");
            send(&mut client, &query(id)).await;
            assert_eq!(next_reply(&mut client).await.map(|r| id_of(&r)), Some(id));
            open.push(client);
        }
        assert_eq!(tcp().open(), 2);

        // The kernel completes the handshake from its backlog; nothing reads.
        let mut third = TcpStream::connect(addr).await.expect("connect");
        send(&mut third, &query(0x0300)).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(300), next_reply(&mut third))
                .await
                .is_err(),
            "a third connection was served with two open"
        );
        assert!(tcp().accept_waits() >= 1);
        assert_eq!(tcp().open(), 2);

        drop(open.remove(0));
        assert_eq!(
            next_reply(&mut third).await.map(|r| id_of(&r)),
            Some(0x0300),
            "served once a slot freed"
        );
        drop(open);
        drop(third);
        tokio::time::timeout(Duration::from_secs(5), async {
            while tcp().open() > 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("every connection closed");

        shutdown.begin();
        let _ = server.await;
        let text = String::from_utf8(logs.lock().expect("logs").clone()).expect("utf-8");
        assert_eq!(text.matches("listener full").count(), 1, "{text}");
        assert_eq!(text.matches("listener has room again").count(), 1, "{text}");
    }

    /// With two per source, a third connection from one peer is closed without
    /// a reply while two are open, and a connection after one closes is
    /// served (`TODO.md` #156).
    #[tokio::test]
    async fn a_source_at_its_limit_has_the_next_connection_closed() {
        let shutdown = Shutdown::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let echo = Arc::new(Echo {
            ctx: ServeContext {
                per_source: crate::SourceConnections::new(
                    2,
                    rdns::security::TransferAcl::default(),
                ),
                ..context(0)
            },
            answer: Answer::AfterIdMillis,
            started: Arc::new(tokio::sync::Notify::new()),
        });
        let metrics = echo.ctx.metrics.clone();
        let server = tokio::spawn(serve(
            listener,
            echo,
            TransportLimits::default(),
            RateLimit::PerMessage,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        let mut open = Vec::new();
        for id in [0x0100u16, 0x0200] {
            let mut client = TcpStream::connect(addr).await.expect("connect");
            send(&mut client, &query(id)).await;
            assert_eq!(next_reply(&mut client).await.map(|r| id_of(&r)), Some(id));
            open.push(client);
        }
        let mut third = TcpStream::connect(addr).await.expect("connect");
        send(&mut third, &query(0x0300)).await;
        assert!(
            next_reply(&mut third).await.is_none(),
            "closed with no reply"
        );
        assert_eq!(
            metrics.listener(StreamListener::Tcp).refused_per_source(),
            1
        );

        drop(open.remove(0));
        // The server notices the close on its next read; until then the
        // source still holds two.
        let served = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut next = TcpStream::connect(addr).await.expect("connect");
                send(&mut next, &query(0x0400)).await;
                if let Some(reply) = next_reply(&mut next).await {
                    return id_of(&reply);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("served once one closed");
        assert_eq!(served, 0x0400);

        shutdown.begin();
        drop(open);
        let _ = server.await;
    }

    /// A peer the query ACL does not list is closed unserved, before the rate
    /// limiter hears of it, and counted on its listener (`TODO.md` #171).
    ///
    /// A limiter with a burst of one and per-connection charging: were the ACL
    /// after it, the second and third connections would be rate-limited
    /// instead. Watched failing with the `admits_connection` call removed: the
    /// echo came back.
    #[tokio::test]
    async fn a_peer_the_query_acl_does_not_list_is_closed_unserved() {
        let shutdown = Shutdown::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let echo = Arc::new(Echo {
            ctx: ServeContext {
                acl: crate::testutil::only(&["192.0.2.0/24"]),
                ..context(1)
            },
            answer: Answer::AfterIdMillis,
            started: Arc::new(tokio::sync::Notify::new()),
        });
        let metrics = echo.ctx.metrics.clone();
        let server = tokio::spawn(serve(
            listener,
            echo,
            TransportLimits::default(),
            RateLimit::PerConnection,
            shutdown.stop_handle(),
            shutdown.busy(),
        ));

        for id in [0x0100u16, 0x0200, 0x0300] {
            let mut client = TcpStream::connect(addr).await.expect("connect");
            send(&mut client, &query(id)).await;
            assert!(next_reply(&mut client).await.is_none(), "closed unserved");
        }
        let tcp = metrics.listener(StreamListener::Tcp);
        assert_eq!(tcp.refused_by_acl(), 3);
        assert_eq!(tcp.open(), 0, "never opened");
        assert_eq!(
            metrics
                .rate_limited
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "the limiter never saw them"
        );

        shutdown.begin();
        let _ = server.await;
    }

    /// Two halves a test chooses, for a connection `TcpStream` cannot stage: a
    /// pipe whose buffer is the test's, or a writer that fails.
    struct Halves<R, W>(R, W);

    impl<R, W> SplitStream for Halves<R, W>
    where
        R: tokio::io::AsyncRead + Unpin + Send + 'static,
        W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        type Reader = R;
        type Writer = W;

        fn split_halves(self) -> (R, W) {
            (self.0, self.1)
        }
    }

    /// A write half whose every write fails, as one to a reset peer does.
    struct Broken;

    impl tokio::io::AsyncWrite for Broken {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A client that pipelines and reads nothing stalls the writer; the
    /// connection then ends one `read_timeout` after the last byte moved
    /// rather than never, freeing its slot and the drain (`TODO.md` #163).
    ///
    /// Watched failing without the progress deadline and the read loop's
    /// `tx.closed()` arms: `serve_one` was still running at the bound.
    #[tokio::test]
    async fn a_client_that_reads_nothing_does_not_hold_the_connection() {
        let shutdown = Shutdown::new();
        let limits = TransportLimits {
            read_timeout: Duration::from_millis(200),
            ..TransportLimits::default()
        };
        let (client, task) = connected(
            Echo::new(Answer::Bulk(60_000), 0),
            limits,
            shutdown.stop_handle(),
        )
        .await;

        let (_unread, mut sending) = client.into_split();
        let pipelining = tokio::spawn(async move {
            let framed = rdns::framed(&query(0x0001)).expect("frames");
            while sending.write_all(&framed).await.is_ok() {}
        });

        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("serve_one returned")
            .expect("and did not panic");
        pipelining.abort();
    }

    /// The deadline is on progress, not on the reply: a reader taking a 64 KB
    /// envelope in 4 KB sips over several `read_timeout`s gets all of it, as a
    /// slow secondary must. A whole-write deadline cut this off (`TODO.md`
    /// #163, grilled).
    #[tokio::test]
    async fn a_slow_but_steady_reader_gets_the_whole_reply() {
        let shutdown = Shutdown::new();
        let limits = TransportLimits {
            read_timeout: Duration::from_millis(100),
            ..TransportLimits::default()
        };
        // A 1 KB pipe, so the reply cannot sit in a buffer and the write
        // lasts as long as the reading does.
        let (mut client, server) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(server);
        let peer: SocketAddr = "192.0.2.1:53".parse().expect("addr");
        let task = tokio::spawn(serve_one(
            Halves(reader, writer),
            peer,
            Echo::new(Answer::Bulk(65_000), 0),
            limits,
            RateLimit::PerMessage,
            Arrival::Tcp,
            shutdown.stop_handle(),
        ));

        client
            .write_all(&rdns::framed(&query(0x0102)).expect("frames"))
            .await
            .expect("send");
        let began = std::time::Instant::now();
        let mut received = Vec::new();
        let mut sip = [0u8; 4096];
        while received.len() < 65_002 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let n = client.read(&mut sip).await.expect("read");
            assert!(n > 0, "closed after {} octets", received.len());
            received.extend_from_slice(&sip[..n]);
        }
        assert_eq!(u16::from_be_bytes([received[0], received[1]]), 65_000);
        assert_eq!(id_of(&received[2..]), 0x0102);
        assert!(
            began.elapsed() > 2 * limits.read_timeout,
            "read in {:?}, so the test did not outlast one deadline",
            began.elapsed()
        );

        drop(client);
        let _ = task.await;
    }

    /// Once a reply cannot be written, nothing else asked on the connection
    /// can be answered, so the read loop ends too rather than admitting and
    /// answering into a closed channel until the client gives up.
    ///
    /// Watched failing without the read loop's `tx.closed()` arm: it sat out
    /// the 10 s idle timeout.
    #[tokio::test]
    async fn a_write_error_ends_the_read_loop() {
        let shutdown = Shutdown::new();
        let handler = Echo::new(Answer::AfterIdMillis, 0);
        let logger = handler.ctx.logger.clone();
        let (mut client, server) = tokio::io::duplex(4096);
        let peer: SocketAddr = "192.0.2.1:53".parse().expect("addr");
        let task = tokio::spawn(serve_one(
            Halves(server, Broken),
            peer,
            handler,
            TransportLimits::default(),
            RateLimit::PerMessage,
            Arrival::Tcp,
            shutdown.stop_handle(),
        ));

        client
            .write_all(&rdns::framed(&query(0x0001)).expect("frames"))
            .await
            .expect("send");
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("serve_one returned with the client still connected")
            .expect("and did not panic");
        assert_eq!(
            logger
                .take_stats(rdns::clock::current_unix_timestamp() + 60)
                .total_errors,
            1
        );
        drop(client);
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
    /// admits one connection, the messages on it are not charged again, and the
    /// next connection waits for the refill.
    ///
    /// The clock is the test's. `RateLimiter::should_allow` refills by whole
    /// seconds, so against `SystemTime` the refusal below was decided by
    /// whether two connects straddled a second boundary — about one run in
    /// thirty served the second connection instead (`TODO.md` #52). A longer
    /// window would only have made the coin heavier; a clock nothing else moves
    /// takes it out of the assertion.
    #[tokio::test]
    async fn the_query_rate_can_be_per_connection_instead_of_per_message() {
        let shutdown = Shutdown::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        // Before `RateLimiter`'s own `last_cleanup`, which it takes from the
        // real clock: the sweep is then never due and cannot evict the bucket
        // this test is about.
        let clock = Clock::fixed(1_000_000_000);
        let handler = Echo::on_clock(Answer::AfterIdMillis, 1, clock.clone());
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

        // One second buys exactly one token back. This half is what says the
        // connection was *charged* rather than never admitted: a refusal that
        // no refill undoes would pass the assertion above on its own.
        clock.advance(1);
        let mut third = TcpStream::connect(addr).await.expect("connect");
        send(&mut third, &query(0x0004)).await;
        let reply = next_reply(&mut third).await.expect("the refill admits one");
        assert_eq!(id_of(&reply), 0x0004);

        shutdown.begin();
        let _ = server.await;
    }
}
