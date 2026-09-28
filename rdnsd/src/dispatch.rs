//! One request in, its reply on the wire.
//!
//! The door (`rdns::validation::Request`), the TSIG check, the four things a
//! request can be — a query, a NOTIFY, a transfer, a dynamic UPDATE — and the
//! epilogue every ordinary answer leaves through. What is *not* here is deciding
//! what a name deserves, which is [`crate::answer`]'s and has no sockets in it.
//!
//! `main.rs` reaches [`Wire`], which the UDP loop names to say where a reply
//! goes, [`Server`]'s constructor and three readers, [`UpdateHandling::new`],
//! and [`Server::answer`]. Everything else is private to this module, which is
//! the whole of `TODO.md` #38d and #109: the transfer and UPDATE answering used
//! to be `impl Server` blocks in the crate root, and then the fields they read
//! were, where private means visible to the root and every descendant
//! (`CLAUDE.md` §17).

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};

use rdns::dnstap;
use rdns::{
    dnssec_validation_mode::DnssecValidator,
    ede::InfoCode,
    error::RequestError,
    ixfr::{ixfr_response, DeltaLog, IxfrResponse},
    journal::Journal,
    logging::QueryLogger,
    notify,
    response::ClientEdns,
    security::{ResponseVerdict, TransferAcl, TransferCertificates},
    transfer::axfr_envelopes,
    tsig::{self, TsigCheck, TsigKeyring, TsigSession},
    update,
    validation::{Arrival, Privacy, Request, Transport},
    zone::{FileDigest, Zone},
    DnsMessage, ExtendedError, Name, OpCode, Qtype, ResponseCode,
};
use rdns_transport::tcp::{self, send_framed, Reply};
use rdns_transport::ServeContext;

use crate::answer::{write_response, NOT_OUR_ZONE};
use crate::replication::{Notified, Secondaries};
use crate::zones::{install_zone, ZoneContext, ZoneMap, ZoneSigning, ZoneSource, Zones};
use crate::Scratch;
use crate::{bad_request, serving_error};

/// Where one request's reply goes, and the two things that follow from it.
///
/// The transport decided three things that were written out twice: how a reply
/// is framed, how large it may be, and whether a response budget applies. It is
/// the parameter that lets `rdnsd` have one dispatcher instead of two
/// (`TODO.md` #39b), and the one place `Framed` is matched for is why "a
/// transfer is TCP-only" is now a branch the compiler can see rather than a
/// comment about which caller got here.
pub(super) enum Wire<'a> {
    /// A connection's writer, and what the connection hid from the path.
    /// Length-prefixed (RFC 1035 §4.2.2), a sequence allowed, and no response
    /// budget: the handshake proved the address.
    ///
    /// The [`Arrival`] rides here rather than beside it because it is a fact
    /// about *this* connection and only a framed one can carry a transfer,
    /// which is the one answer that has a policy about it (RFC 9103 §11).
    Framed(&'a mpsc::Sender<Reply>, Arrival),
    /// One datagram back to the peer, capped by its EDNS advertisement and
    /// charged against the response budget.
    Datagram(&'a UdpSocket, SocketAddr),
}

/// A request in both the forms the epilogue needs it: parsed, and as the octets
/// it arrived as.
///
/// One argument rather than two, which keeps [`Server::finish`] at seven and
/// says the true thing about them: they are one message, and a `DnsMessage`
/// re-serialized is not the bytes a client sent.
#[derive(Clone, Copy)]
pub(super) struct Incoming<'a> {
    pub(super) msg: &'a DnsMessage,
    pub(super) bytes: &'a [u8],
    /// When it arrived, to nanoseconds, and `None` unless there is a query
    /// stream to put it on.
    ///
    /// Not derived from `now`, which is the transport's clock read in whole
    /// seconds: a dnstap reader subtracts the query time from the response
    /// time, so a query time rounded down to the second reports a latency of
    /// up to a second for an answer that took microseconds. A wrong number is
    /// worse than an absent one (`CLAUDE.md` §14), and here it is worse than
    /// the extra `SystemTime::now` — which is paid only when `--dnstap` is on.
    pub(super) arrived: Option<dnstap::Timestamp>,
}

impl Wire<'_> {
    /// Which transport this is, for the two questions that turn on it: the
    /// reply's size ceiling and whether the response budget applies.
    fn transport(&self) -> Transport {
        match self {
            Wire::Framed(..) => Transport::Tcp,
            Wire::Datagram(..) => Transport::Udp,
        }
    }

    /// What a dnstap reader calls this transport.
    ///
    /// All five, since `TODO.md` #54 gave the dispatcher an [`Arrival`] rather
    /// than a [`Privacy`]: the three encrypted ones were one value before, and
    /// the field was left absent rather than guessed at.
    fn socket_protocol(&self) -> dnstap::SocketProtocol {
        match self {
            Wire::Datagram(..) => dnstap::SocketProtocol::Udp,
            Wire::Framed(_, Arrival::Tcp) => dnstap::SocketProtocol::Tcp,
            Wire::Framed(_, Arrival::Dot(..)) => dnstap::SocketProtocol::Dot,
            Wire::Framed(_, Arrival::Doh(..)) => dnstap::SocketProtocol::Doh,
            Wire::Framed(_, Arrival::Doq(_)) => dnstap::SocketProtocol::Doq,
        }
    }

    /// Put one finished message on the wire, framing it if the transport frames.
    ///
    /// Callers hand over unframed bytes whichever transport they are on, which
    /// is what removes the `&framed[2..]` the UDP UPDATE path did by hand.
    async fn send(&self, bytes: &[u8], logger: &QueryLogger, ip: IpAddr) {
        match self {
            Wire::Framed(out, _) => {
                send_framed(out, bytes).await;
            }
            Wire::Datagram(socket, peer) => {
                if let Err(e) = socket.send_to(bytes, *peer).await {
                    bad_request!(logger, ip, "socket send error: {e}");
                }
            }
        }
    }
}

/// Everything both transports answer from. One per process, so a connection or
/// datagram task clones a single `Arc`.
///
/// Shared across transports on purpose: a client's rate limit must not reset
/// because it switched transport, and the metrics are one server's.
///
/// Here rather than in the crate root, with every field private, so that what
/// the root may do with one is build it and read three things (`TODO.md` #109).
/// [`Server::new`] refuses everything it is not told otherwise about.
pub(crate) struct Server {
    zone_map: Arc<RwLock<Zones>>,
    /// The limiter, the response budget, the validator, the logger and the
    /// metrics — the five handles serving a request needs that are not the
    /// answer. `rdnsr` held the same five as its `Shell`, which is how the
    /// admission sequence came to be written twice (`TODO.md` #30e, #32).
    ctx: ServeContext,
    /// Who may ask for a zone transfer. Empty by default, which refuses everyone.
    transfer_acl: Arc<TransferAcl>,
    /// Which client certificates may transfer which zones — §7.5's other
    /// method, additive with the ACL and the keyring (`TODO.md` #59). Empty
    /// unless `--allow-transfer-cert` named somebody.
    transfer_clients: Arc<TransferCertificates>,
    /// Refuse a transfer that did not arrive over TLS 1.3 (RFC 9103 §11,
    /// `--transfer-tls-only`). Beside the ACL because it is the other half of
    /// the same question — the ACL says who may ask, this says on what.
    transfer_tls_only: bool,
    tsig_keys: Arc<TsigKeyring>,
    /// The zones we replicate, so a NOTIFY can be told from a plausible one.
    secondaries: Arc<Secondaries>,
    /// Per-zone change history, so an IXFR can answer with the difference.
    /// Derived from the zone map, so the two are only updated together.
    deltas: Arc<RwLock<DeltaLog>>,
    /// `None` on a server with no writable zone source: every UPDATE refused.
    updates: Arc<UpdateHandling>,
    journal: Option<Arc<Journal>>,
    /// Where the query stream goes, or `None` when `--dnstap` was not given.
    /// See [`crate::dnstap`] for why the queue behind it drops.
    dnstap: Option<crate::dnstap::Sink>,
}

impl Server {
    /// A server answering queries from `zone_map`, and refusing every
    /// transfer, NOTIFY and UPDATE until a `with_*` says otherwise.
    pub(crate) fn new(zone_map: Arc<RwLock<Zones>>, ctx: ServeContext) -> Self {
        Server {
            zone_map,
            ctx,
            transfer_acl: Arc::new(TransferAcl::default()),
            transfer_clients: Arc::new(TransferCertificates::default()),
            transfer_tls_only: false,
            tsig_keys: Arc::new(TsigKeyring::default()),
            secondaries: Arc::new(Secondaries::default()),
            deltas: Arc::new(RwLock::new(DeltaLog::new())),
            updates: Arc::new(UpdateHandling::disabled()),
            journal: None,
            dnstap: None,
        }
    }

    /// Who may transfer, by address and by certificate, and whether only over
    /// TLS. One setter because they are one question (RFC 9103 §11).
    pub(crate) fn with_transfers(
        self,
        acl: TransferAcl,
        clients: TransferCertificates,
        tls_only: bool,
    ) -> Self {
        Server {
            transfer_acl: Arc::new(acl),
            transfer_clients: Arc::new(clients),
            transfer_tls_only: tls_only,
            ..self
        }
    }

    pub(crate) fn with_tsig_keys(self, keys: TsigKeyring) -> Self {
        Server {
            tsig_keys: Arc::new(keys),
            ..self
        }
    }

    pub(crate) fn with_secondaries(self, secondaries: Arc<Secondaries>) -> Self {
        Server {
            secondaries,
            ..self
        }
    }

    /// The change history and where it is persisted. Together because
    /// [`install_zone`] writes both or neither.
    pub(crate) fn with_history(
        self,
        deltas: Arc<RwLock<DeltaLog>>,
        journal: Option<Arc<Journal>>,
    ) -> Self {
        Server {
            deltas,
            journal,
            ..self
        }
    }

    pub(crate) fn with_updates(self, updates: UpdateHandling) -> Self {
        Server {
            updates: Arc::new(updates),
            ..self
        }
    }

    pub(crate) fn with_dnstap(self, dnstap: Option<crate::dnstap::Sink>) -> Self {
        Server { dnstap, ..self }
    }

    /// The admission handles, for the UDP loop's checks before a datagram
    /// reaches [`Server::answer`], and for the metrics and anomaly tasks.
    pub(crate) fn ctx(&self) -> &ServeContext {
        &self.ctx
    }

    pub(crate) fn tsig_keys(&self) -> &TsigKeyring {
        &self.tsig_keys
    }
}

/// What answering a dynamic UPDATE (RFC 2136) needs beyond what a query needs.
///
/// The update must reach the *file*, not just the map: the re-signing timer
/// reloads every zone from its file (see [`ZoneSigning::resign_interval`]), so
/// an in-memory-only edit is discarded within one re-signing interval with
/// nothing logged. The flow is apply to the zone as the file has it, write the
/// file, sign the result, verify what was signed, install that.
pub(crate) struct UpdateHandling {
    /// `None` when the server has no source it may write — a secondary's
    /// replicated zones are the master's copy.
    source: Option<ZoneSource>,
    /// So the installed version is signed the way a loaded one would be.
    signing: Option<Arc<ZoneSigning>>,
    /// And checked the way a loaded one is: the same validator `verify_zones`
    /// is given, so `--require-signed` means one thing (`TODO.md` #100).
    validator: Arc<DnssecValidator>,
    /// Serializes the read-modify-write, which RFC 2136 §3.7 requires.
    ///
    /// One lock for all zones rather than one per zone: two concurrent UPDATEs
    /// is not a workload this has. Held across file I/O and a signing run, so
    /// `tokio::Mutex` and not a `std` one.
    ///
    /// It guards the digest of each zone file as this server last wrote it
    /// (`TODO.md` #64b), because that fact is *made* under this lock: nothing
    /// else writes a zone file while it is held, so the map cannot be stale
    /// with respect to anything the server itself did.
    applying: tokio::sync::Mutex<HashMap<PathBuf, FileDigest>>,
}

impl UpdateHandling {
    /// UPDATEs applied to `source`, signed with `signing` and checked with
    /// `validator` — the three a reload uses, so the two agree on what a zone is.
    pub(crate) fn new(
        source: ZoneSource,
        signing: Option<Arc<ZoneSigning>>,
        validator: Arc<DnssecValidator>,
    ) -> Self {
        UpdateHandling {
            source: Some(source),
            signing,
            validator,
            applying: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// A server that refuses every UPDATE: [`Server::new`]'s default. `serve`
    /// always has a zone source, so this is reached from tests.
    fn disabled() -> Self {
        UpdateHandling {
            source: None,
            signing: None,
            validator: Arc::new(DnssecValidator::new(false)),
            applying: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
}

/// What answers a query on this server, for the shared TCP transport.
///
/// The sink shape is this daemon's requirement: an AXFR is a *sequence* of
/// messages (RFC 5936 §2.2), so a slow client back-pressures the next envelope
/// rather than having the whole zone built ahead of it (`TODO.md` #30a).
impl tcp::Handler for Server {
    fn context(&self) -> &ServeContext {
        &self.ctx
    }

    async fn handle(
        &self,
        packet: Vec<u8>,
        peer: SocketAddr,
        now: u64,
        arrival: Arrival,
        out: mpsc::Sender<Reply>,
    ) {
        // A scratch per message here, where the UDP worker keeps one per worker:
        // `tcp::Handler` has no per-connection state to hang one on
        // (`TODO.md` #39e).
        let mut scratch = Scratch::default();
        self.answer(
            &packet,
            peer,
            now,
            &Wire::Framed(&out, arrival),
            &mut scratch,
        )
        .await;
    }
}

/// The request an error reply is about — everything [`Server::signed_error`]
/// needs that is not the refusal itself.
///
/// Four values that travel together at all twenty call sites: `answer_update`
/// passes the same four to eleven of them and `answer_transfer` to the other
/// nine. A struct rather than four parameters because clippy says so at seven
/// (`CLAUDE.md` §14) — and because one of the four is `now`, the instant that
/// verified the request. Carrying it here is what stops a thirteenth site
/// reading the clock a second time, which is what `TODO.md` #87 was.
#[derive(Clone, Copy)]
struct Refused<'a> {
    msg: &'a DnsMessage,
    ip: IpAddr,
    now: u64,
    max_len: usize,
}

impl<'a> Refused<'a> {
    /// A transfer's, whose reply is framed and so has the whole 16-bit length
    /// to spend rather than a datagram's ceiling.
    fn transfer(msg: &'a DnsMessage, ip: IpAddr, now: u64) -> Self {
        Refused {
            msg,
            ip,
            now,
            max_len: u16::MAX as usize,
        }
    }
}

/// What `answer` has settled about a request before it is answered.
///
/// Six values that travel together into `answer_admitted`, which would
/// otherwise take them one by one past the point clippy stops counting.
struct Admitted<'a> {
    msg: &'a DnsMessage,
    qtype: Option<Qtype>,
    peer: SocketAddr,
    now: u64,
    ceiling: usize,
    advertised: u16,
}

impl Server {
    /// Answer one request, whatever it arrived on.
    ///
    /// One function for both transports: everything up to the TSIG check is the
    /// same question asked of the same bytes, and what differs afterwards is
    /// `wire` (`TODO.md` #39b). Sent rather than returned, because an AXFR
    /// response is a sequence of messages (RFC 5936 §2.2) and a slow client
    /// should back-pressure the next envelope rather than have the whole zone
    /// built ahead of it. Sending nothing is how a query earns no response.
    ///
    /// `now` is the transport's single clock read for this message: the limiter
    /// has already used it, and the logger and the TSIG check want the same
    /// instant (`TODO.md` #28a). Admission ran before this was called, which is
    /// where it belongs (`CLAUDE.md` §9).
    pub(super) async fn answer(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        now: u64,
        wire: &Wire<'_>,
        scratch: &mut Scratch,
    ) {
        let ip = peer.ip();
        // `Request` is the door: it parses and it refuses QR=1. `AdmissionCheck`
        // accepts QR=1 on purpose — it runs on both directions of the wire — so
        // the check belongs here, where we know the packet reached a listener.
        let msg = match Request::from_bytes(packet) {
            Ok(msg) => msg,
            Err(RequestError::Wire(_)) => {
                bad_request!(self.ctx.logger, ip, "failed to parse DNS message");
                return;
            }
            Err(RequestError::NotAQuestion) => {
                // Silence, not a reply: answering turns a pair of servers, or one
                // spoofed datagram, into a packet loop.
                bad_request!(
                    self.ctx.logger,
                    ip,
                    "a response was sent to a server port; dropped"
                );
                return;
            }
        };

        // Before anything that could take time, and only when somebody is
        // reading: see `Incoming::arrived`.
        let arrived = self.dnstap.as_ref().map(|_| dnstap::Timestamp::now());

        let qtype = msg.queries.first().map(|q| q.qtype);
        self.ctx.logger.log_query(ip, qtype, now);
        // Counted before any policy can return, so a request refused later is
        // still a request received (`TODO.md` #39a).
        self.ctx.metrics.count(&self.ctx.metrics.queries_received);
        if let Some(qtype) = qtype {
            self.ctx.metrics.track_query_type(qtype);
        }

        // One ceiling for every reply this request can produce, read once from
        // the transport that will carry it and from this server's own limit —
        // not from the client's advertisement alone (`TODO.md` #41b).
        let ceiling = self.ctx.udp.reply_ceiling(&msg, wire.transport());
        let advertised = self.ctx.udp.advertised();

        let incoming = Incoming {
            msg: &msg,
            bytes: packet,
            arrived,
        };

        let admitted = Admitted {
            msg: &msg,
            qtype,
            peer,
            now,
            ceiling,
            advertised,
        };

        // TSIG before anything that could answer (RFC 8945 §5.2): checking the
        // signature afterwards means answering whoever asked.
        let sent = match tsig::check_request(packet, &self.tsig_keys, now) {
            TsigCheck::Rejected(rejection) => {
                // WARN, not DEBUG: a key that does not verify is either a
                // misconfiguration or somebody trying keys.
                serving_error!(
                    self.ctx.logger,
                    ip,
                    "TSIG rejected (key {}): {}",
                    rejection.key_name(),
                    rejection.error.reason()
                );
                // No RFC 8914 reason: the TSIG record this reply carries says
                // BADKEY, BADSIG or BADTIME itself (RFC 8945 §4.3), which is a
                // finer answer than any INFO-CODE has.
                // A `match` and not a `let ... else`: this is an arm now, so
                // "no reply fits" is a value it produces rather than a
                // divergence it escapes through.
                match error_reply(
                    &msg,
                    ResponseCode::NotAuthorized,
                    None,
                    reserve(ceiling, rejection.reply_overhead()),
                    advertised,
                ) {
                    None => None,
                    Some(response) => match rejection.attach(response, now) {
                        Ok(bytes) => {
                            wire.send(&bytes, &self.ctx.logger, ip).await;
                            // Returned rather than dropped: the tail records
                            // what went out, and a NOTAUTH is an answered
                            // request.
                            Some(Cow::Owned(bytes))
                        }
                        Err(e) => {
                            serving_error!(self.ctx.logger, ip, "TSIG error reply: {e}");
                            None
                        }
                    },
                }
            }
            other => {
                let mut session = match other {
                    TsigCheck::Verified(session) => Some(session),
                    // `Unsigned`; `Rejected` is the arm above.
                    _ => None,
                };
                self.answer_admitted(&admitted, &mut session, wire, scratch)
                    .await
            }
        };

        self.record_dnstap(wire, incoming, peer, sent.as_deref());
    }

    /// Answer a request whose TSIG has been settled: the three ordinary ways,
    /// and the bytes each of them put on the wire.
    ///
    /// Split out of `answer` so a TSIG refusal and an ordinary answer are two
    /// arms of one `match` producing the same value, rather than one of them
    /// returning past the dnstap tail (`TODO.md` #101). The parameters are a
    /// struct because the alternative is nine, four of them a `u16` or a `u64`
    /// next to each other (`CLAUDE.md` §14).
    async fn answer_admitted<'s>(
        &self,
        admitted: &Admitted<'_>,
        session: &mut Option<tsig::TsigSession>,
        wire: &Wire<'_>,
        scratch: &'s mut Scratch,
    ) -> Option<Cow<'s, [u8]>> {
        let Admitted {
            msg,
            qtype,
            peer,
            now,
            ceiling,
            advertised,
        } = *admitted;
        let ip = peer.ip();
        // The record the signer appends comes out of the ceiling, not on top of
        // it: RFC 8945 §5.3 says a TSIG that would not fit means altering the
        // response, not sending it oversized (`TODO.md` #41d). Signing is the
        // one thing here that grows finished bytes.
        let max_len = match &session {
            Some(session) => reserve(ceiling, session.reply_overhead()),
            None => ceiling,
        };

        // Four ways to answer and one tail, because three of them used to
        // `return` past it: `record_dnstap` was reachable only through
        // `finish`, so a capture held no UPDATE and no transfer while
        // `--dnstap` says "every answered request" and `MessageType` carried
        // `UpdateQuery` for nobody (`CLAUDE.md` §7's early return over a shared
        // epilogue). The fourth was a TSIG that did not verify, which answered
        // NOTAUTH and returned sixty lines above the tail (`TODO.md` #101); it
        // now leaves through the caller's `match`, which has to produce a value.
        let transfer = matches!(qtype, Some(Qtype::AXFR) | Some(Qtype::IXFR));
        let sent = if let (true, Wire::Framed(out, arrival)) = (transfer, wire) {
            // A sequence of messages, gated on an ACL, and the answer can be
            // the whole zone. Only where a sequence can be carried — AXFR is
            // TCP alone (RFC 5936 §4.2) and an IXFR over UDP is answered with a
            // single SOA (RFC 1995 §2), both of which `write_response` does
            // below.
            self.answer_transfer(msg, peer, session.as_mut(), now, arrival, out)
                .await;
            // No one envelope is the reply, and buffering the zone to name one
            // would undo what `answer_transfer` is shaped to avoid. The entry
            // says a transfer arrived, which is what a reader cannot get
            // anywhere else.
            None
        } else if msg.opcode == OpCode::Update {
            // Likewise, plus: an UPDATE installs a new zone, and
            // `make_response` holds a read guard on the zone map that
            // installing would deadlock against. RFC 2136 §1 permits it on
            // either transport, and the checks, the ordering and the
            // persistence are the request's, not the transport's.
            let reply = self
                .answer_update(msg, peer, session.as_mut(), now, max_len)
                .await;
            if let Some(reply) = &reply {
                wire.send(reply, &self.ctx.logger, ip).await;
            }
            reply.map(Cow::Owned)
        } else {
            // Never hold the zone lock across a socket write: a SIGHUP reload
            // would queue behind a slow client for the life of its connection.
            let serialized = {
                let zones = self.zone_map.read().await;
                if msg.opcode == OpCode::Notify {
                    notify_reply(msg, &zones, &self.secondaries, peer, advertised)
                        .to_bytes_within_buf_with(
                            max_len,
                            &mut scratch.out,
                            &mut scratch.compressor,
                        )
                } else {
                    write_response(msg, &zones, &self.ctx.metrics, max_len, advertised, scratch)
                }
            };
            if let Err(e) = serialized {
                serving_error!(self.ctx.logger, ip, "serialization error: {e}");
                // Recorded all the same, for the reason a dropped reply is: the
                // request arrived and got nothing.
                None
            } else {
                self.finish(wire, msg, session.as_mut(), peer, now, scratch)
                    .await
            }
        };
        sent
    }

    /// The epilogue every ordinary answer leaves through: charge it, sign it,
    /// send it.
    ///
    /// Charging is the datagram transport's alone — over TCP the handshake has
    /// proved the address, so there is nothing to amplify. Over budget, a
    /// truncated reply is the useful refusal: it carries no records, so it
    /// cannot amplify, and a real client reads TC=1 and asks again over TCP.
    /// Dropping is for the rest.
    ///
    /// `Cow` so the ordinary answer — no budget trouble, no TSIG — goes out of
    /// the caller's scratch buffer with nothing allocated. The two exceptions
    /// build a message of their own and own it.
    async fn finish<'s>(
        &self,
        wire: &Wire<'_>,
        request: &DnsMessage,
        session: Option<&mut TsigSession>,
        peer: SocketAddr,
        now: u64,
        scratch: &'s Scratch,
    ) -> Option<Cow<'s, [u8]>> {
        let ip = peer.ip();
        let advertised = self.ctx.udp.advertised();
        // The ceiling `answer` wrote the body against, signature reserved and
        // all: a truncated reply is signed too, so it is bounded by the same
        // number.
        let ceiling = self.ctx.udp.reply_ceiling(request, wire.transport());
        let ceiling = match &session {
            Some(session) => reserve(ceiling, session.reply_overhead()),
            None => ceiling,
        };
        let mut reply: Option<Cow<'_, [u8]>> = match wire {
            Wire::Framed(..) => Some(Cow::Borrowed(scratch.out.as_slice())),
            Wire::Datagram(..) => match self.ctx.admit_response(ip, scratch.out.len(), now) {
                ResponseVerdict::Send => Some(Cow::Borrowed(scratch.out.as_slice())),
                ResponseVerdict::Truncate => {
                    truncated_reply(request, ceiling, advertised).map(Cow::Owned)
                }
                ResponseVerdict::Drop => None,
            },
        };
        // RFC 8945 §5.3: "If addition of the TSIG record will cause the message
        // to be truncated, the server MUST alter the response so that a TSIG can
        // be included. This response contains only the question and a TSIG
        // record, has the TC bit set, and has an RCODE of 0 (NOERROR)."
        //
        // `answer` reserved the record out of the ceiling, so the body has
        // already gone; what the writer cannot know is that the RCODE goes with
        // it, never having heard of TSIG. Applied to every truncated signed
        // reply rather than only to one the signature pushed over, because the
        // two produce the same message and §5.3 is the stricter shape. The OPT
        // stays — RFC 6891 §6.1.1 requires mirroring it, and §5.3 is older than
        // that being true of every reply.
        if session.is_some() && reply.as_deref().is_some_and(rdns::response::is_truncated) {
            reply = truncated_reply(request, ceiling, advertised).map(Cow::Owned);
        }
        // Sign whatever we ended up sending — including a truncated one, since
        // that is still our answer to a question someone authenticated. Same
        // session, so the reply's MAC covers the request's: that is what stops
        // one question's reply being replayed as another's. This is where the
        // borrow above becomes a copy, and it is the right place for it: a
        // signed query over UDP is a NOTIFY or an SOA probe, not traffic.
        let reply = match (reply, session) {
            (Some(reply), Some(session)) => match session.sign(reply.into_owned(), now) {
                Ok(signed) => Some(Cow::Owned(signed)),
                Err(e) => {
                    serving_error!(self.ctx.logger, ip, "TSIG signing failed: {e}");
                    None
                }
            },
            (reply, _) => reply,
        };
        // `None` is a request answered with silence — over the response
        // budget. The caller records it either way: a query-only entry says it
        // arrived and got nothing, which is the one thing a log line at DEBUG
        // cannot tell an analytics pipeline.
        if let Some(reply) = reply {
            wire.send(&reply, &self.ctx.logger, ip).await;
            Some(reply)
        } else {
            None
        }
    }

    /// Put this exchange on the query stream, if there is one.
    ///
    /// One entry per exchange rather than the two BIND emits: the response
    /// entry carries the query verbatim in `Message.query_message`, which is
    /// what the schema is for, and halves the frames on the hot path.
    ///
    /// `socket_protocol` names the transport exactly, DoT, DoH and DoQ
    /// included, because the dispatcher is told [`Arrival`] — which protocol
    /// carried the message as well as what it hid (`TODO.md` #54). It was
    /// omitted for every encrypted connection until then: [`Privacy`] alone
    /// cannot tell the three apart, and DOT for a DoH query is a wrong value
    /// where an absent one is a reader showing nothing (`CLAUDE.md` §14).
    fn record_dnstap(
        &self,
        wire: &Wire<'_>,
        incoming: Incoming<'_>,
        peer: SocketAddr,
        reply: Option<&[u8]>,
    ) {
        let Some(sink) = &self.dnstap else { return };
        let update = incoming.msg.opcode == OpCode::Update;
        let message_type = match (update, reply.is_some()) {
            (false, true) => dnstap::MessageType::AuthResponse,
            (false, false) => dnstap::MessageType::AuthQuery,
            (true, true) => dnstap::MessageType::UpdateResponse,
            (true, false) => dnstap::MessageType::UpdateQuery,
        };
        sink.record(&dnstap::Entry {
            identity: sink.identity(),
            version: sink.version(),
            message_type,
            socket_protocol: Some(wire.socket_protocol()),
            peer,
            // The listener's address is not carried this far, and a wrong one
            // is worse than none on a multi-homed host.
            local: None,
            // Both to nanoseconds, because a reader subtracts them. See
            // `Incoming::arrived` for why the transport's `now` is not one of
            // them.
            query_time: incoming.arrived.unwrap_or_default(),
            response_time: reply.map(|_| dnstap::Timestamp::now()),
            query: Some(incoming.bytes),
            response: reply,
            // `Message.query_zone` needs the zone the answer came out of, which
            // the epilogue is not told. Optional in the schema, and a reader
            // takes the zone from the question.
            zone: None,
        });
    }

    /// Answer an AXFR: the whole zone, or a refusal.
    ///
    /// Every attempt is logged, allowed or not: a refused one is a probe, an
    /// allowed one is a copy of the zone leaving the building.
    ///
    /// Written to `out` one envelope at a time, so the zone is never
    /// materialized whole. What that costs in failure handling is on
    /// [`Server::abandon_transfer`].
    async fn answer_transfer(
        &self,
        msg: &DnsMessage,
        peer: SocketAddr,
        mut session: Option<&mut TsigSession>,
        now: u64,
        arrival: &Arrival,
        out: &mpsc::Sender<Reply>,
    ) {
        let privacy = arrival.privacy();
        let ip = peer.ip();
        // One for all nine ways out of this function, so none of them can pick
        // a different instant than the one that verified the request.
        let refused = Refused::transfer(msg, ip, now);
        let qname = msg
            .queries
            .first()
            .map(|q| q.qname.clone())
            .unwrap_or_default();
        let incremental = msg.queries.first().map(|q| q.qtype) == Some(Qtype::IXFR);
        let kind = if incremental { "IXFR" } else { "AXFR" };

        // Before anything about who is asking, and before this one too: the
        // answer cannot leave by the door it arrived at, whoever is asking and
        // whatever the policy. Checked here rather than at the dispatch that
        // chose to stream, because this is where a refusal is logged and
        // signed — an authenticated refusal is still signed (RFC 8945 §5.3,
        // `CLAUDE.md` §16) — and because it is before the zone is looked up,
        // which is the whole point of refusing rather than building
        // (`TODO.md` #106).
        if !arrival.carries_a_sequence() {
            serving_error!(
                self.ctx.logger,
                ip,
                "{kind} of {qname} REFUSED: {} carries one message per request",
                match arrival {
                    Arrival::Doh(..) => "DoH",
                    // Unreachable while DoH is the only one, and written out
                    // so adding a transport that cannot stream is a compile
                    // error here rather than a wrong sentence.
                    Arrival::Tcp | Arrival::Dot(..) | Arrival::Doq(_) => "this transport",
                }
            );
            self.send_transfer_error(
                refused,
                ResponseCode::Refused,
                Some(ONE_MESSAGE_TRANSPORT),
                session,
                out,
            )
            .await;
            return;
        }

        // Before anything about who is asking: RFC 9103 §11 — "An individual
        // zone transfer is not considered protected by XoT unless both the
        // client and server are configured to use only XoT" — and this is the
        // server's half. TLS 1.3 or better, because §7.2 is "All
        // implementations of this specification MUST use only TLS 1.3
        // [RFC8446] or later" and a 1.2 DoT connection is a fine way to ask a
        // question and not a way to take a zone.
        //
        // REFUSED, not NOTAUTH: the zone exists and the answer is policy. The
        // reply says which policy, because "REFUSED" alone over a working TLS
        // connection is the sort of thing an operator debugs for an afternoon
        // (RFC 8914, `TODO.md` #44b).
        if self.transfer_tls_only && !privacy.is_xot() {
            serving_error!(
                self.ctx.logger,
                ip,
                "{kind} of {qname} REFUSED: --transfer-tls-only, and this one \
                 arrived over {}",
                match privacy {
                    Privacy::Clear => "an unencrypted connection",
                    Privacy::TlsOlder => "TLS older than 1.3 (RFC 9103 §7.2)",
                    Privacy::Tls13 => "TLS 1.3",
                }
            );
            self.send_transfer_error(
                refused,
                ResponseCode::Refused,
                Some(NOT_OVER_TLS),
                session,
                out,
            )
            .await;
            return;
        }

        // Either a verified TSIG or an address rule grants the transfer, and an
        // IXFR is gated identically because it may answer with the whole zone
        // (RFC 1995 §4).
        //
        // A verified key says who, not what: authorize it against the apex, and
        // do so before the zone is looked up or any message built. A key with no
        // zone list still authorizes everything (`TsigKey::zones`).
        //
        // REFUSED, not NOTAUTH: the peer proved who it is and the answer is no,
        // which is policy rather than a claim about the zone's authority.
        let apex = &qname;
        let apex_text = apex.as_ref().to_presentation();
        let unauthorized = session
            .as_ref()
            .filter(|s| !s.may_transfer(&apex_text))
            .map(|s| s.key_name().to_string());
        if let Some(key_name) = unauthorized {
            serving_error!(
                self.ctx.logger,
                ip,
                "{kind} of {qname} REFUSED: key {key_name} is scoped to other zones"
            );
            self.send_transfer_error(
                refused,
                ResponseCode::Refused,
                Some(NOT_YOURS),
                session,
                out,
            )
            .await;
            return;
        }

        // RFC 9103 §7.5's other method, and the one it says to prefer: "mutual
        // TLS (mTLS)". A certificate verified against `--transfer-client-ca`
        // during the handshake says *who*; `--allow-transfer-cert` says what
        // they may take, and an unlisted certificate authorizes nothing
        // (`CLAUDE.md` §16). Scoped elsewhere is a refusal of its own, for the
        // reason the key one is: the peer proved who it is and the answer is
        // no.
        let by_certificate = self
            .transfer_clients
            .identify(arrival.peer_certificate())
            .map(|client| (client.name().to_string(), client.may_transfer(&apex_text)));
        if let Some((name, false)) = &by_certificate {
            serving_error!(
                self.ctx.logger,
                ip,
                "{kind} of {qname} REFUSED: certificate {name} is scoped to other zones"
            );
            self.send_transfer_error(
                refused,
                ResponseCode::Refused,
                Some(NOT_YOURS),
                session,
                out,
            )
            .await;
            return;
        }
        let authorized_by_certificate = matches!(by_certificate, Some((_, true)));

        let authenticated_by = session.as_ref().map(|s| s.key_name().to_string());
        if authenticated_by.is_none() && !authorized_by_certificate && !self.transfer_acl.allows(ip)
        {
            serving_error!(
                self.ctx.logger,
                ip,
                "{kind} of {qname} REFUSED: no TSIG key, no listed client certificate, \
                 and not in --allow-transfer"
            );
            // No session on this path by construction — it is the "no key" case.
            self.send_transfer_error(refused, ResponseCode::Refused, Some(NOT_YOURS), None, out)
                .await;
            return;
        }

        // An exact match on the origin, not the enclosing-zone lookup an ordinary
        // query does: transferring example.com. because www.example.com. was
        // asked for would hand over a zone nobody named.
        //
        // A snapshot, not the guard: the lock may not be held across writing a
        // whole zone to a socket, but the transfer must still be of one version
        // throughout. `Zones::snapshot` is an `Arc` of the version current now,
        // which reloads replace rather than mutate.
        let (zone, prepared) = {
            let zones = self.zone_map.read().await;
            let Some(zone) = zones.snapshot(apex.as_ref()) else {
                tracing::info!(peer = %ip, "{kind} of {qname}: NOTAUTH (not a zone served here)");
                self.send_transfer_error(
                    refused,
                    ResponseCode::NotAuthorized,
                    Some(NOT_OUR_ZONE),
                    session,
                    out,
                )
                .await;
                return;
            };
            if !incremental {
                (zone, Vec::new())
            } else {
                // Read under the zone lock, so the increments and the zone they
                // are increments of are the same version.
                let deltas = self.deltas.read().await;
                let built = ixfr_response(msg, &zone, &deltas).and_then(|response| {
                    match &response {
                        IxfrResponse::UpToDate(_) => {
                            tracing::info!(peer = %ip, "IXFR of {qname}: already current, sending one SOA")
                        }
                        IxfrResponse::Incremental { steps, records, .. } => tracing::info!(
                            peer = %ip,
                            "IXFR of {qname}: {records} record(s) across {steps} version(s)"
                        ),
                        IxfrResponse::FullTransfer { why, .. } => tracing::info!(
                            peer = %ip,
                            "IXFR of {qname}: sending the whole zone instead ({why})"
                        ),
                    }
                    // A full transfer is left unbuilt: the envelope iterator below
                    // exists not to materialize the zone. The rest is bounded by
                    // the delta log.
                    match response {
                        IxfrResponse::FullTransfer { .. } => Ok(Vec::new()),
                        other => other.messages(msg, &zone),
                    }
                });
                match built {
                    Ok(messages) => (zone, messages),
                    Err(e) => {
                        serving_error!(self.ctx.logger, ip, "{kind} of {qname}: {e}");
                        self.send_transfer_error(
                            refused,
                            ResponseCode::ServerFailure,
                            None,
                            session,
                            out,
                        )
                        .await;
                        return;
                    }
                }
            }
        };

        // One envelope at a time: built, serialized, signed, framed and handed to
        // the writer before the next one exists — hence an iterator rather than a
        // materialized zone. `+ Send` because it stays alive across the `await`
        // on every envelope, in a spawned task.
        let envelopes: Box<dyn Iterator<Item = DnsMessage> + Send + '_> = if prepared.is_empty() {
            match axfr_envelopes(msg, &zone) {
                Ok(envelopes) => Box::new(envelopes),
                Err(e) => {
                    // Nothing sent yet, so an ordinary error response still works.
                    serving_error!(self.ctx.logger, ip, "{kind} of {qname}: {e}");
                    self.send_transfer_error(
                        refused,
                        ResponseCode::ServerFailure,
                        None,
                        session,
                        out,
                    )
                    .await;
                    return;
                }
            }
        } else {
            Box::new(prepared.into_iter())
        };

        let mut records = 0;
        let mut sent = 0usize;
        for message in envelopes {
            records += message.answers.len();
            let bytes = match message.to_bytes_within(u16::MAX as usize) {
                Ok(bytes) => bytes,
                Err(e) => {
                    serving_error!(
                        self.ctx.logger,
                        ip,
                        "{kind} of {qname}: serialization error: {e}"
                    );
                    self.abandon_transfer(refused, session, sent, out).await;
                    return;
                }
            };
            // Every envelope is signed, and the MACs chain (RFC 8945 §5.3.1): a
            // dropped or reordered message then fails at the client instead of
            // passing for a complete zone.
            let bytes = match session.as_mut() {
                Some(session) => match session.sign(bytes, now) {
                    Ok(signed) => signed,
                    Err(e) => {
                        serving_error!(
                            self.ctx.logger,
                            ip,
                            "{kind} of {qname}: TSIG signing failed: {e}"
                        );
                        // Deliberately unsigned, if anything is sent at all:
                        // signing is what just failed.
                        self.abandon_transfer(refused, None, sent, out).await;
                        return;
                    }
                },
                None => bytes,
            };
            if !send_framed(out, &bytes).await {
                // Either the frame is impossible or the peer hung up. The first
                // needs the connection closed; the second closed it already.
                self.abandon_transfer(refused, None, sent, out).await;
                return;
            }
            sent += 1;
        }

        // A transfer is an answer too, and this is the only path that does not
        // go through `make_response`.
        self.ctx.metrics.count(&self.ctx.metrics.responses_sent);
        let how = match &authenticated_by {
            Some(key) => format!("key {key}"),
            None => format!("address {ip}"),
        };
        tracing::info!(
            peer = %ip,
            "{kind} of {qname}: {records} records in {sent} message(s), authenticated by {how}"
        );
    }

    /// Give up on a transfer, in whichever of the two ways is still available.
    ///
    /// Nothing sent yet means an error response. Once an envelope has gone there
    /// is no way back — an error response would be read as another envelope — so
    /// the connection is closed, and the missing closing SOA tells the client
    /// what it holds is not a zone (RFC 5936 §2.2).
    async fn abandon_transfer(
        &self,
        refused: Refused<'_>,
        session: Option<&mut TsigSession>,
        sent: usize,
        out: &mpsc::Sender<Reply>,
    ) {
        if sent == 0 {
            self.send_transfer_error(refused, ResponseCode::ServerFailure, None, session, out)
                .await;
            return;
        }
        tracing::error!(
            peer = %refused.ip,
            "transfer abandoned after {sent} envelope(s); closing the connection so the \
             client sees an incomplete stream rather than waiting for a closing SOA"
        );
        let _ = out.send(Reply::Abort).await;
    }

    /// [`Server::signed_error`], framed and sent.
    async fn send_transfer_error(
        &self,
        refused: Refused<'_>,
        rcode: ResponseCode,
        why: Option<ExtendedError>,
        session: Option<&mut TsigSession>,
        out: &mpsc::Sender<Reply>,
    ) {
        if let Some(bytes) = self.signed_error(refused, rcode, why, session) {
            send_framed(out, &bytes).await;
        }
    }

    /// One error reply, signed if the request was.
    ///
    /// RFC 8945 §5.3: an error response to a verified request is signed too.
    /// Unsigned, a client cannot tell a refusal from a tampered reply.
    ///
    /// `now` is the instant that verified the request, not a second read of the
    /// clock: [`Server::finish`] already signs with it, and a reply signed off
    /// a clock the request was not checked against is the one thing here that
    /// can disagree with itself (`TODO.md` #87).
    fn signed_error(
        &self,
        refused: Refused,
        rcode: ResponseCode,
        why: Option<ExtendedError>,
        session: Option<&mut TsigSession>,
    ) -> Option<Vec<u8>> {
        let Refused {
            msg,
            ip,
            now,
            max_len,
        } = refused;
        let Some(bytes) = error_reply(msg, rcode, why, max_len, self.ctx.udp.advertised()) else {
            serving_error!(self.ctx.logger, ip, "could not serialize an error response");
            return None;
        };
        match session {
            Some(session) => match session.sign(bytes, now) {
                Ok(signed) => Some(signed),
                Err(e) => {
                    // Send nothing: an unsigned error is what signing exists to
                    // avoid producing.
                    serving_error!(self.ctx.logger, ip, "signing an error response failed: {e}");
                    None
                }
            },
            None => Some(bytes),
        }
    }

    /// Answer a dynamic UPDATE (RFC 2136).
    ///
    /// Answered here rather than in `make_response`: gated on a permission, it
    /// touches the disk, and it changes what this server says next.
    ///
    /// Order: §3.1 reads the message, §3.1.1 asks whether the zone is ours,
    /// §3.3 whether the requestor may write it, §3.2 checks the prerequisites,
    /// and only then does §3.4 change anything. Zone before permission, so
    /// NOTAUTH and REFUSED tell a client whether to change server or key.
    /// Permission before §3.2, where the RFC lists it after: prerequisites
    /// answer NXDOMAIN/YXDOMAIN about the zone's contents, and BIND, Knot and
    /// PowerDNS all check permission first (`TODO.md` #118).
    async fn answer_update(
        &self,
        msg: &DnsMessage,
        peer: SocketAddr,
        session: Option<&mut TsigSession>,
        now: u64,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        let ip = peer.ip();
        // One for all thirteen ways out of this function, for the reason
        // `answer_transfer` builds its own.
        let refused = Refused {
            msg,
            ip,
            now,
            max_len,
        };

        // §3.1: read it, and reject the ways it can be malformed.
        let request = match update::parse(msg) {
            Ok(request) => request,
            Err(rejected) => {
                serving_error!(self.ctx.logger, ip, "UPDATE rejected: {rejected}");
                return self.signed_error(refused, rejected.rcode, None, session);
            }
        };
        let zone_name = request.zone.clone();

        // §3.1.1: a zone we are not an authority for is NOTAUTH — not the query
        // path's REFUSED, because an UPDATE names the zone and asks whether we
        // are its authority.
        //
        // Taken, not merely tested for, and in the one read guard: "do we serve
        // it" and the version the signer works against must be the same one.
        // `snapshot` rather than `matching(..).cloned()` — the map holds
        // `Arc<Zone>`, so this is a refcount and not a copy of the whole zone,
        // which was 150 ms at a million records (`TODO.md` #64a).
        let previous = {
            let zones = self.zone_map.read().await;
            zones.snapshot(zone_name.as_ref())
        };
        let Some(previous) = previous else {
            tracing::info!(peer = %ip, "UPDATE of {zone_name}: NOTAUTH (not a zone served here)");
            return self.signed_error(
                refused,
                ResponseCode::NotAuthorized,
                Some(NOT_OUR_ZONE),
                session,
            );
        };

        // §3.3: no permission, REFUSED. An unsigned UPDATE is refused outright,
        // with no address-based alternative: a write is not handed out on a
        // source address UDP makes nobody prove. A key is the only credential,
        // and it must be scoped (`rdns::tsig::UpdatePolicy`).
        let Some(session) = session else {
            serving_error!(
                self.ctx.logger,
                ip,
                "UPDATE of {zone_name} REFUSED: unsigned, and an UPDATE needs a TSIG key"
            );
            return self.signed_error(refused, ResponseCode::Refused, Some(NOT_YOURS), None);
        };
        if !session.may_update(&zone_name.as_ref().to_presentation()) {
            serving_error!(
                self.ctx.logger,
                ip,
                "UPDATE of {zone_name} REFUSED: key {} may not rewrite it",
                session.key_name()
            );
            return self.signed_error(
                refused,
                ResponseCode::Refused,
                Some(NOT_YOURS),
                Some(session),
            );
        }

        // A zone we replicate is the master's copy: the next refresh transfers
        // over the change, so accepting it tells the client a write succeeded
        // that has a timer on it. Folded through the helper the table is keyed
        // with, so the two cannot disagree.
        if self.secondaries.replicates(zone_name.as_ref()) {
            serving_error!(
                self.ctx.logger,
                ip,
                "UPDATE of {zone_name} REFUSED: this server replicates that zone, \
                 so its master owns it"
            );
            return self.signed_error(
                refused,
                ResponseCode::Refused,
                Some(REPLICATED_ZONE),
                Some(session),
            );
        }

        // A zone we cannot write back must not be updated: the change would live
        // in memory only and be discarded by the next reload, having told the
        // client it succeeded. See [`crate::UpdateHandling`].
        let Some(source) = self.updates.source.as_ref() else {
            serving_error!(
                self.ctx.logger,
                ip,
                "UPDATE of {zone_name} REFUSED: this server has no writable zone source"
            );
            return self.signed_error(
                refused,
                ResponseCode::Refused,
                Some(NOT_WRITABLE),
                Some(session),
            );
        };
        let path = match source.file_for(&zone_name.as_ref().to_presentation()) {
            Ok(Some(path)) => path,
            Ok(None) => {
                serving_error!(
                    self.ctx.logger,
                    ip,
                    "UPDATE of {zone_name} REFUSED: no zone file to write it back to"
                );
                return self.signed_error(
                    refused,
                    ResponseCode::Refused,
                    Some(NOT_WRITABLE),
                    Some(session),
                );
            }
            // SERVFAIL, not the REFUSED above: RFC 2136 §4.6 sends the client
            // to another server on SERVFAIL, and ends the update on REFUSED.
            Err(e) => {
                serving_error!(
                    self.ctx.logger,
                    ip,
                    "UPDATE of {zone_name} failed: reading the zone directory: {e}"
                );
                return self.signed_error(
                    refused,
                    ResponseCode::ServerFailure,
                    None,
                    Some(session),
                );
            }
        };

        // §3.7's serialization, held across the whole read-modify-write — and
        // the digests live under it, so "this is what we last wrote" is
        // guarded by the lock that made it true rather than remembered beside
        // it (`TODO.md` #64b).
        let mut digests = self.updates.applying.lock().await;
        let known = digests.get(&path).copied();
        // Cloned for the digest map below: the blocking task takes the original.
        let for_digest = path.clone();

        // Everything from here to the installed zone is blocking — a parse, a
        // full ECDSA signing run, and two file operations — so it goes to a
        // blocking thread rather than stalling a worker that is also answering
        // queries (`CLAUDE.md` §9).
        let signing = self.updates.signing.clone();
        let validator = Arc::clone(&self.updates.validator);
        let changes = request.changes.clone();
        let prerequisites = request.prerequisites.clone();
        let origin = zone_name.clone();
        let applied = tokio::task::spawn_blocking(move || {
            apply_update_to_file(
                &path,
                &origin.as_ref().to_presentation(),
                &previous,
                &prerequisites,
                &changes,
                SigningCheck {
                    signing: signing.as_deref(),
                    validator: &validator,
                },
                known,
            )
        })
        .await;

        let outcome = match applied {
            Ok(outcome) => outcome,
            Err(e) => {
                serving_error!(
                    self.ctx.logger,
                    ip,
                    "UPDATE of {zone_name}: the task failed: {e}"
                );
                return self.signed_error(
                    refused,
                    ResponseCode::ServerFailure,
                    None,
                    Some(session),
                );
            }
        };

        let (installed, report) = match outcome {
            Ok((installed, report, digest)) => {
                digests.insert(for_digest, digest);
                (installed, report)
            }
            Err(UpdateFailure::Prerequisite(rejected)) => {
                tracing::info!(peer = %ip, "UPDATE of {zone_name}: {rejected}");
                return self.signed_error(refused, rejected.rcode, None, Some(session));
            }
            // The two checks above this task answer the configuration's
            // spellings of "nowhere to write it"; this is the file's, and it
            // needs the bytes, which is why it is not up there with them.
            Err(UpdateFailure::NotWritable(why)) => {
                serving_error!(
                    self.ctx.logger,
                    ip,
                    "UPDATE of {zone_name} REFUSED: {}",
                    why.extra_text()
                );
                return self.signed_error(refused, ResponseCode::Refused, Some(why), Some(session));
            }
            // §3.4.2.1: a system failure is SERVFAIL with every applied update
            // undone. Nothing to undo here — the write is atomic and the map is
            // untouched until it succeeds.
            Err(UpdateFailure::System(e)) => {
                serving_error!(self.ctx.logger, ip, "UPDATE of {zone_name} failed: {e:#}");
                return self.signed_error(
                    refused,
                    ResponseCode::ServerFailure,
                    None,
                    Some(session),
                );
            }
        };

        for ignored in &report.ignored {
            // INFO: RFC 2136 has these dropped while the UPDATE still succeeds,
            // so the client is told nothing and only the log can say it.
            tracing::info!(peer = %ip, "UPDATE of {zone_name}: ignored {ignored}");
        }

        match installed {
            Some(zone) => {
                let serial = zone.serial();
                install_zone(&self.zone_context(), zone).await;
                tracing::info!(
                    peer = %ip,
                    "UPDATE of {zone_name} by key {}: {} record{} changed, serial now {}",
                    session.key_name(),
                    report.changed,
                    if report.changed == 1 { "" } else { "s" },
                    serial.map_or_else(|| "unknown".to_string(), |s| s.to_string())
                );
            }
            // Nothing written, nothing installed, and still NOERROR: a
            // well-formed permitted UPDATE whose prerequisites held (§3.4.2.5).
            None => tracing::info!(
                peer = %ip,
                "UPDATE of {zone_name} by key {}: nothing changed",
                session.key_name()
            ),
        }

        drop(digests);
        self.signed_error(refused, ResponseCode::Ok, None, Some(session))
    }

    /// The four things `install_zone` moves together — [`ZoneContext`].
    pub(crate) fn zone_context(&self) -> ZoneContext {
        ZoneContext {
            zone_map: Arc::clone(&self.zone_map),
            deltas: Arc::clone(&self.deltas),
            metrics: Arc::clone(&self.ctx.metrics),
            journal: self.journal.clone(),
        }
    }
}

/// Why a transfer or an UPDATE was refused: RFC 8914 §4.19's "a query from an
/// 'unauthorized' client", which covers all four ways permission is missing
/// here â no key, a key scoped elsewhere, an unsigned UPDATE, a key that may
/// not rewrite this zone. One reason for all four on purpose: telling a
/// stranger *which* of them it was is telling it about the keyring.
const NOT_YOURS: ExtendedError =
    ExtendedError::new(InfoCode::PROHIBITED, "not authorized for this zone");

/// A transfer this server would answer, over a connection it will not answer
/// it on (`--transfer-tls-only`, RFC 9103 §11).
///
/// Not PROHIBITED, which is about the client's credential: this client may be
/// perfectly authorized and asking on the wrong socket, and telling it so is
/// the difference between an operator adding a key it does not need and one
/// turning on the transport it does. RFC 8914 has no code for "use the
/// encrypted transport", so OTHER carries the sentence (§4.1).
const NOT_OVER_TLS: ExtendedError = ExtendedError::new(
    InfoCode::OTHER,
    "zone transfers here are over TLS 1.3 only (RFC 9103)",
);

/// A transfer asked for over a transport that carries one message. Not a
/// policy and not the client's fault, so OTHER again, and the sentence names
/// the transport rather than the server's configuration — there is nothing an
/// operator could turn on (`TODO.md` #106).
const ONE_MESSAGE_TRANSPORT: ExtendedError = ExtendedError::new(
    InfoCode::OTHER,
    "a zone transfer is a sequence of messages and DoH carries one (RFC 8484 §4.2)",
);

/// An UPDATE for a zone this server replicates. Not PROHIBITED â the
/// credential was good and the refusal is about where the zone is written, so
/// OTHER carries what the text says (§4.1: "does not match known extended
/// error codes").
const REPLICATED_ZONE: ExtendedError = ExtendedError::new(
    InfoCode::OTHER,
    "this zone is replicated here; its master owns it",
);

/// An UPDATE this server could apply and could not persist. Same reasoning as
/// [`REPLICATED_ZONE`]: an operator's configuration, not the client's
/// credential. Both spellings of it â no writable source at all, and no file
/// for this zone â answer the one question the client can act on.
const NOT_WRITABLE: ExtendedError = ExtendedError::new(
    InfoCode::OTHER,
    "this server has nowhere to write this zone back to",
);

/// The third spelling of it, and the one that is about the file rather than
/// the configuration: a zone file built out of `$INCLUDE`s cannot be written
/// back as one file without dropping the directive, so the file the operator's
/// other tooling maintains would stop being read with nothing said
/// (`TODO.md` #104).
const INCLUDES_ANOTHER_FILE: ExtendedError = ExtendedError::new(
    InfoCode::OTHER,
    "this zone's file $INCLUDEs another, so it cannot be written back as one",
);

/// A NOTIFY from an address the zone's `masters` list does not name. RFC 8914
/// §4.19's "a query from an 'unauthorized' client", which is what this is: the
/// sender is refused on its address, exactly as a transfer is.
const NOT_ITS_MASTER: ExtendedError =
    ExtendedError::new(InfoCode::PROHIBITED, "not one of this zone's masters");

/// A NOTIFY for a zone this server is the *primary* for. Not §4.21's Not
/// Authoritative, which would be a false statement — we are authoritative, and
/// §4.21's own text is about a query with RD clear rather than about a zone we
/// do not hold. OTHER carries the sentence (§4.1).
const NOT_A_SECONDARY: ExtendedError = ExtendedError::new(
    InfoCode::OTHER,
    "this server is this zone's primary, not a secondary",
);

/// A NOTIFY for a zone this server has never heard of. OTHER as well, and for
/// the same reading of §4.21 — the two NOTAUTHs here are exactly the
/// distinction the reply exists to carry, so they must not share a code.
const NO_SUCH_ZONE: ExtendedError = ExtendedError::new(InfoCode::OTHER, "not a zone served here");

/// The start of every reply that carries no records: the question echoed, and
/// the client's OPT mirrored with its DO bit (RFC 6891 §6.1.1, RFC 3225 §3).
///
/// One function because the mirroring is what drifts. It was written out at four
/// call sites, and three of them dropped the DO bit, so a validating client that
/// asked over UDP and got TC=1 read the answer as coming from a server that had
/// stopped doing DNSSEC (`TODO.md` #38, `CLAUDE.md` §7).
///
/// `why` is RFC 8914's reason for the RCODE, and rides in that OPT or nowhere
/// (§2) — which is [`ClientEdns::mirror_with`]'s rule, and so is what happens
/// to a reason that will not encode.
fn empty_reply(request: &DnsMessage, advertised: u16, why: Option<ExtendedError>) -> DnsMessage {
    let mut resp = DnsMessage::reply_to(request);
    if let Some(edns) = ClientEdns::of(request).mirror_with(advertised, why) {
        resp.set_edns(edns);
    }
    resp
}

/// A reply's ceiling with room kept for a signature.
///
/// Floored at the classic 512 rather than allowed to reach zero: the altered
/// response RFC 8945 §5.3 asks for is a question, an OPT and a TSIG, and it has
/// to fit somewhere. The floor is reachable only from a ceiling already at 512
/// with a long key name and hmac-sha512 — 362 octets of record — and a reply
/// that small plus its TSIG is still under the 512 every peer must accept.
fn reserve(ceiling: usize, signature: usize) -> usize {
    ceiling
        .saturating_sub(signature)
        .max(rdns::CLASSIC_UDP_SIZE as usize)
}

/// An empty reply to `request` carrying `rcode`, serialized within `max_len`.
///
/// The ceiling is [`rdns::UdpSizes::reply_ceiling`]'s, and it is the only thing
/// the UDP TSIG rejection's own copy of this used to differ in
/// (`TODO.md` #30g).
fn error_reply(
    request: &DnsMessage,
    rcode: ResponseCode,
    why: Option<ExtendedError>,
    max_len: usize,
    advertised: u16,
) -> Option<Vec<u8>> {
    let mut resp = empty_reply(request, advertised, why);
    resp.rcode = rcode;
    resp.to_bytes_within(max_len).ok()
}

/// Why an UPDATE could not be applied, split by what the client is owed.
///
/// A prerequisite that did not hold carries the RCODE RFC 2136 §3.2 assigns to
/// its form; everything else is §3.4.2.1's SERVFAIL. One type would make those
/// four codes indistinguishable from a full disk.
enum UpdateFailure {
    Prerequisite(update::Rejected),
    /// The file cannot be written back faithfully, so it is not a writable
    /// source — REFUSED, which is what the two checks above `answer_update`'s
    /// blocking task already answer for the configuration's spellings of the
    /// same thing. A third variant because the caller branches: this is not a
    /// full disk (`CLAUDE.md` §3).
    NotWritable(ExtendedError),
    System(anyhow::Error),
}

/// Apply an UPDATE to the zone as its *file* has it, persist it, sign it, check
/// what was signed, and return the version to install.
///
/// `Ok((None, report, digest))` when nothing changed: no write, nothing to
/// install, and the client still gets NOERROR. See [`crate::UpdateHandling`]
/// for why the file rather than the copy in memory is what gets read and
/// written.
///
/// Write then install: a crash between the two loses nothing, where the other
/// order serves a change that a restart makes disappear. The write is atomic
/// (`rdns::persist`), so the next reload sees one version or the other.
#[allow(clippy::type_complexity)]
fn apply_update_to_file(
    path: &Path,
    origin: &str,
    previous: &Zone,
    prerequisites: &[update::Prerequisite],
    changes: &[update::Change],
    check: SigningCheck<'_>,
    known: Option<FileDigest>,
) -> Result<(Option<Zone>, UpdateReport, FileDigest), UpdateFailure> {
    // The zone as the file has it: unsigned, on the operator's serial. Taken
    // from the file rather than from the served copy, so an edit since the last
    // load is not silently reverted.
    //
    // The *bytes* always; the parse only when they are not the bytes this
    // server last wrote (`TODO.md` #64b). Reading and digesting 24 MB is
    // 7.8 ms against 435 for the parse and index, so the honest test is 1.8%
    // of what it replaces. Why it is the bytes rather than a `stat` at 0.07 ms
    // is `FileDigest`'s own doc, which is where all three callers' copy of
    // that argument now lives (#104).
    let raw = std::fs::read(path)
        .with_context(|| format!("re-reading {} to update it", path.display()))
        .map_err(UpdateFailure::System)?;
    // The one place the shape of the file is judged, and the digest is what it
    // is judged for: `FileDigest::of` is only sound over text this process
    // wrote or a file known to carry no `$INCLUDE`, and this is neither until
    // asked. A digest of the parent says nothing about the included file, so a
    // remembered one would match while the include had moved — the operator's
    // change silently reverted (`TODO.md` #104, `CLAUDE.md` §2's rule about
    // where a check belongs).
    let Some(digest) = FileDigest::of_self_contained(&raw) else {
        return Err(UpdateFailure::NotWritable(INCLUDES_ANOTHER_FILE));
    };

    // Reusing the served copy is only sound with no signing configured: then it
    // *is* what the file holds, because the last thing written there was the
    // last thing installed. A signed server serves RRSIGs and NSECs the file
    // does not carry, and 64d measured the four O(zone) steps at 12% of a
    // signed update anyway — so the case worth having is this one.
    let reused = known == Some(digest) && check.signing.is_none();
    let parsed;
    let source = if reused {
        previous
    } else {
        let text = String::from_utf8(raw)
            .map_err(|_| anyhow::anyhow!("{} is not UTF-8", path.display()))
            .map_err(UpdateFailure::System)?;
        // `parse_zone_text_at`, not `parse_zone_file`: the latter has no base
        // directory and resolves `$INCLUDE` against the process's working
        // directory, where the loader resolves it against the file's. The
        // refusal above means no include reaches here, so this cannot differ
        // today — it is the right function for text that came from a path, and
        // two spellings of "parse this zone file" is what drifts (§7).
        parsed = rdns::zone::parse_zone_text_at(&text, origin, path)
            .with_context(|| format!("re-reading {} to update it", path.display()))
            .map_err(UpdateFailure::System)?;
        &parsed
    };

    // §3.2, against the unsigned zone: a prerequisite naming RRSIG or NSEC would
    // otherwise assert on this server's signing configuration.
    update::check_prerequisites(source, prerequisites).map_err(UpdateFailure::Prerequisite)?;

    let update::Applied {
        zone,
        changed,
        ignored,
    } = update::apply(source, changes);
    let report = UpdateReport { changed, ignored };
    if changed == 0 {
        // Nothing written, so the file is still what was just read.
        return Ok((None, report, digest));
    }

    let text = rdns::zone_writer::zone_to_string(&zone)
        .with_context(|| format!("writing {} back after an update", path.display()))
        .map_err(UpdateFailure::System)?;
    rdns::persist::write_atomically_str(path, &text)
        .with_context(|| format!("writing {} back after an update", path.display()))
        .map_err(UpdateFailure::System)?;
    // The bytes as written, so the next update can tell them from an edit. Off
    // the text rather than by re-reading it: the same bytes went to the file.
    let written = FileDigest::of(text.as_bytes());

    // Signed as a load would sign it, from the file's now-bumped serial, so the
    // served number moves too. Incrementally against the version being served:
    // a full re-sign would reinception every RRSIG and put the whole zone into
    // the next IXFR delta.
    // Verified before it is installed, which until `TODO.md` #100 no path did
    // for an UPDATE: `main.rs`'s two calls to `verify_zones` cover loading and
    // reloading, and this is the third way a zone reaches the map. The signing
    // call hands back something the zone cannot be got out of without asking,
    // so the check is the value's obligation rather than this function's memory
    // of it (`CLAUDE.md` §17).
    let installed = match check.signing {
        Some(signing) => signing
            .sign_one_incrementally(previous, zone)
            .and_then(|signed| signed.verify(check.validator, &names_changed(changes)))
            .map_err(UpdateFailure::System)?,
        None => zone,
    };
    Ok((Some(installed), report, written))
}

/// How an UPDATE's result is signed and checked before it is installed.
///
/// One parameter rather than two. Signing without verifying is the shape
/// `TODO.md` #100 found, and what let it happen is that the check was
/// something a call site had to remember rather than something the signing
/// arrived with (`CLAUDE.md` §17).
struct SigningCheck<'a> {
    signing: Option<&'a ZoneSigning>,
    validator: &'a DnssecValidator,
}

/// Every name the changes name, for [`crate::zones::FreshlySigned::verify`]'s
/// second set.
///
/// Not the same question as "what did the signer sign". A carry-forward that
/// kept a signature over data that moved leaves that RRset out of the fresh
/// list by definition, so a pass given only the fresh list would agree with
/// the one bug the incremental path can have that a full sign cannot
/// (`CLAUDE.md` §19). Deduping is `verify`'s, which has both sets.
fn names_changed(changes: &[update::Change]) -> Vec<Name> {
    changes
        .iter()
        .map(|change| match change {
            update::Change::Add(record) => record.name.clone(),
            update::Change::DeleteRrset { name, .. }
            | update::Change::DeleteName { name }
            | update::Change::DeleteRecord { name, .. } => name.clone(),
        })
        .collect()
}

/// What an UPDATE did, for the log line: the counts, without the zone.
///
/// `update::Applied` owns the zone it produced, and the unsigned path installs
/// that same zone — returning both meant cloning one of them, 9% of a
/// million-record update for a copy nobody read (`TODO.md` #64a). Splitting the
/// counts off is what makes the clone unavailable rather than merely unwise.
struct UpdateReport {
    changed: usize,
    ignored: Vec<update::Ignored>,
}

/// An empty TC=1 answer to `request`: the question echoed, no records.
///
/// What a client over its response budget gets instead of the answer: smaller
/// than the query, so useless for amplification, and RFC 1035 §4.2.1 has the
/// client retry over TCP, where the handshake proves the source address. Silence
/// would leave a legitimate client with a timeout and no hint that TCP works.
///
/// No AA — the reply carries no data — and bounded by the caller's ceiling,
/// which on the transport this can happen on is the smaller of the client's
/// EDNS payload size and this server's own, rather than 512 (RFC 6891 §6.2.4).
fn truncated_reply(request: &DnsMessage, max_len: usize, advertised: u16) -> Option<Vec<u8>> {
    let mut resp = empty_reply(request, advertised, None);
    resp.truncation = true;
    resp.to_bytes_within(max_len).ok()
}

/// Answer a NOTIFY (RFC 1996).
///
/// - A zone we replicate, from one of its masters: NOERROR, and the refresh task
///   is woken. The serial in the message is unauthenticated, so it is not acted
///   on — the refresh compares against what the master answers.
/// - A zone we replicate, from anywhere else: REFUSED (§3.10). A NOTIFY is a
///   spoofable datagram that costs its recipient a transfer, so who may send one
///   is a list.
/// - Anything else: NOTAUTH, "I am not a secondary for that zone" — true alike
///   for a zone we are primary for and one we never heard of, distinguished in
///   the log rather than the rcode.
///
/// Answered as a NOTIFY: same opcode, question echoed, no data (§4.7).
fn notify_reply(
    msg: &DnsMessage,
    zone_map: &ZoneMap,
    secondaries: &Secondaries,
    peer: SocketAddr,
    advertised: u16,
) -> DnsMessage {
    let zone = notify::notified_zone(msg).unwrap_or_default();

    match secondaries.notified(zone.as_ref(), peer.ip()) {
        Notified::Refreshing => {
            tracing::info!(%peer, "NOTIFY for {zone}: refreshing now");
            return notify::notify_response(msg, ResponseCode::Ok, advertised, None);
        }
        Notified::NotItsMaster => {
            tracing::warn!(
                %peer,
                "NOTIFY for {zone}: REFUSED (not one of its masters — \
                 a NOTIFY costs its recipient a transfer)"
            );
            return notify::notify_response(
                msg,
                ResponseCode::Refused,
                advertised,
                Some(NOT_ITS_MASTER),
            );
        }
        Notified::NotOurs => {}
    }

    // Folded octets, which is what the zone map is keyed on, so this is a lookup
    // rather than a scan of every origin. The fold is ASCII-only (RFC 4343) and
    // `Name` does it; `str::to_lowercase` would fold U+212A KELVIN SIGN onto `k`
    // and merge two names that differ on the wire.
    let ours = zone_map.contains_key(zone.as_ref().folded().as_ref());
    // The same distinction on the wire and in the log since #47. It used to be
    // the log alone, which is the half an operator on the *sending* side cannot
    // read.
    let why = if ours { NOT_A_SECONDARY } else { NO_SUCH_ZONE };
    tracing::info!(%peer, "NOTIFY for {zone}: NOTAUTH ({})", why.extra_text());
    notify::notify_response(msg, ResponseCode::NotAuthorized, advertised, Some(why))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::replication::Secondaries;
    use crate::testutil::{
        answered, nm, query, server_with, server_with_keys_at, spawn_primary_full,
        spawn_primary_with_keys, test_context, test_shutdown, update_key, update_message,
        zone_at_serial, ScratchDir,
    };
    use crate::zones::{load_zones, zone_key, ZoneSigning, ZoneSource, Zones};
    use crate::Scratch;
    use rdns::clock::{current_unix_timestamp, Clock};
    use rdns::dnssec_validation_mode::DnssecValidator;
    use rdns::ixfr::DeltaLog;
    use rdns::metrics::DnsMetrics;
    use rdns::security::{TransferAcl, TransferCertificates};
    use rdns::shutdown::Shutdown;
    use rdns::tsig::{self, TsigAlgorithm, TsigKey, TsigKeyring};
    use rdns::validation::{Arrival, Transport};
    use rdns::zone::{parse_zone_file_at, Zone};
    use rdns::{
        notify, record_types, DnsMessage, OpCode, Qtype, ResourceRecord, ResponseCode, Serial, Ttl,
        UdpSizes,
    };
    use rdns_transport::tcp::{self, Reply};
    use rdns_transport::TransportLimits;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::sync::{mpsc, RwLock};

    pub(crate) use rdns::testutil::one_at_a_time;

    /// Validation on, `--require-signed` off: what `serve` builds for a server
    /// that signs (`main.rs`'s `DnssecValidator::new`). Enabled, so the
    /// verification these tests drive actually runs — a disabled one returns
    /// `Unchecked` for everything and would make every assertion below about
    /// nothing.
    fn test_validator() -> DnssecValidator {
        DnssecValidator::new(true)
    }

    /// [`SigningCheck`] for a server that does not sign.
    fn unsigned(validator: &DnssecValidator) -> SigningCheck<'_> {
        SigningCheck {
            signing: None,
            validator,
        }
    }

    /// A zone of `records` A records under one apex, for the benchmarks.
    pub(crate) fn zone_text(records: usize) -> String {
        use std::fmt::Write as _;
        let mut text = String::new();
        text.push_str("$TTL 3600\n");
        text.push_str("@ IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n");
        text.push_str("@ IN NS ns.example.com.\n");
        text.push_str("ns IN A 192.0.2.1\n");
        for i in 0..records {
            let (a, b, c) = ((i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
            let _ = writeln!(text, "h{i} IN A 10.{a}.{b}.{c}");
        }
        text
    }

    /// What one dynamic UPDATE costs as the zone grows (`TODO.md` #64).
    ///
    /// `#[ignore]`d and refused in debug, as `rdns/tests/scale.rs` is: it
    /// builds zone files of up to a million records, and the question is what
    /// a deployment pays.
    ///
    /// ```text
    ///   records      total   re-read     apply to_string     write
    ///     10000     18.4ms    14.5ms     2.1ms     6.1ms     7.5ms
    ///    100000    150.0ms    41.2ms    22.1ms    64.3ms    19.5ms
    ///   1000000    1713.0ms   452.6ms   361.8ms   637.5ms   140.1ms
    /// ```
    ///
    /// Linear in the zone, at about 1.7 µs a record, and **four separate
    /// O(zone) steps for a one-record change**. The re-read is 26% of it and
    /// not the dominant term — `zone_to_string` is, at 37%.
    ///
    /// A fifth step, a `Zone::clone` nothing read, was 150.7 ms before #64a:
    /// `apply_update_to_file` returned the installed zone beside an
    /// `update::Applied` that owned another copy of it. [`UpdateReport`] has
    /// no zone, so there is no column to time.
    ///
    /// The total is printed in milliseconds because `{:.1?}` past a second is
    /// one significant figure, and both sides of that fix read "1.8s". Putting
    /// the `clone()` back separates them: **1907–1947 ms against 1694–1731**,
    /// six warm runs against five. Discard the first run after a rebuild — one
    /// read 1983.9 ms, 270 ms above the five that followed it.
    ///
    /// Unsigned. `sign_one_incrementally` is not in these numbers and has not
    /// been measured; #44c's 28 s is a *full* sign of a zone this size and is
    /// an upper bound that does not apply.
    ///
    /// This is the cold path throughout — the re-read column is what
    /// [`warm_update_cost_against_cold`] skips.
    ///
    /// All of it runs under `UpdateHandling::applying`, which is one lock for
    /// the whole process — so this is the server's update throughput, not one
    /// client's latency.
    #[test]
    #[ignore]
    fn update_cost_against_zone_size() {
        use std::time::Instant;

        let _turn = one_at_a_time();

        if cfg!(debug_assertions) {
            panic!(
                "this would measure the debug build. Run:\n  \
                 cargo test -p rdnsd --release update_cost -- --ignored --nocapture"
            );
        }

        let dir = std::env::temp_dir().join(format!("rdns-update-cost-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        println!(
            "{:>9}  {:>9} {:>9} {:>9} {:>9} {:>9}  {:>8}",
            "records", "total", "re-read", "apply", "to_string", "write", "file"
        );
        for records in [10_000usize, 100_000, 1_000_000] {
            let text = zone_text(records);
            let bytes = text.len();
            let path = dir.join("example.com.zone");
            std::fs::write(&path, &text).expect("write the fixture");

            let previous = parse_zone_file_at(&path, "example.com.").expect("the fixture parses");
            let change = update::Change::Add(rdns::ResourceRecord {
                name: nm("added.example.com."),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(3600),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                    std::net::Ipv4Addr::new(198, 51, 100, 1),
                ))
                .expect("the rdata builds"),
            });

            // The whole path, as `answer_update` calls it on its blocking task.
            let start = Instant::now();
            let (installed, applied, _) = apply_update_to_file(
                &path,
                "example.com.",
                &previous,
                &[],
                std::slice::from_ref(&change),
                unsigned(&test_validator()),
                None,
            )
            .unwrap_or_else(|_| panic!("the update applies at {records}"));
            let total = start.elapsed();
            assert_eq!(applied.changed, 1, "one record added at {records}");
            assert!(installed.is_some(), "a changed zone is installed");

            // The same four O(zone) steps, timed apart. Restore the file
            // first: the call above already added the record to it.
            std::fs::write(&path, &text).expect("restore the fixture");
            let start = Instant::now();
            let source = parse_zone_file_at(&path, "example.com.").expect("parses");
            let reread = start.elapsed();

            // What a "did the file change" test would cost instead of that
            // re-read (`TODO.md` #64b). Two candidates, and the question is
            // whether the cheap one is honest: `stat` cannot see an edit that
            // preserves length and timestamp, and a missed edit is an
            // operator's change silently reverted, which is the failure the
            // re-read exists to prevent (`CLAUDE.md` §4).
            let start = Instant::now();
            let meta = std::fs::metadata(&path).expect("stat");
            let stat_len = meta.len();
            let stat_at = meta.modified().expect("mtime");
            let stat = start.elapsed();
            let start = Instant::now();
            let raw = std::fs::read(&path).expect("read");
            let read = start.elapsed();
            let start = Instant::now();
            let digest = {
                use std::hash::{Hash, Hasher};
                let mut h = std::collections::hash_map::DefaultHasher::new();
                raw.hash(&mut h);
                h.finish()
            };
            let hash = start.elapsed();
            let _ = (stat_len, stat_at, digest);
            println!(
                "{:>9}  stat {:>9.3?}  read {:>9.3?}  hash {:>9.3?}  re-read {:>9.3?}",
                records, stat, read, hash, reread
            );
            let start = Instant::now();
            let applied = update::apply(&source, std::slice::from_ref(&change));
            let apply = start.elapsed();
            let start = Instant::now();
            let out = rdns::zone_writer::zone_to_string(&applied.zone).expect("writes");
            let to_string = start.elapsed();
            let start = Instant::now();
            rdns::persist::write_atomically_str(&path, &out).expect("persists");
            let write = start.elapsed();
            // Total in milliseconds whatever its size: `{:.1?}` switches to
            // seconds past 1 s, and one significant figure there is coarser
            // than the run-to-run spread of the columns it sums.
            println!(
                "{records:>9}  {:>7.1}ms {reread:>9.1?} {apply:>9.1?} {to_string:>9.1?} {write:>9.1?}  {:>6} KB",
                total.as_secs_f64() * 1000.0,
                bytes / 1024
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What skipping the re-read saves: the same update, cold against warm
    /// (`TODO.md` #64b).
    ///
    /// ```text
    ///   records       cold      warm     saved
    ///     10000     21.4ms    15.7ms       27%
    ///    100000    164.1ms   104.5ms       36%
    ///   1000000   1905.8ms  1178.1ms       38%
    /// ```
    ///
    /// Every iteration starts from the *same* state — the file holds exactly
    /// what the served zone serializes to, and the digest is the digest of
    /// those bytes, which the assertion below checks — so the only difference
    /// between a cold iteration and a warm one is whether `known` is supplied.
    /// Alternating rather than one of each, because what a call costs depends
    /// on where in the process's life it falls, and one of each charges that
    /// difference to the thing under test. The first version of this
    /// measurement did exactly that and read 1-5% at a million records
    /// (`CLAUDE.md` §1).
    ///
    /// The saving *grows* with the zone, because it is the parse plus the
    /// freeing of what the parse built, less a read and a hash — see #64b for
    /// that decomposition, which sums to the total within 2 ms.
    #[test]
    #[ignore]
    fn warm_update_cost_against_cold() {
        use std::time::Instant;

        let _turn = one_at_a_time();

        if cfg!(debug_assertions) {
            panic!(
                "this would measure the debug build. Run:\n  \
                 cargo test -p rdnsd --release warm_update_cost -- --ignored --nocapture"
            );
        }

        let dir = std::env::temp_dir().join(format!("rdns-warm-update-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        println!(
            "{:>9}  {:>9} {:>9} {:>9}",
            "records", "cold", "warm", "saved"
        );
        for records in [10_000usize, 100_000, 1_000_000] {
            let path = dir.join("example.com.zone");
            std::fs::write(&path, zone_text(records)).expect("write the fixture");
            let mut served = parse_zone_file_at(&path, "example.com.").expect("the fixture parses");
            let mut digest = FileDigest::of(&std::fs::read(&path).expect("read the fixture"));
            let mut cold = Vec::new();
            let mut warm = Vec::new();

            for round in 0..6 {
                let reuse = round % 2 == 1;
                // A record nobody has added yet: an UPDATE that changes nothing
                // returns before serializing, which would time the early exit
                // and read as a win (`CLAUDE.md` §1).
                let change = update::Change::Add(rdns::ResourceRecord {
                    name: nm(&format!("added-{round}.example.com.")),
                    class: rdns::Class::new(1),
                    ttl: rdns::Ttl::from_secs(3600),
                    rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                        std::net::Ipv4Addr::new(198, 51, 100, round + 1),
                    ))
                    .expect("the rdata builds"),
                });
                let start = Instant::now();
                let (installed, report, written) = apply_update_to_file(
                    &path,
                    "example.com.",
                    &served,
                    &[],
                    std::slice::from_ref(&change),
                    unsigned(&test_validator()),
                    if reuse { Some(digest) } else { None },
                )
                .unwrap_or_else(|_| panic!("the update applies at {records}"));
                let elapsed = start.elapsed().as_secs_f64() * 1e3;
                assert_eq!(report.changed, 1, "one record added at {records}");
                served = installed.unwrap_or_else(|| panic!("a changed zone at {records}"));
                digest = written;
                // The premise of the comparison: whatever the call did, the
                // next iteration starts from a file that is what the served
                // zone serializes to, and from its digest. Without this the two
                // kinds of iteration would differ in more than `known`.
                assert_eq!(
                    digest,
                    FileDigest::of(&std::fs::read(&path).expect("read back")),
                    "the digest returned is the digest of the file at {records}"
                );
                if reuse { &mut warm } else { &mut cold }.push(elapsed);
            }

            let mean = |runs: &[f64]| runs.iter().sum::<f64>() / runs.len() as f64;
            let (cold, warm) = (mean(&cold), mean(&warm));
            println!(
                "{records:>9}  {cold:>7.1}ms {warm:>7.1}ms {:>8.0}%",
                (cold - warm) / cold * 100.0
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What the *signed* update path costs, which the table above does not
    /// measure (`TODO.md` #64d).
    ///
    /// The question the row asks: does `sign_one_incrementally` swamp the four
    /// O(zone) steps, making 64b's 26% and 64c's 42% shares of something that
    /// barely matters? **It does.**
    ///
    /// ```text
    ///   records   unsigned     signed  incr-sign     verify  full-sign      carried
    ///     10000     15.5ms    83.6ms    51.5ms      0.4ms   251.5ms  20004/20008
    ///    100000     95.1ms   715.0ms   627.8ms      2.3ms  2568.4ms  200004/200008
    ///   1000000   1326.2ms  9788.0ms  8832.5ms     21.1ms 27801.1ms  2000004/2000008
    /// ```
    ///
    /// Three warm runs, discarding the first after a rebuild. At a million
    /// records **signing is 8.8 s of 9.8 s, 90%**, so the whole of 64b and
    /// 64c — 68% of the unsigned 1.33 s — is **9% of what a signed update
    /// costs**. `full-sign` reproduces #44c's 28 s by a different route.
    ///
    /// `verify` is what `TODO.md` #100 added: the RRsets this run signed, plus
    /// every signed RRset at a name the update named. **21 ms at a million
    /// records, 0.2% of the signed update** — against the 76 s a whole-zone
    /// `verify_zones` pass costs at that size (#53), which is why it is the
    /// change and not the pass.
    ///
    /// Re-measured 2026-09-21 on the development machine, all columns, when
    /// #100 added the fifth. The four that existed before read 20.7 / 87.0 /
    /// 55.8 / 245.7 at ten thousand and 1952.1 / 11801.0 / 10314.9 / 26939.1
    /// at a million; the shape is the same and the machine was not.
    ///
    /// A real [`ZoneSigning`] rather than a bare `sign_zone_incrementally`, so
    /// the column is the whole path an operator pays. The row filed this as
    /// wanting "signing keys on disk", and it does — but generated ones,
    /// written out by `SigningKey::write_to_dir`, not an operator's.
    ///
    /// `carried` is how many of the installed zone's RRSIGs are byte-identical
    /// to one at the same owner in the served version, over how many there
    /// are: a count rather than a timing, so it reads the same on every
    /// machine. **Four are made fresh at every size** — the A RRset added, the
    /// two NSECs the insertion moves, and the bumped SOA — which is what makes
    /// the 10.3 s the interesting number. It is not the ECDSA. Carrying every
    /// signature forward still pays `PreviousSignatures::of` over the served
    /// zone, `carry_over_records`, `Layout::of` and a full NSEC chain, all
    /// O(zone); `sign_zone_incrementally`'s header argues for building the
    /// chain in full and is right, and this is what that costs (`TODO.md`
    /// #64e).
    ///
    /// NSEC, one ECDSA P-256 KSK and one ZSK, which is the cheap end: NSEC3
    /// hashes every name, and a second algorithm signs every RRset twice.
    #[test]
    #[ignore]
    fn signed_update_cost_against_zone_size() {
        use clap::Parser;
        use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
        use rdns::zone_signer::sign_zone;
        use std::collections::{BTreeMap, HashSet};
        use std::time::Instant;

        let _turn = one_at_a_time();

        if cfg!(debug_assertions) {
            panic!(
                "this would measure the debug build. Run:\n  \
                 cargo test -p rdnsd --release signed_update_cost -- --ignored --nocapture"
            );
        }

        let dir = std::env::temp_dir().join(format!("rdns-signed-update-{}", std::process::id()));
        let key_dir = dir.join("keys");
        std::fs::create_dir_all(&key_dir).expect("temp dirs");
        let keys: Vec<SigningKey> = [
            rdns::dnssec::DNSKEY_FLAG_ZONE | rdns::dnssec::DNSKEY_FLAG_SEP,
            rdns::dnssec::DNSKEY_FLAG_ZONE,
        ]
        .into_iter()
        .map(|flags| {
            let key =
                SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, "example.com.", flags)
                    .expect("a key");
            key.write_to_dir(&key_dir).expect("the key file");
            key
        })
        .collect();
        let mut cli = crate::Cli::parse_from(["rdnsd"]);
        cli.signing_key_dir = Some(key_dir);
        let signing = ZoneSigning::load(&cli, &BTreeMap::new())
            .expect("the keys load")
            .expect("a key directory means signing");

        println!(
            "{:>9}  {:>9} {:>9} {:>9} {:>9} {:>9}  {:>9}",
            "records", "unsigned", "signed", "incr-sign", "verify", "full-sign", "carried"
        );
        for records in [10_000usize, 100_000, 1_000_000] {
            use std::fmt::Write as _;
            let mut text = String::from("$TTL 3600\n");
            text.push_str(
                "@ IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n",
            );
            text.push_str("@ IN NS ns.example.com.\n");
            text.push_str("ns IN A 192.0.2.1\n");
            for i in 0..records {
                let (a, b, c) = ((i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
                let _ = writeln!(text, "h{i} IN A 10.{a}.{b}.{c}");
            }
            let path = dir.join("example.com.zone");
            std::fs::write(&path, &text).expect("write the fixture");

            let source = parse_zone_file_at(&path, "example.com.").expect("the fixture parses");
            let policy = signing.policy_for("example.com.", current_unix_timestamp());
            // The served version: what an update signs *against*.
            let start = Instant::now();
            let previous = sign_zone(&source, &keys, &policy).expect("the fixture signs");
            let full_sign = start.elapsed();
            drop(source);

            let change = update::Change::Add(rdns::ResourceRecord {
                name: nm("added.example.com."),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(3600),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                    std::net::Ipv4Addr::new(198, 51, 100, 1),
                ))
                .expect("the rdata builds"),
            });

            // Both paths through the same door, so the difference between the
            // columns is the signing and nothing else. The file is restored
            // between them: the first call already added the record to it.
            let start = Instant::now();
            apply_update_to_file(
                &path,
                "example.com.",
                &previous,
                &[],
                std::slice::from_ref(&change),
                unsigned(&test_validator()),
                None,
            )
            .unwrap_or_else(|_| panic!("the unsigned update applies at {records}"));
            let unsigned = start.elapsed();

            std::fs::write(&path, &text).expect("restore the fixture");
            let start = Instant::now();
            let (installed, report, _digest) = apply_update_to_file(
                &path,
                "example.com.",
                &previous,
                &[],
                std::slice::from_ref(&change),
                SigningCheck {
                    signing: Some(&signing),
                    validator: &test_validator(),
                },
                None,
            )
            .unwrap_or_else(|_| panic!("the signed update applies at {records}"));
            let signed = start.elapsed();
            assert_eq!(report.changed, 1, "one record added at {records}");
            let installed = installed.expect("a changed zone is installed");

            // The signing step alone, from the same inputs the call above fed
            // it, so `signed` minus this and `verify` is the four unsigned
            // steps. Timed apart because they are different questions: one is
            // the ECDSA and the carry-forward, the other is what `TODO.md`
            // #100 added.
            std::fs::write(&path, &text).expect("restore the fixture");
            let reparsed = parse_zone_file_at(&path, "example.com.").expect("parses");
            let applied = update::apply(&reparsed, std::slice::from_ref(&change));
            let start = Instant::now();
            let fresh = signing
                .sign_one_incrementally(&previous, applied.zone)
                .expect("signs");
            let incr_sign = start.elapsed();
            let start = Instant::now();
            let again = fresh
                .verify(
                    &test_validator(),
                    &names_changed(std::slice::from_ref(&change)),
                )
                .expect("verifies");
            let verify = start.elapsed();
            assert_eq!(
                again.records().len(),
                installed.records().len(),
                "the same zone either way at {records}"
            );

            let rrsig = rdns::record_types::RRSIG;
            let was: HashSet<(rdns::NameRef<'_>, &[u8])> = previous
                .records()
                .iter()
                .filter(|r| r.rdata.rtype() == rrsig)
                .map(|r| (r.name, r.rdata.bytes()))
                .collect();
            let now: Vec<_> = installed
                .records()
                .iter()
                .filter(|r| r.rdata.rtype() == rrsig)
                .collect();
            let carried = now
                .iter()
                .filter(|r| was.contains(&(r.name, r.rdata.bytes())))
                .count();
            // Made fresh, not carried: what the run actually paid ECDSA for.
            let made = now.len() - carried;
            println!(
                "{records:>9}  {:>7.1}ms {:>7.1}ms {:>7.1}ms {:>7.1}ms {:>7.1}ms  {:>9}",
                unsigned.as_secs_f64() * 1000.0,
                signed.as_secs_f64() * 1000.0,
                incr_sign.as_secs_f64() * 1000.0,
                verify.as_secs_f64() * 1000.0,
                full_sign.as_secs_f64() * 1000.0,
                format!("{carried}/{}", now.len()),
            );
            assert!(
                made < 16,
                "a one-record update re-signed {made} RRsets at {records}: the carry-forward \
                 is what makes incr-sign cheaper than full-sign, so this number is the claim"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An UPDATE to a zone whose file `$INCLUDE`s another is refused, not
    /// applied against the wrong file.
    ///
    /// Two defects, and the first hid the second (`TODO.md` #104).
    ///
    /// The parse was `parse_zone_file(&text, origin)`, which has no base
    /// directory and so resolves `$INCLUDE` against the *process's* working
    /// directory — where the reload path uses `parse_zone_file_at` and
    /// resolves it against the zone file's. So the same file parsed to two
    /// different zones depending on which path read it, and usually to an
    /// error here.
    ///
    /// Underneath it: the digest was `FileDigest::of` over bytes read off
    /// disk, which the type's doc restricts to text this process wrote or a
    /// file known to carry no `$INCLUDE`. A no-op UPDATE stores that digest,
    /// and a later one then matches it while the *included* file has moved —
    /// the operator's change silently reverted, which is the failure the
    /// re-read exists to prevent (`CLAUDE.md` §4). Unreachable only because
    /// the parse above failed first.
    ///
    /// Refused rather than flattened. Writing the zone back with
    /// `zone_to_string` inlines the include and drops the directive, so the
    /// file the operator's other tooling maintains stops being read with
    /// nothing said — and REFUSED is what the two other "this is not a
    /// writable source" checks already answer.
    #[test]
    fn an_update_to_a_zone_file_that_includes_another_is_refused() {
        let dir = rdns::testutil::ScratchDir::new("update-include");
        dir.write("hosts.inc", "www IN A 192.0.2.9\n");
        let path = dir.write(
            "example.com.zone",
            concat!(
                "$TTL 3600\n",
                "@ IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n",
                "@ IN NS ns.example.com.\n",
                "$INCLUDE hosts.inc\n",
            ),
        );
        let served = parse_zone_file_at(&path, "example.com.").expect("the fixture parses");
        assert_eq!(
            served
                .query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A))
                .len(),
            1,
            "the loader resolves the include against the zone file's directory"
        );

        let change = update::Change::Add(rdns::ResourceRecord {
            name: nm("added.example.com."),
            class: rdns::Class::new(1),
            ttl: rdns::Ttl::from_secs(3600),
            rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(std::net::Ipv4Addr::new(
                198, 51, 100, 4,
            )))
            .expect("the rdata builds"),
        });
        let outcome = apply_update_to_file(
            &path,
            "example.com.",
            &served,
            &[],
            std::slice::from_ref(&change),
            unsigned(&test_validator()),
            None,
        );
        match outcome {
            Err(UpdateFailure::NotWritable(why)) => {
                assert!(
                    why.extra_text().contains("$INCLUDE"),
                    "the client is told which shape of file it is: {:?}",
                    why.extra_text()
                );
            }
            Err(UpdateFailure::System(e)) => {
                panic!("SERVFAIL for a file we can read perfectly well: {e:#}")
            }
            Err(UpdateFailure::Prerequisite(r)) => panic!("no prerequisites were given: {r}"),
            Ok(_) => panic!("the include was flattened away instead of refused"),
        }

        // And the file is untouched, so the operator's other tooling still
        // owns what it wrote.
        assert!(
            std::fs::read_to_string(&path)
                .expect("still there")
                .contains("$INCLUDE hosts.inc"),
            "a refused update writes nothing"
        );
    }

    /// Every encrypted transport gets its own dnstap label.
    ///
    /// `TODO.md` #54: the dispatcher was told [`Privacy`], which is `Clear`,
    /// `Tls13` or `TlsOlder`, so DoT, DoH and DoQ were one value and the field
    /// was left *absent* rather than guessed at — a reader showing nothing
    /// where it should show three different things. Against the old code the
    /// last three rows here read `None`.
    ///
    /// A table rather than a live exchange: the mapping is what changed, and
    /// `record_dnstap` needs a sink, a socket and a parsed message to reach.
    /// The rule the re-read exists for, kept while the re-read is skipped:
    /// an edit made under a running server is not silently reverted
    /// (`TODO.md` #64b).
    ///
    /// Three updates against one file. The first has no remembered digest and
    /// parses. The second is handed the digest the first returned and must
    /// still produce the same zone — that is the fast path. The third is handed
    /// that same digest after the file has been *edited* underneath, and must
    /// see the edit: the digest no longer matches, so the parse happens.
    ///
    /// Fails against a `stat`-based test on the third case whenever the edit
    /// preserves length and timestamp, and fails against reusing the served
    /// copy unconditionally on the third case always.
    #[test]
    fn an_edit_under_a_running_server_is_seen_even_when_the_re_read_is_skipped() {
        let dir = rdns::testutil::ScratchDir::new("update-digest");
        // Column zero: a leading space makes the parser read the owner name as
        // omitted (`TODO.md` #60, in a fixture).
        let text = concat!(
            "$TTL 3600\n",
            "@ IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n",
            "@ IN NS ns.example.com.\n",
            "ns IN A 192.0.2.1\n",
        );
        let path = dir.write("example.com.zone", text);
        let served = parse_zone_file_at(&path, "example.com.").expect("the fixture parses");

        let add = |name: &str, last: u8| {
            update::Change::Add(rdns::ResourceRecord {
                name: nm(name),
                class: rdns::Class::new(1),
                ttl: rdns::Ttl::from_secs(3600),
                rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                    std::net::Ipv4Addr::new(198, 51, 100, last),
                ))
                .expect("the rdata builds"),
            })
        };

        // No digest yet: the file is parsed.
        let (installed, report, digest) = apply_update_to_file(
            &path,
            "example.com.",
            &served,
            &[],
            std::slice::from_ref(&add("one.example.com.", 1)),
            unsigned(&test_validator()),
            None,
        )
        .unwrap_or_else(|_| panic!("the first update applies"));
        assert_eq!(report.changed, 1);
        let served = installed.expect("a changed zone is installed");

        // The digest matches what was written, so the served copy is reused.
        let (installed, report, digest) = apply_update_to_file(
            &path,
            "example.com.",
            &served,
            &[],
            std::slice::from_ref(&add("two.example.com.", 2)),
            unsigned(&test_validator()),
            Some(digest),
        )
        .unwrap_or_else(|_| panic!("the second update applies"));
        assert_eq!(report.changed, 1);
        let served = installed.expect("a changed zone is installed");
        assert!(
            served
                .query(
                    nm("one.example.com.").as_ref(),
                    Qtype::of(rdns::record_types::A)
                )
                .len()
                == 1,
            "the first update survived the one that reused the served copy"
        );

        // An operator edits the file. The digest is stale, so the edit is read.
        let edited = format!(
            "{text}edited IN A 203.0.113.9
"
        );
        std::fs::write(&path, &edited).expect("the operator edits the file");
        let (installed, report, _) = apply_update_to_file(
            &path,
            "example.com.",
            &served,
            &[],
            std::slice::from_ref(&add("three.example.com.", 3)),
            unsigned(&test_validator()),
            Some(digest),
        )
        .unwrap_or_else(|_| panic!("the third update applies"));
        assert_eq!(report.changed, 1);
        let installed = installed.expect("a changed zone is installed");
        assert_eq!(
            installed
                .query(
                    nm("edited.example.com.").as_ref(),
                    Qtype::of(rdns::record_types::A)
                )
                .len(),
            1,
            "the operator's edit is in the zone that was installed"
        );
    }

    /// A signed UPDATE's own signatures are checked before the zone is
    /// installed.
    ///
    /// The whole of `TODO.md` #100 through the door an UPDATE comes in at, and
    /// the first test of the signed path that is not one of the `#[ignore]`d
    /// benchmarks above. The assertion is that the RRsets the update moved —
    /// the added A, the SOA, the NSECs the insertion shifts — verify against
    /// the zone's own keys after the install, which is what the call now
    /// refuses to skip.
    #[test]
    fn a_signed_update_verifies_what_it_signed() {
        use clap::Parser;
        use rdns::dnssec_key::{SigningAlgorithm, SigningKey};
        use rdns::zone_signer::sign_zone;
        use std::collections::BTreeMap;

        let dir = rdns::testutil::ScratchDir::new("signed-update-verify");
        let key_dir = dir.path().join("keys");
        std::fs::create_dir_all(&key_dir).expect("the key directory");
        let key = SigningKey::generate(
            SigningAlgorithm::Ed25519,
            "example.com.",
            rdns::dnssec::DNSKEY_FLAG_ZONE,
        )
        .expect("a key");
        key.write_to_dir(&key_dir).expect("the key file");
        let mut cli = crate::Cli::parse_from(["rdnsd"]);
        cli.signing_key_dir = Some(key_dir);
        let signing = ZoneSigning::load(&cli, &BTreeMap::new())
            .expect("the keys load")
            .expect("a key directory means signing");

        let path = dir.write(
            "example.com.zone",
            concat!(
                "$TTL 3600\n",
                "@ IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n",
                "@ IN NS ns.example.com.\n",
                "ns IN A 192.0.2.1\n",
                "www IN A 192.0.2.2\n",
            ),
        );
        let source = parse_zone_file_at(&path, "example.com.").expect("the fixture parses");
        let served = sign_zone(
            &source,
            std::slice::from_ref(&key),
            &signing.policy_for("example.com.", current_unix_timestamp()),
        )
        .expect("the fixture signs");

        let change = update::Change::Add(rdns::ResourceRecord {
            name: nm("added.example.com."),
            class: rdns::Class::new(1),
            ttl: rdns::Ttl::from_secs(3600),
            rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(std::net::Ipv4Addr::new(
                198, 51, 100, 4,
            )))
            .expect("the rdata builds"),
        });
        let validator = test_validator();
        let (installed, report, _) = apply_update_to_file(
            &path,
            "example.com.",
            &served,
            &[],
            std::slice::from_ref(&change),
            SigningCheck {
                signing: Some(&signing),
                validator: &validator,
            },
            None,
        )
        .unwrap_or_else(|e| match e {
            UpdateFailure::System(e) => panic!("the signed update applies: {e:#}"),
            UpdateFailure::Prerequisite(r) => panic!("no prerequisites were given: {r}"),
            UpdateFailure::NotWritable(why) => {
                panic!("the fixture is writable: {}", why.extra_text())
            }
        });
        assert_eq!(report.changed, 1);
        let installed = installed.expect("a changed zone is installed");

        // The same question the install now answers, asked again from outside
        // it: every signature in the zone, not only the ones this run made.
        // A pass that agrees with the signer is not evidence (`CLAUDE.md` §1),
        // and this one is the whole-zone check the UPDATE path cannot afford.
        let keys = rdns::dnssec_validation_mode::ZoneKeys::of(&installed);
        assert!(keys.is_signed(), "the installed zone carries its DNSKEYs");
        for (name, rtype) in crate::zones::signed_rrsets(&installed) {
            let records = installed.query(name.as_ref(), Qtype::of(rtype));
            assert!(
                validator
                    .validate_rrset(&installed, &keys, &records)
                    .is_valid(),
                "the {rtype} RRset at {name} does not verify after the update"
            );
        }
    }

    #[test]
    fn a_dnstap_entry_names_the_transport_including_the_encrypted_three() {
        use rdns::validation::{PeerCertificate, TlsVersion};
        let (tx, _rx) = mpsc::channel::<Reply>(1);
        let cases = [
            (Arrival::Tcp, dnstap::SocketProtocol::Tcp),
            (
                Arrival::Dot(TlsVersion::Tls13, PeerCertificate::none()),
                dnstap::SocketProtocol::Dot,
            ),
            // The version does not change the label: DoT over 1.2 is still DoT,
            // and it is `Privacy` that decides whether a transfer may use it.
            (
                Arrival::Dot(TlsVersion::Older, PeerCertificate::none()),
                dnstap::SocketProtocol::Dot,
            ),
            (
                Arrival::Doh(TlsVersion::Tls13, PeerCertificate::none()),
                dnstap::SocketProtocol::Doh,
            ),
            (
                Arrival::Doq(PeerCertificate::none()),
                dnstap::SocketProtocol::Doq,
            ),
        ];
        for (arrival, expected) in cases {
            assert_eq!(
                Wire::Framed(&tx, arrival.clone()).socket_protocol(),
                expected,
                "{arrival:?}"
            );
        }
    }

    /// Every reply built away from `answer.rs` mirrors the client's OPT the
    /// same way that file does — RFC 6891 §6.1.1 for the record, RFC 3225 §3
    /// for the DO bit inside it.
    ///
    /// `truncated_reply` and what is now `error_reply` each set an OPT of their
    /// own with DO clear, so a validating client asking over UDP and getting
    /// TC=1 read the answer as coming from a server that had dropped DNSSEC
    /// (`CLAUDE.md` §7). Both go through [`empty_reply`] since #39c, so this
    /// covers both: a mirror written a third time is the way this comes back.
    #[test]
    fn every_empty_reply_mirrors_the_clients_opt() {
        let udp = UdpSizes::default();
        let asked = query("www.example.com.", Qtype::of(record_types::A), true);
        let ceiling = udp.reply_ceiling(&asked, Transport::Udp);

        let bytes = truncated_reply(&asked, ceiling, udp.advertised()).expect("a truncated reply");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("it parses");
        assert!(reply.truncation, "TC=1");
        assert!(
            reply
                .edns()
                .expect("an OPT, since the query had one")
                .do_bit
        );

        let bytes = error_reply(
            &asked,
            ResponseCode::Refused,
            None,
            ceiling,
            udp.advertised(),
        )
        .expect("an error reply");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("it parses");
        assert_eq!(reply.rcode, ResponseCode::Refused);
        assert!(reply.edns().expect("an OPT").do_bit, "and so does this one");

        let plain = query("www.example.com.", Qtype::of(record_types::A), false);
        let ceiling = udp.reply_ceiling(&plain, Transport::Udp);
        for bytes in [
            truncated_reply(&plain, ceiling, udp.advertised()).expect("a truncated reply"),
            error_reply(
                &plain,
                ResponseCode::Refused,
                None,
                ceiling,
                udp.advertised(),
            )
            .expect("an error reply"),
        ] {
            let reply = DnsMessage::try_from_bytes(&bytes).expect("it parses");
            assert!(!reply.edns().expect("an OPT").do_bit, "and only when asked");
        }
    }

    /// A NOTIFY is acted on when it comes from a master of a zone we replicate,
    /// refused when it does not, and NOTAUTH for anything we are not a secondary
    /// for — three different answers to three different situations.
    #[test]
    fn test_notify_is_answered_by_what_the_zone_is_to_us() {
        let secondaries = Secondaries::replicating(&[rdns::secondary::MasterSpec {
            zone: nm("replicated.test."),
            master: "192.0.2.1:53".parse().expect("a test address"),
            key_name: None,
            tls: None,
        }]);

        let primary_zone = rdns::zone::parse_zone_file(
            "$TTL 3600\n\
             @    IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400\n\
             @    IN NS  ns1.example.com.\n\
             ns1  IN A   192.0.2.1\n",
            "example.com.",
        )
        .expect("zone");
        let mut zones = HashMap::new();
        zones.insert(zone_key(&primary_zone), std::sync::Arc::new(primary_zone));

        // The NOTIFY carries an OPT, because #47 is about what comes back in
        // one: RFC 6891 §6.1.1's MUST applies to a *request*, and a NOTIFY is
        // one.
        let from = |zone: &str, ip: &str| {
            let mut msg = notify::notify_request(nm(zone).as_ref(), None, 1);
            msg.set_edns(rdns::Edns::with_payload_size(1232));
            let peer: SocketAddr = format!("{ip}:5353").parse().unwrap();
            notify_reply(&msg, &zones, &secondaries, peer, 1232)
        };
        let why = |reply: &DnsMessage| {
            let edns = reply.edns().expect("the sender's OPT is mirrored");
            ExtendedError::all_in(edns)
                .expect("a well-formed option list")
                .into_iter()
                .collect::<Vec<_>>()
        };

        let accepted = from("replicated.test.", "192.0.2.1");
        assert_eq!(
            accepted.rcode,
            ResponseCode::Ok,
            "from its master: acted on"
        );
        assert!(
            why(&accepted).is_empty(),
            "nothing went wrong, so there is nothing to annotate"
        );

        let refused = from("replicated.test.", "203.0.113.9");
        assert_eq!(
            refused.rcode,
            ResponseCode::Refused,
            "from anywhere else: refused, because acting would cost us a transfer"
        );
        assert_eq!(
            why(&refused),
            vec![(
                InfoCode::PROHIBITED,
                "not one of this zone's masters".to_string()
            )]
        );

        // The two NOTAUTHs are one RCODE and two operator problems, which is
        // the whole reason the reply carries a reason (`TODO.md` #47).
        let ours = from("example.com.", "192.0.2.1");
        assert_eq!(
            ours.rcode,
            ResponseCode::NotAuthorized,
            "a zone we are the primary for: we are nobody's secondary for it"
        );
        assert_eq!(
            why(&ours),
            vec![(
                InfoCode::OTHER,
                "this server is this zone's primary, not a secondary".to_string()
            )]
        );

        let unknown = from("never-heard-of.test.", "192.0.2.1");
        assert_eq!(unknown.rcode, ResponseCode::NotAuthorized);
        assert_eq!(
            why(&unknown),
            vec![(InfoCode::OTHER, "not a zone served here".to_string())],
            "the same RCODE as the zone we are primary for, and not the same reason"
        );
    }

    /// RFC 6891 §6.2.2: a request with no OPT gets a response with none, EDE
    /// included — the reason rides in the OPT or nowhere (RFC 8914 §2).
    ///
    /// The mirror in the other direction is the defect #47 was: this function
    /// attached nothing at all, whatever the NOTIFY carried, because it predates
    /// the [`empty_reply`] consolidation every other reply here goes through.
    #[test]
    fn a_notify_without_edns_is_answered_without_edns() {
        let secondaries = Secondaries::replicating(&[]);
        let zones = HashMap::new();
        let msg = notify::notify_request(nm("never-heard-of.test.").as_ref(), None, 1);
        assert!(msg.edns().is_none(), "the fixture sends no OPT");

        let peer: SocketAddr = "192.0.2.1:5353".parse().expect("a test address");
        let reply = notify_reply(&msg, &zones, &secondaries, peer, 1232);

        assert_eq!(reply.rcode, ResponseCode::NotAuthorized);
        assert!(
            reply.edns().is_none(),
            "an unsolicited OPT is not a mirror, and the EDE goes with it"
        );
    }

    /// DO is the sender's and is copied back (RFC 3225 §3), the same rule
    /// [`empty_reply`] holds for every other reply. A NOTIFY has no DNSSEC to
    /// ask for; what a dropped bit would say is that this server stopped doing
    /// DNSSEC, which is how the same slip read on three reply paths in #38.
    #[test]
    fn a_notify_reply_mirrors_the_senders_do_bit() {
        let secondaries = Secondaries::replicating(&[]);
        let zones = HashMap::new();
        let peer: SocketAddr = "192.0.2.1:5353".parse().expect("a test address");

        for do_bit in [false, true] {
            let mut msg = notify::notify_request(nm("never-heard-of.test.").as_ref(), None, 1);
            let mut edns = rdns::Edns::with_payload_size(1232);
            edns.do_bit = do_bit;
            msg.set_edns(edns);

            let reply = notify_reply(&msg, &zones, &secondaries, peer, 1232);
            assert_eq!(
                reply.edns().expect("an OPT").do_bit,
                do_bit,
                "DO must be copied in the response"
            );
        }
    }

    // Graceful shutdown

    mod shutdown {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        /// A zone big enough that its AXFR spans many messages, so a transfer is
        /// reliably still in flight when the stop arrives. One message would make
        /// this test pass for the wrong reason.
        fn big_zone() -> Zone {
            use std::fmt::Write as _;
            let mut text = String::from(
                "$ORIGIN example.com.\n\
                 $TTL 3600\n\
                 @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                 @   IN NS  ns1.example.com.\n\
                 ns1 IN A   192.0.2.1\n",
            );
            for i in 0..4000 {
                let _ = writeln!(
                    text,
                    "host{i} IN A 10.{}.{}.{}",
                    (i >> 16) & 255,
                    (i >> 8) & 255,
                    i & 255
                );
            }
            rdns::zone::parse_zone_file(&text, "example.com.").expect("the big zone parses")
        }

        /// Read one length-prefixed message.
        async fn read_message(stream: &mut TcpStream) -> Option<DnsMessage> {
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).await.ok()?;
            let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).await.ok()?;
            DnsMessage::try_from_bytes(&body).ok()
        }

        async fn send_axfr_request(stream: &mut TcpStream) {
            let msg = query("example.com.", Qtype::of(record_types::AXFR), false);
            let bytes = msg.to_bytes_within(u16::MAX as usize).expect("serialize");
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            stream.write_all(&framed).await.expect("send the request");
        }

        /// The harm the whole item is about: `systemctl stop` used to cut an
        /// in-flight AXFR mid-stream, and the client cannot tell a truncated
        /// transfer from a complete one — it sees records, then silence, and a
        /// secondary that believes it holds a zone it holds half of.
        ///
        /// Drives the real `tcp_loop` and the real `serve_connection`, and stops
        /// the server after the first message of a multi-message transfer has
        /// arrived — so the stop is unambiguously mid-transfer.
        #[tokio::test]
        async fn a_transfer_in_flight_survives_the_stop() {
            let shutdown = Shutdown::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let loop_handle = tokio::spawn(tcp::serve(
                listener,
                server_with(big_zone()),
                TransportLimits::default(),
                tcp::RateLimit::PerMessage,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));

            let mut stream = TcpStream::connect(addr).await.expect("connect");
            send_axfr_request(&mut stream).await;

            // One message in: the transfer has begun and is not finished.
            let first = read_message(&mut stream).await.expect("the first message");
            assert!(!first.answers.is_empty());

            shutdown.begin();

            // Everything else must still arrive, ending with the closing SOA
            // that RFC 5936 §2.2 uses to bracket a transfer — which is exactly
            // the thing a cut connection withholds.
            let mut records = first.answers.len();
            let mut messages = 1;
            while let Some(msg) = read_message(&mut stream).await {
                records += msg.answers.len();
                messages += 1;
                let closed = msg
                    .answers
                    .last()
                    .is_some_and(|rr| rr.rdata.rtype() == record_types::SOA);
                if closed {
                    break;
                }
            }
            assert!(
                messages > 1,
                "the zone must not fit in one message or this proves nothing"
            );
            // 4000 hosts + SOA + NS + ns1 + the closing SOA.
            assert_eq!(
                records, 4004,
                "the transfer arrived short after {messages} messages"
            );

            // And the loop stopped accepting, so the drain can complete.
            let _ = tokio::time::timeout(Duration::from_secs(5), loop_handle)
                .await
                .expect("the accept loop must return on stop");
            assert!(
                shutdown.drain(Duration::from_secs(5)).await,
                "the drain must complete once the transfer is done"
            );
        }

        /// The other half: once stopped, nothing new is taken on. A connection
        /// opened after the signal gets no answer — the loop has returned, so the
        /// kernel's backlog holds the socket and the peer's retry goes to whatever
        /// replaces us.
        #[tokio::test]
        async fn nothing_new_is_accepted_after_the_stop() {
            let shutdown = Shutdown::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            let loop_handle = tokio::spawn(tcp::serve(
                listener,
                server_with(big_zone()),
                TransportLimits::default(),
                tcp::RateLimit::PerMessage,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));

            shutdown.begin();
            let _ = tokio::time::timeout(Duration::from_secs(5), loop_handle)
                .await
                .expect("the accept loop must return on stop");

            // The listener is dropped with the loop, so this either fails to
            // connect or connects and is never answered. Both are "not served";
            // what must not happen is a reply.
            if let Ok(Ok(mut stream)) =
                tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(addr)).await
            {
                send_axfr_request(&mut stream).await;
                let answered =
                    tokio::time::timeout(Duration::from_secs(1), read_message(&mut stream)).await;
                assert!(
                    !matches!(answered, Ok(Some(_))),
                    "a stopped server answered a query it accepted after stopping"
                );
            }

            assert!(shutdown.drain(Duration::from_secs(5)).await);
        }

        /// A connection sitting idle between queries closes on the stop rather
        /// than holding the drain for its full idle timeout. This is the case
        /// that decides whether a shutdown takes milliseconds or the whole
        /// budget, since a resolver keeps connections open by design (RFC 7766
        /// §6.2.3) and most of them are idle at any moment.
        #[tokio::test]
        async fn an_idle_connection_does_not_hold_the_drain() {
            let shutdown = Shutdown::new();
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("addr");
            tokio::spawn(tcp::serve(
                listener,
                server_with(big_zone()),
                TransportLimits::default(),
                tcp::RateLimit::PerMessage,
                shutdown.stop_handle(),
                shutdown.busy(),
            ));

            // Connect, ask one question, read the answer, then go quiet — which
            // is what a pooled connection does for most of its life.
            let mut stream = TcpStream::connect(addr).await.expect("connect");
            let msg = query("example.com.", Qtype::of(record_types::SOA), false);
            let bytes = msg.to_bytes_within(u16::MAX as usize).expect("serialize");
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            stream.write_all(&framed).await.expect("send");
            read_message(&mut stream).await.expect("answer");

            shutdown.begin();

            // TCP_IDLE_TIMEOUT is ten seconds; this budget is well under it, so
            // passing means the connection observed the stop rather than timing
            // out. Keep the client end alive so nothing else can close it.
            let drained = shutdown.drain(Duration::from_secs(3)).await;
            drop(stream);
            assert!(
                drained,
                "an idle connection held the drain for its idle timeout"
            );
        }
    }

    // Who a TSIG key authorizes

    mod transfer_authorization {
        use super::*;
        /// A transfer is a sequence of messages, and DoH carries one.
        ///
        /// `TODO.md` #106. `Server::answer` decided to stream from the QTYPE
        /// and `Wire::Framed` alone, so a DoH request reached
        /// `answer_transfer` and the whole zone was serialized one envelope at
        /// a time into a channel `https::answer` drains and discards — the
        /// client waiting on the producer to finish before it is handed the
        /// first envelope. RFC 8484 defines no framing that would carry the
        /// rest and RFC 9103 §7.1 puts DoH outside zone transfer, so the
        /// answer is a refusal rather than a stream nothing can read.
        ///
        /// The arrival is the whole of what this drives, so the socket is a
        /// plain one — the same shape `transfer_by_certificate` uses to test
        /// authorization without a handshake.
        mod transfer_needs_a_transport_that_carries_a_sequence {
            use super::*;
            use rdns::validation::{Arrival, PeerCertificate, TlsVersion};

            /// A primary that allows this address to transfer, arriving as
            /// whatever `arrival` says.
            async fn primary_arriving_over(arrival: Arrival) -> SocketAddr {
                let zone = rdns::zone::parse_zone_file(
                    "$ORIGIN example.com.\n\
                     $TTL 3600\n\
                     @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                     @   IN NS  ns1.example.com.\n\
                     ns1 IN A   192.0.2.1\n",
                    "example.com.",
                )
                .expect("parse");
                let mut zones = HashMap::new();
                zones.insert(zone_key(&zone), std::sync::Arc::new(zone));

                let server = Arc::new(
                    Server::new(Arc::new(RwLock::new(Zones::new(zones))), test_context())
                        .with_transfers(
                            TransferAcl::parse(&["127.0.0.1".to_string()]).expect("acl"),
                            TransferCertificates::default(),
                            false,
                        ),
                );

                let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                let addr = listener.local_addr().expect("addr");
                tokio::spawn(async move {
                    while let Ok((stream, peer)) = listener.accept().await {
                        tokio::spawn(tcp::serve_one(
                            stream,
                            peer,
                            server.clone(),
                            TransportLimits::default(),
                            tcp::RateLimit::PerMessage,
                            arrival.clone(),
                            test_shutdown().stop_handle(),
                        ));
                    }
                });
                addr
            }

            async fn transfer(master: SocketAddr) -> rdns::error::TransferResult<rdns::zone::Zone> {
                rdns::xfr::fetch_zone(
                    &rdns::xfr::Master::plain(master),
                    nm("example.com.").as_ref(),
                    None,
                )
                .await
            }

            /// The three that frame a stream answer it. This is the control:
            /// the ACL is the same and only the arrival differs, so a failure
            /// below is about the transport and not about permission.
            #[tokio::test]
            async fn tcp_dot_and_doq_still_transfer() {
                for arrival in [
                    Arrival::Tcp,
                    Arrival::Dot(TlsVersion::Tls13, PeerCertificate::none()),
                    Arrival::Doq(PeerCertificate::none()),
                ] {
                    let master = primary_arriving_over(arrival.clone()).await;
                    let zone = transfer(master)
                        .await
                        .unwrap_or_else(|e| panic!("{arrival:?} carries a sequence: {e}"));
                    assert_eq!(zone.serial(), Some(Serial::new(1)));
                }
            }

            /// And DoH is refused, however small the zone.
            ///
            /// **This narrows something that worked** (`CLAUDE.md` §16), and
            /// the narrowing is the point: a zone that fitted one envelope
            /// transferred over DoH and a zone that did not was built in full
            /// and thrown away. Succeeding by zone size is the shape §4 is
            /// about — it passes every test fixture and fails the deployment.
            #[tokio::test]
            async fn doh_is_refused_however_small_the_zone() {
                let master =
                    primary_arriving_over(Arrival::Doh(TlsVersion::Tls13, PeerCertificate::none()))
                        .await;
                let err = transfer(master)
                    .await
                    .expect_err("one HTTP response is one message");
                assert!(
                    err.to_string().contains("Refused"),
                    "want a refusal, got: {err}"
                );
            }
        }

        /// RFC 9103 §7.5's other method: a transfer authorized by the certificate
        /// the client presented, with no TSIG key and an empty address ACL —
        /// `TODO.md` #59.
        ///
        /// The handshake half is `rdns_transport::tls`'s
        /// `a_client_certificate_reaches_the_handler`; what these drive is the
        /// authorization, which is the half §16 is about.
        mod transfer_by_certificate {
            use super::*;
            use rdns::validation::{Arrival, PeerCertificate, TlsVersion};

            /// A certificate carrying `name`, generated per run.
            fn certificate_for(name: &str) -> PeerCertificate {
                let issued = rcgen::generate_simple_self_signed(vec![name.to_string()])
                    .expect("a certificate");
                PeerCertificate::presented(issued.cert.der().to_vec())
            }

            /// A primary with no ACL and no keys, so the certificate is the only
            /// thing that can authorize anything.
            async fn primary_trusting(rules: &[&str], presented: PeerCertificate) -> SocketAddr {
                let zone = rdns::zone::parse_zone_file(
                    "$ORIGIN example.com.\n\
                 $TTL 3600\n\
                 @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                 @   IN NS  ns1.example.com.\n\
                 ns1 IN A   192.0.2.1\n",
                    "example.com.",
                )
                .expect("parse");
                let mut zones = HashMap::new();
                zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
                let specs: Vec<String> = rules.iter().map(|r| (*r).to_string()).collect();

                let server = Arc::new(
                    Server::new(Arc::new(RwLock::new(Zones::new(zones))), test_context())
                        .with_transfers(
                            TransferAcl::default(),
                            TransferCertificates::parse(&specs).expect("the rules parse"),
                            false,
                        ),
                );

                // The arrival a DoT listener builds, with the certificate this
                // client presented — the one thing the transport contributes.
                let arrival = Arrival::Dot(TlsVersion::Tls13, presented);
                let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                let addr = listener.local_addr().expect("addr");
                tokio::spawn(async move {
                    while let Ok((stream, peer)) = listener.accept().await {
                        tokio::spawn(tcp::serve_one(
                            stream,
                            peer,
                            server.clone(),
                            TransportLimits::default(),
                            tcp::RateLimit::PerMessage,
                            arrival.clone(),
                            test_shutdown().stop_handle(),
                        ));
                    }
                });
                addr
            }

            async fn transfer(master: SocketAddr) -> rdns::error::TransferResult<rdns::zone::Zone> {
                rdns::xfr::fetch_zone(
                    &rdns::xfr::Master::plain(master),
                    nm("example.com.").as_ref(),
                    None,
                )
                .await
            }

            /// The case the row exists for: an operator who has standardized on
            /// mTLS, with no addresses listed and no keys defined.
            #[tokio::test]
            async fn a_listed_certificate_transfers_its_zone() {
                let master = primary_trusting(
                    &["partner.example.:example.com."],
                    certificate_for("partner.example"),
                )
                .await;

                let zone = transfer(master).await.expect("a listed client transfers");
                assert_eq!(zone.serial(), Some(Serial::new(1)));
            }

            /// #16's lesson, for the credential #59 adds: the certificate proves
            /// who, and the zone list decides what. A partner's certificate must
            /// not be every zone on the server.
            #[tokio::test]
            async fn a_certificate_scoped_to_another_zone_cannot_transfer_this_one() {
                let master = primary_trusting(
                    &["partner.example.:other.test."],
                    certificate_for("partner.example"),
                )
                .await;

                let err = transfer(master).await.expect_err(
                    "a certificate scoped to other.test. must not transfer example.com.",
                );
                assert!(
                    err.to_string().contains("Refused"),
                    "want a refusal, got: {err}"
                );
            }

            /// And a certificate nobody listed authorizes nothing, however it was
            /// issued. The handshake verified it against the operator's anchors,
            /// which is authentication and not permission (`CLAUDE.md` §16).
            #[tokio::test]
            async fn a_certificate_nobody_listed_transfers_nothing() {
                let master = primary_trusting(
                    &["partner.example.:example.com."],
                    certificate_for("stranger.example"),
                )
                .await;

                let err = transfer(master)
                    .await
                    .expect_err("an unlisted certificate is not a credential");
                assert!(
                    err.to_string().contains("Refused"),
                    "want a refusal, got: {err}"
                );
            }

            /// The control from the other direction: with no certificate the rules
            /// change nothing, and the address ACL is still what decides.
            #[tokio::test]
            async fn a_client_with_no_certificate_falls_back_to_the_other_rules() {
                let master =
                    primary_trusting(&["partner.example.:example.com."], PeerCertificate::none())
                        .await;

                let err = transfer(master)
                    .await
                    .expect_err("no certificate, no key, and an empty ACL is a refusal");
                assert!(
                    err.to_string().contains("Refused"),
                    "want a refusal, got: {err}"
                );
            }
        }

        use rdns::tsig::{TsigAlgorithm, TsigKey, TsigKeyring};

        fn key(zones: &[&str]) -> TsigKey {
            TsigKey::new(
                "partner.key.",
                TsigAlgorithm::HmacSha256,
                b"0123456789012345678901234567890123456789".to_vec(),
            )
            .for_zones(zones.iter().copied())
        }

        /// A primary holding both zones, with an empty ACL — so the key is the
        /// only thing that can authorize a transfer, which is the situation the
        /// bug was about.
        async fn primary_with(key: TsigKey) -> SocketAddr {
            let zone = rdns::zone::parse_zone_file(
                "$ORIGIN example.com.\n\
                 $TTL 3600\n\
                 @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
                 @   IN NS  ns1.example.com.\n\
                 ns1 IN A   192.0.2.1\n",
                "example.com.",
            )
            .expect("parse");
            spawn_primary_with_keys(zone, &[], DeltaLog::new(), TsigKeyring::new(vec![key])).await
        }

        /// The bug: `answer_transfer` asked only whether a session *existed*, so
        /// any key in the keyring transferred any zone and bypassed
        /// `--allow-transfer` entirely. Hand a per-customer key to one partner and
        /// you handed them every zone on the server.
        #[tokio::test]
        async fn a_key_scoped_to_another_zone_cannot_transfer_this_one() {
            let scoped = key(&["other.test."]);
            let master = primary_with(scoped.clone()).await;

            let err = rdns::xfr::fetch_zone(
                &rdns::xfr::Master::plain(master),
                nm("example.com.").as_ref(),
                Some(&scoped),
            )
            .await
            .expect_err("a key scoped to other.test. must not transfer example.com.");
            // REFUSED, and reported as a refusal rather than as a bad signature:
            // the peer proved who it is and the answer is still no.
            assert!(
                err.to_string().contains("Refused"),
                "want a refusal, got: {err}"
            );
        }

        /// The control. Narrowing must not break the case it exists to serve.
        #[tokio::test]
        async fn a_key_scoped_to_this_zone_transfers_it() {
            let scoped = key(&["example.com."]);
            let master = primary_with(scoped.clone()).await;

            let zone = rdns::xfr::fetch_zone(
                &rdns::xfr::Master::plain(master),
                nm("example.com.").as_ref(),
                Some(&scoped),
            )
            .await
            .expect("a key naming this zone must transfer it");
            assert_eq!(zone.serial(), Some(Serial::new(1)));
        }

        /// Case-insensitively, and with or without the trailing dot — a zone name
        /// is a domain name, and every other comparison in this codebase folds
        /// ASCII case (RFC 4343). An operator who wrote `EXAMPLE.COM` in a flag
        /// must not get a silent refusal at 3am.
        #[tokio::test]
        async fn the_zone_list_is_matched_as_a_domain_name() {
            let scoped = key(&["EXAMPLE.com"]);
            let master = primary_with(scoped.clone()).await;

            let zone = rdns::xfr::fetch_zone(
                &rdns::xfr::Master::plain(master),
                nm("example.com.").as_ref(),
                Some(&scoped),
            )
            .await
            .expect("case and the trailing dot must not decide authorization");
            assert_eq!(zone.serial(), Some(Serial::new(1)));
        }

        /// The preserved default, stated as a test so that changing it is a
        /// deliberate act rather than a side effect. A key with no zone list still
        /// transfers everything: making it deny instead would mean upgrading the
        /// binary silently stops every transfer on a working deployment.
        #[tokio::test]
        async fn a_key_with_no_zone_list_still_transfers_everything() {
            let unscoped = key(&[]);
            let master = primary_with(unscoped.clone()).await;

            let zone = rdns::xfr::fetch_zone(
                &rdns::xfr::Master::plain(master),
                nm("example.com.").as_ref(),
                Some(&unscoped),
            )
            .await
            .expect("an unscoped key is unrestricted, as it always was");
            assert_eq!(zone.serial(), Some(Serial::new(1)));
        }
    }

    // Dynamic UPDATE, end to end (RFC 2136)

    /// The zone every UPDATE test starts from.
    const UPDATE_ZONE: &str = "$ORIGIN example.com.\n\
         $TTL 3600\n\
         @    IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
         @    IN NS  ns1.example.com.\n\
         ns1  IN A   192.0.2.1\n\
         www  IN A   192.0.2.10\n";

    /// A server serving `example.com.` out of a real directory it can write.
    async fn spawn_updatable(dir: &Path, key: TsigKey) -> SocketAddr {
        spawn_updatable_with(dir, key, None, None).await
    }

    async fn spawn_updatable_with(
        dir: &Path,
        key: TsigKey,
        journal: Option<Arc<rdns::journal::Journal>>,
        dnstap: Option<crate::dnstap::Sink>,
    ) -> SocketAddr {
        listen_updatable(
            updatable_server(dir, key)
                .with_history(Arc::new(RwLock::new(DeltaLog::new())), journal)
                .with_dnstap(dnstap),
        )
        .await
    }

    /// [`spawn_updatable`]'s server, before it listens, for a test that needs
    /// one more piece of configuration.
    fn updatable_server(dir: &Path, key: TsigKey) -> Server {
        std::fs::write(dir.join("example.com.zone"), UPDATE_ZONE).expect("write the zone file");
        let source = ZoneSource::Directory(dir.to_string_lossy().to_string());
        let zones = load_zones(&source, false, false, None)
            .map(|l| l.zones)
            .expect("load");

        Server::new(Arc::new(RwLock::new(Zones::new(zones))), test_context())
            .with_tsig_keys(TsigKeyring::new(vec![key]))
            .with_updates(UpdateHandling::new(
                source,
                None,
                Arc::new(DnssecValidator::new(false)),
            ))
    }

    async fn listen_updatable(server: Server) -> SocketAddr {
        let server = Arc::new(server);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                tokio::spawn(tcp::serve_one(
                    stream,
                    peer,
                    server.clone(),
                    TransportLimits::default(),
                    tcp::RateLimit::PerMessage,
                    Arrival::Tcp,
                    test_shutdown().stop_handle(),
                ));
            }
        });
        addr
    }

    fn a_record(name: &str, addr: &str) -> ResourceRecord {
        ResourceRecord {
            name: nm(name),
            class: rdns::Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: rdns::RecordData::from_parsed(&rdns::ParsedRecord::A(
                addr.parse().expect("an address"),
            ))
            .expect("encodes"),
        }
    }

    /// Send one message over TCP and read one reply.
    async fn round_trip(addr: SocketAddr, bytes: Vec<u8>) -> DnsMessage {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(&rdns::framed(&bytes).expect("the test message frames"))
            .await
            .expect("write");
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.expect("length prefix");
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut buf).await.expect("body");
        DnsMessage::try_from_bytes(&buf).expect("a reply")
    }

    /// Watched failing against a handler that installed the new zone without
    /// writing the file: the map assertion passed, the file assertion did not.
    #[tokio::test]
    async fn an_update_is_applied_persisted_and_served() {
        let dir = ScratchDir::new("update-applied");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let addr = spawn_updatable(dir.path(), key.clone()).await;

        let message = update_message(
            "example.com.",
            vec![a_record("new.example.com.", "192.0.2.50")],
        );
        let bytes = message.to_bytes_within(4096).expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, &key, tsig::now()).expect("sign");
        let reply = round_trip(addr, signed).await;

        assert_eq!(reply.rcode, ResponseCode::Ok, "RFC 2136 §3.4.2.5");
        assert_eq!(reply.opcode, OpCode::Update, "the opcode is echoed");

        // Served: asked over the same socket, so this is the zone map answering
        // and not an inspection of internals.
        let asked = round_trip(
            addr,
            query("new.example.com.", Qtype::of(record_types::A), false)
                .to_bytes_within(4096)
                .expect("serialize"),
        )
        .await;
        assert_eq!(asked.rcode, ResponseCode::Ok);
        assert_eq!(
            asked.answers.len(),
            1,
            "the new record is being served: {:?}",
            asked.answers
        );

        // The file, which is the half that survives a reload.
        let written = std::fs::read_to_string(dir.join("example.com.zone")).expect("read back");
        assert!(
            written.contains("new.example.com."),
            "the record reached the file:\n{written}"
        );

        // And it reads back as a zone with the record and a moved serial, rather
        // than merely containing the right substring.
        let reloaded = rdns::zone::parse_zone_file(&written, "example.com.").expect("reparses");
        assert_eq!(
            reloaded
                .query(nm("new.example.com.").as_ref(), Qtype::of(record_types::A))
                .len(),
            1
        );
        assert_eq!(
            reloaded.serial(),
            Some(Serial::new(2)),
            "RFC 2136 §3.6: the serial moved with the contents"
        );
    }

    /// Data frames in a Frame Streams capture, START and STOP skipped.
    ///
    /// A control frame is escaped by a zero length and carries its own length
    /// after it; anything else is a payload. Counted rather than decoded: what
    /// #77b is about is which paths reach the stream, and the payloads
    /// themselves are `rdns::dnstap`'s own tests.
    fn data_frames(capture: &[u8]) -> usize {
        let word = |at: usize| -> Option<usize> {
            let bytes: [u8; 4] = capture.get(at..at + 4)?.try_into().ok()?;
            Some(u32::from_be_bytes(bytes) as usize)
        };
        let (mut at, mut frames) = (0, 0);
        while let Some(len) = word(at) {
            at += 4;
            match len {
                0 => match word(at) {
                    Some(control) => at += 4 + control,
                    None => break,
                },
                len => {
                    at += len;
                    frames += 1;
                }
            }
        }
        frames
    }

    /// All four answering paths reach the query stream, not just the ordinary
    /// one.
    ///
    /// `TODO.md` #77b, the test #75 landed without. `record_dnstap` used to sit
    /// behind `finish`, which the transfer and UPDATE branches returned above,
    /// so a capture held neither — while `--dnstap` says "every answered
    /// request" and `MessageType::UpdateQuery` was an arm nothing could reach.
    /// Watched failing against that shape: one data frame, not three — and
    /// again at three against the TSIG-rejection branch, which #75 left
    /// returning past the tail and #101 took out.
    ///
    /// The transfer is refused, because this server has no ACL. That is the
    /// case worth capturing anyway — `answer_transfer` logs every attempt for
    /// the same reason — and it exercises the branch rather than the zone.
    #[tokio::test]
    async fn every_answering_path_reaches_the_dnstap_stream() {
        let dir = ScratchDir::new("dnstap-paths");
        let capture = dir.join("capture.fstrm");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        // Its own `Shutdown`: the pump flushes when it stops, and
        // `test_shutdown` is one static that every other test's accept loop is
        // holding.
        let shutdown = Shutdown::new();
        let sink = crate::dnstap::Sink::spawn(
            &crate::dnstap::Target::File(capture.clone()),
            0,
            Vec::new(),
            Vec::new(),
            DnsMetrics::new(),
            shutdown.stop_handle(),
        )
        .await
        .expect("the capture file opens");
        let addr = spawn_updatable_with(dir.path(), key.clone(), None, Some(sink)).await;

        let asked = round_trip(
            addr,
            query("www.example.com.", Qtype::of(record_types::A), false)
                .to_bytes_within(4096)
                .expect("serialize"),
        )
        .await;
        assert_eq!(asked.rcode, ResponseCode::Ok, "an ordinary query");

        let update = update_message(
            "example.com.",
            vec![a_record("new.example.com.", "192.0.2.50")],
        );
        let bytes = update.to_bytes_within(4096).expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, &key, tsig::now()).expect("sign");
        assert_eq!(
            round_trip(addr, signed).await.rcode,
            ResponseCode::Ok,
            "RFC 2136 §3.4.2.5"
        );

        let transfer = round_trip(
            addr,
            query("example.com.", Qtype::AXFR, false)
                .to_bytes_within(4096)
                .expect("serialize"),
        )
        .await;
        assert_eq!(
            transfer.rcode,
            ResponseCode::Refused,
            "an empty ACL refuses everyone"
        );

        // The fourth door (`TODO.md` #101). A key the server does not hold is
        // *answered* — NOTAUTH, signed per RFC 8945 §5.3 — and the branch used
        // to `return` sixty lines above the tail, so the one capture an
        // operator wants during a key-guessing probe held nothing.
        let stranger = TsigKey::new("stranger.key.", TsigAlgorithm::HmacSha256, vec![9u8; 32]);
        let probe = update_message(
            "example.com.",
            vec![a_record("probe.example.com.", "192.0.2.51")],
        );
        let bytes = probe.to_bytes_within(4096).expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, &stranger, tsig::now()).expect("sign");
        assert_eq!(
            round_trip(addr, signed).await.rcode,
            ResponseCode::NotAuthorized,
            "a key this server does not hold"
        );

        // Polled rather than slept, twice, because a loaded machine decided
        // the result (`TODO.md` #68a). A frame is recorded after its reply is
        // sent, so the client can hold the fourth reply before the server has
        // queued the fourth frame; stopping then left three.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while data_frames(&std::fs::read(&capture).expect("the capture file")) < 4 {
            assert!(
                std::time::Instant::now() < deadline,
                "four frames never reached the capture"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // The pump writes STOP and flushes as it stops, so the capture is
        // closed when it ends with one.
        shutdown.begin();
        let capture = loop {
            let bytes = std::fs::read(&capture).expect("the capture file");
            if bytes.ends_with(&rdns::dnstap::stop_frame()) {
                break bytes;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the capture never closed: {} octets, {} data frames",
                bytes.len(),
                data_frames(&bytes)
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(
            data_frames(&capture),
            4,
            "a query, an UPDATE, a transfer attempt and a TSIG refusal"
        );
    }

    /// A refused UPDATE is signed at the instant that verified it.
    ///
    /// `signed_error` used to read the wall clock itself, 464 lines below the
    /// `finish` that signs with the `now` the request was checked against
    /// (`TODO.md` #87). Latent, because `Clock::System` *is* that read — which
    /// is why it takes a fixed clock to see, and why the fix is a type
    /// (`Refused`) rather than a thirteenth careful call site.
    ///
    /// Fails against the old `session.sign(bytes, current_unix_timestamp())`
    /// with `TsigError::BadTime`. Checked by reverting that one call.
    #[tokio::test]
    async fn a_refused_update_is_signed_at_the_instant_that_verified_it() {
        // Fixed, and far outside RFC 8945 §5.2.3's 300-second fudge from any
        // real now, so the wrong clock cannot pass by luck.
        const WHEN: u64 = 1_700_000_000;
        // Valid, and scoped to a zone this server does not hold: the TSIG
        // verifies, so there is a session to sign the refusal with, and §3.3
        // refuses it.
        let key = update_key(rdns::tsig::UpdatePolicy::Zones(vec![
            "elsewhere.test.".to_string()
        ]));
        let zone = rdns::zone::parse_zone_file(
            "$ORIGIN example.com.\n\
             $TTL 3600\n\
             @   IN SOA ns1.example.com. admin.example.com. ( 1 3600 600 604800 300 )\n\
             @   IN NS  ns1.example.com.\n\
             ns1 IN A   192.0.2.1\n",
            "example.com.",
        )
        .expect("the zone parses");
        let server = server_with_keys_at(zone, vec![key.clone()], Clock::fixed(WHEN));

        let bytes = update_message(
            "example.com.",
            vec![a_record("new.example.com.", "192.0.2.50")],
        )
        .to_bytes_within(4096)
        .expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, &key, WHEN).expect("sign");
        let request_mac = rdns::tsig::request_mac(&signed).expect("our own MAC");

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind a client");
        let peer = client.local_addr().expect("addr");
        let mut scratch = Scratch::default();
        server
            .answer(
                &signed,
                peer,
                WHEN,
                &Wire::Datagram(&socket, peer),
                &mut scratch,
            )
            .await;

        let mut buf = vec![0u8; 4096];
        let (n, _) = client.recv_from(&mut buf).await.expect("a refusal");
        let reply = &buf[..n];
        assert_eq!(
            DnsMessage::try_from_bytes(reply).expect("it parses").rcode,
            ResponseCode::Refused,
            "§3.3: the key grants nothing here"
        );
        // The whole point: a client whose clock agrees with the server's must
        // be able to verify the refusal. RFC 8945 §5.3 — unsigned, or signed
        // off a different instant, a refusal is indistinguishable from a
        // tampered reply.
        rdns::tsig::check_response(reply, &key, &request_mac, true, WHEN)
            .expect("the refusal verifies at the instant it was signed at");
    }

    /// The refusal says why, to a client that sent an OPT to hear it in
    /// (RFC 8914 §2).
    ///
    /// PROHIBITED for all four ways permission can be missing, and no finer:
    /// telling a stranger *which* of them it was is telling it about the
    /// keyring. The text is what an operator reads, and the RCODE is still
    /// REFUSED whatever §3 says about EDE â "applications MUST continue to
    /// follow requirements ... on how to process RCODEs".
    #[tokio::test]
    async fn a_refused_update_says_why_when_the_client_used_edns() {
        let dir = ScratchDir::new("update-ede");
        let key = update_key(rdns::tsig::UpdatePolicy::Zones(vec![
            "elsewhere.test.".to_string()
        ]));
        let addr = spawn_updatable(dir.path(), key).await;
        let changes = vec![a_record("new.example.com.", "192.0.2.50")];

        let mut asked = update_message("example.com.", changes.clone());
        asked.set_edns(rdns::Edns::with_payload_size(4096));
        let reply = round_trip(addr, asked.to_bytes_within(4096).expect("serialize")).await;
        assert_eq!(reply.rcode, ResponseCode::Refused);
        let edns = reply.edns.as_ref().expect("the OPT is mirrored");
        let errors = rdns::ExtendedError::all_in(edns).expect("a well-formed option list");
        assert_eq!(
            errors
                .iter()
                .map(|(code, _)| *code)
                .collect::<Vec<rdns::InfoCode>>(),
            vec![rdns::InfoCode::PROHIBITED]
        );

        // The same UPDATE with no OPT: the same refusal, and nowhere to say why.
        let plain = update_message("example.com.", changes);
        let reply = round_trip(addr, plain.to_bytes_within(4096).expect("serialize")).await;
        assert_eq!(reply.rcode, ResponseCode::Refused);
        assert!(reply.edns.is_none(), "an unsolicited OPT is not mirroring");
    }

    /// The refusals, each with the code RFC 2136 gives it.
    ///
    /// They are not interchangeable and that is the point: NOTAUTH says "not my
    /// zone" (§3.1.1) and REFUSED says "not you" (§3.3), and a client uses the
    /// difference to decide whether to look for a different server or a
    /// different key.
    #[tokio::test]
    async fn an_unauthorized_update_is_refused_and_an_unknown_zone_is_notauth() {
        let dir = ScratchDir::new("update-refused");
        // Scoped to a zone this server does not serve, so the key is valid and
        // grants nothing here.
        let key = update_key(rdns::tsig::UpdatePolicy::Zones(vec![
            "elsewhere.test.".to_string()
        ]));
        let addr = spawn_updatable(dir.path(), key.clone()).await;
        let changes = vec![a_record("new.example.com.", "192.0.2.50")];

        // Unsigned: an UPDATE has no address-based path in, by design.
        let unsigned = update_message("example.com.", changes)
            .to_bytes_within(4096)
            .expect("serialize");
        assert_eq!(
            round_trip(addr, unsigned).await.rcode,
            ResponseCode::Refused,
            "§3.3: an unsigned UPDATE has no credential"
        );

        // Signed with a key scoped to another zone. The EDE is the unsigned
        // case's: which of the two it was is not the client's business.
        assert_eq!(
            update_of_with_edns(addr, &key, "example.com.").await,
            (
                ResponseCode::Refused,
                vec![NOT_YOURS.extra_text().to_string()]
            ),
            "§3.3: the key may not rewrite this zone"
        );

        // A zone this server is not authoritative for is NOTAUTH, not REFUSED —
        // the opposite of the query path's rule (`CLAUDE.md` §8).
        assert_eq!(
            update_of_with_edns(addr, &key, "elsewhere.test.").await,
            (
                ResponseCode::NotAuthorized,
                vec![NOT_OUR_ZONE.extra_text().to_string()]
            ),
            "§3.1.1: not one of this server's authority zones"
        );

        // NOTAUTH whatever the credential: the zone is checked first, or the
        // rcode no longer says which of server and key to change (#118).
        let unsigned_elsewhere = update_message(
            "nowhere.test.",
            vec![a_record("new.nowhere.test.", "192.0.2.50")],
        )
        .to_bytes_within(4096)
        .expect("serialize");
        assert_eq!(
            round_trip(addr, unsigned_elsewhere.clone()).await.rcode,
            ResponseCode::NotAuthorized,
            "§3.1.1 before §3.3: unsigned, for a zone not served here"
        );
        let signed = rdns::tsig::sign_request(unsigned_elsewhere, &key, tsig::now()).expect("sign");
        assert_eq!(
            round_trip(addr, signed).await.rcode,
            ResponseCode::NotAuthorized,
            "§3.1.1 before §3.3: a key scoped elsewhere, for a zone not served here"
        );

        // Nothing was written on any of the paths.
        let written = std::fs::read_to_string(dir.join("example.com.zone")).expect("read back");
        assert!(
            !written.contains("new.example.com."),
            "a refused UPDATE changes nothing:\n{written}"
        );
    }

    /// A server with no writable zone source refuses an UPDATE rather than
    /// applying it to memory alone.
    ///
    /// The distinction this protects is the one in [`UpdateHandling`]'s docs: an
    /// in-memory-only change is discarded by the next reload or re-signing run,
    /// silently, after the client was told it succeeded. Refusing is the honest
    /// answer, and it is the branch that exists because the field is an `Option`.
    #[tokio::test]
    async fn an_update_is_refused_without_a_writable_source() {
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let zone = rdns::zone::parse_zone_file(UPDATE_ZONE, "example.com.").expect("parse");
        let addr = spawn_primary_with_keys(
            zone,
            &[],
            DeltaLog::new(),
            TsigKeyring::new(vec![key.clone()]),
        )
        .await;

        assert_eq!(
            update_with_edns(addr, &key).await,
            (
                ResponseCode::Refused,
                vec![NOT_WRITABLE.extra_text().to_string()]
            ),
            "a key that grants everything still cannot write a zone we cannot persist"
        );
    }

    /// A signed UPDATE of `example.com.` adding `new.example.com.`, asking for
    /// EDE, and the reply's rcode and extended errors.
    async fn update_with_edns(addr: SocketAddr, key: &TsigKey) -> (ResponseCode, Vec<String>) {
        update_of_with_edns(addr, key, "example.com.").await
    }

    /// [`update_with_edns`] for another zone, adding `new.` under it.
    async fn update_of_with_edns(
        addr: SocketAddr,
        key: &TsigKey,
        zone: &str,
    ) -> (ResponseCode, Vec<String>) {
        let mut asked = update_message(zone, vec![a_record(&format!("new.{zone}"), "192.0.2.50")]);
        asked.set_edns(rdns::Edns::with_payload_size(4096));
        let bytes = asked.to_bytes_within(4096).expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, key, tsig::now()).expect("sign");
        let reply = round_trip(addr, signed).await;
        let texts = match reply.edns.as_ref() {
            Some(edns) => rdns::ExtendedError::all_in(edns)
                .expect("a well-formed option list")
                .into_iter()
                .map(|(_, text)| text)
                .collect(),
            None => Vec::new(),
        };
        (reply.rcode, texts)
    }

    /// An UPDATE of a zone this server replicates is refused, whatever the key
    /// grants: the master's next transfer would undo it.
    #[tokio::test]
    async fn an_update_of_a_replicated_zone_is_refused() {
        let dir = ScratchDir::new("update-replicated");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let secondaries = Secondaries::replicating(&[rdns::secondary::MasterSpec {
            zone: nm("example.com."),
            master: "192.0.2.1:53".parse().expect("a test address"),
            key_name: None,
            tls: None,
        }]);
        let addr = listen_updatable(
            updatable_server(dir.path(), key.clone()).with_secondaries(Arc::new(secondaries)),
        )
        .await;

        assert_eq!(
            update_with_edns(addr, &key).await,
            (
                ResponseCode::Refused,
                vec![REPLICATED_ZONE.extra_text().to_string()]
            )
        );
        let written = std::fs::read_to_string(dir.join("example.com.zone")).expect("read back");
        assert!(!written.contains("new.example.com."), "{written}");
    }

    /// A readable directory without the zone's file: the operator removed the
    /// source, so there is nowhere to write the change and nothing failed.
    #[tokio::test]
    async fn an_update_whose_zone_file_is_gone_is_refused() {
        let dir = ScratchDir::new("update-no-file");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let addr = spawn_updatable(dir.path(), key.clone()).await;
        std::fs::remove_file(dir.join("example.com.zone")).expect("remove the zone file");

        assert_eq!(
            update_with_edns(addr, &key).await,
            (
                ResponseCode::Refused,
                vec![NOT_WRITABLE.extra_text().to_string()]
            )
        );
    }

    /// The `$INCLUDE` refusal as the client sees it. The unit test on
    /// `apply_update_to_file` stops at the `UpdateFailure`; this is the rcode
    /// and EDE the handler turns it into (`TODO.md` #130).
    #[tokio::test]
    async fn an_update_to_a_zone_file_that_includes_another_says_so() {
        let dir = ScratchDir::new("update-include-answer");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let addr = spawn_updatable(dir.path(), key.clone()).await;
        std::fs::write(dir.join("hosts.inc"), "extra IN A 192.0.2.9\n").expect("write the include");
        let with_include = format!("{UPDATE_ZONE}$INCLUDE hosts.inc\n");
        std::fs::write(dir.join("example.com.zone"), &with_include).expect("add the $INCLUDE");

        assert_eq!(
            update_with_edns(addr, &key).await,
            (
                ResponseCode::Refused,
                vec![INCLUDES_ANOTHER_FILE.extra_text().to_string()]
            )
        );
        let written = std::fs::read_to_string(dir.join("example.com.zone")).expect("read back");
        assert_eq!(written, with_include, "a refused update writes nothing");
    }

    /// A zone directory that cannot be read is a server failure, not a refusal
    /// (RFC 2136 §2.2: "for example an operating system error"). The client
    /// acts on the difference: SERVFAIL sends it to the next server, anything
    /// else ends the update (§4.5, §4.6).
    ///
    /// Removed rather than chmod'ed: a mode does not stop root, and Windows
    /// has none. Watched failing against `file_for`'s `read_dir(dir).ok()?`,
    /// which answered REFUSED with `NOT_WRITABLE` (`TODO.md` #119).
    #[tokio::test]
    async fn an_update_when_the_zone_directory_cannot_be_read_is_servfail() {
        let dir = ScratchDir::new("update-no-dir");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let addr = spawn_updatable(dir.path(), key.clone()).await;
        std::fs::remove_dir_all(dir.path()).expect("remove the zone directory");

        assert_eq!(
            update_with_edns(addr, &key).await,
            (ResponseCode::ServerFailure, Vec::new())
        );
    }

    /// A zone file that no longer parses fails the UPDATE (§3.4.2.1) and
    /// leaves the served zone as it was.
    #[tokio::test]
    async fn an_update_to_a_zone_file_that_no_longer_parses_is_servfail() {
        let dir = ScratchDir::new("update-unparsable");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let addr = spawn_updatable(dir.path(), key.clone()).await;
        std::fs::write(
            dir.join("example.com.zone"),
            "this is not a zone
",
        )
        .expect("overwrite the zone file");

        assert_eq!(
            update_with_edns(addr, &key).await,
            (ResponseCode::ServerFailure, Vec::new())
        );
        let asked = round_trip(
            addr,
            query("www.example.com.", Qtype::of(record_types::A), false)
                .to_bytes_within(4096)
                .expect("serialize"),
        )
        .await;
        assert_eq!(asked.answers.len(), 1, "still serving: {:?}", asked.answers);
    }

    /// An UPDATE leaves a journal, and the journal answers an IXFR from
    /// before it.
    ///
    /// Asserting on the file alone would not show it: what matters is that a
    /// *fresh* `DeltaLog`, as after a restart, can chain from the serial a
    /// secondary held beforehand. Anything less is a file that exists rather
    /// than a history that works.
    ///
    /// Watched failing with the journal write removed from `install_zone`:
    /// the update still applied and was still served, and `Journal::load` came
    /// back empty, so `chain_from` had nothing to answer with — which is
    /// precisely the pre-journal behaviour it is meant to replace.
    #[tokio::test]
    async fn an_update_leaves_a_journal_that_survives_the_process() {
        let dir = ScratchDir::new("update-journal");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let journal = Arc::new(rdns::journal::Journal::new(dir.path().to_path_buf()));
        let addr = spawn_updatable_with(dir.path(), key.clone(), Some(journal.clone()), None).await;

        for (n, addr_text) in [(1u8, "192.0.2.51"), (2, "192.0.2.52")] {
            let bytes = update_message(
                "example.com.",
                vec![a_record(&format!("host{n}.example.com."), addr_text)],
            )
            .to_bytes_within(4096)
            .expect("serialize");
            let signed = rdns::tsig::sign_request(bytes, &key, tsig::now()).expect("sign");
            assert_eq!(round_trip(addr, signed).await.rcode, ResponseCode::Ok);
        }

        // A new process would see exactly this: the file, and nothing in memory.
        let restored = journal
            .load(nm("example.com.").as_ref())
            .expect("the journal reads back");
        assert_eq!(restored.len(), 2, "one step per update");
        assert_eq!(restored[0].from_serial, Serial::new(1), "the zone's serial");
        assert_eq!(restored[1].to_serial, Serial::new(3), "after two bumps");

        let mut log = DeltaLog::new();
        log.restore(nm("example.com.").as_ref(), restored);
        let chain = log
            .chain_from(nm("example.com.").as_ref(), Serial::new(1))
            .expect("a secondary at the pre-update serial can still be caught up");
        assert_eq!(chain.len(), 2);
        assert!(
            chain
                .iter()
                .flat_map(|d| d.added.iter())
                .any(|r| r.name == nm("host1.example.com.")),
            "and the records it was missing are in it"
        );
    }

    /// A prerequisite that does not hold stops the update, with its own RCODE
    /// (§3.2) and with the zone untouched — which is what makes an UPDATE a
    /// transaction rather than a sequence of edits.
    #[tokio::test]
    async fn a_failed_prerequisite_leaves_the_zone_alone() {
        let dir = ScratchDir::new("update-prereq");
        let key = update_key(rdns::tsig::UpdatePolicy::Any);
        let addr = spawn_updatable(dir.path(), key.clone()).await;

        let mut message = update_message(
            "example.com.",
            vec![a_record("new.example.com.", "192.0.2.50")],
        );
        // §2.4.3 CLASS=NONE: "no RRset of this type exists at this name" — and
        // `www` has an A, so it does not hold.
        message.answers = vec![ResourceRecord {
            name: nm("www.example.com."),
            class: rdns::Class::new(254),
            ttl: Ttl::ZERO,
            rdata: rdns::RecordData::new(record_types::A, Vec::new()).expect("bare"),
        }];
        let bytes = message.to_bytes_within(4096).expect("serialize");
        let signed = rdns::tsig::sign_request(bytes, &key, tsig::now()).expect("sign");

        assert_eq!(
            round_trip(addr, signed).await.rcode,
            ResponseCode::ResourceRecordSetExistsForSomeReason,
            "§3.2.2 YXRRSET, not a generic failure"
        );
        let written = std::fs::read_to_string(dir.join("example.com.zone")).expect("read back");
        assert!(!written.contains("new.example.com."), "{written}");
        let reloaded = rdns::zone::parse_zone_file(&written, "example.com.").expect("reparses");
        assert_eq!(
            reloaded.serial(),
            Some(Serial::new(1)),
            "and the serial did not move either"
        );
    }

    /// And the refusal says which policy refused it, because "REFUSED" over a
    /// working TLS connection is otherwise an afternoon's debugging
    /// (RFC 8914, `TODO.md` #44b). Read off the wire rather than from the
    /// constant: the reply's OPT is where it has to be (RFC 8914 §2), and an
    /// EDE that never reaches it is the same as none.
    #[tokio::test]
    async fn the_refusal_says_the_transfer_must_be_encrypted() {
        let zone = rdns::zone::parse_zone_file(&zone_at_serial(7), "example.com.").expect("zone");
        let master = spawn_primary_full(
            zone,
            &["127.0.0.1".to_string()],
            DeltaLog::new(),
            TsigKeyring::new(Vec::new()),
            true,
            Arrival::Tcp,
        )
        .await;

        // With an OPT, because that is where the reason rides and a request
        // without one gets a reply without one.
        let mut request = rdns::xfr::axfr_request(nm("example.com.").as_ref(), 0x77);
        request.edns = Some(rdns::Edns::with_payload_size(4096));
        let mut buf = vec![0u8; 512];
        let n = request.to_bytes(&mut buf).expect("serialize");
        let mut framed = (n as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&buf[..n]);

        let mut stream = TcpStream::connect(master).await.expect("connect");
        stream.write_all(&framed).await.expect("send");
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await.expect("length");
        let mut packet = vec![0u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut packet).await.expect("reply");
        let reply = rdns::DnsMessage::try_from_bytes(&packet).expect("parse the reply");

        assert_eq!(reply.rcode, ResponseCode::Refused);
        let edns = reply.edns.as_ref().expect("the reply mirrors the OPT");
        let reasons = rdns::ExtendedError::all_in(edns).expect("readable options");
        assert!(
            reasons
                .iter()
                .any(|(_, text)| text.contains("over TLS 1.3 only")),
            "the refusal should say which policy refused it: {reasons:?}"
        );
    }

    /// A *response* arriving at the server port is dropped, not answered.
    ///
    /// `AdmissionCheck` deliberately accepts QR=1 — it is used on both
    /// directions of the wire — so nothing between the socket and the zone lookup
    /// tested it, and `make_response` would happily build a reply to a reply. Two
    /// servers pointed at each other, or one spoofed datagram with a forged
    /// source, is then a packet loop that neither end can see is one.
    #[tokio::test]
    async fn a_response_sent_to_the_server_port_is_dropped() {
        let zone = rdns::zone::parse_zone_file(
            "@ IN SOA ns1.example.com. admin.example.com. 1 3600 600 604800 300\n\
             @ IN NS ns1.example.com.\n\
             ns1 IN A 192.0.2.1\n",
            "example.com.",
        )
        .expect("parse the zone");
        let mut zones = HashMap::new();
        zones.insert(zone_key(&zone), std::sync::Arc::new(zone));
        let server = Server::new(Arc::new(RwLock::new(Zones::new(zones))), test_context());
        let peer: SocketAddr = "192.0.2.9:5353".parse().unwrap();

        let wire = |msg: &DnsMessage| {
            let mut buf = vec![0u8; 512];
            let n = msg.to_bytes(&mut buf).expect("serialize");
            buf.truncate(n);
            buf
        };

        // The control: the same question, asked as a question, is answered.
        let mut question = query("ns1.example.com.", Qtype::of(record_types::A), false);
        assert!(
            !answered(&server, &wire(&question), peer).await.is_empty(),
            "a real query must still be answered — the check has to be narrow"
        );

        // The same bytes with QR set are a response, and get nothing back.
        question.response = true;
        assert!(
            answered(&server, &wire(&question), peer).await.is_empty(),
            "a response is not a question, and replying to one is a packet loop"
        );
    }
}
