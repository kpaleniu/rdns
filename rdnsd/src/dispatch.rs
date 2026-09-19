//! One request in, its reply on the wire.
//!
//! The door (`rdns::validation::Request`), the TSIG check, the four things a
//! request can be — a query, a NOTIFY, a transfer, a dynamic UPDATE — and the
//! epilogue every ordinary answer leaves through. What is *not* here is deciding
//! what a name deserves, which is [`crate::answer`]'s and has no sockets in it.
//!
//! `main.rs` reaches two items: [`Wire`], which the UDP loop names to say where
//! a reply goes, and [`Server::answer`]. Everything else is private to this
//! module, which is the whole of `TODO.md` #38d: the transfer and UPDATE
//! answering used to be `impl Server` blocks in the crate root, where private
//! means visible to the root and every descendant (`CLAUDE.md` §17).

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use rdns::dnstap;
use rdns::{
    clock::current_unix_timestamp,
    ede::InfoCode,
    error::RequestError,
    ixfr::{ixfr_response, IxfrResponse},
    logging::QueryLogger,
    notify,
    response::ClientEdns,
    security::ResponseVerdict,
    transfer::axfr_envelopes,
    tsig::{self, TsigCheck, TsigSession},
    update,
    validation::{Arrival, Privacy, Request, Transport},
    zone::{FileDigest, Zone},
    DnsMessage, ExtendedError, OpCode, Qtype, ResponseCode,
};
use rdns_transport::tcp::{self, send_framed, Reply};
use rdns_transport::ServeContext;

use crate::answer::{write_response, NOT_OUR_ZONE};
use crate::replication::{Notified, Secondaries};
use crate::zones::{install_zone, ZoneContext, ZoneMap, ZoneSigning};
use crate::{bad_request, serving_error};
use crate::{Scratch, Server};

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

        // TSIG before anything that could answer (RFC 8945 §5.2): checking the
        // signature afterwards means answering whoever asked.
        let mut session = match tsig::check_request(packet, &self.tsig_keys, now) {
            TsigCheck::Unsigned => None,
            TsigCheck::Verified(session) => Some(session),
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
                let Some(response) = error_reply(
                    &msg,
                    ResponseCode::NotAuthorized,
                    None,
                    reserve(ceiling, rejection.reply_overhead()),
                    advertised,
                ) else {
                    return;
                };
                match rejection.attach(response, now) {
                    Ok(bytes) => wire.send(&bytes, &self.ctx.logger, ip).await,
                    Err(e) => serving_error!(self.ctx.logger, ip, "TSIG error reply: {e}"),
                }
                return;
            }
        };

        // The record the signer appends comes out of the ceiling, not on top of
        // it: RFC 8945 §5.3 says a TSIG that would not fit means altering the
        // response, not sending it oversized (`TODO.md` #41d). Signing is the
        // one thing here that grows finished bytes.
        let max_len = match &session {
            Some(session) => reserve(ceiling, session.reply_overhead()),
            None => ceiling,
        };

        // Answered here rather than in `make_response`: a sequence of messages,
        // gated on an ACL, and the answer can be the whole zone. Only where a
        // sequence can be carried — AXFR is TCP alone (RFC 5936 §4.2) and an
        // IXFR over UDP is answered with a single SOA (RFC 1995 §2), both of
        // which `write_response` does below.
        if matches!(qtype, Some(Qtype::AXFR) | Some(Qtype::IXFR)) {
            if let Wire::Framed(out, arrival) = wire {
                self.answer_transfer(&msg, peer, session.as_mut(), now, arrival, out)
                    .await;
                return;
            }
        }

        // Likewise, plus: an UPDATE installs a new zone, and `make_response`
        // holds a read guard on the zone map that installing would deadlock
        // against. RFC 2136 §1 permits it on either transport, and the checks,
        // the ordering and the persistence are the request's, not the
        // transport's.
        if msg.opcode == OpCode::Update {
            if let Some(reply) = self
                .answer_update(&msg, peer, session.as_mut(), max_len)
                .await
            {
                wire.send(&reply, &self.ctx.logger, ip).await;
            }
            return;
        }

        // Never hold the zone lock across a socket write: a SIGHUP reload would
        // queue behind a slow client for the life of its connection.
        let serialized = {
            let zones = self.zone_map.read().await;
            if msg.opcode == OpCode::Notify {
                notify_reply(&msg, &zones, &self.secondaries, peer, advertised)
                    .to_bytes_within_buf_with(max_len, &mut scratch.out, &mut scratch.compressor)
            } else {
                write_response(
                    &msg,
                    &zones,
                    &self.ctx.metrics,
                    max_len,
                    advertised,
                    scratch,
                )
            }
        };
        if let Err(e) = serialized {
            serving_error!(self.ctx.logger, ip, "serialization error: {e}");
            return;
        }

        self.finish(
            wire,
            Incoming {
                msg: &msg,
                bytes: packet,
                arrived,
            },
            session.as_mut(),
            peer,
            now,
            scratch,
        )
        .await;
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
    async fn finish(
        &self,
        wire: &Wire<'_>,
        incoming: Incoming<'_>,
        session: Option<&mut TsigSession>,
        peer: SocketAddr,
        now: u64,
        scratch: &Scratch,
    ) {
        let request = incoming.msg;
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
        if let Some(reply) = reply {
            wire.send(&reply, &self.ctx.logger, ip).await;
            self.record_dnstap(wire, incoming, peer, Some(&reply));
        } else {
            // A request we answered with silence — over the response budget.
            // A query-only entry says it arrived and got nothing, which is the
            // one thing a log line at DEBUG cannot tell an analytics pipeline.
            self.record_dnstap(wire, incoming, peer, None);
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
        let qname = msg
            .queries
            .first()
            .map(|q| q.qname.clone())
            .unwrap_or_default();
        let incremental = msg.queries.first().map(|q| q.qtype) == Some(Qtype::IXFR);
        let kind = if incremental { "IXFR" } else { "AXFR" };

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
                msg,
                ResponseCode::Refused,
                Some(NOT_OVER_TLS),
                ip,
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
                msg,
                ResponseCode::Refused,
                Some(NOT_YOURS),
                ip,
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
                msg,
                ResponseCode::Refused,
                Some(NOT_YOURS),
                ip,
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
            self.send_transfer_error(msg, ResponseCode::Refused, Some(NOT_YOURS), ip, None, out)
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
                    msg,
                    ResponseCode::NotAuthorized,
                    Some(NOT_OUR_ZONE),
                    ip,
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
                            msg,
                            ResponseCode::ServerFailure,
                            None,
                            ip,
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
                        msg,
                        ResponseCode::ServerFailure,
                        None,
                        ip,
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
                    self.abandon_transfer(msg, ip, session, sent, out).await;
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
                        self.abandon_transfer(msg, ip, None, sent, out).await;
                        return;
                    }
                },
                None => bytes,
            };
            if !send_framed(out, &bytes).await {
                // Either the frame is impossible or the peer hung up. The first
                // needs the connection closed; the second closed it already.
                self.abandon_transfer(msg, ip, None, sent, out).await;
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
        msg: &DnsMessage,
        ip: IpAddr,
        session: Option<&mut TsigSession>,
        sent: usize,
        out: &mpsc::Sender<Reply>,
    ) {
        if sent == 0 {
            self.send_transfer_error(msg, ResponseCode::ServerFailure, None, ip, session, out)
                .await;
            return;
        }
        tracing::error!(
            peer = %ip,
            "transfer abandoned after {sent} envelope(s); closing the connection so the \
             client sees an incomplete stream rather than waiting for a closing SOA"
        );
        let _ = out.send(Reply::Abort).await;
    }

    /// [`Server::signed_error`], framed and sent.
    async fn send_transfer_error(
        &self,
        msg: &DnsMessage,
        rcode: ResponseCode,
        why: Option<ExtendedError>,
        ip: IpAddr,
        session: Option<&mut TsigSession>,
        out: &mpsc::Sender<Reply>,
    ) {
        if let Some(bytes) = self.signed_error(msg, rcode, why, ip, session, u16::MAX as usize) {
            send_framed(out, &bytes).await;
        }
    }

    /// One error reply, signed if the request was.
    ///
    /// RFC 8945 §5.3: an error response to a verified request is signed too.
    /// Unsigned, a client cannot tell a refusal from a tampered reply.
    fn signed_error(
        &self,
        msg: &DnsMessage,
        rcode: ResponseCode,
        why: Option<ExtendedError>,
        ip: IpAddr,
        session: Option<&mut TsigSession>,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        let Some(bytes) = error_reply(msg, rcode, why, max_len, self.ctx.udp.advertised()) else {
            serving_error!(self.ctx.logger, ip, "could not serialize an error response");
            return None;
        };
        match session {
            Some(session) => match session.sign(bytes, current_unix_timestamp()) {
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
    /// The check order is the RFC's, each one keeping the next from running:
    /// §3.1 reads the message, §3.1.1 asks whether the zone is ours, §3.3
    /// whether the requestor may write it, §3.2 checks the prerequisites, and
    /// only then does §3.4 change anything.
    async fn answer_update(
        &self,
        msg: &DnsMessage,
        peer: SocketAddr,
        session: Option<&mut TsigSession>,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        let ip = peer.ip();

        // §3.1: read it, and reject the ways it can be malformed.
        let request = match update::parse(msg) {
            Ok(request) => request,
            Err(rejected) => {
                serving_error!(self.ctx.logger, ip, "UPDATE rejected: {rejected}");
                return self.signed_error(msg, rejected.rcode, None, ip, session, max_len);
            }
        };
        let zone_name = request.zone.clone();

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
            return self.signed_error(
                msg,
                ResponseCode::Refused,
                Some(NOT_YOURS),
                ip,
                None,
                max_len,
            );
        };
        if !session.may_update(&zone_name.as_ref().to_presentation()) {
            serving_error!(
                self.ctx.logger,
                ip,
                "UPDATE of {zone_name} REFUSED: key {} may not rewrite it",
                session.key_name()
            );
            return self.signed_error(
                msg,
                ResponseCode::Refused,
                Some(NOT_YOURS),
                ip,
                Some(session),
                max_len,
            );
        }

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
                msg,
                ResponseCode::NotAuthorized,
                Some(NOT_OUR_ZONE),
                ip,
                Some(session),
                max_len,
            );
        };

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
                msg,
                ResponseCode::Refused,
                Some(REPLICATED_ZONE),
                ip,
                Some(session),
                max_len,
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
                msg,
                ResponseCode::Refused,
                Some(NOT_WRITABLE),
                ip,
                Some(session),
                max_len,
            );
        };
        let Some(path) = source.file_for(&zone_name.as_ref().to_presentation()) else {
            serving_error!(
                self.ctx.logger,
                ip,
                "UPDATE of {zone_name} REFUSED: no zone file to write it back to"
            );
            return self.signed_error(
                msg,
                ResponseCode::Refused,
                Some(NOT_WRITABLE),
                ip,
                Some(session),
                max_len,
            );
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
                signing.as_deref(),
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
                    msg,
                    ResponseCode::ServerFailure,
                    None,
                    ip,
                    Some(session),
                    max_len,
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
                return self.signed_error(msg, rejected.rcode, None, ip, Some(session), max_len);
            }
            // §3.4.2.1: a system failure is SERVFAIL with every applied update
            // undone. Nothing to undo here — the write is atomic and the map is
            // untouched until it succeeds.
            Err(UpdateFailure::System(e)) => {
                serving_error!(self.ctx.logger, ip, "UPDATE of {zone_name} failed: {e:#}");
                return self.signed_error(
                    msg,
                    ResponseCode::ServerFailure,
                    None,
                    ip,
                    Some(session),
                    max_len,
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
        self.signed_error(msg, ResponseCode::Ok, None, ip, Some(session), max_len)
    }

    /// The four things `install_zone` moves together — [`ZoneContext`].
    fn zone_context(&self) -> ZoneContext {
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
    System(anyhow::Error),
}

/// Apply an UPDATE to the zone as its *file* has it, persist it, and return the
/// version to install.
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
    signing: Option<&ZoneSigning>,
    known: Option<FileDigest>,
) -> Result<(Option<Zone>, UpdateReport, FileDigest), UpdateFailure> {
    // The zone as the file has it: unsigned, on the operator's serial. Taken
    // from the file rather than from the served copy, so an edit since the last
    // load is not silently reverted.
    //
    // The *bytes* always; the parse only when they are not the bytes this
    // server last wrote (`TODO.md` #64b). Reading and digesting 24 MB is
    // 7.8 ms against 435 for the parse and index, so the honest test is 1.8% of
    // what it replaces — which is why there is no `stat` shortcut here. `stat`
    // is 0.07 ms and cannot see an edit that preserves length and timestamp,
    // and a missed edit is the operator's change silently reverted, which is
    // the failure this re-read exists to prevent (`CLAUDE.md` §4).
    let raw = std::fs::read(path)
        .with_context(|| format!("re-reading {} to update it", path.display()))
        .map_err(UpdateFailure::System)?;
    let digest = FileDigest::of(&raw);

    // Reusing the served copy is only sound with no signing configured: then it
    // *is* what the file holds, because the last thing written there was the
    // last thing installed. A signed server serves RRSIGs and NSECs the file
    // does not carry, and 64d measured the four O(zone) steps at 12% of a
    // signed update anyway — so the case worth having is this one.
    let reused = known == Some(digest) && signing.is_none();
    let parsed;
    let source = if reused {
        previous
    } else {
        let text = String::from_utf8(raw)
            .map_err(|_| anyhow::anyhow!("{} is not UTF-8", path.display()))
            .map_err(UpdateFailure::System)?;
        parsed = rdns::zone::parse_zone_file(&text, origin)
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
    let installed = match signing {
        Some(signing) => signing
            .sign_one_incrementally(previous, zone)
            .map_err(UpdateFailure::System)?,
        None => zone,
    };
    Ok((Some(installed), report, written))
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
    use crate::testutil::{nm, query};
    use crate::zones::zone_key;
    use rdns::record_types;
    use rdns::zone::parse_zone_file_at;
    use rdns::UdpSizes;
    use std::collections::HashMap;

    pub(crate) use rdns::testutil::one_at_a_time;

    /// A zone of `records` A records under one apex, for the benchmarks.
    pub(crate) fn zone_text(records: usize) -> String {
        let mut text = String::new();
        text.push_str("$TTL 3600\n");
        text.push_str("@ IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n");
        text.push_str("@ IN NS ns.example.com.\n");
        text.push_str("ns IN A 192.0.2.1\n");
        for i in 0..records {
            let (a, b, c) = ((i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
            text.push_str(&format!("h{i} IN A 10.{a}.{b}.{c}\n"));
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
                None,
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
                    None,
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
    ///   records   unsigned     signed  incr-sign  full-sign      carried
    ///     10000     20.7ms    87.0ms    55.8ms   245.7ms  20004/20008
    ///    100000    165.5ms   931.4ms   783.7ms  2556.1ms  200004/200008
    ///   1000000   1952.1ms 11801.0ms 10314.9ms 26939.1ms  2000004/2000008
    /// ```
    ///
    /// Three warm runs, discarding the first after a rebuild. At a million
    /// records **signing is 10.3 s of 11.7 s, 88%**, so the whole of 64b and
    /// 64c — 68% of the unsigned 1.95 s — is **10% of what a signed update
    /// costs**. `full-sign` reproduces #44c's 28 s by a different route.
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
            "{:>9}  {:>9} {:>9} {:>9} {:>9}  {:>9}",
            "records", "unsigned", "signed", "incr-sign", "full-sign", "carried"
        );
        for records in [10_000usize, 100_000, 1_000_000] {
            let mut text = String::from("$TTL 3600\n");
            text.push_str(
                "@ IN SOA ns.example.com. hostmaster.example.com. 1 3600 600 86400 3600\n",
            );
            text.push_str("@ IN NS ns.example.com.\n");
            text.push_str("ns IN A 192.0.2.1\n");
            for i in 0..records {
                let (a, b, c) = ((i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
                text.push_str(&format!("h{i} IN A 10.{a}.{b}.{c}\n"));
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
                None,
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
                Some(&signing),
                None,
            )
            .unwrap_or_else(|_| panic!("the signed update applies at {records}"));
            let signed = start.elapsed();
            assert_eq!(report.changed, 1, "one record added at {records}");
            let installed = installed.expect("a changed zone is installed");

            // The signing step alone, from the same inputs the call above fed
            // it, so `signed` minus this is the four unsigned steps.
            std::fs::write(&path, &text).expect("restore the fixture");
            let reparsed = parse_zone_file_at(&path, "example.com.").expect("parses");
            let applied = update::apply(&reparsed, std::slice::from_ref(&change));
            let start = Instant::now();
            let again = signing
                .sign_one_incrementally(&previous, applied.zone)
                .expect("signs");
            let incr_sign = start.elapsed();
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
                "{records:>9}  {:>7.1}ms {:>7.1}ms {:>7.1}ms {:>7.1}ms  {:>9}",
                unsigned.as_secs_f64() * 1000.0,
                signed.as_secs_f64() * 1000.0,
                incr_sign.as_secs_f64() * 1000.0,
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
            None,
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
            None,
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
            None,
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
}
