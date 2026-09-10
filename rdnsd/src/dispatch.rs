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

use rdns::{
    clock::current_unix_timestamp,
    error::RequestError,
    ixfr::{ixfr_response, IxfrResponse},
    logging::QueryLogger,
    notify,
    response::ClientEdns,
    security::ResponseVerdict,
    transfer::axfr_envelopes,
    tsig::{self, TsigCheck, TsigSession},
    update,
    validation::Request,
    zone::{parse_zone_file_at, Zone},
    DnsMessage, OpCode, Qtype, ResponseCode,
};
use rdns_transport::tcp::{self, send_framed, Reply};
use rdns_transport::ServeContext;

use crate::answer::write_response;
use crate::replication::Secondaries;
use crate::zones::{install_zone, ZoneContext, ZoneMap, ZoneSigning};
use crate::{Scratch, Server, RDNSD_PAYLOAD_SIZE};

/// Where one request's reply goes, and the two things that follow from it.
///
/// The transport decided three things that were written out twice: how a reply
/// is framed, how large it may be, and whether a response budget applies. It is
/// the parameter that lets `rdnsd` have one dispatcher instead of two
/// (`TODO.md` #39b), and the one place `Framed` is matched for is why "a
/// transfer is TCP-only" is now a branch the compiler can see rather than a
/// comment about which caller got here.
pub(super) enum Wire<'a> {
    /// A connection's writer. Length-prefixed (RFC 1035 §4.2.2), a sequence
    /// allowed, and no response budget: the handshake proved the address.
    Framed(&'a mpsc::Sender<Reply>),
    /// One datagram back to the peer, capped by its EDNS advertisement and
    /// charged against the response budget.
    Datagram(&'a UdpSocket, SocketAddr),
}

impl Wire<'_> {
    /// The size ceiling this transport puts on a reply. Over TCP the length
    /// prefix is the only limit, so the client's EDNS payload size does not
    /// apply (RFC 6891 §6.2.2).
    fn max_len(&self, request: &DnsMessage) -> usize {
        match self {
            Wire::Framed(_) => u16::MAX as usize,
            Wire::Datagram(..) => request.udp_payload_size() as usize,
        }
    }

    /// Put one finished message on the wire, framing it if the transport frames.
    ///
    /// Callers hand over unframed bytes whichever transport they are on, which
    /// is what removes the `&framed[2..]` the UDP UPDATE path did by hand.
    async fn send(&self, bytes: &[u8], logger: &QueryLogger, ip: IpAddr) {
        match self {
            Wire::Framed(out) => {
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

    async fn handle(&self, packet: Vec<u8>, peer: SocketAddr, now: u64, out: mpsc::Sender<Reply>) {
        // A scratch per message here, where the UDP worker keeps one per worker:
        // `tcp::Handler` has no per-connection state to hang one on
        // (`TODO.md` #39e).
        let mut scratch = Scratch::default();
        self.answer(&packet, peer, now, &Wire::Framed(&out), &mut scratch)
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

        let qtype = msg.queries.first().map(|q| q.qtype);
        self.ctx.logger.log_query(ip, qtype, now);
        // Counted before any policy can return, so a request refused later is
        // still a request received (`TODO.md` #39a).
        self.ctx.metrics.count(&self.ctx.metrics.queries_received);
        if let Some(qtype) = qtype {
            self.ctx.metrics.track_query_type(qtype);
        }

        // One ceiling for every reply this request can produce, read once from
        // the transport that will carry it.
        let max_len = wire.max_len(&msg);

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
                let Some(response) = error_reply(&msg, ResponseCode::NotAuthorized, max_len) else {
                    return;
                };
                match rejection.attach(response, now) {
                    Ok(bytes) => wire.send(&bytes, &self.ctx.logger, ip).await,
                    Err(e) => serving_error!(self.ctx.logger, ip, "TSIG error reply: {e}"),
                }
                return;
            }
        };

        // Answered here rather than in `make_response`: a sequence of messages,
        // gated on an ACL, and the answer can be the whole zone. Only where a
        // sequence can be carried — AXFR is TCP alone (RFC 5936 §4.2) and an
        // IXFR over UDP is answered with a single SOA (RFC 1995 §2), both of
        // which `write_response` does below.
        if matches!(qtype, Some(Qtype::AXFR) | Some(Qtype::IXFR)) {
            if let Wire::Framed(out) = wire {
                self.answer_transfer(&msg, peer, session.as_mut(), now, out)
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
                notify_reply(&msg, &zones, &self.secondaries, peer).to_bytes_within_buf_with(
                    max_len,
                    &mut scratch.out,
                    &mut scratch.compressor,
                )
            } else {
                write_response(
                    &msg,
                    &zones,
                    &self.ctx.metrics,
                    max_len,
                    &mut scratch.out,
                    &mut scratch.compressor,
                    &mut scratch.key,
                )
            }
        };
        if let Err(e) = serialized {
            serving_error!(self.ctx.logger, ip, "serialization error: {e}");
            return;
        }

        self.finish(wire, &msg, session.as_mut(), peer, now, scratch)
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
        request: &DnsMessage,
        session: Option<&mut TsigSession>,
        peer: SocketAddr,
        now: u64,
        scratch: &Scratch,
    ) {
        let ip = peer.ip();
        let reply: Option<Cow<'_, [u8]>> = match wire {
            Wire::Framed(_) => Some(Cow::Borrowed(scratch.out.as_slice())),
            Wire::Datagram(..) => match self.ctx.admit_response(ip, scratch.out.len(), now) {
                ResponseVerdict::Send => Some(Cow::Borrowed(scratch.out.as_slice())),
                ResponseVerdict::Truncate => {
                    truncated_reply(request, wire.max_len(request)).map(Cow::Owned)
                }
                ResponseVerdict::Drop => None,
            },
        };
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
        }
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
        out: &mpsc::Sender<Reply>,
    ) {
        let ip = peer.ip();
        let qname = msg
            .queries
            .first()
            .map(|q| q.qname.clone())
            .unwrap_or_default();
        let incremental = msg.queries.first().map(|q| q.qtype) == Some(Qtype::IXFR);
        let kind = if incremental { "IXFR" } else { "AXFR" };

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
        let unauthorized = session
            .as_ref()
            .filter(|s| !s.may_transfer(&apex.as_ref().to_presentation()))
            .map(|s| s.key_name().to_string());
        if let Some(key_name) = unauthorized {
            serving_error!(
                self.ctx.logger,
                ip,
                "{kind} of {qname} REFUSED: key {key_name} is scoped to other zones"
            );
            self.send_transfer_error(msg, ResponseCode::Refused, ip, session, out)
                .await;
            return;
        }

        let authenticated_by = session.as_ref().map(|s| s.key_name().to_string());
        if authenticated_by.is_none() && !self.transfer_acl.allows(ip) {
            serving_error!(
                self.ctx.logger,
                ip,
                "{kind} of {qname} REFUSED: no TSIG key, and not in --allow-transfer"
            );
            // No session on this path by construction — it is the "no key" case.
            self.send_transfer_error(msg, ResponseCode::Refused, ip, None, out)
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
                self.send_transfer_error(msg, ResponseCode::NotAuthorized, ip, session, out)
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
                    self.send_transfer_error(msg, ResponseCode::ServerFailure, ip, session, out)
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
            self.send_transfer_error(msg, ResponseCode::ServerFailure, ip, session, out)
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
        ip: IpAddr,
        session: Option<&mut TsigSession>,
        out: &mpsc::Sender<Reply>,
    ) {
        if let Some(bytes) = self.signed_error(msg, rcode, ip, session, u16::MAX as usize) {
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
        ip: IpAddr,
        session: Option<&mut TsigSession>,
        max_len: usize,
    ) -> Option<Vec<u8>> {
        let Some(bytes) = error_reply(msg, rcode, max_len) else {
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
                return self.signed_error(msg, rejected.rcode, ip, session, max_len);
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
            return self.signed_error(msg, ResponseCode::Refused, ip, None, max_len);
        };
        if !session.may_update(&zone_name.as_ref().to_presentation()) {
            serving_error!(
                self.ctx.logger,
                ip,
                "UPDATE of {zone_name} REFUSED: key {} may not rewrite it",
                session.key_name()
            );
            return self.signed_error(msg, ResponseCode::Refused, ip, Some(session), max_len);
        }

        // §3.1.1: a zone we are not an authority for is NOTAUTH — not the query
        // path's REFUSED, because an UPDATE names the zone and asks whether we
        // are its authority.
        //
        // Cloned, not merely tested for, and in the one read guard: "do we serve
        // it" and the copy the signer works against must be the same version.
        let previous = {
            let zones = self.zone_map.read().await;
            zones.matching(zone_name.as_ref()).cloned()
        };
        let Some(previous) = previous else {
            tracing::info!(peer = %ip, "UPDATE of {zone_name}: NOTAUTH (not a zone served here)");
            return self.signed_error(msg, ResponseCode::NotAuthorized, ip, Some(session), max_len);
        };

        // A zone we replicate is the master's copy: the next refresh transfers
        // over the change, so accepting it tells the client a write succeeded
        // that has a timer on it. Folded through the helper the table is keyed
        // with, so the two cannot disagree.
        if self
            .secondaries
            .contains_key(zone_name.as_ref().folded().as_ref() as &[u8])
        {
            serving_error!(
                self.ctx.logger,
                ip,
                "UPDATE of {zone_name} REFUSED: this server replicates that zone, \
                 so its master owns it"
            );
            return self.signed_error(msg, ResponseCode::Refused, ip, Some(session), max_len);
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
            return self.signed_error(msg, ResponseCode::Refused, ip, Some(session), max_len);
        };
        let Some(path) = source.file_for(&zone_name.as_ref().to_presentation()) else {
            serving_error!(
                self.ctx.logger,
                ip,
                "UPDATE of {zone_name} REFUSED: no zone file to write it back to"
            );
            return self.signed_error(msg, ResponseCode::Refused, ip, Some(session), max_len);
        };

        // §3.7's serialization, held across the whole read-modify-write.
        let _applying = self.updates.applying.lock().await;

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
                    ip,
                    Some(session),
                    max_len,
                );
            }
        };

        let (installed, report) = match outcome {
            Ok(applied) => applied,
            Err(UpdateFailure::Prerequisite(rejected)) => {
                tracing::info!(peer = %ip, "UPDATE of {zone_name}: {rejected}");
                return self.signed_error(msg, rejected.rcode, ip, Some(session), max_len);
            }
            // §3.4.2.1: a system failure is SERVFAIL with every applied update
            // undone. Nothing to undo here — the write is atomic and the map is
            // untouched until it succeeds.
            Err(UpdateFailure::System(e)) => {
                serving_error!(self.ctx.logger, ip, "UPDATE of {zone_name} failed: {e:#}");
                return self.signed_error(
                    msg,
                    ResponseCode::ServerFailure,
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

        drop(_applying);
        self.signed_error(msg, ResponseCode::Ok, ip, Some(session), max_len)
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

/// The start of every reply that carries no records: the question echoed, and
/// the client's OPT mirrored with its DO bit (RFC 6891 §6.1.1, RFC 3225 §3).
///
/// One function because the mirroring is what drifts. It was written out at four
/// call sites, and three of them dropped the DO bit, so a validating client that
/// asked over UDP and got TC=1 read the answer as coming from a server that had
/// stopped doing DNSSEC (`TODO.md` #38, `CLAUDE.md` §7).
fn empty_reply(request: &DnsMessage) -> DnsMessage {
    let mut resp = DnsMessage::reply_to(request);
    if let Some(edns) = ClientEdns::of(request).mirror(RDNSD_PAYLOAD_SIZE) {
        resp.set_edns(edns);
    }
    resp
}

/// An empty reply to `request` carrying `rcode`, serialized within `max_len`.
///
/// The ceiling is the transport's — [`Wire::max_len`] — and it is the only thing
/// the UDP TSIG rejection's own copy of this used to differ in
/// (`TODO.md` #30g).
fn error_reply(request: &DnsMessage, rcode: ResponseCode, max_len: usize) -> Option<Vec<u8>> {
    let mut resp = empty_reply(request);
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
/// `Ok((None, report))` when nothing changed: no write, nothing to install, and
/// the client still gets NOERROR. See [`crate::UpdateHandling`] for why the file rather
/// than the copy in memory is what gets read and written.
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
) -> Result<(Option<Zone>, update::Applied), UpdateFailure> {
    // The zone as the file has it: unsigned, on the operator's serial. Re-read
    // rather than taken from the served copy, so an edit since the last load is
    // not silently reverted.
    let source = parse_zone_file_at(path, origin)
        .with_context(|| format!("re-reading {} to update it", path.display()))
        .map_err(UpdateFailure::System)?;

    // §3.2, against the unsigned zone: a prerequisite naming RRSIG or NSEC would
    // otherwise assert on this server's signing configuration.
    update::check_prerequisites(&source, prerequisites).map_err(UpdateFailure::Prerequisite)?;

    let applied = update::apply(&source, changes);
    if applied.changed == 0 {
        return Ok((None, applied));
    }

    rdns::zone_writer::write_zone_file(&applied.zone, path)
        .with_context(|| format!("writing {} back after an update", path.display()))
        .map_err(UpdateFailure::System)?;

    // Signed as a load would sign it, from the file's now-bumped serial, so the
    // served number moves too. Incrementally against the version being served:
    // a full re-sign would reinception every RRSIG and put the whole zone into
    // the next IXFR delta.
    let installed = match signing {
        Some(signing) => signing
            .sign_one_incrementally(previous, &applied.zone)
            .map_err(UpdateFailure::System)?,
        None => applied.zone.clone(),
    };
    Ok((Some(installed), applied))
}

/// An empty TC=1 answer to `request`: the question echoed, no records.
///
/// What a client over its response budget gets instead of the answer: smaller
/// than the query, so useless for amplification, and RFC 1035 §4.2.1 has the
/// client retry over TCP, where the handshake proves the source address. Silence
/// would leave a legitimate client with a timeout and no hint that TCP works.
///
/// No AA — the reply carries no data — and bounded by the caller's ceiling,
/// which on the transport this can happen on is the client's EDNS payload size
/// rather than 512 (RFC 6891 §6.2.4).
fn truncated_reply(request: &DnsMessage, max_len: usize) -> Option<Vec<u8>> {
    let mut resp = empty_reply(request);
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
) -> DnsMessage {
    let zone = notify::notified_zone(msg).unwrap_or_default();
    // Folded octets, which is what the registry is keyed on. The fold is
    // ASCII-only (RFC 4343) and `Name` does it; `str::to_lowercase` would fold
    // U+212A KELVIN SIGN onto `k` and merge two names that differ on the wire.
    let key = zone.as_ref().folded();

    if let Some(replicated) = secondaries.get(key.as_ref() as &[u8]) {
        if replicated.masters.contains(&peer.ip()) {
            // `notify_one` leaves a permit for a task that is mid-transfer, so a
            // NOTIFY arriving at a busy moment is not lost.
            for wake in &replicated.wake {
                wake.notify_one();
            }
            tracing::info!(%peer, "NOTIFY for {zone}: refreshing now");
            return notify::notify_response(msg, ResponseCode::Ok);
        }
        tracing::warn!(
            %peer,
            "NOTIFY for {zone}: REFUSED (not one of its masters — \
             a NOTIFY costs its recipient a transfer)"
        );
        return notify::notify_response(msg, ResponseCode::Refused);
    }

    // The zone map is keyed in the same folded form, so this is a lookup rather
    // than a scan of every origin.
    let ours = zone_map.contains_key(key.as_ref());
    let why = if ours {
        "this server is its primary, not a secondary"
    } else {
        "not a zone served here"
    };
    tracing::info!(%peer, "NOTIFY for {zone}: NOTAUTH ({why})");
    notify::notify_response(msg, ResponseCode::NotAuthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::ReplicatedZone;
    use crate::testutil::{nm, query};
    use crate::zones::zone_key;
    use rdns::record_types;
    use std::collections::HashMap;
    use tokio::sync::Notify;

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
        let asked = query("www.example.com.", Qtype::of(record_types::A), true);
        let ceiling = asked.udp_payload_size() as usize;

        let bytes = truncated_reply(&asked, ceiling).expect("a truncated reply");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("it parses");
        assert!(reply.truncation, "TC=1");
        assert!(
            reply
                .edns()
                .expect("an OPT, since the query had one")
                .do_bit
        );

        let bytes = error_reply(&asked, ResponseCode::Refused, ceiling).expect("an error reply");
        let reply = DnsMessage::try_from_bytes(&bytes).expect("it parses");
        assert_eq!(reply.rcode, ResponseCode::Refused);
        assert!(reply.edns().expect("an OPT").do_bit, "and so does this one");

        let plain = query("www.example.com.", Qtype::of(record_types::A), false);
        let ceiling = plain.udp_payload_size() as usize;
        for bytes in [
            truncated_reply(&plain, ceiling).expect("a truncated reply"),
            error_reply(&plain, ResponseCode::Refused, ceiling).expect("an error reply"),
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
        let wake = Arc::new(Notify::new());
        let mut registry = HashMap::new();
        registry.insert(
            nm("replicated.test.").as_ref().folded().into_owned(),
            ReplicatedZone {
                masters: vec!["192.0.2.1".parse().unwrap()],
                wake: vec![wake.clone()],
            },
        );
        let secondaries: Secondaries = Arc::new(registry);

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

        let from = |zone: &str, ip: &str| {
            let msg = notify::notify_request(nm(zone).as_ref(), None, 1);
            let peer: SocketAddr = format!("{ip}:5353").parse().unwrap();
            notify_reply(&msg, &zones, &secondaries, peer).rcode
        };

        assert_eq!(
            from("replicated.test.", "192.0.2.1"),
            ResponseCode::Ok,
            "from its master: acted on"
        );
        assert_eq!(
            from("replicated.test.", "203.0.113.9"),
            ResponseCode::Refused,
            "from anywhere else: refused, because acting would cost us a transfer"
        );
        assert_eq!(
            from("example.com.", "192.0.2.1"),
            ResponseCode::NotAuthorized,
            "a zone we are the primary for: we are nobody's secondary for it"
        );
        assert_eq!(
            from("never-heard-of.test.", "192.0.2.1"),
            ResponseCode::NotAuthorized
        );
    }
}
