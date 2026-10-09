//! Writing a reply straight into the send buffer.
//!
//! [`ResponseWriter`] appends each record to the wire as it is found, rather
//! than building a [`DnsMessage`] of owned `String`s and cloned RDATA to
//! serialize: [`crate::RecordData`] already holds uncompressed wire-format
//! bytes, so a record costs a copy into the buffer and nothing from the
//! allocator.
//!
//! The header is written last, over a placeholder, because AA, RCODE, TC and the
//! section counts are only known once the answer is built.
//!
//! The record, question, header and OPT encoders live here and are what
//! [`DnsMessage::to_bytes_with`] calls too: two encoders for one wire format is
//! how the second one gets a field wrong (`CLAUDE.md` §7).

use crate::compression::NameCompressor;
use crate::dname::write_bytes;
use crate::ede::ExtendedError;
use crate::error::WireError;
use crate::{
    Class, DnsMessage, Edns, NameRef, OpCode, QuerySection, RecordDataRef, ResponseCode, Ttl,
    CLASSIC_UDP_SIZE, OPT_RECORD_TYPE,
};

/// The twelve-octet header, minus the counts.
#[derive(Clone, Copy)]
pub(crate) struct Header {
    pub id: u16,
    pub response: bool,
    pub opcode: OpCode,
    pub authoritive: bool,
    pub truncation: bool,
    pub recursion: bool,
    pub recursion_ok: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: ResponseCode,
}

/// Which section a record goes in.
///
/// The discriminants index the header's counts, so QDCOUNT is 0 and the three
/// record sections follow it in wire order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Section {
    Answer = 1,
    Authority = 2,
    Additional = 3,
}

/// A response being written into a caller-owned buffer.
///
/// Sections go out in order and a compression pointer can only point backwards,
/// so records must be pushed in section order — [`ResponseWriter::push`] says so
/// with a `debug_assert`. A caller holding two records out of order has to
/// reorder its own code; the wire cannot.
pub struct ResponseWriter<'a> {
    out: &'a mut Vec<u8>,
    compressor: &'a mut NameCompressor,
    /// What the caller asked to fit in. `out` is at least this long, and at
    /// least [`CLASSIC_UDP_SIZE`] so a truncated reply always has room.
    limit: usize,
    pos: usize,
    /// One past the question section: what truncation rewinds to.
    body: usize,
    /// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
    counts: [u16; 4],
    section: Section,
    header: Header,
    edns: Option<Edns>,
    /// The reason beside the RCODE (RFC 8914), folded into the OPT by
    /// [`ResponseWriter::finish`]. Held apart from `edns` because the two are
    /// decided at opposite ends of the answer path: the RCODE and its reason
    /// deep inside the zone lookup, the OPT once, at the end, from what the
    /// client sent. Dropped silently when there is no OPT to carry it, which
    /// is §2's rule and the one this type exists to make unskippable.
    extended_error: Option<ExtendedError>,
    truncated: bool,
}

impl<'a> ResponseWriter<'a> {
    /// Begin a reply to `request`: the header's placeholder and the echoed
    /// question, which is what every caller here starts with.
    ///
    /// The question is written straight from the request, so echoing it costs
    /// neither the `Vec` nor the QNAME `String` that a `queries.clone()` did.
    ///
    /// `compressor` is cleared here for the reason [`DnsMessage::to_bytes_with`]
    /// clears it: an offset is a position in *this* message.
    pub fn start(
        out: &'a mut Vec<u8>,
        compressor: &'a mut NameCompressor,
        max_len: usize,
        request: &DnsMessage,
    ) -> Result<Self, WireError> {
        compressor.clear();
        out.clear();
        out.resize(max_len.max(CLASSIC_UDP_SIZE as usize), 0);

        let qdcount: u16 = request
            .queries
            .len()
            .try_into()
            .map_err(|_| WireError::TooLong {
                what: "the question section",
                limit: u16::MAX as usize,
                actual: request.queries.len(),
            })?;

        let mut pos = HEADER_LEN;
        for q in &request.queries {
            pos = write_query(compressor, out, pos, q)?;
        }

        Ok(Self {
            out,
            compressor,
            limit: max_len,
            pos,
            body: pos,
            counts: [qdcount, 0, 0, 0],
            section: Section::Answer,
            header: Header {
                id: request.id,
                response: true,
                opcode: request.opcode,
                authoritive: false,
                truncation: false,
                recursion: request.recursion,
                recursion_ok: false,
                ad: false,
                cd: request.cd,
                rcode: ResponseCode::Ok,
            },
            edns: None,
            extended_error: None,
            truncated: false,
        })
    }

    pub fn set_authoritative(&mut self, authoritative: bool) {
        self.header.authoritive = authoritative;
    }

    pub fn is_authoritative(&self) -> bool {
        self.header.authoritive
    }

    pub fn set_rcode(&mut self, rcode: ResponseCode) {
        self.header.rcode = rcode;
    }

    pub fn rcode(&self) -> ResponseCode {
        self.header.rcode
    }

    /// Attach an OPT record, written by [`ResponseWriter::finish`] after every
    /// other record — RFC 6891 §6.1.1 mirroring, and the carrier of an extended
    /// RCODE's high bits (§6.1.3).
    pub fn set_edns(&mut self, edns: Edns) {
        self.edns = Some(edns);
    }

    /// Say *why* this reply carries the RCODE it does (RFC 8914).
    ///
    /// Order-independent: it may be set before or after [`set_edns`], and
    /// reaches the wire only if there is an OPT to put it in.
    ///
    /// [`set_edns`]: ResponseWriter::set_edns
    pub fn set_extended_error(&mut self, error: ExtendedError) {
        self.extended_error = Some(error);
    }

    /// Append one record. Past the size limit the reply becomes an empty TC=1
    /// one and every later push is dropped, so a caller need not check.
    pub fn push(
        &mut self,
        section: Section,
        name: NameRef<'_>,
        class: Class,
        ttl: Ttl,
        rdata: RecordDataRef<'_>,
    ) -> Result<(), WireError> {
        if self.truncated {
            return Ok(());
        }
        debug_assert!(
            section >= self.section,
            "sections go out in order: {section:?} after {:?}",
            self.section
        );
        self.section = section;
        match write_rr(self.compressor, self.out, self.pos, name, class, ttl, rdata) {
            Ok(end) if end <= self.limit => {
                self.pos = end;
                self.counts[section as usize] += 1;
            }
            // Fits the buffer but not what the caller asked to send, or does not
            // fit the buffer at all. The second arrives as an error from the
            // writer rather than a comparison, because the buffer *is* the limit
            // (`CLAUDE.md` §13); every other `WireError` is a real failure to
            // encode and is the caller's problem.
            Ok(_)
            | Err(WireError::Truncated {
                what: "the output buffer",
                ..
            }) => self.truncate(),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Drop back to the question and set TC (RFC 1035 §4.2.1).
    ///
    /// All of the records, not back to a record boundary: a partial RRset must
    /// not go out (RFC 2181 §9), and this is the shape `to_bytes_within_buf`
    /// already produced by rebuilding the message with its sections cleared.
    ///
    /// The compressor rewinds with the buffer, because a suffix recorded past
    /// this point is a pointer into bytes about to be overwritten — and
    /// `write_name` records a name's suffixes *before* writing them, so even the
    /// record that overflowed has left entries behind. Nothing after this point
    /// compresses a name today (the OPT's owner is the root), so the rewind is
    /// not observable on the wire; it is here so that it stays true of a change
    /// that writes something else after truncating.
    fn truncate(&mut self) {
        self.truncated = true;
        self.pos = self.body;
        self.counts = [self.counts[0], 0, 0, 0];
        self.compressor.rewind(self.body);
    }

    /// Write the OPT record and the header, leaving `out` holding exactly the
    /// wire bytes.
    pub fn finish(mut self) -> Result<(), WireError> {
        let rcode = wire_rcode(self.header.rcode, self.edns.is_some())?;
        if let Some(mut edns) = self.edns.take() {
            if let Some(error) = self.extended_error {
                edns = edns.with_extended_error(error)?;
            }
            match write_opt(self.out, self.pos, &edns, rcode) {
                Ok(end) if end <= self.limit => {
                    self.pos = end;
                    self.counts[3] += 1;
                }
                Ok(_)
                | Err(WireError::Truncated {
                    what: "the output buffer",
                    ..
                }) => {
                    // The OPT survives truncation: the size limit is itself
                    // signalled through EDNS. A header, a question and an OPT
                    // are under 300 octets, and an EDE adds at most 6 plus
                    // `ede::MAX_EXTRA_TEXT`, so the 512-octet floor `start`
                    // sized the buffer to leaves room for this one.
                    //
                    // Truncating rather than dropping the EDE is RFC 8914 §3
                    // the way round it asks for: "servers SHOULD truncate
                    // messages by dropping EDE options before dropping other
                    // data" is about an EDE on an *answer*, and every reply
                    // that carries one here carries no other data to drop.
                    self.truncate();
                    self.pos = write_opt(self.out, self.pos, &edns, rcode)?;
                    self.counts[3] = 1;
                }
                Err(e) => return Err(e),
            }
        }
        self.header.truncation = self.truncated;
        write_header(self.out, self.header, rcode, self.counts)?;
        self.out.truncate(self.pos);
        Ok(())
    }
}

/// ID, two flag octets, four counts.
pub(crate) const HEADER_LEN: usize = 12;

/// RCODE as the twelve bits RFC 6891 §6.1.3 gives it, checked against what is
/// there to carry them.
#[inline]
pub(crate) fn wire_rcode(rcode: ResponseCode, has_edns: bool) -> Result<u16, WireError> {
    let rcode = rcode.to_u16();
    if rcode > 0xfff {
        return Err(WireError::malformed(
            "the header",
            format!("RCODE {rcode} does not fit the 12 bits RFC 6891 §6.1.3 gives it"),
        ));
    }
    if rcode > 0xf && !has_edns {
        return Err(WireError::malformed(
            "the header",
            format!(
                "extended RCODE {rcode} needs an EDNS0 OPT record to carry \
                 its high bits (RFC 6891 §6.1.3)"
            ),
        ));
    }
    Ok(rcode)
}

/// The TC bit of a message that is already bytes.
///
/// Reparsing a finished reply to read one flag costs a `DnsMessage`, and the
/// caller that needs this — `rdnsd`'s signing epilogue, which owes RFC 8945
/// §5.3's altered response — is on the answer path. Here rather than at that
/// call site so the bit's position is written once, beside the `write_header`
/// that puts it there.
///
/// `false` for anything shorter than a header, which is not a message.
pub fn is_truncated(message: &[u8]) -> bool {
    message.len() >= HEADER_LEN && message[2] & 0b10 != 0
}

#[inline]
pub(crate) fn write_header(
    buf: &mut [u8],
    header: Header,
    rcode: u16,
    counts: [u16; 4],
) -> Result<usize, WireError> {
    let hi: u8 = (header.response as u8) << 7
        | (header.opcode.to_u8() & 0xf_u8) << 3
        | (header.authoritive as u8) << 2
        | (header.truncation as u8) << 1
        | header.recursion as u8;
    let lo: u8 = (header.recursion_ok as u8) << 7
        | (header.ad as u8) << 5
        | (header.cd as u8) << 4
        | (rcode & 0xf) as u8;

    let mut pos = write_bytes(buf, 0, &header.id.to_be_bytes())?;
    pos = write_bytes(buf, pos, &[hi, lo])?;
    for count in counts {
        pos = write_bytes(buf, pos, &count.to_be_bytes())?;
    }
    Ok(pos)
}

#[inline]
pub(crate) fn write_query(
    compressor: &mut NameCompressor,
    buf: &mut [u8],
    pos: usize,
    q: &QuerySection,
) -> Result<usize, WireError> {
    let pos = compressor.write_name(q.qname.as_ref(), buf, pos)?;
    let pos = write_bytes(buf, pos, &q.qtype.to_u16().to_be_bytes())?;
    write_bytes(buf, pos, &q.qclass.to_u16().to_be_bytes())
}

/// One resource record.
///
/// Owner names are compressed against everything written so far; RDATA is stored
/// uncompressed and wire-ready, so it is a straight copy except for the types
/// whose embedded names may legally be compressed.
#[inline]
pub(crate) fn write_rr(
    compressor: &mut NameCompressor,
    buf: &mut [u8],
    pos: usize,
    name: NameRef<'_>,
    class: Class,
    ttl: Ttl,
    rdata: RecordDataRef<'_>,
) -> Result<usize, WireError> {
    let mut pos = compressor.write_name(name, buf, pos)?;
    pos = write_bytes(buf, pos, &rdata.rtype().to_u16().to_be_bytes())?;
    pos = write_bytes(buf, pos, &class.to_u16().to_be_bytes())?;
    pos = write_bytes(buf, pos, &ttl.to_wire().to_be_bytes())?;

    // RDLEN can only be known once the RDATA is written, since compression
    // changes its length. Leave a hole and fill it in.
    let rdlen_at = pos;
    pos = write_bytes(buf, pos, &[0u8, 0u8])?;
    let rdata_at = pos;
    pos = compressor.write_rdata(rdata.rtype(), rdata.bytes(), buf, pos)?;
    let rdlen: u16 = (pos - rdata_at)
        .try_into()
        .map_err(|_| WireError::TooLong {
            what: "RDATA",
            limit: u16::MAX as usize,
            actual: pos - rdata_at,
        })?;
    write_bytes(buf, rdlen_at, &rdlen.to_be_bytes())?;
    Ok(pos)
}

/// The OPT record, last in the additional section: `tsig::append_tsig` appends
/// to the finished bytes, and RFC 8945 §5.1 requires TSIG final.
#[inline]
pub(crate) fn write_opt(
    buf: &mut [u8],
    pos: usize,
    edns: &Edns,
    rcode: u16,
) -> Result<usize, WireError> {
    // NAME is root, TYPE is OPT, CLASS is the payload size and TTL packs the
    // extended RCODE, the version and the flags (RFC 6891 §6.1.3).
    let mut pos = write_bytes(buf, pos, &[0])?;
    pos = write_bytes(buf, pos, &OPT_RECORD_TYPE.to_u16().to_be_bytes())?;
    pos = write_bytes(buf, pos, &edns.udp_payload_size.to_be_bytes())?;
    let ttl = ((rcode as u32 >> 4) << 24)
        | ((edns.version as u32) << 16)
        | if edns.do_bit { 0x8000 } else { 0 };
    pos = write_bytes(buf, pos, &ttl.to_be_bytes())?;
    let rdata = edns.rdata();
    let rdlen: u16 = rdata.len().try_into().map_err(|_| WireError::TooLong {
        what: "OPT RDATA",
        limit: u16::MAX as usize,
        actual: rdata.len(),
    })?;
    pos = write_bytes(buf, pos, &rdlen.to_be_bytes())?;
    write_bytes(buf, pos, rdata)
}

/// What a request's OPT record says, once the two refusals RFC 6891 requires
/// are out of the way.
///
/// Carries only what a reply needs: whether to attach an OPT at all
/// (RFC 6891 §6.1.1), what to set DO to (RFC 3225 §3), and which options the
/// client asked for that a reply honours — Padding (RFC 7830 §4, `TODO.md`
/// #187) and NSID (RFC 5001, #179), one field each. The advertised
/// payload size is not here — that is [`DnsMessage::udp_payload_size`], which
/// applies §6.2.3's floor, and is a question about the transport rather than
/// about the reply's OPT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientEdns {
    /// No OPT record: the reply carries none either.
    Absent,
    /// An OPT we can answer, with DO as the client set it, and whether it
    /// carried a Padding option (code 12) and an NSID option (code 3).
    Present {
        do_bit: bool,
        padding: bool,
        nsid: bool,
    },
}

/// What this server says about itself in a reply's OPT: the payload size it
/// can reassemble and, if the operator set one, its NSID (RFC 5001).
///
/// One value for [`ClientEdns::mirror`] to read rather than a size and an
/// identifier passed separately, so a site that mirrors an OPT cannot mirror
/// it without the NSID (`CLAUDE.md` §7). `Copy`, with the identifier
/// `'static`: it is set once at startup and read on every reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerOpt {
    pub payload_size: u16,
    pub nsid: Option<&'static [u8]>,
}

impl ServerOpt {
    /// A server with no NSID configured, advertising `payload_size`.
    pub fn sized(payload_size: u16) -> ServerOpt {
        ServerOpt {
            payload_size,
            nsid: None,
        }
    }
}

impl ClientEdns {
    /// The client's EDNS as far as a *reply* needs it. Total: it has no refusal
    /// to report.
    ///
    /// [`client_edns`] is the answering path's version, and refuses a malformed
    /// option list with the RCODE that refuses it. A reply that has already
    /// chosen its RCODE — a refusal, a TC=1, a NOTIMP — has nothing left to
    /// refuse, still owes the OPT (RFC 6891 §6.1.1), and cannot read DO out of
    /// a list that did not parse, so that case mirrors DO clear.
    ///
    /// Every such reply goes through here rather than through `has_edns()` and
    /// a fresh `Edns`: three sites did that and all three dropped the client's
    /// DO bit, which RFC 3225 §3 says "MUST be copied in the response"
    /// (`CLAUDE.md` §7).
    pub fn of(request: &DnsMessage) -> ClientEdns {
        client_edns(request).unwrap_or(ClientEdns::Present {
            do_bit: false,
            padding: false,
            nsid: false,
        })
    }

    fn is_present(self) -> bool {
        matches!(self, ClientEdns::Present { .. })
    }

    /// DNSSEC records are the client's to ask for (RFC 4035 §3.1.1); no OPT is
    /// no DO.
    pub fn do_bit(self) -> bool {
        matches!(self, ClientEdns::Present { do_bit: true, .. })
    }

    /// The query carried RFC 7830's Padding option, so a reply over an
    /// encrypted transport owes one ([`pad_reply`]).
    pub fn padding(self) -> bool {
        matches!(self, ClientEdns::Present { padding: true, .. })
    }

    /// The query carried an NSID option (RFC 5001 §2.1).
    pub fn nsid(self) -> bool {
        matches!(self, ClientEdns::Present { nsid: true, .. })
    }

    /// The OPT to mirror back, or `None` when the client used no EDNS —
    /// replying with an unsolicited OPT is not mirroring.
    ///
    /// Carries the server's NSID when the client asked for it and one is
    /// configured. RFC 5001 §2.2: the server "MUST ignore any NSID payload data
    /// that might be present in the query message" and "MUST NOT send an NSID
    /// option back to a resolver which did not request it" — so the value is
    /// the configuration's and the trigger the request's.
    pub fn mirror(self, server: ServerOpt) -> Option<Edns> {
        self.is_present().then(|| {
            let mut edns = match server.nsid.filter(|_| self.nsid()) {
                Some(nsid) => Edns::with_options(
                    server.payload_size,
                    crate::EDNS_VERSION,
                    false,
                    &[crate::edns::EdnsOption {
                        code: crate::edns::EDNS_OPTION_NSID,
                        data: nsid.to_vec(),
                    }],
                )
                // Validated at startup to fit the 16-bit length field.
                .unwrap_or_else(|_| Edns::with_payload_size(server.payload_size)),
                None => Edns::with_payload_size(server.payload_size),
            };
            edns.do_bit = self.do_bit();
            edns
        })
    }

    /// The same OPT, carrying `error` when there is one (RFC 8914 §2).
    ///
    /// The EDE goes where the OPT goes and nowhere else, so a client that sent
    /// none gets neither: this is the [`DnsMessage`]-shaped half of the rule
    /// [`ResponseWriter::set_extended_error`] holds for the writer-shaped half.
    ///
    /// Total. Encoding the option can only fail on one too long for its length
    /// field, which [`ExtendedError`]'s own bound on EXTRA-TEXT puts out of
    /// reach on the fresh OPT this builds; the answer to that impossible `Err`
    /// is to drop the *reason* and keep the reply, since a refusal without its
    /// annotation is still the answer and a refusal that failed to serialize is
    /// not. Decided here rather than by each caller (`CLAUDE.md` §7).
    pub fn mirror_with(self, server: ServerOpt, error: Option<ExtendedError>) -> Option<Edns> {
        let mirrored = self.mirror(server)?;
        let Some(error) = error else {
            return Some(mirrored);
        };
        match mirrored.with_extended_error(error) {
            Ok(annotated) => Some(annotated),
            // `with_extended_error` consumed the OPT, so the unreachable arm
            // rebuilds the bare one rather than cloning it up front for it.
            Err(_) => self.mirror(server),
        }
    }
}

/// Read `request`'s EDNS, or the RCODE that refuses it.
///
/// `Err` is FORMERR for an option list that does not parse and BADVERS for a
/// version past [`crate::EDNS_VERSION`] (RFC 6891 §6.1.3). Both refusals still owe the
/// client a bare version-0 OPT, since BADVERS is an extended RCODE and its high
/// bits live in that record — the caller attaches it, because a refusal is
/// answered differently on each daemon.
///
/// `edns_header` rather than `edns()`: nothing here wants the option list,
/// which costs a `Vec` per option, and it still checks the list is well formed.
/// One function for both daemons (`CLAUDE.md` §7). The Padding option is looked
/// for with [`Edns::has_option`], which copies nothing.
pub fn client_edns(request: &DnsMessage) -> Result<ClientEdns, ResponseCode> {
    let header = request
        .edns_header()
        .map_err(|_| ResponseCode::FormatError)?;
    match header {
        None => Ok(ClientEdns::Absent),
        Some(edns) if edns.version > crate::EDNS_VERSION => Err(ResponseCode::BadOptVersion),
        Some(edns) => Ok(ClientEdns::Present {
            do_bit: edns.do_bit,
            nsid: request
                .edns
                .as_ref()
                .is_some_and(|opt| opt.has_option(crate::edns::EDNS_OPTION_NSID) == Ok(true)),
            padding: request
                .edns
                .as_ref()
                .is_some_and(|opt| opt.has_option(crate::edns::EDNS_OPTION_PADDING) == Ok(true)),
        }),
    }
}

/// RFC 8467 §4.1(2): a server "SHOULD pad the corresponding response to a
/// multiple of 468 octets".
pub const PADDING_BLOCK: usize = 468;

/// Pad a finished, unsigned reply whose last record is its OPT, in place
/// (RFC 7830, `TODO.md` #187). `false` when there is no OPT last, or no room.
///
/// The caller decides *whether*: only a reply over an encrypted transport to a
/// query that carried the option, because RFC 7830 §6 says "implementations
/// MUST NOT use this option if the DNS transport is not encrypted". This
/// decides *how much*: the whole message, option header included, to the next
/// multiple of [`PADDING_BLOCK`], with 0x00 octets (§3).
///
/// Here, on bytes, because only the final length decides it, and every reply
/// leaves through serialization by a different builder. Before TSIG, which
/// must be last (RFC 8945 §5.1) and has to cover the padding.
///
/// `payload` is the client's advertised size and `frame` what the transport
/// can carry, each less anything the caller will still append. §4: "padded
/// DNS messages MUST NOT exceed the number of octets specified in the
/// Requestor's Payload Size field", so a reply that fits under `payload` is
/// padded at most to it. One already past it — a stream reply larger than a
/// datagram could be, which is ordinary — was never bounded by it, and is
/// bounded by `frame` instead.
pub fn pad_reply(reply: &mut Vec<u8>, payload: usize, frame: usize) -> bool {
    let Some(opt) = last_record_is_opt(reply) else {
        return false;
    };
    let len = reply.len();
    let limit = if len <= payload { payload } else { frame };
    let target = (len + 4).div_ceil(PADDING_BLOCK) * PADDING_BLOCK;
    let target = target.min(limit);
    if target < len + 4 {
        return false;
    }
    let pad = target - len - 4;
    let rdlen = u16::from_be_bytes([reply[opt.rdlen], reply[opt.rdlen + 1]]) as usize;
    let Ok(rdlen) = u16::try_from(rdlen + 4 + pad) else {
        return false;
    };
    let Ok(pad16) = u16::try_from(pad) else {
        return false;
    };
    reply[opt.rdlen..opt.rdlen + 2].copy_from_slice(&rdlen.to_be_bytes());
    reply.extend_from_slice(&crate::edns::EDNS_OPTION_PADDING.to_be_bytes());
    reply.extend_from_slice(&pad16.to_be_bytes());
    reply.resize(target, 0);
    true
}

/// Append one option to a finished message whose last record is its OPT, in
/// place. `false` when there is no OPT last or the RDATA would overflow.
///
/// For a query built elsewhere that one transport needs more of: the
/// resolver's DoT queries carry edns-tcp-keepalive (RFC 7828 §3.2.1), which
/// UDP ones must not.
pub fn append_option(msg: &mut Vec<u8>, code: u16, data: &[u8]) -> bool {
    let Some(opt) = last_record_is_opt(msg) else {
        return false;
    };
    let rdlen = u16::from_be_bytes([msg[opt.rdlen], msg[opt.rdlen + 1]]) as usize;
    let (Ok(rdlen), Ok(len)) = (
        u16::try_from(rdlen + 4 + data.len()),
        u16::try_from(data.len()),
    ) else {
        return false;
    };
    msg[opt.rdlen..opt.rdlen + 2].copy_from_slice(&rdlen.to_be_bytes());
    msg.extend_from_slice(&code.to_be_bytes());
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(data);
    true
}

/// Where an OPT's RDLENGTH sits, found by walking the message.
struct OptAt {
    rdlen: usize,
}

/// The OPT, if it is the message's last record, sits in the additional
/// section and ends exactly where the message does. Walked rather than assumed
/// from the tail: a record's start cannot be found from its end.
fn last_record_is_opt(msg: &[u8]) -> Option<OptAt> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let count = |at: usize| u16::from_be_bytes([msg[at], msg[at + 1]]) as usize;
    let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));
    if ar == 0 {
        return None;
    }
    let mut pos = HEADER_LEN;
    for _ in 0..qd {
        pos = skip_name(msg, pos)?.checked_add(4)?;
    }
    let mut last = None;
    for _ in 0..an + ns + ar {
        let start = pos;
        pos = skip_name(msg, pos)?;
        let fixed = msg.get(pos..pos + 10)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rdlen = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        last = Some((start, rtype, pos + 8));
        pos = pos.checked_add(10 + rdlen)?;
    }
    let (start, rtype, rdlen) = last?;
    (pos == msg.len() && rtype == OPT_RECORD_TYPE.to_u16() && msg.get(start) == Some(&0))
        .then_some(OptAt { rdlen })
}

/// One past a name, compressed or not.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            l if l & 0xc0 == 0xc0 => return (pos + 2 <= msg.len()).then_some(pos + 2),
            l if l & 0xc0 == 0 => pos += 1 + l as usize,
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::RecordData;

    use super::*;
    use crate::ede::InfoCode;

    /// `TODO.md` #45e, answered **no**: this resolver does not implement EDNS
    /// Client Subnet, so a query carrying one is answered without it. RFC 7871
    /// §11 is the reason — the option makes "the network address of the client
    /// ... visible to all servers involved in the resolution process" — and the
    /// mechanism is that `mirror` builds a *fresh* OPT rather than copying the
    /// client's.
    ///
    /// A test for the absence of a behaviour, because that is the kind that
    /// comes back: echoing an option is one line away from here, and an echoed
    /// ECS with SCOPE 0 is a claim to support it (RFC 7871 §7.2).
    #[test]
    fn no_option_of_the_clients_is_echoed_back() {
        use crate::edns::{EdnsOption, EDNS_OPTION_CLIENT_SUBNET, EDNS_OPTION_NSID};

        let ecs = EdnsOption {
            code: EDNS_OPTION_CLIENT_SUBNET,
            // FAMILY 1, SOURCE PREFIX-LENGTH 24, SCOPE 0, 192.0.2.0.
            data: vec![0, 1, 24, 0, 192, 0, 2],
        };
        let nsid = EdnsOption {
            code: EDNS_OPTION_NSID,
            data: Vec::new(),
        };
        let mut request = request("example.com.", false);
        request.set_edns(
            Edns::with_options(1232, 0, true, &[ecs, nsid]).expect("a well-formed option list"),
        );

        let mirrored = ClientEdns::of(&request)
            .mirror(ServerOpt::sized(1232))
            .expect("the client used EDNS, so it gets an OPT back");
        assert!(
            mirrored.options().expect("well formed").is_empty(),
            "a fresh OPT, carrying the payload size and DO and nothing else"
        );
        assert!(mirrored.do_bit, "and DO, which is mirrored on purpose");
    }

    use crate::name::nm;
    use crate::record_types;
    use crate::ResourceRecord;
    use crate::{DnsMessageBuilder, ParsedRecord, Qtype, Rtype};

    /// Both daemons ask this one function what a request's OPT says, so it owes
    /// both of them the same four answers.
    #[test]
    fn the_edns_decision_is_one_function() {
        assert_eq!(
            client_edns(&request("example.com.", false)),
            Ok(ClientEdns::Absent)
        );
        assert!(
            ClientEdns::Absent.mirror(ServerOpt::sized(4096)).is_none(),
            "no OPT asked for, no OPT sent (RFC 6891 §6.1.1)"
        );

        assert_eq!(
            client_edns(&request("example.com.", true)),
            Ok(ClientEdns::Present {
                do_bit: false,
                padding: false,
                nsid: false
            })
        );

        let mut dnssec = request("example.com.", false);
        let mut opt = Edns::with_payload_size(4096);
        opt.do_bit = true;
        dnssec.set_edns(opt);
        let asked = client_edns(&dnssec).expect("a version we implement");
        assert_eq!(
            asked,
            ClientEdns::Present {
                do_bit: true,
                padding: false,
                nsid: false
            }
        );
        let mirrored = asked
            .mirror(ServerOpt::sized(1232))
            .expect("an OPT to mirror");
        assert!(mirrored.do_bit, "DO is echoed (RFC 3225 §3)");
        assert_eq!(
            mirrored.udp_payload_size, 1232,
            "at the size we advertise, not the client's"
        );

        // A version past ours is BADVERS, and never a lookup (RFC 6891 §6.1.3).
        let mut future = request("example.com.", false);
        future.set_edns(
            Edns::with_options(4096, crate::EDNS_VERSION + 1, false, &[]).expect("encodes"),
        );
        assert_eq!(client_edns(&future), Err(ResponseCode::BadOptVersion));

        // An option claiming eight bytes of data and supplying two is FORMERR.
        let mut malformed = request("example.com.", false);
        // Through the wire-side constructor, because `Edns::rdata` is private
        // to its module: flags 0 is version 0 with DO clear.
        malformed.set_edns(Edns::from_opt(
            1232,
            0,
            &[0x00, 0x0a, 0x00, 0x08, 0xde, 0xad],
        ));
        assert_eq!(client_edns(&malformed), Err(ResponseCode::FormatError));
    }

    /// An EDE reaches the wire only in an OPT, and an OPT only when the client
    /// sent one (RFC 8914 §2). The writer holds the two apart until `finish`
    /// precisely so the second half cannot be forgotten at a call site that is
    /// choosing an RCODE.
    #[test]
    fn an_extended_error_rides_in_the_opt_or_not_at_all() {
        for (client_used_edns, expected) in
            [(true, Some(InfoCode::NOT_AUTHORITATIVE)), (false, None)]
        {
            let request = request("example.com.", client_used_edns);
            let mut out = Vec::new();
            let mut compressor = NameCompressor::new();
            let mut w =
                ResponseWriter::start(&mut out, &mut compressor, 4096, &request).expect("a start");
            w.set_rcode(ResponseCode::Refused);
            w.set_extended_error(ExtendedError::new(
                InfoCode::NOT_AUTHORITATIVE,
                "no zone here",
            ));
            if let Some(edns) = ClientEdns::of(&request).mirror(ServerOpt::sized(1232)) {
                w.set_edns(edns);
            }
            w.finish().expect("a reply");

            let reply = DnsMessage::try_from_bytes(&out).expect("a message");
            assert_eq!(reply.rcode, ResponseCode::Refused);
            let errors = reply
                .edns
                .as_ref()
                .map(|e| ExtendedError::all_in(e).expect("a well-formed option list"))
                .unwrap_or_default();
            assert_eq!(
                errors.first().map(|(code, _)| *code),
                expected,
                "client used EDNS: {client_used_edns}"
            );
            if let Some((_, text)) = errors.first() {
                assert_eq!(text, "no zone here");
            }
        }
    }

    fn request(qname: &str, edns: bool) -> DnsMessage {
        let mut builder = DnsMessageBuilder::new()
            .with_id(0x1234)
            .with_query(nm(qname), Qtype::of(record_types::A));
        if edns {
            builder = builder.with_edns(4096, false);
        }
        builder.build()
    }

    fn a_record(address: [u8; 4]) -> RecordData {
        RecordData::from_parsed(&ParsedRecord::A(address.into())).expect("an A record")
    }

    /// The writer's bytes are the bytes the build-then-serialize path produced:
    /// same header, same question, same compressed owner names.
    #[test]
    fn a_written_response_is_the_message_it_describes() {
        let request = request("www.example.com.", true);
        let records = [
            ResourceRecord {
                name: nm("www.example.com."),
                class: Class::IN,
                ttl: Ttl::from_secs(300),
                rdata: a_record([192, 0, 2, 1]),
            },
            ResourceRecord {
                name: nm("www.example.com."),
                class: Class::IN,
                ttl: Ttl::from_secs(300),
                rdata: a_record([192, 0, 2, 2]),
            },
        ];
        let ns = ResourceRecord {
            name: nm("example.com."),
            class: Class::IN,
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NS(nm("ns1.example.com.")))
                .expect("an NS record"),
        };

        let mut built = request.clone();
        built.response = true;
        built.authoritive = true;
        built.answers = records.to_vec();
        built.authorities = vec![ns.clone()];
        built.set_edns(Edns::with_payload_size(1232));
        let expected = built.to_bytes_within(4096).expect("serialize");

        let mut out = Vec::new();
        let mut compressor = NameCompressor::new();
        let mut w = ResponseWriter::start(&mut out, &mut compressor, 4096, &request).unwrap();
        w.set_authoritative(true);
        for rr in &records {
            w.push(
                Section::Answer,
                rr.name.as_ref(),
                rr.class,
                rr.ttl,
                rr.rdata.as_ref(),
            )
            .unwrap();
        }
        w.push(
            Section::Authority,
            ns.name.as_ref(),
            ns.class,
            ns.ttl,
            ns.rdata.as_ref(),
        )
        .unwrap();
        w.set_edns(Edns::with_payload_size(1232));
        w.finish().unwrap();

        assert_eq!(out, expected);
    }

    /// An EDE set on a reply with no OPT reaches no wire.
    ///
    /// The type allows it: `set_edns` is `pub`, so `mirror` is not the only way
    /// to an OPT. What holds is `finish`'s guard: the EDE is folded in under
    /// `if let Some(mut edns) = self.edns.take()`. Fails if the guard is
    /// loosened to synthesize an OPT.
    #[test]
    fn an_extended_error_with_no_opt_reaches_no_wire() {
        let request = request("www.example.com.", false);
        let mut out = Vec::new();
        let mut compressor = NameCompressor::new();
        let mut w = ResponseWriter::start(&mut out, &mut compressor, 512, &request).unwrap();
        w.set_rcode(ResponseCode::ServerFailure);
        w.set_extended_error(ExtendedError::new(
            crate::ede::InfoCode::SIGNATURE_EXPIRED,
            "the zone's signatures have expired",
        ));
        w.finish().unwrap();

        let parsed = DnsMessage::try_from_bytes(&out).expect("the reply parses");
        assert!(!parsed.has_edns(), "no OPT was asked for, so none goes out");
        assert_eq!(
            parsed.rcode,
            ResponseCode::ServerFailure,
            "the RCODE stands"
        );
        assert!(
            !out.windows(2).any(|pair| pair == 15u16.to_be_bytes()),
            "and the EDE option code is nowhere in the bytes"
        );
    }

    /// Past the limit the reply is the question, TC=1 and the OPT record — the
    /// shape `to_bytes_within_buf` produces by rebuilding the message with its
    /// sections cleared (RFC 1035 §4.2.1; RFC 6891 §6.2.4 on keeping the OPT).
    #[test]
    fn a_response_over_the_limit_becomes_an_empty_tc_answer() {
        let request = request("www.example.com.", true);
        let mut out = Vec::new();
        let mut compressor = NameCompressor::new();
        let mut w = ResponseWriter::start(&mut out, &mut compressor, 512, &request).unwrap();
        w.set_authoritative(true);
        for i in 0..64u8 {
            let name = nm(&format!("h{i}.www.example.com."));
            w.push(
                Section::Answer,
                name.as_ref(),
                Class::IN,
                Ttl::from_secs(300),
                a_record([192, 0, 2, i]).as_ref(),
            )
            .unwrap();
        }
        w.set_edns(Edns::with_payload_size(1232));
        w.finish().unwrap();

        assert!(out.len() <= 512, "{} octets", out.len());
        let parsed = DnsMessage::try_from_bytes(&out).expect("a truncated reply still parses");
        assert!(parsed.truncation, "TC is what makes the client retry");
        assert!(parsed.answers.is_empty(), "and no partial RRset goes out");
        assert!(parsed.authorities.is_empty());
        assert_eq!(parsed.queries[0].qname, nm("www.example.com."));
        assert!(parsed.has_edns(), "the OPT survives truncation");
    }

    /// A carried compressor is cleared per message, so a response is the bytes
    /// it would have been on its own — including after one that truncated, which
    /// is the case that leaves entries past the rewind point.
    #[test]
    fn a_carried_compressor_does_not_leak_offsets_between_responses() {
        let big = request("many.example.com.", true);
        let small = request("one.example.org.", true);

        let one_small = |out: &mut Vec<u8>, compressor: &mut NameCompressor| {
            let mut w = ResponseWriter::start(out, compressor, 512, &small).unwrap();
            w.set_authoritative(true);
            w.push(
                Section::Answer,
                nm("one.example.org.").as_ref(),
                Class::IN,
                Ttl::from_secs(300),
                a_record([192, 0, 2, 9]).as_ref(),
            )
            .unwrap();
            w.set_edns(Edns::with_payload_size(1232));
            w.finish().unwrap();
        };

        let mut carried = Vec::new();
        let mut compressor = NameCompressor::new();
        for _ in 0..2 {
            let mut w = ResponseWriter::start(&mut carried, &mut compressor, 512, &big).unwrap();
            for i in 0..64u8 {
                let name = nm(&format!("h{i}.many.example.com."));
                w.push(
                    Section::Answer,
                    name.as_ref(),
                    Class::IN,
                    Ttl::from_secs(300),
                    a_record([192, 0, 2, i]).as_ref(),
                )
                .unwrap();
            }
            w.set_edns(Edns::with_payload_size(1232));
            w.finish().unwrap();
            one_small(&mut carried, &mut compressor);
        }

        let mut fresh = Vec::new();
        let mut once = NameCompressor::new();
        one_small(&mut fresh, &mut once);

        assert_eq!(carried, fresh);
    }

    /// RDLENGTH is what was written, not what was stored: the two differ for the
    /// types whose embedded names compress.
    #[test]
    fn rdlength_counts_the_compressed_rdata() {
        let request = request("example.com.", false);
        let mut out = Vec::new();
        let mut compressor = NameCompressor::new();
        let mut w = ResponseWriter::start(&mut out, &mut compressor, 4096, &request).unwrap();
        w.set_authoritative(true);
        let mx = RecordData::from_parsed(&ParsedRecord::MX {
            preference: 10,
            exchange: nm("mail.example.com."),
        })
        .expect("an MX record");
        w.push(
            Section::Answer,
            nm("example.com.").as_ref(),
            Class::IN,
            Ttl::from_secs(300),
            mx.as_ref(),
        )
        .unwrap();
        w.finish().unwrap();

        let parsed = DnsMessage::try_from_bytes(&out).expect("parse back");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rdata.rtype(), Rtype::new(15));
        // The stored form is uncompressed again on the way back in, so this is
        // the round trip and not merely the same bytes.
        assert_eq!(parsed.answers[0].rdata, mx);
    }

    /// A request for `example.com.` carrying `options`, at payload `size`.
    fn padded_request(size: u16, options: &[crate::edns::EdnsOption]) -> DnsMessage {
        let mut request = request("example.com.", false);
        request.set_edns(Edns::with_options(size, 0, false, options).expect("options"));
        request
    }

    fn padding_option(data: Vec<u8>) -> crate::edns::EdnsOption {
        crate::edns::EdnsOption {
            code: crate::edns::EDNS_OPTION_PADDING,
            data,
        }
    }

    /// A reply to `request` with `answers` A records and the client's OPT
    /// mirrored, as bytes.
    fn reply_bytes(request: &DnsMessage, answers: usize) -> Vec<u8> {
        let mut reply = DnsMessage::reply_to(request);
        reply.answers = (0..answers)
            .map(|i| ResourceRecord {
                name: nm("example.com."),
                class: Class::IN,
                ttl: Ttl::from_secs(60),
                rdata: a_record([192, 0, 2, i as u8]),
            })
            .collect();
        if let Some(edns) = ClientEdns::of(request).mirror(ServerOpt::sized(1232)) {
            reply.set_edns(edns);
        }
        reply.to_bytes_within(u16::MAX as usize).expect("serialize")
    }

    /// The Padding option is read whatever its octets hold: RFC 7830 §3 says
    /// received padding of any value MUST be accepted.
    #[test]
    fn a_padding_option_of_any_content_is_a_request_for_padding() {
        for data in [Vec::new(), vec![0; 8], vec![1, 2, 3]] {
            assert!(ClientEdns::of(&padded_request(1232, &[padding_option(data)])).padding());
        }
        assert!(!ClientEdns::of(&padded_request(1232, &[])).padding());
        assert!(!ClientEdns::of(&request("example.com.", false)).padding());
    }

    /// RFC 8467 §4.1(2)'s block: the whole message to a multiple of 468, one
    /// option of 0x00 octets, and the reply still reads (`TODO.md` #187).
    #[test]
    fn a_reply_is_padded_to_the_next_block() {
        let request = padded_request(4096, &[padding_option(Vec::new())]);
        for answers in [1, 40] {
            let mut bytes = reply_bytes(&request, answers);
            let before = bytes.len();
            assert!(pad_reply(&mut bytes, 4096, u16::MAX as usize));
            assert_eq!(
                bytes.len() % PADDING_BLOCK,
                0,
                "{before} -> {}",
                bytes.len()
            );
            assert!(bytes.len() >= before + 4);

            let parsed = DnsMessage::try_from_bytes(&bytes).expect("still a message");
            assert_eq!(parsed.answers.len(), answers);
            let options = parsed.edns.expect("the OPT").options().expect("options");
            assert_eq!(options.len(), 1);
            assert_eq!(options[0].code, crate::edns::EDNS_OPTION_PADDING);
            assert!(options[0].data.iter().all(|&b| b == 0));
        }
    }

    /// §4: never past the client's payload size. A 512-octet client with a
    /// reply that fits gets at most 512, not 936; one that cannot take even
    /// the option header gets none.
    #[test]
    fn padding_stops_at_the_clients_payload_size() {
        let request = padded_request(512, &[padding_option(Vec::new())]);
        let mut bytes = reply_bytes(&request, 1);
        assert!(pad_reply(&mut bytes, 512, u16::MAX as usize));
        assert!(bytes.len() <= 468, "the first block fits: {}", bytes.len());

        let mut bytes = reply_bytes(&request, 28);
        let before = bytes.len();
        assert!(before > 468 && before + 4 < 512, "{before}");
        assert!(pad_reply(&mut bytes, 512, u16::MAX as usize));
        assert_eq!(bytes.len(), 512);

        let mut full = reply_bytes(&request, 28);
        let before = full.len();
        assert!(!pad_reply(&mut full, before + 3, u16::MAX as usize));
        assert_eq!(full.len(), before, "no room, untouched");
    }

    /// No OPT last, no padding: the option has nowhere to go.
    #[test]
    fn a_reply_without_an_opt_is_left_alone() {
        let mut bytes = reply_bytes(&request("example.com.", false), 1);
        let before = bytes.clone();
        assert!(!pad_reply(&mut bytes, 4096, u16::MAX as usize));
        assert_eq!(bytes, before);
    }
}
