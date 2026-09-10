//! The message: its header, its question section, serialization with name
//! compression, and the builder that asks a question.

use crate::codes::{OpCode, Qtype, QueryClass, ResponseCode};
use crate::compression::NameCompressor;
use crate::dname::{DNameUnpacker, TryUnpackFromBytes};
use crate::edns::{Edns, EdnsHeader, CLASSIC_UDP_SIZE};
use crate::error::WireError;
use crate::name::{Name, NameRef};
use crate::record::{Additional, ResourceRecord};
use crate::response;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct QuerySection {
    pub qname: Name,
    /// The type asked for. See [`Qtype`] — a QTYPE is not a TYPE.
    pub qtype: Qtype,
    pub qclass: QueryClass,
}

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,      // is the message response or query, QR
    pub opcode: OpCode,      // type of query, copied over to the response
    pub authoritive: bool,   // response: whether or not responding nameserver is the zone owner
    pub truncation: bool, // whether or not the message had to be truncated due to transmission channel
    pub recursion: bool,  // query: whether or not client wants server to do recursion
    pub recursion_ok: bool, // response: whether or not server support is available
    pub ad: bool,         // Authenticated Data bit (RFC 4035)
    pub cd: bool,         // Checking Disabled bit (RFC 4035)
    pub rcode: ResponseCode, // response status: whether or not response was succesful

    pub queries: Vec<QuerySection>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    /// The additional section without its OPT record — see [`DnsMessage::edns`].
    pub additionals: Vec<ResourceRecord>,
    /// The EDNS0 OPT pseudo-record, if the message carries one (RFC 6891).
    ///
    /// A field rather than a record in [`DnsMessage::additionals`], because OPT
    /// is not a resource record: its CLASS is a payload size and its TTL a flags
    /// word. `Option` also makes the two-OPT message RFC 6891 §6.1.1 forbids
    /// unspellable.
    pub edns: Option<Edns>,
}

/// A section's record count as the header's `u16`.
///
/// Checked, not cast: `as` would wrap a section past 65,535 records to a count
/// the reader then trusts, and every count here is derived from a `Vec` a caller
/// filled.
fn section_count(len: usize, what: &'static str) -> Result<u16, WireError> {
    len.try_into().map_err(|_| WireError::TooLong {
        what,
        limit: u16::MAX as usize,
        actual: len,
    })
}

/// A message with its RFC 1035 §4.2.2 two-octet length prefix, in one buffer so
/// a writer emits both in a single call.
///
/// The length is checked rather than cast: a wrapped prefix is 0 at exactly
/// 65,536, which every read loop here treats as a broken peer, and above that
/// desynchronises the stream. `rdns::tsig` appends to the *finished* bytes
/// and is the one path that can grow a message past the size it was serialized
/// to.
pub fn framed(bytes: &[u8]) -> Result<Vec<u8>, WireError> {
    let len: u16 = bytes.len().try_into().map_err(|_| WireError::TooLong {
        what: "a TCP message",
        limit: u16::MAX as usize,
        actual: bytes.len(),
    })?;
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

impl<'a> TryUnpackFromBytes<'a> for QuerySection {
    type Output = (QuerySection, &'a [u8]);
    type Error = WireError;
    fn try_from_bytes(
        data: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<
        <QuerySection as TryUnpackFromBytes<'a>>::Output,
        <QuerySection as TryUnpackFromBytes<'a>>::Error,
    > {
        let (qname, rest) = Name::from_wire_in(data, unpacker)?;
        let (qtype, rest) = read_be!(u16, rest);
        let (qclass, rest) = read_be!(u16, rest);
        Ok((
            Self {
                qname,
                // Total: every 16-bit value is a QTYPE, including the ones no
                // record can hold. See [`Qtype`].
                qtype: Qtype::from_u16(qtype),
                // Total, and it has to be: a class we have no name for is
                // echoed back unchanged, not folded onto one we do.
                qclass: QueryClass::from_u16(qclass),
            },
            rest,
        ))
    }
}

impl DnsMessage {
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, WireError> {
        if data.len() < 12 {
            return Err(WireError::Truncated {
                what: "the DNS header",
                need: 12,
                have: data.len(),
            });
        }

        let unpacker = DNameUnpacker::new(data);

        let (id, rest) = read_be!(u16, data);
        let (hi, rest) = read_be!(u8, rest);
        let (lo, rest) = read_be!(u8, rest);
        let (query_len, rest) = read_be!(u16, rest);
        let (answer_len, rest) = read_be!(u16, rest);
        let (auth_len, rest) = read_be!(u16, rest);
        let (add_len, mut rest) = read_be!(u16, rest);

        // The opcode is bits 3..6 of the flags' high byte, so it is shifted
        // down, not masked in place. Total, and it has to be: an opcode we have
        // no name for is echoed back unchanged (RFC 1035 §4.1.1).
        let opcode = OpCode::from_u8(hi >> 3);

        let mut queries: Vec<QuerySection> = Vec::new();
        for _ in 0..query_len {
            let (query, r) = QuerySection::try_from_bytes(rest, &unpacker)?;
            queries.push(query);
            rest = r;
        }

        let mut answers = Vec::new();
        for _ in 0..answer_len {
            let (query, r) = ResourceRecord::try_from_bytes(rest, &unpacker)?;
            answers.push(query);
            rest = r;
        }

        let mut authorities = Vec::new();
        for _ in 0..auth_len {
            let (query, r) = ResourceRecord::try_from_bytes(rest, &unpacker)?;
            authorities.push(query);
            rest = r;
        }

        // The additional section, with the OPT pseudo-record taken out as it is
        // read rather than fished back out of a list of resource records.
        let mut additionals = Vec::new();
        let mut edns: Option<Edns> = None;
        let mut ext_rcode: u16 = 0;
        for _ in 0..add_len {
            let (item, r) = Additional::try_from_bytes(rest, &unpacker)?;
            match item {
                Additional::Record(rr) => additionals.push(rr),
                Additional::Opt(opt, flags) => {
                    // RFC 6891 §6.1.1: more than one OPT RR MUST be FORMERR.
                    if edns.is_some() {
                        return Err(WireError::malformed(
                            "the additional section",
                            "more than one OPT record; RFC 6891 §6.1.1 allows one",
                        ));
                    }
                    ext_rcode = (flags >> 24) as u16;
                    edns = Some(opt);
                }
            }
            rest = r;
        }

        // RCODE is 12 bits (RFC 6891 §6.1.3): the low 4 in the header, the high
        // 8 in the OPT record's flags word. The option list is *not* read here —
        // a malformed one must not fail the parse, or the FORMERR that answers
        // it could not be built (see [`Edns`]).
        let rcode = ResponseCode::from_u16((ext_rcode << 4) | (lo & 0x0f) as u16);

        Ok(Self {
            id,
            response: hi & 0x80 == 0x80,
            opcode,
            authoritive: hi & 0x04 == 0x04,
            truncation: hi & 0x02 == 0x02,
            recursion: hi & 0x01 == 0x01,
            recursion_ok: lo & 0x80 == 0x80,
            ad: lo & 0x20 == 0x20,
            cd: lo & 0x10 == 0x10,
            rcode,
            queries,
            answers,
            authorities,
            additionals,
            edns,
        })
    }

    /// Serialize the message into `output`, with domain-name compression
    /// (RFC 1035 §4.1.4). Returns the number of bytes written; errors if the
    /// message does not fit rather than writing a silently truncated one.
    /// An empty reply to `request`, carrying only what a reply must echo.
    ///
    /// The id, the opcode and RD are the client's and are copied back
    /// (RFC 1035 §4.1.1), and so is the question. CD is copied because
    /// RFC 4035 §3.2.2 says so in one line — "The name server side MUST copy
    /// the setting of the CD bit from a query to the corresponding response".
    ///
    /// AA, RA, AD, the RCODE and the OPT record are *policy*: they are exactly
    /// what five hand-written copies of this skeleton disagreed about
    /// (`TODO.md` #30g), so they are left neutral for the caller to set. This
    /// is deliberately not a finished message; a function that returned one
    /// would fit none of the callers.
    ///
    /// [`response::ResponseWriter::start`] is the same constructor for the path
    /// that writes straight into the send buffer.
    pub fn reply_to(request: &DnsMessage) -> DnsMessage {
        DnsMessage {
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
            queries: request.queries.clone(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        }
    }

    pub fn to_bytes(&self, output: &mut [u8]) -> Result<usize, WireError> {
        self.to_bytes_with(output, &mut NameCompressor::new())
    }

    /// [`DnsMessage::to_bytes`] with a compressor the caller keeps.
    ///
    /// Its two allocations are per-message state, so a send loop answering one
    /// datagram after another paid them per answer. `compressor` is cleared
    /// here, not by the caller: offsets do not survive a message, and this is
    /// the only place that knows a message is starting.
    pub fn to_bytes_with(
        &self,
        output: &mut [u8],
        compressor: &mut NameCompressor,
    ) -> Result<usize, WireError> {
        compressor.clear();

        // RCODE is 12 bits, split across the header (low 4) and the OPT record's
        // TTL (high 8). A value past the ceiling is a caller bug, not something
        // to paper over with a success code.
        let rcode = response::wire_rcode(self.rcode, self.edns.is_some())?;

        // ARCOUNT counts the OPT record, which is a field here rather than a
        // member of `additionals`.
        let arcount = self.additionals.len() + usize::from(self.edns.is_some());
        let counts = [
            section_count(self.queries.len(), "the question section")?,
            section_count(self.answers.len(), "the answer section")?,
            section_count(self.authorities.len(), "the authority section")?,
            section_count(arcount, "the additional section")?,
        ];
        let mut pos = response::write_header(
            output,
            response::Header {
                id: self.id,
                response: self.response,
                opcode: self.opcode,
                authoritive: self.authoritive,
                truncation: self.truncation,
                recursion: self.recursion,
                recursion_ok: self.recursion_ok,
                ad: self.ad,
                cd: self.cd,
                rcode: self.rcode,
            },
            rcode,
            counts,
        )?;

        for q in &self.queries {
            pos = response::write_query(compressor, output, pos, q)?;
        }
        for section in [&self.answers, &self.authorities, &self.additionals] {
            for rr in section {
                pos = response::write_rr(
                    compressor,
                    output,
                    pos,
                    rr.name.as_ref(),
                    rr.class,
                    rr.ttl,
                    &rr.rdata,
                )?;
            }
        }
        if let Some(edns) = &self.edns {
            pos = response::write_opt(output, pos, edns, rcode)?;
        }
        Ok(pos)
    }

    /// The message's EDNS parameters, if it carries an OPT record. Infallible:
    /// "is the option list well formed" is a separate question (see [`Edns`]).
    pub fn edns(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    /// The EDNS parameters a server acts on, with the option list checked but
    /// not built — see [`EdnsHeader`]. `Err` on a malformed option list, which
    /// is the caller's cue to answer FORMERR.
    pub fn edns_header(&self) -> Result<Option<EdnsHeader>, WireError> {
        let Some(edns) = &self.edns else {
            return Ok(None);
        };
        edns.check_options()?;
        Ok(Some(edns.header()))
    }

    /// Whether the message carries an OPT record at all, regardless of whether
    /// its options parse. Use this to decide OPT mirroring (RFC 6891 §6.1.1).
    pub fn has_edns(&self) -> bool {
        self.edns.is_some()
    }

    /// The requestor's advertised UDP payload size: the EDNS value (floored at
    /// the classic 512 per RFC 6891 §6.2.3) if present, else the classic 512.
    ///
    /// Readable even when the option list is malformed: the size lives in the
    /// OPT CLASS field.
    pub fn udp_payload_size(&self) -> u16 {
        self.edns
            .as_ref()
            .map(|e| e.udp_payload_size.max(CLASSIC_UDP_SIZE))
            .unwrap_or(CLASSIC_UDP_SIZE)
    }

    /// Set the message's OPT record, replacing any it already had. Infallible:
    /// encoding the option list is [`Edns::with_options`]' job.
    pub fn set_edns(&mut self, edns: Edns) {
        self.edns = Some(edns);
    }

    /// An upper bound on what [`DnsMessage::to_bytes_with`] writes, for sizing a
    /// scratch buffer.
    ///
    /// Sound in one direction, which is the one that matters: name compression
    /// makes the wire form shorter than this and never longer, RDATA is stored
    /// uncompressed so writing it can only shrink it, and a name's presentation
    /// text is at least its wire length — an escape like `\.` is two characters
    /// for one octet.
    fn wire_size_bound(&self) -> usize {
        // A name's wire form is its text plus a leading length octet and the
        // root label, and shorter than that whenever it is compressed.
        // A name's wire length exactly, now that a name is its wire form —
        // where the text form had to add two for the length octet and the root
        // and explain why that was right.
        let name = |name: NameRef<'_>| name.as_wire().len();
        let mut bound = response::HEADER_LEN;
        for q in &self.queries {
            bound += name(q.qname.as_ref()) + 4;
        }
        for rr in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
        {
            // TYPE, CLASS, TTL and RDLENGTH, then the RDATA.
            bound += name(rr.name.as_ref()) + 10 + rr.rdata.bytes().len();
        }
        if let Some(edns) = &self.edns {
            // The owner is the root, so one octet rather than a name.
            bound += 11 + edns.rdata().len();
        }
        bound
    }

    /// Serialize, truncating to `max_len` bytes (RFC 1035 §4.2.1). If the full
    /// message doesn't fit, the answer/authority records are dropped (the OPT
    /// record and question are kept) and TC=1 is set so the client retries over
    /// TCP. Returns the wire bytes.
    pub fn to_bytes_within(&self, max_len: usize) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        self.to_bytes_within_buf(max_len, &mut out)?;
        Ok(out)
    }

    /// [`Self::to_bytes_within`] into a caller-owned buffer, which is left
    /// holding exactly the wire bytes.
    ///
    /// Lets a hot send path keep one scratch buffer and allocate nothing per
    /// response: `Vec::truncate` does not release capacity, so a buffer sized to
    /// the protocol maximum travels into `send_to` whatever the answer was, and
    /// the allocation escapes into the socket call rather than being optimized
    /// away. The buffer is sized to `max_len` — only the TCP and transfer paths
    /// pass `u16::MAX`; a UDP caller passes its EDNS payload size.
    pub fn to_bytes_within_buf(&self, max_len: usize, out: &mut Vec<u8>) -> Result<(), WireError> {
        self.to_bytes_within_buf_with(max_len, out, &mut NameCompressor::new())
    }

    /// [`DnsMessage::to_bytes_within_buf`] with a compressor the caller keeps
    /// alongside the buffer, so an answer costs the allocator nothing at all.
    ///
    /// Both passes below go through [`DnsMessage::to_bytes_with`], which clears
    /// it: the retry must not see the offsets of the message it is replacing.
    pub fn to_bytes_within_buf_with(
        &self,
        max_len: usize,
        out: &mut Vec<u8>,
        compressor: &mut NameCompressor,
    ) -> Result<(), WireError> {
        // Sized to what this message can need, not to the ceiling: the TCP and
        // transfer paths pass `u16::MAX`, so a 43-byte reply was a 64 KiB
        // allocation and a 64 KiB memset (`TODO.md` #25b).
        let scratch = self.wire_size_bound().min(max_len);
        out.clear();
        out.resize(scratch, 0);
        let mut wrote = self.to_bytes_with(out, compressor);
        // The bound is an upper bound (see it), so this cannot fire — but a
        // wrong bound would truncate a message that fits, silently and only on
        // the shapes nobody tests. Growing to the limit and writing again makes
        // it a hint rather than an invariant (§4).
        if scratch < max_len
            && matches!(
                wrote,
                Err(WireError::Truncated {
                    what: "the output buffer",
                    ..
                })
            )
        {
            debug_assert!(
                false,
                "wire_size_bound said {scratch} and it was not enough"
            );
            out.clear();
            out.resize(max_len, 0);
            wrote = self.to_bytes_with(out, compressor);
        }
        match wrote {
            Ok(n) if n <= max_len => {
                out.truncate(n);
                return Ok(());
            }
            // Fits the buffer but not the limit — only reachable when a caller
            // passes a `max_len` above what it means to send, which none do.
            Ok(_) => {}
            // Sizing the scratch to `max_len` turns "too long" from a comparison
            // into this error, so it is caught rather than propagated; every
            // other `WireError` is a real failure to encode.
            Err(WireError::Truncated {
                what: "the output buffer",
                ..
            }) => {}
            Err(e) => return Err(e),
        }

        let mut truncated = self.clone();
        truncated.truncation = true;
        truncated.answers.clear();
        truncated.authorities.clear();
        // `truncated.edns` is carried over untouched: the size limit is itself
        // signalled via EDNS, so the OPT record must survive truncation.
        truncated.additionals.clear();

        // Floor at the classic 512: a header, a question and an OPT record fit
        // there, so a too-small `max_len` still yields a TC=1 answer to retry on.
        out.clear();
        out.resize(
            truncated
                .wire_size_bound()
                .max(max_len.min(CLASSIC_UDP_SIZE as usize)),
            0,
        );
        let n = truncated.to_bytes_with(out, compressor)?;
        out.truncate(n);
        Ok(())
    }
}

/// The payload size [`DnsMessageBuilder::with_dnssec`] advertises. A signed
/// answer does not fit in the classic 512 bytes; 4096 is what `dig +dnssec`
/// asks with.
const DNSSEC_PAYLOAD_SIZE: u16 = 4096;

/// A query, built field by field.
///
/// The question's type is a [`Qtype`] and not an `Rtype`. It was an `Rtype`, and
/// the presentation-name door resolved through `record_type_name_to_code`, which
/// answers `None` for ANY, AXFR and IXFR because no *record* is one of those
/// types — and the question was then dropped with no `else`, so `rdnsc`, this
/// tree's only query client, could not ask an ANY query at all (`TODO.md` #33b).
/// The name door is [`utils::qtype_name_to_code`](crate::record_types::qtype_name_to_code), which answers `Option` and
/// leaves the reporting to the caller that has a person to report to.
pub struct DnsMessageBuilder {
    id: u16,
    queries: Vec<(Name, Qtype)>,
    recursion: bool,
    /// The OPT record to attach, if any.
    edns: Option<Edns>,
}

impl Default for DnsMessageBuilder {
    /// RD set, because the caller of a query builder is asking a resolver. AXFR
    /// wants it clear (RFC 5936 §4.1.1): [`DnsMessageBuilder::with_recursion`].
    fn default() -> Self {
        DnsMessageBuilder {
            id: 0,
            queries: Vec::new(),
            recursion: true,
            edns: None,
        }
    }
}

impl DnsMessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask `name` for `qtype`.
    /// Takes a [`Name`] rather than text, because presentation text can fail
    /// to be a name — a bad escape, a label over 63 octets — and a builder
    /// method that cannot fail would have to guess at one of those. The caller
    /// parses, and sees the error where the text is.
    pub fn with_query(mut self, name: Name, qtype: Qtype) -> Self {
        self.queries.push((name, qtype));
        self
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    /// Set or clear RD. A transfer asks with it clear (RFC 5936 §4.1.1).
    pub fn with_recursion(mut self, recursion: bool) -> Self {
        self.recursion = recursion;
        self
    }

    /// Attach an EDNS0 OPT record advertising `udp_payload_size`, with DO as
    /// given (RFC 6891 §6.1.2, RFC 4035 §3.2.1).
    pub fn with_edns(mut self, udp_payload_size: u16, do_bit: bool) -> Self {
        let mut edns = Edns::with_payload_size(udp_payload_size);
        edns.do_bit = do_bit;
        self.edns = Some(edns);
        self
    }

    /// Ask for DNSSEC records: an EDNS0 OPT with DO set (RFC 4035 §3.2.1).
    /// Without DO a server must not send RRSIG, NSEC or NSEC3.
    ///
    /// [`DnsMessageBuilder::with_edns`] with the payload size that goes with
    /// asking for signatures — they do not fit in 512 bytes.
    pub fn with_dnssec(self, dnssec: bool) -> Self {
        if dnssec {
            self.with_edns(DNSSEC_PAYLOAD_SIZE, true)
        } else {
            self
        }
    }

    pub fn build(&self) -> DnsMessage {
        let mut id = self.id;
        if id == 0 {
            let mut rng = rand::thread_rng();
            id = rng.gen::<u16>();
        }

        DnsMessage {
            id,
            response: false,
            opcode: OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: self.recursion,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: self
                .queries
                .iter()
                .map(|(name, qtype)| QuerySection {
                    qname: name.clone(),
                    qtype: *qtype,
                    qclass: QueryClass::IN,
                })
                .collect(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: self.edns.clone(),
        }
    }
}
