//! Writing a reply straight into the send buffer.
//!
//! An answer used to be a [`DnsMessage`] of owned `String`s and cloned RDATA
//! that was then serialized. [`ResponseWriter`] appends each record to the wire
//! as it is found instead: [`RecordData`] already holds uncompressed wire-format
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
use crate::error::WireError;
use crate::{
    Class, DnsMessage, Edns, OpCode, QuerySection, RecordData, ResourceRecord, ResponseCode, Ttl,
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

    /// Append one record. Past the size limit the reply becomes an empty TC=1
    /// one and every later push is dropped, so a caller need not check.
    pub fn push(
        &mut self,
        section: Section,
        name: &str,
        class: Class,
        ttl: Ttl,
        rdata: &RecordData,
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

    /// [`ResponseWriter::push`] for records something else already built — the
    /// DNSSEC proofs, which are synthesized rather than read out of a zone.
    pub fn push_all(
        &mut self,
        section: Section,
        records: &[ResourceRecord],
    ) -> Result<(), WireError> {
        for rr in records {
            self.push(section, &rr.name, rr.class, rr.ttl, &rr.rdata)?;
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
        if let Some(edns) = self.edns.take() {
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
                    // are under 300 octets, so the 512-octet floor `start` sized
                    // the buffer to leaves room for this one.
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
    let pos = compressor.write_name(q.qname.as_str(), buf, pos)?;
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
    name: &str,
    class: Class,
    ttl: Ttl,
    rdata: &RecordData,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::record_types;
    use crate::{ParsedRecord, Qtype, QueryClass, Rtype};

    fn request(qname: &str, edns: bool) -> DnsMessage {
        let mut msg = DnsMessage {
            id: 0x1234,
            response: false,
            opcode: OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: true,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: qname.to_string(),
                qtype: Qtype::of(record_types::A),
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        };
        if edns {
            msg.set_edns(Edns::with_payload_size(4096));
        }
        msg
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
                name: "www.example.com.".to_string(),
                class: Class::IN,
                ttl: Ttl::from_secs(300),
                rdata: a_record([192, 0, 2, 1]),
            },
            ResourceRecord {
                name: "www.example.com.".to_string(),
                class: Class::IN,
                ttl: Ttl::from_secs(300),
                rdata: a_record([192, 0, 2, 2]),
            },
        ];
        let ns = ResourceRecord {
            name: "example.com.".to_string(),
            class: Class::IN,
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NS("ns1.example.com.".to_string()))
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
        w.push_all(Section::Answer, &records).unwrap();
        w.push_all(Section::Authority, std::slice::from_ref(&ns))
            .unwrap();
        w.set_edns(Edns::with_payload_size(1232));
        w.finish().unwrap();

        assert_eq!(out, expected);
    }

    /// Past the limit the reply is the question, TC=1 and the OPT record — the
    /// shape `to_bytes_within_buf` produced by rebuilding the message with its
    /// sections cleared (RFC 1035 §4.2.1; RFC 6891 §6.2.4 on keeping the OPT).
    #[test]
    fn a_response_over_the_limit_becomes_an_empty_tc_answer() {
        let request = request("www.example.com.", true);
        let mut out = Vec::new();
        let mut compressor = NameCompressor::new();
        let mut w = ResponseWriter::start(&mut out, &mut compressor, 512, &request).unwrap();
        w.set_authoritative(true);
        for i in 0..64u8 {
            let name = format!("h{i}.www.example.com.");
            w.push(
                Section::Answer,
                &name,
                Class::IN,
                Ttl::from_secs(300),
                &a_record([192, 0, 2, i]),
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
        assert_eq!(parsed.queries[0].qname, "www.example.com.");
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
                "one.example.org.",
                Class::IN,
                Ttl::from_secs(300),
                &a_record([192, 0, 2, 9]),
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
                let name = format!("h{i}.many.example.com.");
                w.push(
                    Section::Answer,
                    &name,
                    Class::IN,
                    Ttl::from_secs(300),
                    &a_record([192, 0, 2, i]),
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
            exchange: "mail.example.com.".to_string(),
        })
        .expect("an MX record");
        w.push(
            Section::Answer,
            "example.com.",
            Class::IN,
            Ttl::from_secs(300),
            &mx,
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
}
