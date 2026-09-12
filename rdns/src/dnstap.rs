//! dnstap: the query *stream*, as distinct from the query log.
//!
//! `TODO.md` #44g. [`crate::logging`] answers "is something wrong" for a human
//! reading a terminal, and deliberately says nothing per packet above DEBUG so
//! that a flood costs no log lines. That decision is why there is no data
//! pipeline, and a pipeline is what analytics, abuse handling and security
//! tooling consume. Two different outputs; this is the second.
//!
//! Two wire formats, neither of them DNS, and both small enough to write out
//! rather than depend on:
//!
//! - **Protocol Buffers**, for the payload. Three wire types are needed —
//!   varint, 32-bit fixed and length-delimited — and the schema is fixed, so
//!   what a code generator would produce is [`Entry::encode`] below. The
//!   alternative is `prost` plus `prost-build` plus a `build.rs` invoking
//!   `protoc`, which is what #14 spent 83 packages on the last time this tree
//!   linked a protobuf stack for something that never ran.
//! - **Frame Streams** (`fstrm`), for the framing. A data frame is a 32-bit
//!   big-endian length and that many octets; a length of zero escapes to a
//!   control frame, which is its own 32-bit length, a 32-bit type, and typed
//!   fields. Five control types and one field type, all of them constants here.
//!
//! The schema is `dnstap.proto`'s, field numbers included, and the content type
//! a reader matches on is `protobuf:dnstap.Dnstap` — golang-dnstap's
//! `FSContentType`, which is what `dnstap -r` and `fstrm_capture` expect.
//!
//! Nothing here does I/O or knows about `tokio`: a frame is octets and the
//! daemon decides where they go. That is what lets the encoder be tested
//! against its own reader without a socket.

use std::net::{IpAddr, SocketAddr};

/// The Frame Streams content type for dnstap, as golang-dnstap's
/// `FSContentType` spells it. A reader that does not see exactly this in the
/// START frame will not decode the stream.
pub const CONTENT_TYPE: &[u8] = b"protobuf:dnstap.Dnstap";

/// `fstrm_control_type`, from `fstrm/control.h`.
const CONTROL_ACCEPT: u32 = 0x01;
const CONTROL_START: u32 = 0x02;
const CONTROL_STOP: u32 = 0x03;
const CONTROL_READY: u32 = 0x04;
const CONTROL_FINISH: u32 = 0x05;

/// `fstrm_control_field`: the only field type there is.
const FIELD_CONTENT_TYPE: u32 = 0x01;

/// `FSTRM_CONTROL_FRAME_LENGTH_MAX`. A reader refuses anything larger, so this
/// bounds what may be written rather than being a buffer size here.
const CONTROL_FRAME_LENGTH_MAX: usize = 512;

/// `Message.Type` in `dnstap.proto`. Only the four an authoritative server
/// produces are named: this tree is not a forwarder or a stub.
///
/// `TOOL_QUERY` and the resolver-side types exist in the schema and are not
/// here, for the reason `crate::ede::InfoCode` names only the codes this tree
/// emits — a constant nothing writes is a thing to keep in step for nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// A query received by an authoritative server.
    AuthQuery = 1,
    /// The answer it sent.
    AuthResponse = 2,
    /// An UPDATE received (RFC 2136).
    UpdateQuery = 13,
    /// The answer to one.
    UpdateResponse = 14,
}

/// `SocketProtocol` in `dnstap.proto`.
///
/// Not [`crate::validation::Transport`], which is the question "what size may
/// this answer be" and has two values. dnstap wants the transport the packet
/// actually arrived on, and DoT, DoH and DoQ are three different answers a
/// reader displays differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProtocol {
    Udp = 1,
    Tcp = 2,
    Dot = 3,
    Doh = 4,
    Doq = 7,
}

/// One dnstap payload: a `Dnstap` wrapping a `Message`.
///
/// Borrowed rather than owned, because the caller already holds the query and
/// the response and this is on the answer path: the only allocation a payload
/// costs is the buffer it is encoded into.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
    /// `Dnstap.identity`, usually the server's hostname. Empty is omitted.
    pub identity: &'a [u8],
    /// `Dnstap.version`, the software name and version.
    pub version: &'a [u8],
    pub message_type: MessageType,
    /// `None` when the transport is known to be encrypted and not which of the
    /// three encrypted transports it was. The field is `optional` in the
    /// schema, and an absent one is a reader showing nothing rather than
    /// showing DoT for a DoH query (`TODO.md` #54).
    pub socket_protocol: Option<SocketProtocol>,
    /// Who asked. `query_address` and `query_port`.
    pub peer: SocketAddr,
    /// Which of our addresses answered, when it is known.
    pub local: Option<SocketAddr>,
    /// `query_time_sec` and `query_time_nsec`: when the request arrived.
    pub query_time: Timestamp,
    /// `response_time_sec` and `response_time_nsec`. `None` for a query-only
    /// entry; the pair is what lets a reader subtract and get the latency.
    pub response_time: Option<Timestamp>,
    /// The query as it arrived, or none for a response-only entry.
    pub query: Option<&'a [u8]>,
    /// The response as it left, or none for a query-only entry.
    pub response: Option<&'a [u8]>,
    /// `Message.query_zone`: the zone the answer came out of, in wire form.
    pub zone: Option<&'a [u8]>,
}

/// A dnstap timestamp: whole seconds and nanoseconds within the second.
///
/// Two fields because the schema has two, and `query_time_nsec` is `fixed32`
/// rather than a varint — a full nanosecond value is four octets either way and
/// the schema chose the one that does not vary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timestamp {
    pub secs: u64,
    pub nanos: u32,
}

impl Timestamp {
    /// The wall clock now. `SystemTime`, because this names an instant for
    /// somebody else to read rather than measuring an interval
    /// (`CLAUDE.md` §6).
    pub fn now() -> Timestamp {
        match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => Timestamp {
                secs: d.as_secs(),
                nanos: d.subsec_nanos(),
            },
            // Before 1970. A zero timestamp is wrong and a panic on the answer
            // path is worse; a reader shows it as the epoch, which is visibly
            // not a real time.
            Err(_) => Timestamp::default(),
        }
    }
}

// Protocol Buffers, the three wire types this schema uses (and no more).

const WIRE_VARINT: u32 = 0;
const WIRE_FIXED32: u32 = 5;
const WIRE_BYTES: u32 = 2;

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn put_tag(out: &mut Vec<u8>, field: u32, wire_type: u32) {
    put_varint(out, u64::from((field << 3) | wire_type));
}

fn put_varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    put_tag(out, field, WIRE_VARINT);
    put_varint(out, value);
}

fn put_fixed32_field(out: &mut Vec<u8>, field: u32, value: u32) {
    put_tag(out, field, WIRE_FIXED32);
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes_field(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    put_tag(out, field, WIRE_BYTES);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

impl Entry<'_> {
    /// The `Dnstap` message, encoded.
    ///
    /// Field numbers are `dnstap.proto`'s and the order is ascending, which
    /// protobuf does not require and every generator does: a reader that
    /// hand-parses rather than using the schema is likelier to work.
    ///
    /// An empty `identity` or `version` is *omitted* rather than encoded as a
    /// zero-length string. The fields are `optional`, and a reader prints an
    /// empty one as an empty identity rather than as none.
    pub fn encode(&self) -> Vec<u8> {
        let message = self.encode_message();
        let mut out = Vec::with_capacity(message.len() + 32);
        if !self.identity.is_empty() {
            put_bytes_field(&mut out, 1, self.identity);
        }
        if !self.version.is_empty() {
            put_bytes_field(&mut out, 2, self.version);
        }
        // `Dnstap.message` is field 14 and `Dnstap.type` is 15, so ascending
        // order puts the payload first. `Type.MESSAGE` is the only value.
        put_bytes_field(&mut out, 14, &message);
        put_varint_field(&mut out, 15, 1);
        out
    }

    fn encode_message(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.query.map_or(0, <[u8]>::len) + self.response.map_or(0, <[u8]>::len) + 64,
        );
        put_varint_field(&mut out, 1, self.message_type as u64);
        put_varint_field(&mut out, 2, socket_family(self.peer.ip()));
        if let Some(protocol) = self.socket_protocol {
            put_varint_field(&mut out, 3, protocol as u64);
        }
        put_bytes_field(&mut out, 4, &address_octets(self.peer.ip()));
        if let Some(local) = self.local {
            put_bytes_field(&mut out, 5, &address_octets(local.ip()));
        }
        put_varint_field(&mut out, 6, u64::from(self.peer.port()));
        if let Some(local) = self.local {
            put_varint_field(&mut out, 7, u64::from(local.port()));
        }
        // 8/9 is always the *query*'s time, even on a response entry, so a
        // reader can subtract 8 from 12 and get the latency. An entry carrying
        // both messages is one frame instead of two, which is why this server
        // emits one per exchange.
        put_varint_field(&mut out, 8, self.query_time.secs);
        put_fixed32_field(&mut out, 9, self.query_time.nanos);
        if let Some(query) = self.query {
            put_bytes_field(&mut out, 10, query);
        }
        if let Some(zone) = self.zone {
            put_bytes_field(&mut out, 11, zone);
        }
        if let Some(response) = self.response {
            let at = self.response_time.unwrap_or(self.query_time);
            put_varint_field(&mut out, 12, at.secs);
            put_fixed32_field(&mut out, 13, at.nanos);
            put_bytes_field(&mut out, 14, response);
        }
        out
    }
}

/// `SocketFamily`: INET is 1 and INET6 is 2.
fn socket_family(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(_) => 1,
        IpAddr::V6(_) => 2,
    }
}

/// The address in network byte order, which is what `bytes query_address` is.
///
/// A v4-mapped v6 peer stays v6 here rather than being unwrapped to its four
/// octets. The family field would then disagree with the length, and a reader
/// that trusts the family gets a truncated address; `security::TransferAcl`
/// makes the same distinction for the same reason.
fn address_octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

// Frame Streams.

/// Append a data frame carrying `payload`.
///
/// A zero-length payload is not written: zero is the escape that introduces a
/// control frame, so an empty data frame is a stream a reader misparses.
pub fn put_data_frame(out: &mut Vec<u8>, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
}

/// One control frame, with its escape and length prefix.
fn control_frame(control_type: u32, content_type: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::with_capacity(CONTROL_FRAME_LENGTH_MAX);
    body.extend_from_slice(&control_type.to_be_bytes());
    if let Some(content_type) = content_type {
        body.extend_from_slice(&FIELD_CONTENT_TYPE.to_be_bytes());
        body.extend_from_slice(&(content_type.len() as u32).to_be_bytes());
        body.extend_from_slice(content_type);
    }
    debug_assert!(body.len() <= CONTROL_FRAME_LENGTH_MAX);

    let mut frame = Vec::with_capacity(body.len() + 8);
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// The START frame that opens a stream, naming [`CONTENT_TYPE`].
pub fn start_frame() -> Vec<u8> {
    control_frame(CONTROL_START, Some(CONTENT_TYPE))
}

/// The STOP frame that closes one. No content type: a reader matches on START's.
pub fn stop_frame() -> Vec<u8> {
    control_frame(CONTROL_STOP, None)
}

/// READY, which opens the *bidirectional* handshake a socket reader expects
/// before START.
///
/// A file or a reader that only reads takes START directly; a `fstrm_capture`
/// listening on a socket answers READY with ACCEPT and expects START after it.
/// Both shapes are here because the writer picks one by where it is pointed.
pub fn ready_frame() -> Vec<u8> {
    control_frame(CONTROL_READY, Some(CONTENT_TYPE))
}

/// FINISH, the bidirectional close that follows STOP.
pub fn finish_frame() -> Vec<u8> {
    control_frame(CONTROL_FINISH, None)
}

/// What a reader sent back, as far as a writer needs to tell the two apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFrame {
    Accept,
    Finish,
    /// A control frame this writer has no use for. Not an error: a reader may
    /// send one and a writer that treated it as a protocol failure would close
    /// a working stream.
    Other(u32),
}

/// Read one control frame from the front of `bytes`, returning it and how many
/// octets it used.
///
/// `None` means "not yet": a short read, not a malformed stream. The caller is
/// reading from a socket and has to be able to ask again.
///
/// `Err` is a stream that cannot be resynchronized — a data frame where a
/// control frame belongs, or a length past the maximum — because the escape is
/// the only framing there is and a writer that guessed past a bad length would
/// be reading payload as lengths.
pub fn read_control_frame(bytes: &[u8]) -> Result<Option<(ControlFrame, usize)>, &'static str> {
    if bytes.len() < 8 {
        return Ok(None);
    }
    let escape = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if escape != 0 {
        return Err("a data frame where a control frame was expected");
    }
    let length = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if !(4..=CONTROL_FRAME_LENGTH_MAX).contains(&length) {
        return Err("a control frame length outside fstrm's bounds");
    }
    if bytes.len() < 8 + length {
        return Ok(None);
    }
    let control_type = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let frame = match control_type {
        CONTROL_ACCEPT => ControlFrame::Accept,
        CONTROL_FINISH => ControlFrame::Finish,
        other => ControlFrame::Other(other),
    };
    Ok(Some((frame, 8 + length)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";

    fn entry() -> Entry<'static> {
        Entry {
            identity: b"ns1.example.com",
            version: b"rdnsd 0.1.0",
            message_type: MessageType::AuthQuery,
            socket_protocol: Some(SocketProtocol::Udp),
            peer: "192.0.2.10:5353".parse().expect("a test address"),
            local: Some("192.0.2.1:53".parse().expect("a test address")),
            query_time: Timestamp {
                secs: 1_700_000_000,
                nanos: 123_456_789,
            },
            response_time: None,
            query: Some(QUERY),
            response: None,
            zone: None,
        }
    }

    /// A minimal protobuf reader, so the encoder is judged by something that
    /// parses rather than by a byte string written beside it (`CLAUDE.md` §1).
    /// Returns (field number, wire type, value) in the order encountered.
    fn fields(mut bytes: &[u8]) -> Vec<(u32, u32, Vec<u8>)> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let (tag, used) = varint(bytes).expect("a tag");
            bytes = &bytes[used..];
            let (field, wire_type) = ((tag >> 3) as u32, (tag & 7) as u32);
            let value = match wire_type {
                WIRE_VARINT => {
                    let (v, used) = varint(bytes).expect("a varint");
                    bytes = &bytes[used..];
                    v.to_be_bytes().to_vec()
                }
                WIRE_FIXED32 => {
                    let v = bytes[..4].to_vec();
                    bytes = &bytes[4..];
                    v
                }
                WIRE_BYTES => {
                    let (len, used) = varint(bytes).expect("a length");
                    bytes = &bytes[used..];
                    let v = bytes[..len as usize].to_vec();
                    bytes = &bytes[len as usize..];
                    v
                }
                other => panic!("wire type {other} is not in this schema"),
            };
            out.push((field, wire_type, value));
        }
        out
    }

    fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
        let mut value = 0u64;
        for (i, byte) in bytes.iter().enumerate().take(10) {
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                return Some((value, i + 1));
            }
        }
        None
    }

    fn field(fields: &[(u32, u32, Vec<u8>)], number: u32) -> Option<&[u8]> {
        fields
            .iter()
            .find(|(f, _, _)| *f == number)
            .map(|(_, _, v)| v.as_slice())
    }

    fn as_u64(bytes: &[u8]) -> u64 {
        u64::from_be_bytes(bytes.try_into().expect("a varint value"))
    }

    /// The field numbers are `dnstap.proto`'s, and a reader that hand-parses
    /// them is the only thing that would notice one being wrong: protobuf has
    /// no names on the wire, so a misnumbered field decodes as a different one
    /// or as an unknown, silently.
    #[test]
    fn an_entry_decodes_as_the_schema_says() {
        let bytes = entry().encode();
        let top = fields(&bytes);

        assert_eq!(field(&top, 1), Some(&b"ns1.example.com"[..]), "identity");
        assert_eq!(field(&top, 2), Some(&b"rdnsd 0.1.0"[..]), "version");
        assert_eq!(as_u64(field(&top, 15).expect("type")), 1, "Type.MESSAGE");

        let message = fields(field(&top, 14).expect("Dnstap.message"));
        assert_eq!(as_u64(field(&message, 1).expect("type")), 1, "AUTH_QUERY");
        assert_eq!(as_u64(field(&message, 2).expect("family")), 1, "INET");
        assert_eq!(as_u64(field(&message, 3).expect("protocol")), 1, "UDP");
        assert_eq!(field(&message, 4), Some(&[192, 0, 2, 10][..]), "the peer");
        assert_eq!(field(&message, 5), Some(&[192, 0, 2, 1][..]), "us");
        assert_eq!(as_u64(field(&message, 6).expect("port")), 5353);
        assert_eq!(as_u64(field(&message, 7).expect("port")), 53);
        assert_eq!(as_u64(field(&message, 8).expect("secs")), 1_700_000_000);
        assert_eq!(
            field(&message, 9).expect("nsec"),
            123_456_789u32.to_le_bytes(),
            "fixed32 is little-endian, unlike everything else in DNS"
        );
        assert_eq!(field(&message, 10), Some(QUERY), "the query, verbatim");
        assert_eq!(field(&message, 14), None, "and no response half");
    }

    /// The response half carries both timestamps, so a reader can subtract them.
    #[test]
    fn a_response_entry_carries_the_response_and_both_times() {
        let response = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00";
        let entry = Entry {
            message_type: MessageType::AuthResponse,
            response: Some(response),
            response_time: Some(Timestamp {
                secs: 1_700_000_001,
                nanos: 5,
            }),
            zone: Some(b"\x07example\x03com\x00"),
            ..entry()
        };
        let top = fields(&entry.encode());
        let message = fields(field(&top, 14).expect("Dnstap.message"));

        assert_eq!(
            as_u64(field(&message, 1).expect("type")),
            2,
            "AUTH_RESPONSE"
        );
        assert_eq!(field(&message, 10), Some(QUERY), "the query is still here");
        assert_eq!(field(&message, 11), Some(&b"\x07example\x03com\x00"[..]));
        assert_eq!(
            as_u64(field(&message, 8).expect("secs")),
            1_700_000_000,
            "8 is still the query's time, so 12 minus 8 is the latency"
        );
        assert_eq!(as_u64(field(&message, 12).expect("secs")), 1_700_000_001);
        assert_eq!(field(&message, 14), Some(&response[..]));
    }

    /// An IPv6 peer is sixteen octets and family 2. A v4-mapped one stays v6:
    /// four octets under family INET6 is an address a reader truncates.
    #[test]
    fn an_ipv6_peer_keeps_its_family_and_its_sixteen_octets() {
        for (peer, family, len) in [
            ("[2001:db8::10]:5353", 2u64, 16usize),
            ("[::ffff:192.0.2.10]:5353", 2, 16),
            ("192.0.2.10:5353", 1, 4),
        ] {
            let entry = Entry {
                peer: peer.parse().expect("a test address"),
                local: None,
                ..entry()
            };
            let top = fields(&entry.encode());
            let message = fields(field(&top, 14).expect("Dnstap.message"));
            assert_eq!(
                as_u64(field(&message, 2).expect("family")),
                family,
                "{peer}"
            );
            assert_eq!(field(&message, 4).expect("address").len(), len, "{peer}");
            assert_eq!(field(&message, 5), None, "no local address, so no field 5");
            assert_eq!(field(&message, 7), None, "and no local port either");
        }
    }

    /// An empty identity is omitted, not written as a zero-length string: the
    /// field is `optional`, and a reader shows an empty one as an identity that
    /// is empty rather than as none.
    #[test]
    fn an_unset_identity_is_absent_rather_than_empty() {
        let entry = Entry {
            identity: b"",
            version: b"",
            ..entry()
        };
        let top = fields(&entry.encode());
        assert_eq!(field(&top, 1), None);
        assert_eq!(field(&top, 2), None);
    }

    /// A varint is seven bits a byte, little-endian, with the high bit as the
    /// continuation flag — the one piece of protobuf that is easy to get subtly
    /// wrong and impossible to see afterwards.
    #[test]
    fn varints_round_trip_at_the_boundaries() {
        for value in [
            0u64,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            assert_eq!(varint(&out), Some((value, out.len())), "{value}");
        }
        // The shape a reader depends on.
        let mut out = Vec::new();
        put_varint(&mut out, 300);
        assert_eq!(out, vec![0xac, 0x02]);
    }

    /// A data frame is a 32-bit big-endian length and that many octets, and a
    /// length of zero is the escape that introduces a control frame — so an
    /// empty payload must not be framed at all.
    #[test]
    fn data_frames_are_length_prefixed_and_never_empty() {
        let mut out = Vec::new();
        put_data_frame(&mut out, b"hello");
        assert_eq!(out, b"\x00\x00\x00\x05hello");

        let before = out.len();
        put_data_frame(&mut out, b"");
        assert_eq!(out.len(), before, "an empty frame would read as an escape");
    }

    /// START names the content type; STOP does not. A reader matches on the
    /// first and would reject a stream whose START said anything else.
    #[test]
    fn the_start_frame_names_the_content_type_golang_dnstap_expects() {
        let start = start_frame();
        assert_eq!(&start[..4], b"\x00\x00\x00\x00", "the escape");
        let length = u32::from_be_bytes(start[4..8].try_into().unwrap()) as usize;
        assert_eq!(
            start.len(),
            8 + length,
            "the length covers the body exactly"
        );
        assert_eq!(&start[8..12], &CONTROL_START.to_be_bytes(), "START");
        assert_eq!(&start[12..16], &FIELD_CONTENT_TYPE.to_be_bytes());
        assert_eq!(
            u32::from_be_bytes(start[16..20].try_into().unwrap()) as usize,
            CONTENT_TYPE.len()
        );
        assert_eq!(&start[20..], CONTENT_TYPE);
        assert_eq!(CONTENT_TYPE, b"protobuf:dnstap.Dnstap");

        let stop = stop_frame();
        assert_eq!(stop.len(), 12, "escape, length, type, and nothing else");
        assert_eq!(&stop[8..12], &CONTROL_STOP.to_be_bytes());
    }

    /// The bidirectional handshake, which is what a socket reader speaks: we
    /// send READY, it answers ACCEPT, we send START. Reading its answer has to
    /// cope with the reply arriving in pieces.
    #[test]
    fn a_readers_accept_is_read_back_and_a_short_read_is_not_an_error() {
        let accept = control_frame(CONTROL_ACCEPT, Some(CONTENT_TYPE));
        assert_eq!(
            read_control_frame(&accept),
            Ok(Some((ControlFrame::Accept, accept.len())))
        );
        for cut in 0..accept.len() {
            assert_eq!(
                read_control_frame(&accept[..cut]),
                Ok(None),
                "{cut} octets in is not yet a frame"
            );
        }
        // Trailing octets belong to whatever comes next, and the count says so.
        let mut stream = accept.clone();
        stream.extend_from_slice(&finish_frame());
        let (frame, used) = read_control_frame(&stream).expect("valid").expect("whole");
        assert_eq!(frame, ControlFrame::Accept);
        assert_eq!(
            read_control_frame(&stream[used..]),
            Ok(Some((ControlFrame::Finish, 12)))
        );
    }

    /// A reader that is not speaking Frame Streams, and one that claims a frame
    /// longer than fstrm allows. Neither can be resynchronized, because the
    /// escape is the only framing there is.
    #[test]
    fn a_stream_that_is_not_frame_streams_is_an_error_rather_than_a_short_read() {
        assert!(read_control_frame(b"\x00\x00\x00\x05hello...").is_err());
        let mut oversized = 0u32.to_be_bytes().to_vec();
        oversized.extend_from_slice(&((CONTROL_FRAME_LENGTH_MAX as u32) + 1).to_be_bytes());
        oversized.extend_from_slice(&[0u8; 600]);
        assert!(read_control_frame(&oversized).is_err());
        // And a length too short to hold even the control type.
        let mut stunted = 0u32.to_be_bytes().to_vec();
        stunted.extend_from_slice(&3u32.to_be_bytes());
        stunted.extend_from_slice(&[0u8; 3]);
        assert!(read_control_frame(&stunted).is_err());
    }

    /// An unknown control type is not a failure. A reader may send one, and
    /// closing a working stream over it would be the wrong answer.
    #[test]
    fn an_unknown_control_type_is_carried_rather_than_refused() {
        let odd = control_frame(0x42, None);
        assert_eq!(
            read_control_frame(&odd),
            Ok(Some((ControlFrame::Other(0x42), odd.len())))
        );
    }
}
