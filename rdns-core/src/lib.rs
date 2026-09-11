//! The DNS wire format: the codes a message is written in, the records it
//! carries, its EDNS0 OPT pseudo-record, and the message itself.
//!
//! The four modules below are private and re-exported here, so every type keeps
//! the one path it has always had. They are modules rather than one file because
//! a private field in the crate *root* is visible to the whole crate: `Class`,
//! `Rtype`, `Qtype`, `Ttl`, `Serial` and `Edns`'s option list are sealed by
//! sitting in a module small enough to be the boundary (`CLAUDE.md` §17).

/// This build, as `<package version> (<git describe>)`. Stamped by `build.rs`
/// and passed to clap's `version` by every binary, so `--version` names a
/// commit.
pub const VERSION: &str = env!("RDNS_VERSION");

pub mod clock;
pub mod codecs;
pub mod compression;
pub mod control;
pub mod dname;
pub mod error;
pub mod name;
pub mod name_keys;
mod record_data;
pub mod record_types;
pub mod response;
pub mod socket;
pub mod text_names;
pub mod validation;

/// [`RecordData`] lives in its own module so its fields are private to it.
pub use record_data::RecordData;

/// A domain name is the wire's, not presentation text — see [`name`].
pub use name::{Name, NameRef};

mod codes;
mod edns;
mod macros;
mod message;
mod record;

pub use codes::{Class, OpCode, Qtype, QueryClass, ResponseCode, Rtype, Serial, Ttl};
pub use edns::{
    Edns, EdnsHeader, EdnsOption, CLASSIC_UDP_SIZE, EDNS_OPTION_CLIENT_SUBNET, EDNS_OPTION_COOKIE,
    EDNS_OPTION_NSID, EDNS_OPTION_PADDING, EDNS_VERSION, OPT_RECORD_TYPE,
};
pub use message::{framed, rand_id, DnsMessage, DnsMessageBuilder, QuerySection};
pub use record::{ParsedRecord, ResourceRecord};

#[cfg(test)]
mod builder_dnssec_tests {
    use super::*;
    use crate::name::nm;

    /// `--dnssec` has to produce an OPT record with DO set and survive the wire.
    /// Round-tripped rather than inspected, because the flag only matters if a
    /// *server* reads it: `edns_header` is the call `rdnsd` makes to decide
    /// whether to attach signatures.
    #[test]
    fn the_dnssec_flag_sets_do_and_survives_the_wire() {
        let plain = DnsMessageBuilder::new()
            .with_query(nm("example.com"), Qtype::of(record_types::A))
            .build();
        assert!(plain.edns.is_none(), "no OPT unless asked for");

        let asked = DnsMessageBuilder::new()
            .with_query(nm("example.com"), Qtype::of(record_types::A))
            .with_dnssec(true)
            .build();
        let mut buf = vec![0u8; 512];
        let n = asked.to_bytes(&mut buf).expect("serializes");
        let back = DnsMessage::try_from_bytes(&buf[..n]).expect("and reads back");
        let edns = back
            .edns_header()
            .expect("a well-formed OPT")
            .expect("which is there");
        assert!(
            edns.do_bit,
            "DO is what asks for RRSIG/NSEC (RFC 4035 §3.2.1)"
        );
    }

    /// #33b: the builder took an `Rtype`, so ANY, AXFR and IXFR resolved to
    /// `None` through the record-type table and the question was dropped with no
    /// `else` — a message with an empty question section went on the wire, and
    /// `rdnsc` re-derived the failure from `queries.is_empty()`. Round-tripped,
    /// because the QTYPE only matters if it survives serialization.
    #[test]
    fn the_question_only_types_can_be_asked_for() {
        for (name, qtype) in [
            ("ANY", Qtype::ANY),
            ("*", Qtype::ANY),
            ("AXFR", Qtype::AXFR),
            ("IXFR", Qtype::IXFR),
        ] {
            let asked =
                record_types::qtype_name_to_code(name).expect("a name this client can ask for");
            assert_eq!(asked, qtype);

            let request = DnsMessageBuilder::new()
                .with_query(nm("example.com."), asked)
                .build();
            let mut buf = vec![0u8; 512];
            let n = request.to_bytes(&mut buf).expect("serializes");
            let back = DnsMessage::try_from_bytes(&buf[..n]).expect("and reads back");
            let question = back.queries.first().expect("a question, not an empty one");
            assert_eq!(question.qtype, qtype, "{name} survives the wire");
        }
    }

    /// RD is set by default because the caller is usually asking a resolver; a
    /// transfer asks with it clear (RFC 5936 §4.1.1).
    #[test]
    fn recursion_and_edns_are_the_callers_to_choose() {
        let plain = DnsMessageBuilder::new()
            .with_query(nm("example.com."), Qtype::of(record_types::A))
            .build();
        assert!(plain.recursion, "RD by default");

        let transfer = DnsMessageBuilder::new()
            .with_query(nm("example.com."), Qtype::AXFR)
            .with_recursion(false)
            .with_edns(1232, false)
            .build();
        assert!(!transfer.recursion);
        let edns = transfer.edns.as_ref().expect("an OPT record");
        assert_eq!(edns.udp_payload_size, 1232);
        assert!(!edns.do_bit, "EDNS without DO asks for no signatures");
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::dname::DNameUnpacker;
    use crate::error::WireError;
    use crate::name::nm;
    use crate::record_types as rt;
    use std::net::Ipv4Addr;

    /// RFC 1982 §3.2, which is the whole reason [`Serial`] exists.
    #[test]
    fn a_wrapped_serial_is_still_an_increment() {
        let s = Serial::new;
        assert!(s(2).is_newer_than(s(1)));
        assert!(!s(1).is_newer_than(s(2)));
        assert!(!s(5).is_newer_than(s(5)), "the same serial is not newer");
        assert!(
            s(3).is_newer_than(s(u32::MAX - 1)),
            "RFC 1982 §3.2: the forward distance is 4, so this is an increment"
        );
        assert!(!s(u32::MAX - 1).is_newer_than(s(3)));
    }

    /// Half the space apart, RFC 1982 §3.2 leaves the result undefined — neither
    /// is later, which is why [`Serial`] has no `Ord` to invent an answer.
    #[test]
    fn serials_half_the_space_apart_are_neither_newer() {
        let (a, b) = (Serial::new(0), Serial::new(0x8000_0000));
        assert!(!a.is_newer_than(b));
        assert!(!b.is_newer_than(a));
        assert_ne!(a, b, "and they are still different versions");
    }

    /// `Display` forwards the formatter, so width and alignment survive:
    /// `zone_writer` lays an SOA out as `{serial:<12}` and `rdnsctl status` as
    /// `{:>6}`, and `write!(f, "{}", self.0)` would silently ignore both.
    #[test]
    fn a_serial_keeps_the_padding_it_is_formatted_with() {
        assert_eq!(format!("{:<12}|", Serial::new(2026080201)), "2026080201  |");
        assert_eq!(format!("{:>6}|", Serial::new(42)), "    42|");
    }

    /// An SOA read off the wire and written back out is byte-identical,
    /// including a serial past the signed ceiling.
    #[test]
    fn a_serial_round_trips_through_the_wire_form() {
        for value in [0, 1, 2_026_080_201, 0x8000_0000, u32::MAX] {
            let soa = ParsedRecord::SOA {
                mname: nm("ns1.example.com."),
                rname: nm("admin.example.com."),
                serial: Serial::new(value),
                refresh: 3600,
                retry: 1800,
                expire: 604_800,
                minimum: 86_400,
            };
            let encoded = RecordData::from_parsed(&soa).expect("an SOA serializes");
            assert_eq!(
                encoded.bytes()[encoded.bytes().len() - 20..encoded.bytes().len() - 16],
                value.to_be_bytes(),
                "the serial is the four bytes after the two names"
            );
            assert_eq!(encoded.parse().expect("and parses back"), soa);
        }
    }

    /// A record may not declare more RDATA than the message carries — an error,
    /// not a panic on a slice sized by an attacker-chosen `u16`.
    #[test]
    fn rdlength_past_end_of_message_is_an_error() {
        // Header: id, QR=1, qd=0, an=1, ns=0, ar=0.
        let mut packet: Vec<u8> = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        packet.push(0x00); // owner name = root
        packet.extend_from_slice(&1u16.to_be_bytes()); // type A
        packet.extend_from_slice(&1u16.to_be_bytes()); // class IN
        packet.extend_from_slice(&3600u32.to_be_bytes()); // ttl
        packet.extend_from_slice(&0xFFFFu16.to_be_bytes()); // RDLENGTH, with nothing following

        let parsed = DnsMessage::try_from_bytes(&packet);
        assert!(
            parsed.is_err(),
            "a record claiming 65535 bytes of RDATA in a message that carries none \
             must be rejected, not sliced"
        );
    }

    /// The same shape in the additional section, which
    /// `AdmissionCheck::validate_packet` only count-caps — OPT and TSIG
    /// legitimately live there.
    #[test]
    fn rdlength_past_end_in_additional_section_is_an_error() {
        // Header: id, QR=0 opcode=QUERY, qd=0, an=0, ns=0, ar=1.
        let mut packet: Vec<u8> = vec![0x12, 0x34, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 1];
        packet.push(0x00); // OPT owner name is always root
        packet.extend_from_slice(&41u16.to_be_bytes()); // type OPT
        packet.extend_from_slice(&4096u16.to_be_bytes()); // class = UDP payload size
        packet.extend_from_slice(&0u32.to_be_bytes()); // extended rcode and flags
        packet.extend_from_slice(&0xFFFFu16.to_be_bytes()); // RDLENGTH, with nothing following

        let parsed = DnsMessage::try_from_bytes(&packet);
        assert!(
            parsed.is_err(),
            "an OPT record claiming 65535 bytes of options must be rejected, not sliced"
        );
    }

    /// A record whose RDLENGTH exactly consumes the rest of the message is
    /// legal — the boundary where an off-by-one in the check would live.
    #[test]
    fn rdlength_reaching_exactly_the_end_of_the_message_parses() {
        let mut packet: Vec<u8> = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        packet.push(0x00);
        packet.extend_from_slice(&1u16.to_be_bytes()); // type A
        packet.extend_from_slice(&1u16.to_be_bytes()); // class IN
        packet.extend_from_slice(&3600u32.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
        packet.extend_from_slice(&[192, 0, 2, 1]); // ...and exactly 4 bytes of A rdata

        let parsed = DnsMessage::try_from_bytes(&packet)
            .expect("a record whose RDATA ends exactly at the message end is well-formed");
        assert_eq!(parsed.answers.len(), 1);
    }

    #[test]
    fn test_query_parse() {
        let query_header: [u8; 31] = [
            0xf5, 0x6f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        let msg = DnsMessage::try_from_bytes(&query_header).unwrap();
        assert!(msg.recursion);

        let query = &msg.queries[0];
        assert_eq!(query.qname, nm("www.google.fi."));
        assert_eq!(query.qtype, Qtype::of(rt::A));
        assert_eq!(query.qclass, QueryClass::IN);
    }

    #[test]
    fn test_query_builder() {
        let req = DnsMessageBuilder::new()
            .with_id(u16::from_be_bytes([0xf5, 0x6f]))
            .with_query(nm("www.google.fi"), Qtype::of(record_types::A))
            .build();

        let mut buf = [0u8; 512];
        let n = req.to_bytes(&mut buf).expect("to_bytes");

        let expected: [u8; 31] = [
            0xf5, 0x6f, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69, 0x00, 0x00,
            0x01, 0x00, 0x01,
        ];

        assert_eq!(&buf[0..n], &expected);
    }

    /// Every opcode has to survive the wire. A decoder that masks the field in
    /// place instead of shifting it reads every opcode but QUERY wrong, and only
    /// QUERY survives any mask — so a test that uses it alone sees nothing.
    #[test]
    fn test_every_opcode_survives_the_wire() {
        for opcode in [
            OpCode::Query,
            OpCode::IQuery,
            OpCode::Status,
            OpCode::Notify,
            OpCode::Update,
        ] {
            let msg = DnsMessage {
                id: 0x1234,
                response: false,
                opcode,
                authoritive: true,
                truncation: false,
                recursion: false,
                recursion_ok: false,
                ad: false,
                cd: false,
                rcode: ResponseCode::Ok,
                queries: vec![QuerySection {
                    qname: nm("example.com."),
                    qtype: Qtype::of(rt::SOA),
                    qclass: QueryClass::IN,
                }],
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
                edns: None,
            };
            let mut buf = vec![0u8; 512];
            let n = msg.to_bytes(&mut buf).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");
            assert_eq!(
                parsed.opcode, opcode,
                "opcode {opcode:?} did not round-trip"
            );
            // And the flags either side of it are unharmed.
            assert!(parsed.authoritive, "AA survived alongside {opcode:?}");
            assert!(!parsed.response);
        }
    }

    /// An opcode with no name here is echoed unchanged. RFC 1035 §4.1.1 has
    /// OPCODE set by the originator and copied into the response, so a sentinel
    /// that cannot carry the value sends a DSO client (opcode 6, RFC 8490) a
    /// NOTIMP naming a different opcode.
    ///
    /// Written from raw bytes: a test that starts by naming a variant can only
    /// reach the values that have names.
    #[test]
    fn an_opcode_this_library_has_no_name_for_is_echoed_unchanged() {
        for raw in 0u8..16 {
            let mut query = vec![0u8; 12];
            query[0] = 0x12;
            query[1] = 0x34;
            query[2] = (raw & 0x0f) << 3;

            let parsed = DnsMessage::try_from_bytes(&query).expect("a bare header parses");
            let mut buf = vec![0u8; 512];
            parsed.to_bytes(&mut buf).expect("serialize");
            let echoed = (buf[2] >> 3) & 0x0f;

            assert_eq!(
                echoed, raw,
                "opcode {raw} came back as {echoed} (parsed as {:?})",
                parsed.opcode
            );
        }
    }

    /// TXT framing (RFC 1035 §3.3.14): each string is preceded by its length.
    /// Stored as one unframed blob, the first byte of the text is read as a
    /// length and the record arrives short.
    #[test]
    fn test_txt_is_framed_as_character_strings() {
        let one = RecordData::from_parsed(&ParsedRecord::TXT(vec![b"hello".to_vec()])).unwrap();
        assert_eq!(one.bytes(), b"\x05hello");

        let two = RecordData::from_parsed(&ParsedRecord::TXT(vec![
            b"v=spf1".to_vec(),
            b"-all".to_vec(),
        ]))
        .unwrap();
        assert_eq!(two.bytes(), b"\x06v=spf1\x04-all");
    }

    #[test]
    fn test_txt_survives_a_wire_roundtrip() {
        let strings = vec![
            b"first string".to_vec(),
            Vec::new(),
            // Arbitrary octets: a character-string is not text. As a `String`
            // one such record fails to decode and takes the response with it.
            vec![0xff, 0x00, 0x80],
        ];
        let encoded = RecordData::from_parsed(&ParsedRecord::TXT(strings.clone())).unwrap();
        assert_eq!(
            encoded.parse().unwrap(),
            ParsedRecord::TXT(strings),
            "an empty character-string is legal too, and must survive"
        );
    }

    /// A character-string's length is one byte, so 255 is the ceiling; splitting
    /// a longer string in two would change what the record says.
    #[test]
    fn test_txt_string_longer_than_255_is_refused() {
        let err = RecordData::from_parsed(&ParsedRecord::TXT(vec![vec![b'x'; 256]])).unwrap_err();
        assert!(err.to_string().contains("255"), "got: {err}");

        // 255 exactly is fine.
        assert!(RecordData::from_parsed(&ParsedRecord::TXT(vec![vec![b'y'; 255]])).is_ok());
    }

    #[test]
    fn test_txt_with_no_strings_is_refused() {
        let err = RecordData::from_parsed(&ParsedRecord::TXT(Vec::new())).unwrap_err();
        assert!(err.to_string().contains("at least one"), "got: {err}");
    }

    /// A length byte that runs past the end of the RDATA is malformed, and is
    /// refused as the record is read rather than indexed off the end of.
    #[test]
    fn test_txt_with_a_length_past_the_end_is_an_error() {
        let unpacker = crate::dname::DNameUnpacker::new(&[]);
        let err = RecordData::from_wire(rt::TXT, b"\x09short", &unpacker).unwrap_err();
        assert!(err.to_string().contains("character-string"), "got: {err}");
    }

    #[test]
    fn test_response_roundtrip_with_answer() {
        use std::net::Ipv4Addr;

        let answer = ResourceRecord {
            name: nm("www.example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        };
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: true,
            recursion_ok: true,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: nm("www.example.com."),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            }],
            answers: vec![answer],
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        };

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        assert_eq!(
            parsed.answers.len(),
            1,
            "answer record must survive round-trip"
        );
        let a = &parsed.answers[0];
        assert_eq!(a.name, nm("www.example.com."));
        assert_eq!(a.class, Class::new(1));
        assert_eq!(a.ttl, Ttl::from_secs(3600));
        assert_eq!(a.rdata.rtype(), rt::A);
        assert_eq!(a.rdata.bytes(), [192, 0, 2, 1]); // A record: 4 address octets
    }

    /// A response whose records all share the question's owner name should
    /// carry that name once, with 2-byte pointers thereafter.
    #[test]
    fn test_output_compresses_repeated_owner_names() {
        use std::net::Ipv4Addr;

        let answers: Vec<ResourceRecord> = (1..=10)
            .map(|i| ResourceRecord {
                name: nm("www.example.com."),
                class: Class::new(1),
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, i)))
                    .unwrap(),
            })
            .collect();

        let mut msg = query_msg(0x4242);
        msg.response = true;
        msg.queries[0].qname = nm("www.example.com.");
        msg.answers = answers;

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");

        // 12 header + 21 question (17-byte name + type + class) + 10 * (2
        // pointer + 2 type + 2 class + 4 TTL + 2 RDLEN + 4 address) = 193.
        // Without compression each answer would carry the 17-byte name instead
        // of a 2-byte pointer: 33 + 10 * 31 = 343.
        assert_eq!(n, 193);

        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");
        assert_eq!(parsed.answers.len(), 10);
        for (i, a) in parsed.answers.iter().enumerate() {
            assert_eq!(a.name, nm("www.example.com."));
            assert_eq!(a.rdata.bytes(), [192, 0, 2, (i + 1) as u8]);
        }
    }

    /// Names inside NS/CNAME/SOA/MX RDATA are compressed too, and survive the
    /// round-trip — the parser resolves the pointers against the full message.
    #[test]
    fn test_output_compresses_names_inside_rdata() {
        let ns = ResourceRecord {
            name: nm("example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::NS(nm("ns1.example.com."))).unwrap(),
        };
        let mx = ResourceRecord {
            name: nm("example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::MX {
                preference: 10,
                exchange: nm("mail.example.com."),
            })
            .unwrap(),
        };
        let cname = ResourceRecord {
            name: nm("alias.example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::CNAME(nm("www.example.com."))).unwrap(),
        };

        let mut msg = query_msg(0x5150);
        msg.response = true;
        msg.answers = vec![ns.clone(), mx.clone(), cname.clone()];

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        // RDATA is stored uncompressed, so the parsed records must equal the
        // originals byte for byte even though the wire form used pointers.
        assert_eq!(parsed.answers.len(), 3);
        for (got, want) in parsed.answers.iter().zip([&ns, &mx, &cname]) {
            assert_eq!(got.name, want.name);
            assert_eq!(got.ttl, want.ttl);
            assert_eq!(got.rdata, want.rdata);
        }

        // Every one of those names ends in a pointer rather than spelling the
        // zone out again. (Labels are length-prefixed on the wire, so the
        // literal to look for is the label "example", not "example.com".)
        assert_eq!(
            buf[..n].windows(7).filter(|w| *w == b"example").count(),
            1,
            "the zone name should appear exactly once in the message"
        );
    }

    /// RFC 9460 §2.2 lists what makes an SVCB record malformed, and two of the
    /// three are structural: "the end of the RDATA occurs within a SvcParam",
    /// and "SvcParamKeys are not in strictly increasing numeric order" — which,
    /// as the section notes, also rules out duplicates.
    #[test]
    fn svcb_params_must_be_in_strictly_increasing_key_order() {
        // priority 1, target ".", then key 3 (port) and key 1 (alpn).
        let backwards = [
            0x00, 0x01, 0x00, // priority, root target
            0x00, 0x03, 0x00, 0x02, 0x01, 0xbb, // port=443
            0x00, 0x01, 0x00, 0x02, 0x01, b'h', // alpn
        ];
        let err = RecordData::new(record_types::SVCB, &backwards[..])
            .expect_err("out-of-order keys do not make a record");
        assert!(
            err.to_string().contains("increasing"),
            "the error should say which rule: {err}"
        );

        // The same two keys the right way round do read back.
        let forwards = [
            0x00, 0x01, 0x00, //
            0x00, 0x01, 0x00, 0x02, 0x01, b'h', //
            0x00, 0x03, 0x00, 0x02, 0x01, 0xbb,
        ];
        let rdata = RecordData::new(record_types::SVCB, &forwards[..])
            .expect("the right way round is a record");
        let Ok(ParsedRecord::SVCB { params, .. }) = rdata.parse() else {
            panic!("it parses");
        };
        assert_eq!(params.len(), 2);

        // And a value that runs off the end is truncated, not a panic: this is
        // pre-authentication input on both transports (`TODO.md` #12).
        let short = [0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x09, b'h'];
        assert!(RecordData::new(record_types::SVCB, &short[..]).is_err());
    }

    /// The two type codes are one format (RFC 9460 §6), and `rtype` is what
    /// carries which — so a record built as HTTPS comes back as HTTPS.
    #[test]
    fn svcb_and_https_are_one_format_under_two_numbers() {
        for rtype in [record_types::SVCB, record_types::HTTPS] {
            let built = RecordData::from_parsed(&ParsedRecord::SVCB {
                rtype,
                priority: 1,
                target: nm("foo.example.com."),
                params: vec![(3, vec![0x01, 0xbb])],
            })
            .expect("it encodes");
            assert_eq!(built.rtype(), rtype);
            let Ok(ParsedRecord::SVCB {
                rtype: back,
                priority,
                target,
                params,
            }) = built.parse()
            else {
                panic!("it parses")
            };
            assert_eq!(back, rtype, "the rtype survives the round trip");
            assert_eq!(priority, 1);
            assert_eq!(target, nm("foo.example.com."));
            assert_eq!(params, vec![(3, vec![0x01, 0xbb])]);
        }
    }

    /// The encoder sorts, because the wire order carries no information — but a
    /// duplicate key is two values with no rule for choosing, so it is an error
    /// rather than something to quietly drop.
    #[test]
    fn svcb_encoding_sorts_keys_and_refuses_a_duplicate() {
        let sorted = RecordData::from_parsed(&ParsedRecord::SVCB {
            rtype: record_types::SVCB,
            priority: 1,
            target: nm("."),
            params: vec![(3, vec![0x01, 0xbb]), (1, vec![0x01, b'h'])],
        })
        .expect("it encodes");
        // priority, root target, then key 1 before key 3.
        assert_eq!(
            sorted.bytes(),
            [
                0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x02, 0x01, b'h', 0x00, 0x03, 0x00, 0x02, 0x01,
                0xbb
            ]
        );

        let err = RecordData::from_parsed(&ParsedRecord::SVCB {
            rtype: record_types::SVCB,
            priority: 1,
            target: nm("."),
            params: vec![(3, vec![0x00, 0x35]), (3, vec![0x01, 0xbb])],
        })
        .expect_err("two values for one key");
        assert!(err.to_string().contains("twice"), "{err}");
    }

    /// RFC 6672 §2.5: "The DNAME RDATA target name MUST NOT be sent out in
    /// compressed form." The owner name is compressed like any other, which is
    /// why DNAME is not in `write_rdata`'s single-name arm beside NS and CNAME.
    #[test]
    fn a_dname_target_goes_out_uncompressed() {
        let dname = |owner: &str| ResourceRecord {
            name: nm(owner),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::DNAME(nm("to.example.net."))).unwrap(),
        };
        let mut msg = query_msg(0x6672);
        msg.response = true;
        msg.queries[0].qname = nm("a.example.com.");
        msg.answers = vec![dname("example.com."), dname("other.example.com.")];

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");

        // The length-prefixed label, so this counts targets and not substrings
        // of some other name. Twice: the second record pointing at the first
        // would be exactly the compression the section forbids.
        assert_eq!(
            buf[..n].windows(3).filter(|w| *w == b"to").count(),
            2,
            "each DNAME spells its own target out"
        );

        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");
        assert_eq!(parsed.answers.len(), 2);
        for (got, want) in parsed.answers.iter().zip(&msg.answers) {
            assert_eq!(got.name, want.name);
            assert_eq!(got.rdata, want.rdata);
        }
    }

    /// RFC 3597 §4 / RFC 4034: names in types the receiver may not know must
    /// not be compressed. SRV is the canonical example.
    #[test]
    fn test_unknown_and_dnssec_rdata_is_not_compressed() {
        // SRV: priority, weight, port, then a target name we must leave alone.
        let mut srv_rdata = vec![0, 10, 0, 20, 0, 80];
        srv_rdata.extend_from_slice(nm("www.example.com.").as_ref().as_wire());
        let srv = ResourceRecord {
            name: nm("_sip._tcp.example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::new(Rtype::new(33), srv_rdata.clone())
                .expect("SRV has no decoder here, so its bytes are opaque"),
        };

        let mut msg = query_msg(0x1111);
        msg.response = true;
        msg.queries[0].qname = nm("_sip._tcp.example.com.");
        msg.answers = vec![srv];

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");

        // The RDATA appears verbatim, pointers and all.
        assert!(
            buf[..n]
                .windows(srv_rdata.len())
                .any(|w| w == srv_rdata.as_slice()),
            "SRV RDATA must go out byte-for-byte"
        );

        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");
        assert_eq!(parsed.answers[0].rdata.bytes(), srv_rdata.as_slice());
    }

    /// A packet that claims more questions than it carries must be an error,
    /// not a panic: the name parser runs off the end of the buffer otherwise.
    #[test]
    fn test_truncated_message_is_an_error_not_a_panic() {
        // Header says qdcount=2, but only one (short) question follows.
        let packet: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, // id, flags
            0x00, 0x02, // qdcount = 2
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar = 0
            0x03, b'w', b'w', b'w', 0x00, // "www."
            0x00, 0x01, 0x00, 0x01, // qtype, qclass
        ];
        assert!(DnsMessage::try_from_bytes(&packet).is_err());

        // A name whose length byte overruns the buffer.
        let overrun: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, b'a',
        ];
        assert!(DnsMessage::try_from_bytes(&overrun).is_err());

        // A compression pointer cut in half by the end of the buffer.
        let half_pointer: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        ];
        assert!(DnsMessage::try_from_bytes(&half_pointer).is_err());
    }

    /// A compressor carried from one message to the next must produce exactly
    /// what a fresh one produces.
    ///
    /// Compression offsets are positions *in the message being written*, so a
    /// compressor that remembers the last message emits pointers into bytes that
    /// are no longer there — a reply that parses as something else, or does not
    /// parse. Two different messages, alternating, because a leak only shows
    /// when the names differ.
    #[test]
    fn a_carried_compressor_writes_what_a_fresh_one_writes() {
        let messages: Vec<DnsMessage> = ["www.example.com.", "a.very.different.name.test."]
            .iter()
            .map(|name| DnsMessage {
                id: 0x1234,
                response: true,
                opcode: OpCode::Query,
                authoritive: true,
                truncation: false,
                recursion: false,
                recursion_ok: false,
                ad: false,
                cd: false,
                rcode: ResponseCode::Ok,
                queries: vec![QuerySection {
                    qname: nm(name),
                    qtype: Qtype::of(record_types::A),
                    qclass: QueryClass::IN,
                }],
                answers: vec![ResourceRecord {
                    name: nm(name),
                    class: Class::IN,
                    ttl: Ttl::from_secs(60),
                    rdata: RecordData::from_parsed(&ParsedRecord::A(std::net::Ipv4Addr::new(
                        192, 0, 2, 1,
                    )))
                    .expect("encode"),
                }],
                authorities: Vec::new(),
                additionals: Vec::new(),
                edns: None,
            })
            .collect();

        let fresh: Vec<Vec<u8>> = messages
            .iter()
            .map(|m| m.to_bytes_within(512).expect("serialize"))
            .collect();

        let mut carried = compression::NameCompressor::new();
        let mut buf = Vec::new();
        for round in 0..3 {
            for (i, message) in messages.iter().enumerate() {
                message
                    .to_bytes_within_buf_with(512, &mut buf, &mut carried)
                    .expect("serialize");
                assert_eq!(
                    buf, fresh[i],
                    "round {round}, message {i}: a carried compressor changed the bytes"
                );
                // And it still decodes to the same message, which is what a
                // stale pointer would break.
                let back = DnsMessage::try_from_bytes(&buf).expect("re-parse");
                assert_eq!(back.queries[0].qname, message.queries[0].qname);
                assert_eq!(back.answers[0].name, message.answers[0].name);
            }
        }
    }

    /// The truncation retry serializes twice through one call, so it is the path
    /// where a compressor cleared by the *caller* rather than per message would
    /// carry the abandoned attempt's offsets into the reply that goes out.
    #[test]
    fn the_truncated_retry_does_not_inherit_the_abandoned_attempt() {
        let big = DnsMessage {
            id: 0x4321,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: nm("www.example.com."),
                qtype: Qtype::of(record_types::A),
                qclass: QueryClass::IN,
            }],
            answers: (0..40)
                .map(|i| ResourceRecord {
                    name: nm(&format!("host{i}.example.com.")),
                    class: Class::IN,
                    ttl: Ttl::from_secs(60),
                    rdata: RecordData::from_parsed(&ParsedRecord::A(std::net::Ipv4Addr::new(
                        192, 0, 2, i as u8,
                    )))
                    .expect("encode"),
                })
                .collect(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        };

        let fresh = big.to_bytes_within(512).expect("truncate");
        let mut carried = compression::NameCompressor::new();
        let mut buf = Vec::new();
        big.to_bytes_within_buf_with(512, &mut buf, &mut carried)
            .expect("truncate");

        assert_eq!(
            buf, fresh,
            "the retry must not depend on a carried compressor"
        );
        let back = DnsMessage::try_from_bytes(&buf).expect("the truncated reply parses");
        assert!(back.truncation, "TC is set");
        assert!(back.answers.is_empty(), "and it carries no records");
        assert_eq!(back.queries[0].qname, nm("www.example.com."));
    }

    /// Serializing into a buffer that cannot hold the message is an error, not
    /// a silently short write.
    #[test]
    fn test_to_bytes_rejects_undersized_buffer() {
        let mut msg = query_msg(7);
        msg.queries[0].qname = nm("a-rather-long-name.example.com.");

        let mut buf = [0u8; 20];
        assert!(msg.to_bytes(&mut buf).is_err());
    }

    fn query_msg(id: u16) -> DnsMessage {
        DnsMessage {
            id,
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
                qname: nm("example.com."),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        }
    }

    /// An unknown QCLASS is echoed as itself. 254 is RFC 2136's real NONE, not a
    /// free sentinel, and a client matches the echoed question (RFC 5452 §9.1).
    #[test]
    fn an_unknown_qclass_is_echoed_back_as_the_class_that_was_asked() {
        for qclass in [99u16, 2, 0, 253, 256, 0xffff] {
            let mut msg = query_msg(1);
            msg.queries[0].qclass = QueryClass::from_u16(qclass);

            let bytes = msg.to_bytes_within(512).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
            assert_eq!(
                parsed.queries[0].qclass.to_u16(),
                qclass,
                "QCLASS {qclass} came back as {}",
                parsed.queries[0].qclass.to_u16()
            );
        }
    }

    /// And the classes we do name still travel as themselves, so widening the
    /// type did not turn IN into `Other(1)` on the way through.
    #[test]
    fn the_named_qclasses_round_trip_as_themselves() {
        for (class, value) in [
            (QueryClass::IN, 1u16),
            (QueryClass::CH, 3),
            (QueryClass::HS, 4),
            (QueryClass::None, 254),
            (QueryClass::Any, 255),
        ] {
            assert_eq!(class.to_u16(), value);
            assert_eq!(QueryClass::from_u16(value), class);
        }
    }

    /// An rcode with no name here used to serialize as 0. `rdnsr` relays
    /// upstream messages, so an unrecognized *failure* reached the client as a
    /// successful empty answer — the one direction a response code must never
    /// fail in. RFC 6895 §2.3 keeps the space open on purpose; a relay that does
    /// not know a code still has to pass it on.
    #[test]
    fn an_unknown_rcode_is_relayed_rather_than_rewritten_to_noerror() {
        // 12 is unassigned; 4095 is the top of the extended range. Both need an
        // OPT record to carry the high bits (RFC 6891 §6.1.3).
        for value in [12u16, 24, 100, 0xfff] {
            let mut msg = query_msg(1);
            msg.response = true;
            msg.rcode = ResponseCode::from_u16(value);
            msg.set_edns(Edns::with_payload_size(4096));

            let bytes = msg.to_bytes_within(512).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
            assert_eq!(
                parsed.rcode.to_u16(),
                value,
                "rcode {value} came back as {}",
                parsed.rcode.to_u16()
            );
            assert_ne!(parsed.rcode, ResponseCode::Ok);
        }
    }

    /// The low four bits still work without EDNS, which is the case every
    /// non-EDNS client sees.
    #[test]
    fn the_named_rcodes_round_trip_as_themselves() {
        for code in [
            ResponseCode::Ok,
            ResponseCode::FormatError,
            ResponseCode::ServerFailure,
            ResponseCode::NoSuchDomain,
            ResponseCode::NotImplemented,
            ResponseCode::Refused,
        ] {
            let mut msg = query_msg(1);
            msg.response = true;
            msg.rcode = code;
            let bytes = msg.to_bytes_within(512).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
            assert_eq!(parsed.rcode, code);
        }
        assert_eq!(ResponseCode::from_u16(23), ResponseCode::BadCookie);
        assert_eq!(ResponseCode::BadCookie.to_u16(), 23);
    }

    /// An OPT record whose option list is whatever bytes the test wants,
    /// including bytes that are not a valid list.
    ///
    /// `Edns::rdata` is private on purpose — the public constructors encode a
    /// well-formed list — so this goes in the way the wire does, through the
    /// one constructor that takes RDATA it has not encoded. Flags 0 is EDNS
    /// version 0 with DO clear.
    fn edns_with_rdata(rdata: &[u8]) -> Edns {
        Edns::from_opt(1232, 0, rdata)
    }

    /// RFC 6891 §6.1.1: "If a query message with more than one OPT RR is
    /// received, a FORMERR (RCODE=1) MUST be returned."
    ///
    /// Nothing checked this before OPT became a field. The first OPT was
    /// read and every one of them was written back out, so a message with two
    /// went through as if it had one and came back malformed. `Option<Edns>`
    /// makes the state unrepresentable in the struct; this is the other half —
    /// refusing it at the door, since the wire can still carry it.
    #[test]
    fn more_than_one_opt_record_is_formerr() {
        // A bare header claiming two additionals, then two OPT records:
        // root NAME, TYPE 41, CLASS 1232, TTL 0, RDLENGTH 0.
        let opt = [
            0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut two = vec![0x12, 0x34, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0x00, 0x02];
        two.extend_from_slice(&opt);
        two.extend_from_slice(&opt);
        let err = DnsMessage::try_from_bytes(&two).expect_err("two OPT records are FORMERR");
        assert!(
            matches!(
                err,
                WireError::Malformed {
                    what: "the additional section",
                    ..
                }
            ),
            "got {err:?}"
        );

        // And exactly one is still fine, so the check is not simply refusing
        // every OPT record it sees.
        let mut one = vec![0x12, 0x34, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0x00, 0x01];
        one.extend_from_slice(&opt);
        let msg = DnsMessage::try_from_bytes(&one).expect("one OPT record parses");
        assert!(msg.edns().is_some());
        assert!(
            msg.additionals.is_empty(),
            "and it is not left in the section"
        );
    }

    /// ARCOUNT counts the OPT record even though it is no longer in
    /// `additionals` — the arithmetic most likely to break when OPT moved out.
    #[test]
    fn arcount_counts_the_opt_record_that_is_not_in_the_section() {
        let mut msg = query_msg(7);
        msg.additionals.push(ResourceRecord {
            name: nm("ns1.example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1)))
                .expect("encode"),
        });
        msg.set_edns(Edns::with_payload_size(1232));

        let bytes = msg.to_bytes_within(512).expect("serialize");
        assert_eq!(
            u16::from_be_bytes([bytes[10], bytes[11]]),
            2,
            "one real additional plus the OPT record"
        );

        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
        assert_eq!(parsed.additionals.len(), 1, "the A record, and only it");
        assert!(parsed.edns().is_some(), "the OPT record, in its own field");
    }

    /// RFC 2181 §8, at the boundary that now owns it: "implementations should
    /// treat TTL values received with the most significant bit set as if the
    /// entire value received was zero".
    ///
    /// Driven from the wire rather than from `Ttl::from_wire`, because the
    /// claim being tested is that *parsing a record* applies the rule — that is
    /// what lets fourteen call sites stop applying it themselves.
    #[test]
    fn a_ttl_with_the_high_bit_set_parses_as_zero() {
        for raw in [-1i32, i32::MIN, -3600] {
            let mut wire = vec![0x12, 0x34, 0x00, 0x00, 0, 0, 0x00, 0x01, 0, 0, 0, 0];
            wire.push(0x00); // root owner name
            wire.extend_from_slice(&record_types::A.to_u16().to_be_bytes());
            wire.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
            wire.extend_from_slice(&raw.to_be_bytes());
            wire.extend_from_slice(&4u16.to_be_bytes());
            wire.extend_from_slice(&[192, 0, 2, 1]);

            let msg = DnsMessage::try_from_bytes(&wire).expect("parses");
            assert_eq!(
                msg.answers[0].ttl,
                Ttl::ZERO,
                "a wire TTL of {raw} is zero seconds, not {} or a huge unsigned value",
                raw
            );
        }

        // And a TTL without the high bit is untouched.
        let mut wire = vec![0x12, 0x34, 0x00, 0x00, 0, 0, 0x00, 0x01, 0, 0, 0, 0];
        wire.push(0x00);
        wire.extend_from_slice(&record_types::A.to_u16().to_be_bytes());
        wire.extend_from_slice(&1u16.to_be_bytes());
        wire.extend_from_slice(&3600i32.to_be_bytes());
        wire.extend_from_slice(&4u16.to_be_bytes());
        wire.extend_from_slice(&[192, 0, 2, 1]);
        let msg = DnsMessage::try_from_bytes(&wire).expect("parses");
        assert_eq!(msg.answers[0].ttl, Ttl::from_secs(3600));
    }

    #[test]
    fn test_edns_absent_defaults_to_512() {
        let msg = query_msg(1);
        assert!(msg.edns().is_none());
        assert!(!msg.has_edns());
        assert_eq!(msg.udp_payload_size(), 512);
    }

    #[test]
    fn test_edns_set_and_read() {
        let mut msg = query_msg(1);
        let mut edns = Edns::with_payload_size(4096);
        edns.do_bit = true;
        msg.set_edns(edns);

        let got = msg.edns().expect("edns present");
        assert_eq!(got.udp_payload_size, 4096);
        assert!(got.do_bit);
        assert_eq!(got.version, 0);
        assert_eq!(msg.udp_payload_size(), 4096);

        // `set_edns` replaces rather than accumulates. This used to be checked
        // by counting the OPT records in the additional section and asserting
        // there was exactly one. With OPT as an `Option` field a second one is
        // unspellable, which is also what RFC 6891 §6.1.1 says about receiving
        // one.
        msg.set_edns(Edns::with_payload_size(1232));
        assert!(msg.additionals.is_empty(), "OPT is not a resource record");
        assert_eq!(msg.edns().expect("still present").udp_payload_size, 1232);
        assert_eq!(msg.udp_payload_size(), 1232);
    }

    #[test]
    fn test_edns_survives_wire_roundtrip() {
        let mut msg = query_msg(0xABCD);
        let mut edns = Edns::with_payload_size(4096);
        edns.do_bit = true;
        msg.set_edns(edns.clone());

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        let got = parsed.edns().expect("edns survives round-trip");
        assert_eq!(*got, edns);
    }

    #[test]
    fn test_edns_payload_size_floored_at_512() {
        // RFC 6891 §6.2.3: values below 512 are treated as 512.
        let mut msg = query_msg(1);
        msg.set_edns(Edns::with_payload_size(300));
        assert_eq!(msg.udp_payload_size(), 512);
    }

    /// RFC 4034 §3.1 fixes the RRSIG field order, and expiration comes *before*
    /// inception. Decoding them the other way round is invisible to a
    /// round-trip test — both halves agree — so this checks the decode against
    /// bytes laid out by hand, which is the only thing a real signer's output
    /// can be compared to.
    #[test]
    fn test_rrsig_reads_expiration_before_inception() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // type covered = A
        rdata.push(13); // algorithm = ECDSAP256SHA256
        rdata.push(3); // labels
        rdata.extend_from_slice(&3600u32.to_be_bytes()); // original TTL
        rdata.extend_from_slice(&0x5000_0000u32.to_be_bytes()); // expiration
        rdata.extend_from_slice(&0x4000_0000u32.to_be_bytes()); // inception
        rdata.extend_from_slice(&12345u16.to_be_bytes()); // key tag
        rdata.extend_from_slice(nm("example.com.").as_ref().as_wire());
        rdata.extend_from_slice(&[0xAB; 64]); // signature

        let record = RecordData::from_wire(rt::RRSIG, &rdata, &DNameUnpacker::new(&rdata))
            .expect("RRSIG should decode");
        let ParsedRecord::RRSIG {
            expiration,
            inception,
            key_tag,
            signer_name,
            ref signature,
            ..
        } = record.parse().expect("parse")
        else {
            panic!("not an RRSIG");
        };
        assert_eq!(expiration, 0x5000_0000, "the earlier field is expiration");
        assert_eq!(inception, 0x4000_0000, "the later field is inception");
        assert!(inception < expiration, "a signature is valid over a range");
        assert_eq!(key_tag, 12345);
        assert_eq!(signer_name, nm("example.com."));
        assert_eq!(signature.len(), 64);

        // And the encoder puts them back in the same order it found them.
        assert_eq!(record.bytes(), rdata.as_slice());
    }

    #[test]
    fn test_edns_options_survive_wire_roundtrip() {
        let mut msg = query_msg(0x0F0F);
        let edns = Edns::with_options(
            1232,
            EDNS_VERSION,
            false,
            &[
                EdnsOption {
                    code: EDNS_OPTION_COOKIE,
                    data: vec![1, 2, 3, 4, 5, 6, 7, 8],
                },
                // A zero-length option is legal and must not be dropped.
                EdnsOption {
                    code: EDNS_OPTION_NSID,
                    data: Vec::new(),
                },
            ],
        )
        .expect("encode the options");
        msg.set_edns(edns.clone());

        // 2 (code) + 2 (len) + 8 (data), then 2 + 2 + 0.
        assert_eq!(msg.edns().expect("OPT present").rdata().len(), 16);

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");

        let got = parsed.edns().expect("edns present");
        assert_eq!(*got, edns);
        assert_eq!(
            got.option(EDNS_OPTION_COOKIE).unwrap(),
            Some(vec![1u8, 2, 3, 4, 5, 6, 7, 8])
        );
        assert_eq!(got.option(EDNS_OPTION_NSID).unwrap(), Some(Vec::new()));
        assert_eq!(got.option(EDNS_OPTION_PADDING).unwrap(), None);
    }

    /// A malformed option list is an error — but not an error that reaching
    /// the OPT record produces.
    ///
    /// OPT is a field carrying its RDATA unparsed, so "does this message have
    /// EDNS" is infallible and "is its option list well formed" is a separate,
    /// fallible question. The split is what keeps a bad list answerable: if
    /// reading it were part of parsing the message,
    /// `try_from_bytes` would fail, `rdnsd` would return no bytes at all
    /// (`main.rs:1465`), and the FORMERR this deserves could not be built.
    #[test]
    fn test_malformed_edns_options_surface_error() {
        let mut msg = query_msg(1);
        // Option claims 8 bytes of data but supplies 2.
        msg.set_edns(edns_with_rdata(&[0x00, 0x0a, 0x00, 0x08, 0xde, 0xad]));

        let err = msg
            .edns()
            .expect("the OPT record itself is readable")
            .check_options()
            .expect_err("truncated option must be rejected");
        assert_eq!(
            err,
            WireError::Truncated {
                what: "EDNS option data",
                need: 8,
                have: 2,
            },
            "the option declared 8 bytes and supplied 2"
        );
        // The payload size is still readable — it lives in the OPT CLASS field.
        assert_eq!(msg.udp_payload_size(), 1232);
        assert!(msg.has_edns());
    }

    /// `edns_header` sees exactly what `edns` sees, minus the options.
    ///
    /// This is the property the answer path now depends on. Both daemons decide
    /// FORMERR from the cheap one, so if it accepted a list the full parse
    /// rejects — or the reverse — a packet would be answered differently
    /// depending on which of the two a call site happened to use, which is
    /// precisely the drift that comes of writing the walk twice
    /// (`CLAUDE.md` §7). They share it; this holds them to it.
    #[test]
    fn the_edns_header_agrees_with_the_full_parse() {
        // No OPT at all.
        let plain = query_msg(1);
        assert_eq!(plain.edns_header().unwrap(), None);

        // An OPT with options, an OPT without, and a non-zero version — the
        // three shapes the answer path branches on.
        for (payload, version, do_bit, options) in [
            (4096u16, 0u8, true, vec![]),
            (
                1232,
                0,
                false,
                vec![EdnsOption {
                    code: EDNS_OPTION_COOKIE,
                    data: vec![1, 2, 3, 4, 5, 6, 7, 8],
                }],
            ),
            (512, 1, true, vec![]),
        ] {
            let mut msg = query_msg(1);
            msg.set_edns(
                Edns::with_options(payload, version, do_bit, &options).expect("encode the options"),
            );
            // Through the wire, because that is where a request comes from and
            // the version lives in a field `set_edns` writes and the parser
            // re-reads.
            let bytes = msg.to_bytes_within(512).expect("serialize");
            let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");

            let full = parsed.edns().expect("OPT present");
            let header = parsed.edns_header().unwrap().expect("OPT present");
            assert_eq!(header, full.header(), "payload {payload} version {version}");
            assert_eq!(header.do_bit, do_bit);
            assert_eq!(header.version, version);
        }
    }

    /// And a malformed option list is malformed to both of them.
    #[test]
    fn the_edns_header_rejects_what_the_full_parse_rejects() {
        for rdata in [
            // An option header cut short: three bytes where four are needed.
            vec![0x00u8, 0x0a, 0x00],
            // Data shorter than the length field claims.
            vec![0x00, 0x0a, 0x00, 0x08, 0xde, 0xad],
            // A well-formed option followed by a truncated one, which only a
            // walk that gets that far can see.
            vec![0x00, 0x0a, 0x00, 0x01, 0xff, 0x00, 0x03, 0x00, 0x04],
        ] {
            let mut msg = query_msg(1);
            msg.set_edns(edns_with_rdata(&rdata));

            assert_eq!(
                msg.edns_header().unwrap_err(),
                msg.edns().expect("OPT present").options().unwrap_err(),
                "{rdata:02x?}: the same walk, so the same error"
            );
        }
    }

    #[test]
    fn test_extended_rcode_splits_across_header_and_opt() {
        // BADVERS is 16: 0 in the header's low 4 bits, 1 in the OPT TTL's top byte.
        let mut msg = query_msg(0x2222);
        msg.response = true;
        msg.rcode = ResponseCode::BadOptVersion;
        msg.set_edns(Edns::with_payload_size(1232));

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        assert_eq!(buf[3] & 0x0f, 0, "low 4 bits of RCODE 16 are 0");

        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");
        assert_eq!(parsed.rcode, ResponseCode::BadOptVersion);
    }

    #[test]
    fn test_extended_rcode_without_opt_is_an_error() {
        let mut msg = query_msg(1);
        msg.response = true;
        msg.rcode = ResponseCode::BadOptVersion;

        let mut buf = [0u8; 512];
        let err = msg
            .to_bytes(&mut buf)
            .expect_err("extended RCODE needs an OPT record");
        assert!(err.to_string().contains("OPT record"), "got: {err}");
        // The whole message, not a substring of it: this literal carried 22
        // spaces where a `\` continuation belonged, and the assertion above was
        // true throughout. rustfmt does not touch string literals (§12), so a
        // wrapped one has no other check.
        assert!(
            !err.to_string().contains("  "),
            "a wrapped literal leaked its indentation: {err}"
        );
    }

    #[test]
    fn test_basic_rcode_unaffected_by_opt() {
        // A plain 4-bit RCODE must not have its bits disturbed by OPT presence.
        let mut msg = query_msg(1);
        msg.response = true;
        msg.rcode = ResponseCode::NoSuchDomain;
        msg.set_edns(Edns::with_payload_size(4096));

        let mut buf = [0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("to_bytes");
        let parsed = DnsMessage::try_from_bytes(&buf[0..n]).expect("try_from_bytes");
        assert_eq!(parsed.rcode, ResponseCode::NoSuchDomain);
        assert_eq!(parsed.udp_payload_size(), 4096);
    }

    #[test]
    fn test_to_bytes_within_truncates_and_sets_tc() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        // Pack in enough answers to blow past 512 bytes.
        for i in 0..60u8 {
            msg.answers.push(ResourceRecord {
                name: nm(&format!("host{i}.example.com.")),
                class: Class::new(1),
                ttl: Ttl::from_secs(3600),
                rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(10, 0, 0, i)))
                    .unwrap(),
            });
        }
        msg.set_edns(Edns::with_payload_size(4096));

        let bytes = msg.to_bytes_within(512).expect("to_bytes_within");
        assert!(
            bytes.len() <= 512,
            "must fit within 512, got {}",
            bytes.len()
        );

        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse truncated");
        assert!(parsed.truncation, "TC bit must be set on truncation");
        assert!(parsed.answers.is_empty(), "answers dropped on truncation");
        assert!(parsed.has_edns(), "OPT record must survive truncation");
    }

    /// A response used to be built in a zeroed 64 KB scratch that `truncate`
    /// then shrank the *length* of and not the capacity, so the `Vec` handed to
    /// `send_to` and held for the duration of the send was 64 KB whatever the
    /// answer was — a 1000x overshoot at a thousand in flight.
    ///
    /// Asserted on capacity rather than on a timing, deliberately: capacity is
    /// exact and does not care what else is running on the machine
    /// (`CLAUDE.md` §10). Against the old code this reads 65535.
    #[test]
    fn a_small_response_does_not_carry_a_64k_buffer_into_the_send() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        msg.answers.push(ResourceRecord {
            name: nm("example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(1, 2, 3, 4))).unwrap(),
        });

        let bytes = msg.to_bytes_within(4096).expect("to_bytes_within");
        assert!(bytes.len() < 100, "a one-record answer is small");
        assert!(
            bytes.capacity() <= 4096,
            "a UDP response asked to fit in 4096 bytes must not hold {} of \
             capacity — that is the buffer travelling into send_to",
            bytes.capacity()
        );

        // And the TCP path, which passes the protocol ceiling because the length
        // prefix is its only limit. This is what `TODO.md` #25b measured: 65 535
        // bytes allocated and zeroed for the same 60 bytes of answer, because
        // the scratch was sized to the limit rather than to the message.
        let framed = msg.to_bytes_within(u16::MAX as usize).expect("TCP");
        assert_eq!(framed, bytes, "the limit does not change the bytes");
        assert!(
            framed.capacity() < 1024,
            "a TCP response must not hold {} of capacity for {} bytes of answer",
            framed.capacity(),
            framed.len()
        );
    }

    /// The reason [`DnsMessage::to_bytes_within_buf`] exists: a send path that
    /// keeps one buffer allocates nothing per response. Checked by pointer
    /// identity, which is the only way to say "did not reallocate" without
    /// measuring time.
    #[test]
    fn serializing_into_a_reused_buffer_does_not_reallocate() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        msg.answers.push(ResourceRecord {
            name: nm("example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(1, 2, 3, 4))).unwrap(),
        });

        let mut buf = Vec::new();
        msg.to_bytes_within_buf(4096, &mut buf).expect("first");
        let first_len = buf.len();
        let (ptr, cap) = (buf.as_ptr(), buf.capacity());

        for _ in 0..16 {
            msg.to_bytes_within_buf(4096, &mut buf).expect("again");
            assert_eq!(buf.len(), first_len, "same message, same bytes");
        }
        assert_eq!(buf.as_ptr(), ptr, "the buffer moved, so it reallocated");
        assert_eq!(buf.capacity(), cap);
    }

    /// The boundary the new sizing introduces: with the scratch sized to
    /// `max_len`, "the message is too long" arrives as a `WireError` from the
    /// writer rather than as a comparison, so an off-by-one puts a message that
    /// fits exactly onto the truncation path. The RFC 1035 §4.2.1 answer for a
    /// message of exactly `max_len` bytes is to send it, TC clear.
    #[test]
    fn a_response_of_exactly_the_limit_is_sent_whole() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        msg.answers.push(ResourceRecord {
            name: nm("example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(1, 2, 3, 4))).unwrap(),
        });
        let exact = msg.to_bytes_within(4096).expect("measure").len();

        let bytes = msg.to_bytes_within(exact).expect("at the limit");
        assert_eq!(bytes.len(), exact);
        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
        assert!(!parsed.truncation, "it fit, so TC must be clear");
        assert_eq!(parsed.answers.len(), 1);

        // One byte less and it must truncate rather than error.
        let bytes = msg.to_bytes_within(exact - 1).expect("under the limit");
        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
        assert!(parsed.truncation, "TC set when it does not fit");
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn test_to_bytes_within_keeps_full_when_it_fits() {
        use std::net::Ipv4Addr;
        let mut msg = query_msg(1);
        msg.response = true;
        msg.answers.push(ResourceRecord {
            name: nm("example.com."),
            class: Class::new(1),
            ttl: Ttl::from_secs(3600),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(1, 2, 3, 4))).unwrap(),
        });

        let bytes = msg.to_bytes_within(4096).expect("to_bytes_within");
        let parsed = DnsMessage::try_from_bytes(&bytes).expect("parse");
        assert!(!parsed.truncation);
        assert_eq!(parsed.answers.len(), 1);
    }

    #[test]
    fn test_response_parse() {
        let resp: [u8; 295] = [
            0xf5, 0x6f, 0x81, 0x80, 0x00, 0x01, 0x00, 0x07, 0x00, 0x04, 0x00, 0x04, 0x03, 0x77,
            0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69, 0x00, 0x00,
            0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0xc4, 0x74, 0x00,
            0x10, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00, 0xc0, 0x2b, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0xc4, 0x6a, 0x00,
            0x08, 0x03, 0x77, 0x77, 0x77, 0x01, 0x6c, 0xc0, 0x2f, 0xc0, 0x47, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x04, 0xad, 0xc2, 0x20, 0x13, 0xc0, 0x47, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x04, 0xad, 0xc2, 0x20, 0x14, 0xc0,
            0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x04, 0xad, 0xc2, 0x20,
            0x10, 0xc0, 0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x04, 0xad,
            0xc2, 0x20, 0x11, 0xc0, 0x47, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8a, 0x00,
            0x04, 0xad, 0xc2, 0x20, 0x12, 0xc0, 0x2f, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x46,
            0xe7, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x32, 0xc0, 0x2f, 0xc0, 0x2f, 0x00, 0x02, 0x00,
            0x01, 0x00, 0x01, 0x46, 0xe7, 0x00, 0x06, 0x03, 0x6e, 0x73, 0x33, 0xc0, 0x2f, 0xc0,
            0x2f, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x46, 0xe7, 0x00, 0x06, 0x03, 0x6e, 0x73,
            0x34, 0xc0, 0x2f, 0xc0, 0x2f, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0x46, 0xe7, 0x00,
            0x06, 0x03, 0x6e, 0x73, 0x31, 0xc0, 0x2f, 0xc0, 0xe1, 0x00, 0x01, 0x00, 0x01, 0x00,
            0x00, 0xc5, 0x00, 0x00, 0x04, 0xd8, 0xef, 0x20, 0x0a, 0xc0, 0xab, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x04, 0xd8, 0xef, 0x22, 0x0a, 0xc0, 0xbd, 0x00,
            0x01, 0x00, 0x01, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x04, 0xd8, 0xef, 0x24, 0x0a, 0xc0,
            0xcf, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xc5, 0x00, 0x00, 0x04, 0xd8, 0xef, 0x26,
            0x0a,
        ];

        let msg = DnsMessage::try_from_bytes(&resp).expect("deserialize");
        assert!(msg.recursion_ok);
    }

    #[test]
    fn test_ad_bit_serialization() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: true, // Set AD bit
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(parsed.ad, "AD bit should be set");
    }

    #[test]
    fn test_cd_bit_serialization() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: true, // Set CD bit
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(parsed.cd, "CD bit should be set");
    }

    #[test]
    fn test_ad_and_cd_bits_serialization() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: true, // Set AD bit
            cd: true, // Set CD bit
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(parsed.ad, "AD bit should be set");
        assert!(parsed.cd, "CD bit should be set");
    }

    #[test]
    fn test_ad_bit_not_set() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false, // AD bit not set
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(!parsed.ad, "AD bit should not be set");
    }

    #[test]
    fn test_cd_bit_not_set() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: false, // CD bit not set
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(!parsed.cd, "CD bit should not be set");
    }

    #[test]
    fn test_ad_bit_with_ra_bit() {
        let msg = DnsMessage {
            id: 0x1234,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: false,
            recursion_ok: true, // RA bit set
            ad: true,           // AD bit set
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: None,
        };

        let mut buf = [0u8; 512];
        let len = msg.to_bytes(&mut buf).expect("serialize");

        // Parse it back
        let parsed = DnsMessage::try_from_bytes(&buf[..len]).expect("deserialize");
        assert!(parsed.recursion_ok, "RA bit should be set");
        assert!(parsed.ad, "AD bit should be set");
    }

    #[test]
    fn test_message_builder_initializes_ad_cd_false() {
        let builder =
            DnsMessageBuilder::new().with_query(nm("example.com"), Qtype::of(record_types::A));
        let msg = builder.build();

        assert!(!msg.ad, "AD bit should be false by default");
        assert!(!msg.cd, "CD bit should be false by default");
    }

    /// **D-1's actual claim, at the message level.** A response carrying a label
    /// that is not valid UTF-8 used to be unparseable, so `rdnsr` could not
    /// relay somebody else's zone that had one (RFC 2181 §11: "any binary string
    /// whatever can be used as the label").
    ///
    /// `rdns-core` no longer has a presentation reader to contrast with — that
    /// half of `dname.rs` went with the change — so what is asserted is the
    /// relay itself: in, out, and the same octets.
    #[test]
    fn a_response_carrying_a_binary_label_relays_byte_for_byte() {
        // Header, one question, one answer. The owner's first label is a single
        // 0xff octet, which no UTF-8 sequence begins with.
        let mut wire: Vec<u8> = vec![
            0x12, 0x34, // id
            0x81, 0x80, // QR, RD, RA
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let name: &[u8] = &[
            1, 0xff, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        wire.extend_from_slice(name);
        wire.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        wire.extend_from_slice(name);
        wire.extend_from_slice(&[
            0x00, 0x01, 0x00, 0x01, // TYPE A, CLASS IN
            0x00, 0x00, 0x01, 0x2c, // TTL 300
            0x00, 0x04, 192, 0, 2, 1,
        ]);

        let msg = DnsMessage::try_from_bytes(&wire).expect("a binary label is a label");
        assert_eq!(
            msg.queries[0].qname.as_ref().labels().next(),
            Some(&[0xffu8][..])
        );
        assert_eq!(msg.answers[0].name, msg.queries[0].qname);

        // Relayed: what goes back out is the name that came in, octet for octet.
        // Serialized without compression to compare against the input directly.
        let mut out = vec![0u8; 512];
        let len = msg.to_bytes(&mut out).expect("serialize");
        let back = DnsMessage::try_from_bytes(&out[..len]).expect("and parses again");
        assert_eq!(back.answers[0].name.as_ref().as_wire(), name);
        assert_eq!(back.answers[0].name, msg.answers[0].name);
    }
}
