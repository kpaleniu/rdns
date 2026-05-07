use anyhow::anyhow;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use rand::Rng;
use std::{
    io::{Cursor, Write},
    net::{Ipv4Addr, Ipv6Addr},
    str::from_utf8,
};

use dname::{dname_from_bytes, dname_to_bytes, DNameUnpacker, TryUnpackFromBytes};

pub mod dname;
pub mod zone;
pub mod security;
pub mod validation;
pub mod logging;
pub mod bench;
pub mod cache;
pub mod resolver;
pub mod metrics;

#[macro_use]
mod macros {
    macro_rules! read_be {
        ($dt:ty, $data:expr) => {{
            let sz = std::mem::size_of::<$dt>();
            (
                <$dt>::from_be_bytes($data[..sz].try_into().unwrap()),
                &$data[sz..],
            )
        }};
    }
}

#[derive(Debug, FromPrimitive, ToPrimitive, Clone)]
pub enum OpCode {
    Query = 0,
    IQuery = 1, // RFC3425: IQUERY obsolete
    Status = 2,
    Notify = 4,
    Update = 5,
    Unknown = 15,
}

// practically always IN (1), classes are supposed to be sort of
// dimension to the DNS database (see RFC6895 section 3.2). Only CH (3)
// and HS (4) are mentioned but practially never used outside of local tests
#[derive(Debug, FromPrimitive, ToPrimitive, PartialEq, Clone)]
pub enum QueryClass {
    IN = 1,
    CH = 3,
    HS = 4,
    None = 254,
    Any = 255,
}

#[derive(Debug, Clone)]
pub struct QuerySection {
    // Contains the domain name for the question
    pub qname: String,
    // Query type, matches ResourceRecordKind discriminant
    pub qtype: u16,
    pub qclass: QueryClass,
}

#[derive(Debug, Clone)]
pub enum ResourceRecordKind {
    A(Ipv4Addr),
    NS(String),
    CNAME(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
    PTR(String),
    MX {
        preference: u16,
        exchange: String,
    },
    TXT(String),
    AAAA(Ipv6Addr),
}

impl ResourceRecordKind {
    fn to_u16(kind: &str) -> Option<u16> {
        match kind {
            "A" => Some(1),
            "NS" => Some(2),
            "CNAME" => Some(5),
            "SOA" => Some(6),
            "PTR" => Some(12),
            "MX" => Some(15),
            "TXT" => Some(16),
            "AAAA" => Some(28),
            _ => None,
        }
    }

    fn try_from_bytes<'a>(
        record_type: u16,
        rdata: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<Self, anyhow::Error> {
        match record_type {
            1 => {
                let addr: [u8; 4] = rdata.try_into()?;
                Ok(ResourceRecordKind::A(Ipv4Addr::from(addr)))
            }
            2 => {
                let (nsname, _) = dname_from_bytes(rdata, unpacker)?;
                Ok(ResourceRecordKind::NS(nsname))
            }
            5 => {
                let (cname, _) = dname_from_bytes(rdata, unpacker)?;
                Ok(ResourceRecordKind::CNAME(cname))
            }
            6 => {
                let (mname, rest) = dname_from_bytes(rdata, unpacker)?;
                let (rname, rest) = dname_from_bytes(rest, unpacker)?;
                let (serial, rest) = read_be!(u32, rest);
                let (refresh, rest) = read_be!(i32, rest);
                let (retry, rest) = read_be!(i32, rest);
                let (expire, rest) = read_be!(i32, rest);
                let (minimum, _) = read_be!(u32, rest);

                Ok(ResourceRecordKind::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
            }
            12 => {
                let (ptrdname, _) = dname_from_bytes(rdata, unpacker)?;
                Ok(ResourceRecordKind::PTR(ptrdname))
            }
            15 => {
                let (preference, rest) = read_be!(u16, rdata);
                let (exchange, _) = dname_from_bytes(rest, unpacker)?;
                Ok(ResourceRecordKind::MX {
                    preference,
                    exchange,
                })
            }
            16 => Ok(ResourceRecordKind::TXT(from_utf8(rdata)?.to_string())),
            28 => {
                let addr: [u8; 16] = rdata.try_into()?;
                Ok(ResourceRecordKind::AAAA(Ipv6Addr::from(addr)))
            }
            _ => Err(anyhow!("unknown record type: {record_type}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub class: u16,
    pub ttl: i32, // As per 2.3.3 in RFC 1035
    pub rdata: ResourceRecordKind,
}

#[derive(Debug, FromPrimitive, ToPrimitive, Clone)]
pub enum ResponseCode {
    // RFC 1035 - Basic codes
    Ok = 0,
    FormatError = 1,
    ServerFailure = 2,
    NoSuchDomain = 3,
    NotImplemented = 4,
    Refused = 5,
    // RFC 2136 - Domain update related codes
    DomainExistsForSomeReason = 6,
    ResourceRecordSetExistsForSomeReason = 7,
    NoSuchResourceRecordSet = 8,
    NotAuthorized = 9, // Or ServerNotAuthorativeForZone (RFC8945)
    NameNotInZone = 10,

    // RFC 8490 - DNS Stateful Operations
    DsoTypeNotImplemented = 11,

    BadOptVersion = 16, // Or BadTsigSignature (RFC8945)
    BadKey = 17,
    BadTime = 18,

    // RFC 2930 - TKEY RR
    BadTkeyMode = 19,
    BadName = 20,
    BadAlgorithm = 21,
    BadTruncation = 22,
    BadCookie = 23,

    Unknown = 65535,
}

#[derive(Debug)]
pub struct DnsMessage {
    pub id: u16,
    pub response: bool,      // is the message response or query, QR
    pub opcode: OpCode,      // type of query, copied over to the response
    pub authoritive: bool,   // response: whether or not responding nameserver is the zone owner
    pub truncation: bool, // whether or not the message had to be truncated due to transmission channel
    pub recursion: bool,  // query: whether or not client wants server to do recursion
    pub recursion_ok: bool, // response: whether or not server support is available
    pub rcode: ResponseCode, // response status: whether or not response was succesful

    pub queries: Vec<QuerySection>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl<'a> TryUnpackFromBytes<'a> for QuerySection {
    type Output = (QuerySection, &'a [u8]);
    type Error = anyhow::Error;
    fn try_from_bytes(
        data: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<
        <QuerySection as TryUnpackFromBytes<'a>>::Output,
        <QuerySection as TryUnpackFromBytes<'a>>::Error,
    > {
        let (qname, rest) = dname_from_bytes(data, unpacker)?;
        let (qtype, rest) = read_be!(u16, rest);
        let (qclass, rest) = read_be!(u16, rest);
        Ok((
            Self {
                qname,
                qtype,
                qclass: QueryClass::from_u16(qclass).unwrap_or(QueryClass::None),
            },
            rest,
        ))
    }
}

impl<'a> TryUnpackFromBytes<'a> for ResourceRecord {
    type Output = (ResourceRecord, &'a [u8]);
    type Error = anyhow::Error;
    fn try_from_bytes(
        data: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<<Self as TryUnpackFromBytes<'a>>::Output, Self::Error> {
        let (name, rest) = dname_from_bytes(data, unpacker)?;
        let (record_type, rest) = read_be!(u16, rest);
        let (class, rest) = read_be!(u16, rest);
        let (ttl, rest) = read_be!(i32, rest);
        let (rdatalen, rest) = read_be!(u16, rest);
        let rdata = &rest[..rdatalen as usize];

        let rdata = ResourceRecordKind::try_from_bytes(record_type, rdata, unpacker)?;
        Ok((
            Self {
                name,
                class,
                ttl,
                rdata,
            },
            &rest[rdatalen as usize..],
        ))
    }
}

impl DnsMessage {
    pub fn try_from_bytes(data: &[u8]) -> Result<Self, anyhow::Error> {
        if data.len() < 12 {
            return Err(anyhow!("not enough data"));
        }

        let unpacker = DNameUnpacker::new(data);

        let (id, rest) = read_be!(u16, data);
        let (hi, rest) = read_be!(u8, rest);
        let (lo, rest) = read_be!(u8, rest);
        let (query_len, rest) = read_be!(u16, rest);
        let (answer_len, rest) = read_be!(u16, rest);
        let (auth_len, rest) = read_be!(u16, rest);
        let (add_len, mut rest) = read_be!(u16, rest);

        let opcode = OpCode::from_u8(hi & 0x70).unwrap_or(OpCode::Unknown);
        let rcode = ResponseCode::from_u8(lo & 0x0f).unwrap_or(ResponseCode::Unknown);

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

        let mut additionals = Vec::new();
        for _ in 0..add_len {
            let (query, r) = ResourceRecord::try_from_bytes(rest, &unpacker)?;
            additionals.push(query);
            rest = r;
        }

        Ok(Self {
            id,
            response: hi & 0x80 == 0x80,
            opcode,
            authoritive: hi & 0x04 == 0x04,
            truncation: hi & 0x02 == 0x02,
            recursion: hi & 0x01 == 0x01,
            recursion_ok: lo & 0x80 == 0x80,
            rcode,
            queries,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn to_bytes(&self, output: &mut [u8]) -> Result<usize, anyhow::Error> {
        let mut written = 0;
        let mut buf = Cursor::new(output);
        written += buf.write(&self.id.to_be_bytes())?;

        let opcode = self.opcode.to_u8().unwrap_or_default();
        let rcode = self.rcode.to_u8().unwrap_or_default();
        let hi: u8 = (self.response as u8) << 7
            | (opcode & 0xf_u8) << 3
            | (self.authoritive as u8) << 2
            | (self.truncation as u8) << 1
            | self.recursion as u8;
        let lo: u8 = (self.recursion_ok as u8) << 7 | (rcode & 0x7);

        written += buf.write(&[hi, lo])?;
        written += buf.write(&(self.queries.len() as u16).to_be_bytes())?;
        written += buf.write(&(self.answers.len() as u16).to_be_bytes())?;
        written += buf.write(&(self.authorities.len() as u16).to_be_bytes())?;
        written += buf.write(&(self.additionals.len() as u16).to_be_bytes())?;

        for q in &self.queries {
            written += buf.write(&dname_to_bytes(q.qname.as_str())?)?;
            written += buf.write(&q.qtype.to_be_bytes())?;
            let qclass = &q.qclass.to_u16().unwrap_or(254);
            written += buf.write(&qclass.to_be_bytes())?;
        }
        Ok(written)
    }
}

#[derive(Default)]
pub struct DnsMessageBuilder {
    id: u16,
    queries: Vec<(String, u16)>,
}

impl DnsMessageBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_url(mut self, url: &str, query_type: &str) -> Self {
        if let Some(q) = ResourceRecordKind::to_u16(query_type) {
            self.queries.push((url.to_owned(), q));
        }
        self
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
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
            recursion: true,
            recursion_ok: false,
            rcode: ResponseCode::Ok,
            queries: self
                .queries
                .iter()
                .map(|(url, qt)| QuerySection {
                    qname: url.to_owned(),
                    qtype: *qt,
                    qclass: QueryClass::IN,
                })
                .collect(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(query.qname, "www.google.fi.");
        assert_eq!(query.qtype, 1);
        assert_eq!(query.qclass, QueryClass::IN);
    }

    #[test]
    fn test_query_builder() {
        let req = DnsMessageBuilder::new()
            .with_id(u16::from_be_bytes([0xf5, 0x6f]))
            .with_url("www.google.fi", "A")
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
}
