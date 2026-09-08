//! EDNS0 (RFC 6891): the OPT pseudo-record and the parameters it carries.
//!
//! A module so [`Edns::rdata`] — the option list, held unparsed — cannot be set
//! by anything but the constructors here, which encode a well-formed one.

use crate::codes::Rtype;
use crate::error::WireError;

/// The RR TYPE code of the EDNS0 OPT pseudo-record (RFC 6891).
pub const OPT_RECORD_TYPE: Rtype = Rtype::new(41);

/// The classic (pre-EDNS) UDP message size limit (RFC 1035 §4.2.1).
pub const CLASSIC_UDP_SIZE: u16 = 512;

/// The EDNS version we implement. A request at a higher version gets BADVERS
/// (RFC 6891 §6.1.3).
pub const EDNS_VERSION: u8 = 0;

// EDNS option codes (IANA "DNS EDNS0 Option Codes"). None is interpreted;
// options round-trip as opaque bytes.
/// Name Server Identifier (RFC 5001).
pub const EDNS_OPTION_NSID: u16 = 3;
/// Client Subnet (RFC 7871).
pub const EDNS_OPTION_CLIENT_SUBNET: u16 = 8;
/// DNS Cookie (RFC 7873).
pub const EDNS_OPTION_COOKIE: u16 = 10;
/// Padding (RFC 7830).
pub const EDNS_OPTION_PADDING: u16 = 12;

/// A single EDNS option carried in the OPT RDATA (RFC 6891 §6.1.2): a 16-bit
/// option code, a 16-bit length, then that many bytes of option data.
///
/// Option data is stored verbatim; we don't interpret any option's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    pub code: u16,
    pub data: Vec<u8>,
}

/// EDNS0 OPT pseudo-record (RFC 6891).
///
/// OPT repurposes the usual RR fields: NAME is root, CLASS is the requestor's
/// UDP payload size, TTL packs the extended-RCODE / version / flags (including
/// DNSSEC-OK).
///
/// The extended RCODE is not a field here — it belongs to the message, so it
/// lives in [`DnsMessage::rcode`](crate::DnsMessage::rcode) and is split across the header and the OPT TTL
/// only in [`DnsMessage::to_bytes`](crate::DnsMessage::to_bytes). The option list is held unparsed because it
/// is the only fallible part: parsing it with the message would make a bad list
/// fail `DnsMessage::try_from_bytes`, leaving no parsed message for
/// `error_bytes` to answer FORMERR from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edns {
    /// Requestor's/responder's advertised UDP payload size (OPT CLASS field).
    pub udp_payload_size: u16,
    /// EDNS version (0 for EDNS0).
    pub version: u8,
    /// DNSSEC OK bit (DO) — the client is willing to receive DNSSEC records.
    pub do_bit: bool,
    /// The OPT RDATA: the option list in wire form. See the note above.
    rdata: Box<[u8]>,
}

/// The three EDNS parameters a server acts on, without the option list.
///
/// The answer path asks only how big a reply may be, whether the version is one
/// we implement, and whether DO is set; building the options costs a `Vec` and a
/// `Vec<u8>` per option at a call site that wanted a flag. `Copy`, so threading
/// it through costs nothing. The options are still on [`DnsMessage::edns`](crate::DnsMessage::edns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdnsHeader {
    /// Requestor's advertised UDP payload size (OPT CLASS field), as sent — not
    /// floored at 512. [`DnsMessage::udp_payload_size`](crate::DnsMessage::udp_payload_size) applies RFC 6891
    /// §6.2.3's floor, which is a question about what we may send.
    pub udp_payload_size: u16,
    /// EDNS version. Anything but 0 is BADVERS (RFC 6891 §6.1.3).
    pub version: u8,
    /// DNSSEC OK: the client can make sense of DNSSEC records (RFC 3225).
    pub do_bit: bool,
}

impl Edns {
    /// The parameters without the options — see [`EdnsHeader`].
    pub fn header(&self) -> EdnsHeader {
        EdnsHeader {
            udp_payload_size: self.udp_payload_size,
            version: self.version,
            do_bit: self.do_bit,
        }
    }

    /// The OPT record read off the wire: the CLASS field, the TTL flags word and
    /// the RDATA exactly as they arrived.
    ///
    /// The option list is not walked here — a malformed one must not fail the
    /// message parse (see the note above) — so this is the one constructor that
    /// takes RDATA it has not encoded itself.
    ///
    /// The extended RCODE's high byte lives in the top of `flags` and is *not*
    /// kept: it is a property of the message, so `DnsMessage` reassembles it
    /// into `rcode` from the same word.
    pub(crate) fn from_opt(udp_payload_size: u16, flags: u32, rdata: &[u8]) -> Self {
        Edns {
            udp_payload_size,
            version: ((flags >> 16) & 0xff) as u8,
            do_bit: (flags & 0x8000) != 0,
            rdata: rdata.to_vec().into_boxed_slice(),
        }
    }

    /// A plain OPT advertising `size` bytes, EDNS version 0, DO clear, no options.
    pub fn with_payload_size(size: u16) -> Self {
        Edns {
            udp_payload_size: size,
            version: EDNS_VERSION,
            do_bit: false,
            rdata: Box::new([]),
        }
    }

    /// An OPT carrying `options`, encoded into RDATA once here rather than at
    /// serialization time.
    ///
    /// Errors only if an option's data exceeds the 16-bit length field.
    pub fn with_options(
        size: u16,
        version: u8,
        do_bit: bool,
        options: &[EdnsOption],
    ) -> Result<Self, WireError> {
        let mut rdata = Vec::new();
        for opt in options {
            let len: u16 = opt.data.len().try_into().map_err(|_| WireError::TooLong {
                what: "EDNS option data",
                limit: u16::MAX as usize,
                actual: opt.data.len(),
            })?;
            rdata.extend_from_slice(&opt.code.to_be_bytes());
            rdata.extend_from_slice(&len.to_be_bytes());
            rdata.extend_from_slice(&opt.data);
        }
        Ok(Edns {
            udp_payload_size: size,
            version,
            do_bit,
            rdata: rdata.into_boxed_slice(),
        })
    }

    /// The option list, parsed. A malformed list is an error rather than a
    /// partial read: it earns FORMERR, not a truncated view.
    pub fn options(&self) -> Result<Vec<EdnsOption>, WireError> {
        let mut options = Vec::new();
        Self::walk_options(&self.rdata, |code, data| {
            options.push(EdnsOption {
                code,
                data: data.to_vec(),
            })
        })?;
        Ok(options)
    }

    /// Whether the option list is well formed, without building it — the
    /// FORMERR question, which the answer path asks and [`Edns::options`] does
    /// more work than it needs to answer.
    pub fn check_options(&self) -> Result<(), WireError> {
        Self::walk_options(&self.rdata, |_, _| {})
    }

    /// The data of the first option with `code`, if the list is well formed.
    pub fn option(&self, code: u16) -> Result<Option<Vec<u8>>, WireError> {
        let mut found = None;
        Self::walk_options(&self.rdata, |c, data| {
            if c == code && found.is_none() {
                found = Some(data.to_vec());
            }
        })?;
        Ok(found)
    }

    /// The OPT RDATA as it will go on the wire.
    pub(crate) fn rdata(&self) -> &[u8] {
        &self.rdata
    }

    /// Walk the option list, handing each option's code and data to `each`
    /// without copying either.
    ///
    /// Shared by [`Edns::options`] and [`Edns::check_options`] so the TLV
    /// arithmetic that decides whether a packet is FORMERR exists once.
    fn walk_options(mut rdata: &[u8], mut each: impl FnMut(u16, &[u8])) -> Result<(), WireError> {
        while !rdata.is_empty() {
            if rdata.len() < 4 {
                return Err(WireError::Truncated {
                    what: "an EDNS option header",
                    need: 4,
                    have: rdata.len(),
                });
            }
            let code = u16::from_be_bytes([rdata[0], rdata[1]]);
            let len = u16::from_be_bytes([rdata[2], rdata[3]]) as usize;
            rdata = &rdata[4..];
            if rdata.len() < len {
                return Err(WireError::Truncated {
                    what: "EDNS option data",
                    need: len,
                    have: rdata.len(),
                });
            }
            each(code, &rdata[..len]);
            rdata = &rdata[len..];
        }
        Ok(())
    }
}
