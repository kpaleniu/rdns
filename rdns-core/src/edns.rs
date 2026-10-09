//! EDNS0 (RFC 6891): the OPT pseudo-record and the parameters it carries.
//!
//! A module so [`Edns::rdata`] — the option list, held unparsed — cannot be set
//! by anything but the constructors here, which encode a well-formed one.

use crate::codes::Rtype;
use crate::ede::ExtendedError;
use crate::error::WireError;
use crate::macros::read_be;
use crate::validation::Transport;
use crate::DnsMessage;

/// The RR TYPE code of the EDNS0 OPT pseudo-record (RFC 6891).
pub const OPT_RECORD_TYPE: Rtype = Rtype::new(41);

/// The classic (pre-EDNS) UDP message size limit (RFC 1035 §4.2.1).
pub const CLASSIC_UDP_SIZE: u16 = 512;

/// The EDNS version we implement. A request at a higher version gets BADVERS
/// (RFC 6891 §6.1.3).
pub const EDNS_VERSION: u8 = 0;

/// The two UDP sizes a server chooses, and the one rule that relates them to
/// the size the *client* chose.
///
/// [`UdpSizes::advertised`] goes in every reply's OPT (RFC 6891 §6.2.4) and
/// floors request admission; [`UdpSizes::max_response`] caps what this host
/// sends, where the client's number alone would fragment. The only way to a
/// reply's size is [`UdpSizes::reply_ceiling`], so the min cannot be forgotten
/// (`CLAUDE.md` §17). The split is Unbound's and BIND's `max-udp-size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSizes {
    advertised: u16,
    max_response: u16,
}

impl UdpSizes {
    /// Both floored at [`CLASSIC_UDP_SIZE`], where a truncated reply must fit;
    /// a mistyped flag is wrong, not fatal (`CLAUDE.md` §14). `u16::MAX` is
    /// every datagram, so there is no off.
    pub fn new(advertised: u16, max_response: u16) -> UdpSizes {
        UdpSizes {
            advertised: advertised.max(CLASSIC_UDP_SIZE),
            max_response: max_response.max(CLASSIC_UDP_SIZE),
        }
    }

    /// What every reply's OPT says this host can reassemble.
    pub fn advertised(&self) -> u16 {
        self.advertised
    }

    /// The largest UDP datagram this host will send, before the client's own
    /// number is taken into account.
    pub fn max_response(&self) -> u16 {
        self.max_response
    }

    /// What a reply to `request` may weigh on `transport`.
    ///
    /// On UDP the smaller of the client's size (RFC 6891 §6.2.3, floored at
    /// 512) and ours, which RFC 7766 §4 permits for fragmentation's sake. On
    /// TCP only the RFC 1035 §4.2.2 prefix limits it.
    pub fn reply_ceiling(&self, request: &DnsMessage, transport: Transport) -> usize {
        match transport {
            Transport::Tcp => u16::MAX as usize,
            Transport::Udp => request.udp_payload_size().min(self.max_response) as usize,
        }
    }
}

impl Default for UdpSizes {
    /// 1232 for both, which is the documented default of BIND's `max-udp-size`
    /// and `edns-udp-size`, Knot's `udp-max-payload`, NSD's `ipv4-edns-size`
    /// and Unbound's `edns-buffer-size` and `max-udp-size` alike, after DNS
    /// Flag Day 2020. It is the smallest MTU IPv6 guarantees less the headers,
    /// so a reply at it is not fragmented on any path that works at all.
    fn default() -> Self {
        UdpSizes::new(FLAG_DAY_UDP_SIZE, FLAG_DAY_UDP_SIZE)
    }
}

/// The UDP size DNS Flag Day 2020 settled on: 1280 (IPv6's minimum MTU,
/// RFC 8200 §5) less 40 octets of IPv6 header and 8 of UDP header.
///
/// Not a protocol constant — an operational one, which is why every
/// implementation makes it a knob. Above it the reply is fragmented, and a
/// fragment is what middleboxes drop and what "Fragmentation Considered
/// Poisonous" (draft-ietf-dnsop-fragmentation-poisoned) is about.
pub const FLAG_DAY_UDP_SIZE: u16 = 1232;

// EDNS option codes (IANA). Any option is carried as opaque bytes; a reply
// reads Padding and builds the rest fresh (`ClientEdns`).
/// Name Server Identifier (RFC 5001).
pub const EDNS_OPTION_NSID: u16 = 3;
/// Client Subnet (RFC 7871), which this tree never sends or echoes.
///
/// RFC 7871 §11: the client's network "becomes visible to all servers involved
/// in the resolution process", and it "SHOULD be disabled in all default
/// configurations". [`crate::response::ClientEdns::mirror`] builds a fresh OPT
/// and the resolver's query carries no options; tests pin both.
pub const EDNS_OPTION_CLIENT_SUBNET: u16 = 8;
/// DNS Cookie (RFC 7873).
pub const EDNS_OPTION_COOKIE: u16 = 10;
/// edns-tcp-keepalive (RFC 7828): empty in a query, a timeout in units of
/// 100 ms in a reply.
pub const EDNS_OPTION_TCP_KEEPALIVE: u16 = 11;
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

impl EdnsOption {
    /// Append this option's three fields to an OPT RDATA under construction.
    ///
    /// The one encoder: [`Edns::with_options`] and [`Edns::with_extended_error`]
    /// both go through it, because a second copy is where the length field
    /// would come to disagree with the data (`CLAUDE.md` §7).
    fn append_to(&self, rdata: &mut Vec<u8>) -> Result<(), WireError> {
        let len: u16 = self.data.len().try_into().map_err(|_| WireError::TooLong {
            what: "EDNS option data",
            limit: u16::MAX as usize,
            actual: self.data.len(),
        })?;
        rdata.extend_from_slice(&self.code.to_be_bytes());
        rdata.extend_from_slice(&len.to_be_bytes());
        rdata.extend_from_slice(&self.data);
        Ok(())
    }
}

/// EDNS0 OPT pseudo-record (RFC 6891). CLASS is the requestor's UDP payload
/// size, TTL the extended RCODE, version and flags.
///
/// The extended RCODE belongs to the message
/// ([`DnsMessage::rcode`](crate::DnsMessage::rcode)). The option list is held
/// unparsed, so a bad one leaves a parsed message to answer FORMERR from.
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

    /// The OPT record read off the wire: CLASS, the TTL flags word and the
    /// RDATA as they arrived.
    ///
    /// The option list is not walked, so a malformed one cannot fail the parse.
    /// The extended RCODE's high byte is not kept: `DnsMessage` reassembles
    /// `rcode` from it.
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
            opt.append_to(&mut rdata)?;
        }
        Ok(Edns {
            udp_payload_size: size,
            version,
            do_bit,
            rdata: rdata.into_boxed_slice(),
        })
    }

    /// The same OPT with `error` appended to its option list (RFC 8914 §2,
    /// which allows several). `Result` as for [`Edns::with_options`], though
    /// [`ExtendedError`]'s bound keeps it from firing.
    pub fn with_extended_error(self, error: ExtendedError) -> Result<Self, WireError> {
        let mut rdata = self.rdata.into_vec();
        error.to_option().append_to(&mut rdata)?;
        Ok(Edns {
            rdata: rdata.into_boxed_slice(),
            ..self
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

    /// Whether an option with `code` is in a well-formed list, without
    /// copying its data.
    pub fn has_option(&self, code: u16) -> Result<bool, WireError> {
        let mut found = false;
        Self::walk_options(&self.rdata, |c, _| found |= c == code)?;
        Ok(found)
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
            // Before `read_be!`, whose error names a type, so this one names
            // the field.
            if rdata.len() < 4 {
                return Err(WireError::Truncated {
                    what: "an EDNS option header",
                    need: 4,
                    have: rdata.len(),
                });
            }
            let (code, tail) = read_be!(u16, rdata);
            let (len, tail) = read_be!(u16, tail);
            let len = len as usize;
            if tail.len() < len {
                return Err(WireError::Truncated {
                    what: "EDNS option data",
                    need: len,
                    have: tail.len(),
                });
            }
            each(code, &tail[..len]);
            rdata = &tail[len..];
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DnsMessageBuilder, Qtype, Rtype};

    /// The guard `read_be!` cannot replace: a tail too short for a header is
    /// reported as the header, where the macro would report `u16`.
    #[test]
    fn an_option_list_too_short_for_a_header_names_the_header() {
        let edns = Edns::from_opt(1232, 0, &[0x00, 0x0a, 0x00]);
        assert_eq!(
            edns.check_options()
                .expect_err("three octets cannot hold a code and a length"),
            WireError::Truncated {
                what: "an EDNS option header",
                need: 4,
                have: 3,
            }
        );
    }

    /// A query advertising `advertised`, or none at all when `None`.
    fn asking(advertised: Option<u16>) -> DnsMessage {
        let mut msg = DnsMessageBuilder::new()
            .with_id(1)
            .with_query(
                "example.com.".parse().expect("a name"),
                Qtype::of(Rtype::new(1)),
            )
            .build();
        if let Some(size) = advertised {
            msg.set_edns(Edns::with_payload_size(size));
        }
        msg
    }

    /// A reply is bounded by both numbers, and the client does not get to raise
    /// ours.
    ///
    /// Fails on the 65,535 row if the client's number is honoured in full: ~45
    /// IP fragments for an answer that size.
    #[test]
    fn a_udp_reply_is_bounded_by_the_smaller_of_the_two_advertisements() {
        let sizes = UdpSizes::new(1232, 1232);
        for (client, expected) in [
            (Some(u16::MAX), 1232),
            (Some(4096), 1232),
            (Some(1232), 1232),
            (Some(900), 900),
            // Under the classic 512, which `udp_payload_size` floors
            // (RFC 6891 §6.2.3).
            (Some(300), 512),
            (None, 512),
        ] {
            assert_eq!(
                sizes.reply_ceiling(&asking(client), Transport::Udp),
                expected,
                "client advertising {client:?}"
            );
        }
    }

    /// TCP is framed by a 16-bit length prefix and neither number applies
    /// (RFC 1035 §4.2.2) — the trap being a UDP ceiling silently reaching TCP,
    /// which is why the transport is this method's parameter rather than each
    /// caller's `match`.
    #[test]
    fn tcp_is_bounded_by_the_length_prefix_alone() {
        let sizes = UdpSizes::new(512, 512);
        assert_eq!(
            sizes.reply_ceiling(&asking(Some(512)), Transport::Tcp),
            u16::MAX as usize
        );
    }

    /// A knob that can turn the server off is floored, not obeyed: a ceiling of
    /// zero has no room for the truncated reply that says so
    /// (`CLAUDE.md` §14).
    #[test]
    fn both_sizes_are_floored_at_the_classic_512() {
        let sizes = UdpSizes::new(0, 0);
        assert_eq!(sizes.advertised(), CLASSIC_UDP_SIZE);
        assert_eq!(sizes.max_response(), CLASSIC_UDP_SIZE);
        assert_eq!(UdpSizes::default().max_response(), FLAG_DAY_UDP_SIZE);
    }
}
