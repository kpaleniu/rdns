//! [`RecordData`] and nothing else.
//!
//! A field is sealed only against the module declaring it — private in the crate
//! root means visible to the whole library — so a type whose fields must be
//! sealed against its own crate needs a file of its own.

use crate::dname::{skip_uncompressed_name, DNameUnpacker};
use crate::error::WireError;
use crate::{ParsedRecord, Rtype, Serial};

/// A record's data, stored as uncompressed wire-format bytes.
///
/// 24 bytes whatever the type, since the large DNSSEC and SOA payloads no longer
/// sit inline in every record. Embedded names are expanded on the way in, so the
/// bytes are self-contained: re-parsing or re-serializing needs no access to the
/// message they came from.
///
/// Private fields are the invariant — the bytes decode as their TYPE, and the
/// three constructors are the only way in. What it does not claim:
///
/// - A type with no decoder here is stored verbatim (RFC 3597 §5), as is an
///   RDLENGTH of zero, which RFC 2136 §2.4 and §2.5 use to mean "this type, no
///   value".
/// - [`RecordData::parse`] still returns a `Result`. Making it infallible would
///   mean proving every `ParsedRecord` re-encodes to bytes that decode again.
/// - Nothing bounds the length; that check lives where the 16-bit RDLENGTH is
///   written, at message serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordData {
    rtype: Rtype,
    rdata: Box<[u8]>,
}

impl RecordData {
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// The stored bytes: uncompressed wire-format RDATA.
    ///
    /// Read-only: a `&mut` would let the contents disagree with `rtype`.
    pub fn bytes(&self) -> &[u8] {
        &self.rdata
    }

    /// Read a record's RDATA off the wire and store it compactly.
    ///
    /// `unpacker` follows compression pointers against the full message; the
    /// result is re-encoded uncompressed so the stored bytes stand alone.
    pub fn from_wire<'a>(
        record_type: Rtype,
        rdata: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<Self, WireError> {
        let parsed = ParsedRecord::decode(record_type, rdata, unpacker)?;
        if let ParsedRecord::Unknown(_) = parsed {
            // Opaque type, or an RDLENGTH of zero: keep the original bytes
            // exactly as received.
            return Ok(RecordData {
                rtype: record_type,
                rdata: rdata.to_vec().into_boxed_slice(),
            });
        }
        Self::from_parsed(&parsed)
    }

    /// Encode a typed record into compact, uncompressed wire-format storage.
    pub fn from_parsed(parsed: &ParsedRecord) -> Result<Self, WireError> {
        let (rtype, rdata) = parsed.encode()?;
        Ok(RecordData {
            rtype,
            rdata: rdata.into_boxed_slice(),
        })
    }

    /// Wire-format RDATA that some other code produced — a signer building a
    /// DNSKEY, a zone file's RFC 3597 `\#` escape, a test.
    ///
    /// Checked, not trusted: the bytes must decode as `rtype`. A type with no
    /// decoder reads back as [`ParsedRecord::Unknown`], so only a *known* type
    /// whose bytes are not that type is rejected. Names must already be
    /// uncompressed; there is no message here to resolve a pointer against.
    pub fn new(rtype: Rtype, rdata: impl Into<Box<[u8]>>) -> Result<Self, WireError> {
        let stored = RecordData {
            rtype,
            rdata: rdata.into(),
        };
        stored.parse()?;
        Ok(stored)
    }

    /// Parse the stored bytes into a typed [`ParsedRecord`] on demand.
    ///
    /// Records only cached and re-served never need this. Stored names are
    /// uncompressed, so the unpacker over the rdata itself suffices.
    pub fn parse(&self) -> Result<ParsedRecord, WireError> {
        let unpacker = DNameUnpacker::new(&self.rdata);
        ParsedRecord::decode(self.rtype, &self.rdata, &unpacker)
    }

    /// The SOA's SERIAL (RFC 1035 §3.3.13), or `None` if this is not an SOA.
    pub fn soa_serial(&self) -> Option<Serial> {
        let s = self.soa_scalars()?;
        Some(Serial::new(u32::from_be_bytes([s[0], s[1], s[2], s[3]])))
    }

    /// The SOA's MINIMUM: the ceiling on how long a negative answer about this
    /// zone may be cached (RFC 2308 §3).
    pub fn soa_minimum(&self) -> Option<u32> {
        let s = self.soa_scalars()?;
        Some(u32::from_be_bytes([s[16], s[17], s[18], s[19]]))
    }

    /// The RRSIG's TYPE COVERED, the first two octets of its RDATA
    /// (RFC 4034 §3.1.1), or `None` if this is not an RRSIG.
    ///
    /// Every signature lookup on the answer path filters a name's RRSIGs by
    /// this field alone, and [`RecordData::parse`] answers it by decoding the
    /// signer's name and copying the signature out. A signed negative answer
    /// paid that once per RRSIG at the apex — five of them for the zone the
    /// tests use, and the field is at a fixed offset.
    pub fn rrsig_type_covered(&self) -> Option<Rtype> {
        if self.rtype != crate::utils::record_types::RRSIG {
            return None;
        }
        let covered: [u8; 2] = self.rdata.get(..2)?.try_into().ok()?;
        Some(Rtype::new(u16::from_be_bytes(covered)))
    }

    /// The five 32-bit fields an SOA carries after MNAME and RNAME.
    ///
    /// [`RecordData::parse`] answers the same questions and allocates four times
    /// on the way: a label `Vec` and a `String` for each of the two names, both
    /// discarded by every caller that wanted a number. Every negative answer
    /// reads MINIMUM, which is the shape a random-subdomain flood generates.
    fn soa_scalars(&self) -> Option<&[u8; 20]> {
        if self.rtype != crate::utils::record_types::SOA {
            return None;
        }
        let after_mname = skip_uncompressed_name(&self.rdata)?;
        let after_rname = skip_uncompressed_name(after_mname)?;
        after_rname.get(..20)?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::record_types as rt;

    /// A TYPE that says A, and bytes that are not an address. Cannot be a
    /// failing-first test: what it guards is a line that no longer compiles.
    #[test]
    fn rdata_that_is_not_its_type_is_refused() {
        assert!(
            RecordData::new(rt::A, vec![0u8; 17]).is_err(),
            "seventeen bytes are not an IPv4 address"
        );
        assert!(RecordData::new(rt::A, vec![192, 0, 2, 1]).is_ok());
    }

    /// Two cases the invariant deliberately does not cover, because the wire has
    /// them: a type with no decoder (RFC 3597 §5), and an RDLENGTH of zero,
    /// which RFC 2136 §2.4 and §2.5 use to mean "this type, no value". Assuming
    /// the second away makes a legal UPDATE unparseable.
    #[test]
    fn opaque_and_empty_rdata_are_both_storable() {
        let unknown = RecordData::new(Rtype::new(64_999), vec![0xde, 0xad])
            .expect("a type with no decoder is kept verbatim");
        assert_eq!(unknown.bytes(), [0xde, 0xad]);

        let empty = RecordData::new(rt::A, Vec::new())
            .expect("RFC 2136 §2.5.2 spells 'delete this RRset' exactly so");
        assert_eq!(empty.rtype(), rt::A, "the TYPE is the whole content");
        assert!(empty.bytes().is_empty());
    }

    /// The offset walk must answer what the decoder answers, for names of
    /// differing label counts — an arithmetic slip reads a neighbouring field
    /// and still returns a plausible number. `parse` is the reference here
    /// because it is the code these two replaced at four call sites.
    #[test]
    fn the_soa_accessors_agree_with_the_full_parse() {
        for (mname, rname) in [
            ("ns1.example.com.", "admin.example.com."),
            (".", "."),
            ("a.b.c.d.e.f.example.com.", "hostmaster.example.com."),
        ] {
            let soa = RecordData::from_parsed(&ParsedRecord::SOA {
                mname: mname.to_string(),
                rname: rname.to_string(),
                serial: Serial::new(0x0102_0304),
                refresh: 3600,
                retry: 600,
                expire: 604_800,
                minimum: 300,
            })
            .expect("encode");

            let Ok(ParsedRecord::SOA {
                serial, minimum, ..
            }) = soa.parse()
            else {
                panic!("an SOA parses as an SOA");
            };
            assert_eq!(soa.soa_serial(), Some(serial), "{mname} {rname}");
            assert_eq!(soa.soa_minimum(), Some(minimum), "{mname} {rname}");
        }
    }

    /// TYPE COVERED is at a fixed offset, but so is every other RRSIG field,
    /// so reading the wrong one still returns a plausible `Rtype`. `parse` is
    /// the reference, over types whose codes cannot be confused with the
    /// algorithm or label bytes beside them.
    #[test]
    fn rrsig_type_covered_agrees_with_the_full_parse() {
        for covered in [rt::A, rt::SOA, rt::NSEC3, Rtype::new(64_999)] {
            let rrsig = RecordData::from_parsed(&ParsedRecord::RRSIG {
                type_covered: covered,
                algorithm: 13,
                labels: 2,
                original_ttl: 3600,
                inception: 1_700_000_000,
                expiration: 1_702_592_000,
                key_tag: 0x1234,
                signer_name: "example.com.".to_string(),
                signature: vec![0xab; 64],
            })
            .expect("encode");

            let Ok(ParsedRecord::RRSIG { type_covered, .. }) = rrsig.parse() else {
                panic!("an RRSIG parses as an RRSIG");
            };
            assert_eq!(
                rrsig.rrsig_type_covered(),
                Some(type_covered),
                "{covered:?}"
            );
        }
    }

    /// Not an RRSIG, and the empty RRSIG that RFC 2136 §2.5.2 spells to delete
    /// an RRset: neither may answer with a type read out of whatever is there.
    /// A *truncated* one cannot be built — [`RecordData::new`] parses — so the
    /// bounds check covers only the empty case and stays because the field
    /// offset is not the constructor's invariant.
    #[test]
    fn rrsig_type_covered_refuses_anything_it_cannot_read() {
        let a = RecordData::new(rt::A, vec![192, 0, 2, 1]).expect("an A record");
        assert_eq!(a.rrsig_type_covered(), None);

        let empty = RecordData::new(rt::RRSIG, Vec::new()).expect("delete this RRset");
        assert_eq!(empty.rrsig_type_covered(), None, "no octets are not a TYPE");
    }

    /// Neither accessor answers for a record that is not an SOA, however much
    /// its bytes might look like one.
    #[test]
    fn the_soa_accessors_refuse_another_type() {
        let a = RecordData::new(rt::A, vec![192, 0, 2, 1]).expect("an A record");
        assert_eq!(a.soa_serial(), None);
        assert_eq!(a.soa_minimum(), None);
    }

    /// Anything that exists parses, so `parse`'s `Result` means "should not
    /// happen" rather than "a caller may have built nonsense".
    #[test]
    fn every_constructor_leaves_something_that_parses() {
        let built = [
            RecordData::from_parsed(&ParsedRecord::A("192.0.2.1".parse().unwrap())).unwrap(),
            RecordData::new(rt::A, vec![192, 0, 2, 1]).unwrap(),
            RecordData::new(Rtype::new(64_999), vec![1, 2, 3]).unwrap(),
        ];
        for record in &built {
            assert!(record.parse().is_ok(), "{record:?}");
        }
    }
}
