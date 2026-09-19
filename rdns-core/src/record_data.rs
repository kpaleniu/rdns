//! [`RecordData`], its borrowed form, and the arena that stores one.
//!
//! A field is sealed only against the module declaring it — private in the crate
//! root means visible to the whole library — so a type whose fields must be
//! sealed against its own crate needs a file of its own.
//!
//! [`RdataArena`] is here for that reason and no other. It hands out
//! [`RecordDataRef`]s over octets it holds, which means minting one without
//! going through a checking constructor; doing that from another module would
//! need a `pub(crate)` constructor, and a `pub(crate)` hole is open to every
//! module in the library rather than to the one that needs it. What seals the
//! arena instead is its own door: the only way in is a [`RecordDataRef`], so
//! what comes out was checked on the way in (`CLAUDE.md` §17).

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

/// A borrowed [`RecordData`]: a TYPE and octets that decode as it.
///
/// The same invariant as the owned form and the same way in — nothing here
/// constructs one from parts, so every `RecordDataRef` came from a
/// `RecordData` or from an [`RdataArena`] that was handed one.
///
/// Every read-only accessor lives here and [`RecordData`] delegates to it, so
/// the offset arithmetic that reads an SOA's SERIAL or an RRSIG's TYPE COVERED
/// exists once (`CLAUDE.md` §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordDataRef<'a> {
    rtype: Rtype,
    rdata: &'a [u8],
}

impl RecordData {
    /// Borrow the type and the octets.
    pub fn as_ref(&self) -> RecordDataRef<'_> {
        RecordDataRef {
            rtype: self.rtype,
            rdata: &self.rdata,
        }
    }

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
        self.as_ref().parse()
    }

    /// The SOA's SERIAL (RFC 1035 §3.3.13), or `None` if this is not an SOA.
    pub fn soa_serial(&self) -> Option<Serial> {
        self.as_ref().soa_serial()
    }

    /// The SOA's MINIMUM: the ceiling on how long a negative answer about this
    /// zone may be cached (RFC 2308 §3).
    pub fn soa_minimum(&self) -> Option<u32> {
        self.as_ref().soa_minimum()
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
        self.as_ref().rrsig_type_covered()
    }

    /// The NSEC3's iteration count and salt (RFC 5155 §3.2), or `None` if this
    /// is not an NSEC3.
    ///
    /// Both fields sit at a fixed offset ahead of the two variable-length ones,
    /// so reading them is arithmetic. Every negative answer over an NSEC3 zone
    /// asks the chain what it was built with, and [`RecordData::parse`] answers
    /// by copying out the salt, the next hashed owner and the type bitmap.
    pub fn nsec3_parameters(&self) -> Option<(u16, &[u8])> {
        self.as_ref().nsec3_parameters()
    }
}

impl<'a> RecordDataRef<'a> {
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// The octets: uncompressed wire-format RDATA, borrowed for as long as
    /// whatever holds them.
    pub fn bytes(&self) -> &'a [u8] {
        self.rdata
    }

    /// A copy that owns its octets.
    pub fn to_owned(&self) -> RecordData {
        RecordData {
            rtype: self.rtype,
            rdata: self.rdata.to_vec().into_boxed_slice(),
        }
    }

    /// Parse the octets into a typed [`ParsedRecord`] on demand.
    ///
    /// Records only cached and re-served never need this. Stored names are
    /// uncompressed, so the unpacker over the rdata itself suffices.
    pub fn parse(&self) -> Result<ParsedRecord, WireError> {
        let unpacker = DNameUnpacker::new(self.rdata);
        ParsedRecord::decode(self.rtype, self.rdata, &unpacker)
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
    pub fn rrsig_type_covered(&self) -> Option<Rtype> {
        if self.rtype != crate::record_types::RRSIG {
            return None;
        }
        let covered: [u8; 2] = self.rdata.get(..2)?.try_into().ok()?;
        Some(Rtype::new(u16::from_be_bytes(covered)))
    }

    /// The NSEC3's iteration count and salt (RFC 5155 §3.2), or `None` if this
    /// is not an NSEC3.
    pub fn nsec3_parameters(&self) -> Option<(u16, &'a [u8])> {
        if self.rtype != crate::record_types::NSEC3 {
            return None;
        }
        let iterations = u16::from_be_bytes(self.rdata.get(2..4)?.try_into().ok()?);
        let salt_len = *self.rdata.get(4)? as usize;
        Some((iterations, self.rdata.get(5..5 + salt_len)?))
    }

    /// The five 32-bit fields an SOA carries after MNAME and RNAME.
    ///
    /// [`RecordDataRef::parse`] answers the same questions and allocates a
    /// `String` for each of the two names on the way, both discarded by every
    /// caller that wanted a number. Every negative answer reads MINIMUM, which
    /// is the shape a random-subdomain flood generates.
    fn soa_scalars(&self) -> Option<&'a [u8; 20]> {
        if self.rtype != crate::record_types::SOA {
            return None;
        }
        let after_mname = skip_uncompressed_name(self.rdata)?;
        let after_rname = skip_uncompressed_name(after_mname)?;
        after_rname.get(..20)?.try_into().ok()
    }
}

impl PartialEq<RecordData> for RecordDataRef<'_> {
    fn eq(&self, other: &RecordData) -> bool {
        self.rtype == other.rtype && self.rdata == &*other.rdata
    }
}

impl PartialEq<RecordDataRef<'_>> for RecordData {
    fn eq(&self, other: &RecordDataRef<'_>) -> bool {
        other == self
    }
}

/// What an RRset's elements have in common: each can name its own RDATA.
///
/// The bound the DNSSEC code carries, and it used to be `Borrow<RecordData>` —
/// which cannot reach a [`RecordDataRef`], since there is no `RecordData` for it
/// to hand back a reference to. This is the same requirement stated as what the
/// callers actually do with it: a zone's records are spans into an arena
/// (`TODO.md` #71e) and an answer's are owned, and canonical form is built from
/// the TYPE and the octets either way.
pub trait AsRdata {
    fn rdata(&self) -> RecordDataRef<'_>;
}

impl AsRdata for RecordData {
    fn rdata(&self) -> RecordDataRef<'_> {
        self.as_ref()
    }
}

impl AsRdata for RecordDataRef<'_> {
    fn rdata(&self) -> RecordDataRef<'_> {
        *self
    }
}

/// Where one record's RDATA sits in an [`RdataArena`], and what TYPE it is.
///
/// The TYPE travels with the span rather than beside it, because the two
/// together are the invariant: octets that decode as *that* type. Two fields a
/// caller could pair up wrongly is the shape `CLAUDE.md` §17 opens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RdataSpan {
    off: u32,
    len: u16,
    rtype: Rtype,
}

impl RdataSpan {
    /// The TYPE, without needing the arena — the one question a caller can ask
    /// of a stored record without touching its octets, and the one a zone's
    /// index asks per record.
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }
}

/// Every record's RDATA in one allocation.
///
/// The store behind a zone (`TODO.md` #71e). A `Box<[u8]>` per record is a heap
/// allocation to make, one to copy and one to free per record; an arena is one
/// of each per zone, and a record shrinks to a span. Measured at a million
/// records: cloning them was 78 ms and 2 000 001 allocations, and the same
/// octets in an arena are 3.8 ms and two.
///
/// **Append-only, and spans belong to the arena that minted them.** Nothing
/// here removes or rewrites octets: a span handed back after a removal would
/// otherwise name something else. Reclaiming the octets of a record that has
/// gone means rebuilding the arena, which is the owner's business —
/// `rdns::zone::Zone` does it on a counter.
#[derive(Debug, Clone, Default)]
pub struct RdataArena {
    bytes: Vec<u8>,
}

impl RdataArena {
    pub fn new() -> RdataArena {
        RdataArena::default()
    }

    /// Copy `data`'s octets in and give back where they went.
    ///
    /// The only way to make an [`RdataSpan`], which is what lets [`get`] be
    /// infallible and unchecked: what comes out was a [`RecordDataRef`] on the
    /// way in.
    ///
    /// [`get`]: RdataArena::get
    pub fn push(&mut self, data: RecordDataRef<'_>) -> RdataSpan {
        let off = self.bytes.len();
        self.bytes.extend_from_slice(data.rdata);
        RdataSpan {
            // RDLENGTH is 16 bits, so `len` cannot overflow; `off` is checked
            // because an arena past 4 GiB is reachable on a zone big enough to
            // exhaust the machine and a silent truncation there is §2's "`as`
            // is a bug until proven otherwise" with a wrong answer at the end
            // of it.
            off: u32::try_from(off).expect("an RDATA arena under 4 GiB"),
            len: data.rdata.len() as u16,
            rtype: data.rtype,
        }
    }

    /// The RDATA at `at`.
    pub fn get(&self, at: RdataSpan) -> RecordDataRef<'_> {
        let off = at.off as usize;
        RecordDataRef {
            rtype: at.rtype,
            rdata: &self.bytes[off..off + at.len as usize],
        }
    }

    /// Octets held, for a caller sizing a rebuild.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn reserve(&mut self, octets: usize) {
        self.bytes.reserve(octets);
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::name::nm;
    use crate::record_types as rt;

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
                mname: nm(mname),
                rname: nm(rname),
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
                signer_name: nm("example.com."),
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

    #[test]
    fn test_record_type_code_standard() {
        use std::net::Ipv4Addr;

        let a_record =
            RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap();
        assert_eq!(a_record.rtype(), rt::A);

        let aaaa_record =
            RecordData::from_parsed(&ParsedRecord::AAAA("::1".parse().unwrap())).unwrap();
        assert_eq!(aaaa_record.rtype(), rt::AAAA);
    }

    #[test]
    fn test_record_type_code_dnssec() {
        let dnskey = RecordData::from_parsed(&ParsedRecord::DNSKEY {
            rtype: crate::record_types::DNSKEY,
            flags: 0x0100,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3],
        })
        .unwrap();
        assert_eq!(dnskey.rtype(), rt::DNSKEY);

        let ds = RecordData::from_parsed(&ParsedRecord::DS {
            rtype: crate::record_types::DS,
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: vec![1, 2, 3],
        })
        .unwrap();
        assert_eq!(ds.rtype(), rt::DS);
    }

    #[test]
    fn test_record_type_code_unknown() {
        let unknown = RecordData::from_parsed(&ParsedRecord::Unknown(Rtype::new(99))).unwrap();
        assert_eq!(unknown.rtype(), Rtype::new(99));
    }
}
