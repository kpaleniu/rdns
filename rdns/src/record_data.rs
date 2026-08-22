//! [`RecordData`] and nothing else.
//!
//! A field is sealed only against the module declaring it — private in the crate
//! root means visible to the whole library — so a type whose fields must be
//! sealed against its own crate needs a file of its own.

use crate::dname::DNameUnpacker;
use crate::error::WireError;
use crate::{ParsedRecord, Rtype};

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
