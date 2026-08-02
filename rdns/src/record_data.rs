//! [`RecordData`] and nothing else, so that its two fields can be private *to
//! this file*.
//!
//! **A module for one struct is the point, not an accident** (`TODO.md` #14c).
//! `RecordData` used to live in `lib.rs` with `pub` fields, and fourteen sites
//! across the crate built one directly: `RecordData { rtype: A, rdata:
//! <seventeen bytes> }` was a value nothing objected to until something tried to
//! read it, which is why [`RecordData::parse`] returns a `Result` at all.
//! Marking the fields private in the crate root would have changed nothing —
//! private there means visible to the crate root *and every descendant module*,
//! which is the whole library. A field is only sealed against the module it is
//! declared in, so the type had to move somewhere small.
//!
//! The three doors are [`RecordData::from_wire`] (bytes off the wire, names
//! decompressed), [`RecordData::from_parsed`] (a typed record encoded) and
//! [`RecordData::new`] (bytes some other code produced, checked). All three
//! establish the same thing: the bytes decode as their TYPE.

use crate::dname::DNameUnpacker;
use crate::error::WireError;
use crate::{ParsedRecord, Rtype};

/// A record's data, stored as **uncompressed wire-format bytes**.
///
/// This is the compact, allocation-light form we keep resident (in caches,
/// zones, and messages). It is 24 bytes regardless of record type, versus the
/// ~96-byte typed enum it replaces, because the large/rare DNSSEC and SOA
/// payloads no longer sit inline in every record.
///
/// Any domain names embedded in the data are expanded to their full,
/// uncompressed form when the record is read off the wire (see
/// [`RecordData::from_wire`]), so the bytes are self-contained: they can be
/// re-parsed with [`RecordData::parse`] or re-serialized without needing the
/// original message for compression-pointer resolution.
///
/// **The fields are private, and that is the invariant.** The bytes decode as
/// their TYPE, because the three constructors are the only way in and each
/// establishes it. Sealing them only *means* anything now that `rtype` is an
/// [`Rtype`] rather than a `u16` anyone can invent (`TODO.md` #13c), which is
/// why this was not worth doing before.
///
/// **What the invariant does not say**, so it is not read for more than it is:
///
/// - **A type with no decoder here is stored verbatim** (RFC 3597 §5) and
///   checked only for being storable, because there is nothing to check it
///   against. So does an RDLENGTH of zero, which RFC 2136 §2.4 and §2.5 use to
///   mean "this type, no value" — a record that is a specifier rather than data.
///   That case is where the invariant *would* have been wrong, and finding it is
///   what this change was worth: see the commit that fixed
///   `ParsedRecord::decode` for it.
/// - **[`RecordData::parse`] still returns a `Result`.** Making it infallible
///   would mean proving that every `ParsedRecord` re-encodes to bytes that
///   decode again, which is a round-trip property nothing here establishes. The
///   `Result` is now "this should not happen" rather than "a caller may have
///   built nonsense", which is a smaller claim than removing it would be.
/// - **Nothing bounds the length.** RDLENGTH is 16 bits, and a longer RDATA
///   fails when the message it is in is serialized rather than here. Left alone
///   deliberately: the check exists where the limit exists, and duplicating it
///   is §7's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordData {
    /// The RR TYPE code (e.g. 1 = A, 28 = AAAA).
    rtype: Rtype,
    /// Uncompressed wire-format RDATA.
    rdata: Box<[u8]>,
}

impl RecordData {
    /// The RR TYPE code of this record.
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// The stored bytes: uncompressed wire-format RDATA.
    ///
    /// Read-only on purpose. A `&mut` to these would be a way to make the
    /// contents disagree with `rtype` again, which is the thing this type
    /// stopped allowing.
    pub fn bytes(&self) -> &[u8] {
        &self.rdata
    }

    /// Read a record's RDATA off the wire and store it compactly.
    ///
    /// `unpacker` is used to follow any compression pointers against the full
    /// message; the result is re-encoded without compression so the stored
    /// bytes are self-contained. Types we don't parse are stored verbatim
    /// (RFC 3597), which — unlike the old typed enum — preserves their bytes.
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
    /// DNSKEY or an NSEC3PARAM, a zone file's RFC 3597 `\#` escape, a test.
    ///
    /// Checked, not trusted: the bytes must decode as `rtype`. A type with no
    /// decoder here reads back as [`ParsedRecord::Unknown`] rather than failing,
    /// so this only ever rejects a *known* type whose bytes are not that type —
    /// which is exactly the case the public fields used to let through.
    ///
    /// The names inside must already be uncompressed, since the stored form is
    /// self-contained by definition and there is no message here to resolve a
    /// pointer against.
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
    /// Records that are only cached and re-served never need this, which is the
    /// whole point of storing raw bytes. Stored names are uncompressed, so no
    /// message context is required — the decoder is handed an unpacker over the
    /// rdata itself, which by construction contains no pointers.
    pub fn parse(&self) -> Result<ParsedRecord, WireError> {
        let unpacker = DNameUnpacker::new(&self.rdata);
        ParsedRecord::decode(self.rtype, &self.rdata, &unpacker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::record_types as rt;

    /// The value the public fields used to allow: a TYPE that says A, and bytes
    /// that are not an address.
    ///
    /// **Not a failing-first test, and it cannot be one** (`CLAUDE.md` §1). The
    /// old code let you *write* `RecordData { rtype: A, rdata: <seventeen bytes>
    /// }`, so the thing this change prevents is a line that no longer compiles,
    /// and a test cannot contain it. What is testable is the constructor that
    /// replaced it, which is what this is.
    #[test]
    fn rdata_that_is_not_its_type_is_refused() {
        assert!(
            RecordData::new(rt::A, vec![0u8; 17]).is_err(),
            "seventeen bytes are not an IPv4 address"
        );
        assert!(RecordData::new(rt::A, vec![192, 0, 2, 1]).is_ok());
    }

    /// Two cases the invariant deliberately does not cover, because the wire has
    /// them: a type with no decoder here (RFC 3597 §5), and an RDLENGTH of zero,
    /// which RFC 2136 §2.4 and §2.5 use to mean "this type, no value".
    ///
    /// The second is the one that mattered. Assuming it away is what made a legal
    /// UPDATE unparseable, and asserting it here is what stops the assumption
    /// coming back through this door instead.
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

    /// What sealing bought, stated as the property rather than as a refusal:
    /// anything that exists parses, so `parse`'s `Result` is now "this should not
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
