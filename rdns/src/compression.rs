//! Domain-name compression for message output (RFC 1035 §4.1.4).
//!
//! [`NameCompressor`] is scoped to one serialization pass; offsets are
//! meaningless across messages. Owner names are always compressed; names inside
//! RDATA only for the types RFC 1035 defines, since a receiver cannot find names
//! in a type it does not know (RFC 3597 §4, RFC 4034).

use crate::dname::{
    dname_from_bytes, write_bytes, write_label, DNameUnpacker, POINTER_MASK, POINTER_TAG,
};
use crate::error::WireError;
use crate::utils::record_types as rt;
use crate::Rtype;
use std::collections::HashMap;

/// Per-message table of name suffixes already written, and where.
#[derive(Debug, Default)]
pub struct NameCompressor {
    /// Every name that contributed a suffix, concatenated, in the case written.
    ///
    /// Ranges into one arena: an owned `String` per suffix is quadratic in the
    /// shared tail. Not lowercased — [`NameCompressor::lookup`] compares
    /// case-insensitively, so folding here would only add a fold on the needle.
    arena: String,
    /// Suffixes of those names, as ranges into `arena` with the offset each was
    /// first written at. Never holds two entries for the same suffix.
    seen: Vec<Suffix>,
    /// Folded hash of a suffix to its entry in `seen`, built only once `seen`
    /// outgrows [`SCAN_LIMIT`] and empty before that: a `HashMap` allocates on
    /// its first insert, and a one-record response is held to three allocations.
    ///
    /// A hash collision drops the newer suffix rather than chaining it, so the
    /// value is one index. Compression is optional (RFC 1035 §4.1.4), so a
    /// collision costs a few bytes; the older entry kept has the lower offset.
    index: HashMap<u64, u32>,
}

/// How many suffixes the linear scan stays cheaper than an index for.
///
/// Measured through `to_bytes_within_buf`, not on the compressor alone: at 60
/// names scan and index tie at 5.55 µs, at a 400-record envelope the scan is
/// 130.7 µs against 42.8. A threshold of 32 made the 60-name bench 26% slower.
const SCAN_LIMIT: usize = 128;

#[derive(Debug, Clone, Copy)]
struct Suffix {
    /// Byte range into [`NameCompressor::arena`].
    start: u32,
    end: u32,
    /// Where this suffix begins in the message being written.
    offset: u16,
}

impl NameCompressor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget everything, keeping the room it was kept in.
    ///
    /// Offsets are meaningless across messages, so a compressor carried from one
    /// serialization to the next must be emptied between them or it writes
    /// pointers into a message that is no longer there. That is why
    /// [`crate::DnsMessage::to_bytes_with`] clears at the *start* of a
    /// serialization rather than leaving it to the caller: the truncation retry
    /// serializes twice through one call, and a rule the caller has to remember
    /// would be wrong on the path least likely to be exercised.
    pub fn clear(&mut self) {
        self.arena.clear();
        self.seen.clear();
        self.index.clear();
    }

    /// Write `name` at `pos`, using a pointer to the longest suffix already
    /// present in the message. Returns the new position.
    pub fn write_name(
        &mut self,
        name: &str,
        buf: &mut [u8],
        pos: usize,
    ) -> Result<usize, WireError> {
        let trimmed = name.strip_suffix('.').unwrap_or(name);
        if trimmed.is_empty() {
            // The root is one zero octet; a pointer to it would cost two.
            return write_bytes(buf, pos, &[0]);
        }

        // Longest-first. Each needle is a slice of the caller's own name, so a
        // lookup allocates nothing.
        let mut matched = None;
        for (i, start) in label_starts(trimmed).enumerate() {
            if let Some(target) = self.lookup(&trimmed[start..]) {
                matched = Some((i, target));
                break;
            }
        }

        // The labels before the match are written literally here, so record
        // where each lands as a target for a later name. From the match on is
        // already recorded; `fresh == 0` contributes nothing, not even a copy.
        let fresh = matched.map_or_else(|| label_starts(trimmed).count(), |(i, _)| i);
        if fresh > 0 {
            let first_new = self.seen.len();
            let base = self.arena.len();
            self.arena.push_str(trimmed);
            let end = self.arena.len();
            for start in label_starts(trimmed).take(fresh) {
                // A label costs its bytes plus a length prefix on the wire and
                // its bytes plus a `.` in the text, so the text offset is the
                // wire offset.
                let suffix_pos = pos + start;
                // A pointer field is 14 bits; a suffix past that is unreachable.
                if suffix_pos <= POINTER_MASK as usize {
                    self.seen.push(Suffix {
                        start: (base + start) as u32,
                        end: end as u32,
                        offset: suffix_pos as u16,
                    });
                }
            }
            self.index_from(first_new);
        }

        // Split `trimmed` rather than the arena so the name goes out in the case
        // it was given: RFC 4343 folds case for comparison only.
        let mut out = pos;
        for label in trimmed.split('.').take(fresh) {
            out = write_label(buf, out, label)?;
        }
        match matched {
            Some((_, target)) => write_bytes(buf, out, &(POINTER_TAG | target).to_be_bytes()),
            None => write_bytes(buf, out, &[0]),
        }
    }

    /// The offset a suffix was first written at, if it has been.
    ///
    /// Case-insensitive over ASCII only (RFC 4343): `str::to_lowercase` folds
    /// U+212A KELVIN SIGN to `k`, and two names that differ on the wire must not
    /// compress against each other. [`folded_hash`] folds identically or the
    /// index would file a suffix where nothing looks for it.
    ///
    /// Both arms compare against the arena, so the index is only an accelerator
    /// and a collision cannot become a pointer to the wrong name.
    ///
    /// The comparison is written out twice rather than shared: factoring it into
    /// a method or a closure cost the scan 51 -> 75 ns per name.
    fn lookup(&self, needle: &str) -> Option<u16> {
        if self.index.is_empty() {
            let arena = self.arena.as_str();
            return self
                .seen
                .iter()
                .find(|s| arena[s.start as usize..s.end as usize].eq_ignore_ascii_case(needle))
                .map(|s| s.offset);
        }
        let entry = self.seen[*self.index.get(&folded_hash(needle))? as usize];
        self.arena[entry.start as usize..entry.end as usize]
            .eq_ignore_ascii_case(needle)
            .then_some(entry.offset)
    }

    /// Note the entries from `first` on in the index, building it first if the
    /// table has just outgrown the scan.
    fn index_from(&mut self, first: usize) {
        if self.index.is_empty() {
            if self.seen.len() <= SCAN_LIMIT {
                return;
            }
            // The whole table: entries from before the threshold were only ever
            // reachable by the scan.
            for i in 0..self.seen.len() {
                self.note(i);
            }
            return;
        }
        for i in first..self.seen.len() {
            self.note(i);
        }
    }

    /// Index one entry of `seen`, keeping whichever is already there.
    fn note(&mut self, i: usize) {
        let entry = self.seen[i];
        let hash = folded_hash(&self.arena[entry.start as usize..entry.end as usize]);
        self.index.entry(hash).or_insert(i as u32);
    }

    /// Write a record's RDATA at `pos`, compressing embedded names for the
    /// record types where that is legal. Returns the new position.
    ///
    /// `rdata` is the stored, uncompressed wire form, so the names inside it can
    /// be read without message context.
    pub fn write_rdata(
        &mut self,
        rtype: Rtype,
        rdata: &[u8],
        buf: &mut [u8],
        pos: usize,
    ) -> Result<usize, WireError> {
        match rtype {
            // NS, CNAME, PTR: the RDATA is exactly one domain name.
            rt::NS | rt::CNAME | rt::PTR => {
                let (name, rest) = read_name(rdata)?;
                let pos = self.write_name(&name, buf, pos)?;
                write_bytes(buf, pos, rest)
            }
            // SOA: MNAME, RNAME, then five 32-bit fields.
            rt::SOA => {
                let (mname, rest) = read_name(rdata)?;
                let (rname, rest) = read_name(rest)?;
                let pos = self.write_name(&mname, buf, pos)?;
                let pos = self.write_name(&rname, buf, pos)?;
                write_bytes(buf, pos, rest)
            }
            // MX: 16-bit preference, then EXCHANGE.
            rt::MX => {
                if rdata.len() < 2 {
                    return Err(WireError::Truncated {
                        what: "MX RDATA",
                        need: 2,
                        have: rdata.len(),
                    });
                }
                let pos = write_bytes(buf, pos, &rdata[..2])?;
                let (exchange, rest) = read_name(&rdata[2..])?;
                let pos = self.write_name(&exchange, buf, pos)?;
                write_bytes(buf, pos, rest)
            }
            // Everything else — including SRV, DNAME and the DNSSEC types —
            // goes out byte-for-byte (RFC 3597 §4, RFC 4034 §3.1.7/§4.1.1).
            _ => write_bytes(buf, pos, rdata),
        }
    }
}

/// Where each label of `name` begins: byte 0, then one past every `.`.
///
/// An iterator, not a `Vec`: collecting is an allocation per name written, and
/// the two passes are over at most 255 bytes. Splits on every `.` as
/// `str::split` does, so an empty label reaches `write_label` and is rejected
/// there.
fn label_starts(name: &str) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(0).chain(
        name.bytes()
            .enumerate()
            .filter(|(_, byte)| *byte == b'.')
            .map(|(i, _)| i + 1),
    )
}

/// FNV-1a over the ASCII-folded bytes (RFC 4343), folding exactly as [`lookup`]
/// compares.
///
/// Not DoS-resistant on purpose: a collision drops a compression target, so a
/// chosen name buys a few extra bytes in one message and nothing else.
///
/// [`lookup`]: NameCompressor::lookup
fn folded_hash(name: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    for byte in name.bytes() {
        hash ^= u64::from(byte.to_ascii_lowercase());
        hash = u64::wrapping_mul(hash, 0x0000_0100_0000_01b3);
    }
    hash
}

/// Read one uncompressed name from the head of `data`, returning it with the
/// bytes that follow.
fn read_name(data: &[u8]) -> Result<(String, &[u8]), WireError> {
    // Stored RDATA contains no pointers by construction, so the unpacker only
    // ever walks the bytes it is given.
    let unpacker = DNameUnpacker::new(data);
    dname_from_bytes(data, &unpacker)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cost per name written does not grow with the size of the message: a
    /// ratio between 25 names and 800, so it is machine-independent.
    ///
    /// The true ratio is ~2 (53 ns to 112, the residue being cache, not the
    /// table) and an unindexed scan's is 13, so 5 discriminates.
    #[test]
    fn writing_a_name_costs_the_same_however_many_the_message_holds() {
        let per_name = |count: usize| {
            let names: Vec<String> = (0..count).map(|i| format!("h{i}.e.com.")).collect();
            let mut buf = vec![0u8; 0x4000];
            // Best of three: a lost timeslice can only make a run look slower.
            (0..3)
                .map(|_| {
                    let start = std::time::Instant::now();
                    for _ in 0..20 {
                        let mut c = NameCompressor::new();
                        let mut pos = 12;
                        for name in &names {
                            pos = c.write_name(name, &mut buf, pos).expect("fits");
                        }
                        // Every name here must be a compression target, so none
                        // may land past the 14-bit pointer range.
                        assert!(pos < POINTER_MASK as usize);
                    }
                    start.elapsed() / (20 * count) as u32
                })
                .min()
                .expect("three runs")
        };

        let few = per_name(25);
        let many = per_name(800);
        assert!(
            many < few * 5,
            "800 names cost {many:?} each against {few:?} for 25: \
             the cost is growing with the size of the message"
        );
    }

    /// A suffix recorded before the table outgrew the scan is still found after.
    ///
    /// Missing one costs bytes and not correctness, so nothing else would catch
    /// it.
    #[test]
    fn a_suffix_from_before_the_index_is_still_found_after_it() {
        let mut c = NameCompressor::new();
        let mut buf = vec![0u8; 0x4000];

        // `example.com.` lands at 18: 12 for the header plus `5first`.
        let mut pos = c.write_name("first.example.com.", &mut buf, 12).unwrap();
        for i in 0..SCAN_LIMIT + 8 {
            pos = c
                .write_name(&format!("h{i}.other.test."), &mut buf, pos)
                .unwrap();
        }
        assert!(!c.index.is_empty(), "the table outgrew the scan");

        let end = c.write_name("second.example.com.", &mut buf, pos).unwrap();
        assert_eq!(
            &buf[pos..end],
            &[6, b's', b'e', b'c', b'o', b'n', b'd', 0xc0, 18]
        );
    }

    /// The index folds case exactly as the comparison does, and no further:
    /// `k` and U+212A KELVIN SIGN are different names (RFC 4343).
    #[test]
    fn the_index_folds_the_same_ascii_the_comparison_does() {
        assert_eq!(folded_hash("Example.COM"), folded_hash("example.com"));
        assert_ne!(
            folded_hash("\u{212A}.example.com"),
            folded_hash("k.example.com")
        );
    }

    /// Names are written in full the first time and pointed at after that.
    #[test]
    fn test_repeated_name_becomes_a_pointer() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 128];

        let pos = c.write_name("example.com.", &mut buf, 12).unwrap();
        assert_eq!(pos, 12 + 13, "13 bytes: 7example3com0");

        let end = c.write_name("example.com.", &mut buf, pos).unwrap();
        assert_eq!(end - pos, 2, "the repeat is a bare pointer");
        assert_eq!(&buf[pos..end], &[0xc0, 12]);
    }

    /// A shared suffix compresses even when the leading labels differ.
    #[test]
    fn test_partial_suffix_match() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 128];

        let pos = c.write_name("example.com.", &mut buf, 12).unwrap();
        let end = c.write_name("www.example.com.", &mut buf, pos).unwrap();

        // "3www" written literally, then a pointer to example.com at 12.
        assert_eq!(&buf[pos..end], &[3, b'w', b'w', b'w', 0xc0, 12]);
    }

    /// The suffixes written as part of a longer name are targets themselves.
    #[test]
    fn test_suffix_of_earlier_name_is_a_target() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 128];

        // www.example.com. at 12 => "com." starts at 12 + 4 + 8 = 24.
        let pos = c.write_name("www.example.com.", &mut buf, 12).unwrap();
        let end = c.write_name("com.", &mut buf, pos).unwrap();

        assert_eq!(&buf[pos..end], &[0xc0, 24]);
    }

    /// Comparison is case-insensitive (RFC 4343), but the bytes first written
    /// keep the case they were given.
    #[test]
    fn test_case_insensitive_match() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 128];

        let pos = c.write_name("Example.COM.", &mut buf, 12).unwrap();
        assert_eq!(&buf[12..20], b"\x07Example");

        let end = c.write_name("example.com.", &mut buf, pos).unwrap();
        assert_eq!(&buf[pos..end], &[0xc0, 12]);
    }

    /// The root is a single zero octet, never a pointer.
    #[test]
    fn test_root_is_never_compressed() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 16];

        let pos = c.write_name(".", &mut buf, 0).unwrap();
        assert_eq!(&buf[..pos], &[0]);

        let end = c.write_name(".", &mut buf, pos).unwrap();
        assert_eq!(&buf[pos..end], &[0]);
    }

    /// A name's suffixes share one arena copy: an owned `String` per suffix is
    /// quadratic in the label count. Asserted on bytes held, which is exact.
    #[test]
    fn a_names_suffixes_are_stored_once_between_them_not_once_each() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 256];

        let name = "a.b.c.d.example.com.";
        c.write_name(name, &mut buf, 12).unwrap();

        assert_eq!(c.seen.len(), 6, "six suffixes, one per label");
        assert_eq!(
            c.arena.len(),
            name.len() - 1,
            "and one copy of the name between them, not one per suffix"
        );

        // A second name sharing five of those labels adds only its own label.
        c.write_name("z.b.c.d.example.com.", &mut buf, 40).unwrap();
        assert_eq!(c.seen.len(), 7);
        assert_eq!(
            c.arena.len(),
            (name.len() - 1) * 2,
            "the shared tail is not copied per suffix, only per name"
        );
    }

    /// A name already known in full adds nothing, and finding that out copies
    /// nothing: the lookup compares against the caller's own bytes.
    #[test]
    fn a_fully_matched_name_leaves_the_table_and_the_arena_untouched() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 256];

        let pos = c.write_name("www.example.com.", &mut buf, 12).unwrap();
        let (suffixes, bytes) = (c.seen.len(), c.arena.len());

        let mut at = pos;
        for _ in 0..20 {
            at = c.write_name("WWW.Example.Com.", &mut buf, at).unwrap();
        }
        assert_eq!(c.seen.len(), suffixes, "no new suffixes");
        assert_eq!(c.arena.len(), bytes, "and no new bytes");
        assert_eq!(at - pos, 40, "twenty two-byte pointers");
    }

    /// A name past the 14-bit pointer range is written, but never becomes a
    /// compression target.
    #[test]
    fn test_offset_beyond_pointer_range_is_not_a_target() {
        let mut c = NameCompressor::new();
        let mut buf = vec![0u8; 0x5000];

        let far = 0x4000;
        let pos = c.write_name("example.com.", &mut buf, far).unwrap();
        assert_eq!(pos - far, 13);

        // Nothing reachable to point at, so the second copy is written in full.
        let end = c.write_name("example.com.", &mut buf, pos).unwrap();
        assert_eq!(end - pos, 13);
    }

    /// RDATA of a type RFC 1035 predates is compressed; anything else is not.
    #[test]
    fn test_rdata_compression_is_type_gated() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 256];

        let pos = c.write_name("example.com.", &mut buf, 12).unwrap();

        // NS RDATA: one name, sharing the whole suffix -> "2ns" + pointer.
        let ns = crate::dname::dname_to_bytes("ns.example.com.").unwrap();
        let end = c.write_rdata(rt::NS, &ns, &mut buf, pos).unwrap();
        assert_eq!(&buf[pos..end], &[2, b'n', b's', 0xc0, 12]);

        // SRV (33) is not on the list: byte-for-byte, pointers or not.
        let srv_start = end;
        let mut srv = vec![0, 10, 0, 20, 0, 80];
        srv.extend_from_slice(&crate::dname::dname_to_bytes("ns.example.com.").unwrap());
        let end = c
            .write_rdata(Rtype::new(33), &srv, &mut buf, srv_start)
            .unwrap();
        assert_eq!(&buf[srv_start..end], &srv[..]);
    }

    /// MX keeps its preference field and compresses only the exchange.
    #[test]
    fn test_mx_rdata_compression() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 256];

        let pos = c.write_name("example.com.", &mut buf, 12).unwrap();

        let mut mx = vec![0, 10];
        mx.extend_from_slice(&crate::dname::dname_to_bytes("mail.example.com.").unwrap());
        let end = c.write_rdata(rt::MX, &mx, &mut buf, pos).unwrap();

        assert_eq!(
            &buf[pos..end],
            &[0, 10, 4, b'm', b'a', b'i', b'l', 0xc0, 12]
        );
    }

    /// SOA compresses both of its names and leaves the 20 bytes of counters.
    #[test]
    fn test_soa_rdata_compression() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 256];

        let pos = c.write_name("example.com.", &mut buf, 12).unwrap();

        let mut soa = crate::dname::dname_to_bytes("ns.example.com.").unwrap();
        soa.extend_from_slice(&crate::dname::dname_to_bytes("admin.example.com.").unwrap());
        soa.extend_from_slice(&[9u8; 20]);
        let end = c.write_rdata(rt::SOA, &soa, &mut buf, pos).unwrap();

        let expected: Vec<u8> = [
            2, b'n', b's', 0xc0, 12, 5, b'a', b'd', b'm', b'i', b'n', 0xc0, 12,
        ]
        .into_iter()
        .chain([9u8; 20])
        .collect();
        assert_eq!(&buf[pos..end], &expected[..]);
    }

    /// Overflowing the output buffer is an error, not a silent short write.
    #[test]
    fn test_buffer_overflow_is_an_error() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 8];

        let result = c.write_name("example.com.", &mut buf, 0);
        assert!(result.is_err());
    }
}
