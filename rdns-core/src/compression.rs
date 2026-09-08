//! Domain-name compression for message output (RFC 1035 §4.1.4).
//!
//! [`NameCompressor`] is scoped to one serialization pass; offsets are
//! meaningless across messages. Owner names are always compressed; names inside
//! RDATA only for the types RFC 1035 defines, since a receiver cannot find names
//! in a type it does not know (RFC 3597 §4, RFC 4034).

use crate::dname::{write_bytes, POINTER_MASK, POINTER_TAG};
use crate::error::WireError;
use crate::utils::record_types as rt;
use crate::{Name, NameRef, Rtype};
use std::collections::HashMap;

/// Per-message table of name suffixes already written, and where.
#[derive(Debug, Default)]
pub struct NameCompressor {
    /// Every name that contributed a suffix, concatenated, in the case written.
    ///
    /// Ranges into one arena: an owned `String` per suffix is quadratic in the
    /// shared tail. Not lowercased — [`NameCompressor::lookup`] compares
    /// case-insensitively, so folding here would only add a fold on the needle.
    arena: Vec<u8>,
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

    /// Forget every suffix at or past `at`, keeping the rest.
    ///
    /// For a writer that rewinds the output buffer — an answer that overflowed
    /// the size limit drops back to the question and sets TC. Whatever was
    /// recorded past the rewind point now points at bytes that are about to be
    /// overwritten, which is silent wire corruption on the least-tested path.
    ///
    /// `seen` is ordered by offset: a name's suffixes are recorded left to
    /// right, and `pos` only ever moves forward.
    pub fn rewind(&mut self, at: usize) {
        let keep = self.seen.partition_point(|s| (s.offset as usize) < at);
        if keep == self.seen.len() {
            return;
        }
        self.seen.truncate(keep);
        // The index holds positions in `seen`, so the entries pointing past its
        // new end go with them. The arena is left alone: it is bytes, and the
        // surviving entries' ranges are still theirs.
        self.index.retain(|_, i| (*i as usize) < keep);
    }

    /// Write `name` at `pos`, using a pointer to the longest suffix already
    /// present in the message. Returns the new position.
    ///
    /// A suffix of a wire-form name at a label boundary *is* a name, so the
    /// candidates are exactly [`NameRef::ancestors`] and the offset of each is
    /// the difference in length. That is what the text form had to reconstruct
    /// by splitting on `.` and counting, and why the two offsets — text and
    /// wire — needed a comment explaining that they happened to coincide.
    pub fn write_name(
        &mut self,
        name: NameRef<'_>,
        buf: &mut [u8],
        pos: usize,
    ) -> Result<usize, WireError> {
        let wire = name.as_wire();
        if name.is_root() {
            // One zero octet; a pointer to it would cost two.
            return write_bytes(buf, pos, &[0]);
        }

        // Longest-first. Each needle is a slice of the caller's own name, so a
        // lookup allocates nothing.
        let mut matched = None;
        for ancestor in name.ancestors() {
            if ancestor.is_root() {
                break;
            }
            let start = wire.len() - ancestor.as_wire().len();
            if let Some(target) = self.lookup(ancestor.as_wire()) {
                matched = Some((start, target));
                break;
            }
        }

        // Everything before the match is written literally here, so record
        // where each of those suffixes lands as a target for a later name. From
        // the match on is already recorded; a match at 0 contributes nothing,
        // not even a copy. With no match the whole name goes out except its
        // root octet, which is written below as the terminator.
        let fresh_end = matched.map_or(wire.len() - 1, |(start, _)| start);
        if fresh_end > 0 {
            let first_new = self.seen.len();
            let base = self.arena.len();
            self.arena.extend_from_slice(wire);
            let end = self.arena.len();
            for ancestor in name.ancestors() {
                let start = wire.len() - ancestor.as_wire().len();
                if start >= fresh_end {
                    break;
                }
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

        // The caller's own octets, so the name goes out in the case it was
        // given: RFC 4343 folds case for comparison only.
        let out = write_bytes(buf, pos, &wire[..fresh_end])?;
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
    fn lookup(&self, needle: &[u8]) -> Option<u16> {
        if self.index.is_empty() {
            let arena = self.arena.as_slice();
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
                let (name, rest) = Name::from_wire(rdata)?;
                let pos = self.write_name(name.as_ref(), buf, pos)?;
                write_bytes(buf, pos, rest)
            }
            // SOA: MNAME, RNAME, then five 32-bit fields.
            rt::SOA => {
                let (mname, rest) = Name::from_wire(rdata)?;
                let (rname, rest) = Name::from_wire(rest)?;
                let pos = self.write_name(mname.as_ref(), buf, pos)?;
                let pos = self.write_name(rname.as_ref(), buf, pos)?;
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
                let (exchange, rest) = Name::from_wire(&rdata[2..])?;
                let pos = self.write_name(exchange.as_ref(), buf, pos)?;
                write_bytes(buf, pos, rest)
            }
            // Everything else — including SRV, DNAME, SVCB/HTTPS and the
            // DNSSEC types — goes out byte-for-byte (RFC 3597 §4,
            // RFC 4034 §3.1.7/§4.1.1). Two of them say so themselves: a DNAME's
            // <target> "MUST NOT be sent out in compressed form"
            // (RFC 6672 §2.5), and SVCB's is "the uncompressed, fully qualified
            // TargetName" (RFC 9460 §2.2). That is why neither is in the arm
            // above with the other single-name RDATAs.
            _ => write_bytes(buf, pos, rdata),
        }
    }
}

/// FNV-1a over the ASCII-folded bytes (RFC 4343), folding exactly as [`lookup`]
/// compares.
///
/// Not DoS-resistant on purpose: a collision drops a compression target, so a
/// chosen name buys a few extra bytes in one message and nothing else.
///
/// [`lookup`]: NameCompressor::lookup
fn folded_hash(name: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325;
    for &byte in name {
        hash ^= u64::from(byte.to_ascii_lowercase());
        hash = u64::wrapping_mul(hash, 0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::name::nm;

    /// Cost per name written does not grow with the size of the message: a
    /// ratio between 25 names and 800, so it is machine-independent.
    ///
    /// The true ratio is ~2 (53 ns to 112, the residue being cache, not the
    /// table) and an unindexed scan's is 13, so 5 discriminates.
    #[test]
    fn writing_a_name_costs_the_same_however_many_the_message_holds() {
        let per_name = |count: usize| {
            let names: Vec<Name> = (0..count).map(|i| nm(&format!("h{i}.e.com."))).collect();
            let mut buf = vec![0u8; 0x4000];
            // Best of three: a lost timeslice can only make a run look slower.
            (0..3)
                .map(|_| {
                    let start = std::time::Instant::now();
                    for _ in 0..20 {
                        let mut c = NameCompressor::new();
                        let mut pos = 12;
                        for name in &names {
                            pos = c.write_name(name.as_ref(), &mut buf, pos).expect("fits");
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

    /// A rewind forgets exactly the suffixes past the mark, and the ones before
    /// it still compress — including through the index, which holds positions in
    /// the table that has just been cut.
    #[test]
    fn a_rewind_forgets_what_was_written_past_it() {
        let mut c = NameCompressor::new();
        let mut buf = vec![0u8; 0x4000];

        // `example.com.` lands at 18: 12 for the header plus `5first`.
        let mark = c
            .write_name(nm("first.example.com.").as_ref(), &mut buf, 12)
            .unwrap();
        let mut pos = mark;
        for i in 0..SCAN_LIMIT + 8 {
            pos = c
                .write_name(nm(&format!("h{i}.other.test.")).as_ref(), &mut buf, pos)
                .unwrap();
        }
        assert!(!c.index.is_empty(), "the table outgrew the scan");

        c.rewind(mark);
        // Written again at the rewind point: the suffix from before it is still a
        // target, and `other.test.` is not one any more.
        let end = c
            .write_name(nm("second.example.com.").as_ref(), &mut buf, mark)
            .unwrap();
        assert_eq!(
            &buf[mark..end],
            &[6, b's', b'e', b'c', b'o', b'n', b'd', 0xc0, 18]
        );
        let after = c
            .write_name(nm("h0.other.test.").as_ref(), &mut buf, end)
            .unwrap();
        assert_eq!(after - end, 15, "written in full, not pointed at");
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
        let mut pos = c
            .write_name(nm("first.example.com.").as_ref(), &mut buf, 12)
            .unwrap();
        for i in 0..SCAN_LIMIT + 8 {
            pos = c
                .write_name(nm(&format!("h{i}.other.test.")).as_ref(), &mut buf, pos)
                .unwrap();
        }
        assert!(!c.index.is_empty(), "the table outgrew the scan");

        let end = c
            .write_name(nm("second.example.com.").as_ref(), &mut buf, pos)
            .unwrap();
        assert_eq!(
            &buf[pos..end],
            &[6, b's', b'e', b'c', b'o', b'n', b'd', 0xc0, 18]
        );
    }

    /// The index folds case exactly as the comparison does, and no further:
    /// `k` and U+212A KELVIN SIGN are different names (RFC 4343).
    #[test]
    fn the_index_folds_the_same_ascii_the_comparison_does() {
        // The hash takes wire octets now, so the comparison is over names.
        let wire = |text: &str| nm(text).as_ref().as_wire().to_vec();
        assert_eq!(
            folded_hash(&wire("Example.COM.")),
            folded_hash(&wire("example.com."))
        );
        assert_ne!(
            folded_hash(&wire("\u{212A}.example.com.")),
            folded_hash(&wire("k.example.com."))
        );
    }

    /// Names are written in full the first time and pointed at after that.
    #[test]
    fn test_repeated_name_becomes_a_pointer() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 128];

        let pos = c
            .write_name(nm("example.com.").as_ref(), &mut buf, 12)
            .unwrap();
        assert_eq!(pos, 12 + 13, "13 bytes: 7example3com0");

        let end = c
            .write_name(nm("example.com.").as_ref(), &mut buf, pos)
            .unwrap();
        assert_eq!(end - pos, 2, "the repeat is a bare pointer");
        assert_eq!(&buf[pos..end], &[0xc0, 12]);
    }

    /// A shared suffix compresses even when the leading labels differ.
    #[test]
    fn test_partial_suffix_match() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 128];

        let pos = c
            .write_name(nm("example.com.").as_ref(), &mut buf, 12)
            .unwrap();
        let end = c
            .write_name(nm("www.example.com.").as_ref(), &mut buf, pos)
            .unwrap();

        // "3www" written literally, then a pointer to example.com at 12.
        assert_eq!(&buf[pos..end], &[3, b'w', b'w', b'w', 0xc0, 12]);
    }

    /// The suffixes written as part of a longer name are targets themselves.
    #[test]
    fn test_suffix_of_earlier_name_is_a_target() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 128];

        // www.example.com. at 12 => "com." starts at 12 + 4 + 8 = 24.
        let pos = c
            .write_name(nm("www.example.com.").as_ref(), &mut buf, 12)
            .unwrap();
        let end = c.write_name(nm("com.").as_ref(), &mut buf, pos).unwrap();

        assert_eq!(&buf[pos..end], &[0xc0, 24]);
    }

    /// Comparison is case-insensitive (RFC 4343), but the bytes first written
    /// keep the case they were given.
    #[test]
    fn test_case_insensitive_match() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 128];

        let pos = c
            .write_name(nm("Example.COM.").as_ref(), &mut buf, 12)
            .unwrap();
        assert_eq!(&buf[12..20], b"\x07Example");

        let end = c
            .write_name(nm("example.com.").as_ref(), &mut buf, pos)
            .unwrap();
        assert_eq!(&buf[pos..end], &[0xc0, 12]);
    }

    /// The root is a single zero octet, never a pointer.
    #[test]
    fn test_root_is_never_compressed() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 16];

        let pos = c.write_name(nm(".").as_ref(), &mut buf, 0).unwrap();
        assert_eq!(&buf[..pos], &[0]);

        let end = c.write_name(nm(".").as_ref(), &mut buf, pos).unwrap();
        assert_eq!(&buf[pos..end], &[0]);
    }

    /// A name's suffixes share one arena copy: an owned `String` per suffix is
    /// quadratic in the label count. Asserted on bytes held, which is exact.
    #[test]
    fn a_names_suffixes_are_stored_once_between_them_not_once_each() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 256];

        let name = nm("a.b.c.d.example.com.");
        c.write_name(name.as_ref(), &mut buf, 12).unwrap();

        assert_eq!(c.seen.len(), 6, "six suffixes, one per label");
        // The arena holds the name's wire octets, root terminator included.
        assert_eq!(
            c.arena.len(),
            name.as_ref().as_wire().len(),
            "and one copy of the name between them, not one per suffix"
        );

        // A second name sharing five of those labels adds only its own label.
        c.write_name(nm("z.b.c.d.example.com.").as_ref(), &mut buf, 40)
            .unwrap();
        assert_eq!(c.seen.len(), 7);
        assert_eq!(
            c.arena.len(),
            name.as_ref().as_wire().len() * 2,
            "the shared tail is not copied per suffix, only per name"
        );
    }

    /// A name already known in full adds nothing, and finding that out copies
    /// nothing: the lookup compares against the caller's own bytes.
    #[test]
    fn a_fully_matched_name_leaves_the_table_and_the_arena_untouched() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 256];

        let pos = c
            .write_name(nm("www.example.com.").as_ref(), &mut buf, 12)
            .unwrap();
        let (suffixes, bytes) = (c.seen.len(), c.arena.len());

        let mut at = pos;
        for _ in 0..20 {
            at = c
                .write_name(nm("WWW.Example.Com.").as_ref(), &mut buf, at)
                .unwrap();
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
        let pos = c
            .write_name(nm("example.com.").as_ref(), &mut buf, far)
            .unwrap();
        assert_eq!(pos - far, 13);

        // Nothing reachable to point at, so the second copy is written in full.
        let end = c
            .write_name(nm("example.com.").as_ref(), &mut buf, pos)
            .unwrap();
        assert_eq!(end - pos, 13);
    }

    /// RDATA of a type RFC 1035 predates is compressed; anything else is not.
    #[test]
    fn test_rdata_compression_is_type_gated() {
        let mut c = NameCompressor::new();
        let mut buf = [0u8; 256];

        let pos = c
            .write_name(nm("example.com.").as_ref(), &mut buf, 12)
            .unwrap();

        // NS RDATA: one name, sharing the whole suffix -> "2ns" + pointer.
        let ns = nm("ns.example.com.");
        let ns = ns.as_ref().as_wire();
        let end = c.write_rdata(rt::NS, ns, &mut buf, pos).unwrap();
        assert_eq!(&buf[pos..end], &[2, b'n', b's', 0xc0, 12]);

        // SRV (33) is not on the list: byte-for-byte, pointers or not.
        let srv_start = end;
        let mut srv = vec![0, 10, 0, 20, 0, 80];
        srv.extend_from_slice(nm("ns.example.com.").as_ref().as_wire());
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

        let pos = c
            .write_name(nm("example.com.").as_ref(), &mut buf, 12)
            .unwrap();

        let mut mx = vec![0, 10];
        mx.extend_from_slice(nm("mail.example.com.").as_ref().as_wire());
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

        let pos = c
            .write_name(nm("example.com.").as_ref(), &mut buf, 12)
            .unwrap();

        let mut soa = nm("ns.example.com.").as_ref().as_wire().to_vec();
        soa.extend_from_slice(nm("admin.example.com.").as_ref().as_wire());
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

        let result = c.write_name(nm("example.com.").as_ref(), &mut buf, 0);
        assert!(result.is_err());
    }
}
