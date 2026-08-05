//! Domain-name compression for message output (RFC 1035 §4.1.4).
//!
//! A name can be written as a sequence of labels ending in a pointer to a name
//! (or the tail of a name) that appeared earlier in the same message. Since
//! most records in a response share a suffix with the question — often the
//! whole owner name — this is where nearly all the size saving in a DNS
//! response comes from.
//!
//! [`NameCompressor`] tracks, for one message being written, the offset at
//! which every name suffix was first emitted. It is deliberately scoped to a
//! single serialization pass: offsets are meaningless across messages.
//!
//! **Where compression is applied.** Owner names (question and RR name fields)
//! always. Names *inside* RDATA only for the record types RFC 1035 defines,
//! because a receiver that does not know a type cannot find the names in it to
//! decompress — RFC 3597 §4 makes this a MUST NOT for newer types. That rules
//! out SRV (RFC 2782), DNAME, and the DNSSEC types, whose embedded names RFC
//! 4034 requires to stay uncompressed.

use crate::dname::{
    dname_from_bytes, write_bytes, write_label, DNameUnpacker, POINTER_MASK, POINTER_TAG,
};
use crate::error::WireError;
use crate::utils::record_types as rt;
use crate::Rtype;
use std::collections::HashMap;

/// Per-message table of name suffixes already written, and where.
///
/// **Suffixes are ranges into one arena, not owned `String`s.** This used to be
/// a `HashMap<String, u16>` filled by `labels[i..].join(".").to_ascii_lowercase()`
/// — which allocates once to join and *again* to lowercase, since
/// `to_ascii_lowercase` on a `str` returns a new `String` rather than mutating.
/// Writing `www.example.com.` cold cost about eight allocations and a total byte
/// count quadratic in the label count, because every suffix carried its own copy
/// of the tail it shares with the others. Measured at 339 ns per name, which made
/// compression the *majority* of response serialization: the whole rest of
/// `to_bytes` for a three-record answer was under 400 ns.
///
/// A linear scan beats a hash here rather than merely tying it — **for the
/// message shape that reasoning was measured on**, which is a query response. One
/// of those holds a handful of distinct names, so the table is a handful of
/// entries long; hashing a string costs a pass over it either way, and the
/// `HashMap` had to be built and dropped per message on top of that.
///
/// It is false of every other caller of `to_bytes`, and that is `TODO.md` #24b:
/// an AXFR envelope targets 16 KiB, which is 300-500 records, and the scan is one
/// pass over the table per name written. Measured at 51 ns per name for 25 names
/// and 663 for 800 — quadratic, and worsening in exactly the direction anyone
/// tuning envelope size would push. See [`NameCompressor::index`].
#[derive(Debug, Default)]
pub struct NameCompressor {
    /// Every name that contributed a suffix to the table, concatenated, in the
    /// case it was written in.
    ///
    /// Not lowercased: [`NameCompressor::lookup`] compares case-insensitively,
    /// so folding a stored copy would buy nothing and the fold would have to be
    /// paid on the needle as well — which is an allocation per name looked up,
    /// and looking a name up is what this type does. A name written *without*
    /// contributing anything — one already in the table in full — is never
    /// copied here at all.
    arena: String,
    /// Suffixes of those names, as ranges into `arena` with the offset each was
    /// first written at. Never holds two entries for the same suffix.
    seen: Vec<Suffix>,
    /// Folded hash of a suffix to its entry in `seen`, **built only once `seen`
    /// outgrows [`SCAN_LIMIT`]** and empty before that.
    ///
    /// Lazily, because the two message shapes want opposite answers and one of
    /// them is the query path: a `HashMap` allocates on its first insert, and
    /// `rdns/tests/allocations.rs` holds a one-record response at exactly three
    /// allocations. A transfer envelope pays that one allocation and gets its
    /// name lookups back in constant time; a response never reaches the
    /// threshold and is byte-for-byte the code it was.
    ///
    /// **A hash collision drops the newer suffix rather than chaining it**, which
    /// is why the value is one index and not a list. Compression is optional —
    /// RFC 1035 §4.1.4 permits any name to be written in full — so a collision
    /// costs a few bytes on the wire and nothing else, where a bucket per entry
    /// would be an allocation per distinct name. The older entry is the one kept
    /// on purpose: it has the lower offset, which is the better pointer target
    /// anyway.
    index: HashMap<u64, u32>,
}

/// How many suffixes the linear scan stays cheaper than an index for.
///
/// **Measured on whole messages, which is the second answer this got.** Timing
/// the compressor alone puts the crossover in the thirties, and a threshold of 32
/// made `serialize a full-size response` — 60 names, an existing bench — **26%
/// slower** (5.55 → 7.00 µs): building the map and hashing every lookup cost more
/// at that size than the scan they replaced. Through `to_bytes_within_buf`:
///
/// | | scan | index at 128 |
/// |---|---|---|
/// | one record | 134.0 ns | 134.5 ns |
/// | 60 names | 5.55 µs | 5.56 µs |
/// | 400-record envelope | 130.7 µs | 42.8 µs |
///
/// So it sits where a response cannot reach it and a transfer envelope still
/// does. `cargo bench -p rdns -- "serialize a"` is the measurement, and the
/// number this replaced is `CLAUDE.md` §10's rule about measuring the thing
/// rather than a proxy for it.
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

        // Walk this name's suffixes longest-first, looking for one already in
        // the message. Each needle is a slice of the caller's own name, so
        // finding out whether a name is already here costs nothing at all —
        // which matters because a response repeats one owner name across every
        // record in it.
        let mut matched = None;
        for (i, start) in label_starts(trimmed).enumerate() {
            if let Some(target) = self.lookup(&trimmed[start..]) {
                matched = Some((i, target));
                break;
            }
        }

        // Everything before the match is a suffix that will be written literally
        // here, so note where it lands: a later name can point at it, and its
        // tail continues correctly into whatever we emit after it (labels or a
        // pointer). Everything from the match on is already recorded, and a name
        // matched at its first label — `fresh == 0` — is recorded in full
        // already and contributes nothing, not even a copy.
        let fresh = matched.map_or_else(|| label_starts(trimmed).count(), |(i, _)| i);
        if fresh > 0 {
            let first_new = self.seen.len();
            let base = self.arena.len();
            self.arena.push_str(trimmed);
            let end = self.arena.len();
            for start in label_starts(trimmed).take(fresh) {
                // Where this suffix lands in the message. A label costs its own
                // bytes plus a one-byte length prefix on the wire, and its own
                // bytes plus a separating `.` in the text — the same number
                // either way, so the distance from the start of the name is the
                // same on both sides and needs no running total.
                let suffix_pos = pos + start;
                // A pointer field is 14 bits, so a suffix past that is a target
                // nothing can reach. Recording it would only slow the scan.
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

        // The labels ahead of the match go out literally; `fresh` is exactly how
        // many those are, whether or not anything matched. Split `trimmed`
        // rather than the arena so the name keeps the case it was given — RFC
        // 4343 folds case for *comparison*, and the arena copy exists for that
        // and nothing else.
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
    /// Case-insensitively, and **ASCII-only** (RFC 4343), which is the same rule
    /// `utils::ascii_lowered` exists for: `str::to_lowercase` folds U+212A KELVIN
    /// SIGN to `k`, and two names that differ on the wire must not compress
    /// against each other. `eq_ignore_ascii_case` folds exactly the 26 letters
    /// and nothing else.
    /// The offset a suffix was first written at, if it has been.
    ///
    /// Case-insensitively, and **ASCII-only** (RFC 4343), which is the same rule
    /// `utils::ascii_lowered` exists for: `str::to_lowercase` folds U+212A KELVIN
    /// SIGN to `k`, and two names that differ on the wire must not compress
    /// against each other. `eq_ignore_ascii_case` folds exactly the 26 letters and
    /// nothing else — and so does [`folded_hash`], which has to fold the same way
    /// or the index would file a suffix where nothing looks for it.
    ///
    /// **Both arms compare against the arena**, so the index is only ever an
    /// accelerator. A hash that collided with a different suffix's would otherwise
    /// be a pointer to the wrong name.
    ///
    /// That comparison is written out twice rather than shared, which is measured
    /// rather than sloppy: as a method on `&self`, and again as one closure both
    /// arms call, the scan below cost 51 -> 75 ns per name written — half again as
    /// much, on the message shape the scan is the whole reason for.
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
            // The whole table, not just the new entries: everything before the
            // threshold has only ever been reachable by the scan.
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
/// An iterator rather than the `Vec<usize>` this used to collect. A name has at
/// most 127 labels and in practice four, so the vector was 64 bytes of heap per
/// name written — two allocations on every query, which the DHAT profile
/// (`TODO.md` #9e) ranked beside the whole rest of serialization. The two passes
/// it is walked in are over at most 255 bytes and cost nothing measurable.
///
/// Splits on every `.`, exactly as `str::split` does, so an empty label is still
/// produced here and still rejected by `write_label`.
fn label_starts(name: &str) -> impl Iterator<Item = usize> + '_ {
    std::iter::once(0).chain(
        name.bytes()
            .enumerate()
            .filter(|(_, byte)| *byte == b'.')
            .map(|(i, _)| i + 1),
    )
}

/// FNV-1a over the ASCII-folded bytes (RFC 4343), which is what [`lookup`]
/// compares on — a hash that folded differently from the comparison would file a
/// suffix where nothing looks for it.
///
/// **Deliberately not a DoS-resistant hash.** A collision here drops a
/// compression target, so the most a chosen name can buy is a few extra bytes in
/// one message; SipHash's guarantee has nothing to protect and costs several
/// times FNV on the short strings this hashes.
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

    /// Writing a name must not cost more because the message already holds many.
    ///
    /// **A ratio, not a floor** (`CLAUDE.md` §10): the same work per name, timed
    /// on a message of 25 distinct names and one of 800, on whatever machine is
    /// running it. The scan read 51 ns per name at 25 and 663 at 800 — a factor of
    /// 13, which is `TODO.md` #24b — and the index reads 53 and 112.
    ///
    /// The threshold is 5 rather than §10's usual factor of ten because the true
    /// ratio is about 2 and the defect's was 13, so anything between the two
    /// discriminates. What is left is cache rather than the table: at 800 names
    /// the arena, `seen` and the index have all outgrown L1, and no lookup scheme
    /// avoids that.
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
                        // Every name here is meant to be a compression target, so
                        // none may have landed past the 14-bit pointer range.
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
    /// The index is built from the whole of `seen` at the crossover for exactly
    /// this. An entry only the scan had ever reached would quietly stop matching,
    /// and every later name carrying that suffix would go out in full — a message
    /// that is still correct and merely bigger, which is the kind of defect
    /// nothing notices (`CLAUDE.md` §4).
    #[test]
    fn a_suffix_from_before_the_index_is_still_found_after_it() {
        let mut c = NameCompressor::new();
        let mut buf = vec![0u8; 0x4000];

        // `example.com.` is recorded here, while the table is still scanned, at
        // 12 for the header plus the six bytes of `5first`.
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

    /// The index folds case exactly as the comparison does, and no further.
    ///
    /// Two spellings of one name must hash together, or the index files a suffix
    /// where nothing looks for it. `k` and U+212A KELVIN SIGN must *not*, which is
    /// the fold `str::to_lowercase` gets wrong and this codebase has been bitten
    /// by twice (`CLAUDE.md` §8).
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

    /// The suffix table used to hold an owned, separately-allocated `String` per
    /// suffix, so `a.b.c.d.example.com.` stored six keys totalling 84 bytes for
    /// a 20-byte name — a copy of the shared tail per label, quadratic in label
    /// count, on top of one discarded intermediate `String` per suffix from the
    /// `join` that built it. Suffixes are ranges into one copy now.
    ///
    /// Asserted on bytes held rather than on a timing, because it is exact and
    /// does not care what else is running (`CLAUDE.md` §10).
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

    /// A name already known in full adds nothing at all — and, since the lookup
    /// compares against the caller's own bytes, nothing is copied in order to
    /// find that out either. A response repeating one owner name across twenty
    /// records touches the arena once, for the first.
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

        // The second copy has nothing reachable to point at, so it is written
        // out in full as well.
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
