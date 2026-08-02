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
/// A linear scan beats a hash here rather than merely tying it. One message holds
/// a handful of distinct names, so the table is a handful of entries long; hashing
/// a string costs a pass over it either way, and the `HashMap` had to be built and
/// dropped per message on top of that.
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
}

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
    fn lookup(&self, needle: &str) -> Option<u16> {
        self.seen
            .iter()
            .find(|s| self.arena[s.start as usize..s.end as usize].eq_ignore_ascii_case(needle))
            .map(|s| s.offset)
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
