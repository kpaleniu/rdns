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
use anyhow::anyhow;
use std::collections::HashMap;

/// Per-message table of name suffixes already written, and where.
#[derive(Debug, Default)]
pub struct NameCompressor {
    /// Lowercased suffix (no trailing dot) -> offset of its first occurrence.
    /// Lowercased because name comparison is case-insensitive (RFC 4343).
    seen: HashMap<String, u16>,
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
    ) -> Result<usize, anyhow::Error> {
        let trimmed = name.strip_suffix('.').unwrap_or(name);
        if trimmed.is_empty() {
            // The root is one zero octet; a pointer to it would cost two.
            return write_bytes(buf, pos, &[0]);
        }

        let labels: Vec<&str> = trimmed.split('.').collect();

        // Walk suffixes longest-first. Everything we pass is a suffix that will
        // be written literally here, so note where it lands: a later name can
        // point at it, and its tail continues correctly into whatever we emit
        // after it (labels or a pointer).
        let mut suffix_pos = pos;
        let mut fresh: Vec<(String, usize)> = Vec::with_capacity(labels.len());

        for i in 0..labels.len() {
            let key = labels[i..].join(".").to_ascii_lowercase();

            if let Some(&target) = self.seen.get(&key) {
                self.remember(fresh);
                let mut out = pos;
                for label in &labels[..i] {
                    out = write_label(buf, out, label)?;
                }
                return write_bytes(buf, out, &(POINTER_TAG | target).to_be_bytes());
            }

            fresh.push((key, suffix_pos));
            suffix_pos += labels[i].len() + 1;
        }

        // Nothing matched: write the name out in full.
        self.remember(fresh);
        let mut out = pos;
        for label in &labels {
            out = write_label(buf, out, label)?;
        }
        write_bytes(buf, out, &[0])
    }

    /// Record where each newly-written suffix starts, skipping any that a
    /// 14-bit pointer cannot reach.
    fn remember(&mut self, suffixes: Vec<(String, usize)>) {
        for (key, offset) in suffixes {
            if offset <= POINTER_MASK as usize {
                self.seen.entry(key).or_insert(offset as u16);
            }
        }
    }

    /// Write a record's RDATA at `pos`, compressing embedded names for the
    /// record types where that is legal. Returns the new position.
    ///
    /// `rdata` is the stored, uncompressed wire form, so the names inside it can
    /// be read without message context.
    pub fn write_rdata(
        &mut self,
        rtype: u16,
        rdata: &[u8],
        buf: &mut [u8],
        pos: usize,
    ) -> Result<usize, anyhow::Error> {
        match rtype {
            // NS, CNAME, PTR: the RDATA is exactly one domain name.
            2 | 5 | 12 => {
                let (name, rest) = read_name(rdata)?;
                let pos = self.write_name(&name, buf, pos)?;
                write_bytes(buf, pos, rest)
            }
            // SOA: MNAME, RNAME, then five 32-bit fields.
            6 => {
                let (mname, rest) = read_name(rdata)?;
                let (rname, rest) = read_name(rest)?;
                let pos = self.write_name(&mname, buf, pos)?;
                let pos = self.write_name(&rname, buf, pos)?;
                write_bytes(buf, pos, rest)
            }
            // MX: 16-bit preference, then EXCHANGE.
            15 => {
                if rdata.len() < 2 {
                    return Err(anyhow!("MX RDATA too short for its preference field"));
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

/// Read one uncompressed name from the head of `data`, returning it with the
/// bytes that follow.
fn read_name(data: &[u8]) -> Result<(String, &[u8]), anyhow::Error> {
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
        let end = c.write_rdata(2, &ns, &mut buf, pos).unwrap();
        assert_eq!(&buf[pos..end], &[2, b'n', b's', 0xc0, 12]);

        // SRV (33) is not on the list: byte-for-byte, pointers or not.
        let srv_start = end;
        let mut srv = vec![0, 10, 0, 20, 0, 80];
        srv.extend_from_slice(&crate::dname::dname_to_bytes("ns.example.com.").unwrap());
        let end = c.write_rdata(33, &srv, &mut buf, srv_start).unwrap();
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
        let end = c.write_rdata(15, &mx, &mut buf, pos).unwrap();

        assert_eq!(&buf[pos..end], &[0, 10, 4, b'm', b'a', b'i', b'l', 0xc0, 12]);
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
        let end = c.write_rdata(6, &soa, &mut buf, pos).unwrap();

        let expected: Vec<u8> = [2, b'n', b's', 0xc0, 12, 5, b'a', b'd', b'm', b'i', b'n', 0xc0, 12]
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
