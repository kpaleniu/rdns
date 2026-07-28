use crate::error::WireError;
use std::str::from_utf8;
use std::cell::RefCell;
use std::collections::HashSet;


/// The two high bits that mark a label as a compression pointer (RFC 1035
/// §4.1.4).
pub(crate) const POINTER_TAG: u16 = 0xc000;

/// The offset a pointer carries, once the tag bits are masked off. Being a
/// 14-bit field, this doubles as the highest offset a pointer can address —
/// which is why a name written past it can never become a compression target.
pub(crate) const POINTER_MASK: u16 = 0x3fff;

/// The longest a single label may be (RFC 1035 §2.3.4).
pub(crate) const MAX_LABEL_LEN: usize = 63;

/// Copy `bytes` into `buf` at `pos`, returning the position just past them.
///
/// This is the one bounds-checked write every wire serializer goes through.
/// Unlike an `io::Cursor` over a slice, it refuses to write past the end rather
/// than silently dropping the tail of a message.
pub(crate) fn write_bytes(
    buf: &mut [u8],
    pos: usize,
    bytes: &[u8],
) -> Result<usize, WireError> {
    let end = pos + bytes.len();
    if end > buf.len() {
        return Err(WireError::Truncated {
            what: "the output buffer",
            need: end,
            have: buf.len(),
        });
    }
    buf[pos..end].copy_from_slice(bytes);
    Ok(end)
}

/// Write one length-prefixed label, validating it first.
///
/// The single place a label becomes bytes — shared by [`dname_to_bytes`] (which
/// writes whole names uncompressed) and the message compressor (which writes the
/// labels ahead of a pointer).
pub(crate) fn write_label(
    buf: &mut [u8],
    pos: usize,
    label: &str,
) -> Result<usize, WireError> {
    if label.is_empty() {
        return Err(WireError::malformed("domain name", "a label may not be empty"));
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(WireError::TooLong {
            what: "a label",
            limit: MAX_LABEL_LEN,
            actual: label.len(),
        });
    }
    let pos = write_bytes(buf, pos, &[label.len() as u8])?;
    write_bytes(buf, pos, label.as_bytes())
}

pub(crate) trait TryFromBytes<'a> {
    type Output;
    type Error;

    fn try_from_bytes(data: &'a [u8]) -> Result<Self::Output, Self::Error>;
}

// TODO: TryToBytes and others

#[derive(Debug, PartialEq, Clone)]
enum Label<'a> {
    String(&'a [u8]),
    Pointer(usize),
    Root,
}

impl<'a> Label<'a> {
    fn len(&self) -> usize {
        match *self {
            Label::String(s) => s.len() + 1,
            Label::Pointer(_) => 2,
            Label::Root => 1,
        }
    }
}

impl<'a> TryInto<&'a str> for Label<'a> {
    type Error = WireError;

    fn try_into(self) -> Result<&'a str, WireError> {
        match self {
            Label::String(s) => from_utf8(s)
                .map_err(|_| WireError::malformed("a label", "not valid UTF-8")),
            _ => Err(WireError::malformed("a label", "not a text label")),
        }
    }
}

/**
 * Labels are LV encoded strings (originally ASCII, effectively UTF8 nowadays) that
 * can be one of
 * * Normal label
 *   * Root, if len is 0 (see RFC 6895 section 3.3.2)
 *   * String, otherwise
 * * Pointer, if top 2 bits are 11
 * * Extended label, if top 2 bits are 01
 *   * Not supported until I read through RFC6891
 */
impl<'a> TryFromBytes<'a> for Label<'a> {
    type Output = Label<'a>;
    type Error = WireError;
    fn try_from_bytes(data: &'a [u8]) -> Result<Label<'a>, WireError> {
        // Every index below is on bytes a hostile peer chose the length of, so
        // each one is checked: a truncated message must be an error, not a panic.
        let Some(&first) = data.first() else {
            return Err(WireError::Truncated {
                what: "a label",
                need: 1,
                have: 0,
            });
        };
        let lt = first >> 6;
        let len = (first & 0x3f) as usize; // guarantees len cannot be more than 63

        match lt {
            /* normal label */
            0x0 => match len {
                0 => Ok(Label::Root),
                _ => {
                    if data.len() <= len {
                        return Err(WireError::Truncated {
                            what: "a label",
                            need: len,
                            have: data.len() - 1,
                        });
                    }
                    Ok(Label::String(&data[1..=len]))
                }
            },
            /* compressed label */
            0x3 => {
                if data.len() < 2 {
                    return Err(WireError::Truncated {
                        what: "a compression pointer",
                        need: 2,
                        have: data.len(),
                    });
                }
                Ok(Label::Pointer(
                    (u16::from_be_bytes([data[0], data[1]]) & POINTER_MASK) as usize,
                ))
            }
            /* extended label */
            0x1 => match data[0] {
                // Legal encodings we do not implement (RFC 2673, RFC 6891
                // §6.2.4), so the sender is not at fault: NOTIMP, not FORMERR.
                0x41 => Err(WireError::Unsupported { what: "a binary label" }),
                0x7f => Err(WireError::Unsupported {
                    what: "the reserved extended label type",
                }),
                _ => Err(WireError::malformed("a label", "unknown extended label type")),
            },
            _ => Err(WireError::malformed("a label", "unknown label type")),
        }
    }
}

pub(crate) struct DName<'a> {
    labels: Vec<Label<'a>>,
}

/*
Quoting from RFC 1035:
> The following syntax will result in fewer problems with many
> applications that use domain names (e.g., mail, TELNET).

> <domain> ::= <subdomain> | " "

> <subdomain> ::= <label> | <subdomain> "." <label>

> <label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]

> <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>

> <let-dig-hyp> ::= <let-dig> | "-"

> <let-dig> ::= <letter> | <digit>

> <letter> ::= any one of the 52 alphabetic characters A through Z in
> upper case and a through z in lower case

> <digit> ::= any one of the ten digits 0 through 9

TODO: Implement validation to enforce this pattern
*/
impl<'a> TryFromBytes<'a> for DName<'a> {
    type Output = (DName<'a>, &'a [u8]);
    type Error = WireError;
    fn try_from_bytes(data: &'a [u8]) -> Result<(DName<'a>, &'a [u8]), WireError> {
        let mut labels = Vec::new();
        let mut off = data;
        loop {
            let lbl = Label::try_from_bytes(off)?;
            off = &off[lbl.len()..];

            let end = !matches!(lbl, Label::String(_));
            labels.push(lbl);
            if end {
                break;
            }
        }
        Ok((DName { labels }, off))
    }
}

/**
 * Since dnames contain pointers, we must have a way to resolve them. Pointers are
 * offsets to bytes in the complete DNS message. While rest of the deserialization
 * works with
 *
 *   let (val, rest) = sometype::try_from_bytes(bytes)?;
 *
 * to simplify how the code reads, this loses the original byte context. We still
 * need a lookup mechanism to hop anywhere in the original set of bytes. Unpacker
 * gets contructed with the original bytes and thus is able to perform the lookup.
 */
pub struct DNameUnpacker<'a> {
    data: &'a [u8],
    visited: RefCell<HashSet<usize>>,
}

impl<'a> DNameUnpacker<'a> {
    pub fn new(data: &'a [u8]) -> DNameUnpacker<'a> {
        DNameUnpacker {
            data,
            visited: RefCell::new(HashSet::new()),
        }
    }

    fn unpack_internal(
        &self,
        name: DName<'a>,
        depth: usize,
    ) -> Result<UnpackedDName<'a>, WireError> {
        const MAX_DEPTH: usize = 50;
        
        if depth > MAX_DEPTH {
            return Err(WireError::TooLong {
                what: "compression pointer nesting",
                limit: MAX_DEPTH,
                actual: MAX_DEPTH + 1,
            });
        }

        let mut output = Vec::new();
        for label in &name.labels {
            match label {
                Label::String(_) => {
                    output.push(label.clone());
                }
                Label::Pointer(offset) => {
                    // Bounds check: pointer offset must be within message
                    if *offset >= self.data.len() {
                        return Err(WireError::malformed(
                            "a compression pointer",
                            format!(
                                "offset {offset} is past the {}-byte message",
                                self.data.len()
                            ),
                        ));
                    }

                    // Cycle detection: check if we've already visited this offset
                    if self.visited.borrow().contains(offset) {
                        return Err(WireError::malformed(
                            "a compression pointer",
                            format!("offset {offset} points into a cycle"),
                        ));
                    }

                    // Mark offset as visited
                    self.visited.borrow_mut().insert(*offset);
                    
                    let (name, _) = DName::try_from_bytes(&self.data[*offset..])?;
                    let unpacked = self.unpack_internal(name, depth + 1)?;
                    
                    // Unmark offset (allows same offset in other branches)
                    self.visited.borrow_mut().remove(offset);
                    
                    output.extend(unpacked.labels);
                }
                Label::Root => break,
            }
        }
        Ok(UnpackedDName { labels: output })
    }

    fn unpack(&self, name: DName<'a>) -> Result<UnpackedDName<'a>, WireError> {
        self.visited.borrow_mut().clear();
        self.unpack_internal(name, 0)
    }
}

pub(crate) trait TryUnpackFromBytes<'a> {
    type Output;
    type Error;

    fn try_from_bytes(
        data: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<Self::Output, Self::Error>;
}

#[derive(Debug)]
pub(crate) struct UnpackedDName<'a> {
    labels: Vec<Label<'a>>,
}

/***
 * Main API for converting to and from bytes to dnames
 */

pub fn dname_from_bytes<'a>(
    bytes: &'a [u8],
    unpacker: &DNameUnpacker<'a>,
) -> Result<(String, &'a [u8]), WireError> {
    let (name, rest) = DName::try_from_bytes(bytes)?;
    let name = unpacker.unpack(name)?;
    let s = name.try_into()?;
    Ok((s, rest))
}

/// Encode a name in full, without compression.
///
/// This is the form stored in RDATA and the one DNSSEC canonical serialization
/// requires; the message serializer uses the compressor instead.
pub fn dname_to_bytes(name: &str) -> Result<Vec<u8>, WireError> {
    // A fully-qualified name carries a trailing '.' denoting the root; splitting
    // on '.' would otherwise yield a spurious empty final label (and a second
    // zero byte), which corrupts any record that stores data after the name.
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Ok(vec![0]); // the root, on its own
    }

    // Size the buffer from the labels themselves, then let `write_label` do the
    // validating as it writes. An over-long or empty label errors there rather
    // than being checked twice.
    let labels: Vec<&str> = name.split('.').collect();
    let size: usize = labels.iter().map(|l| l.len() + 1).sum::<usize>() + 1;

    let mut out = vec![0u8; size];
    let mut pos = 0;
    for label in &labels {
        pos = write_label(&mut out, pos, label)?;
    }
    write_bytes(&mut out, pos, &[0])?; // terminate with the root label
    Ok(out)
}

/**
 * Implement TryInto for UnpackedDName so we can finally turn the name into
 * a string. The design is you can only go
 *
 *   bytes -> DName -> unpacker -> UnpackedDName -> String
 *
 * This way the type system makes sure you don't end up with dname fragments,
 * as you would with a more naive implementation.
 */
impl<'a> TryInto<String> for UnpackedDName<'a> {
    fn try_into(self) -> Result<String, Self::Error> {
        // Phase 1: Calculate exact size needed
        let mut total_len = 1; // For trailing dot
        for l in &self.labels {
            if let Label::String(s) = l {
                total_len += s.len() + 1; // label + dot
            }
        }

        // Phase 2: Single allocation with exact capacity
        let mut result = String::with_capacity(total_len);
        
        for l in &self.labels {
            match l {
                Label::String(s) => {
                    let label_str = std::str::from_utf8(s)?;
                    result.push_str(label_str);
                    result.push('.');
                }
                Label::Pointer(_) => {
                    return Err(WireError::malformed(
                        "a domain name",
                        "an unpacked name may not contain a compression pointer",
                    ));
                }
                Label::Root => break,
            }
        }

        // Every other name ends up with a trailing dot because each label
        // contributes one. The root has no labels, so it would come back as the
        // empty string — which is not what the rest of the codebase calls the
        // root, and not what we put on the wire when we ask for it. A query for
        // `.` (which is exactly what fetching the root's DNSKEY RRset is) would
        // then fail the reply check, its question having apparently changed
        // from "." to "" in transit.
        if result.is_empty() {
            result.push('.');
        }

        Ok(result)
    }

    type Error = WireError;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_parse() {
        let data: [u8; 15] = [
            0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69,
            0x00,
        ];

        let lbl = Label::try_from_bytes(&data).expect("www");
        let lbl: &str = lbl.try_into().unwrap();
        assert_eq!(lbl, "www");

        let lbl = Label::try_from_bytes(&data[4..]).expect("google");
        let lbl: &str = lbl.try_into().unwrap();
        assert_eq!(lbl, "google");

        let lbl = Label::try_from_bytes(&data[11..]).expect("fi");
        let lbl: &str = lbl.try_into().unwrap();
        assert_eq!(lbl, "fi");

        assert_eq!(Label::try_from_bytes(&data[14..]).unwrap(), Label::Root);
    }

    #[test]
    fn test_name_parse() {
        let data: [u8; 15] = [
            0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69,
            0x00,
        ];
        let unpacker = DNameUnpacker::new(&data);

        let (s, _) = dname_from_bytes(&data, &unpacker).expect("www.google.fi");
        assert_eq!(s, "www.google.fi.");
    }

    #[test]
    fn test_name_pack() {
        let data: [u8; 15] = [
            0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69,
            0x00,
        ];
        let unpacker = DNameUnpacker::new(&data);

        let (s, _) = dname_from_bytes(&data, &unpacker).expect("www.google.fi");
        assert_eq!(s, "www.google.fi.");

        let res = dname_to_bytes("www.google.fi.").expect("www.google.fi");
        assert!(res.iter().zip(&data).all(|(l, r)| l == r));
    }

    /// A label header is attacker-controlled, so every read past it must be
    /// bounds-checked rather than indexing into whatever is left.
    #[test]
    fn test_truncated_labels_are_errors_not_panics() {
        assert!(Label::try_from_bytes(&[]).is_err(), "empty input");

        // Claims a 32-byte label with only one byte behind it.
        assert!(Label::try_from_bytes(&[0x20, b'a']).is_err(), "short label");

        // A pointer needs two bytes; only the tag byte is present.
        assert!(Label::try_from_bytes(&[0xc0]).is_err(), "half pointer");

        // The boundary case either side: exactly enough, and one short.
        assert!(Label::try_from_bytes(&[0x02, b'a', b'b']).is_ok());
        assert!(Label::try_from_bytes(&[0x02, b'a']).is_err());
    }

    /// Encoding rejects what it cannot represent, rather than truncating.
    #[test]
    fn test_dname_to_bytes_rejects_bad_labels() {
        assert!(dname_to_bytes("a..b.").is_err(), "empty label");
        let too_long = "x".repeat(MAX_LABEL_LEN + 1);
        assert!(dname_to_bytes(&format!("{too_long}.com.")).is_err());
        // The longest legal label is still fine.
        let max = "x".repeat(MAX_LABEL_LEN);
        assert!(dname_to_bytes(&format!("{max}.com.")).is_ok());
    }

    /// The root encodes to a single zero octet, with or without the dot.
    #[test]
    fn test_dname_to_bytes_root() {
        assert_eq!(dname_to_bytes(".").unwrap(), vec![0]);
        assert_eq!(dname_to_bytes("").unwrap(), vec![0]);
    }

    #[test]
    fn test_pointer_bounds_protection() {
        // Test bounds checking with an out-of-bounds pointer
        let data = &[0xc0, 0x50]; // Pointer to offset 80 (message is only 2 bytes)
        let unpacker = DNameUnpacker::new(data);

        let (dname, _) = DName::try_from_bytes(data).expect("should parse pointer");
        let result = unpacker.unpack(dname);
        
        // Matched on the variant rather than on the message: what a caller acts
        // on is the category, and an assertion on wording breaks every time the
        // wording improves.
        assert!(
            matches!(result, Err(WireError::Malformed { what: "a compression pointer", .. })),
            "got {result:?}"
        );
    }

    #[test]
    fn test_cycle_detection_works() {
        // Test that cycle detection catches self-referential pointers
        let data = &[0xc0, 0x00]; // Pointer to offset 0
        let unpacker = DNameUnpacker::new(data);

        let (dname, _) = DName::try_from_bytes(data).expect("should parse pointer");
        let result = unpacker.unpack(dname);
        
        assert!(
            matches!(result, Err(WireError::Malformed { what: "a compression pointer", .. })),
            "cycle detection should prevent unpacking, got {result:?}"
        );
    }

    #[test]
    fn test_depth_limit_prevents_deep_recursion() {
        // Verify depth limit is enforced
        // Create a deep but valid pointer structure
        let mut data = vec![0xc0u8; 102];
        // Each pointer points forward: 0->2->4...
        for i in 0..50 {
            data[i * 2 + 1] = ((i + 1) * 2) as u8;
        }

        let unpacker = DNameUnpacker::new(&data);
        let (dname, _) = DName::try_from_bytes(&data[0..2]).expect("should parse");
        let result = unpacker.unpack(dname);
        
        // Should hit depth limit and fail safely
        assert!(result.is_err(), "depth limit should be enforced");
    }
}
