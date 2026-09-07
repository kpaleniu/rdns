use crate::error::WireError;
use std::str::from_utf8;

/// The two high bits that mark a label as a compression pointer (RFC 1035
/// §4.1.4).
pub(crate) const POINTER_TAG: u16 = 0xc000;

/// The offset a pointer carries, once the tag bits are masked off. Being 14
/// bits, it is also the highest offset a pointer can address, so a name written
/// past it can never become a compression target.
pub(crate) const POINTER_MASK: u16 = 0x3fff;

/// The longest a single label may be (RFC 1035 §2.3.4).
pub(crate) const MAX_LABEL_LEN: usize = 63;

/// The longest a whole name may be, *encoded*: RFC 1035 §2.3.4's "names 255
/// octets or less", counting each label's length octet and the root's
/// terminating zero.
pub const MAX_NAME_LEN: usize = 255;

/// Copy `bytes` into `buf` at `pos`, returning the position just past them.
///
/// The one bounds-checked write every wire serializer goes through: unlike an
/// `io::Cursor` over a slice, it errors rather than dropping the tail.
pub(crate) fn write_bytes(buf: &mut [u8], pos: usize, bytes: &[u8]) -> Result<usize, WireError> {
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

/// Why a label cannot be carried in this library's presentation-text form, if
/// it cannot.
///
/// A wire label may hold any octet (RFC 1035 §3.1), but a name here is a
/// `String` in presentation form, so two have no faithful spelling: `.`, which
/// would make the one-label name `a.b` and the two-label name `a`+`b` the same
/// string and so break every name-keyed map and `is_at_or_under`; and `\`,
/// RFC 1035 §5.1's escape, which no zone-file reader would read back as the
/// same name. Refused rather than escaped — resolving escapes needs a stored
/// form that can hold a dot inside a label, which presentation text cannot.
fn unrepresentable_octet(label: &str) -> Option<&'static str> {
    if label.as_bytes().contains(&b'.') {
        return Some("a label containing the label separator");
    }
    if label.as_bytes().contains(&b'\\') {
        return Some("a label containing an escape character");
    }
    None
}

/// Write one length-prefixed label, validating it first.
///
/// The single place a label becomes bytes, shared by [`dname_to_bytes`] and the
/// message compressor.
pub(crate) fn write_label(buf: &mut [u8], pos: usize, label: &str) -> Result<usize, WireError> {
    if let Some(what) = unrepresentable_octet(label) {
        return Err(WireError::Unsupported { what });
    }
    if label.is_empty() {
        return Err(WireError::malformed(
            "domain name",
            "a label may not be empty",
        ));
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
            Label::String(s) => {
                from_utf8(s).map_err(|_| WireError::malformed("a label", "not valid UTF-8"))
            }
            _ => Err(WireError::malformed("a label", "not a text label")),
        }
    }
}

/// A label is length-prefixed, and the top two bits of that length byte pick the
/// kind: 00 a text label (length 0 is the root, RFC 6895 §3.3.2), 11 a
/// compression pointer, 01 an extended label (RFC 2673, unsupported).
impl<'a> TryFromBytes<'a> for Label<'a> {
    type Output = Label<'a>;
    type Error = WireError;
    fn try_from_bytes(data: &'a [u8]) -> Result<Label<'a>, WireError> {
        // Every index below is on a length a peer chose: truncation is an error,
        // never a panic.
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
                            // Cannot underflow: `data.first()` above returned
                            // early on an empty slice, so the length byte being
                            // subtracted here is present.
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
                // §6.2.4): NOTIMP, not FORMERR.
                0x41 => Err(WireError::Unsupported {
                    what: "a binary label",
                }),
                0x7f => Err(WireError::Unsupported {
                    what: "the reserved extended label type",
                }),
                _ => Err(WireError::malformed(
                    "a label",
                    "unknown extended label type",
                )),
            },
            _ => Err(WireError::malformed("a label", "unknown label type")),
        }
    }
}

/// A name as it sits in a message: its own encoded bytes, nothing copied.
///
/// Was a `Vec<Label>`, collected by the parser and dropped as soon as the name
/// became a `String` — one allocation per name of every message parsed. The
/// labels are walked again on demand, which costs nothing and cannot disagree
/// with the first walk because it is the same function over the same bytes.
pub(crate) struct DName<'a> {
    /// Exactly the name: every label, and the root octet or pointer that ended
    /// it.
    encoded: &'a [u8],
    /// Whether the name ends in a compression pointer, which is the only thing
    /// that needs the message to resolve.
    compressed: bool,
}

impl<'a> DName<'a> {
    /// The labels, in wire order, ending with [`Label::Root`] or the pointer.
    ///
    /// Fallible rather than trusting [`DName::try_from_bytes`]'s walk: an
    /// invariant nobody checks is a claim, not a guarantee (`CLAUDE.md` §17),
    /// and the check is a comparison the caller was making anyway.
    fn labels(&self) -> impl Iterator<Item = Result<Label<'a>, WireError>> + '_ {
        let mut rest = self.encoded;
        std::iter::from_fn(move || {
            if rest.is_empty() {
                return None;
            }
            Some(match Label::try_from_bytes(rest) {
                Ok(label) => {
                    rest = &rest[label.len()..];
                    Ok(label)
                }
                Err(e) => {
                    rest = &[];
                    Err(e)
                }
            })
        })
    }

    /// The presentation form of a name that carries no pointer.
    ///
    /// The common case, and the one worth not routing through
    /// [`UnpackedDName`]: a QNAME structurally cannot be compressed — nothing
    /// precedes it to point at — and stored RDATA holds its names uncompressed.
    fn to_presentation(&self) -> Result<String, WireError> {
        debug_assert!(!self.compressed, "a pointer needs the message to resolve");
        check_name_len(self.encoded.len())?;
        // One octet per label becomes the separator that follows it, so the text
        // is the encoded length less the root's terminator.
        let mut out = String::with_capacity(self.encoded.len().saturating_sub(1));
        for label in self.labels() {
            match label? {
                Label::String(s) => push_label(&mut out, s)?,
                Label::Root => break,
                Label::Pointer(_) => {
                    return Err(WireError::malformed(
                        "a domain name",
                        "an unpacked name may not contain a compression pointer",
                    ))
                }
            }
        }
        Ok(root_if_empty(out))
    }
}

/// The wire octets of a name that carries no pointer.
///
/// The uncompressed case is a copy: `encoded` already *is* the wire form, and
/// [`DName::try_from_bytes`] has walked its labels. Only the length is left to
/// check, and it is checked here rather than trusted because §2.3.4's limit is
/// on the assembled name (`CLAUDE.md` §17).
impl DName<'_> {
    fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        debug_assert!(!self.compressed, "a pointer needs the message to resolve");
        check_name_len(self.encoded.len())?;
        Ok(self.encoded.to_vec())
    }
}

impl UnpackedDName<'_> {
    /// The resolved labels as wire octets, root terminator included.
    ///
    /// [`UnpackedDName::new`] has already held the assembled length to
    /// §2.3.4's limit, and `unpack_internal` strips the trailing `Root`, which
    /// is why the terminator is added back here.
    fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::with_capacity(MAX_NAME_LEN);
        for label in &self.labels {
            match label {
                Label::String(bytes) => {
                    // `Label::try_from_bytes` held it to `MAX_LABEL_LEN`, so
                    // this cast cannot truncate.
                    out.push(bytes.len() as u8);
                    out.extend_from_slice(bytes);
                }
                Label::Root => break,
                Label::Pointer(_) => {
                    return Err(WireError::malformed(
                        "a domain name",
                        "an unpacked name may not contain a compression pointer",
                    ))
                }
            }
        }
        out.push(0);
        Ok(out)
    }
}

/// One label's text, appended with its separator.
///
/// Shared by the two assemblers so neither can drop a rule the other keeps.
fn push_label(out: &mut String, label: &[u8]) -> Result<(), WireError> {
    let text = std::str::from_utf8(label)?;
    // The other end of `unrepresentable_octet`: a name that cannot be spelled
    // is refused as it is read, so no such `String` ever exists to be compared,
    // keyed on or written.
    if let Some(what) = unrepresentable_octet(text) {
        return Err(WireError::Unsupported { what });
    }
    out.push_str(text);
    out.push('.');
    Ok(())
}

/// Every other name ends up with a trailing dot because each label contributes
/// one. The root has no labels, so it would come back as the empty string —
/// which is not what the rest of the codebase calls the root, and not what we
/// put on the wire when we ask for it. A query for `.` (which is exactly what
/// fetching the root's DNSKEY RRset is) would then fail the reply check, its
/// question having apparently changed from "." to "" in transit.
fn root_if_empty(mut name: String) -> String {
    if name.is_empty() {
        name.push('.');
    }
    name
}

// RFC 1035 §2.3.1's LDH "preferred name syntax" is advice to whoever chooses a
// hostname, not a rule about what the protocol carries: RFC 2181 §11 says "any
// binary string whatever can be used as the label of any resource record", and
// enforcing LDH would refuse `_dmarc`, every `_tcp` SRV owner and `*` itself.
// Only §2.3.4's lengths are enforced — `MAX_LABEL_LEN` here, `MAX_NAME_LEN` in
// `UnpackedDName::new`.
impl<'a> TryFromBytes<'a> for DName<'a> {
    type Output = (DName<'a>, &'a [u8]);
    type Error = WireError;
    fn try_from_bytes(data: &'a [u8]) -> Result<(DName<'a>, &'a [u8]), WireError> {
        let mut len = 0;
        let compressed = loop {
            let lbl = Label::try_from_bytes(&data[len..])?;
            len += lbl.len();
            match lbl {
                Label::String(_) => {}
                Label::Pointer(_) => break true,
                Label::Root => break false,
            }
        };
        let (encoded, rest) = data.split_at(len);
        Ok((
            DName {
                encoded,
                compressed,
            },
            rest,
        ))
    }
}

/// Resolves compression pointers, which are offsets into the whole message.
///
/// The rest of the parser works on suffix slices and so has lost that context;
/// this holds the original bytes to hop about in.
pub struct DNameUnpacker<'a> {
    data: &'a [u8],
}

impl<'a> DNameUnpacker<'a> {
    pub fn new(data: &'a [u8]) -> DNameUnpacker<'a> {
        DNameUnpacker { data }
    }

    /// Follow `name`'s compression pointers into the message.
    ///
    /// `prev_target` is the offset the previous pointer in this chain jumped to;
    /// every later one must land strictly before it.
    fn unpack_internal(
        &self,
        name: DName<'a>,
        depth: usize,
        prev_target: usize,
    ) -> Result<UnpackedDName<'a>, WireError> {
        // Bounds the work, not the correctness: strictly decreasing targets
        // already terminate, but a 14-bit offset leaves ~16k hops per name, each
        // a recursive call and so a stack depth the sender would choose.
        const MAX_DEPTH: usize = 50;

        if depth > MAX_DEPTH {
            return Err(WireError::TooLong {
                what: "compression pointer nesting",
                limit: MAX_DEPTH,
                actual: MAX_DEPTH + 1,
            });
        }

        // A name with no pointer is already unpacked; only a pointer target
        // reaches here that way, since [`DNameUnpacker::decode`] assembles the
        // uncompressed case straight into its `String`.
        //
        // The trailing `Root` comes off because an `UnpackedDName`'s labels are
        // the name's content: the `extend` below would otherwise splice one into
        // the middle of the name that pointed here.
        if !name.compressed {
            let mut labels = name.labels().collect::<Result<Vec<_>, _>>()?;
            if matches!(labels.last(), Some(Label::Root)) {
                labels.pop();
            }
            return UnpackedDName::new(labels);
        }

        let mut output = Vec::new();
        for label in name.labels() {
            match label? {
                label @ Label::String(_) => {
                    output.push(label);
                }
                Label::Pointer(offset) => {
                    if offset >= self.data.len() {
                        return Err(WireError::malformed(
                            "a compression pointer",
                            format!(
                                "offset {offset} is past the {}-byte message",
                                self.data.len()
                            ),
                        ));
                    }

                    // A pointer must point backwards (RFC 1035 §4.1.4: "to a
                    // prior occurance of the same name"), and that comparison is
                    // the whole of cycle prevention — a strictly decreasing
                    // sequence of `usize` cannot repeat, so a cycle is
                    // unreachable rather than detected. Cheaper than the visited
                    // set it replaces, which allocated per compressed name on
                    // the pre-authentication parse path.
                    //
                    // The first hop is unconstrained: a name is parsed from a
                    // suffix slice that does not know its own offset, and
                    // recovering it would mean pointer arithmetic valid only if
                    // every caller passes a slice of the message — an invariant
                    // no type states. One free step does not cost termination.
                    if offset >= prev_target {
                        return Err(WireError::malformed(
                            "a compression pointer",
                            format!(
                                "offset {offset} does not precede the previous target {prev_target}"
                            ),
                        ));
                    }

                    let (name, _) = DName::try_from_bytes(&self.data[offset..])?;
                    let unpacked = self.unpack_internal(name, depth + 1, offset)?;

                    output.extend(unpacked.labels);
                }
                Label::Root => break,
            }
        }
        UnpackedDName::new(output)
    }

    /// `usize::MAX` as the starting `prev_target` leaves the first hop
    /// unconstrained: an offset is 14 bits, so no real target can equal it.
    fn unpack(&self, name: DName<'a>) -> Result<UnpackedDName<'a>, WireError> {
        self.unpack_internal(name, 0, usize::MAX)
    }

    /// The presentation form of a name already read off the wire.
    ///
    /// Split out of [`dname_from_bytes`] so a caller can read *past* a name and
    /// decode it only if it turns out to want it: an OPT record's owner is the
    /// root and is discarded (RFC 6891 §6.1.2), and building it cost a `Vec` and
    /// a `String` on every EDNS query.
    pub(crate) fn decode(&self, name: DName<'a>) -> Result<String, WireError> {
        if name.compressed {
            return self.unpack(name)?.try_into();
        }
        name.to_presentation()
    }

    /// The same name as uncompressed wire octets, for [`crate::Name`].
    ///
    /// The sibling of [`DNameUnpacker::decode`]: same walk, same pointer
    /// resolution, and it keeps the octets instead of spelling them. Here
    /// rather than in `name.rs` because resolving a pointer needs the message
    /// and the depth cap, both of which are this type's.
    pub(crate) fn decode_wire(&self, name: DName<'a>) -> Result<Vec<u8>, WireError> {
        if name.compressed {
            return self.unpack(name)?.to_wire();
        }
        name.to_wire()
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

impl<'a> UnpackedDName<'a> {
    /// The only way to build one, so a name over RFC 1035 §2.3.4's limit is
    /// unrepresentable rather than merely unwelcome.
    ///
    /// Both label-assembling paths meet here, and every intermediate hop of a
    /// pointer chain is built through it too, so a chain is cut off as it grows.
    ///
    /// Measured on the *encoded* length, which is what §2.3.4 limits:
    /// `Label::len` includes each label's length octet, and the root's
    /// terminating zero is added back here since `unpack_internal` has stripped
    /// the trailing `Root`.
    fn new(labels: Vec<Label<'a>>) -> Result<UnpackedDName<'a>, WireError> {
        check_name_len(labels.iter().map(Label::len).sum::<usize>() + 1)?;
        Ok(UnpackedDName { labels })
    }
}

/// The one place RFC 1035 §2.3.4's 255-octet name limit is compared.
///
/// Its two callers — a name off the wire (`UnpackedDName::new`) and one encoded
/// from presentation text (`dname_to_bytes`) — reach `encoded` by different
/// arithmetic, and must agree that it is the encoded length including every
/// length octet and the root's terminating zero.
pub(crate) fn check_name_len(encoded: usize) -> Result<(), WireError> {
    if encoded > MAX_NAME_LEN {
        return Err(WireError::TooLong {
            what: "a domain name",
            limit: MAX_NAME_LEN,
            actual: encoded,
        });
    }
    Ok(())
}

/// Read an uncompressed name from the front of `bytes` as wire octets.
///
/// The [`crate::Name`] door for stored RDATA and anything else with no message
/// behind it: a pointer here is malformed rather than something to follow.
pub(crate) fn name_wire_from_bytes(bytes: &[u8]) -> Result<(Vec<u8>, &[u8]), WireError> {
    let (name, rest) = DName::try_from_bytes(bytes)?;
    if name.compressed {
        return Err(WireError::malformed(
            "a domain name",
            "a compression pointer needs the message it points into",
        ));
    }
    Ok((name.to_wire()?, rest))
}

/// The same, following pointers against the message `unpacker` was built over.
pub(crate) fn name_wire_from_bytes_in<'a>(
    bytes: &'a [u8],
    unpacker: &DNameUnpacker<'a>,
) -> Result<(Vec<u8>, &'a [u8]), WireError> {
    let (name, rest) = DName::try_from_bytes(bytes)?;
    Ok((unpacker.decode_wire(name)?, rest))
}

pub fn dname_from_bytes<'a>(
    bytes: &'a [u8],
    unpacker: &DNameUnpacker<'a>,
) -> Result<(String, &'a [u8]), WireError> {
    let (name, rest) = DName::try_from_bytes(bytes)?;
    Ok((unpacker.decode(name)?, rest))
}

/// Past the name at the start of `data`, returning what follows it.
///
/// For stored RDATA, which [`crate::RecordData`] keeps uncompressed: a pointer
/// here is a malformed record rather than something to follow, since there is no
/// message to resolve it against. [`dname_from_bytes`] is the reading form; this
/// exists for a caller that wants a field *after* a name and would otherwise
/// allocate the name to get past it.
///
/// Not `rdns::tsig`'s `skip_name`, which walks a whole message and so stops
/// at a pointer instead of refusing one.
pub(crate) fn skip_uncompressed_name(data: &[u8]) -> Option<&[u8]> {
    let mut pos = 0;
    loop {
        let len = *data.get(pos)? as usize;
        // A pointer, or one of RFC 6891 §6.1's reserved label types.
        if len & 0xc0 != 0 {
            return None;
        }
        pos += 1;
        if len == 0 {
            return data.get(pos..);
        }
        pos = pos.checked_add(len)?;
    }
}

/// Encode a name in full, without compression.
///
/// This is the form stored in RDATA and the one DNSSEC canonical serialization
/// requires; the message serializer uses the compressor instead.
pub fn dname_to_bytes(name: &str) -> Result<Vec<u8>, WireError> {
    let mut buf = [0u8; MAX_NAME_LEN];
    let len = dname_to_bytes_in(name, &mut buf)?;
    Ok(buf[..len].to_vec())
}

/// [`dname_to_bytes`] into a caller's buffer, returning the encoded length.
///
/// A name never exceeds [`MAX_NAME_LEN`] encoded, so a caller that throws the
/// bytes away can put the buffer on the stack: the NSEC3 closest-encloser walk
/// encodes a name per label of the QNAME (RFC 5155 §8.3) and keeps none of them.
pub fn dname_to_bytes_in(name: &str, buf: &mut [u8]) -> Result<usize, WireError> {
    // A fully-qualified name carries a trailing '.' denoting the root; splitting
    // on '.' would otherwise yield a spurious empty final label (and a second
    // zero byte), which corrupts any record that stores data after the name.
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return write_bytes(buf, 0, &[0]); // the root, on its own
    }

    // `size` is the encoded length §2.3.4 limits: one octet per byte of
    // presentation text holds because a label containing `.` or `\` is refused
    // rather than escaped, so nothing here encodes shorter than it reads.
    // Checked before anything is written, so a name about to be refused costs
    // only the sum.
    let size: usize = name.split('.').map(|l| l.len() + 1).sum::<usize>() + 1;
    check_name_len(size)?;

    // `write_label` validates each label as it writes, so nothing is checked
    // twice here.
    let mut pos = 0;
    for label in name.split('.') {
        pos = write_label(buf, pos, label)?;
    }
    write_bytes(buf, pos, &[0]) // terminate with the root label
}

/// The only route to a string is `bytes -> DName -> unpacker -> UnpackedDName`,
/// so the type system rules out formatting a name fragment.
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
                Label::String(s) => push_label(&mut result, s)?,
                Label::Pointer(_) => {
                    return Err(WireError::malformed(
                        "a domain name",
                        "an unpacked name may not contain a compression pointer",
                    ));
                }
                Label::Root => break,
            }
        }

        Ok(root_if_empty(result))
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

    /// The encode door holds the same 255-octet limit as the parse door
    /// (RFC 1035 §2.3.4), so a name that arrived from a zone file rather than
    /// off the wire cannot be written over-long either.
    ///
    /// This was left open by the commit that closed the parse side and is the
    /// other half of it: `dname_to_bytes` is what a zone file's names go
    /// through, and it sized its buffer from the name without ever asking
    /// whether the total was legal. Watched failing against that behaviour —
    /// without `check_name_len` the over-long cases return `Ok` with a 256- and
    /// a 321-octet buffer.
    ///
    /// The boundary is tested either side, in presentation lengths: four labels
    /// encoding to exactly 255 octets is fine, and one octet more is not.
    #[test]
    fn a_name_over_255_octets_is_not_encoded() {
        let label = "x".repeat(MAX_LABEL_LEN);

        // 3 x 63 = 192 encoded octets, plus a 61-octet label (62) plus the
        // root's zero is exactly 255.
        let exact = format!("{label}.{label}.{label}.{}.", "x".repeat(61));
        let bytes = dname_to_bytes(&exact).expect("exactly 255 octets");
        assert_eq!(bytes.len(), MAX_NAME_LEN);

        // The same name with one more octet in the last label is 256.
        let over = format!("{label}.{label}.{label}.{}.", "x".repeat(62));
        let err = dname_to_bytes(&over).expect_err("256 octets");
        assert!(
            matches!(
                err,
                WireError::TooLong {
                    what: "a domain name",
                    limit: MAX_NAME_LEN,
                    actual: 256,
                }
            ),
            "got {err:?}"
        );

        // And the case that found the parse-side hole, from this direction.
        let five = format!("{label}.{label}.{label}.{label}.{label}.");
        assert!(dname_to_bytes(&five).is_err(), "321 octets");
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

    /// A label may hold any octet (RFC 1035 §3.1), `.` included — and this
    /// library stores a name as presentation text in which `.` is the label
    /// separator. Both cannot be true, so the name is refused rather than
    /// silently flattened.
    ///
    /// Before this check, the one-label name `[03 'a' '.' 'b']` and the
    /// two-label name `[01 'a' 01 'b']` both read as `"a.b."` — two distinct
    /// names collapsing onto one string, which every name-keyed map and every
    /// tree-shaped question in this codebase assumes cannot happen. The visible
    /// consequence was `is_at_or_under("evil.com.", "com.")` answering true
    /// for a single label that is a *sibling* of `com.`, not a child of it.
    ///
    /// NOTIMP rather than FORMERR: the sender is not at fault. A legal encoding
    /// we decline to represent, as `Label` already does for binary labels.
    #[test]
    fn a_label_containing_the_separator_is_refused() {
        // ONE label: 'a', '.', 'b'.
        let one_label: &[u8] = &[0x03, b'a', b'.', b'b', 0x00];
        let unpacker = DNameUnpacker::new(one_label);
        let err = dname_from_bytes(one_label, &unpacker)
            .expect_err("a dot inside a label cannot be represented");
        assert!(matches!(err, WireError::Unsupported { .. }), "got {err:?}");

        // TWO labels spelling the same string are the ordinary name, and fine.
        let two_labels: &[u8] = &[0x01, b'a', 0x01, b'b', 0x00];
        let unpacker = DNameUnpacker::new(two_labels);
        let (name, _) = dname_from_bytes(two_labels, &unpacker).expect("an ordinary name");
        assert_eq!(name, "a.b.");
    }

    /// The same judgement for a backslash, and for the same reason one step
    /// removed: a stored name is presentation text, and presentation text reads
    /// `\` as an escape (RFC 1035 §5.1). A label holding one would be written
    /// into a zone file that no correct reader — including this one — reads back
    /// as the same name.
    #[test]
    fn a_label_containing_a_backslash_is_refused() {
        let wire: &[u8] = &[0x03, b'a', 0x5c, b'b', 0x00];
        let unpacker = DNameUnpacker::new(wire);
        let err = dname_from_bytes(wire, &unpacker).expect_err("an escape character");
        assert!(matches!(err, WireError::Unsupported { .. }), "got {err:?}");
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
            matches!(
                result,
                Err(WireError::Malformed {
                    what: "a compression pointer",
                    ..
                })
            ),
            "got {result:?}"
        );
    }

    /// A name that points at itself is refused — now by arithmetic rather than
    /// by a visited set.
    ///
    /// The first hop is unconstrained (there is no offset to compare it
    /// against), so this is caught on the *second*: offset 0 is reached, the
    /// pointer there targets 0 again, and 0 does not precede 0.
    #[test]
    fn test_cycle_detection_works() {
        let data = &[0xc0, 0x00]; // Pointer to offset 0
        let unpacker = DNameUnpacker::new(data);

        let (dname, _) = DName::try_from_bytes(data).expect("should parse pointer");
        let result = unpacker.unpack(dname);

        assert!(
            matches!(
                result,
                Err(WireError::Malformed {
                    what: "a compression pointer",
                    ..
                })
            ),
            "cycle detection should prevent unpacking, got {result:?}"
        );
    }

    /// The depth limit is enforced on a chain that is otherwise legal.
    ///
    /// This test used to build a chain running *forwards* — `0->2->4->…` — and
    /// so would now be refused by the backwards rule on its second hop, passing
    /// while measuring nothing. Every hop below decreases, so the backwards
    /// check is satisfied throughout and `MAX_DEPTH` is the only thing that can
    /// fire (`CLAUDE.md` §10: say what a test is a regression for).
    #[test]
    fn test_depth_limit_prevents_deep_recursion() {
        // 0x00 at offset 0: a root label, so the chain terminates on its own if
        // it is ever allowed to run to the end.
        let mut data = vec![0u8; 200];
        for i in (2..200).step_by(2) {
            data[i] = 0xc0;
            data[i + 1] = (i - 2) as u8;
        }

        // Entering at the top gives 99 strictly decreasing hops, comfortably
        // past the limit of 50.
        let unpacker = DNameUnpacker::new(&data);
        let (dname, _) = DName::try_from_bytes(&data[198..]).expect("should parse");
        let result = unpacker.unpack(dname);

        assert!(
            matches!(
                result,
                Err(WireError::TooLong {
                    what: "compression pointer nesting",
                    ..
                })
            ),
            "the depth limit should be what fires, got {result:?}"
        );
    }

    /// A pointer must point backwards (RFC 1035 §4.1.4 — a name is replaced
    /// "with a pointer to a prior occurance of the same name"), and a chain that
    /// runs forwards is refused.
    ///
    /// Watched failing against the old code (`CLAUDE.md` §1): with the
    /// visited-offsets set, this chain has no repeated offset, so it unpacked
    /// happily to `"a.b."`. Two hops are needed to demonstrate it because the
    /// first is unconstrained — see `unpack_internal`.
    #[test]
    fn a_pointer_chain_that_runs_forwards_is_refused() {
        let mut data = vec![0u8; 16];
        data[0] = 0xc0; // offset 0: pointer forwards to 6, and nothing to
        data[1] = 6; //             compare it against, so it is allowed
        data[6] = 0x01; // offset 6: the label "a" …
        data[7] = b'a';
        data[8] = 0xc0; //           … then a pointer forwards again, to 12,
        data[9] = 12; //             which does not precede 6
        data[12] = 0x01; // offset 12: the label "b", then the root
        data[13] = b'b';
        data[14] = 0x00;

        let unpacker = DNameUnpacker::new(&data);
        let (dname, _) = DName::try_from_bytes(&data[0..]).expect("the pointer itself parses");
        let result = unpacker.unpack(dname);

        assert!(
            matches!(
                result,
                Err(WireError::Malformed {
                    what: "a compression pointer",
                    ..
                })
            ),
            "a forward chain is not compression, got {result:?}"
        );
    }

    /// The ordinary case, beside the refused one: real compression points
    /// backwards and still works, including through two hops.
    #[test]
    fn an_ordinary_backwards_pointer_chain_still_resolves() {
        // offset 0: "b." (the tail every name below shares)
        // offset 4: the label "a" then a pointer back to 0  => "a.b."
        // offset 8: the label "w" then a pointer back to 4  => "w.a.b."
        let data = vec![
            0x01, b'b', 0x00, 0x00, // 0: "b.", then a spare byte
            0x01, b'a', 0xc0, 0x00, // 4: "a" -> 0
            0x01, b'w', 0xc0, 0x04, // 8: "w" -> 4
        ];
        let unpacker = DNameUnpacker::new(&data);

        let (name, _) = dname_from_bytes(&data[4..], &unpacker).expect("one hop");
        assert_eq!(name, "a.b.");

        let (name, _) = dname_from_bytes(&data[8..], &unpacker).expect("two hops");
        assert_eq!(name, "w.a.b.");
    }

    /// Build an uncompressed name of `labels` labels of `len` octets each,
    /// root-terminated. Its encoded length is `labels * (len + 1) + 1`, which is
    /// the number RFC 1035 §2.3.4 limits.
    fn wire_name(labels: usize, len: usize) -> Vec<u8> {
        let mut data = Vec::new();
        for _ in 0..labels {
            data.push(len as u8);
            data.extend(std::iter::repeat_n(b'x', len));
        }
        data.push(0);
        data
    }

    /// A name over 255 encoded octets is refused (RFC 1035 §2.3.4: "names 255
    /// octets or less"), with the boundary tested on both sides.
    ///
    /// This limit was unenforced until 2026-08-03 while the 63-octet per-label
    /// one was checked on every label — five 63-octet labels parsed to a
    /// 320-character `String` and nothing objected. Watched failing against the
    /// old code: without `UnpackedDName::new`'s check the `is_err` assertions
    /// below fail and the 320-character name comes back `Ok`.
    ///
    /// No pointer is involved in any of these, which is the point: the hole was
    /// not in the compression logic, it was in the total nobody was keeping.
    #[test]
    fn a_name_over_255_octets_is_refused() {
        // 5 x 63 = 321 encoded octets. The case from the probe that found this.
        let data = wire_name(5, MAX_LABEL_LEN);
        let unpacker = DNameUnpacker::new(&data);
        let err = dname_from_bytes(&data, &unpacker).expect_err("321 octets");
        assert!(
            matches!(
                err,
                WireError::TooLong {
                    what: "a domain name",
                    limit: MAX_NAME_LEN,
                    actual: 321,
                }
            ),
            "got {err:?}"
        );

        // The boundary either side. 3 x 63 = 192, plus a 61-octet label (62)
        // plus the root's zero is exactly 255; making that label 62 octets is
        // 256. An off-by-one in the check lands between these two.
        let mut exact = wire_name(3, MAX_LABEL_LEN);
        exact.pop(); // the root, put back after the fourth label
        exact.push(61);
        exact.extend(std::iter::repeat_n(b'x', 61));
        exact.push(0);
        assert_eq!(exact.len(), MAX_NAME_LEN);
        let unpacker = DNameUnpacker::new(&exact);
        let (name, _) = dname_from_bytes(&exact, &unpacker).expect("exactly 255 octets");
        assert_eq!(name.len(), 63 * 3 + 61 + 4, "three dots and one more");

        let mut over = wire_name(3, MAX_LABEL_LEN);
        over.pop();
        over.push(62);
        over.extend(std::iter::repeat_n(b'x', 62));
        over.push(0);
        assert_eq!(over.len(), MAX_NAME_LEN + 1);
        let unpacker = DNameUnpacker::new(&over);
        assert!(
            dname_from_bytes(&over, &unpacker).is_err(),
            "256 octets is one too many"
        );
    }

    /// The same limit holds for a name *assembled* across compression pointers,
    /// which is the second of the two paths through `unpack_internal` and a
    /// separate branch of code from the one above.
    ///
    /// Both halves are legal on their own — 128 and 126 encoded octets — so this
    /// fails against any check placed on the parse of a single name rather than
    /// on the resolved total, which is why the bound sits in `UnpackedDName::new`
    /// where both paths meet.
    #[test]
    fn a_compressed_name_whose_total_exceeds_255_is_refused() {
        // offset 0: two 63-octet labels, then the root. 128 octets.
        let mut data = wire_name(2, MAX_LABEL_LEN);
        let tail = data.len();
        // Then two more 63-octet labels followed by a pointer back to 0, so the
        // resolved name is four 63-octet labels: 4 * 64 + 1 = 257 octets.
        for _ in 0..2 {
            data.push(MAX_LABEL_LEN as u8);
            data.extend(std::iter::repeat_n(b'y', MAX_LABEL_LEN));
        }
        data.push(0xc0);
        data.push(0x00);

        let unpacker = DNameUnpacker::new(&data);

        // The prefix alone resolves: this is not a message that is broken.
        let (name, _) = dname_from_bytes(&data[..tail], &unpacker).expect("the 128-octet half");
        assert_eq!(name.len(), 63 * 2 + 2);

        let err = dname_from_bytes(&data[tail..], &unpacker).expect_err("257 octets resolved");
        assert!(
            matches!(
                err,
                WireError::TooLong {
                    what: "a domain name",
                    limit: MAX_NAME_LEN,
                    actual: 257,
                }
            ),
            "got {err:?}"
        );
    }
}
