use crate::error::WireError;

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

    /// The wire octets of a name that carries no pointer.
    ///
    /// The uncompressed case is a copy: `encoded` already *is* the wire form,
    /// and [`DName::try_from_bytes`] has walked its labels. Only the length is
    /// left to check, and it is checked here rather than trusted because
    /// §2.3.4's limit is on the assembled name (`CLAUDE.md` §17).
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
        // Exact, not `MAX_NAME_LEN`: `Name` keeps a boxed slice, and shrinking
        // an over-sized `Vec` reallocates — one copy per compressed name in
        // every message parsed (`rdns/tests/allocations.rs` read 18 for 15).
        // `new` has already held this sum to §2.3.4's limit.
        let len = self.labels.iter().map(Label::len).sum::<usize>() + 1;
        let mut out = Vec::with_capacity(len);
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
/// Its callers — a name off the wire (`UnpackedDName::new`) and one built from
/// presentation text ([`crate::Name`]) — reach `encoded` by different
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_parse() {
        let data: [u8; 15] = [
            0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69,
            0x00,
        ];

        assert_eq!(
            Label::try_from_bytes(&data).expect("www"),
            Label::String(b"www")
        );
        assert_eq!(
            Label::try_from_bytes(&data[4..]).expect("google"),
            Label::String(b"google")
        );
        assert_eq!(
            Label::try_from_bytes(&data[11..]).expect("fi"),
            Label::String(b"fi")
        );

        assert_eq!(Label::try_from_bytes(&data[14..]).unwrap(), Label::Root);
    }

    #[test]
    fn test_name_parse() {
        let data: [u8; 15] = [
            0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69,
            0x00,
        ];
        let unpacker = DNameUnpacker::new(&data);

        let (s, _) = crate::Name::from_wire_in(&data, &unpacker).expect("www.google.fi");
        assert_eq!(s.as_ref().to_presentation(), "www.google.fi.");
    }

    #[test]
    fn test_name_pack() {
        let data: [u8; 15] = [
            0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x02, 0x66, 0x69,
            0x00,
        ];
        let unpacker = DNameUnpacker::new(&data);

        let (s, _) = crate::Name::from_wire_in(&data, &unpacker).expect("www.google.fi");
        assert_eq!(s.as_ref().to_presentation(), "www.google.fi.");

        let back = crate::Name::from_presentation("www.google.fi.").expect("www.google.fi");
        assert_eq!(back.as_ref().as_wire(), &data);
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
    /// other half of it: the encoder sized its buffer from the name without ever
    /// asking whether the total was legal. Watched failing against that
    /// behaviour — without `check_name_len` the over-long cases return `Ok` with
    /// a 256- and a 321-octet buffer.
    ///
    /// The boundary is tested either side, in presentation lengths: four labels
    /// encoding to exactly 255 octets is fine, and one octet more is not.
    #[test]
    fn a_name_over_255_octets_is_not_encoded() {
        let label = "x".repeat(MAX_LABEL_LEN);

        // 3 x 63 = 192 encoded octets, plus a 61-octet label (62) plus the
        // root's zero is exactly 255.
        let exact = format!("{label}.{label}.{label}.{}.", "x".repeat(61));
        let name = crate::Name::from_presentation(&exact).expect("exactly 255 octets");
        assert_eq!(name.as_ref().as_wire().len(), MAX_NAME_LEN);

        // The same name with one more octet in the last label is 256.
        let over = format!("{label}.{label}.{label}.{}.", "x".repeat(62));
        let err = crate::Name::from_presentation(&over).expect_err("256 octets");
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

        // And the case that found the parse-side hole, from this direction. It
        // reports 256 rather than 321: the encoder stops at the first octet
        // that does not fit and does not decode the rest to total it up.
        let five = format!("{label}.{label}.{label}.{label}.{label}.");
        let err = crate::Name::from_presentation(&five).expect_err("321 octets");
        assert!(
            matches!(err, WireError::TooLong { actual: 256, .. }),
            "got {err:?}"
        );
    }

    /// Encoding rejects what it cannot represent, rather than truncating.
    #[test]
    fn a_bad_label_is_not_encoded() {
        let encode = crate::Name::from_presentation;
        assert!(encode("a..b.").is_err(), "empty label");
        let too_long = "x".repeat(MAX_LABEL_LEN + 1);
        assert!(encode(&format!("{too_long}.com.")).is_err());
        // The longest legal label is still fine.
        let max = "x".repeat(MAX_LABEL_LEN);
        assert!(encode(&format!("{max}.com.")).is_ok());
    }

    /// The root encodes to a single zero octet, with or without the dot.
    #[test]
    fn the_root_encodes_to_one_zero_octet() {
        assert_eq!(
            crate::Name::from_presentation(".")
                .unwrap()
                .as_ref()
                .as_wire(),
            &[0]
        );
        assert_eq!(
            crate::Name::from_presentation("")
                .unwrap()
                .as_ref()
                .as_wire(),
            &[0]
        );
    }

    /// The one-label name `[03 'a' '.' 'b']` and the two-label `[01 'a' 01 'b']`
    /// are different names, and both are legal (RFC 2181 §11).
    ///
    /// Presentation storage read both as `"a.b."` — two names collapsing onto
    /// one string, which every name-keyed map and every tree-shaped question
    /// here assumes cannot happen. `is_at_or_under("evil.com.", "com.")`
    /// answered true for a single label that is a *sibling* of `com.`. #13e
    /// closed that by refusing the first, at the price D-1 named; wire storage
    /// keeps both, and this asserts they stay apart.
    #[test]
    fn a_label_containing_the_separator_is_its_own_name() {
        // ONE label: 'a', '.', 'b'.
        let one_label: &[u8] = &[0x03, b'a', b'.', b'b', 0x00];
        let unpacker = DNameUnpacker::new(one_label);
        let (one, _) = crate::Name::from_wire_in(one_label, &unpacker).expect("one label");
        assert_eq!(one.as_ref().label_count(), 1);
        assert_eq!(one.as_ref().labels().next(), Some(&b"a.b"[..]));

        // TWO labels, which the text form could not tell from the first.
        let two_labels: &[u8] = &[0x01, b'a', 0x01, b'b', 0x00];
        let unpacker = DNameUnpacker::new(two_labels);
        let (two, _) = crate::Name::from_wire_in(two_labels, &unpacker).expect("two labels");
        assert_eq!(two.as_ref().label_count(), 2);
        assert_ne!(one, two, "the collapse D-1 was about");

        // And the tree question they used to answer the same way.
        assert!(!one
            .as_ref()
            .is_at_or_under(two.as_ref().parent().expect("`b.`")));
    }

    /// The same for a backslash: RFC 1035 §5.1's escape is a spelling, not a
    /// restriction on what a label may hold, and `to_presentation` writes it
    /// back as `\\` so a zone file reads the same octets.
    #[test]
    fn a_label_containing_a_backslash_survives() {
        let wire: &[u8] = &[0x03, b'a', 0x5c, b'b', 0x00];
        let unpacker = DNameUnpacker::new(wire);
        let (name, _) =
            crate::Name::from_wire_in(wire, &unpacker).expect("a backslash is an octet");
        assert_eq!(name.as_ref().labels().next(), Some(&b"a\\b"[..]));
        assert_eq!(name.as_ref().to_presentation(), r"a\\b.");
        assert_eq!(name.as_ref().as_wire(), wire);
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

        let (name, _) = crate::Name::from_wire_in(&data[4..], &unpacker).expect("one hop");
        assert_eq!(name.as_ref().to_presentation(), "a.b.");

        let (name, _) = crate::Name::from_wire_in(&data[8..], &unpacker).expect("two hops");
        assert_eq!(name.as_ref().to_presentation(), "w.a.b.");
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
        let err = crate::Name::from_wire_in(&data, &unpacker).expect_err("321 octets");
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
        let (name, _) = crate::Name::from_wire_in(&exact, &unpacker).expect("exactly 255 octets");
        assert_eq!(
            name.as_ref().as_wire().len(),
            MAX_NAME_LEN,
            "the encoded length is what §2.3.4 limits"
        );

        let mut over = wire_name(3, MAX_LABEL_LEN);
        over.pop();
        over.push(62);
        over.extend(std::iter::repeat_n(b'x', 62));
        over.push(0);
        assert_eq!(over.len(), MAX_NAME_LEN + 1);
        let unpacker = DNameUnpacker::new(&over);
        assert!(
            crate::Name::from_wire_in(&over, &unpacker).is_err(),
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
        let (name, _) =
            crate::Name::from_wire_in(&data[..tail], &unpacker).expect("the 128-octet half");
        assert_eq!(name.as_ref().as_wire().len(), 63 * 2 + 2 + 1);

        let err =
            crate::Name::from_wire_in(&data[tail..], &unpacker).expect_err("257 octets resolved");
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
