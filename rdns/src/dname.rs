use std::str::from_utf8;
use std::cell::RefCell;
use std::collections::HashSet;

use anyhow::anyhow;

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
    type Error = anyhow::Error;

    fn try_into(self) -> Result<&'a str, anyhow::Error> {
        match self {
            Label::String(s) => from_utf8(s).or(Err(anyhow!("not a string"))),
            _ => Err(anyhow!("not a string")),
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
    type Error = anyhow::Error;
    fn try_from_bytes(data: &'a [u8]) -> Result<Label<'a>, anyhow::Error> {
        let lt = data[0] >> 6;
        let len = data[0] & 0x3f; // guarantees len cannot be more than 63

        match lt {
            /* normal label */
            0x0 => match len {
                0 => Ok(Label::Root),
                _ => Ok(Label::String(&data[1..=len as usize])),
            },
            /* compressed label */
            0x3 => Ok(Label::Pointer(
                ((data[0] & 0x3f) as usize) << 8 | (data[1] as usize),
            )),
            /* extended label */
            0x1 => match data[0] {
                0x41 => Err(anyhow!("binary label, not supported")),
                0x7f => Err(anyhow!("reseved for future expansion, not supported")),
                _ => Err(anyhow!("unknown label")),
            },
            _ => Err(anyhow!("unknown label")),
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
    type Error = anyhow::Error;
    fn try_from_bytes(data: &'a [u8]) -> Result<(DName<'a>, &'a [u8]), anyhow::Error> {
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
    ) -> Result<UnpackedDName<'a>, anyhow::Error> {
        const MAX_DEPTH: usize = 50;
        
        if depth > MAX_DEPTH {
            return Err(anyhow!("pointer recursion depth limit ({}) exceeded", MAX_DEPTH));
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
                        return Err(anyhow!(
                            "pointer offset {} exceeds message size {}",
                            offset,
                            self.data.len()
                        ));
                    }

                    // Cycle detection: check if we've already visited this offset
                    if self.visited.borrow().contains(offset) {
                        return Err(anyhow!(
                            "circular pointer detected at offset {}",
                            offset
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

    fn unpack(&self, name: DName<'a>) -> Result<UnpackedDName<'a>, anyhow::Error> {
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
) -> Result<(String, &'a [u8]), anyhow::Error> {
    let (name, rest) = DName::try_from_bytes(bytes)?;
    let name = unpacker.unpack(name)?;
    let s = name.try_into()?;
    Ok((s, rest))
}

pub fn dname_to_bytes(name: &str) -> Result<Vec<u8>, anyhow::Error> {
    let mut res = Vec::new();
    for lbl in name.split('.') {
        res.push(lbl.len().try_into()?);
        res.extend_from_slice(lbl.as_bytes());
    }
    res.push(0); // terminate with 'End' label
    Ok(res)
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
                    return Err(anyhow!("unpacked names should not contain pointers"));
                }
                Label::Root => break,
            }
        }
        
        Ok(result)
    }

    type Error = anyhow::Error;
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

    #[test]
    fn test_pointer_bounds_protection() {
        // Test bounds checking with an out-of-bounds pointer
        let data = &[0xc0, 0x50]; // Pointer to offset 80 (message is only 2 bytes)
        let unpacker = DNameUnpacker::new(data);

        let (dname, _) = DName::try_from_bytes(data).expect("should parse pointer");
        let result = unpacker.unpack(dname);
        
        assert!(result.is_err(), "should fail on bounds check");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("out of bounds") || err_msg.contains("exceeds"), 
                "got error: {}", err_msg);
    }

    #[test]
    fn test_cycle_detection_works() {
        // Test that cycle detection catches self-referential pointers
        let data = &[0xc0, 0x00]; // Pointer to offset 0
        let unpacker = DNameUnpacker::new(data);

        let (dname, _) = DName::try_from_bytes(data).expect("should parse pointer");
        let result = unpacker.unpack(dname);
        
        assert!(result.is_err(), "cycle detection should prevent unpacking");
        assert!(result.unwrap_err().to_string().contains("circular"));
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
