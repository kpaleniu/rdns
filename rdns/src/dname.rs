use std::str::from_utf8;

use anyhow::anyhow;

pub(crate) trait TryDeserialize<'a> {
    type Output;
    type Error;

    fn try_deserialize(data: &'a [u8]) -> Result<Self::Output, Self::Error>;
}

// TODO: TrySerialize and others

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

impl<'a> TryDeserialize<'a> for Label<'a> {
    type Output = Label<'a>;
    type Error = anyhow::Error;
    fn try_deserialize(data: &'a [u8]) -> Result<Label<'a>, anyhow::Error> {
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

impl<'a> TryDeserialize<'a> for DName<'a> {
    type Output = (DName<'a>, &'a [u8]);
    type Error = anyhow::Error;
    fn try_deserialize(data: &'a [u8]) -> Result<(DName<'a>, &'a [u8]), anyhow::Error> {
        let mut labels = Vec::new();
        let mut off = data;
        loop {
            let lbl = Label::try_deserialize(off)?;
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
 *   let (val, rest) = sometype::try_deserialize(bytes)?;
 *
 * to simplify how the code reads, this loses the original byte context. We still
 * need a lookup mechanism to hop anywhere in the original set of bytes. Unpacker
 * gets contructed with the original bytes and thus is able to perform the lookup.
 */

pub struct DNameUnpacker<'a> {
    data: &'a [u8],
}

impl<'a> DNameUnpacker<'a> {
    pub fn new(data: &'a [u8]) -> DNameUnpacker<'a> {
        DNameUnpacker { data }
    }

    fn unpack(&self, name: DName<'a>) -> Result<UnpackedDName<'a>, anyhow::Error> {
        let mut output = Vec::new();
        for label in &name.labels {
            match label {
                Label::String(_) => {
                    output.push(label.clone());
                }
                Label::Pointer(offset) => {
                    let (name, _) = DName::try_deserialize(&self.data[*offset..])?;
                    let name = self.unpack(name)?;
                    output.extend(name.labels);
                }
                Label::Root => break,
            }
        }
        Ok(UnpackedDName { labels: output })
    }
}

pub(crate) trait TryUnpackDeserialize<'a> {
    type Output;
    type Error;

    fn try_deserialize(
        data: &'a [u8],
        unpacker: &DNameUnpacker<'a>,
    ) -> Result<Self::Output, Self::Error>;
}

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
    let (name, rest) = DName::try_deserialize(bytes)?;
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
        let mut res = Vec::new();
        for l in &self.labels {
            match l {
                Label::String(s) => {
                    let lbl = std::str::from_utf8(s)?;
                    res.push(lbl.to_string());
                }
                Label::Pointer(_) => {
                    return Err(anyhow!("unpacked names should not contain pointers"));
                }
                Label::Root => {
                    break;
                }
            }
        }
        Ok(res.join(".") + ".")
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

        let lbl = Label::try_deserialize(&data).expect("www");
        let lbl: &str = lbl.try_into().unwrap();
        assert_eq!(lbl, "www");

        let lbl = Label::try_deserialize(&data[4..]).expect("google");
        let lbl: &str = lbl.try_into().unwrap();
        assert_eq!(lbl, "google");

        let lbl = Label::try_deserialize(&data[11..]).expect("fi");
        let lbl: &str = lbl.try_into().unwrap();
        assert_eq!(lbl, "fi");

        assert_eq!(Label::try_deserialize(&data[14..]).unwrap(), Label::Root);
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
}
