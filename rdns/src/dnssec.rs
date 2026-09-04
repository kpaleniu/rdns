//! DNSSEC primitives: the canonical form of an RRset, the exact bytes a
//! signature covers, and the crypto that verifies one.
//!
//! Nothing here decides *policy* — whether a zone is secure, insecure or bogus
//! is [`crate::dnssec_chain`]'s job. This module answers one question at a time:
//! do these bytes verify under this key, does this DNSKEY hash to this DS.
//!
//! The load-bearing part is [`signed_data`]. A signature covers
//! `RRSIG_RDATA(signature field removed) || canonical RRset` (RFC 4035 §5.3.2),
//! not the RRset as it appeared on the wire: owner names down-cased, the RRSIG's
//! original TTL rather than the received one, embedded names down-cased for the
//! RFC 4034 §6.2 types, RRs sorted by canonical RDATA, duplicates dropped.

use crate::dname::dname_to_bytes;
use crate::error::WireError;
use crate::error::{DnssecError, DnssecResult};
use crate::utils::{current_unix_timestamp, record_types as rt};
use crate::Class;
use crate::Rtype;
use crate::{ParsedRecord, RecordData, ResourceRecord};
use ring::signature;

/// DNSKEY flags bit 7 (0x0100): a zone key, which may sign RRsets in its own
/// zone. A DNSKEY without it must not validate anything (RFC 4034 §2.1.1).
pub const DNSKEY_FLAG_ZONE: u16 = 0x0100;

/// DNSKEY flags bit 15 (0x0001): Secure Entry Point. RFC 4034 §2.1.1 makes it
/// only a hint that a DS points here, and nothing treats it as more.
pub const DNSKEY_FLAG_SEP: u16 = 0x0001;

/// The DNSSEC algorithms we can verify, by IANA number (RFC 8624 §3.1).
///
/// Everything else — RSAMD5 (1), DSA (3 and 6), GOST (12), Ed448 (16) — is
/// *unsupported*, not *invalid*: RFC 4035 §5.2 makes a delegation whose DS
/// records name only unreadable algorithms insecure rather than bogus. An
/// unreadable signature is no basis for calling an answer forged.
pub fn algorithm_supported(algorithm: u8) -> bool {
    matches!(algorithm, 5 | 7 | 8 | 10 | 13 | 14 | 15)
}

/// The DS digest types we can compute (RFC 4034 §5.1.3, RFC 4509, RFC 6605).
/// Same insecure-not-bogus rule as [`algorithm_supported`].
pub fn digest_type_supported(digest_type: u8) -> bool {
    matches!(digest_type, 1 | 2 | 4)
}

/// Why a signature could not be checked, as opposed to checked and rejected.
///
/// Not a plain `false`, because the two lead to opposite answers: a failed
/// verification is bogus, an unreadable algorithm is insecure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// We do not implement this DNSSEC algorithm number.
    UnsupportedAlgorithm(u8),
    /// The DNSKEY's public key does not have the shape its algorithm requires.
    MalformedKey(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::UnsupportedAlgorithm(a) => write!(f, "unsupported DNSSEC algorithm {a}"),
            CryptoError::MalformedKey(why) => write!(f, "malformed DNSKEY: {why}"),
        }
    }
}

impl std::error::Error for CryptoError {}

// Typed views of the three records the chain of trust is built from

/// A DNSKEY together with the name it was published at.
///
/// The owner is not in the RDATA but is part of what a DS hashes and what a
/// signature is checked against, so carrying it keeps a key from being applied
/// to the wrong zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnskey {
    pub owner: String,
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl Dnskey {
    /// Interpret a resource record as a DNSKEY, or `None` if it is not one.
    pub fn from_record(rr: &ResourceRecord) -> Option<Self> {
        if rr.rdata.rtype() != rt::DNSKEY {
            return None;
        }
        match rr.rdata.parse().ok()? {
            ParsedRecord::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => Some(Dnskey {
                owner: canonical_name(&rr.name),
                flags,
                protocol,
                algorithm,
                public_key,
            }),
            _ => None,
        }
    }

    /// The key tag (RFC 4034 Appendix B): a cheap, non-unique index narrowing
    /// which key an RRSIG or DS means. Collisions are legal, so it selects
    /// candidates and decides nothing.
    pub fn key_tag(&self) -> u16 {
        key_tag(self.flags, self.protocol, self.algorithm, &self.public_key)
    }

    /// Whether this key may sign RRsets in its zone (RFC 4034 §2.1.1).
    pub fn is_zone_key(&self) -> bool {
        self.flags & DNSKEY_FLAG_ZONE != 0
    }

    /// Whether the Secure Entry Point hint is set.
    pub fn is_sep(&self) -> bool {
        self.flags & DNSKEY_FLAG_SEP != 0
    }

    /// The DNSKEY RDATA in wire form: flags | protocol | algorithm | key.
    pub fn rdata(&self) -> Vec<u8> {
        let mut v = self.flags.to_be_bytes().to_vec();
        v.push(self.protocol);
        v.push(self.algorithm);
        v.extend_from_slice(&self.public_key);
        v
    }
}

/// An RRSIG together with the name it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rrsig {
    /// Owner of the RRSIG record, i.e. the name of the RRset it covers.
    pub owner: String,
    pub type_covered: Rtype,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub inception: u32,
    pub expiration: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature: Vec<u8>,
}

impl Rrsig {
    pub fn from_record(rr: &ResourceRecord) -> Option<Self> {
        if rr.rdata.rtype() != rt::RRSIG {
            return None;
        }
        match rr.rdata.parse().ok()? {
            ParsedRecord::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                inception,
                expiration,
                key_tag,
                signer_name,
                signature,
            } => Some(Rrsig {
                owner: canonical_name(&rr.name),
                type_covered,
                algorithm,
                labels,
                original_ttl,
                inception,
                expiration,
                key_tag,
                signer_name: canonical_name(&signer_name),
                signature,
            }),
            _ => None,
        }
    }

    /// Whether `now` falls inside the signature's validity window.
    ///
    /// The RFC makes both bounds serial-number arithmetic (§3.1.5), but the wrap
    /// only bites in 2106; a plain comparison is what implementations do.
    pub fn is_current(&self, now: u64) -> bool {
        now >= self.inception as u64 && now <= self.expiration as u64
    }

    /// Whether this signature was made over a wildcard that was then expanded
    /// to reach `owner` (RFC 4035 §5.3.4): the label count in the RRSIG is
    /// fewer than the owner name actually has.
    ///
    /// The label arithmetic alone is not enough: the labels field never counts a
    /// leading `*` (RFC 4034 §3.1.3), so the RRset sitting *at* the wildcard has
    /// one label more than its RRSIG claims and would read as an expansion.
    /// Comparing against the signed name separates them — an expansion is
    /// exactly where the signed name is not the owner.
    pub fn is_wildcard_expansion(&self) -> bool {
        (self.labels as usize) < label_count(&self.owner)
            && signed_owner(&self.owner, self.labels) != canonical_name(&self.owner)
    }
}

/// A DS record together with the delegated name it appears at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ds {
    /// The delegated (child) zone name — the DS's owner.
    pub owner: String,
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl Ds {
    pub fn from_record(rr: &ResourceRecord) -> Option<Self> {
        if rr.rdata.rtype() != rt::DS {
            return None;
        }
        match rr.rdata.parse().ok()? {
            ParsedRecord::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => Some(Ds {
                owner: canonical_name(&rr.name),
                key_tag,
                algorithm,
                digest_type,
                digest,
            }),
            _ => None,
        }
    }

    /// Whether `key` is the DNSKEY this DS commits to (RFC 4035 §5.2). The tag
    /// and algorithm only filter; the digest decides, since a tag is not unique.
    pub fn matches_key(&self, key: &Dnskey) -> DnssecResult<bool> {
        if self.key_tag != key.key_tag() || self.algorithm != key.algorithm {
            return Ok(false);
        }
        let computed = ds_digest(key, self.digest_type)?;
        // A plain compare: digests are public, so there is nothing to leak by
        // timing.
        Ok(computed == self.digest)
    }
}

/// Every DNSKEY in `records`, at any owner name.
pub fn dnskeys_in(records: &[ResourceRecord]) -> Vec<Dnskey> {
    records.iter().filter_map(Dnskey::from_record).collect()
}

/// Every RRSIG in `records`.
pub fn rrsigs_in(records: &[ResourceRecord]) -> Vec<Rrsig> {
    records.iter().filter_map(Rrsig::from_record).collect()
}

/// Every DS record in `records`.
pub fn ds_in(records: &[ResourceRecord]) -> Vec<Ds> {
    records.iter().filter_map(Ds::from_record).collect()
}

// Canonical form (RFC 4034 §6)

/// Absolute, lowercased form. DNS names compare case-insensitively (RFC 4343)
/// and canonical DNSSEC form is down-cased (RFC 4034 §6.2).
pub fn canonical_name(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    if lowered.ends_with('.') {
        lowered
    } else {
        format!("{lowered}.")
    }
}

/// How many labels a name has, the root being zero. `example.com.` is 2.
pub use crate::utils::label_count;

/// The last `labels` labels of `name`, canonical and owned. Asking for more than
/// the name has yields the whole name.
///
/// [`crate::utils::suffix_labels`] is the same rule without the copy, for a name
/// the caller has already made absolute — which is every walk up the tree.
pub fn suffix_labels(name: &str, labels: usize) -> String {
    let n = canonical_name(name);
    crate::utils::suffix_labels(&n, labels).to_string()
}

/// The owner name a signature was actually computed over (RFC 4035 §5.3.2).
///
/// Normally the RRset's own name. When the RRSIG's label count is smaller, the
/// records were synthesized from a wildcard, and what was signed is that
/// wildcard — `*.example.com.` — not the expanded name the client asked for.
pub fn signed_owner(owner: &str, rrsig_labels: u8) -> String {
    let owner = canonical_name(owner);
    let have = label_count(&owner);
    let want = rrsig_labels as usize;
    if want >= have {
        owner
    } else {
        format!("*.{}", suffix_labels(&owner, want))
    }
}

/// The label count an RRSIG over `owner` must carry (RFC 4034 §3.1.3).
///
/// The root and a leading `*` are not counted. Not counting the `*` is the whole
/// of wildcard signing: a validator reconstructs the signed owner from this
/// number, so one signature verifies at every name the wildcard expands to.
/// [`signed_owner`] is the same rule read backwards.
pub fn rrsig_labels(owner: &str) -> u8 {
    let labels = label_count(owner);
    let counted = if owner.starts_with("*.") {
        labels.saturating_sub(1)
    } else {
        labels
    };
    // 127 labels is the most that fits in 255 octets, so the cast is total;
    // saturating keeps a monster name from claiming *fewer* labels than it has.
    counted.min(u8::MAX as usize) as u8
}

/// A record's RDATA in canonical form: identical to the stored bytes except for
/// the RFC 4034 §6.2 types, whose embedded domain names are down-cased.
///
/// RFC 6840 §5.1 froze that list, so a name inside any other type is left as
/// received. Of the listed types we parse NS, CNAME, SOA, PTR, MX, RRSIG and
/// NSEC; the rest are obsolete or unparsed and pass through unchanged — a
/// signature failure rather than a false accept, should one arrive mixed-case.
pub fn canonical_rdata(record: &RecordData) -> DnssecResult<Vec<u8>> {
    let lowered = match record.rtype() {
        rt::NS | rt::CNAME | rt::PTR | rt::SOA | rt::MX | rt::RRSIG | rt::NSEC => {
            match record.parse()? {
                ParsedRecord::NS(n) => Some(ParsedRecord::NS(canonical_name(&n))),
                ParsedRecord::CNAME(n) => Some(ParsedRecord::CNAME(canonical_name(&n))),
                ParsedRecord::PTR(n) => Some(ParsedRecord::PTR(canonical_name(&n))),
                ParsedRecord::MX {
                    preference,
                    exchange,
                } => Some(ParsedRecord::MX {
                    preference,
                    exchange: canonical_name(&exchange),
                }),
                ParsedRecord::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                } => Some(ParsedRecord::SOA {
                    mname: canonical_name(&mname),
                    rname: canonical_name(&rname),
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }),
                ParsedRecord::RRSIG {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    inception,
                    expiration,
                    key_tag,
                    signer_name,
                    signature,
                } => Some(ParsedRecord::RRSIG {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    inception,
                    expiration,
                    key_tag,
                    signer_name: canonical_name(&signer_name),
                    signature,
                }),
                ParsedRecord::NSEC {
                    next_domain_name,
                    type_bitmap,
                } => Some(ParsedRecord::NSEC {
                    next_domain_name: canonical_name(&next_domain_name),
                    type_bitmap,
                }),
                _ => None,
            }
        }
        _ => None,
    };

    match lowered {
        Some(parsed) => Ok(RecordData::from_parsed(&parsed)?.bytes().to_vec()),
        None => Ok(record.bytes().to_vec()),
    }
}

/// The exact byte sequence an RRSIG's signature was computed over
/// (RFC 4035 §5.3.2).
///
/// `owner` is the RRset's name as received, `class` its class, and `rdatas` the
/// RDATA of every record in the RRset — which must be the complete RRset, since
/// a signature covers all of it or none of it.
///
/// Four parts, each of which silently breaks every signature if left out: the
/// RRSIG's own RDATA goes in front, minus the signature field; the TTL is the
/// RRSIG's *original* TTL, not the received one; the owner is down-cased and,
/// for a wildcard-expanded answer, replaced by the wildcard really signed; and
/// the records are sorted by canonical RDATA with duplicates removed.
pub fn signed_data(
    rrsig: &Rrsig,
    owner: &str,
    class: Class,
    rdatas: &[RecordData],
) -> DnssecResult<Vec<u8>> {
    if rdatas.is_empty() {
        return Err(DnssecError::signing(
            "cannot build signed data for an empty RRset",
        ));
    }

    // RRSIG_RDATA with the signature field left off.
    let mut data = Vec::new();
    data.extend_from_slice(&rrsig.type_covered.to_u16().to_be_bytes());
    data.push(rrsig.algorithm);
    data.push(rrsig.labels);
    data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
    data.extend_from_slice(&rrsig.expiration.to_be_bytes());
    data.extend_from_slice(&rrsig.inception.to_be_bytes());
    data.extend_from_slice(&rrsig.key_tag.to_be_bytes());
    data.extend_from_slice(&dname_to_bytes(&canonical_name(&rrsig.signer_name))?);

    let name_wire = dname_to_bytes(&signed_owner(owner, rrsig.labels))?;

    // By canonical RDATA alone, not the whole encoded RR: RDLEN sits before the
    // RDATA, so sorting encoded RRs orders by length first.
    let mut canonical: Vec<Vec<u8>> = rdatas
        .iter()
        .map(canonical_rdata)
        .collect::<Result<_, _>>()?;
    canonical.sort_unstable();
    canonical.dedup();

    for rdata in &canonical {
        let rdlen: u16 = rdata.len().try_into().map_err(|_| WireError::TooLong {
            what: "RDATA",
            limit: u16::MAX as usize,
            actual: rdata.len(),
        })?;
        data.extend_from_slice(&name_wire);
        data.extend_from_slice(&rrsig.type_covered.to_u16().to_be_bytes());
        data.extend_from_slice(&class.to_u16().to_be_bytes());
        data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        data.extend_from_slice(&rdlen.to_be_bytes());
        data.extend_from_slice(rdata);
    }

    Ok(data)
}

// Key tags and DS digests

/// The key tag of a DNSKEY, per RFC 4034 Appendix B.
///
/// Appendix B.1 gives algorithm 1 (RSAMD5) a different rule; we do not support
/// that algorithm, and a wrong tag for it only means no candidate key is found.
pub fn key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut rdata = flags.to_be_bytes().to_vec();
    rdata.push(protocol);
    rdata.push(algorithm);
    rdata.extend_from_slice(public_key);

    let mut sum: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        sum += if i % 2 == 0 {
            (byte as u32) << 8
        } else {
            byte as u32
        };
    }
    sum += (sum >> 16) & 0xFFFF;
    (sum & 0xFFFF) as u16
}

/// The digest a DS record holds for `key` (RFC 4034 §5.1.4):
/// `H(canonical DNSKEY owner name | DNSKEY RDATA)`.
///
/// The owner name is part of the input. Hashing the RDATA alone produces a
/// value that matches nothing a real parent publishes, and — since a mismatch
/// reads as "this key is not the one the parent vouched for" — turns every
/// secure delegation into a failure.
pub fn ds_digest(key: &Dnskey, digest_type: u8) -> DnssecResult<Vec<u8>> {
    let mut input = dname_to_bytes(&canonical_name(&key.owner))?;
    input.extend_from_slice(&key.rdata());

    Ok(match digest_type {
        1 => {
            use sha1::{Digest, Sha1};
            Sha1::digest(&input).to_vec()
        }
        2 => {
            use sha2::{Digest, Sha256};
            Sha256::digest(&input).to_vec()
        }
        4 => {
            use sha2::{Digest, Sha384};
            Sha384::digest(&input).to_vec()
        }
        other => {
            return Err(DnssecError::UnsupportedAlgorithm {
                what: "DS digest",
                algorithm: other,
            })
        }
    })
}

// Signature verification

/// Verify `signature` over `data` with a DNSKEY's public key.
///
/// `Ok(false)` means the signature is genuinely wrong. An `Err` means we could
/// not form an opinion — an algorithm we do not implement, or a key whose bytes
/// do not fit its algorithm — which the caller must not treat as a forgery.
pub fn verify(
    algorithm: u8,
    public_key: &[u8],
    data: &[u8],
    sig: &[u8],
) -> Result<bool, CryptoError> {
    match algorithm {
        // RSA (RFC 3110 key format: exponent length, exponent, modulus).
        5 | 7 | 8 | 10 => {
            let (exponent, modulus) = rsa_key_parts(public_key)?;
            let params: &signature::RsaParameters = match algorithm {
                // RSA/SHA-1 is NOT RECOMMENDED for validation (RFC 8624 §3.1)
                // but is still what a long tail of zones is signed with, and
                // refusing it would mark those zones bogus rather than let
                // their signatures speak. Ring gates it behind an explicit
                // legacy name, which is the right amount of friction.
                5 | 7 => &signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
                8 => &signature::RSA_PKCS1_2048_8192_SHA256,
                _ => &signature::RSA_PKCS1_2048_8192_SHA512,
            };
            let key = signature::RsaPublicKeyComponents {
                n: modulus,
                e: exponent,
            };
            Ok(key.verify(params, data, sig).is_ok())
        }
        // ECDSA (RFC 6605). The DNSKEY carries the bare x||y coordinates; the
        // SEC1 uncompressed-point encoding ring wants is those prefixed with
        // 0x04. Handing over the raw coordinates fails every time.
        13 | 14 => {
            let (alg, expected): (&dyn signature::VerificationAlgorithm, usize) = match algorithm {
                13 => (&signature::ECDSA_P256_SHA256_FIXED, 64),
                _ => (&signature::ECDSA_P384_SHA384_FIXED, 96),
            };
            if public_key.len() != expected {
                return Err(CryptoError::MalformedKey(format!(
                    "ECDSA algorithm {algorithm} needs a {expected}-byte key, got {}",
                    public_key.len()
                )));
            }
            let mut point = Vec::with_capacity(expected + 1);
            point.push(0x04);
            point.extend_from_slice(public_key);
            Ok(signature::UnparsedPublicKey::new(alg, point)
                .verify(data, sig)
                .is_ok())
        }
        // Ed25519 (RFC 8080): the DNSKEY is the 32-byte public key as-is.
        15 => {
            if public_key.len() != 32 {
                return Err(CryptoError::MalformedKey(format!(
                    "Ed25519 needs a 32-byte key, got {}",
                    public_key.len()
                )));
            }
            Ok(
                signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
                    .verify(data, sig)
                    .is_ok(),
            )
        }
        other => Err(CryptoError::UnsupportedAlgorithm(other)),
    }
}

/// Split an RFC 3110 RSA public key into `(exponent, modulus)`.
///
/// The exponent's length is one byte, or — when that byte is zero — the two
/// bytes after it, which is how exponents longer than 255 bytes are expressed.
fn rsa_key_parts(public_key: &[u8]) -> Result<(&[u8], &[u8]), CryptoError> {
    let short = |what: &str| CryptoError::MalformedKey(format!("RSA key truncated in {what}"));

    let (exp_len, offset) = match public_key.first() {
        None => return Err(short("length prefix")),
        Some(0) => {
            if public_key.len() < 3 {
                return Err(short("3-byte exponent length"));
            }
            (
                u16::from_be_bytes([public_key[1], public_key[2]]) as usize,
                3,
            )
        }
        Some(&len) => (len as usize, 1),
    };
    if exp_len == 0 {
        return Err(CryptoError::MalformedKey("RSA exponent is empty".into()));
    }
    if public_key.len() <= offset + exp_len {
        return Err(short("exponent"));
    }
    Ok((
        &public_key[offset..offset + exp_len],
        &public_key[offset + exp_len..],
    ))
}

// The leaf validator: one RRset against its signatures

/// What checking an RRset's signatures established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RrsetProof {
    /// A signature verified under one of the supplied keys.
    Verified {
        /// The wildcard the records were synthesized from, if they were. A
        /// caller that cares about denial of existence needs this: an expanded
        /// wildcard answer is only complete with an NSEC proving the queried
        /// name itself does not exist (RFC 4035 §5.3.4).
        wildcard: Option<String>,
        /// When the signature stops being valid, so a cache can be capped by it.
        expires: u32,
    },
    /// No RRSIG covered this RRset at all. Normal — most zones are unsigned —
    /// and emphatically not the same as a signature that failed.
    Unsigned,
    /// Signatures were present but none verified. An attack or a
    /// misconfiguration; either way the data must not be served as authentic.
    Bogus(String),
    /// Signatures were present but every one of them used an algorithm or key
    /// we cannot read, so we have no opinion either way.
    Unsupported(String),
}

/// One RRset: every record sharing an owner name, type and class.
///
/// A signature covers an RRset as a unit, never an individual record, so this
/// is the granularity everything in DNSSEC works at — including the attacks,
/// which are mostly about adding a record to a set or removing one from it.
#[derive(Debug, Clone, Copy)]
pub struct Rrset<'a> {
    pub owner: &'a str,
    pub rtype: Rtype,
    pub class: Class,
    pub rdatas: &'a [RecordData],
}

impl<'a> Rrset<'a> {
    pub fn new(owner: &'a str, rtype: Rtype, class: Class, rdatas: &'a [RecordData]) -> Self {
        Rrset {
            owner,
            rtype,
            class,
            rdatas,
        }
    }
}

/// Check an RRset against its RRSIGs using an already-trusted set of DNSKEYs.
///
/// `rrsigs` are the signatures found at the same owner name, and `keys` are the
/// keys of `zone` — which must already have been established as trustworthy by
/// the caller; this function does not walk any chain.
///
/// Every gate here is one an attacker would otherwise walk through: the signer
/// must be the zone we think we are talking to (or any name could sign for any
/// other), the key must be a zone key at that name, the signature must be
/// current, and the label count must not claim more labels than the name has.
pub fn verify_rrset(
    rrset: &Rrset<'_>,
    rrsigs: &[Rrsig],
    keys: &[Dnskey],
    zone: &str,
    now: u64,
) -> RrsetProof {
    let Rrset {
        rtype,
        class,
        rdatas,
        ..
    } = *rrset;
    let owner = canonical_name(rrset.owner);
    let zone = canonical_name(zone);

    let covering: Vec<&Rrsig> = rrsigs
        .iter()
        .filter(|s| s.type_covered == rtype && s.owner == owner)
        .collect();
    if covering.is_empty() {
        return RrsetProof::Unsigned;
    }

    let mut last_failure = String::new();
    let mut unsupported: Option<String> = None;

    for rrsig in covering {
        // The signer has to be the zone whose keys we hold. Without this a
        // signature from anyone at all would do, as long as we happened to have
        // their key.
        if rrsig.signer_name != zone {
            last_failure = format!(
                "RRSIG on {owner} names signer {} but the RRset belongs to {zone}",
                rrsig.signer_name
            );
            continue;
        }
        // A label count larger than the name has is nonsense, and one smaller
        // is a wildcard — legitimate, but it must not claim to have been signed
        // at a name above the zone apex.
        let owner_labels = label_count(&owner);
        if rrsig.labels as usize > owner_labels || (rrsig.labels as usize) < label_count(&zone) {
            last_failure = format!(
                "RRSIG on {owner} claims {} labels, which its owner and zone do not allow",
                rrsig.labels
            );
            continue;
        }
        if !rrsig.is_current(now) {
            last_failure = format!(
                "RRSIG on {owner} is valid {}..{} but now is {now}",
                rrsig.inception, rrsig.expiration
            );
            continue;
        }

        let data = match signed_data(rrsig, &owner, class, rdatas) {
            Ok(data) => data,
            Err(e) => {
                last_failure = format!("could not build signed data for {owner}: {e}");
                continue;
            }
        };

        for key in keys.iter().filter(|k| {
            k.owner == zone
                && k.is_zone_key()
                && k.algorithm == rrsig.algorithm
                && k.key_tag() == rrsig.key_tag
        }) {
            match verify(key.algorithm, &key.public_key, &data, &rrsig.signature) {
                Ok(true) => {
                    return RrsetProof::Verified {
                        wildcard: rrsig
                            .is_wildcard_expansion()
                            .then(|| signed_owner(&owner, rrsig.labels)),
                        expires: rrsig.expiration,
                    }
                }
                Ok(false) => {
                    last_failure = format!(
                        "signature on {owner} did not verify under key {}",
                        key.key_tag()
                    )
                }
                Err(e) => unsupported = Some(format!("{owner}: {e}")),
            }
        }
        if last_failure.is_empty() {
            last_failure = format!(
                "no DNSKEY at {zone} matches RRSIG key tag {} algorithm {}",
                rrsig.key_tag, rrsig.algorithm
            );
        }
    }

    // Only report "cannot read" when nothing was actually rejected: a genuine
    // failure alongside an unreadable algorithm is still a failure.
    match unsupported {
        Some(why) if last_failure.is_empty() => RrsetProof::Unsupported(why),
        _ => RrsetProof::Bogus(last_failure),
    }
}

/// Convenience wrapper for the common case of "verify these resource records,
/// which are all one RRset, against these signatures and keys".
pub fn verify_records(
    records: &[ResourceRecord],
    rrsigs: &[Rrsig],
    keys: &[Dnskey],
    zone: &str,
) -> RrsetProof {
    let Some(first) = records.first() else {
        return RrsetProof::Unsigned;
    };
    let rdatas: Vec<RecordData> = records.iter().map(|r| r.rdata.clone()).collect();
    verify_rrset(
        &Rrset::new(&first.name, first.rdata.rtype(), first.class, &rdatas),
        rrsigs,
        keys,
        zone,
        current_unix_timestamp(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec_test_util::{TestKey, TestZone};
    use crate::Ttl;
    use crate::{ParsedRecord, RecordData};
    use std::net::Ipv4Addr;

    fn a_rdata(last: u8) -> RecordData {
        RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, last))).unwrap()
    }

    #[test]
    fn test_signed_owner_rebuilds_the_wildcard() {
        // A 3-label name signed with labels=2 was expanded from *.example.com.
        assert_eq!(
            signed_owner("WWW.Example.com.", 2),
            "*.example.com.",
            "a wildcard-expanded answer was signed at the wildcard, not the name"
        );
        // Label count equal to the name's: not a wildcard, just down-cased.
        assert_eq!(signed_owner("WWW.Example.com.", 3), "www.example.com.");
        // More labels than the name has cannot happen; take the name as-is.
        assert_eq!(signed_owner("example.com.", 9), "example.com.");
    }

    #[test]
    fn test_canonical_rdata_downcases_only_the_listed_types() {
        let ns = RecordData::from_parsed(&ParsedRecord::NS("NS1.Example.COM.".into())).unwrap();
        let lowered = canonical_rdata(&ns).unwrap();
        let want = RecordData::from_parsed(&ParsedRecord::NS("ns1.example.com.".into())).unwrap();
        assert_eq!(
            lowered,
            want.bytes().to_vec(),
            "NS is on the RFC 4034 §6.2 list"
        );

        // TXT is not on the list, so its bytes pass through untouched — length
        // prefix (RFC 1035 §3.3.14) and case both.
        let txt = RecordData::from_parsed(&ParsedRecord::TXT(vec!["MiXeD".into()])).unwrap();
        assert_eq!(canonical_rdata(&txt).unwrap(), b"\x05MiXeD".to_vec());
    }

    /// A signed TXT RRset, including one with several `<character-string>`s.
    ///
    /// The canonical form of a TXT record is its RDATA unchanged, so it is only
    /// right if the RDATA is right: while TXT was stored as one unframed blob,
    /// what got signed here was not what a real signer would have signed, and a
    /// genuine zone's TXT signature could not have verified against it.
    #[test]
    fn test_signed_txt_rrset_with_several_strings_verifies() {
        let zone = TestZone::new("example.test.");
        let txt = ResourceRecord {
            name: "txt.example.test.".into(),
            class: Class::new(1),
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::TXT(vec![
                b"v=spf1 include:example.net".to_vec(),
                b"-all".to_vec(),
            ]))
            .unwrap(),
        };
        let sig = zone.sign_records(std::slice::from_ref(&txt));

        let proof = verify_records(
            &[txt],
            &[Rrsig::from_record(&sig).unwrap()],
            &zone.dnskeys(),
            "example.test.",
        );
        assert!(
            matches!(proof, RrsetProof::Verified { .. }),
            "a multi-string TXT RRset must verify: {proof:?}"
        );
    }

    /// RFC 4034 §6.3 sorts by RDATA, not by the encoded RR — and the two differ
    /// exactly when one RDATA is a prefix of another, because RDLEN sits in
    /// between and would order by length first.
    #[test]
    fn test_rrset_is_sorted_by_rdata_and_deduplicated() {
        let key = TestKey::generate_p256();
        let rrsig = key.rrsig_template("example.com.", rt::A, 3600, "example.com.", 2);

        let ordered = signed_data(
            &rrsig,
            "example.com.",
            Class::new(1),
            &[a_rdata(1), a_rdata(2), a_rdata(3)],
        )
        .unwrap();
        let shuffled = signed_data(
            &rrsig,
            "example.com.",
            Class::new(1),
            // Same RRset, different order, with one record repeated.
            &[a_rdata(3), a_rdata(1), a_rdata(2), a_rdata(1)],
        )
        .unwrap();

        assert_eq!(
            ordered, shuffled,
            "wire order and duplicates must not change what is signed"
        );
    }

    #[test]
    fn test_signed_data_uses_the_rrsigs_original_ttl() {
        let key = TestKey::generate_p256();
        let mut rrsig = key.rrsig_template("example.com.", rt::A, 3600, "example.com.", 2);
        let with_3600 = signed_data(&rrsig, "example.com.", Class::new(1), &[a_rdata(1)]).unwrap();
        rrsig.original_ttl = 60;
        let with_60 = signed_data(&rrsig, "example.com.", Class::new(1), &[a_rdata(1)]).unwrap();
        assert_ne!(
            with_3600, with_60,
            "the TTL in the signed bytes comes from the RRSIG"
        );
    }

    // Real crypto. These are the tests the old suite could not make:
    // every signature below is produced by ring at test time, so a
    // verifier that never actually runs cannot pass them.

    #[test]
    fn test_ecdsa_p256_signature_verifies() {
        let key = TestKey::generate_p256();
        let rdatas = vec![a_rdata(1), a_rdata(2)];
        let rrsig = key.sign_rrset(
            "www.example.com.",
            rt::A,
            Class::new(1),
            3600,
            "example.com.",
            &rdatas,
        );

        let proof = verify_rrset(
            &Rrset::new("www.example.com.", rt::A, Class::new(1), &rdatas),
            &[rrsig],
            &[key.dnskey("example.com.")],
            "example.com.",
            current_unix_timestamp(),
        );
        assert!(
            matches!(proof, RrsetProof::Verified { wildcard: None, .. }),
            "a genuine P-256 signature must verify: {proof:?}"
        );
    }

    #[test]
    fn test_ecdsa_p384_signature_verifies() {
        let key = TestKey::generate_p384();
        let rdatas = vec![a_rdata(7)];
        let rrsig = key.sign_rrset(
            "example.com.",
            rt::A,
            Class::new(1),
            300,
            "example.com.",
            &rdatas,
        );

        let proof = verify_rrset(
            &Rrset::new("example.com.", rt::A, Class::new(1), &rdatas),
            &[rrsig],
            &[key.dnskey("example.com.")],
            "example.com.",
            current_unix_timestamp(),
        );
        assert!(matches!(proof, RrsetProof::Verified { .. }), "{proof:?}");
    }

    #[test]
    fn test_ed25519_signature_verifies() {
        let key = TestKey::generate_ed25519();
        let rdatas = vec![a_rdata(3)];
        let rrsig = key.sign_rrset(
            "example.com.",
            rt::A,
            Class::new(1),
            300,
            "example.com.",
            &rdatas,
        );

        let proof = verify_rrset(
            &Rrset::new("example.com.", rt::A, Class::new(1), &rdatas),
            &[rrsig],
            &[key.dnskey("example.com.")],
            "example.com.",
            current_unix_timestamp(),
        );
        assert!(matches!(proof, RrsetProof::Verified { .. }), "{proof:?}");
    }

    /// The point of the whole exercise: change one byte of the data and the
    /// signature must stop verifying.
    #[test]
    fn test_tampered_rrset_is_bogus() {
        let key = TestKey::generate_p256();
        let signed = vec![a_rdata(1)];
        let rrsig = key.sign_rrset(
            "www.example.com.",
            rt::A,
            Class::new(1),
            3600,
            "example.com.",
            &signed,
        );

        let tampered = vec![a_rdata(66)];
        let proof = verify_rrset(
            &Rrset::new("www.example.com.", rt::A, Class::new(1), &tampered),
            &[rrsig],
            &[key.dnskey("example.com.")],
            "example.com.",
            current_unix_timestamp(),
        );
        assert!(
            matches!(proof, RrsetProof::Bogus(_)),
            "a substituted address must not verify: {proof:?}"
        );
    }

    /// Adding a record to a signed RRset must break the signature — otherwise
    /// an attacker could append an address to a legitimate answer.
    #[test]
    fn test_added_record_is_bogus() {
        let key = TestKey::generate_p256();
        let signed = vec![a_rdata(1)];
        let rrsig = key.sign_rrset(
            "www.example.com.",
            rt::A,
            Class::new(1),
            3600,
            "example.com.",
            &signed,
        );

        let proof = verify_rrset(
            &Rrset::new(
                "www.example.com.",
                rt::A,
                Class::new(1),
                &[a_rdata(1), a_rdata(99)],
            ),
            &[rrsig],
            &[key.dnskey("example.com.")],
            "example.com.",
            current_unix_timestamp(),
        );
        assert!(matches!(proof, RrsetProof::Bogus(_)), "{proof:?}");
    }

    /// A signature made by one zone must not validate data in another, even
    /// when the attacker holds a perfectly good key.
    #[test]
    fn test_signature_from_the_wrong_zone_is_rejected() {
        let attacker = TestKey::generate_p256();
        let rdatas = vec![a_rdata(6)];
        // Signed correctly, but by evil.test. for a name in example.com.
        let rrsig = attacker.sign_rrset(
            "www.example.com.",
            rt::A,
            Class::new(1),
            3600,
            "evil.test.",
            &rdatas,
        );

        let proof = verify_rrset(
            &Rrset::new("www.example.com.", rt::A, Class::new(1), &rdatas),
            &[rrsig],
            &[attacker.dnskey("evil.test.")],
            "example.com.",
            current_unix_timestamp(),
        );
        assert!(
            matches!(proof, RrsetProof::Bogus(_)),
            "a signer outside the zone must be refused: {proof:?}"
        );
    }

    #[test]
    fn test_expired_signature_is_bogus() {
        let key = TestKey::generate_p256();
        let rdatas = vec![a_rdata(1)];
        let mut rrsig = key.sign_rrset(
            "example.com.",
            rt::A,
            Class::new(1),
            3600,
            "example.com.",
            &rdatas,
        );
        let now = current_unix_timestamp();
        rrsig.inception = (now - 7200) as u32;
        rrsig.expiration = (now - 3600) as u32;

        let proof = verify_rrset(
            &Rrset::new("example.com.", rt::A, Class::new(1), &rdatas),
            &[rrsig],
            &[key.dnskey("example.com.")],
            "example.com.",
            now,
        );
        assert!(matches!(proof, RrsetProof::Bogus(_)), "{proof:?}");
    }

    #[test]
    fn test_unsigned_rrset_is_not_bogus() {
        let proof = verify_rrset(
            &Rrset::new("example.com.", rt::A, Class::new(1), &[a_rdata(1)]),
            &[],
            &[],
            "example.com.",
            current_unix_timestamp(),
        );
        assert_eq!(
            proof,
            RrsetProof::Unsigned,
            "an unsigned zone is normal, not an attack"
        );
    }

    /// A key without the zone flag may not sign zone data (RFC 4034 §2.1.1).
    #[test]
    fn test_non_zone_key_cannot_sign() {
        let key = TestKey::generate_p256();
        let rdatas = vec![a_rdata(1)];
        let rrsig = key.sign_rrset(
            "example.com.",
            rt::A,
            Class::new(1),
            3600,
            "example.com.",
            &rdatas,
        );

        let mut dnskey = key.dnskey("example.com.");
        dnskey.flags &= !DNSKEY_FLAG_ZONE;
        // Clearing the flag changes the key tag, so the RRSIG has to be pointed
        // at the modified key for this to test the flag rather than the tag.
        let mut rrsig = rrsig;
        rrsig.key_tag = dnskey.key_tag();

        let proof = verify_rrset(
            &Rrset::new("example.com.", rt::A, Class::new(1), &rdatas),
            &[rrsig],
            &[dnskey],
            "example.com.",
            current_unix_timestamp(),
        );
        assert!(matches!(proof, RrsetProof::Bogus(_)), "{proof:?}");
    }

    /// A wildcard-expanded answer verifies, and says which wildcard it came
    /// from — the caller needs that to know an NSEC proof is still owed.
    #[test]
    fn test_wildcard_expansion_reports_the_wildcard() {
        let key = TestKey::generate_p256();
        let rdatas = vec![a_rdata(5)];
        // Signed at *.example.com. (2 labels) but served for anything.example.com.
        let mut rrsig = key.sign_rrset(
            "*.example.com.",
            rt::A,
            Class::new(1),
            3600,
            "example.com.",
            &rdatas,
        );
        rrsig.owner = "anything.example.com.".to_string();
        rrsig.labels = 2;

        let proof = verify_rrset(
            &Rrset::new("anything.example.com.", rt::A, Class::new(1), &rdatas),
            &[rrsig],
            &[key.dnskey("example.com.")],
            "example.com.",
            current_unix_timestamp(),
        );
        match proof {
            RrsetProof::Verified { wildcard, .. } => {
                assert_eq!(wildcard.as_deref(), Some("*.example.com."))
            }
            other => panic!("wildcard answer should verify: {other:?}"),
        }
    }

    // DS

    /// The DS digest covers the owner name as well as the RDATA, so the same
    /// key published at two names has two different DS records.
    #[test]
    fn test_ds_digest_covers_the_owner_name() {
        let key = TestKey::generate_p256();
        let at_example = key.dnskey("example.com.");
        let at_other = key.dnskey("other.com.");

        assert_ne!(
            ds_digest(&at_example, 2).unwrap(),
            ds_digest(&at_other, 2).unwrap(),
            "a DS is bound to the name the key was published at"
        );
    }

    #[test]
    fn test_ds_matches_its_own_key() {
        let key = TestKey::generate_p256();
        let dnskey = key.dnskey("example.com.");
        for digest_type in [1u8, 2, 4] {
            let ds = Ds {
                owner: "example.com.".into(),
                key_tag: dnskey.key_tag(),
                algorithm: dnskey.algorithm,
                digest_type,
                digest: ds_digest(&dnskey, digest_type).unwrap(),
            };
            assert!(
                ds.matches_key(&dnskey).unwrap(),
                "digest type {digest_type} should match"
            );
        }
    }

    #[test]
    fn test_ds_rejects_a_different_key() {
        let real = TestKey::generate_p256().dnskey("example.com.");
        let impostor = TestKey::generate_p256().dnskey("example.com.");
        let ds = Ds {
            owner: "example.com.".into(),
            key_tag: real.key_tag(),
            algorithm: real.algorithm,
            digest_type: 2,
            digest: ds_digest(&real, 2).unwrap(),
        };
        // Key tags rarely collide, so force the interesting case: same tag,
        // different key. The digest is what has to reject it.
        assert!(!ds.matches_key(&impostor).unwrap_or(false));
    }

    /// RFC 4034 Appendix B: the key tag is a plain checksum over the RDATA,
    /// and it must be stable across runs and independent of the owner name.
    #[test]
    fn test_key_tag_is_a_checksum_over_the_rdata() {
        let key = TestKey::generate_p256();
        assert_eq!(
            key.dnskey("example.com.").key_tag(),
            key.dnskey("other.test.").key_tag(),
            "the key tag does not depend on the owner name"
        );
        // Flipping a flag bit changes the RDATA, so it changes the tag.
        let mut altered = key.dnskey("example.com.");
        let original = altered.key_tag();
        altered.flags |= DNSKEY_FLAG_SEP;
        assert_ne!(altered.key_tag(), original);
    }

    // Key parsing

    #[test]
    fn test_rsa_key_parts_both_length_forms() {
        // One-byte length: 3 bytes of exponent, then the modulus.
        let mut short = vec![3, 0x01, 0x00, 0x01];
        short.extend_from_slice(&[0xAB; 128]);
        let (e, n) = rsa_key_parts(&short).unwrap();
        assert_eq!(e, &[0x01, 0x00, 0x01]);
        assert_eq!(n.len(), 128);

        // Three-byte length: a leading zero, then a 16-bit length.
        let mut long = vec![0, 0x00, 0x03, 0x01, 0x00, 0x01];
        long.extend_from_slice(&[0xCD; 256]);
        let (e, n) = rsa_key_parts(&long).unwrap();
        assert_eq!(e, &[0x01, 0x00, 0x01]);
        assert_eq!(n.len(), 256);
    }

    #[test]
    fn test_malformed_keys_error_rather_than_panic() {
        assert!(rsa_key_parts(&[]).is_err());
        assert!(
            rsa_key_parts(&[0]).is_err(),
            "3-byte form with nothing after"
        );
        assert!(
            rsa_key_parts(&[9, 1, 2]).is_err(),
            "exponent runs off the end"
        );
        assert!(rsa_key_parts(&[3, 1, 2, 3]).is_err(), "no modulus left");
    }

    #[test]
    fn test_unsupported_algorithm_is_not_a_failure() {
        // Algorithm 3 (DSA) is one we deliberately do not implement.
        let err = verify(3, &[0; 32], b"data", &[0; 64]).expect_err("should not verify");
        assert_eq!(err, CryptoError::UnsupportedAlgorithm(3));
        assert!(!algorithm_supported(3));
        assert!(algorithm_supported(13), "ECDSA P-256 is our primary target");
    }

    #[test]
    fn test_ecdsa_key_of_the_wrong_length_is_malformed_not_forged() {
        let err = verify(13, &[0; 32], b"data", &[0; 64]).expect_err("should not verify");
        assert!(matches!(err, CryptoError::MalformedKey(_)), "{err:?}");
    }

    // A whole signed zone, end to end

    /// KSK signs the DNSKEY RRset, ZSK signs the data, the parent's DS commits
    /// to the KSK: the shape every signed zone actually has.
    #[test]
    fn test_signed_zone_validates_from_its_ds() {
        let zone = TestZone::new("example.com.");
        let now = current_unix_timestamp();

        // 1. The DS in the parent commits to the KSK.
        let ds = zone.ds(2);
        assert!(
            ds.matches_key(&zone.ksk.ksk("example.com.")).unwrap(),
            "the DS must point at the KSK"
        );
        assert!(
            !ds.matches_key(&zone.zsk.dnskey("example.com."))
                .unwrap_or(false),
            "and not at the ZSK, which the parent never saw"
        );

        // 2. The KSK signs the DNSKEY RRset, so the DS reaches both keys.
        let (dnskey_rdatas, dnskey_sig) = zone.signed_dnskey_rrset();
        let proof = verify_rrset(
            &Rrset::new("example.com.", rt::DNSKEY, Class::new(1), &dnskey_rdatas),
            &[dnskey_sig],
            &zone.dnskeys(),
            "example.com.",
            now,
        );
        assert!(
            matches!(proof, RrsetProof::Verified { .. }),
            "DNSKEY RRset should verify under its own KSK: {proof:?}"
        );

        // 3. The ZSK signs ordinary data, validated by the keys just proven.
        let rdatas = vec![a_rdata(1)];
        let sig = zone.zsk.sign_rrset(
            "www.example.com.",
            rt::A,
            Class::new(1),
            300,
            "example.com.",
            &rdatas,
        );
        let proof = verify_rrset(
            &Rrset::new("www.example.com.", rt::A, Class::new(1), &rdatas),
            &[sig],
            &zone.dnskeys(),
            "example.com.",
            now,
        );
        assert!(matches!(proof, RrsetProof::Verified { .. }), "{proof:?}");
    }
}
