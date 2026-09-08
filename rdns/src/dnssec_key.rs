//! Private keys, and the signatures they make.
//!
//! The other half of [`crate::dnssec`], which holds the public side and can say
//! whether a signature is good but cannot make one.
//!
//! The key file format is ours: PKCS#8 as `ring` hands it over, base64, with the
//! owner name and flags beside it, extension `.rdnskey`. BIND's `.private` body
//! differs per algorithm and keeps the public half in a separate `.key`, and
//! reassembling PKCS#8 from the two is a conversion whose failure mode is a key
//! signing with the wrong identity. `openssl genpkey` output imports as-is.
//!
//! The owner and flags live in the file, not in the caller: both feed the key
//! tag, so deciding them at the call site would give one key different tags
//! depending on who loaded it, and every RRSIG naming that tag would point at a
//! key nobody can find.

use crate::dnssec::{
    ds_digest, key_tag, rrsig_labels_of, signed_data, Dnskey, Ds, Rrset, Rrsig, DNSKEY_FLAG_SEP,
    DNSKEY_FLAG_ZONE,
};
use crate::error::DnssecError;
use crate::error::DnssecResult as Result;
use crate::utils::base64_encode;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING, RSA_PKCS1_SHA256, RSA_PKCS1_SHA512,
};
use std::path::{Path, PathBuf};

/// The extension a key file carries, and what a key directory is scanned for.
pub const KEY_FILE_EXTENSION: &str = "rdnskey";

/// An algorithm we can sign with — a subset of what [`crate::dnssec::verify`]
/// accepts. A validator must read whatever the internet signed with; a signer
/// picks, and RFC 8624 §3.1 is the list of what may be picked. So RSA/SHA-1 (5
/// and 7) is verifiable and not signable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// 13 — RFC 6605. The default: small keys, small signatures, universally
    /// implemented.
    EcdsaP256Sha256,
    /// 14 — RFC 6605.
    EcdsaP384Sha384,
    /// 15 — RFC 8080.
    Ed25519,
    /// 8 — RFC 5702. Import only; `ring` does not generate RSA keys.
    RsaSha256,
    /// 10 — RFC 5702. Import only.
    RsaSha512,
}

impl SigningAlgorithm {
    /// The DNSKEY algorithm number.
    pub fn code(self) -> u8 {
        match self {
            SigningAlgorithm::RsaSha256 => 8,
            SigningAlgorithm::RsaSha512 => 10,
            SigningAlgorithm::EcdsaP256Sha256 => 13,
            SigningAlgorithm::EcdsaP384Sha384 => 14,
            SigningAlgorithm::Ed25519 => 15,
        }
    }

    /// The registry mnemonic, as it appears in a key file and in `--algorithm`.
    pub fn name(self) -> &'static str {
        match self {
            SigningAlgorithm::RsaSha256 => "RSASHA256",
            SigningAlgorithm::RsaSha512 => "RSASHA512",
            SigningAlgorithm::EcdsaP256Sha256 => "ECDSAP256SHA256",
            SigningAlgorithm::EcdsaP384Sha384 => "ECDSAP384SHA384",
            SigningAlgorithm::Ed25519 => "ED25519",
        }
    }

    pub fn from_code(code: u8) -> Result<Self> {
        Ok(match code {
            8 => SigningAlgorithm::RsaSha256,
            10 => SigningAlgorithm::RsaSha512,
            13 => SigningAlgorithm::EcdsaP256Sha256,
            14 => SigningAlgorithm::EcdsaP384Sha384,
            15 => SigningAlgorithm::Ed25519,
            5 | 7 => {
                return Err(DnssecError::key(format!(
                    "algorithm {code} (RSA/SHA-1) can be verified but not signed with: \
                 RFC 8624 §3.1 lists it MUST NOT for signing",
                )))
            }
            other => {
                return Err(DnssecError::UnsupportedAlgorithm {
                    what: "signing",
                    algorithm: other,
                })
            }
        })
    }

    /// Either the number or the mnemonic.
    pub fn parse(text: &str) -> Result<Self> {
        if let Ok(code) = text.trim().parse::<u8>() {
            return Self::from_code(code);
        }
        let wanted = text.trim();
        [
            SigningAlgorithm::EcdsaP256Sha256,
            SigningAlgorithm::EcdsaP384Sha384,
            SigningAlgorithm::Ed25519,
            SigningAlgorithm::RsaSha256,
            SigningAlgorithm::RsaSha512,
        ]
        .into_iter()
        .find(|a| a.name().eq_ignore_ascii_case(wanted))
        .ok_or_else(|| {
            DnssecError::key(format!(
                "{text:?} is not a signing algorithm this build knows"
            ))
        })
    }

    /// Whether a key of this algorithm can be created here rather than only
    /// loaded. `ring` has no RSA key generation.
    pub fn can_generate(self) -> bool {
        !matches!(
            self,
            SigningAlgorithm::RsaSha256 | SigningAlgorithm::RsaSha512
        )
    }
}

/// The `ring` keypair behind a [`SigningKey`]. All three boxed: an
/// `EcdsaKeyPair` alone is 240 bytes.
enum Pair {
    Ecdsa(Box<EcdsaKeyPair>),
    Ed25519(Box<Ed25519KeyPair>),
    Rsa(Box<RsaKeyPair>),
}

/// A private key that can sign an RRset for one zone.
pub struct SigningKey {
    owner: String,
    flags: u16,
    algorithm: SigningAlgorithm,
    /// The public half in DNSKEY form, which is not `ring`'s form for ECDSA or
    /// RSA.
    public_key: Vec<u8>,
    /// Kept so the key writes back out without a second encoding path.
    pkcs8: Vec<u8>,
    pair: Pair,
}

impl std::fmt::Debug for SigningKey {
    /// Hand-written so the private bytes never reach a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("owner", &self.owner)
            .field("flags", &self.flags)
            .field("algorithm", &self.algorithm.name())
            .field("key_tag", &self.key_tag())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Create a key. `flags` is the DNSKEY flags field —
    /// [`DNSKEY_FLAG_ZONE`] for a zone-signing key, plus [`DNSKEY_FLAG_SEP`]
    /// for a key-signing key.
    pub fn generate(algorithm: SigningAlgorithm, owner: &str, flags: u16) -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = match algorithm {
            SigningAlgorithm::EcdsaP256Sha256 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .map_err(|e| DnssecError::key(format!("generating a P-256 key: {e}")))?
                    .as_ref()
                    .to_vec()
            }
            SigningAlgorithm::EcdsaP384Sha384 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng)
                    .map_err(|e| DnssecError::key(format!("generating a P-384 key: {e}")))?
                    .as_ref()
                    .to_vec()
            }
            SigningAlgorithm::Ed25519 => Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|e| DnssecError::key(format!("generating an Ed25519 key: {e}")))?
                .as_ref()
                .to_vec(),
            rsa => {
                return Err(DnssecError::key(format!(
                    "{} keys cannot be generated here — ring implements RSA signing but not \
                     RSA key generation. Make one elsewhere and import the PKCS#8: \
                     openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
                     -outform DER -out key.der",
                    rsa.name(),
                )))
            }
        };
        Self::from_pkcs8(algorithm, owner, flags, &pkcs8)
    }

    /// Adopt an existing PKCS#8 private key.
    pub fn from_pkcs8(
        algorithm: SigningAlgorithm,
        owner: &str,
        flags: u16,
        pkcs8: &[u8],
    ) -> Result<Self> {
        let rng = SystemRandom::new();
        let (pair, public_key) = match algorithm {
            SigningAlgorithm::EcdsaP256Sha256 | SigningAlgorithm::EcdsaP384Sha384 => {
                let signing = if algorithm == SigningAlgorithm::EcdsaP256Sha256 {
                    &ECDSA_P256_SHA256_FIXED_SIGNING
                } else {
                    &ECDSA_P384_SHA384_FIXED_SIGNING
                };
                let pair = EcdsaKeyPair::from_pkcs8(signing, pkcs8, &rng).map_err(|e| {
                    DnssecError::key(format!("reading a {} key: {e}", algorithm.name(),))
                })?;
                // ring hands back an uncompressed SEC1 point; RFC 6605 §4
                // publishes it without the leading 0x04.
                let public = pair.public_key().as_ref()[1..].to_vec();
                (Pair::Ecdsa(Box::new(pair)), public)
            }
            SigningAlgorithm::Ed25519 => {
                // v2 carries the public key beside the seed and ring checks
                // they agree; v1 — what OpenSSL writes — carries only the seed.
                let pair = Ed25519KeyPair::from_pkcs8(pkcs8)
                    .or_else(|_| Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8))
                    .map_err(|e| DnssecError::key(format!("reading an Ed25519 key: {e}")))?;
                let public = pair.public_key().as_ref().to_vec();
                (Pair::Ed25519(Box::new(pair)), public)
            }
            SigningAlgorithm::RsaSha256 | SigningAlgorithm::RsaSha512 => {
                let pair = RsaKeyPair::from_pkcs8(pkcs8)
                    .map_err(|e| DnssecError::key(format!("reading an RSA key: {e}")))?;
                let public = rsa_dnskey_public_key(pair.public().as_ref())?;
                (Pair::Rsa(Box::new(pair)), public)
            }
        };

        if flags & DNSKEY_FLAG_ZONE == 0 {
            return Err(DnssecError::key(format!(
                "flags {flags} do not have the Zone Key bit set, so this key may not sign zone \
                 data (RFC 4034 §2.1.1)",
            )));
        }

        Ok(SigningKey {
            owner: crate::dnssec::canonical_name(owner),
            flags,
            algorithm,
            public_key,
            pkcs8: pkcs8.to_vec(),
            pair,
        })
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// Whether this key is a Secure Entry Point: the one a parent's DS points
    /// at, and by convention the one signing the DNSKEY RRset.
    pub fn is_sep(&self) -> bool {
        self.flags & DNSKEY_FLAG_SEP != 0
    }

    /// The public half in the form a DNSKEY publishes it.
    pub fn dnskey_public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The DNSKEY this key is published as.
    pub fn dnskey(&self) -> Dnskey {
        Dnskey {
            owner: self.owner.clone(),
            flags: self.flags,
            protocol: 3,
            algorithm: self.algorithm.code(),
            public_key: self.public_key.clone(),
        }
    }

    pub fn key_tag(&self) -> u16 {
        key_tag(self.flags, 3, self.algorithm.code(), &self.public_key)
    }

    /// The DS record a parent must publish to make this key an entry point.
    pub fn ds(&self, digest_type: u8) -> Result<Ds> {
        let key = self.dnskey();
        Ok(Ds {
            owner: self.owner.clone(),
            key_tag: key.key_tag(),
            algorithm: key.algorithm,
            digest_type,
            digest: ds_digest(&key, digest_type)?,
        })
    }

    /// Sign arbitrary bytes; the caller owes the canonical form. The way in is
    /// [`SigningKey::sign_rrset`].
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.pair {
            // DNSSEC wants the fixed-width r||s pair (RFC 6605 §4), not the
            // ASN.1 sequence — hence the `_FIXED_` signing algorithm above.
            Pair::Ecdsa(pair) => {
                let rng = SystemRandom::new();
                Ok(pair
                    .sign(&rng, data)
                    .map_err(|e| DnssecError::key(format!("ECDSA signing failed: {e}")))?
                    .as_ref()
                    .to_vec())
            }
            Pair::Ed25519(pair) => Ok(pair.sign(data).as_ref().to_vec()),
            Pair::Rsa(pair) => {
                let rng = SystemRandom::new();
                let padding = if self.algorithm == SigningAlgorithm::RsaSha256 {
                    &RSA_PKCS1_SHA256
                } else {
                    &RSA_PKCS1_SHA512
                };
                let mut signature = vec![0u8; pair.public().modulus_len()];
                pair.sign(padding, &rng, data, &mut signature)
                    .map_err(|e| DnssecError::key(format!("RSA signing failed: {e}")))?;
                Ok(signature)
            }
        }
    }

    /// A genuine RRSIG over `rrset`, valid from `inception` until `expiration`.
    ///
    /// `original_ttl` is the TTL the records are published with, not one a cache
    /// counted down: a validator restores it before hashing, so a signature
    /// keeps verifying as the records age (RFC 4034 §3.1.3).
    ///
    /// The signer name is this key's owner and cannot be passed in — a signature
    /// naming another zone is rejected by [`crate::dnssec::verify_rrset`] before
    /// the bytes are looked at.
    pub fn sign_rrset(
        &self,
        rrset: &Rrset<'_>,
        original_ttl: u32,
        inception: u32,
        expiration: u32,
    ) -> Result<Rrsig> {
        let mut rrsig = Rrsig {
            owner: crate::dnssec::canonical_name_of(rrset.owner),
            type_covered: rrset.rtype,
            algorithm: self.algorithm.code(),
            labels: rrsig_labels_of(rrset.owner),
            original_ttl,
            inception,
            expiration,
            key_tag: self.key_tag(),
            signer_name: self.owner.clone(),
            signature: Vec::new(),
        };
        let data = signed_data(&rrsig, rrset.owner, rrset.class, rrset.rdatas)
            .map_err(|e| DnssecError::key(format!("building the bytes to sign: {e}")))?;
        rrsig.signature = self.sign(&data)?;
        Ok(rrsig)
    }

    /// `K<owner>+<algorithm>+<tag>.rdnskey`, so a key directory is readable
    /// without opening anything in it.
    pub fn file_name(&self) -> String {
        format!(
            "K{}+{:03}+{:05}.{KEY_FILE_EXTENSION}",
            self.owner,
            self.algorithm.code(),
            self.key_tag()
        )
    }

    /// The key file's text.
    ///
    /// The key tag is a comment, not a field: it is derived from the flags and
    /// the public key, so a field would be a second copy — and the first thing
    /// to disagree after a hand-edited `Flags` during a rollover.
    pub fn to_key_file(&self) -> String {
        format!(
            "; rdns DNSSEC signing key. Anyone who can read this file can sign {owner}\n\
             ; Algorithm: {alg_name}\n\
             ; KeyTag: {tag}\n\
             Owner: {owner}\n\
             Flags: {flags}\n\
             Algorithm: {alg}\n\
             PrivateKey: {key}\n",
            owner = self.owner,
            alg_name = self.algorithm.name(),
            tag = self.key_tag(),
            flags = self.flags,
            alg = self.algorithm.code(),
            key = base64_encode(&self.pkcs8),
        )
    }

    /// Read a key file back.
    pub fn from_key_file(text: &str) -> Result<Self> {
        let mut owner = None;
        let mut flags = None;
        let mut algorithm = None;
        let mut private = None;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| DnssecError::key(format!("{line:?} is not a `Name: value` line")))?;
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "owner" => owner = Some(value.to_string()),
                "flags" => {
                    flags = Some(
                        value
                            .parse::<u16>()
                            .map_err(|e| DnssecError::key(format!("the Flags field: {e}")))?,
                    );
                }
                "algorithm" => algorithm = Some(SigningAlgorithm::parse(value)?),
                "privatekey" => {
                    private = Some(
                        base64_decode(value)
                            .map_err(|e| DnssecError::key(format!("the PrivateKey: {e}")))?,
                    )
                }
                // Unknown fields ignored so a file from a later version loads,
                // as the anchor file does.
                _ => {}
            }
        }

        let owner = owner.ok_or_else(|| {
            DnssecError::key(
                "no Owner field: a key with no name at which \
             it is published cannot sign anything",
            )
        })?;
        let flags = flags.ok_or_else(|| DnssecError::key("no Flags field"))?;
        let algorithm = algorithm.ok_or_else(|| DnssecError::key("no Algorithm field"))?;
        let private = private.ok_or_else(|| DnssecError::key("no PrivateKey field"))?;
        Self::from_pkcs8(algorithm, &owner, flags, &private)
    }

    /// Write the key into `dir` under [`SigningKey::file_name`], returning the
    /// path.
    ///
    /// Readable by its owner alone where the platform can say so. Windows has no
    /// mode bits, so there it is the directory's permissions or nothing.
    ///
    /// The restriction is applied before the file reaches its final name, and
    /// failing to apply it fails the write — see
    /// [`crate::persist::write_atomically_private`].
    pub fn write_to_dir(&self, dir: &Path) -> Result<PathBuf> {
        let path = dir.join(self.file_name());
        crate::persist::write_atomically_private(&path, &self.to_key_file())
            .map_err(|e| DnssecError::key(format!("writing {}: {e}", path.display(),)))?;
        Ok(path)
    }

    /// Every key file in `dir`.
    ///
    /// A file that will not parse is an error, never a skip: a dropped key means
    /// a zone short a signature, which looks exactly like a rollover in
    /// progress, so nothing downstream reports it either.
    pub fn load_dir(dir: &Path) -> Result<Vec<SigningKey>> {
        let mut keys = Vec::new();
        let entries = std::fs::read_dir(dir).map_err(|e| {
            DnssecError::key(format!("reading the key directory {}: {e}", dir.display(),))
        })?;
        for entry in entries {
            let path = entry
                .map_err(|e| {
                    DnssecError::key(format!("reading the key directory {}: {e}", dir.display(),))
                })?
                .path();
            if path.extension().and_then(|e| e.to_str()) != Some(KEY_FILE_EXTENSION) {
                continue;
            }
            // Checked on the way in, not only set on the way out: a backup
            // restore or a `chmod -R` is the ordinary way a private key stops
            // being private, and whoever can read this can sign the zone.
            crate::persist::ensure_private(&path, "a DNSSEC private key")
                .map_err(|e| DnssecError::key(e.to_string()))?;
            let text = std::fs::read_to_string(&path)
                .map_err(|e| DnssecError::key(format!("reading {}: {e}", path.display(),)))?;
            let key = SigningKey::from_key_file(&text)
                .map_err(|e| DnssecError::key(format!("in {}: {e}", path.display(),)))?;
            keys.push(key);
        }
        // A directory listing has no reliable order. Canonical sorting makes it
        // irrelevant to a signature, but the order signatures are *generated*
        // in shows up in the written zone file, and a zone that reshuffles on
        // every reload makes a diff useless.
        keys.sort_by_key(|k| (k.owner.clone(), k.algorithm.code(), k.key_tag()));
        Ok(keys)
    }
}

/// The DNSKEY form of an RSA public key (RFC 3110 §2): the exponent's length,
/// then the exponent, then the modulus.
///
/// `ring` publishes DER `RSAPublicKey` — `SEQUENCE { modulus, publicExponent }`
/// — so the two numbers are lifted out and re-laid in the other order. DER
/// integers are signed, so one with its top bit set carries a leading zero byte
/// of padding; leaving it in changes the key tag, and every RRSIG then names a
/// key that is not there.
fn rsa_dnskey_public_key(der: &[u8]) -> Result<Vec<u8>> {
    let body = der_expect(der, 0x30)
        .map_err(|e| DnssecError::key(format!("the RSA public key's outer SEQUENCE: {e}")))?;
    let (modulus, rest) =
        der_take(body, 0x02).map_err(|e| DnssecError::key(format!("the RSA modulus: {e}")))?;
    let (exponent, rest) =
        der_take(rest, 0x02).map_err(|e| DnssecError::key(format!("the RSA exponent: {e}")))?;
    if !rest.is_empty() {
        return Err(DnssecError::key(format!(
            "{} trailing bytes after the RSA public key",
            rest.len(),
        )));
    }
    let modulus = strip_leading_zeros(modulus);
    let exponent = strip_leading_zeros(exponent);
    if exponent.is_empty() || modulus.is_empty() {
        return Err(DnssecError::key("an RSA key part is zero"));
    }

    let mut out = Vec::with_capacity(3 + exponent.len() + modulus.len());
    if exponent.len() <= 255 {
        out.push(exponent.len() as u8);
    } else {
        // The zero byte says "the real length is the next two" (RFC 3110 §2).
        let len: u16 = exponent
            .len()
            .try_into()
            .map_err(|_| DnssecError::key("RSA exponent is longer than 65535 bytes"))?;
        out.push(0);
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(exponent);
    out.extend_from_slice(modulus);
    Ok(out)
}

/// The contents of a DER element of type `tag`, which must be the whole of
/// `der`.
fn der_expect(der: &[u8], tag: u8) -> Result<&[u8]> {
    let (body, rest) = der_take(der, tag)?;
    if !rest.is_empty() {
        return Err(DnssecError::key(format!("{} trailing bytes", rest.len(),)));
    }
    Ok(body)
}

/// Split one DER element of type `tag` off the front, returning its contents
/// and what follows.
///
/// Only definite-length forms are accepted, which is all DER has.
fn der_take(der: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let short = || DnssecError::key("DER element is truncated");
    if der.first() != Some(&tag) {
        return Err(DnssecError::key(format!(
            "expected DER tag {tag:#04x}, found {:?}",
            der.first(),
        )));
    }
    let first = *der.get(1).ok_or_else(short)?;
    let (len, offset) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return Err(DnssecError::key(format!(
                "DER length of {count} bytes is not one we read"
            )));
        }
        let bytes = der.get(2..2 + count).ok_or_else(short)?;
        let mut len = 0usize;
        for byte in bytes {
            len = (len << 8) | *byte as usize;
        }
        (len, 2 + count)
    };
    let body = der.get(offset..offset + len).ok_or_else(short)?;
    Ok((body, &der[offset + len..]))
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

fn base64_decode(text: &str) -> Result<Vec<u8>> {
    base64::Engine::decode(&base64::prelude::BASE64_STANDARD, text.trim())
        .map_err(|e| DnssecError::parse(format!("not valid base64: {e}")))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::dnssec::{verify, verify_rrset, RrsetProof};
    use crate::test_records::a_rdata;
    use crate::test_records::nm;
    use crate::utils::record_types as rt;
    use crate::Class;

    #[test]
    fn a_generated_key_signs_something_the_validator_accepts() {
        for algorithm in [
            SigningAlgorithm::EcdsaP256Sha256,
            SigningAlgorithm::EcdsaP384Sha384,
            SigningAlgorithm::Ed25519,
        ] {
            let key = SigningKey::generate(algorithm, "example.com.", DNSKEY_FLAG_ZONE).unwrap();
            let rdatas = vec![a_rdata([192, 0, 2, 1])];
            let owner = nm("www.example.com.");
            let rrset = Rrset::new(owner.as_ref(), rt::A, Class::new(1), &rdatas);
            let sig = key.sign_rrset(&rrset, 3600, 1_000, 2_000_000_000).unwrap();

            let proof = verify_rrset(
                &rrset,
                &[sig],
                &[key.dnskey()],
                nm("example.com.").as_ref(),
                1_500,
            );
            assert!(
                matches!(proof, RrsetProof::Verified { .. }),
                "{}: {proof:?}",
                algorithm.name()
            );
        }
    }

    #[test]
    fn a_signature_does_not_verify_against_a_different_key() {
        let key = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            DNSKEY_FLAG_ZONE,
        )
        .unwrap();
        let other = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            DNSKEY_FLAG_ZONE,
        )
        .unwrap();
        let rdatas = vec![a_rdata([192, 0, 2, 1])];
        let owner = nm("www.example.com.");
        let rrset = Rrset::new(owner.as_ref(), rt::A, Class::new(1), &rdatas);
        let sig = key.sign_rrset(&rrset, 3600, 1_000, 2_000_000_000).unwrap();

        let data = signed_data(&sig, rrset.owner, rrset.class, rrset.rdatas).unwrap();
        assert!(!verify(
            other.algorithm().code(),
            &other.dnskey().public_key,
            &data,
            &sig.signature
        )
        .unwrap());
    }

    #[test]
    fn a_wildcards_signature_counts_labels_without_the_star() {
        // The label count is what lets one signature cover every name the
        // wildcard reaches; wrong here, wildcards break only at a validator.
        let key = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            DNSKEY_FLAG_ZONE,
        )
        .unwrap();
        let rdatas = vec![a_rdata([192, 0, 2, 1])];
        let owner = nm("*.example.com.");
        let rrset = Rrset::new(owner.as_ref(), rt::A, Class::new(1), &rdatas);
        let sig = key.sign_rrset(&rrset, 3600, 1_000, 2_000_000_000).unwrap();
        assert_eq!(sig.labels, 2);

        // Re-owned onto a name the wildcard expands to, it still verifies.
        let mut expanded = sig.clone();
        expanded.owner = "anything.example.com.".to_string();
        let expanded_owner = nm("anything.example.com.");
        let expanded_rrset = Rrset::new(expanded_owner.as_ref(), rt::A, Class::new(1), &rdatas);
        assert!(matches!(
            verify_rrset(
                &expanded_rrset,
                &[expanded],
                &[key.dnskey()],
                nm("example.com.").as_ref(),
                1_500
            ),
            RrsetProof::Verified {
                wildcard: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn a_key_survives_a_round_trip_through_its_file() {
        let key = SigningKey::generate(
            SigningAlgorithm::Ed25519,
            "example.com.",
            DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
        )
        .unwrap();
        let text = key.to_key_file();
        let back = SigningKey::from_key_file(&text).unwrap();

        assert_eq!(back.owner(), key.owner());
        assert_eq!(back.flags(), key.flags());
        assert_eq!(back.algorithm(), key.algorithm());
        assert_eq!(back.key_tag(), key.key_tag());
        assert_eq!(back.dnskey().public_key, key.dnskey().public_key);
        assert!(back.is_sep());

        // The same *private* key, not one that merely describes itself the
        // same: a signature from the loaded copy verifies under the original.
        let rdatas = vec![a_rdata([192, 0, 2, 1])];
        let owner = nm("example.com.");
        let rrset = Rrset::new(owner.as_ref(), rt::A, Class::new(1), &rdatas);
        let sig = back.sign_rrset(&rrset, 3600, 1_000, 2_000_000_000).unwrap();
        assert!(matches!(
            verify_rrset(
                &rrset,
                &[sig],
                &[key.dnskey()],
                nm("example.com.").as_ref(),
                1_500
            ),
            RrsetProof::Verified { .. }
        ));
    }

    #[test]
    fn the_file_never_holds_the_private_key_in_a_debug_line() {
        let key = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            DNSKEY_FLAG_ZONE,
        )
        .unwrap();
        let rendered = format!("{key:?}");
        assert!(!rendered.contains(&base64_encode(&key.pkcs8)));
        assert!(rendered.contains("example.com."));
    }

    #[test]
    fn a_key_without_the_zone_bit_is_refused() {
        // RFC 4034 §2.1.1: without it the DNSKEY is not a key for zone data, so
        // its signatures verify against nothing. Fail at load, not after
        // signing a zone nobody can validate.
        let err = SigningKey::generate(SigningAlgorithm::Ed25519, "example.com.", 0).unwrap_err();
        assert!(err.to_string().contains("Zone Key"), "{err}");
    }

    #[test]
    fn rsa_cannot_be_generated_but_says_why() {
        let err = SigningKey::generate(
            SigningAlgorithm::RsaSha256,
            "example.com.",
            DNSKEY_FLAG_ZONE,
        )
        .unwrap_err();
        assert!(err.to_string().contains("openssl"), "{err}");
    }

    #[test]
    fn algorithms_parse_by_number_and_by_name() {
        assert_eq!(
            SigningAlgorithm::parse("13").unwrap(),
            SigningAlgorithm::EcdsaP256Sha256
        );
        assert_eq!(
            SigningAlgorithm::parse("ed25519").unwrap(),
            SigningAlgorithm::Ed25519
        );
        // Verifiable, not signable — and the error says which of the two.
        let err = SigningAlgorithm::parse("5").unwrap_err();
        assert!(err.to_string().contains("MUST NOT for signing"), "{err}");
    }

    #[test]
    fn an_rsa_public_key_is_re_laid_into_rfc_3110_form() {
        // SEQUENCE { INTEGER 0x00C0FFEE, INTEGER 0x010001 } — the modulus
        // carries DER's sign-padding zero, which RFC 3110 form must not.
        let der = [
            0x30, 0x0b, 0x02, 0x04, 0x00, 0xc0, 0xff, 0xee, 0x02, 0x03, 0x01, 0x00, 0x01,
        ];
        let out = rsa_dnskey_public_key(&der).unwrap();
        assert_eq!(out, vec![3, 0x01, 0x00, 0x01, 0xc0, 0xff, 0xee]);
    }

    #[test]
    fn a_truncated_rsa_public_key_is_an_error_not_a_panic() {
        assert!(rsa_dnskey_public_key(&[0x30, 0x40, 0x02, 0x01]).is_err());
        assert!(rsa_dnskey_public_key(&[]).is_err());
        assert!(rsa_dnskey_public_key(&[0x30, 0x03, 0x02, 0x01, 0x00]).is_err());
    }

    #[test]
    fn a_key_directory_loads_every_key_and_refuses_a_broken_one() {
        let dir = std::env::temp_dir().join(format!("rdns-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let ksk = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
        )
        .unwrap();
        let zsk = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            DNSKEY_FLAG_ZONE,
        )
        .unwrap();
        ksk.write_to_dir(&dir).unwrap();
        zsk.write_to_dir(&dir).unwrap();
        // A file that is not ours is not a key, and is not an error either.
        std::fs::write(dir.join("notes.txt"), "ignore me").unwrap();

        let loaded = SigningKey::load_dir(&dir).unwrap();
        assert_eq!(loaded.len(), 2);
        let mut tags: Vec<u16> = loaded.iter().map(|k| k.key_tag()).collect();
        tags.sort_unstable();
        let mut expected = vec![ksk.key_tag(), zsk.key_tag()];
        expected.sort_unstable();
        assert_eq!(tags, expected);

        // 0600: `fs::write` leaves 0644, and `load_dir` refuses a world-readable
        // key *before* parsing it, so the assertion below would pass on the
        // permission error instead of on the broken key.
        let broken = dir.join("broken.rdnskey");
        std::fs::write(&broken, "Owner: example.com.\n").unwrap();
        restrict(&broken);
        let err = SigningKey::load_dir(&dir).unwrap_err();
        assert!(format!("{err:#}").contains("broken.rdnskey"), "{err:#}");
        assert!(
            format!("{err:#}").contains("Flags"),
            "the parse failure, not the permission check: {err:#}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn restrict(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(not(unix))]
    fn restrict(_path: &Path) {}

    /// A private key anybody can read is refused.
    ///
    /// Unix only, and the check genuinely does not exist on Windows — there are
    /// no mode bits to read. Said here so a green suite on the wrong platform is
    /// not mistaken for coverage.
    #[cfg(unix)]
    #[test]
    fn a_world_readable_private_key_is_refused_by_the_loader() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rdns-keyperms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key = SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            "example.com.",
            DNSKEY_FLAG_ZONE,
        )
        .unwrap();
        let path = key.write_to_dir(&dir).unwrap();

        // What the server writes is already private, and loads.
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(SigningKey::load_dir(&dir).unwrap().len(), 1);

        // What a deploy script leaves behind does not.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = SigningKey::load_dir(&dir).unwrap_err();
        let text = format!("{err:#}");
        assert!(text.contains("644"), "name the mode: {text}");
        assert!(
            text.contains(&path.display().to_string()),
            "name the file: {text}"
        );

        // And group-readable is no better — the group is other people.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(SigningKey::load_dir(&dir).is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            SigningKey::load_dir(&dir).unwrap().len(),
            1,
            "and putting it back is all it takes to recover"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
