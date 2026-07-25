//! Test-only DNSSEC signing: real keys, real signatures, no network.
//!
//! Port 53 is intercepted on the machine this was developed on, so there is no
//! live signed zone to validate against and never was — which is how the
//! validator came to be written without a single genuine signature ever
//! reaching it. The answer is to sign in-process: `ring` can generate a P-256
//! keypair and produce a real signature in microseconds, so a test can stand up
//! a signed zone (KSK, ZSK, DS in the parent, signed answers) and put the
//! actual verification path through it.
//!
//! Nothing here is compiled into a release build.

use crate::dnssec::{key_tag, label_count, signed_data, Dnskey, Ds, Rrset, Rrsig};
use crate::utils::{current_unix_timestamp, record_types as rt};
use crate::{ParsedRecord, RecordData, ResourceRecord};
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
};

/// DNSKEY flags for a zone-signing key, and for a key-signing key (which adds
/// the Secure Entry Point bit).
pub const ZSK_FLAGS: u16 = 0x0100;
pub const KSK_FLAGS: u16 = 0x0101;

/// A keypair that can actually sign.
pub enum TestKey {
    Ecdsa {
        algorithm: u8,
        pair: EcdsaKeyPair,
        /// The DNSKEY form: x || y, without SEC1's 0x04 prefix (RFC 6605 §4).
        public: Vec<u8>,
    },
    Ed25519 {
        pair: Ed25519KeyPair,
        public: Vec<u8>,
    },
}

impl TestKey {
    pub fn generate_p256() -> Self {
        Self::generate_ecdsa(13, &ECDSA_P256_SHA256_FIXED_SIGNING)
    }

    pub fn generate_p384() -> Self {
        Self::generate_ecdsa(14, &ECDSA_P384_SHA384_FIXED_SIGNING)
    }

    fn generate_ecdsa(
        algorithm: u8,
        signing: &'static ring::signature::EcdsaSigningAlgorithm,
    ) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(signing, &rng).expect("generate ECDSA key");
        let pair =
            EcdsaKeyPair::from_pkcs8(signing, pkcs8.as_ref(), &rng).expect("parse ECDSA key");
        // ring hands back an uncompressed SEC1 point; DNSSEC publishes it
        // without the leading 0x04.
        let public = pair.public_key().as_ref()[1..].to_vec();
        TestKey::Ecdsa {
            algorithm,
            pair,
            public,
        }
    }

    pub fn generate_ed25519() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519 key");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse Ed25519 key");
        let public = pair.public_key().as_ref().to_vec();
        TestKey::Ed25519 { pair, public }
    }

    pub fn algorithm(&self) -> u8 {
        match self {
            TestKey::Ecdsa { algorithm, .. } => *algorithm,
            TestKey::Ed25519 { .. } => 15,
        }
    }

    pub fn public_key(&self) -> &[u8] {
        match self {
            TestKey::Ecdsa { public, .. } | TestKey::Ed25519 { public, .. } => public,
        }
    }

    /// Sign arbitrary bytes, exactly as a signer would sign the canonical form.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            TestKey::Ecdsa { pair, .. } => {
                let rng = SystemRandom::new();
                pair.sign(&rng, data).expect("sign").as_ref().to_vec()
            }
            TestKey::Ed25519 { pair, .. } => pair.sign(data).as_ref().to_vec(),
        }
    }

    /// This key published at `owner` as a zone-signing key.
    pub fn dnskey(&self, owner: &str) -> Dnskey {
        self.dnskey_with(owner, ZSK_FLAGS)
    }

    /// This key published at `owner` as a key-signing key (SEP set).
    pub fn ksk(&self, owner: &str) -> Dnskey {
        self.dnskey_with(owner, KSK_FLAGS)
    }

    pub fn dnskey_with(&self, owner: &str, flags: u16) -> Dnskey {
        Dnskey {
            owner: owner.to_string(),
            flags,
            protocol: 3,
            algorithm: self.algorithm(),
            public_key: self.public_key().to_vec(),
        }
    }

    /// An RRSIG with everything filled in but the signature itself — the shape
    /// [`signed_data`] hashes.
    pub fn rrsig_template(
        &self,
        owner: &str,
        type_covered: u16,
        original_ttl: u32,
        signer: &str,
        flags: u16,
    ) -> Rrsig {
        let now = current_unix_timestamp();
        Rrsig {
            owner: owner.to_string(),
            type_covered,
            algorithm: self.algorithm(),
            labels: wildcard_aware_label_count(owner) as u8,
            original_ttl,
            inception: (now - 3600) as u32,
            expiration: (now + 86_400) as u32,
            key_tag: key_tag(flags, 3, self.algorithm(), self.public_key()),
            signer_name: signer.to_string(),
            signature: Vec::new(),
        }
    }

    /// Produce a genuine RRSIG over `rdatas`, signed as a ZSK would sign it.
    pub fn sign_rrset(
        &self,
        owner: &str,
        rtype: u16,
        class: u16,
        ttl: u32,
        signer: &str,
        rdatas: &[RecordData],
    ) -> Rrsig {
        self.sign_rrset_as(&Rrset::new(owner, rtype, class, rdatas), ttl, signer, ZSK_FLAGS)
    }

    /// As [`TestKey::sign_rrset`], but for a key published with `flags` — the
    /// key tag depends on the flags, so a KSK signature has to name the KSK.
    pub fn sign_rrset_as(
        &self,
        rrset: &Rrset<'_>,
        ttl: u32,
        signer: &str,
        flags: u16,
    ) -> Rrsig {
        let mut rrsig = self.rrsig_template(rrset.owner, rrset.rtype, ttl, signer, flags);
        let data = signed_data(&rrsig, rrset.owner, rrset.class, rrset.rdatas)
            .expect("build signed data");
        rrsig.signature = self.sign(&data);
        rrsig
    }
}

/// Labels as RFC 4034 §3.1.3 counts them: the root and a leading `*` do not
/// count, which is what makes a wildcard signature validate at every name it
/// expands to.
fn wildcard_aware_label_count(owner: &str) -> usize {
    let n = label_count(owner);
    if owner.starts_with("*.") {
        n.saturating_sub(1)
    } else {
        n
    }
}

/// A signed zone: a KSK the parent's DS points at, and a ZSK that signs the
/// data. Splitting the two is not required by the protocol but is what every
/// real zone does, and it is the arrangement the chain walk has to handle.
pub struct TestZone {
    pub name: String,
    pub ksk: TestKey,
    pub zsk: TestKey,
}

impl TestZone {
    pub fn new(name: &str) -> Self {
        TestZone {
            name: name.to_string(),
            ksk: TestKey::generate_p256(),
            zsk: TestKey::generate_p256(),
        }
    }

    /// Both public keys as they are published at the apex.
    pub fn dnskeys(&self) -> Vec<Dnskey> {
        vec![self.ksk.ksk(&self.name), self.zsk.dnskey(&self.name)]
    }

    /// The apex DNSKEY RRset and the KSK's signature over it.
    pub fn signed_dnskey_rrset(&self) -> (Vec<RecordData>, Rrsig) {
        let rdatas: Vec<RecordData> = self
            .dnskeys()
            .iter()
            .map(dnskey_rdata)
            .collect();
        let sig = self.ksk.sign_rrset_as(
            &Rrset::new(&self.name, rt::DNSKEY, 1, &rdatas),
            3600,
            &self.name,
            KSK_FLAGS,
        );
        (rdatas, sig)
    }

    /// The DS record the parent must publish for this zone.
    pub fn ds(&self, digest_type: u8) -> Ds {
        let ksk = self.ksk.ksk(&self.name);
        Ds {
            owner: self.name.clone(),
            key_tag: ksk.key_tag(),
            algorithm: ksk.algorithm,
            digest_type,
            digest: crate::dnssec::ds_digest(&ksk, digest_type).expect("digest"),
        }
    }

    /// The apex DNSKEY RRset plus its RRSIG, as resource records ready to put
    /// in an answer section.
    pub fn dnskey_records(&self) -> Vec<ResourceRecord> {
        let (rdatas, sig) = self.signed_dnskey_rrset();
        let mut out: Vec<ResourceRecord> = rdatas
            .into_iter()
            .map(|rdata| ResourceRecord {
                name: self.name.clone(),
                class: 1,
                ttl: 3600,
                rdata,
            })
            .collect();
        out.push(rrsig_record(&sig, 3600));
        out
    }

    /// Sign `records` (all one RRset) with the ZSK, returning the RRSIG record
    /// to put beside them.
    pub fn sign_records(&self, records: &[ResourceRecord]) -> ResourceRecord {
        let first = records.first().expect("an RRset has at least one record");
        let rdatas: Vec<RecordData> = records.iter().map(|r| r.rdata.clone()).collect();
        let sig = self.zsk.sign_rrset(
            &first.name,
            first.rdata.rtype,
            first.class,
            first.ttl.max(0) as u32,
            &self.name,
            &rdatas,
        );
        rrsig_record(&sig, first.ttl)
    }
}

/// A DNSKEY's RDATA in stored form.
pub fn dnskey_rdata(key: &Dnskey) -> RecordData {
    RecordData::from_parsed(&ParsedRecord::DNSKEY {
        flags: key.flags,
        protocol: key.protocol,
        algorithm: key.algorithm,
        public_key: key.public_key.clone(),
    })
    .expect("encode DNSKEY")
}

/// An RRSIG as a resource record.
pub fn rrsig_record(sig: &Rrsig, ttl: i32) -> ResourceRecord {
    ResourceRecord {
        name: sig.owner.clone(),
        class: 1,
        ttl,
        rdata: RecordData::from_parsed(&ParsedRecord::RRSIG {
            type_covered: sig.type_covered,
            algorithm: sig.algorithm,
            labels: sig.labels,
            original_ttl: sig.original_ttl,
            inception: sig.inception,
            expiration: sig.expiration,
            key_tag: sig.key_tag,
            signer_name: sig.signer_name.clone(),
            signature: sig.signature.clone(),
        })
        .expect("encode RRSIG"),
    }
}

/// A DS as a resource record.
pub fn ds_record(ds: &Ds, ttl: i32) -> ResourceRecord {
    ResourceRecord {
        name: ds.owner.clone(),
        class: 1,
        ttl,
        rdata: RecordData::from_parsed(&ParsedRecord::DS {
            key_tag: ds.key_tag,
            algorithm: ds.algorithm,
            digest_type: ds.digest_type,
            digest: ds.digest.clone(),
        })
        .expect("encode DS"),
    }
}
