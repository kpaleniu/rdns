//! Test-only DNSSEC signing: real keys, real signatures, no network.
//!
//! `ring` generates a P-256 keypair and signs in microseconds, so a test can
//! stand up a signed zone — KSK, ZSK, DS in the parent, signed answers — and put
//! the real verification path through it rather than a mock.

use crate::clock::current_unix_timestamp;
use crate::dnssec::{
    key_tag, rrsig_labels_of, signed_data, Dnskey, Ds, Rrset, Rrsig, DNSKEY_FLAG_SEP,
    DNSKEY_FLAG_ZONE,
};
use crate::dnssec_key::{SigningAlgorithm, SigningKey};
use crate::record_types as rt;
use crate::test_records::nm;
use crate::zone_signer::{DenialChain, SigningPolicy};
use crate::Class;
use crate::Rtype;
use crate::Ttl;
use crate::{NameRef, ParsedRecord, RecordData, ResourceRecord};

/// DNSKEY flags for a zone-signing key, and for a key-signing key (which adds
/// the Secure Entry Point bit).
const ZSK_FLAGS: u16 = 0x0100;
pub const KSK_FLAGS: u16 = 0x0101;

/// A keypair that can actually sign.
///
/// The signing is [`SigningKey`]'s, the same code `rdnsd` uses, so a second
/// implementation cannot agree with the validator while the real one does not.
/// What is added here is publishing one key at several owner names and flag
/// combinations, which a signer has no business offering and a chain-walk test
/// needs constantly.
pub struct TestKey {
    key: SigningKey,
}

impl TestKey {
    pub fn generate_p256() -> Self {
        Self::generate(SigningAlgorithm::EcdsaP256Sha256)
    }

    pub fn generate_p384() -> Self {
        Self::generate(SigningAlgorithm::EcdsaP384Sha384)
    }

    pub fn generate_ed25519() -> Self {
        Self::generate(SigningAlgorithm::Ed25519)
    }

    /// The owner and flags here are placeholders; every publishing method takes
    /// its own.
    fn generate(algorithm: SigningAlgorithm) -> Self {
        TestKey {
            key: SigningKey::generate(algorithm, ".", ZSK_FLAGS).expect("generate key"),
        }
    }

    pub fn algorithm(&self) -> u8 {
        self.key.algorithm().code()
    }

    pub fn public_key(&self) -> &[u8] {
        self.key.dnskey_public_key()
    }

    /// Sign arbitrary bytes, exactly as a signer would sign the canonical form.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.key.sign(data).expect("sign")
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
            owner: nm(owner),
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
        owner: NameRef<'_>,
        type_covered: Rtype,
        original_ttl: u32,
        signer: &str,
        flags: u16,
    ) -> Rrsig {
        let now = current_unix_timestamp();
        Rrsig {
            owner: owner.to_owned(),
            type_covered,
            algorithm: self.algorithm(),
            labels: rrsig_labels_of(owner),
            original_ttl,
            inception: (now - 3600) as u32,
            expiration: (now + 86_400) as u32,
            key_tag: key_tag(flags, 3, self.algorithm(), self.public_key()),
            signer_name: nm(signer),
            signature: Vec::new(),
        }
    }

    /// Produce a genuine RRSIG over `rdatas`, signed as a ZSK would sign it.
    pub fn sign_rrset(
        &self,
        owner: &str,
        rtype: Rtype,
        class: Class,
        ttl: u32,
        signer: &str,
        rdatas: &[RecordData],
    ) -> Rrsig {
        self.sign_rrset_as(
            &Rrset::new(nm(owner).as_ref(), rtype, class, rdatas),
            ttl,
            signer,
            ZSK_FLAGS,
        )
    }

    /// As [`TestKey::sign_rrset`], but for a key published with `flags` — the
    /// key tag depends on the flags, so a KSK signature has to name the KSK.
    pub fn sign_rrset_as(&self, rrset: &Rrset<'_>, ttl: u32, signer: &str, flags: u16) -> Rrsig {
        let mut rrsig = self.rrsig_template(rrset.owner, rrset.rtype, ttl, signer, flags);
        let data =
            signed_data(&rrsig, rrset.owner, rrset.class, rrset.rdatas).expect("build signed data");
        rrsig.signature = self.sign(&data);
        rrsig
    }
}

/// A signed zone: a KSK the parent's DS points at, and a ZSK signing the data.
/// The split is not required by the protocol, but it is what real zones do and
/// what the chain walk has to handle.
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
        let rdatas: Vec<RecordData> = self.dnskeys().iter().map(dnskey_rdata).collect();
        let sig = self.ksk.sign_rrset_as(
            &Rrset::new(nm(&self.name).as_ref(), rt::DNSKEY, Class::new(1), &rdatas),
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
            owner: nm(&self.name),
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
                name: nm(&self.name.clone()),
                class: Class::new(1),
                ttl: Ttl::from_secs(3600),
                rdata,
            })
            .collect();
        out.push(rrsig_record(&sig, Ttl::from_secs(3600)));
        out
    }

    /// Sign as a server answering from a wildcard does: over `wildcard`, the
    /// name really in the zone, but published at the expanded owner with the
    /// wildcard's shorter label count.
    ///
    /// The same signature verifies at every name the wildcard could reach, so a
    /// test may re-own the result onto any of them.
    pub fn sign_as_wildcard(&self, records: &[ResourceRecord], wildcard: &str) -> ResourceRecord {
        let first = records.first().expect("an RRset has at least one record");
        let rdatas: Vec<RecordData> = records.iter().map(|r| r.rdata.clone()).collect();
        let mut sig = self.zsk.sign_rrset(
            wildcard,
            first.rdata.rtype(),
            first.class,
            first.ttl.as_secs(),
            &self.name,
            &rdatas,
        );
        sig.owner = first.name.clone();
        rrsig_record(&sig, first.ttl)
    }

    /// Sign `records` (all one RRset) with the ZSK, returning the RRSIG record
    /// to put beside them.
    pub fn sign_records(&self, records: &[ResourceRecord]) -> ResourceRecord {
        let first = records.first().expect("an RRset has at least one record");
        let rdatas: Vec<RecordData> = records.iter().map(|r| r.rdata.clone()).collect();
        let sig = self.zsk.sign_rrset(
            &first.name.to_string(),
            first.rdata.rtype(),
            first.class,
            first.ttl.as_secs(),
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
pub fn rrsig_record(sig: &Rrsig, ttl: Ttl) -> ResourceRecord {
    ResourceRecord {
        name: sig.owner.clone(),
        class: Class::new(1),
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
pub fn ds_record(ds: &Ds, ttl: Ttl) -> ResourceRecord {
    ResourceRecord {
        name: ds.owner.clone(),
        class: Class::new(1),
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

/// The key set a zone-signing test signs with: a P-256 KSK and a P-256 ZSK,
/// both at `origin`.
///
/// This is [`SigningKey`] rather than [`TestKey`] on purpose — a `sign_zone`
/// test is exercising the signer, so its keys have to be the ones the signer
/// would be handed.
pub fn signing_keys(origin: &str) -> Vec<SigningKey> {
    vec![
        SigningKey::generate(
            SigningAlgorithm::EcdsaP256Sha256,
            origin,
            DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
        )
        .expect("generate KSK"),
        SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, origin, DNSKEY_FLAG_ZONE)
            .expect("generate ZSK"),
    ]
}

/// Thirty days' validity from `now`, which is the default the daemon runs and
/// the only value either signing test has wanted.
pub fn signing_policy(now: u64, chain: DenialChain) -> SigningPolicy {
    SigningPolicy::valid_for(now, 30 * 86_400).with_chain(chain)
}
