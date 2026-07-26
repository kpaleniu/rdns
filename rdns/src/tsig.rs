//! TSIG: authenticating a DNS message with a shared secret (RFC 8945).
//!
//! An address is not an identity. `--allow-transfer` decides who may pull a zone
//! by looking at the source address, which is the right default-deny gate and
//! still trusts the network to be telling the truth about who is calling. TSIG
//! replaces that trust with a keyed MAC over the message: a secondary proves it
//! holds the key, and the primary proves the same to the secondary in the reply.
//!
//! The mechanism is a pseudo-record. A TSIG RR is appended as the **last record
//! of the additional section**, and it is not really part of the message: it
//! covers the message, so verifying means removing it again and hashing what is
//! left. That is why almost everything here works on bytes rather than on a
//! parsed [`crate::DnsMessage`] — a re-serialized message is not necessarily the
//! same bytes (name compression is a choice), and the MAC is over the bytes that
//! were actually sent.
//!
//! What the digest covers (RFC 8945 §4.3.3, §5.4.2):
//!
//! ```text
//! request:   message-without-TSIG (ARCOUNT-1, ID = Original ID) || TSIG variables
//! response:  2-byte length || request MAC || message-without-TSIG || TSIG variables
//! envelope:  2-byte length || previous MAC || message-without-TSIG || timers only
//! ```
//!
//! where "TSIG variables" is the key name in canonical form, the class (ANY), the
//! TTL (0), the algorithm name, the time signed, the fudge, the error, and the
//! other data — and "timers only" is just the time signed and the fudge, which is
//! what the messages after the first in a zone transfer are signed with (§5.3.1).
//!
//! The failure codes are not interchangeable and say different things to the peer:
//! **BADKEY** — I do not know that key name; **BADSIG** — I know it and the MAC
//! does not match; **BADTIME** — the MAC matched but your clock and mine disagree
//! by more than the fudge, and here is my time so you can tell which of us is
//! wrong. The first two go back unsigned (there is no key to sign with, or no
//! reason to believe the sender holds it); BADTIME is signed, because the MAC did
//! verify.

use crate::dname::dname_to_bytes;
use crate::utils::current_unix_timestamp;
use base64::Engine;
use ring::hmac;

/// The TSIG pseudo-record type. A meta-type: no zone ever holds one.
pub const TSIG_TYPE: u16 = 250;

/// A TSIG RR is always class ANY with TTL 0 (RFC 8945 §4.2).
pub const TSIG_CLASS: u16 = 255;

/// The clock skew a signature tolerates, in seconds (RFC 8945 §4.2 suggests 300).
pub const DEFAULT_FUDGE: u16 = 300;

/// NOTAUTH — the rcode every TSIG failure is reported with (RFC 8945 §5.3).
pub const RCODE_NOTAUTH: u16 = 9;

/// The MAC algorithms this implements.
///
/// HMAC-SHA256 is the one RFC 8945 §6 requires and the default here. HMAC-SHA1 is
/// kept because a great deal of deployed configuration still names it; HMAC-MD5,
/// which RFC 8945 deprecates, is deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigAlgorithm {
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithm {
    /// The name that goes on the wire, as an absolute domain name.
    pub fn wire_name(&self) -> &'static str {
        match self {
            TsigAlgorithm::HmacSha1 => "hmac-sha1.",
            TsigAlgorithm::HmacSha256 => "hmac-sha256.",
            TsigAlgorithm::HmacSha384 => "hmac-sha384.",
            TsigAlgorithm::HmacSha512 => "hmac-sha512.",
        }
    }

    /// Match a name from the wire or from configuration, with or without the
    /// trailing dot and in any case — it is a domain name (RFC 4343).
    pub fn from_name(name: &str) -> Option<Self> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        match name.as_str() {
            "hmac-sha1" => Some(TsigAlgorithm::HmacSha1),
            "hmac-sha256" => Some(TsigAlgorithm::HmacSha256),
            "hmac-sha384" => Some(TsigAlgorithm::HmacSha384),
            "hmac-sha512" => Some(TsigAlgorithm::HmacSha512),
            _ => None,
        }
    }

    fn ring_algorithm(&self) -> hmac::Algorithm {
        match self {
            TsigAlgorithm::HmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            TsigAlgorithm::HmacSha256 => hmac::HMAC_SHA256,
            TsigAlgorithm::HmacSha384 => hmac::HMAC_SHA384,
            TsigAlgorithm::HmacSha512 => hmac::HMAC_SHA512,
        }
    }

    /// The full MAC length in bytes. A shorter MAC than this is refused rather
    /// than accepted as a truncation (see [`TsigError::BadTrunc`]).
    pub fn mac_len(&self) -> usize {
        match self {
            TsigAlgorithm::HmacSha1 => 20,
            TsigAlgorithm::HmacSha256 => 32,
            TsigAlgorithm::HmacSha384 => 48,
            TsigAlgorithm::HmacSha512 => 64,
        }
    }
}

/// A shared secret and the name it is known by.
#[derive(Debug, Clone)]
pub struct TsigKey {
    /// The key name, absolute and down-cased — it is a domain name, and it is
    /// hashed in canonical form, so the case it was configured in cannot matter.
    pub name: String,
    pub algorithm: TsigAlgorithm,
    secret: Vec<u8>,
}

impl TsigKey {
    pub fn new(name: &str, algorithm: TsigAlgorithm, secret: Vec<u8>) -> Self {
        TsigKey {
            name: canonical_key_name(name),
            algorithm,
            secret,
        }
    }

    /// Parse `[algorithm:]name:base64secret`, the shape `dig -y` uses.
    ///
    /// The algorithm defaults to HMAC-SHA256 when omitted. An unparsable spec is
    /// an error rather than a skip: a key the operator believes is configured but
    /// is not would fail every transfer, and the reason would not be visible.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let parts: Vec<&str> = spec.split(':').collect();
        let (algorithm, name, secret) = match parts.as_slice() {
            [name, secret] => (TsigAlgorithm::HmacSha256, *name, *secret),
            [alg, name, secret] => (
                TsigAlgorithm::from_name(alg)
                    .ok_or_else(|| format!("unknown TSIG algorithm {alg:?}"))?,
                *name,
                *secret,
            ),
            _ => {
                return Err(format!(
                    "TSIG key {spec:?} is not [algorithm:]name:base64secret"
                ))
            }
        };
        if name.is_empty() {
            return Err("TSIG key name is empty".to_string());
        }
        let secret = base64::prelude::BASE64_STANDARD
            .decode(secret)
            .map_err(|e| format!("TSIG secret for {name:?} is not base64: {e}"))?;
        if secret.is_empty() {
            return Err(format!("TSIG secret for {name:?} is empty"));
        }
        Ok(TsigKey::new(name, algorithm, secret))
    }
}

/// The keys a server knows, by name.
#[derive(Debug, Clone, Default)]
pub struct TsigKeyring {
    keys: Vec<TsigKey>,
}

impl TsigKeyring {
    pub fn new(keys: Vec<TsigKey>) -> Self {
        TsigKeyring { keys }
    }

    pub fn parse(specs: &[String]) -> Result<Self, String> {
        let mut keys = Vec::new();
        for spec in specs {
            let spec = spec.trim();
            if !spec.is_empty() {
                keys.push(TsigKey::parse(spec)?);
            }
        }
        Ok(TsigKeyring { keys })
    }

    /// The key of that name, matched case-insensitively as a domain name.
    ///
    /// The algorithm has to agree too: a key name is not a licence to use it with
    /// whatever algorithm the sender prefers, and answering BADKEY for a mismatch
    /// is what stops a peer from downgrading SHA-256 to SHA-1 by asking.
    pub fn get(&self, name: &str, algorithm: TsigAlgorithm) -> Option<&TsigKey> {
        let name = canonical_key_name(name);
        self.keys
            .iter()
            .find(|k| k.name == name && k.algorithm == algorithm)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

/// A TSIG record's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tsig {
    /// The owner name of the RR, which is the key name.
    pub key_name: String,
    pub algorithm_name: String,
    /// Seconds since the epoch, 48 bits on the wire.
    pub time_signed: u64,
    pub fudge: u16,
    pub mac: Vec<u8>,
    /// The message id as the signer wrote it, before any forwarder rewrote it.
    pub original_id: u16,
    /// A TSIG error code, or 0 in a normal signature.
    pub error: u16,
    /// For BADTIME, the signer's own time.
    pub other: Vec<u8>,
}

impl Tsig {
    /// Parse the RDATA of a TSIG record.
    fn parse_rdata(key_name: &str, rdata: &[u8]) -> Result<Self, String> {
        let (algorithm_name, rest) = read_name(rdata).ok_or("TSIG algorithm name is malformed")?;
        if rest.len() < 10 {
            return Err("TSIG RDATA is truncated before its time".to_string());
        }
        let time_signed = rest[..6].iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
        let fudge = u16::from_be_bytes([rest[6], rest[7]]);
        let mac_size = u16::from_be_bytes([rest[8], rest[9]]) as usize;
        let rest = &rest[10..];
        if rest.len() < mac_size + 6 {
            return Err("TSIG RDATA is truncated inside its MAC".to_string());
        }
        let mac = rest[..mac_size].to_vec();
        let rest = &rest[mac_size..];
        let original_id = u16::from_be_bytes([rest[0], rest[1]]);
        let error = u16::from_be_bytes([rest[2], rest[3]]);
        let other_len = u16::from_be_bytes([rest[4], rest[5]]) as usize;
        let rest = &rest[6..];
        if rest.len() < other_len {
            return Err("TSIG RDATA is truncated inside its other data".to_string());
        }
        Ok(Tsig {
            key_name: canonical_key_name(key_name),
            algorithm_name,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other: rest[..other_len].to_vec(),
        })
    }

    /// The RDATA bytes of this record.
    fn rdata_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = dname_to_bytes(&self.algorithm_name)
            .map_err(|e| format!("TSIG algorithm name {}: {e}", self.algorithm_name))?;
        out.extend_from_slice(&self.time_signed.to_be_bytes()[2..]); // 48 bits
        out.extend_from_slice(&self.fudge.to_be_bytes());
        out.extend_from_slice(&(self.mac.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.original_id.to_be_bytes());
        out.extend_from_slice(&self.error.to_be_bytes());
        out.extend_from_slice(&(self.other.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.other);
        Ok(out)
    }

    /// The "TSIG variables" half of the digest (RFC 8945 §4.3.3): everything
    /// about the record except the MAC itself.
    fn variables(&self) -> Result<Vec<u8>, String> {
        let mut out = dname_to_bytes(&self.key_name)
            .map_err(|e| format!("TSIG key name {}: {e}", self.key_name))?;
        out.extend_from_slice(&TSIG_CLASS.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // TTL, always 0
        out.extend_from_slice(
            &dname_to_bytes(&self.algorithm_name)
                .map_err(|e| format!("TSIG algorithm name: {e}"))?,
        );
        out.extend_from_slice(&self.time_signed.to_be_bytes()[2..]);
        out.extend_from_slice(&self.fudge.to_be_bytes());
        out.extend_from_slice(&self.error.to_be_bytes());
        out.extend_from_slice(&(self.other.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.other);
        Ok(out)
    }

    /// Just the timers, which is all that is hashed for the messages after the
    /// first in a transfer (RFC 8945 §5.3.1).
    fn timers(&self) -> Vec<u8> {
        let mut out = self.time_signed.to_be_bytes()[2..].to_vec();
        out.extend_from_slice(&self.fudge.to_be_bytes());
        out
    }
}

/// Why a TSIG did not verify. The numbers are the extended RCODEs RFC 8945 §4.2
/// puts in the record's error field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsigError {
    /// The MAC does not match: the sender does not hold this key, or something
    /// changed the message on the way.
    BadSig,
    /// No such key name (or not with that algorithm).
    BadKey,
    /// The MAC matched but the clocks disagree by more than the fudge.
    BadTime,
    /// The MAC was shorter than the algorithm's output. Accepting a truncated MAC
    /// is a policy this server does not have.
    BadTrunc,
    /// The record itself did not parse.
    FormErr,
}

impl TsigError {
    pub fn code(&self) -> u16 {
        match self {
            TsigError::BadSig => 16,
            TsigError::BadKey => 17,
            TsigError::BadTime => 18,
            TsigError::BadTrunc => 22,
            // Not a TSIG error code: a malformed record is a format error about
            // the message, and the record's error field stays 0.
            TsigError::FormErr => 0,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            TsigError::BadSig => "BADSIG: the MAC does not verify",
            TsigError::BadKey => "BADKEY: unknown key name or algorithm",
            TsigError::BadTime => "BADTIME: the signature's clock is outside the fudge",
            TsigError::BadTrunc => "BADTRUNC: the MAC is shorter than the algorithm's output",
            TsigError::FormErr => "FORMERR: the TSIG record is malformed",
        }
    }
}

/// What checking an incoming message concluded.
pub enum TsigCheck {
    /// No TSIG at all. Ordinary, and for most servers most of the time.
    Unsigned,
    /// It verified. The session is what a reply is signed with.
    Verified(TsigSession),
    /// It did not. The rejection carries what the error reply needs.
    Rejected(TsigRejection),
}

/// A verified request, and the state a reply needs.
///
/// Holds the request's MAC because a response is signed over it — that binding is
/// what stops a reply to one question being replayed as the reply to another.
pub struct TsigSession {
    key: TsigKey,
    /// The MAC of the request, or of the previous envelope once a transfer has
    /// started. RFC 8945 §5.3.1 chains them.
    previous_mac: Vec<u8>,
    /// Whether the first message of the exchange has been signed. Subsequent ones
    /// hash only the timers.
    first_signed: bool,
    original_id: u16,
}

impl TsigSession {
    /// The name of the key that authenticated the request, for logging.
    pub fn key_name(&self) -> &str {
        &self.key.name
    }

    /// Sign one response message, returning the bytes with a TSIG appended.
    ///
    /// Call it once per message of a zone transfer, in order: the MACs chain, so
    /// a reordered or dropped envelope fails at the client rather than passing
    /// unnoticed.
    pub fn sign(&mut self, message: Vec<u8>, now: u64) -> Result<Vec<u8>, String> {
        if message.len() < 12 {
            return Err("cannot sign a message shorter than a header".to_string());
        }
        let mut tsig = Tsig {
            key_name: self.key.name.clone(),
            algorithm_name: self.key.algorithm.wire_name().to_string(),
            time_signed: now,
            fudge: DEFAULT_FUDGE,
            mac: Vec::new(),
            original_id: u16::from_be_bytes([message[0], message[1]]),
            error: 0,
            other: Vec::new(),
        };

        let mut digest = Vec::new();
        push_prior_mac(&mut digest, &self.previous_mac);
        digest.extend_from_slice(&message);
        if self.first_signed {
            // A later envelope of a transfer: timers only (RFC 8945 §5.3.1).
            digest.extend_from_slice(&tsig.timers());
        } else {
            digest.extend_from_slice(&tsig.variables()?);
        }

        tsig.mac = mac(&self.key, &digest);
        self.previous_mac = tsig.mac.clone();
        self.first_signed = true;
        append_tsig(message, &tsig)
    }

    /// The id the signer used, which is what the digest of a reply must restore.
    pub fn original_id(&self) -> u16 {
        self.original_id
    }
}

/// A TSIG that did not verify, and enough of it to answer honestly.
pub struct TsigRejection {
    pub error: TsigError,
    key_name: String,
    algorithm_name: String,
    original_id: u16,
    /// Present only for BADTIME: the MAC verified, so the reply can be signed.
    key: Option<TsigKey>,
}

impl TsigRejection {
    pub fn key_name(&self) -> &str {
        &self.key_name
    }

    /// Attach the TSIG that reports this failure to an already-built response.
    ///
    /// BADKEY and BADSIG go back with an empty MAC — there is either no key to
    /// sign with or no reason to believe the sender holds it, and RFC 8945 §5.3.2
    /// asks for exactly that. BADTIME is signed, because the MAC did verify, and
    /// carries this server's time in the other-data field so the peer can see
    /// which of the two clocks is wrong (§5.2.3).
    pub fn attach(&self, response: Vec<u8>, now: u64) -> Result<Vec<u8>, String> {
        let mut tsig = Tsig {
            key_name: self.key_name.clone(),
            algorithm_name: self.algorithm_name.clone(),
            time_signed: now,
            fudge: DEFAULT_FUDGE,
            mac: Vec::new(),
            original_id: self.original_id,
            error: self.error.code(),
            other: Vec::new(),
        };
        if self.error == TsigError::BadTime {
            tsig.other = now.to_be_bytes()[2..].to_vec();
        }
        if let Some(key) = &self.key {
            let mut digest = Vec::new();
            digest.extend_from_slice(&response);
            digest.extend_from_slice(&tsig.variables()?);
            tsig.mac = mac(key, &digest);
        }
        append_tsig(response, &tsig)
    }
}

/// Check the TSIG on an incoming message, if it has one.
///
/// `packet` must be the bytes exactly as received: the MAC covers them, and a
/// message that has been parsed and re-serialized is not necessarily the same
/// bytes.
pub fn check_request(packet: &[u8], keyring: &TsigKeyring, now: u64) -> TsigCheck {
    let Some((offset, rdata, owner)) = find_tsig(packet) else {
        return TsigCheck::Unsigned;
    };
    let tsig = match Tsig::parse_rdata(&owner, rdata) {
        Ok(tsig) => tsig,
        Err(_) => {
            return TsigCheck::Rejected(TsigRejection {
                error: TsigError::FormErr,
                key_name: owner,
                algorithm_name: TsigAlgorithm::HmacSha256.wire_name().to_string(),
                original_id: u16::from_be_bytes([packet[0], packet[1]]),
                key: None,
            })
        }
    };

    let reject = |error: TsigError, key: Option<TsigKey>| {
        TsigCheck::Rejected(TsigRejection {
            error,
            key_name: tsig.key_name.clone(),
            algorithm_name: tsig.algorithm_name.clone(),
            original_id: tsig.original_id,
            key,
        })
    };

    // An algorithm we do not implement is indistinguishable, from the peer's side,
    // from a key we do not hold: either way we cannot check what it sent.
    let Some(algorithm) = TsigAlgorithm::from_name(&tsig.algorithm_name) else {
        return reject(TsigError::BadKey, None);
    };
    let Some(key) = keyring.get(&tsig.key_name, algorithm) else {
        return reject(TsigError::BadKey, None);
    };
    if tsig.mac.len() != algorithm.mac_len() {
        return reject(TsigError::BadTrunc, None);
    }

    // The digest is over the message without the TSIG, with the id the signer
    // used restored — a forwarder may have rewritten the one on the wire.
    let unsigned = strip_tsig(packet, offset, tsig.original_id);
    let mut digest = unsigned;
    match tsig.variables() {
        Ok(variables) => digest.extend_from_slice(&variables),
        Err(_) => return reject(TsigError::FormErr, None),
    }

    if !verify_mac(key, &digest, &tsig.mac) {
        return reject(TsigError::BadSig, None);
    }

    // Only now is the clock worth checking: a time outside the fudge from someone
    // who does hold the key is a clock problem, and it is reported differently
    // (signed, with our time) from someone who does not (§5.2.3).
    if now.abs_diff(tsig.time_signed) > tsig.fudge as u64 {
        return reject(TsigError::BadTime, Some(key.clone()));
    }

    TsigCheck::Verified(TsigSession {
        key: key.clone(),
        previous_mac: tsig.mac.clone(),
        first_signed: false,
        original_id: tsig.original_id,
    })
}

/// Sign a request with `key` — the client half, and what the tests drive both
/// sides through.
pub fn sign_request(message: Vec<u8>, key: &TsigKey, now: u64) -> Result<Vec<u8>, String> {
    if message.len() < 12 {
        return Err("cannot sign a message shorter than a header".to_string());
    }
    let mut tsig = Tsig {
        key_name: key.name.clone(),
        algorithm_name: key.algorithm.wire_name().to_string(),
        time_signed: now,
        fudge: DEFAULT_FUDGE,
        mac: Vec::new(),
        original_id: u16::from_be_bytes([message[0], message[1]]),
        error: 0,
        other: Vec::new(),
    };
    let mut digest = message.clone();
    digest.extend_from_slice(&tsig.variables()?);
    tsig.mac = mac(key, &digest);
    append_tsig(message, &tsig)
}

/// Verify a response against the request's MAC — the client half of a reply, and
/// of each envelope of a transfer.
///
/// `previous_mac` is the request's MAC for the first message and the previous
/// envelope's for the rest; on success the new MAC is returned to carry forward.
pub fn check_response(
    packet: &[u8],
    key: &TsigKey,
    previous_mac: &[u8],
    first: bool,
    now: u64,
) -> Result<Vec<u8>, TsigError> {
    let Some((offset, rdata, owner)) = find_tsig(packet) else {
        return Err(TsigError::FormErr);
    };
    let tsig = Tsig::parse_rdata(&owner, rdata).map_err(|_| TsigError::FormErr)?;
    if tsig.error != 0 {
        // The server is reporting a failure rather than signing an answer; its
        // own error code is the useful one to surface.
        return Err(match tsig.error {
            16 => TsigError::BadSig,
            17 => TsigError::BadKey,
            18 => TsigError::BadTime,
            22 => TsigError::BadTrunc,
            _ => TsigError::FormErr,
        });
    }
    if tsig.mac.len() != key.algorithm.mac_len() {
        return Err(TsigError::BadTrunc);
    }

    let mut digest = Vec::new();
    push_prior_mac(&mut digest, previous_mac);
    digest.extend_from_slice(&strip_tsig(packet, offset, tsig.original_id));
    if first {
        digest.extend_from_slice(&tsig.variables().map_err(|_| TsigError::FormErr)?);
    } else {
        digest.extend_from_slice(&tsig.timers());
    }

    if !verify_mac(key, &digest, &tsig.mac) {
        return Err(TsigError::BadSig);
    }
    if now.abs_diff(tsig.time_signed) > tsig.fudge as u64 {
        return Err(TsigError::BadTime);
    }
    Ok(tsig.mac)
}

// ---------------------------------------------------------------------------
// Bytes
// ---------------------------------------------------------------------------

/// The MAC of `data` under `key`.
fn mac(key: &TsigKey, data: &[u8]) -> Vec<u8> {
    let hmac_key = hmac::Key::new(key.algorithm.ring_algorithm(), &key.secret);
    hmac::sign(&hmac_key, data).as_ref().to_vec()
}

/// Whether `expected` is the MAC of `data`. Uses `ring`'s constant-time compare:
/// a MAC check that leaks how many leading bytes matched is a MAC check an
/// attacker can walk through one byte at a time.
fn verify_mac(key: &TsigKey, data: &[u8], expected: &[u8]) -> bool {
    let hmac_key = hmac::Key::new(key.algorithm.ring_algorithm(), &key.secret);
    hmac::verify(&hmac_key, data, expected).is_ok()
}

/// A prior MAC as it enters a digest: two bytes of length, then the MAC
/// (RFC 8945 §4.3.3). Nothing is added when there is none.
fn push_prior_mac(digest: &mut Vec<u8>, prior: &[u8]) {
    if !prior.is_empty() {
        digest.extend_from_slice(&(prior.len() as u16).to_be_bytes());
        digest.extend_from_slice(prior);
    }
}

/// The TSIG record at the end of `packet`: where it starts, its RDATA, and its
/// owner name.
///
/// `None` unless the **last** record of the additional section is a TSIG, which
/// is where RFC 8945 §5.1 requires it: a TSIG anywhere else does not cover the
/// records after it, so treating one as a signature would be a way to append
/// whatever you like to a signed message.
fn find_tsig(packet: &[u8]) -> Option<(usize, &[u8], String)> {
    if packet.len() < 12 {
        return None;
    }
    let counts: Vec<usize> = (0..4)
        .map(|i| u16::from_be_bytes([packet[4 + i * 2], packet[5 + i * 2]]) as usize)
        .collect();
    let (qd, an, ns, ar) = (counts[0], counts[1], counts[2], counts[3]);
    if ar == 0 {
        return None;
    }

    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(packet, pos)?;
        pos = pos.checked_add(4)?;
    }
    for _ in 0..(an + ns + ar - 1) {
        pos = skip_record(packet, pos)?;
    }

    // The last additional record: it starts here.
    let start = pos;
    let after_name = skip_name(packet, pos)?;
    let owner = read_name_at(packet, pos)?;
    if after_name + 10 > packet.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([packet[after_name], packet[after_name + 1]]);
    if rtype != TSIG_TYPE {
        return None;
    }
    let rdlen = u16::from_be_bytes([packet[after_name + 8], packet[after_name + 9]]) as usize;
    let rdata_start = after_name + 10;
    let rdata_end = rdata_start.checked_add(rdlen)?;
    if rdata_end > packet.len() {
        return None;
    }
    Some((start, &packet[rdata_start..rdata_end], owner))
}

/// The message as it was before the TSIG was appended: the bytes up to it, with
/// ARCOUNT one lower and the signer's own id restored.
fn strip_tsig(packet: &[u8], tsig_offset: usize, original_id: u16) -> Vec<u8> {
    let mut out = packet[..tsig_offset].to_vec();
    out[0..2].copy_from_slice(&original_id.to_be_bytes());
    let ar = u16::from_be_bytes([out[10], out[11]]).saturating_sub(1);
    out[10..12].copy_from_slice(&ar.to_be_bytes());
    out
}

/// `message` with `tsig` appended as the last additional record and ARCOUNT
/// raised to match.
fn append_tsig(mut message: Vec<u8>, tsig: &Tsig) -> Result<Vec<u8>, String> {
    let rdata = tsig.rdata_bytes()?;
    let owner = dname_to_bytes(&tsig.key_name)
        .map_err(|e| format!("TSIG key name {}: {e}", tsig.key_name))?;

    // The owner name goes in uncompressed. A pointer would still be legal, but
    // the record has to be removable by truncating the message, and a pointer
    // into it from anywhere else would break that.
    message.extend_from_slice(&owner);
    message.extend_from_slice(&TSIG_TYPE.to_be_bytes());
    message.extend_from_slice(&TSIG_CLASS.to_be_bytes());
    message.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
    message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    message.extend_from_slice(&rdata);

    let ar = u16::from_be_bytes([message[10], message[11]])
        .checked_add(1)
        .ok_or("additional count would overflow")?;
    message[10..12].copy_from_slice(&ar.to_be_bytes());
    Ok(message)
}

/// Past a name at `pos`, following the rule that a pointer ends it.
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *packet.get(pos)?;
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2);
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos = pos.checked_add(1 + len as usize)?;
    }
}

/// Past a whole resource record at `pos`.
fn skip_record(packet: &[u8], pos: usize) -> Option<usize> {
    let pos = skip_name(packet, pos)?;
    if pos + 10 > packet.len() {
        return None;
    }
    let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
    let end = pos.checked_add(10 + rdlen)?;
    if end > packet.len() {
        return None;
    }
    Some(end)
}

/// A name read from `packet` at `pos`, following one level of pointer. Used for
/// the TSIG owner name only, where the name is the key's.
fn read_name_at(packet: &[u8], pos: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut pos = pos;
    let mut jumps = 0;
    loop {
        let len = *packet.get(pos)?;
        if len & 0xc0 == 0xc0 {
            let target = u16::from_be_bytes([packet[pos] & 0x3f, *packet.get(pos + 1)?]) as usize;
            jumps += 1;
            if jumps > 4 {
                return None;
            }
            pos = target;
            continue;
        }
        if len == 0 {
            break;
        }
        let start = pos + 1;
        let end = start + len as usize;
        labels.push(String::from_utf8_lossy(packet.get(start..end)?).to_string());
        pos = end;
    }
    Some(if labels.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", labels.join("."))
    })
}

/// A name at the start of `data`, and what follows it. No compression: this reads
/// the algorithm name out of TSIG RDATA, where RFC 3597 §4 forbids pointers.
fn read_name(data: &[u8]) -> Option<(String, &[u8])> {
    let mut labels = Vec::new();
    let mut pos = 0;
    loop {
        let len = *data.get(pos)? as usize;
        if len & 0xc0 != 0 {
            return None; // a pointer has no business in here
        }
        if len == 0 {
            pos += 1;
            break;
        }
        let start = pos + 1;
        let end = start + len;
        labels.push(String::from_utf8_lossy(data.get(start..end)?).to_string());
        pos = end;
    }
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        format!("{}.", labels.join("."))
    };
    Some((name, &data[pos..]))
}

/// A key name in the form it is compared and hashed in: absolute and down-cased,
/// because it is a domain name (RFC 4343).
fn canonical_key_name(name: &str) -> String {
    let mut name = name.trim().to_ascii_lowercase();
    if !name.ends_with('.') {
        name.push('.');
    }
    name
}

/// The current time, for callers that do not have one to hand.
pub fn now() -> u64 {
    current_unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DnsMessage, OpCode, QueryClass, QuerySection, ResponseCode};

    fn test_key() -> TsigKey {
        // 32 bytes, the natural length for HMAC-SHA256.
        TsigKey::new("transfer.key.", TsigAlgorithm::HmacSha256, vec![0x0b; 32])
    }

    fn query_bytes(qname: &str, qtype: u16) -> Vec<u8> {
        let msg = DnsMessage {
            id: 0x4d2,
            response: false,
            opcode: OpCode::Query,
            authoritive: false,
            truncation: false,
            recursion: false,
            recursion_ok: false,
            ad: false,
            cd: false,
            rcode: ResponseCode::Ok,
            queries: vec![QuerySection {
                qname: qname.to_string(),
                qtype,
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        };
        let mut buf = vec![0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("serialize");
        buf.truncate(n);
        buf
    }

    // -----------------------------------------------------------------
    // Keys
    // -----------------------------------------------------------------

    #[test]
    fn test_key_specs_parse() {
        let with_alg = TsigKey::parse("hmac-sha512:my.key:AAECAwQFBgcICQoLDA0ODw==").unwrap();
        assert_eq!(with_alg.algorithm, TsigAlgorithm::HmacSha512);
        assert_eq!(with_alg.name, "my.key.", "absolute and down-cased");

        let default = TsigKey::parse("Other.Key.:AAECAwQFBgcICQoLDA0ODw==").unwrap();
        assert_eq!(
            default.algorithm,
            TsigAlgorithm::HmacSha256,
            "SHA-256 is what RFC 8945 requires, so it is the default"
        );
        assert_eq!(default.name, "other.key.");
    }

    #[test]
    fn test_bad_key_specs_are_errors() {
        assert!(TsigKey::parse("no-secret").is_err());
        assert!(TsigKey::parse("hmac-md5:k:AAEC").is_err(), "MD5 is deprecated");
        assert!(TsigKey::parse("hmac-sha256:k:not base64!").is_err());
        assert!(TsigKey::parse("hmac-sha256::AAECAwQFBgcICQoLDA0ODw==").is_err(), "no name");
    }

    /// A key name is not a licence to pick the algorithm: answering BADKEY for a
    /// mismatch is what stops a peer downgrading SHA-256 to SHA-1 by asking.
    #[test]
    fn test_the_keyring_matches_name_and_algorithm() {
        let ring = TsigKeyring::new(vec![test_key()]);
        assert!(ring.get("TRANSFER.KEY.", TsigAlgorithm::HmacSha256).is_some());
        assert!(ring.get("transfer.key", TsigAlgorithm::HmacSha256).is_some());
        assert!(ring.get("transfer.key.", TsigAlgorithm::HmacSha1).is_none());
        assert!(ring.get("other.key.", TsigAlgorithm::HmacSha256).is_none());
    }

    // -----------------------------------------------------------------
    // Signing and verifying
    // -----------------------------------------------------------------

    #[test]
    fn test_a_signed_request_verifies() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;

        let signed = sign_request(query_bytes("example.com.", 252), &key, now).unwrap();

        // It is still a parseable DNS message, with the TSIG in its additionals.
        let parsed = DnsMessage::try_from_bytes(&signed).expect("still a DNS message");
        assert_eq!(parsed.queries[0].qname, "example.com.");
        assert_eq!(parsed.additionals.len(), 1);
        assert_eq!(parsed.additionals[0].rdata.rtype, TSIG_TYPE);

        match check_request(&signed, &ring, now) {
            TsigCheck::Verified(session) => assert_eq!(session.key_name(), "transfer.key."),
            TsigCheck::Unsigned => panic!("the request is signed"),
            TsigCheck::Rejected(r) => panic!("should verify: {}", r.error.reason()),
        }
    }

    #[test]
    fn test_an_unsigned_request_is_unsigned_not_rejected() {
        let ring = TsigKeyring::new(vec![test_key()]);
        assert!(matches!(
            check_request(&query_bytes("example.com.", 1), &ring, 1_800_000_000),
            TsigCheck::Unsigned
        ));
    }

    /// The whole point: a message altered after signing does not verify. The bit
    /// flipped here is in the question, which is what a TSIG is protecting.
    #[test]
    fn test_a_tampered_message_is_badsig() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;
        let mut signed = sign_request(query_bytes("example.com.", 252), &key, now).unwrap();

        signed[13] ^= 0x20; // 'e' -> 'E' in the question name
        match check_request(&signed, &ring, now) {
            TsigCheck::Rejected(r) => assert_eq!(r.error, TsigError::BadSig),
            _ => panic!("a changed message must not verify"),
        }
    }

    #[test]
    fn test_a_different_secret_is_badsig() {
        let signer = test_key();
        let ring = TsigKeyring::new(vec![TsigKey::new(
            "transfer.key.",
            TsigAlgorithm::HmacSha256,
            vec![0x0c; 32],
        )]);
        let now = 1_800_000_000;
        let signed = sign_request(query_bytes("example.com.", 252), &signer, now).unwrap();
        match check_request(&signed, &ring, now) {
            TsigCheck::Rejected(r) => assert_eq!(r.error, TsigError::BadSig),
            _ => panic!("the wrong secret must not verify"),
        }
    }

    #[test]
    fn test_an_unknown_key_is_badkey() {
        let key = test_key();
        let now = 1_800_000_000;
        let signed = sign_request(query_bytes("example.com.", 252), &key, now).unwrap();
        match check_request(&signed, &TsigKeyring::default(), now) {
            TsigCheck::Rejected(r) => {
                assert_eq!(r.error, TsigError::BadKey);
                assert_eq!(r.key_name(), "transfer.key.", "the error names the key asked for");
            }
            _ => panic!("an empty keyring knows no keys"),
        }
    }

    /// The clock check, both directions, and the fudge boundary.
    #[test]
    fn test_a_stale_signature_is_badtime() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let signed_at = 1_800_000_000;
        let signed = sign_request(query_bytes("example.com.", 252), &key, signed_at).unwrap();

        for skew in [DEFAULT_FUDGE as u64, 0] {
            assert!(
                matches!(
                    check_request(&signed, &ring, signed_at + skew),
                    TsigCheck::Verified(_)
                ),
                "{skew}s of skew is inside the fudge"
            );
        }
        for now in [
            signed_at + DEFAULT_FUDGE as u64 + 1,
            signed_at - DEFAULT_FUDGE as u64 - 1,
        ] {
            match check_request(&signed, &ring, now) {
                TsigCheck::Rejected(r) => assert_eq!(r.error, TsigError::BadTime),
                _ => panic!("{now} is outside the fudge"),
            }
        }
    }

    /// A TSIG that is not the last record covers nothing after it, so it is not a
    /// signature at all — accepting one would let anything be appended to a
    /// signed message.
    #[test]
    fn test_a_tsig_that_is_not_last_is_not_a_signature() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;
        let mut signed = sign_request(query_bytes("example.com.", 252), &key, now).unwrap();

        // Append an A record after the TSIG and bump ARCOUNT.
        let extra = b"\x03www\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04";
        signed.extend_from_slice(extra);
        let ar = u16::from_be_bytes([signed[10], signed[11]]) + 1;
        signed[10..12].copy_from_slice(&ar.to_be_bytes());

        assert!(
            matches!(check_request(&signed, &ring, now), TsigCheck::Unsigned),
            "the TSIG no longer signs the message, so the message is unsigned"
        );
    }

    #[test]
    fn test_a_truncated_mac_is_badtrunc() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;

        // Sign, then shorten the MAC in place — RDLEN, MAC size and the MAC.
        let signed = sign_request(query_bytes("example.com.", 252), &key, now).unwrap();
        let (offset, rdata, owner) = find_tsig(&signed).unwrap();
        let mut tsig = Tsig::parse_rdata(&owner, rdata).unwrap();
        tsig.mac.truncate(16);
        let rebuilt = append_tsig(strip_tsig(&signed, offset, tsig.original_id), &tsig).unwrap();

        match check_request(&rebuilt, &ring, now) {
            TsigCheck::Rejected(r) => assert_eq!(r.error, TsigError::BadTrunc),
            _ => panic!("half a MAC is not a MAC"),
        }
    }

    // -----------------------------------------------------------------
    // Responses
    // -----------------------------------------------------------------

    /// A response is signed over the *request's* MAC, which is what binds the two
    /// together: a reply to one question cannot be replayed as the reply to
    /// another.
    #[test]
    fn test_a_response_verifies_against_the_request() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;

        let request = sign_request(query_bytes("example.com.", 252), &key, now).unwrap();
        let request_mac = {
            let (_, rdata, owner) = find_tsig(&request).unwrap();
            Tsig::parse_rdata(&owner, rdata).unwrap().mac
        };
        let TsigCheck::Verified(mut session) = check_request(&request, &ring, now) else {
            panic!("the request should verify");
        };

        let response = session.sign(query_bytes("example.com.", 252), now).unwrap();
        check_response(&response, &key, &request_mac, true, now)
            .expect("the client should accept the reply");

        // And a reply signed against a *different* request does not verify.
        let other_mac = vec![0xaa; 32];
        assert_eq!(
            check_response(&response, &key, &other_mac, true, now).unwrap_err(),
            TsigError::BadSig
        );
    }

    /// A transfer's envelopes chain: each MAC covers the previous one, so a
    /// dropped or reordered message fails instead of passing unnoticed.
    #[test]
    fn test_transfer_envelopes_chain() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;

        let request = sign_request(query_bytes("example.com.", 252), &key, now).unwrap();
        let request_mac = {
            let (_, rdata, owner) = find_tsig(&request).unwrap();
            Tsig::parse_rdata(&owner, rdata).unwrap().mac
        };
        let TsigCheck::Verified(mut session) = check_request(&request, &ring, now) else {
            panic!("the request should verify");
        };

        let envelopes: Vec<Vec<u8>> = (0..3)
            .map(|i| session.sign(query_bytes(&format!("e{i}.example.com."), 252), now).unwrap())
            .collect();

        // In order: each verifies against the previous MAC.
        let mut previous = request_mac.clone();
        for (i, envelope) in envelopes.iter().enumerate() {
            previous = check_response(envelope, &key, &previous, i == 0, now)
                .unwrap_or_else(|e| panic!("envelope {i} should verify: {}", e.reason()));
        }

        // Out of order: the second envelope does not verify against the request.
        assert_eq!(
            check_response(&envelopes[1], &key, &request_mac, false, now).unwrap_err(),
            TsigError::BadSig,
            "the chain is what makes a reordered envelope detectable"
        );
    }

    /// BADKEY and BADSIG go back unsigned; BADTIME is signed and carries our
    /// clock so the peer can see which side is wrong.
    #[test]
    fn test_error_replies_carry_the_right_tsig() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let signed_at = 1_800_000_000;
        let request = sign_request(query_bytes("example.com.", 252), &key, signed_at).unwrap();

        // BADKEY: unsigned, empty MAC.
        let TsigCheck::Rejected(badkey) = check_request(&request, &TsigKeyring::default(), signed_at)
        else {
            panic!("expected a rejection");
        };
        let reply = badkey.attach(query_bytes("example.com.", 252), signed_at).unwrap();
        let (_, rdata, owner) = find_tsig(&reply).unwrap();
        let tsig = Tsig::parse_rdata(&owner, rdata).unwrap();
        assert_eq!(tsig.error, 17);
        assert!(tsig.mac.is_empty(), "nothing to sign with");
        assert!(tsig.other.is_empty());

        // BADTIME: signed, and the other-data field is our time.
        let later = signed_at + 10_000;
        let TsigCheck::Rejected(badtime) = check_request(&request, &ring, later) else {
            panic!("expected a rejection");
        };
        assert_eq!(badtime.error, TsigError::BadTime);
        let reply = badtime.attach(query_bytes("example.com.", 252), later).unwrap();
        let (_, rdata, owner) = find_tsig(&reply).unwrap();
        let tsig = Tsig::parse_rdata(&owner, rdata).unwrap();
        assert_eq!(tsig.error, 18);
        assert_eq!(tsig.mac.len(), 32, "the MAC verified, so the reply is signed");
        assert_eq!(
            tsig.other.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64),
            later,
            "so the peer can see whose clock is wrong"
        );
    }

    // -----------------------------------------------------------------
    // The record itself
    // -----------------------------------------------------------------

    #[test]
    fn test_tsig_rdata_round_trips() {
        let tsig = Tsig {
            key_name: "transfer.key.".into(),
            algorithm_name: "hmac-sha256.".into(),
            time_signed: 0x0000_1234_5678_9abc & 0x0000_ffff_ffff_ffff,
            fudge: 300,
            mac: vec![0xab; 32],
            original_id: 0x4d2,
            error: 18,
            other: vec![0, 0, 0, 1, 2, 3],
        };
        let rdata = tsig.rdata_bytes().unwrap();
        let parsed = Tsig::parse_rdata("transfer.key.", &rdata).unwrap();
        assert_eq!(parsed, tsig);
    }

    #[test]
    fn test_malformed_rdata_is_an_error_not_a_panic() {
        assert!(Tsig::parse_rdata("k.", &[]).is_err());
        assert!(Tsig::parse_rdata("k.", b"\x0chmac-sha256\x00").is_err(), "no timers");
        // A MAC size that runs past the end.
        let mut rdata = b"\x0bhmac-sha256\x00".to_vec();
        rdata.extend_from_slice(&[0, 0, 0, 0, 0, 1]); // time
        rdata.extend_from_slice(&300u16.to_be_bytes()); // fudge
        rdata.extend_from_slice(&9999u16.to_be_bytes()); // MAC size
        assert!(Tsig::parse_rdata("k.", &rdata).is_err());
    }

    /// The time signed is 48 bits on the wire, and 2038 is not a problem for it.
    #[test]
    fn test_time_signed_is_48_bits() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let far_future = 1u64 << 40;
        let signed = sign_request(query_bytes("example.com.", 1), &key, far_future).unwrap();
        assert!(matches!(
            check_request(&signed, &ring, far_future),
            TsigCheck::Verified(_)
        ));
    }
}
