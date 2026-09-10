//! TSIG: authenticating a DNS message with a shared secret (RFC 8945).
//!
//! Works on bytes, not a parsed [`crate::DnsMessage`]: name compression is a
//! choice, so a re-serialized message is not the bytes that were sent.
//!
//! What the digest covers (RFC 8945 §4.3.3, §5.4.2):
//!
//! ```text
//! request:   message-without-TSIG (ARCOUNT-1, ID = Original ID) || TSIG variables
//! response:  2-byte length || request MAC || message-without-TSIG || TSIG variables
//! envelope:  2-byte length || previous MAC || message-without-TSIG || timers only
//! ```
//!
//! "TSIG variables" is the key name, class (ANY), TTL (0), algorithm name, time
//! signed, fudge, error and other data; "timers only" is the time signed and the
//! fudge, used for every message after the first in a transfer (§5.3.1).

use crate::error::{ConfigError, ConfigResult};

/// A name from config, as uncompressed wire octets.
///
/// Through [`crate::Name`], which is the one text-to-wire door: RFC 8945's key
/// and algorithm names are domain names, and the digest covers their encoded
/// form. `dname_to_bytes` was a second decoder that refused RFC 1035 §5.1's
/// escapes, so the two disagreed about what a key name meant.
fn name_wire(name: &str) -> crate::error::WireResult<Vec<u8>> {
    Ok(crate::Name::from_presentation(name)?
        .as_ref()
        .as_wire()
        .to_vec())
}
use crate::utils::current_unix_timestamp;
use base64::Engine;
use ring::hmac;

/// The TSIG pseudo-record type. A meta-type: no zone ever holds one.
const TSIG_TYPE: u16 = 250;

/// A TSIG RR is always class ANY with TTL 0 (RFC 8945 §4.2).
const TSIG_CLASS: u16 = 255;

/// The clock skew a signature tolerates, in seconds (RFC 8945 §4.2 suggests 300).
const DEFAULT_FUDGE: u16 = 300;

/// The MAC algorithms this implements. HMAC-MD5 is absent: deprecated by
/// RFC 8945.
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

    /// Match a wire or configured name, with or without the trailing dot and in
    /// any case (RFC 4343).
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

    /// The full MAC length in bytes. A shorter MAC is [`TsigError::BadTrunc`],
    /// not an accepted truncation.
    fn mac_len(&self) -> usize {
        match self {
            TsigAlgorithm::HmacSha1 => 20,
            TsigAlgorithm::HmacSha256 => 32,
            TsigAlgorithm::HmacSha384 => 48,
            TsigAlgorithm::HmacSha512 => 64,
        }
    }
}

/// What a TSIG key may rewrite through dynamic UPDATE (RFC 2136 §3.3).
///
/// Denied by default, unlike the transfer scope: an update rewrites the
/// original, so an unscoped key must not inherit write access. Three states
/// rather than a `Vec` with an overloaded empty case.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UpdatePolicy {
    /// No zone, by any key holder.
    #[default]
    Denied,
    /// These zone apexes, absolute and down-cased.
    Zones(Vec<String>),
    /// Every zone this server is authoritative for. Spelled `*` in a key spec,
    /// so granting it is something an operator typed.
    Any,
}

impl UpdatePolicy {
    /// Whether this policy authorizes rewriting the zone at `apex`.
    ///
    /// Matched against the apex: an UPDATE names one zone (RFC 2136 §3.1), so a
    /// rule matching anything less specific authorizes more than it names.
    pub fn allows(&self, apex: &str) -> bool {
        match self {
            UpdatePolicy::Denied => false,
            UpdatePolicy::Any => true,
            UpdatePolicy::Zones(zones) => zones.contains(&canonical_key_name(apex)),
        }
    }
}

impl std::fmt::Display for UpdatePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdatePolicy::Denied => write!(f, "no zones"),
            UpdatePolicy::Any => write!(f, "every zone"),
            UpdatePolicy::Zones(zones) => write!(f, "{}", zones.join(", ")),
        }
    }
}

/// A shared secret and the name it is known by.
#[derive(Debug, Clone)]
pub struct TsigKey {
    /// The key name, absolute and down-cased: it is hashed in canonical form.
    pub name: String,
    pub algorithm: TsigAlgorithm,
    secret: Vec<u8>,
    /// The zone apexes this key may transfer, absolute and down-cased. Empty
    /// means every zone, kept so a binary upgrade cannot stop every transfer
    /// on a working deployment; the startup banner names each key's scope.
    zones: Vec<String>,
    /// What this key may rewrite through dynamic UPDATE. Denies by default,
    /// unlike `zones` — see [`UpdatePolicy`].
    update: UpdatePolicy,
}

impl TsigKey {
    pub fn new(name: &str, algorithm: TsigAlgorithm, secret: Vec<u8>) -> Self {
        TsigKey {
            name: canonical_key_name(name),
            algorithm,
            secret,
            zones: Vec::new(),
            update: UpdatePolicy::Denied,
        }
    }

    /// Restrict this key to the given zone apexes. No zones means no restriction.
    pub fn for_zones<I, S>(mut self, zones: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.zones = zones
            .into_iter()
            .map(|z| canonical_key_name(z.as_ref()))
            .collect();
        self
    }

    /// Whether this key authorizes a transfer of the zone at `apex`.
    ///
    /// Matched against the apex: a transfer hands over a whole zone, so anything
    /// less specific authorizes more than it names.
    pub fn may_transfer(&self, apex: &str) -> bool {
        if self.zones.is_empty() {
            return true;
        }
        let apex = canonical_key_name(apex);
        self.zones.contains(&apex)
    }

    /// Restrict — or grant — what this key may rewrite through dynamic UPDATE.
    pub fn for_updates(mut self, policy: UpdatePolicy) -> Self {
        self.update = policy;
        self
    }

    /// Whether this key authorizes a dynamic UPDATE of the zone at `apex`.
    ///
    /// Not derived from [`TsigKey::may_transfer`]: reading a zone and rewriting
    /// it are two permissions.
    pub fn may_update(&self, apex: &str) -> bool {
        self.update.allows(apex)
    }

    /// What this key may rewrite, for the startup banner.
    pub fn update_scope(&self) -> &UpdatePolicy {
        &self.update
    }

    /// The zones this key is restricted to, or `None` if it is unrestricted.
    fn zone_scope(&self) -> Option<&[String]> {
        if self.zones.is_empty() {
            None
        } else {
            Some(&self.zones)
        }
    }

    /// Parse `[algorithm:]name:base64secret[:transfer-zones[:update-zones]]`;
    /// the first three fields are the shape `dig -y` uses.
    ///
    /// The algorithm defaults to HMAC-SHA256, but a zone list requires it spelled
    /// out: `name:secret:zones` and `alg:name:secret` are both three fields. An
    /// absent fifth field is [`UpdatePolicy::Denied`]; `*` in either list means
    /// every zone. An unparsable spec is an error, not a skip.
    pub fn parse(spec: &str) -> ConfigResult<Self> {
        let parts: Vec<&str> = spec.split(':').collect();
        let named_algorithm = |alg: &str| {
            TsigAlgorithm::from_name(alg)
                .ok_or_else(|| ConfigError::new(format!("unknown TSIG algorithm {alg:?}")))
        };
        // `None` for "no field at all" rather than `""`: an empty field reads as
        // a narrowing, and an empty list means the opposite.
        let (algorithm, name, secret, zones, updates) = match parts.as_slice() {
            [name, secret] => (TsigAlgorithm::HmacSha256, *name, *secret, None, None),
            [alg, name, secret] => (named_algorithm(alg)?, *name, *secret, None, None),
            [alg, name, secret, zones] => {
                (named_algorithm(alg)?, *name, *secret, Some(*zones), None)
            }
            [alg, name, secret, zones, updates] => (
                named_algorithm(alg)?,
                *name,
                *secret,
                Some(*zones),
                Some(*updates),
            ),
            _ => {
                return Err(ConfigError::new(format!(
                    "TSIG key {spec:?} is not \
                     [algorithm:]name:base64secret[:transfer-zones[:update-zones]] \
                     (a zone list needs the algorithm spelled out, since otherwise it cannot \
                     be told apart from one; `*` means every zone)"
                )))
            }
        };
        if name.is_empty() {
            return Err(ConfigError::new("TSIG key name is empty"));
        }
        let secret = base64::prelude::BASE64_STANDARD
            .decode(secret)
            .map_err(|e| {
                ConfigError::new(format!("TSIG secret for {name:?} is not base64: {e}"))
            })?;
        if secret.is_empty() {
            return Err(ConfigError::new(format!(
                "TSIG secret for {name:?} is empty"
            )));
        }

        // `*` and an absent field both give the empty list, i.e. unrestricted.
        let allowed = match zones {
            Some(list) => parse_key_zone_list(name, "transfer", list)?.unwrap_or_default(),
            None => Vec::new(),
        };
        let update = match updates {
            None => UpdatePolicy::Denied,
            Some(list) => match parse_key_zone_list(name, "update", list)? {
                None => UpdatePolicy::Any,
                Some(zones) => {
                    UpdatePolicy::Zones(zones.iter().map(|z| canonical_key_name(z)).collect())
                }
            },
        };
        Ok(TsigKey::new(name, algorithm, secret)
            .for_zones(allowed)
            .for_updates(update))
    }
}

/// One comma-separated zone list from a key spec: `None` for `*` (every zone),
/// the entries otherwise. `field` names the list in the error.
///
/// An empty entry is refused: silently it would narrow the list, or widen it to
/// everything, which is what an empty transfer list means.
fn parse_key_zone_list(name: &str, field: &str, list: &str) -> ConfigResult<Option<Vec<String>>> {
    if list.trim() == "*" {
        return Ok(None);
    }
    let mut zones = Vec::new();
    for zone in list.split(',') {
        if zone.trim().is_empty() {
            return Err(ConfigError::new(format!(
                "TSIG key {name:?} has an empty zone in its {field} list {list:?}"
            )));
        }
        zones.push(zone.trim().to_string());
    }
    Ok(Some(zones))
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

    pub fn parse(specs: &[String]) -> ConfigResult<Self> {
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
    /// The algorithm has to agree too: BADKEY for a mismatch stops a peer
    /// downgrading SHA-256 to SHA-1 by asking.
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

    /// Every key, for reporting what the transfer policy actually is.
    pub fn keys(&self) -> impl Iterator<Item = &TsigKey> {
        self.keys.iter()
    }

    /// One line per key: name, transfer scope, update scope. Printed at startup,
    /// so that "this key can transfer everything" is a visible decision.
    ///
    /// The update scope is named only when it is not [`UpdatePolicy::Denied`].
    pub fn describe(&self) -> String {
        self.keys
            .iter()
            .map(|key| {
                let transfer = match key.zone_scope() {
                    Some(zones) => zones.join(","),
                    None => "every zone".to_string(),
                };
                match key.update_scope() {
                    UpdatePolicy::Denied => format!("{} -> {transfer}", key.name),
                    granted => format!("{} -> {transfer}, updates {granted}", key.name),
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
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
    fn parse_rdata(key_name: &str, rdata: &[u8]) -> ConfigResult<Self> {
        let (algorithm_name, rest) =
            read_name(rdata).ok_or_else(|| ConfigError::new("TSIG algorithm name is malformed"))?;
        if rest.len() < 10 {
            return Err(ConfigError::new("TSIG RDATA is truncated before its time"));
        }
        let time_signed = rest[..6].iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
        let fudge = u16::from_be_bytes([rest[6], rest[7]]);
        let mac_size = u16::from_be_bytes([rest[8], rest[9]]) as usize;
        let rest = &rest[10..];
        if rest.len() < mac_size + 6 {
            return Err(ConfigError::new("TSIG RDATA is truncated inside its MAC"));
        }
        let mac = rest[..mac_size].to_vec();
        let rest = &rest[mac_size..];
        let original_id = u16::from_be_bytes([rest[0], rest[1]]);
        let error = u16::from_be_bytes([rest[2], rest[3]]);
        let other_len = u16::from_be_bytes([rest[4], rest[5]]) as usize;
        let rest = &rest[6..];
        if rest.len() < other_len {
            return Err(ConfigError::new(
                "TSIG RDATA is truncated inside its other data",
            ));
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
    fn rdata_bytes(&self) -> ConfigResult<Vec<u8>> {
        let mut out = name_wire(&self.algorithm_name).map_err(|e| {
            ConfigError::new(format!("TSIG algorithm name {}: {e}", self.algorithm_name))
        })?;
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
    fn variables(&self) -> ConfigResult<Vec<u8>> {
        let mut out = name_wire(&self.key_name)
            .map_err(|e| ConfigError::new(format!("TSIG key name {}: {e}", self.key_name)))?;
        out.extend_from_slice(&TSIG_CLASS.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // TTL, always 0
        out.extend_from_slice(
            &name_wire(&self.algorithm_name)
                .map_err(|e| ConfigError::new(format!("TSIG algorithm name: {e}")))?,
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
    /// The MAC does not match: wrong key, or the message changed on the way.
    BadSig,
    /// No such key name (or not with that algorithm).
    BadKey,
    /// The MAC matched but the clocks disagree by more than the fudge.
    BadTime,
    /// The MAC was shorter than the algorithm's output. Truncated MACs are not
    /// accepted.
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
            // Not a TSIG error code: a malformed record is FORMERR about the
            // message, and the record's error field stays 0.
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
    /// No TSIG at all.
    Unsigned,
    /// It verified. The session is what a reply is signed with.
    Verified(TsigSession),
    /// It did not. The rejection carries what the error reply needs.
    Rejected(TsigRejection),
}

/// A verified request, and the state a reply needs.
///
/// Holds the request's MAC because a response is signed over it: that binding
/// stops a reply to one question being replayed as the reply to another.
pub struct TsigSession {
    key: TsigKey,
    /// The request's MAC, or the previous envelope's once a transfer has started
    /// (RFC 8945 §5.3.1 chains them).
    previous_mac: Vec<u8>,
    /// Whether the first message has been signed. Later ones hash only timers.
    first_signed: bool,
}

impl TsigSession {
    /// The name of the key that authenticated the request, for logging.
    pub fn key_name(&self) -> &str {
        &self.key.name
    }

    /// Whether the key that authenticated this request may transfer `apex`.
    ///
    /// On the session, not looked up by name: a key name is attacker-supplied
    /// until the MAC verifies.
    pub fn may_transfer(&self, apex: &str) -> bool {
        self.key.may_transfer(apex)
    }

    /// Whether the key that authenticated this request may rewrite `apex`
    /// through dynamic UPDATE (RFC 2136 §3.3). On the session, per
    /// [`TsigSession::may_transfer`].
    pub fn may_update(&self, apex: &str) -> bool {
        self.key.may_update(apex)
    }

    /// Sign one response message, returning the bytes with a TSIG appended.
    ///
    /// Call once per message of a transfer, in order: the MACs chain, so a
    /// reordered or dropped envelope fails at the client.
    pub fn sign(&mut self, message: Vec<u8>, now: u64) -> ConfigResult<Vec<u8>> {
        if message.len() < 12 {
            return Err(ConfigError::new(
                "cannot sign a message shorter than a header",
            ));
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
    /// BADKEY and BADSIG go back with an empty MAC (RFC 8945 §5.3.2): no key to
    /// sign with. BADTIME is signed — the MAC did verify — and carries this
    /// server's time so the peer can see which clock is wrong (§5.2.3).
    pub fn attach(&self, response: Vec<u8>, now: u64) -> ConfigResult<Vec<u8>> {
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
/// `packet` must be the bytes exactly as received: a parsed and re-serialized
/// message is not necessarily the same bytes.
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

    // An algorithm we do not implement is, from the peer's side, a key we do not
    // hold.
    let Some(algorithm) = TsigAlgorithm::from_name(&tsig.algorithm_name) else {
        return reject(TsigError::BadKey, None);
    };
    let Some(key) = keyring.get(&tsig.key_name, algorithm) else {
        return reject(TsigError::BadKey, None);
    };
    if tsig.mac.len() != algorithm.mac_len() {
        return reject(TsigError::BadTrunc, None);
    }

    // Digest the message without the TSIG, with the signer's id restored: a
    // forwarder may have rewritten the one on the wire.
    let unsigned = strip_tsig(packet, offset, tsig.original_id);
    let mut digest = unsigned;
    match tsig.variables() {
        Ok(variables) => digest.extend_from_slice(&variables),
        Err(_) => return reject(TsigError::FormErr, None),
    }

    if !verify_mac(key, &digest, &tsig.mac) {
        return reject(TsigError::BadSig, None);
    }

    // Clock last: BADTIME is reported signed and with our time (§5.2.3), which
    // is only defensible once the MAC has verified.
    if now.abs_diff(tsig.time_signed) > tsig.fudge as u64 {
        return reject(TsigError::BadTime, Some(key.clone()));
    }

    TsigCheck::Verified(TsigSession {
        key: key.clone(),
        previous_mac: tsig.mac.clone(),
        first_signed: false,
    })
}

/// Sign a request with `key`: the client half.
pub fn sign_request(message: Vec<u8>, key: &TsigKey, now: u64) -> ConfigResult<Vec<u8>> {
    if message.len() < 12 {
        return Err(ConfigError::new(
            "cannot sign a message shorter than a header",
        ));
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

/// The MAC carried by a signed message. A client keeps its request's MAC: a
/// response's digest opens with it (RFC 8945 §4.3.3).
pub fn request_mac(packet: &[u8]) -> Option<Vec<u8>> {
    let (_, rdata, owner) = find_tsig(packet)?;
    Tsig::parse_rdata(&owner, rdata).ok().map(|tsig| tsig.mac)
}

/// Verify a response, or one envelope of a transfer: the client half.
///
/// `previous_mac` is the request's MAC for the first message and the previous
/// envelope's for the rest; the new MAC is returned to carry forward.
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
        // The server is reporting a failure rather than signing an answer.
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

/// The MAC of `data` under `key`.
fn mac(key: &TsigKey, data: &[u8]) -> Vec<u8> {
    let hmac_key = hmac::Key::new(key.algorithm.ring_algorithm(), &key.secret);
    hmac::sign(&hmac_key, data).as_ref().to_vec()
}

/// Whether `expected` is the MAC of `data`. `ring`'s compare is constant-time:
/// leaking how many leading bytes matched walks the MAC a byte at a time.
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

/// The TSIG at the end of `packet`: its offset, RDATA and owner name.
///
/// `None` unless the last record of the additional section is a TSIG
/// (RFC 8945 §5.1): elsewhere it does not cover what follows it, so honouring
/// one would let anything be appended to a signed message.
fn find_tsig(packet: &[u8]) -> Option<(usize, &[u8], String)> {
    if packet.len() < 12 {
        return None;
    }
    // An array, not a `Vec`: collecting heap-allocates 32 bytes on every packet
    // received, ahead of the `ar == 0` check below.
    let counts: [usize; 4] = std::array::from_fn(|i| {
        u16::from_be_bytes([packet[4 + i * 2], packet[5 + i * 2]]) as usize
    });
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

    let start = pos;
    let after_name = skip_name(packet, pos)?;
    if after_name + 10 > packet.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([packet[after_name], packet[after_name + 1]]);
    if rtype != TSIG_TYPE {
        return None;
    }
    // After the TYPE check, not before it. `read_name_at` allocates a `String`
    // per label plus a `join`, so reading first charged every EDNS query for the
    // OPT record's owner name and then threw it away — and the label count is
    // the sender's, on a path reached before anything is authenticated.
    let owner = read_name_at(packet, pos)?;
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
fn append_tsig(mut message: Vec<u8>, tsig: &Tsig) -> ConfigResult<Vec<u8>> {
    let rdata = tsig.rdata_bytes()?;
    let owner = name_wire(&tsig.key_name)
        .map_err(|e| ConfigError::new(format!("TSIG key name {}: {e}", tsig.key_name)))?;

    // Uncompressed owner name: the record must be removable by truncating the
    // message, which a pointer into it would break.
    message.extend_from_slice(&owner);
    message.extend_from_slice(&TSIG_TYPE.to_be_bytes());
    message.extend_from_slice(&TSIG_CLASS.to_be_bytes());
    message.extend_from_slice(&0u32.to_be_bytes()); // TTL 0
    message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    message.extend_from_slice(&rdata);

    let ar = u16::from_be_bytes([message[10], message[11]])
        .checked_add(1)
        .ok_or_else(|| ConfigError::new("additional count would overflow"))?;
    message[10..12].copy_from_slice(&ar.to_be_bytes());

    // The only path that grows a message past the size it was serialized to: ~82
    // octets onto finished bytes. Past 65,535 the TCP framing prefix wraps, and
    // at 65,536 it is 0, which every read loop treats as a broken peer.
    let tsig_octets = owner.len() + 10 + rdata.len();
    if message.len() > u16::MAX as usize {
        return Err(ConfigError::new(format!(
            "a signed message is {} octets, and RFC 1035 §4.2.2's length \
             prefix cannot express more than {} — the TSIG record added \
             {tsig_octets} to a message that was already close to it",
            message.len(),
            u16::MAX,
        )));
    }
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

/// A name read from `packet` at `pos`, following pointers. Used for the TSIG
/// owner name only, which is the key name.
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

/// A name at the start of `data`, and what follows. No compression: this reads
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

/// A key name as compared and hashed: absolute and down-cased, because it is a
/// domain name (RFC 4343).
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
    use crate::record_types as rt;
    use crate::test_records::nm;
    use crate::{DnsMessage, DnsMessageBuilder, Qtype, Rtype};

    fn test_key() -> TsigKey {
        // 32 bytes, the natural length for HMAC-SHA256.
        TsigKey::new("transfer.key.", TsigAlgorithm::HmacSha256, vec![0x0b; 32])
    }

    fn query_bytes(qname: &str, qtype: Qtype) -> Vec<u8> {
        let msg = DnsMessageBuilder::new()
            .with_id(0x4d2)
            .with_query(nm(qname), qtype)
            .with_recursion(false)
            .build();
        let mut buf = vec![0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("serialize");
        buf.truncate(n);
        buf
    }

    /// A signed message that will not fit a length prefix is refused, not framed
    /// with a wrapped one.
    ///
    /// A sweep, because the window `append_tsig` adds is 82 octets out of
    /// 65,536; asserting on the error type alone would pass against an
    /// implementation that refused everything.
    #[test]
    fn a_signed_message_too_long_to_frame_is_refused_rather_than_wrapped() {
        let key = test_key();
        let mut refused = 0usize;
        let mut framed_ok = 0usize;

        // 255 character-strings of 255 octets is 65,280 octets of RDATA, just
        // below the ceiling; `pad` walks it through the window.
        for pad in 0..250usize {
            let mut msg = DnsMessage::try_from_bytes(&query_bytes(
                "big.example.com.",
                Qtype::of(crate::record_types::TXT),
            ))
            .expect("a query parses");
            msg.response = true;
            let filler = vec![b'x'; 255];
            let chunks = 255;
            let mut strings: Vec<Vec<u8>> = (0..chunks).map(|_| filler.clone()).collect();
            strings.push(vec![b'y'; pad]);
            msg.answers.push(crate::ResourceRecord {
                name: nm(&nm("big.example.com.").to_string()),
                class: crate::Class::new(1),
                ttl: crate::Ttl::from_secs(60),
                rdata: crate::RecordData::from_parsed(&crate::ParsedRecord::TXT(strings))
                    .expect("a TXT encodes"),
            });

            let Ok(bytes) = msg.to_bytes_within(u16::MAX as usize) else {
                continue;
            };
            // Only sizes near the ceiling prove anything.
            if bytes.len() < 65_300 {
                continue;
            }

            match sign_request(bytes.clone(), &key, 1_000) {
                Ok(signed) => {
                    assert!(
                        signed.len() <= u16::MAX as usize,
                        "a signature that fits must actually fit: {} octets",
                        signed.len()
                    );
                    let framed = crate::framed(&signed).expect("and frames");
                    let prefix = u16::from_be_bytes([framed[0], framed[1]]) as usize;
                    assert_eq!(
                        prefix,
                        signed.len(),
                        "the prefix must agree with the body it introduces \
                         (serialized {}, signed {})",
                        bytes.len(),
                        signed.len()
                    );
                    framed_ok += 1;
                }
                Err(_) => refused += 1,
            }
        }

        assert!(
            framed_ok > 0,
            "the sweep must include sizes that legitimately fit"
        );
        assert!(
            refused > 0,
            "and sizes that do not — otherwise the boundary was never crossed \
             and this test proves nothing"
        );
    }

    /// A message carrying both an OPT record and a TSIG must put the TSIG last
    /// (RFC 8945 §5.1). Nothing enforces it: `to_bytes` writes OPT after
    /// everything else in the section, so a TSIG placed in the struct rather
    /// than appended to finished bytes would end up before it.
    #[test]
    fn a_signed_message_with_edns_still_ends_in_its_tsig() {
        let key = test_key();
        let keyring = TsigKeyring::new(vec![key.clone()]);

        let mut msg = DnsMessage::try_from_bytes(&query_bytes(
            "www.example.com.",
            Qtype::of(crate::record_types::A),
        ))
        .expect("the query parses");
        msg.set_edns(crate::Edns::with_payload_size(1232));
        assert!(msg.edns().is_some(), "the message really carries an OPT");

        let unsigned = msg.to_bytes_within(512).expect("serialize");
        let signed = sign_request(unsigned, &key, 1_000).expect("sign");

        match check_request(&signed, &keyring, 1_000) {
            TsigCheck::Verified(_) => {}
            other => panic!(
                "a signed message carrying EDNS must verify; the TSIG has to \
                 be the last record and OPT is written before it. Got {}",
                match other {
                    TsigCheck::Unsigned => "no TSIG found at all".to_string(),
                    TsigCheck::Rejected(r) => format!("rejected: {}", r.error.reason()),
                    TsigCheck::Verified(_) => unreachable!(),
                }
            ),
        }

        let parsed = DnsMessage::try_from_bytes(&signed).expect("the signed message parses");
        assert!(parsed.edns().is_some(), "OPT survived");
        assert_eq!(parsed.additionals.len(), 1, "the TSIG, and only it");
        assert_eq!(parsed.additionals[0].rdata.rtype(), Rtype::new(TSIG_TYPE));
    }

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
        assert!(
            TsigKey::parse("hmac-md5:k:AAEC").is_err(),
            "MD5 is deprecated"
        );
        assert!(TsigKey::parse("hmac-sha256:k:not base64!").is_err());
        assert!(
            TsigKey::parse("hmac-sha256::AAECAwQFBgcICQoLDA0ODw==").is_err(),
            "no name"
        );
    }

    /// Holding a key is not a licence to transfer every zone: a verified MAC
    /// answers who, not what may be done.
    #[test]
    fn a_key_may_be_scoped_to_zones() {
        let scoped = TsigKey::parse(
            "hmac-sha256:partner.key:AAECAwQFBgcICQoLDA0ODw==:example.com.,other.test",
        )
        .expect("a zone list parses");
        assert_eq!(
            scoped.zone_scope().map(<[String]>::len),
            Some(2),
            "and is reported, because an unscoped key is a decision to display"
        );
        assert!(scoped.may_transfer("example.com."));
        assert!(
            scoped.may_transfer("OTHER.TEST"),
            "a zone name is a domain name: ASCII case and the trailing dot do not \
             decide authorization (RFC 4343)"
        );
        assert!(
            !scoped.may_transfer("third.test."),
            "a zone it does not name is refused"
        );
        assert!(
            !scoped.may_transfer("sub.example.com."),
            "and so is a child — a transfer hands over a whole zone, so anything \
             less specific than the apex authorizes more than it names"
        );

        // The default: unscoped transfers everything, by design.
        let unscoped = TsigKey::parse("hmac-sha256:any.key:AAECAwQFBgcICQoLDA0ODw==").unwrap();
        assert_eq!(unscoped.zone_scope(), None);
        assert!(unscoped.may_transfer("anything.test."));
    }

    /// A key that may transfer a zone may not thereby rewrite it. The update
    /// default runs opposite to the transfer scope beside it: inheriting the
    /// unscoped-transfers-everything default would hand write access to every
    /// zone to every key already in every keyring.
    #[test]
    fn a_key_that_may_transfer_a_zone_may_not_thereby_rewrite_it() {
        let unscoped = TsigKey::parse("hmac-sha256:any.key:AAECAwQFBgcICQoLDA0ODw==").unwrap();
        assert!(
            unscoped.may_transfer("anything.test."),
            "the transfer default is unchanged"
        );
        assert!(
            !unscoped.may_update("anything.test."),
            "and grants nothing at all for UPDATE"
        );

        let transfer_only =
            TsigKey::parse("hmac-sha256:partner.key:AAECAwQFBgcICQoLDA0ODw==:example.com.")
                .unwrap();
        assert!(transfer_only.may_transfer("example.com."));
        assert!(
            !transfer_only.may_update("example.com."),
            "reading a zone is not permission to rewrite it"
        );
        assert_eq!(transfer_only.update_scope(), &UpdatePolicy::Denied);

        // Granted and scoped: the fifth field.
        let writer = TsigKey::parse(
            "hmac-sha256:dhcp.key:AAECAwQFBgcICQoLDA0ODw==:*:dyn.example.com.,other.test",
        )
        .expect("a five-field spec parses");
        assert!(
            writer.may_transfer("anything.test."),
            "`*` in the fourth field is the unrestricted transfer scope"
        );
        assert!(writer.may_update("dyn.example.com."));
        assert!(
            writer.may_update("OTHER.TEST"),
            "a zone name is a domain name: ASCII case and the trailing dot do \
             not decide authorization (RFC 4343)"
        );
        assert!(
            !writer.may_update("example.com."),
            "a zone it does not name is refused"
        );
        assert!(
            !writer.may_update("sub.dyn.example.com."),
            "and so is a child — an UPDATE names one zone in its Zone section, \
             so anything less specific than the apex authorizes more than it names"
        );

        // The explicit grant of everything, which has to be typed.
        let any = TsigKey::parse("hmac-sha256:root.key:AAECAwQFBgcICQoLDA0ODw==:*:*").unwrap();
        assert_eq!(any.update_scope(), &UpdatePolicy::Any);
        assert!(any.may_update("whatever.test."));
    }

    /// The empty-entry rule applies to the fifth field too, and the error names
    /// which list is wrong.
    #[test]
    fn an_update_scope_reports_its_own_typos() {
        let with_bad_update =
            TsigKey::parse("hmac-sha256:k:AAECAwQFBgcICQoLDA0ODw==:*:example.com.,");
        let err = with_bad_update.expect_err("a trailing comma").to_string();
        assert!(
            err.contains("update"),
            "the message names the list with the typo, not just 'a list': {err}"
        );

        let with_bad_transfer =
            TsigKey::parse("hmac-sha256:k:AAECAwQFBgcICQoLDA0ODw==:example.com.,:*");
        let err = with_bad_transfer.expect_err("a trailing comma").to_string();
        assert!(err.contains("transfer"), "{err}");

        // Six fields is not a spec.
        assert!(TsigKey::parse("hmac-sha256:k:AAECAwQFBgcICQoLDA0ODw==:*:*:extra").is_err());
    }

    /// The banner names an update grant, and stays quiet when there is none: a
    /// clause on every line trains the reader to skip the granted one.
    #[test]
    fn the_banner_names_an_update_grant_and_only_a_grant() {
        let ring = TsigKeyring::new(vec![
            TsigKey::new("reader.key.", TsigAlgorithm::HmacSha256, vec![1; 32]),
            TsigKey::new("writer.key.", TsigAlgorithm::HmacSha256, vec![2; 32])
                .for_zones(["example.com."])
                .for_updates(UpdatePolicy::Zones(vec!["dyn.example.com.".to_string()])),
        ]);
        let described = ring.describe();
        assert!(
            described.contains("reader.key. -> every zone;"),
            "no update clause for a key with no grant: {described}"
        );
        assert!(
            described.contains("writer.key. -> example.com., updates dyn.example.com."),
            "{described}"
        );
    }

    /// A zone list needs the algorithm spelled out: `name:secret:zones` and
    /// `alg:name:secret` are both three fields.
    #[test]
    fn a_zone_list_without_an_algorithm_is_an_error_rather_than_a_guess() {
        // Three fields whose first is not an algorithm: refused, not read as
        // name:secret:zones.
        assert!(TsigKey::parse("my.key:AAECAwQFBgcICQoLDA0ODw==:example.com.").is_err());
        assert!(
            TsigKey::parse("hmac-sha256:k:AAECAwQFBgcICQoLDA0ODw==:example.com.,").is_err(),
            "a trailing comma"
        );
        assert!(
            TsigKey::parse("hmac-sha256:k:AAECAwQFBgcICQoLDA0ODw==:").is_err(),
            "no zones"
        );
    }

    /// The banner names each key's scope: an unscoped key is indistinguishable
    /// at run time from a scoped one until someone transfers a zone.
    #[test]
    fn the_keyring_describes_what_each_key_may_transfer() {
        let ring = TsigKeyring::new(vec![
            TsigKey::new("wide.key.", TsigAlgorithm::HmacSha256, vec![1; 32]),
            TsigKey::new("narrow.key.", TsigAlgorithm::HmacSha256, vec![2; 32])
                .for_zones(["example.com."]),
        ]);
        let described = ring.describe();
        assert!(described.contains("wide.key. -> every zone"), "{described}");
        assert!(
            described.contains("narrow.key. -> example.com."),
            "{described}"
        );
    }

    /// BADKEY for an algorithm mismatch stops a peer downgrading SHA-256 to
    /// SHA-1 by asking.
    #[test]
    fn test_the_keyring_matches_name_and_algorithm() {
        let ring = TsigKeyring::new(vec![test_key()]);
        assert!(ring
            .get("TRANSFER.KEY.", TsigAlgorithm::HmacSha256)
            .is_some());
        assert!(ring
            .get("transfer.key", TsigAlgorithm::HmacSha256)
            .is_some());
        assert!(ring.get("transfer.key.", TsigAlgorithm::HmacSha1).is_none());
        assert!(ring.get("other.key.", TsigAlgorithm::HmacSha256).is_none());
    }

    #[test]
    fn test_a_signed_request_verifies() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;

        let signed = sign_request(query_bytes("example.com.", Qtype::AXFR), &key, now).unwrap();

        // It is still a parseable DNS message, with the TSIG in its additionals.
        let parsed = DnsMessage::try_from_bytes(&signed).expect("still a DNS message");
        assert_eq!(parsed.queries[0].qname, nm("example.com."));
        assert_eq!(parsed.additionals.len(), 1);
        assert_eq!(parsed.additionals[0].rdata.rtype(), Rtype::new(TSIG_TYPE));

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
            check_request(
                &query_bytes("example.com.", Qtype::of(rt::A)),
                &ring,
                1_800_000_000
            ),
            TsigCheck::Unsigned
        ));
    }

    /// A message altered after signing does not verify. The bit flipped is in
    /// the question.
    #[test]
    fn test_a_tampered_message_is_badsig() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;
        let mut signed = sign_request(query_bytes("example.com.", Qtype::AXFR), &key, now).unwrap();

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
        let signed = sign_request(query_bytes("example.com.", Qtype::AXFR), &signer, now).unwrap();
        match check_request(&signed, &ring, now) {
            TsigCheck::Rejected(r) => assert_eq!(r.error, TsigError::BadSig),
            _ => panic!("the wrong secret must not verify"),
        }
    }

    #[test]
    fn test_an_unknown_key_is_badkey() {
        let key = test_key();
        let now = 1_800_000_000;
        let signed = sign_request(query_bytes("example.com.", Qtype::AXFR), &key, now).unwrap();
        match check_request(&signed, &TsigKeyring::default(), now) {
            TsigCheck::Rejected(r) => {
                assert_eq!(r.error, TsigError::BadKey);
                assert_eq!(
                    r.key_name(),
                    "transfer.key.",
                    "the error names the key asked for"
                );
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
        let signed =
            sign_request(query_bytes("example.com.", Qtype::AXFR), &key, signed_at).unwrap();

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

    /// A TSIG that is not the last record covers nothing after it: accepting one
    /// would let anything be appended to a signed message.
    #[test]
    fn test_a_tsig_that_is_not_last_is_not_a_signature() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;
        let mut signed = sign_request(query_bytes("example.com.", Qtype::AXFR), &key, now).unwrap();

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
        let signed = sign_request(query_bytes("example.com.", Qtype::AXFR), &key, now).unwrap();
        let (offset, rdata, owner) = find_tsig(&signed).unwrap();
        let mut tsig = Tsig::parse_rdata(&owner, rdata).unwrap();
        tsig.mac.truncate(16);
        let rebuilt = append_tsig(strip_tsig(&signed, offset, tsig.original_id), &tsig).unwrap();

        match check_request(&rebuilt, &ring, now) {
            TsigCheck::Rejected(r) => assert_eq!(r.error, TsigError::BadTrunc),
            _ => panic!("half a MAC is not a MAC"),
        }
    }

    /// A response is signed over the request's MAC: a reply to one question
    /// cannot be replayed as the reply to another.
    #[test]
    fn test_a_response_verifies_against_the_request() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;

        let request = sign_request(query_bytes("example.com.", Qtype::AXFR), &key, now).unwrap();
        let request_mac = {
            let (_, rdata, owner) = find_tsig(&request).unwrap();
            Tsig::parse_rdata(&owner, rdata).unwrap().mac
        };
        let TsigCheck::Verified(mut session) = check_request(&request, &ring, now) else {
            panic!("the request should verify");
        };

        let response = session
            .sign(query_bytes("example.com.", Qtype::AXFR), now)
            .unwrap();
        check_response(&response, &key, &request_mac, true, now)
            .expect("the client should accept the reply");

        // And a reply signed against a *different* request does not verify.
        let other_mac = vec![0xaa; 32];
        assert_eq!(
            check_response(&response, &key, &other_mac, true, now).unwrap_err(),
            TsigError::BadSig
        );
    }

    /// Envelopes chain: each MAC covers the previous, so a dropped or reordered
    /// message fails rather than passing unnoticed.
    #[test]
    fn test_transfer_envelopes_chain() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;

        let request = sign_request(query_bytes("example.com.", Qtype::AXFR), &key, now).unwrap();
        let request_mac = {
            let (_, rdata, owner) = find_tsig(&request).unwrap();
            Tsig::parse_rdata(&owner, rdata).unwrap().mac
        };
        let TsigCheck::Verified(mut session) = check_request(&request, &ring, now) else {
            panic!("the request should verify");
        };

        let envelopes: Vec<Vec<u8>> = (0..3)
            .map(|i| {
                session
                    .sign(query_bytes(&format!("e{i}.example.com."), Qtype::AXFR), now)
                    .unwrap()
            })
            .collect();

        let mut previous = request_mac.clone();
        for (i, envelope) in envelopes.iter().enumerate() {
            previous = check_response(envelope, &key, &previous, i == 0, now)
                .unwrap_or_else(|e| panic!("envelope {i} should verify: {}", e.reason()));
        }

        // Out of order.
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
        let request =
            sign_request(query_bytes("example.com.", Qtype::AXFR), &key, signed_at).unwrap();

        // BADKEY: unsigned, empty MAC.
        let TsigCheck::Rejected(badkey) =
            check_request(&request, &TsigKeyring::default(), signed_at)
        else {
            panic!("expected a rejection");
        };
        let reply = badkey
            .attach(query_bytes("example.com.", Qtype::AXFR), signed_at)
            .unwrap();
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
        let reply = badtime
            .attach(query_bytes("example.com.", Qtype::AXFR), later)
            .unwrap();
        let (_, rdata, owner) = find_tsig(&reply).unwrap();
        let tsig = Tsig::parse_rdata(&owner, rdata).unwrap();
        assert_eq!(tsig.error, 18);
        assert_eq!(
            tsig.mac.len(),
            32,
            "the MAC verified, so the reply is signed"
        );
        assert_eq!(
            tsig.other
                .iter()
                .fold(0u64, |acc, b| (acc << 8) | *b as u64),
            later,
            "so the peer can see whose clock is wrong"
        );
    }

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
        assert!(
            Tsig::parse_rdata("k.", b"\x0chmac-sha256\x00").is_err(),
            "no timers"
        );
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
        let signed = sign_request(
            query_bytes("example.com.", Qtype::of(rt::A)),
            &key,
            far_future,
        )
        .unwrap();
        assert!(matches!(
            check_request(&signed, &ring, far_future),
            TsigCheck::Verified(_)
        ));
    }
}
