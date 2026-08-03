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
use crate::error::{ConfigError, ConfigResult};
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

/// What a TSIG key may rewrite through dynamic UPDATE (RFC 2136 §3.3).
///
/// §3.3 is one paragraph and it specifies almost nothing: the authorization
/// mechanism is "implementation dependent", and the only thing it fixes is that
/// a requestor who fails it is told REFUSED. So the shape below is this
/// codebase's decision, and it is the one `CLAUDE.md` §16 arrived at for
/// transfers — authentication is not authorization, and the check hangs off the
/// session that already knows which key verified rather than looking the name up
/// a second time.
///
/// **Denied by default, which is the opposite of the transfer scope beside it,
/// and deliberately so.** [`TsigKey::zones`] treats an empty list as *every*
/// zone, and §16 records why that default was left alone: narrowing it would
/// mean a binary upgrade silently stops every transfer on a working deployment,
/// which is a worse failure than the one it fixes.
///
/// Neither half of that argument survives the move to UPDATE. There is no
/// working deployment to break, because nothing has ever served an UPDATE here;
/// and the consequence runs the other way, since a transfer hands over a copy
/// and an update rewrites the original. Had this reused the transfer scope,
/// every key that exists — all of them unscoped, because scoping is opt-in —
/// would have silently gained write access to every zone on the server on the
/// first release that dispatched an UPDATE. That is `CLAUDE.md` §16's opening
/// bug exactly, arrived at from the other direction.
///
/// **Three states rather than a `Vec` with an overloaded empty case**
/// (`CLAUDE.md` §17). "No zones" and "all zones" are the two answers furthest
/// apart, and a sentinel meaning one of them depending on which field you are
/// reading is how `QueryClass::None` and `ResponseCode::Unknown` both went
/// wrong. Here the compiler makes the caller name which one it meant.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UpdatePolicy {
    /// No zone, by any key holder. The default, and what every key configured
    /// without an explicit update scope has.
    #[default]
    Denied,
    /// These zone apexes, absolute and down-cased.
    Zones(Vec<String>),
    /// Every zone this server is authoritative for. Spelled `*` in a key spec,
    /// so that granting it is something an operator typed.
    Any,
}

impl UpdatePolicy {
    /// Whether this policy authorizes rewriting the zone at `apex`.
    ///
    /// Against the *apex*, for the reason [`TsigKey::may_transfer`] gives: an
    /// UPDATE names one zone in its Zone section (RFC 2136 §3.1) and every
    /// change in it is confined to that zone by §3.4.1's prescan, so the apex is
    /// the whole of what is being authorized. A rule matching anything less
    /// specific would authorize more than it names.
    pub fn allows(&self, apex: &str) -> bool {
        match self {
            UpdatePolicy::Denied => false,
            UpdatePolicy::Any => true,
            UpdatePolicy::Zones(zones) => zones.contains(&canonical_key_name(apex)),
        }
    }
}

impl std::fmt::Display for UpdatePolicy {
    /// For the startup banner, where what a key may rewrite has to be readable
    /// without cross-referencing the flag that set it.
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
    /// The key name, absolute and down-cased — it is a domain name, and it is
    /// hashed in canonical form, so the case it was configured in cannot matter.
    pub name: String,
    pub algorithm: TsigAlgorithm,
    secret: Vec<u8>,
    /// The zone apexes this key may transfer, absolute and down-cased.
    ///
    /// **Empty means every zone**, which is what every key used to mean whether
    /// its holder was meant to have that or not: `answer_transfer` asked only
    /// whether a session existed, so holding *any* key transferred *any* zone
    /// and bypassed `--allow-transfer` entirely. Hand a per-customer key to one
    /// partner and you handed them every zone on the server, including ones
    /// whose ACL named nobody.
    ///
    /// Empty still means everything, deliberately: changing the default would
    /// mean upgrading the binary silently stops every transfer on a working
    /// deployment. What changes is that scoping is now *expressible* and an
    /// unscoped key is *visible* — the startup banner names each key and what it
    /// may transfer. Narrowing the default belongs with the config file, where an
    /// operator is editing the whole policy at once rather than reading a
    /// changelog. See `TODO.md` #9d.
    zones: Vec<String>,
    /// What this key may rewrite through dynamic UPDATE. See [`UpdatePolicy`]
    /// for why this one denies by default where `zones` permits.
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
    /// Checked against the *apex being transferred*, which is the only name that
    /// matters: a transfer hands over a whole zone, so authorizing by anything
    /// less specific than the zone itself authorizes more than it names.
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
    /// Separate from [`TsigKey::may_transfer`] and not derived from it: reading
    /// a zone and rewriting it are two permissions, and a key granted one has
    /// said nothing about the other. See [`UpdatePolicy`] for why the defaults
    /// differ.
    pub fn may_update(&self, apex: &str) -> bool {
        self.update.allows(apex)
    }

    /// What this key may rewrite, for the startup banner.
    pub fn update_scope(&self) -> &UpdatePolicy {
        &self.update
    }

    /// The zones this key is restricted to, or `None` if it is unrestricted.
    ///
    /// For the startup banner: an unscoped key is a policy decision and has to be
    /// visible, because it is indistinguishable at run time from a scoped one
    /// until the moment someone transfers a zone you did not mean to give them.
    pub fn zone_scope(&self) -> Option<&[String]> {
        if self.zones.is_empty() {
            None
        } else {
            Some(&self.zones)
        }
    }

    /// Parse `[algorithm:]name:base64secret[:transfer-zones[:update-zones]]`,
    /// the first three fields being the shape `dig -y` uses.
    ///
    /// The algorithm defaults to HMAC-SHA256 when omitted — but **a zone list
    /// requires it to be spelled out**, because `name:secret:zones` and
    /// `alg:name:secret` are both three colon-separated fields and there is no
    /// way to tell them apart that does not turn on whether the first field
    /// happens to look like an algorithm name. Requiring the algorithm is the
    /// less surprising of the two: it fails at startup with a message, rather
    /// than reading a zone list as a secret.
    ///
    /// **The fifth field is the update scope, and it needs no disambiguation**:
    /// four fields already require the algorithm, so five cannot collide with
    /// anything (§16's rule about an ambiguous new field is satisfied by the
    /// rule that was already there). Absent means [`UpdatePolicy::Denied`] —
    /// every key that predates this keeps exactly the permissions it had.
    ///
    /// `*` in either list means every zone. It is what lets a key be
    /// unrestricted for transfers *and* scoped for updates, which the
    /// positional fields would otherwise make unsayable — the fourth field
    /// cannot be left empty, since an empty list means "every zone" and an empty
    /// *field* reads as a narrowing the operator typed.
    ///
    /// An unparsable spec is an error rather than a skip: a key the operator
    /// believes is configured but is not would fail every transfer, and the
    /// reason would not be visible.
    pub fn parse(spec: &str) -> ConfigResult<Self> {
        let parts: Vec<&str> = spec.split(':').collect();
        let named_algorithm = |alg: &str| {
            TsigAlgorithm::from_name(alg)
                .ok_or_else(|| ConfigError::new(format!("unknown TSIG algorithm {alg:?}")))
        };
        // `None` for "no field at all" rather than `""`, because an *empty*
        // field has to be an error: it reads as a narrowing the operator typed,
        // and an empty list means the opposite — every zone.
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

        // An unrestricted transfer scope is the empty list, which is what `*`
        // and an absent field both come back as.
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

/// One comma-separated zone list from a key spec: `None` for `*`, which means
/// every zone, and the entries otherwise.
///
/// One function for both lists rather than the rule written twice, because the
/// two differ only in what "every zone" is spelled as at the far end — and a
/// second copy is where the empty-entry check would have gone missing
/// (`CLAUDE.md` §7). `field` is in the message so the error says *which* list
/// has the typo, which is the whole of what `TransferAcl::parse_named` cost and
/// bought.
///
/// An empty entry — a trailing comma, or a bare trailing colon — means the
/// operator wrote something they did not mean. Refusing beats silently narrowing
/// the list, and beats silently *widening* it, which is what an empty list means
/// for transfers.
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

    /// Every key, for reporting what the transfer policy actually is.
    pub fn keys(&self) -> impl Iterator<Item = &TsigKey> {
        self.keys.iter()
    }

    /// One line per key: its name, what it may transfer, and what it may
    /// rewrite.
    ///
    /// Printed at startup because "this key can transfer everything" is a
    /// decision, and an undisplayed decision is one nobody reviews.
    ///
    /// The update scope is named only when it is not [`UpdatePolicy::Denied`],
    /// which is every key until an operator grants one. The banner would
    /// otherwise carry "updates no zones" for every key on every server that has
    /// never used dynamic UPDATE — noise that trains the reader to skip the line
    /// where the interesting case appears.
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
        let mut out = dname_to_bytes(&self.algorithm_name).map_err(|e| {
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
        let mut out = dname_to_bytes(&self.key_name)
            .map_err(|e| ConfigError::new(format!("TSIG key name {}: {e}", self.key_name)))?;
        out.extend_from_slice(&TSIG_CLASS.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // TTL, always 0
        out.extend_from_slice(
            &dname_to_bytes(&self.algorithm_name)
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

    /// Whether the key that authenticated this request may transfer `apex`.
    ///
    /// On the session rather than reached through the keyring by name, because
    /// the session *is* the answer to "which key was this" — looking the name up
    /// again would be a second chance to get it wrong, and a key name is
    /// attacker-supplied until the MAC verifies.
    pub fn may_transfer(&self, apex: &str) -> bool {
        self.key.may_transfer(apex)
    }

    /// Whether the key that authenticated this request may rewrite `apex`
    /// through dynamic UPDATE (RFC 2136 §3.3).
    ///
    /// On the session for the same reason as [`TsigSession::may_transfer`], and
    /// it is worth restating because this is the more dangerous of the two: the
    /// session *is* the answer to "which key was this", and a key name in a
    /// request is attacker-supplied until the MAC verifies. Looking the name up
    /// again to decide who may rewrite a zone would be a second chance to get
    /// that wrong.
    pub fn may_update(&self, apex: &str) -> bool {
        self.key.may_update(apex)
    }

    /// Sign one response message, returning the bytes with a TSIG appended.
    ///
    /// Call it once per message of a zone transfer, in order: the MACs chain, so
    /// a reordered or dropped envelope fails at the client rather than passing
    /// unnoticed.
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

/// The MAC carried by a signed message.
///
/// A client needs its own request's MAC to check the reply against: a response's
/// digest opens with it (RFC 8945 §4.3.3), which is the binding that stops a
/// reply to one question being replayed as the reply to another. Reading it back
/// off the signed bytes keeps [`sign_request`]'s signature as it is and means
/// there is one definition of where a MAC lives.
pub fn request_mac(packet: &[u8]) -> Option<Vec<u8>> {
    let (_, rdata, owner) = find_tsig(packet)?;
    Tsig::parse_rdata(&owner, rdata).ok().map(|tsig| tsig.mac)
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
    // An array, not a `Vec`. This was `(0..4).map(..).collect::<Vec<usize>>()`,
    // which heap-allocates on **every packet the server receives** — before the
    // `ar == 0` check below, so it happened even for the overwhelming majority
    // of queries that carry no additional section and for every server with no
    // TSIG keys configured at all. Found by the DHAT profile (#9e): one block
    // per query, 32 bytes, for four `usize`s whose count is known at compile
    // time.
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
fn append_tsig(mut message: Vec<u8>, tsig: &Tsig) -> ConfigResult<Vec<u8>> {
    let rdata = tsig.rdata_bytes()?;
    let owner = dname_to_bytes(&tsig.key_name)
        .map_err(|e| ConfigError::new(format!("TSIG key name {}: {e}", tsig.key_name)))?;

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
        .ok_or_else(|| ConfigError::new("additional count would overflow"))?;
    message[10..12].copy_from_slice(&ar.to_be_bytes());

    // **This is the only path that can grow a message past the size it was
    // serialized to**, and until this check existed it did so silently.
    // `to_bytes_within(u16::MAX)` cannot return more than 65,535 octets — the
    // scratch buffer is exactly that big, so anything larger comes back as a
    // TC=1 reply instead — and then these ~82 octets are appended to the
    // finished bytes. The ARCOUNT overflow above was the only thing checked.
    //
    // The consequence was not a wrong length but a *wrapped* one: at exactly
    // 65,536 octets the TCP framing prefix is 0, which every read loop here
    // treats as a broken peer, so a signed answer in an 82-octet window below
    // 64 KB dropped the client's connection with nothing said. Refusing here is
    // the right place because it is the only place that knows both halves —
    // `framed` sees a buffer that is already too long and cannot say why.
    //
    // A caller that hits this has a genuinely oversized answer and its options
    // are the protocol's: send it over TCP in pieces, as a transfer does, or
    // truncate. Neither is something this function can choose.
    let tsig_octets = owner.len() + 10 + rdata.len();
    if message.len() > u16::MAX as usize {
        return Err(ConfigError::new(format!(
            "a signed message is {} octets, and RFC 1035 §4.2.2's length prefix              cannot express more than {} — the TSIG record added {tsig_octets}              to a message that was already within that of the limit",
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
    use crate::utils::record_types as rt;
    use crate::{DnsMessage, OpCode, Qtype, QueryClass, QuerySection, ResponseCode, Rtype};

    fn test_key() -> TsigKey {
        // 32 bytes, the natural length for HMAC-SHA256.
        TsigKey::new("transfer.key.", TsigAlgorithm::HmacSha256, vec![0x0b; 32])
    }

    fn query_bytes(qname: &str, qtype: Qtype) -> Vec<u8> {
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
            edns: None,
        };
        let mut buf = vec![0u8; 512];
        let n = msg.to_bytes(&mut buf).expect("serialize");
        buf.truncate(n);
        buf
    }

    /// **A signed message that will not fit a length prefix is refused, not
    /// framed with a wrapped one** (`TODO.md` #17).
    ///
    /// `to_bytes_within(u16::MAX)` cannot return more than 65,535 octets, so
    /// this is the only path that can grow a message past the size it was
    /// serialized to: `append_tsig` adds ~82 octets to the *finished* bytes and
    /// used to check only that ARCOUNT did not overflow. A serialized length in
    /// 65,454..=65,535 therefore produced a message of 65,536 or more, and at
    /// exactly 65,536 the framing prefix is **0** — which every read loop here
    /// treats as a broken peer, so the client's connection was dropped with no
    /// answer and nothing saying why.
    ///
    /// The sweep is the one recorded in `TODO.md` #17, kept because the window
    /// is only 82 octets wide out of 65,536 sizes and a single hand-picked case
    /// would sit next to it as easily as on it. Each step asserts the thing that
    /// actually matters: **the prefix agrees with the body**, or there is no
    /// message at all. Asserting on the error type instead would pass against an
    /// implementation that refused everything.
    ///
    /// **Watched failing** against the unchecked `append_tsig`, at exactly the
    /// size `TODO.md` #17's original sweep recorded: "a signature that fits must
    /// actually fit: **65536** octets". That is the assertion that fires, one
    /// line before the framing — `framed` refuses 65,536 outright now, so the
    /// prefix-of-0 the bug produced is no longer reachable through it, and the
    /// check that catches the bug is the one on the signed length.
    #[test]
    fn a_signed_message_too_long_to_frame_is_refused_rather_than_wrapped() {
        let key = test_key();
        let mut refused = 0usize;
        let mut framed_ok = 0usize;

        // 255 character-strings of 255 octets is 65,280 octets of RDATA, which
        // with the header, question and record overhead lands the serialized
        // message just below the ceiling; `pad` then walks it through the
        // 82-octet window an octet at a time.
        for pad in 0..250usize {
            // A TXT RRset sized to walk the serialized length through the
            // boundary an octet at a time.
            let mut msg = DnsMessage::try_from_bytes(&query_bytes(
                "big.example.com.",
                Qtype::of(crate::utils::record_types::TXT),
            ))
            .expect("a query parses");
            msg.response = true;
            let filler = vec![b'x'; 255];
            let chunks = 255;
            let mut strings: Vec<Vec<u8>> = (0..chunks).map(|_| filler.clone()).collect();
            strings.push(vec![b'y'; pad]);
            msg.answers.push(crate::ResourceRecord {
                name: "big.example.com.".to_string(),
                class: crate::Class::new(1),
                ttl: crate::Ttl::from_secs(60),
                rdata: crate::RecordData::from_parsed(&crate::ParsedRecord::TXT(strings))
                    .expect("a TXT encodes"),
            });

            let Ok(bytes) = msg.to_bytes_within(u16::MAX as usize) else {
                continue;
            };
            // Only the sizes near the ceiling are interesting; below that the
            // message is nowhere near the boundary and proves nothing.
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
                // Refused, which is the correct answer for a message that
                // cannot be expressed on the wire at all.
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

    // -----------------------------------------------------------------
    // Keys
    // -----------------------------------------------------------------

    /// A message carrying **both** an OPT record and a TSIG must put the TSIG
    /// last (RFC 8945 §5.1), and the OPT record's move out of `additionals`
    /// (`TODO.md` #13d) is what makes that worth asserting.
    ///
    /// The invariant holds today for a reason that is not the serializer's
    /// doing: `TSIG_TYPE` appears nowhere outside this module, `append_tsig`
    /// works on finished bytes rather than on the struct, and `make_response`
    /// and `error_bytes` both build `additionals: Vec::new()` — so no reply ever
    /// carries a TSIG *through* `DnsMessage::to_bytes`. Nothing enforces it.
    /// Since `to_bytes` now writes the OPT record after everything else in the
    /// section, a future change that put a TSIG in the struct would silently put
    /// OPT after it.
    ///
    /// This is a functional check rather than a byte-offset one: `strip_tsig`
    /// and the scan in [`check_request`] both require the TSIG to be the last
    /// record, so if OPT landed after it, verification fails.
    #[test]
    fn a_signed_message_with_edns_still_ends_in_its_tsig() {
        let key = test_key();
        let keyring = TsigKeyring::new(vec![key.clone()]);

        let mut msg = DnsMessage::try_from_bytes(&query_bytes(
            "www.example.com.",
            Qtype::of(crate::utils::record_types::A),
        ))
        .expect("the query parses");
        msg.set_edns(crate::Edns::with_payload_size(1232));
        assert!(msg.edns().is_some(), "the message really carries an OPT");

        let unsigned = msg.to_bytes_within(512).expect("serialize");
        let signed = sign_request(unsigned, &key, 1_000).expect("sign");

        match check_request(&signed, &keyring, 1_000) {
            TsigCheck::Verified(_) => {}
            other => panic!(
                "a signed message carrying EDNS must verify; the TSIG has to be                  the last record and OPT is written before it. Got {}",
                match other {
                    TsigCheck::Unsigned => "no TSIG found at all".to_string(),
                    TsigCheck::Rejected(r) => format!("rejected: {}", r.error.reason()),
                    TsigCheck::Verified(_) => unreachable!(),
                }
            ),
        }

        // And the OPT record survived the signing, in its own field.
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

    /// A key used to be a licence to transfer **every** zone: `answer_transfer`
    /// asked only whether a session existed, so holding any key transferred any
    /// zone and bypassed `--allow-transfer` entirely.
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

        // The preserved default, so that changing it has to be deliberate.
        let unscoped = TsigKey::parse("hmac-sha256:any.key:AAECAwQFBgcICQoLDA0ODw==").unwrap();
        assert_eq!(unscoped.zone_scope(), None);
        assert!(unscoped.may_transfer("anything.test."));
    }

    /// **A key that may transfer a zone may not thereby rewrite it.**
    ///
    /// RFC 2136 §3.3 leaves the mechanism to the implementation, so the shape is
    /// this codebase's decision — but the *default* is the security-relevant
    /// part, and it runs opposite to the transfer scope beside it. An unscoped
    /// key transfers everything, which `CLAUDE.md` §16 kept deliberately because
    /// narrowing it would stop every transfer on a working deployment. Reusing
    /// that for updates would have handed write access to every zone to every
    /// key already in every keyring, on the first release that dispatched an
    /// UPDATE — §16's opening bug, arrived at from the other direction.
    ///
    /// **Watched failing** against `may_update` delegating to `may_transfer`:
    /// the unscoped key rewrote `anything.test.` and the transfer-scoped key
    /// rewrote `example.com.`, and the first two assertions below fired.
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

        // Granted, and scoped: the fifth field.
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

        // And the explicit grant of everything, which has to be typed.
        let any = TsigKey::parse("hmac-sha256:root.key:AAECAwQFBgcICQoLDA0ODw==:*:*").unwrap();
        assert_eq!(any.update_scope(), &UpdatePolicy::Any);
        assert!(any.may_update("whatever.test."));
    }

    /// The fifth field needs no disambiguation — four already require the
    /// algorithm — but the empty-entry rule has to apply to it too, and the
    /// error has to say *which* list is wrong.
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

    /// The banner names an update grant, and stays quiet when there is none.
    ///
    /// Both halves matter: an ungranted key is the overwhelming majority, and a
    /// banner carrying "updates no zones" for every one of them is what trains
    /// the reader to skip the line where the granted key appears.
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

    /// A zone list needs the algorithm spelled out, because `name:secret:zones`
    /// and `alg:name:secret` are both three colon-separated fields. Failing at
    /// startup with a message beats reading a zone list as a base64 secret.
    #[test]
    fn a_zone_list_without_an_algorithm_is_an_error_rather_than_a_guess() {
        // Three fields where the first is not an algorithm: refused, and *not*
        // read as name:secret:zones.
        assert!(TsigKey::parse("my.key:AAECAwQFBgcICQoLDA0ODw==:example.com.").is_err());
        // An empty entry means the operator wrote something they did not mean.
        // Refusing beats silently narrowing the list — or widening it to
        // everything, which is what an empty list means.
        assert!(
            TsigKey::parse("hmac-sha256:k:AAECAwQFBgcICQoLDA0ODw==:example.com.,").is_err(),
            "a trailing comma"
        );
        assert!(
            TsigKey::parse("hmac-sha256:k:AAECAwQFBgcICQoLDA0ODw==:").is_err(),
            "no zones"
        );
    }

    /// The startup banner has to name each key's scope: "this key can transfer
    /// everything" is indistinguishable at run time from a scoped key until the
    /// moment someone transfers a zone you did not mean to give them.
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

    /// A key name is not a licence to pick the algorithm: answering BADKEY for a
    /// mismatch is what stops a peer downgrading SHA-256 to SHA-1 by asking.
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

    // -----------------------------------------------------------------
    // Signing and verifying
    // -----------------------------------------------------------------

    #[test]
    fn test_a_signed_request_verifies() {
        let key = test_key();
        let ring = TsigKeyring::new(vec![key.clone()]);
        let now = 1_800_000_000;

        let signed = sign_request(query_bytes("example.com.", Qtype::AXFR), &key, now).unwrap();

        // It is still a parseable DNS message, with the TSIG in its additionals.
        let parsed = DnsMessage::try_from_bytes(&signed).expect("still a DNS message");
        assert_eq!(parsed.queries[0].qname, "example.com.");
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

    /// The whole point: a message altered after signing does not verify. The bit
    /// flipped here is in the question, which is what a TSIG is protecting.
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

    /// A TSIG that is not the last record covers nothing after it, so it is not a
    /// signature at all — accepting one would let anything be appended to a
    /// signed message.
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

    /// A transfer's envelopes chain: each MAC covers the previous one, so a
    /// dropped or reordered message fails instead of passing unnoticed.
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
