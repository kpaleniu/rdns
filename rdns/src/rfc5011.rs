//! Following a trust anchor as it rolls (RFC 5011).
//!
//! A trust anchor is a key you decided to believe out of band, which means every
//! change to one is an out-of-band event: a new build, or an operator editing a
//! file. That is fine until the key rolls, and the root KSK does roll — at which
//! point every validator that has not been updated fails closed on the entire
//! internet. RFC 5011 turns the roll into something a resolver can follow by
//! itself, using the zone's own signed DNSKEY RRset as the announcement channel.
//!
//! **The whole safety argument rests on two rules**, and everything here exists
//! to enforce them:
//!
//! - **A new key is only trusted after a hold-down.** Seeing a key in a
//!   validated DNSKEY RRset is not enough — it must stay there for 30 days
//!   ([`ADD_HOLD_DOWN`]). The point is time: an attacker who compromises the
//!   zone's keys long enough to publish a key of their own has to keep the
//!   compromise up, and visible, for a month before any validator adopts it.
//! - **A key is only revoked by itself.** The REVOKE bit means "stop trusting
//!   this key", and it counts only when the DNSKEY RRset carrying it is signed
//!   *by that key* (RFC 5011 §2.1). Without that rule, whoever holds any one of
//!   a zone's keys could retire the others.
//!
//! **Everything here presumes the input was validated.** [`ManagedAnchors::observe`]
//! does not check a signature; it is handed a DNSKEY RRset the caller has already
//! validated to a currently-trusted anchor, and its whole job is deciding what
//! that observation means over time. Feeding it unvalidated records is handing an
//! attacker the trust anchor set, which is the one thing a validator has that
//! nothing else can re-derive. This is the same posture — and the same warning —
//! as `NsecCache::insert_validated`.
//!
//! **Key identity here is (algorithm, protocol, public key), not the whole
//! record.** Revoking a key changes its flags, and therefore its key tag
//! (RFC 5011 §2.1 is explicit that the tag is computed with the REVOKE bit set).
//! A tracker that identified keys by tag or by RDATA would see a revocation as an
//! unrelated new key and start a hold-down on it, which is the opposite of what
//! happened.

use std::path::Path;

use crate::dnssec::{ds_digest, Dnskey, Ds, Rrset};
use crate::utils::record_types as rt;
use crate::{ParsedRecord, RecordData, ResourceRecord};

/// The REVOKE bit (RFC 5011 §3), flags bit 8.
pub const DNSKEY_FLAG_REVOKE: u16 = 0x0080;

/// How long a new key must be continuously present before it is trusted
/// (RFC 5011 §2.4.1: 30 days).
pub const ADD_HOLD_DOWN: u64 = 30 * 86_400;

/// How long a revoked key is remembered before it is forgotten (§2.4.2).
///
/// It is already untrusted from the moment the revocation is seen; the wait is
/// so that a validator which was offline still learns the key was revoked rather
/// than merely finding it gone.
pub const REMOVE_HOLD_DOWN: u64 = 30 * 86_400;

/// The digest algorithm used when turning a tracked key back into a DS for the
/// validator: SHA-256 (RFC 4509), which every deployed zone supports.
const DS_DIGEST_SHA256: u8 = 2;

/// Where a key is in its life as a trust anchor (RFC 5011 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Seen, but not for long enough to be trusted. Not an anchor.
    AddPend,
    /// Trusted. This is what a validator gets to use.
    Valid,
    /// Trusted, but absent from the last DNSKEY RRset we saw.
    ///
    /// Still an anchor, deliberately: a key vanishing without being revoked is
    /// far more likely to be a zone publishing badly, or a spoofed answer that
    /// somehow validated, than a key the operator meant to retire. Retiring one
    /// has a mechanism, and it is the REVOKE bit.
    Missing,
    /// The zone said, in a message signed by this key, to stop trusting it. Not
    /// an anchor, and never again.
    Revoked,
}

impl KeyState {
    /// Whether a key in this state may be used to validate.
    pub fn is_anchor(&self) -> bool {
        matches!(self, KeyState::Valid | KeyState::Missing)
    }

    fn as_str(&self) -> &'static str {
        match self {
            KeyState::AddPend => "ADDPEND",
            KeyState::Valid => "VALID",
            KeyState::Missing => "MISSING",
            KeyState::Revoked => "REVOKED",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_uppercase().as_str() {
            "ADDPEND" => Some(KeyState::AddPend),
            "VALID" => Some(KeyState::Valid),
            "MISSING" => Some(KeyState::Missing),
            "REVOKED" => Some(KeyState::Revoked),
            _ => None,
        }
    }
}

/// One key being followed, and since when.
#[derive(Debug, Clone)]
pub struct TrackedKey {
    pub key: Dnskey,
    pub state: KeyState,
    /// When it entered this state, in Unix seconds. Every hold-down is measured
    /// from here.
    pub since: u64,
}

impl TrackedKey {
    /// Whether the hold-down that would make this key trusted has elapsed.
    pub fn hold_down_elapsed(&self, now: u64) -> bool {
        now.saturating_sub(self.since) >= ADD_HOLD_DOWN
    }
}

/// What changed in an [`ManagedAnchors::observe`] — for the log, because a trust
/// anchor moving is an event an operator wants to have been told about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorChange {
    /// A key we had not seen before is now in its hold-down.
    Pending { zone: String, key_tag: u16 },
    /// A key completed its hold-down and is now a trust anchor.
    Trusted { zone: String, key_tag: u16 },
    /// A key in its hold-down disappeared before completing it.
    Withdrawn { zone: String, key_tag: u16 },
    /// A trusted key was absent from the RRset.
    Absent { zone: String, key_tag: u16 },
    /// An absent key came back.
    Returned { zone: String, key_tag: u16 },
    /// A key revoked itself.
    Revoked { zone: String, key_tag: u16 },
    /// A revoked key's remove hold-down elapsed; it is forgotten.
    Forgotten { zone: String, key_tag: u16 },
}

/// The trust anchors being followed, and their state.
///
/// Holds two kinds of thing, because a validator is bootstrapped with one and
/// tracks the other. **DS anchors** are what an operator (or the built-in ICANN
/// anchor) configures: a digest saying "trust whichever key hashes to this".
/// **Tracked keys** are what RFC 5011 accumulates from watching the zone. A DS
/// anchor is never modified by the state machine — it was not learned, so it is
/// not ours to retire — and a key matching one starts out trusted rather than in
/// a hold-down, since it already *is* an anchor by the operator's decision.
#[derive(Debug, Clone, Default)]
pub struct ManagedAnchors {
    ds: Vec<Ds>,
    keys: Vec<TrackedKey>,
}

impl ManagedAnchors {
    pub fn new(ds: Vec<Ds>, keys: Vec<TrackedKey>) -> Self {
        ManagedAnchors { ds, keys }
    }

    /// Start from a set of configured DS anchors, tracking nothing yet.
    pub fn from_ds(anchors: &crate::dnssec_chain::TrustAnchors) -> Self {
        ManagedAnchors {
            ds: anchors.all().to_vec(),
            keys: Vec::new(),
        }
    }

    pub fn keys(&self) -> &[TrackedKey] {
        &self.keys
    }

    pub fn ds(&self) -> &[Ds] {
        &self.ds
    }

    /// The zones anything here is an anchor for.
    pub fn zones(&self) -> Vec<String> {
        let mut zones: Vec<String> = self
            .ds
            .iter()
            .map(|ds| ds.owner.clone())
            .chain(self.keys.iter().map(|k| k.key.owner.clone()))
            .collect();
        zones.sort();
        zones.dedup();
        zones
    }

    /// Everything currently usable as a trust anchor, as DS records — the form
    /// the chain validator already takes.
    ///
    /// Converting rather than teaching the validator about DNSKEY anchors is
    /// deliberate: a DS *is* the statement "a key with this digest is trusted at
    /// this name", which is exactly what a tracked key means, and it keeps one
    /// definition of what an anchor is instead of two.
    pub fn trust_anchors(&self) -> crate::dnssec_chain::TrustAnchors {
        // A revocation outranks a configured DS. The operator wrote down "trust
        // the key with this digest"; the key itself has since said, with its own
        // signature, to stop. Leaving the DS in place would mean a static anchor
        // could never be retired by the mechanism designed to retire it — and
        // the built-in ICANN root anchor is exactly such a DS, so this is the
        // case that matters most.
        let revoked: Vec<&TrackedKey> = self
            .keys
            .iter()
            .filter(|k| k.state == KeyState::Revoked)
            .collect();
        let mut anchors: Vec<Ds> = self
            .ds
            .iter()
            .filter(|ds| {
                !revoked
                    .iter()
                    .any(|r| ds.matches_key(&r.key).unwrap_or(false))
            })
            .cloned()
            .collect();

        for tracked in self.keys.iter().filter(|k| k.state.is_anchor()) {
            let Ok(digest) = ds_digest(&tracked.key, DS_DIGEST_SHA256) else {
                continue;
            };
            let ds = Ds {
                owner: tracked.key.owner.clone(),
                key_tag: tracked.key.key_tag(),
                algorithm: tracked.key.algorithm,
                digest_type: DS_DIGEST_SHA256,
                digest,
            };
            if !anchors.contains(&ds) {
                anchors.push(ds);
            }
        }
        crate::dnssec_chain::TrustAnchors::new(anchors)
    }

    /// Whether we still hold any anchor for `zone`.
    ///
    /// RFC 5011 §5: once the last anchor for a zone is gone, a resolver must not
    /// bootstrap itself a new one from the zone's own data — that would be
    /// trusting an unauthenticated key. The zone becomes unvalidatable until
    /// somebody configures an anchor out of band, which is the correct and
    /// deliberately painful outcome.
    pub fn has_anchor_for(&self, zone: &str) -> bool {
        let zone = zone.to_ascii_lowercase();
        self.ds.iter().any(|ds| ds.owner.eq_ignore_ascii_case(&zone))
            || self
                .keys
                .iter()
                .any(|k| k.state.is_anchor() && k.key.owner.eq_ignore_ascii_case(&zone))
    }

    /// Take in a **validated** DNSKEY RRset for `zone` and move the state machine
    /// on.
    ///
    /// `seen` is every DNSKEY in the RRset. `self_signers` is the subset of them
    /// whose signature over that RRset the caller verified — which is what makes
    /// a revocation believable, and nothing else here depends on it.
    ///
    /// Does nothing at all if we hold no anchor for the zone: with nothing to
    /// have validated against, there is no basis for any of this.
    pub fn observe(
        &mut self,
        zone: &str,
        seen: &[Dnskey],
        self_signers: &[Dnskey],
        now: u64,
    ) -> Vec<AnchorChange> {
        let mut changes = Vec::new();
        if !self.has_anchor_for(zone) {
            return changes;
        }
        let zone_lc = zone.to_ascii_lowercase();
        let in_zone = |owner: &str| owner.eq_ignore_ascii_case(&zone_lc);

        // Revocations first: a revoked key must not also be read as "present and
        // healthy" by the pass below, and a key that revokes itself in the same
        // RRset it appears in is the ordinary case rather than an odd one.
        for key in seen.iter().filter(|k| in_zone(&k.owner)) {
            if key.flags & DNSKEY_FLAG_REVOKE == 0 {
                continue;
            }
            // §2.1: only the key itself may revoke it. Anything else is one of
            // the zone's other keys — or an attacker holding one — retiring an
            // anchor it does not own.
            if !self_signers.iter().any(|signer| same_key(signer, key)) {
                continue;
            }
            if let Some(tracked) = self.keys.iter_mut().find(|t| same_key(&t.key, key)) {
                if tracked.state != KeyState::Revoked {
                    tracked.state = KeyState::Revoked;
                    tracked.since = now;
                    // The key is kept in the form it was *published in before*
                    // the revocation, deliberately. A DS digest covers the flags,
                    // so a DS anchor only matches the unrevoked form — and the
                    // whole point of recording this is to be able to say that a
                    // configured anchor has been retired. The revocation lives in
                    // the state, which is where it belongs.
                    // The *tracked* tag, not the revoked key's. Setting REVOKE
                    // changes the tag, so reporting the one on the wire would
                    // make a log read as two unrelated keys — one that appeared
                    // and revoked itself, and one that silently vanished.
                    changes.push(AnchorChange::Revoked {
                        zone: zone_lc.clone(),
                        key_tag: tracked.key.key_tag(),
                    });
                }
            }
        }

        // Keys present in the RRset.
        for key in seen.iter().filter(|k| in_zone(&k.owner)) {
            if key.flags & DNSKEY_FLAG_REVOKE != 0 {
                continue;
            }
            if !is_candidate_anchor(key) {
                continue;
            }

            match self.keys.iter_mut().find(|t| same_key(&t.key, key)) {
                None => {
                    // A key matching a configured DS anchor is already trusted by
                    // the operator's decision; there is nothing for a hold-down
                    // to establish.
                    let anchored = self
                        .ds
                        .iter()
                        .any(|ds| ds.owner.eq_ignore_ascii_case(&key.owner)
                            && ds.matches_key(key).unwrap_or(false));
                    let state = if anchored { KeyState::Valid } else { KeyState::AddPend };
                    self.keys.push(TrackedKey {
                        key: key.clone(),
                        state,
                        since: now,
                    });
                    changes.push(if anchored {
                        AnchorChange::Trusted {
                            zone: zone_lc.clone(),
                            key_tag: key.key_tag(),
                        }
                    } else {
                        AnchorChange::Pending {
                            zone: zone_lc.clone(),
                            key_tag: key.key_tag(),
                        }
                    });
                }
                Some(tracked) => match tracked.state {
                    KeyState::AddPend if tracked.hold_down_elapsed(now) => {
                        tracked.state = KeyState::Valid;
                        tracked.since = now;
                        changes.push(AnchorChange::Trusted {
                            zone: zone_lc.clone(),
                            key_tag: key.key_tag(),
                        });
                    }
                    // Still waiting: `since` is deliberately *not* refreshed, or
                    // the hold-down would restart with every observation and
                    // never elapse.
                    KeyState::AddPend => {}
                    KeyState::Missing => {
                        tracked.state = KeyState::Valid;
                        tracked.since = now;
                        changes.push(AnchorChange::Returned {
                            zone: zone_lc.clone(),
                            key_tag: key.key_tag(),
                        });
                    }
                    KeyState::Valid => {}
                    // A revoked key reappearing unrevoked is either a zone that
                    // has made a serious mistake or an attacker trying to undo a
                    // revocation. §2.1 is unambiguous: never again.
                    KeyState::Revoked => {}
                },
            }
        }

        // Keys we track that were not in the RRset.
        let mut forgotten = Vec::new();
        for tracked in self.keys.iter_mut().filter(|t| in_zone(&t.key.owner)) {
            if seen.iter().any(|k| same_key(k, &tracked.key)) {
                continue;
            }
            match tracked.state {
                // Never completed its hold-down and is gone again: it was never
                // an anchor, so nothing is lost by dropping it.
                KeyState::AddPend => {
                    forgotten.push(tracked.key.clone());
                    changes.push(AnchorChange::Withdrawn {
                        zone: zone_lc.clone(),
                        key_tag: tracked.key.key_tag(),
                    });
                }
                KeyState::Valid => {
                    tracked.state = KeyState::Missing;
                    tracked.since = now;
                    changes.push(AnchorChange::Absent {
                        zone: zone_lc.clone(),
                        key_tag: tracked.key.key_tag(),
                    });
                }
                KeyState::Missing => {}
                KeyState::Revoked => {
                    if now.saturating_sub(tracked.since) >= REMOVE_HOLD_DOWN {
                        forgotten.push(tracked.key.clone());
                        changes.push(AnchorChange::Forgotten {
                            zone: zone_lc.clone(),
                            key_tag: tracked.key.key_tag(),
                        });
                    }
                }
            }
        }
        self.keys
            .retain(|t| !forgotten.iter().any(|f| same_key(f, &t.key)));

        changes
    }

    // -----------------------------------------------------------------
    // The file
    // -----------------------------------------------------------------

    /// Parse a managed anchor file.
    ///
    /// Lines are DS or DNSKEY records in presentation format, with the state
    /// carried in a `;;` annotation after the record:
    ///
    /// ```text
    /// . IN DS 20326 8 2 E06D44B8...            ; a configured anchor
    /// . 172800 IN DNSKEY 257 3 8 AwEAA...  ;;state=VALID ;;since=1700000000
    /// ```
    ///
    /// A DNSKEY line with no annotation is read as **VALID from now** — that is
    /// an operator writing down a key they have decided to trust, and making
    /// them add bookkeeping fields by hand to be believed would be a trap.
    ///
    /// A line that does not parse is an error rather than a skip, as it is for
    /// the static anchor file: a typo must stop the resolver rather than quietly
    /// leave it trusting less, or differently, than intended.
    pub fn parse(text: &str, now: u64) -> Result<Self, String> {
        let mut ds = Vec::new();
        let mut keys = Vec::new();

        for (number, raw) in text.lines().enumerate() {
            let line = raw.trim();
            // A whole-line comment first, and only then the split — otherwise a
            // comment that happens to contain `;;` (this file's own header does)
            // is read as a record with annotations after it.
            if line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            // Everything up to the first `;` is the record; the rest may carry
            // `;;name=value` annotations, and an ordinary trailing comment simply
            // has none for `parse_annotations` to find.
            let (record, annotations) = match line.find(';') {
                Some(at) => (&line[..at], &line[at..]),
                None => (line, ""),
            };
            let record = record.trim();
            if record.is_empty() {
                continue;
            }

            let fields: Vec<&str> = record.split_whitespace().collect();
            let error = |e: String| format!("line {}: {e} in {:?}", number + 1, raw.trim());
            match parse_anchor_line(&fields).map_err(error)? {
                AnchorLine::Ds(record) => ds.push(record),
                AnchorLine::Key(key) => {
                    let (state, since) = parse_annotations(annotations);
                    keys.push(TrackedKey {
                        key,
                        state: state.unwrap_or(KeyState::Valid),
                        since: since.unwrap_or(now),
                    });
                }
            }
        }

        if ds.is_empty() && keys.is_empty() {
            return Err("no DS or DNSKEY records found".to_string());
        }
        Ok(ManagedAnchors { ds, keys })
    }

    /// The file's contents, ready to be written.
    pub fn format(&self) -> String {
        // Deliberately ASCII: this is a file an operator opens in whatever editor
        // is to hand, and a Windows one reading UTF-8 as the ANSI codepage turns
        // a stray em-dash into mojibake in the first thing they see.
        let mut out = String::from(
            "; Managed DNSSEC trust anchors (RFC 5011). Written by rdnsr.\n\
             ; An edit here is honoured. A DNSKEY line without a ;;state=\n\
             ; annotation is read back as a key you have decided to trust.\n",
        );
        for ds in &self.ds {
            out.push_str(&format!(
                "{} IN DS {} {} {} {}\n",
                ds.owner,
                ds.key_tag,
                ds.algorithm,
                ds.digest_type,
                hex(&ds.digest)
            ));
        }
        for tracked in &self.keys {
            out.push_str(&format!(
                "{} IN DNSKEY {} {} {} {} ;;state={} ;;since={} ;;tag={}\n",
                tracked.key.owner,
                tracked.key.flags,
                tracked.key.protocol,
                tracked.key.algorithm,
                base64(&tracked.key.public_key),
                tracked.state.as_str(),
                tracked.since,
                tracked.key.key_tag(),
            ));
        }
        out
    }

    /// Read the file, or start from the configured DS anchors if it is not there
    /// yet.
    ///
    /// Unlike the transfer sidecar, a *corrupt* file here is fatal rather than
    /// something to shrug off. Forgetting a zone's serial costs a refresh;
    /// forgetting a trust anchor's state means either failing to validate the
    /// internet or restarting a hold-down that had nearly elapsed, and neither is
    /// something to do silently.
    pub fn load_or_seed(
        path: &Path,
        seed: &crate::dnssec_chain::TrustAnchors,
        now: u64,
    ) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, now).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::from_ds(seed)),
            Err(e) => Err(format!("reading {}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        crate::persist::write_atomically_str(path, &self.format())
            .map_err(|e| format!("writing {}: {e}", path.display()))
    }
}

/// Whether a published key is one that could ever become a trust anchor.
///
/// Two requirements, and the second is a deliberate narrowing found by running
/// this against the real root zone.
///
/// **A zone key**, because a key that may not sign RRsets can never anchor
/// anything (RFC 4034 §2.1.1).
///
/// **A secure entry point.** Tracking every key in the RRset is the literal
/// reading of RFC 5011 §4, and against the root it means tracking the ZSK — a key
/// nobody will ever point a DS at. The root rolls its ZSK quarterly and retires
/// each one by simply dropping it, never by revoking it, and a key that vanishes
/// without a revocation stays trusted by design. So the literal reading
/// accumulates a stale trust anchor every three months, for ever. SEP is formally
/// only a hint (§2.1.1), so this does mean a zone rolling to a KSK that forgot to
/// set it would not be followed — an unusual mistake, visible in the log as
/// nothing happening, and with `--trust-anchor` as the way out. Growing the
/// trusted set without bound is the worse failure, because nothing makes it
/// visible at all.
pub fn is_candidate_anchor(key: &Dnskey) -> bool {
    key.is_zone_key() && key.is_sep()
}

/// Whether two DNSKEYs are the same key.
///
/// Flags are deliberately not compared: revoking a key sets a flag bit and so
/// changes its key tag too (RFC 5011 §2.1). Comparing whole records would make a
/// revocation look like the arrival of an unrelated key, and start a hold-down on
/// the very key that was being retired.
pub fn same_key(a: &Dnskey, b: &Dnskey) -> bool {
    a.algorithm == b.algorithm
        && a.protocol == b.protocol
        && a.public_key == b.public_key
        && a.owner.eq_ignore_ascii_case(&b.owner)
}

/// Which of `keys` actually signed this DNSKEY RRset.
///
/// The check a revocation rests on. Each candidate is verified *alone* against
/// the RRSIGs, so "some key signed it" can never be mistaken for "this key signed
/// it" — which is the whole distinction RFC 5011 §2.1 draws.
pub fn self_signers(zone: &str, records: &[ResourceRecord], now: u64) -> Vec<Dnskey> {
    let keys: Vec<Dnskey> = records.iter().filter_map(Dnskey::from_record).collect();
    let rrsigs: Vec<crate::dnssec::Rrsig> = records
        .iter()
        .filter_map(crate::dnssec::Rrsig::from_record)
        .filter(|sig| sig.type_covered == rt::DNSKEY)
        .collect();
    if keys.is_empty() || rrsigs.is_empty() {
        return Vec::new();
    }

    let rdatas: Vec<RecordData> = records
        .iter()
        .filter(|rr| rr.rdata.rtype == rt::DNSKEY)
        .map(|rr| rr.rdata.clone())
        .collect();
    let class = records
        .iter()
        .find(|rr| rr.rdata.rtype == rt::DNSKEY)
        .map(|rr| rr.class)
        .unwrap_or(1);
    let rrset = Rrset::new(zone, rt::DNSKEY, class, &rdatas);

    keys.into_iter()
        .filter(|key| {
            matches!(
                crate::dnssec::verify_rrset(&rrset, &rrsigs, std::slice::from_ref(key), zone, now),
                crate::dnssec::RrsetProof::Verified { .. }
            )
        })
        .collect()
}

/// How long to wait before asking for the DNSKEY RRset again (RFC 5011 §2.3).
///
/// `MAX(1 hour, MIN(15 days, ½ × the RRset's original TTL, ½ × the time left on
/// its signature))`. The shape matters more than the numbers: it is bounded below
/// so a zone publishing a tiny TTL cannot turn a validator into a query flood,
/// and bounded above so a zone publishing a huge one cannot make a validator miss
/// a roll it was told about.
pub fn query_interval(original_ttl: u32, signature_remaining: u64) -> u64 {
    const HOUR: u64 = 3_600;
    const FIFTEEN_DAYS: u64 = 15 * 86_400;
    let half_ttl = original_ttl as u64 / 2;
    let half_signature = signature_remaining / 2;
    HOUR.max(FIFTEEN_DAYS.min(half_ttl).min(half_signature))
}

/// How long to wait after a failed probe (§2.3): the same shape, an order of
/// magnitude smaller, so a transient failure is retried without hammering.
pub fn retry_interval(original_ttl: u32, signature_remaining: u64) -> u64 {
    const HOUR: u64 = 3_600;
    const DAY: u64 = 86_400;
    let tenth_ttl = original_ttl as u64 / 10;
    let tenth_signature = signature_remaining / 10;
    HOUR.max(DAY.min(tenth_ttl).min(tenth_signature))
}

// ---------------------------------------------------------------------------
// Line parsing
// ---------------------------------------------------------------------------

enum AnchorLine {
    Ds(Ds),
    Key(Dnskey),
}

fn parse_anchor_line(fields: &[&str]) -> Result<AnchorLine, String> {
    let mut index = 0;
    let owner = fields
        .first()
        .ok_or_else(|| "empty record".to_string())?
        .to_string();
    index += 1;

    // The TTL and class are optional, exactly as in a zone file.
    while index < fields.len() {
        let field = fields[index];
        if field.parse::<u32>().is_ok()
            || field.eq_ignore_ascii_case("IN")
            || field.eq_ignore_ascii_case("CH")
            || field.eq_ignore_ascii_case("HS")
        {
            index += 1;
        } else {
            break;
        }
    }

    let rtype = fields
        .get(index)
        .ok_or_else(|| "no record type".to_string())?
        .to_ascii_uppercase();
    index += 1;
    let rest = &fields[index..];
    let owner = absolute(&owner);

    match rtype.as_str() {
        "DS" => {
            if rest.len() < 4 {
                return Err(format!("a DS needs 4 fields, got {}", rest.len()));
            }
            Ok(AnchorLine::Ds(Ds {
                owner,
                key_tag: rest[0].parse().map_err(|e| format!("key tag: {e}"))?,
                algorithm: rest[1].parse().map_err(|e| format!("algorithm: {e}"))?,
                digest_type: rest[2].parse().map_err(|e| format!("digest type: {e}"))?,
                digest: parse_hex(&rest[3..].concat())?,
            }))
        }
        "DNSKEY" => {
            if rest.len() < 4 {
                return Err(format!("a DNSKEY needs 4 fields, got {}", rest.len()));
            }
            let public_key = base64::Engine::decode(
                &base64::prelude::BASE64_STANDARD,
                rest[3..].concat(),
            )
            .map_err(|e| format!("public key: {e}"))?;
            Ok(AnchorLine::Key(Dnskey {
                owner,
                flags: rest[0].parse().map_err(|e| format!("flags: {e}"))?,
                protocol: rest[1].parse().map_err(|e| format!("protocol: {e}"))?,
                algorithm: rest[2].parse().map_err(|e| format!("algorithm: {e}"))?,
                public_key,
            }))
        }
        other => Err(format!("{other} is not a trust anchor record type")),
    }
}

/// `;;state=VALID ;;since=1700000000` — unknown annotations are ignored, so a
/// file written by a future version, or by a person, still loads.
fn parse_annotations(text: &str) -> (Option<KeyState>, Option<u64>) {
    let mut state = None;
    let mut since = None;
    for annotation in text.split(";;") {
        let annotation = annotation.trim();
        let Some((name, value)) = annotation.split_once('=') else {
            continue;
        };
        match name.trim() {
            "state" => state = KeyState::parse(value.trim()),
            "since" => since = value.trim().parse().ok(),
            _ => {}
        }
    }
    (state, since)
}

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !text.len().is_multiple_of(2) {
        return Err("digest has an odd number of hex digits".to_string());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| format!("digest: {e}")))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn base64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::prelude::BASE64_STANDARD, bytes)
}

fn absolute(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// A DNSKEY as a resource record, for building test RRsets and for anything that
/// needs to put a tracked key back on the wire.
pub fn key_record(key: &Dnskey, ttl: i32) -> Option<ResourceRecord> {
    let rdata = RecordData::from_parsed(&ParsedRecord::DNSKEY {
        flags: key.flags,
        protocol: key.protocol,
        algorithm: key.algorithm,
        public_key: key.public_key.clone(),
    })
    .ok()?;
    Some(ResourceRecord {
        name: key.owner.clone(),
        class: 1,
        ttl,
        rdata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnssec_chain::TrustAnchors;

    const DAY: u64 = 86_400;

    fn key(tagseed: u8, flags: u16) -> Dnskey {
        Dnskey {
            owner: ".".to_string(),
            flags,
            protocol: 3,
            algorithm: 8,
            // Distinct material per key, so the tags differ and `same_key` has
            // something real to compare.
            public_key: vec![tagseed; 64],
        }
    }

    fn zone_key(tagseed: u8) -> Dnskey {
        key(tagseed, crate::dnssec::DNSKEY_FLAG_ZONE | crate::dnssec::DNSKEY_FLAG_SEP)
    }

    fn anchored_on(k: &Dnskey) -> ManagedAnchors {
        let ds = Ds {
            owner: k.owner.clone(),
            key_tag: k.key_tag(),
            algorithm: k.algorithm,
            digest_type: DS_DIGEST_SHA256,
            digest: ds_digest(k, DS_DIGEST_SHA256).expect("digest"),
        };
        ManagedAnchors::new(vec![ds], Vec::new())
    }

    // -----------------------------------------------------------------
    // Adding a key
    // -----------------------------------------------------------------

    /// The hold-down is the whole security argument: a new key is not trusted
    /// because it appeared, it is trusted because it stayed.
    #[test]
    fn test_a_new_key_is_not_trusted_until_the_hold_down_elapses() {
        let existing = zone_key(1);
        let fresh = zone_key(2);
        let mut anchors = anchored_on(&existing);
        let t0 = 1_700_000_000;

        // Both keys published. The existing one is anchored by DS, so it is
        // trusted at once; the new one starts its hold-down.
        let changes = anchors.observe(".", &[existing.clone(), fresh.clone()], &[], t0);
        assert!(changes.contains(&AnchorChange::Trusted {
            zone: ".".to_string(),
            key_tag: existing.key_tag()
        }));
        assert!(changes.contains(&AnchorChange::Pending {
            zone: ".".to_string(),
            key_tag: fresh.key_tag()
        }));
        assert_eq!(state_of(&anchors, &fresh), Some(KeyState::AddPend));
        assert!(
            !anchors
                .trust_anchors()
                .all()
                .iter()
                .any(|ds| ds.key_tag == fresh.key_tag()),
            "a key in its hold-down is not an anchor"
        );

        // A day short of the hold-down, still not trusted.
        anchors.observe(
            ".",
            &[existing.clone(), fresh.clone()],
            &[],
            t0 + ADD_HOLD_DOWN - DAY,
        );
        assert_eq!(state_of(&anchors, &fresh), Some(KeyState::AddPend));

        // And past it, trusted.
        let changes = anchors.observe(
            ".",
            &[existing.clone(), fresh.clone()],
            &[],
            t0 + ADD_HOLD_DOWN,
        );
        assert!(changes.contains(&AnchorChange::Trusted {
            zone: ".".to_string(),
            key_tag: fresh.key_tag()
        }));
        assert_eq!(state_of(&anchors, &fresh), Some(KeyState::Valid));
        assert!(anchors
            .trust_anchors()
            .all()
            .iter()
            .any(|ds| ds.key_tag == fresh.key_tag()));
    }

    /// The hold-down must not restart every time we look, or it never elapses
    /// and the key is never adopted — a failure that would only show up 30 days
    /// after a roll, in production.
    #[test]
    fn test_the_hold_down_is_not_restarted_by_being_observed() {
        let existing = zone_key(1);
        let fresh = zone_key(2);
        let mut anchors = anchored_on(&existing);
        let t0 = 1_700_000_000;

        anchors.observe(".", &[existing.clone(), fresh.clone()], &[], t0);
        // Probed daily, as a resolver would. Day 30 is the first observation at
        // or past the hold-down; every one before it must leave the clock alone.
        for day in 1..30 {
            anchors.observe(".", &[existing.clone(), fresh.clone()], &[], t0 + day * DAY);
            assert_eq!(
                state_of(&anchors, &fresh),
                Some(KeyState::AddPend),
                "day {day} is still inside the hold-down"
            );
        }
        anchors.observe(".", &[existing.clone(), fresh.clone()], &[], t0 + 30 * DAY);
        assert_eq!(state_of(&anchors, &fresh), Some(KeyState::Valid));
    }

    /// A key that vanishes mid-hold-down was never an anchor, so it is simply
    /// forgotten — and a later reappearance starts the clock again.
    #[test]
    fn test_a_key_withdrawn_during_its_hold_down_is_forgotten() {
        let existing = zone_key(1);
        let fresh = zone_key(2);
        let mut anchors = anchored_on(&existing);
        let t0 = 1_700_000_000;

        anchors.observe(".", &[existing.clone(), fresh.clone()], &[], t0);
        let changes = anchors.observe(".", std::slice::from_ref(&existing), &[], t0 + DAY);
        assert!(changes.contains(&AnchorChange::Withdrawn {
            zone: ".".to_string(),
            key_tag: fresh.key_tag()
        }));
        assert_eq!(state_of(&anchors, &fresh), None);

        // It comes back; the hold-down starts over rather than resuming.
        anchors.observe(".", &[existing.clone(), fresh.clone()], &[], t0 + 2 * DAY);
        assert_eq!(state_of(&anchors, &fresh), Some(KeyState::AddPend));
        anchors.observe(
            ".",
            &[existing.clone(), fresh.clone()],
            &[],
            t0 + 2 * DAY + ADD_HOLD_DOWN - 1,
        );
        assert_eq!(
            state_of(&anchors, &fresh),
            Some(KeyState::AddPend),
            "the clock restarted from the second sighting"
        );
    }

    // -----------------------------------------------------------------
    // Revocation
    // -----------------------------------------------------------------

    /// A key revokes itself, and only itself.
    #[test]
    fn test_a_key_revokes_itself() {
        let old = zone_key(1);
        let new = zone_key(2);
        let mut anchors = anchored_on(&old);
        let t0 = 1_700_000_000;

        // Both trusted: `old` by DS, `new` after its hold-down.
        anchors.observe(".", &[old.clone(), new.clone()], &[], t0);
        anchors.observe(".", &[old.clone(), new.clone()], &[], t0 + ADD_HOLD_DOWN);
        assert_eq!(state_of(&anchors, &new), Some(KeyState::Valid));

        // The old key is republished with REVOKE set, signed by itself.
        let mut revoked = old.clone();
        revoked.flags |= DNSKEY_FLAG_REVOKE;
        let changes = anchors.observe(
            ".",
            &[revoked.clone(), new.clone()],
            std::slice::from_ref(&revoked),
            t0 + ADD_HOLD_DOWN + DAY,
        );
        assert!(changes.contains(&AnchorChange::Revoked {
            zone: ".".to_string(),
            // The stable tag, not the one the REVOKE bit produces: a key that
            // changed identifier as it retired would be two keys in a log.
            key_tag: old.key_tag()
        }));
        assert_eq!(state_of(&anchors, &old), Some(KeyState::Revoked));
        assert!(
            !anchors
                .trust_anchors()
                .all()
                .iter()
                .any(|ds| ds.key_tag == new.key_tag() && ds.key_tag == old.key_tag()),
            "sanity"
        );
        assert!(
            anchors
                .trust_anchors()
                .all()
                .iter()
                .any(|ds| ds.key_tag == new.key_tag()),
            "the successor is still an anchor"
        );
    }

    /// The signature requirement is the whole of §2.1: without it, whoever holds
    /// any one of a zone's keys could retire the others.
    #[test]
    fn test_a_revocation_signed_by_another_key_is_ignored() {
        let old = zone_key(1);
        let other = zone_key(2);
        let mut anchors = anchored_on(&old);
        let t0 = 1_700_000_000;
        anchors.observe(".", std::slice::from_ref(&old), &[], t0);

        let mut revoked = old.clone();
        revoked.flags |= DNSKEY_FLAG_REVOKE;
        // Signed by a different key, not by the one being revoked.
        let changes = anchors.observe(".", std::slice::from_ref(&revoked), std::slice::from_ref(&other), t0 + DAY);

        assert!(!changes.iter().any(|c| matches!(c, AnchorChange::Revoked { .. })));
        assert_eq!(state_of(&anchors, &old), Some(KeyState::Valid));

        // Nobody signing it at all is the same answer.
        anchors.observe(".", std::slice::from_ref(&revoked), &[], t0 + 2 * DAY);
        assert_eq!(state_of(&anchors, &old), Some(KeyState::Valid));
    }

    /// A revoked key is remembered for the remove hold-down and then forgotten —
    /// and never comes back, however it is republished.
    #[test]
    fn test_a_revoked_key_is_forgotten_after_the_hold_down_and_never_returns() {
        let old = zone_key(1);
        let successor = zone_key(2);
        let mut anchors = anchored_on(&old);
        let t0 = 1_700_000_000;
        anchors.observe(".", &[old.clone(), successor.clone()], &[], t0);
        anchors.observe(
            ".",
            &[old.clone(), successor.clone()],
            &[],
            t0 + ADD_HOLD_DOWN,
        );

        let mut revoked = old.clone();
        revoked.flags |= DNSKEY_FLAG_REVOKE;
        let revoked_at = t0 + ADD_HOLD_DOWN + DAY;
        anchors.observe(
            ".",
            &[revoked.clone(), successor.clone()],
            std::slice::from_ref(&revoked),
            revoked_at,
        );

        // Republished without the REVOKE bit: it stays revoked.
        anchors.observe(
            ".",
            &[old.clone(), successor.clone()],
            &[],
            revoked_at + DAY,
        );
        assert_eq!(
            state_of(&anchors, &old),
            Some(KeyState::Revoked),
            "a revocation cannot be taken back"
        );

        // Dropped from the zone; forgotten once the remove hold-down elapses.
        anchors.observe(".", std::slice::from_ref(&successor), &[], revoked_at + DAY + 1);
        assert_eq!(state_of(&anchors, &old), Some(KeyState::Revoked));
        let changes = anchors.observe(
            ".",
            std::slice::from_ref(&successor),
            &[],
            revoked_at + REMOVE_HOLD_DOWN,
        );
        assert!(changes.contains(&AnchorChange::Forgotten {
            zone: ".".to_string(),
            key_tag: old.key_tag()
        }));
        assert_eq!(state_of(&anchors, &old), None);
    }

    /// Revoking changes the flags and therefore the key tag, so identity cannot
    /// be either of those. This is the test that pins why `same_key` exists.
    #[test]
    fn test_revoking_changes_the_key_tag_but_not_the_key() {
        let k = zone_key(1);
        let mut revoked = k.clone();
        revoked.flags |= DNSKEY_FLAG_REVOKE;

        assert_ne!(k.key_tag(), revoked.key_tag(), "the tag moves");
        assert!(same_key(&k, &revoked), "the key does not");
        assert!(!same_key(&k, &zone_key(2)));
    }

    // -----------------------------------------------------------------
    // Absence, and the refusal to bootstrap
    // -----------------------------------------------------------------

    /// A trusted key that simply vanishes stays an anchor. Retiring one has a
    /// mechanism, and it is not "stopped appearing".
    #[test]
    fn test_a_missing_key_is_still_an_anchor() {
        let old = zone_key(1);
        let new = zone_key(2);
        let mut anchors = anchored_on(&old);
        let t0 = 1_700_000_000;
        anchors.observe(".", &[old.clone(), new.clone()], &[], t0);
        anchors.observe(".", &[old.clone(), new.clone()], &[], t0 + ADD_HOLD_DOWN);

        let changes = anchors.observe(".", std::slice::from_ref(&old), &[], t0 + ADD_HOLD_DOWN + DAY);
        assert!(changes.contains(&AnchorChange::Absent {
            zone: ".".to_string(),
            key_tag: new.key_tag()
        }));
        assert_eq!(state_of(&anchors, &new), Some(KeyState::Missing));
        assert!(
            anchors
                .trust_anchors()
                .all()
                .iter()
                .any(|ds| ds.key_tag == new.key_tag()),
            "still trusted"
        );

        let changes = anchors.observe(
            ".",
            &[old.clone(), new.clone()],
            &[],
            t0 + ADD_HOLD_DOWN + 2 * DAY,
        );
        assert!(changes.contains(&AnchorChange::Returned {
            zone: ".".to_string(),
            key_tag: new.key_tag()
        }));
        assert_eq!(state_of(&anchors, &new), Some(KeyState::Valid));
    }

    /// RFC 5011 §5: with no anchor for a zone there is nothing to have validated
    /// against, so nothing observed about it can be believed. A resolver that
    /// bootstrapped itself here would be trusting whatever answered.
    #[test]
    fn test_nothing_is_learned_about_a_zone_we_have_no_anchor_for() {
        let mut anchors = ManagedAnchors::default();
        let changes = anchors.observe(".", &[zone_key(1)], &[], 1_700_000_000);
        assert!(changes.is_empty());
        assert!(anchors.keys().is_empty());
        assert!(!anchors.has_anchor_for("."));
    }

    /// Only a zone key that is also a secure entry point is a candidate.
    ///
    /// The ZSK half of this was found by pointing the resolver at the real root:
    /// it tracked key 57780, the root's ZSK, as a future trust anchor. Nobody
    /// will ever publish a DS for a ZSK, and the root replaces its ZSK quarterly
    /// by dropping it rather than revoking it — and a key that merely disappears
    /// stays trusted. Left alone, that is one more permanently trusted key every
    /// three months.
    #[test]
    fn test_only_secure_entry_points_are_tracked() {
        let anchor = zone_key(1);
        let mut anchors = anchored_on(&anchor);
        let zsk = key(9, crate::dnssec::DNSKEY_FLAG_ZONE);
        let not_a_zone_key = key(8, crate::dnssec::DNSKEY_FLAG_SEP);

        anchors.observe(
            ".",
            &[anchor.clone(), zsk.clone(), not_a_zone_key.clone()],
            &[],
            1,
        );
        assert_eq!(state_of(&anchors, &zsk), None, "a ZSK is not an anchor in waiting");
        assert_eq!(state_of(&anchors, &not_a_zone_key), None);
        assert_eq!(
            state_of(&anchors, &anchor),
            Some(KeyState::Valid),
            "and the real anchor is unaffected"
        );

        assert!(is_candidate_anchor(&anchor));
        assert!(!is_candidate_anchor(&zsk));
        assert!(!is_candidate_anchor(&not_a_zone_key));
    }

    /// Anchors are per zone: what the root publishes says nothing about anyone
    /// else's keys.
    #[test]
    fn test_keys_from_another_zone_are_ignored() {
        let anchor = zone_key(1);
        let mut anchors = anchored_on(&anchor);
        let mut elsewhere = zone_key(5);
        elsewhere.owner = "example.test.".to_string();

        anchors.observe(".", &[anchor.clone(), elsewhere.clone()], &[], 1);
        assert_eq!(state_of(&anchors, &elsewhere), None);
    }

    // -----------------------------------------------------------------
    // The file
    // -----------------------------------------------------------------

    #[test]
    fn test_the_file_round_trips() {
        let old = zone_key(1);
        let new = zone_key(2);
        let mut anchors = anchored_on(&old);
        let t0 = 1_700_000_000;
        anchors.observe(".", &[old.clone(), new.clone()], &[], t0);

        let text = anchors.format();
        let reread = ManagedAnchors::parse(&text, t0 + 999).expect("re-parse");

        assert_eq!(reread.ds().len(), 1);
        assert_eq!(reread.ds()[0].digest, anchors.ds()[0].digest);
        assert_eq!(reread.keys().len(), 2);
        for tracked in reread.keys() {
            let original = anchors
                .keys()
                .iter()
                .find(|k| same_key(&k.key, &tracked.key))
                .expect("the same keys came back");
            assert_eq!(tracked.state, original.state, "state survived");
            assert_eq!(tracked.since, original.since, "and so did the clock");
            assert_eq!(tracked.key.flags, original.key.flags);
        }
    }

    /// A key an operator wrote down by hand, with no bookkeeping, is one they
    /// have decided to trust. Requiring annotations would be a trap.
    #[test]
    fn test_a_hand_written_key_is_trusted_as_written() {
        let text = format!(
            ". 172800 IN DNSKEY 257 3 8 {}\n",
            base64(&zone_key(3).public_key)
        );
        let anchors = ManagedAnchors::parse(&text, 4_242).expect("parse");
        assert_eq!(anchors.keys().len(), 1);
        assert_eq!(anchors.keys()[0].state, KeyState::Valid);
        assert_eq!(anchors.keys()[0].since, 4_242, "the clock starts now");
    }

    /// A DS line is a configured anchor and is left alone by the state machine —
    /// it was not learned, so it is not ours to retire.
    #[test]
    fn test_ds_anchors_are_read_and_never_modified() {
        let anchor = zone_key(1);
        let text = anchored_on(&anchor).format();
        let mut anchors = ManagedAnchors::parse(&text, 1).expect("parse");
        assert_eq!(anchors.ds().len(), 1);

        let mut revoked = anchor.clone();
        revoked.flags |= DNSKEY_FLAG_REVOKE;
        anchors.observe(".", std::slice::from_ref(&revoked), std::slice::from_ref(&revoked), 2);

        assert_eq!(anchors.ds().len(), 1, "the DS anchor is untouched");
        assert!(anchors.has_anchor_for("."));
    }

    /// Fatal rather than shrugged off, unlike the transfer sidecar: forgetting a
    /// serial costs a refresh, forgetting anchor state costs either the internet
    /// or a hold-down that had nearly elapsed.
    #[test]
    fn test_a_damaged_file_is_an_error() {
        assert!(ManagedAnchors::parse(". IN DS nonsense\n", 1).is_err());
        assert!(ManagedAnchors::parse(". IN A 192.0.2.1\n", 1).is_err());
        assert!(ManagedAnchors::parse("; only a comment\n", 1).is_err());
        assert!(ManagedAnchors::parse("", 1).is_err());
    }

    #[test]
    fn test_a_missing_file_seeds_from_the_configured_anchors() {
        let path = std::env::temp_dir().join("rdns-no-such-anchor-file-12345");
        let _ = std::fs::remove_file(&path);
        let seeded = ManagedAnchors::load_or_seed(&path, &TrustAnchors::icann_root(), 1)
            .expect("seed from the built-in anchor");
        assert_eq!(seeded.ds().len(), TrustAnchors::icann_root().all().len());
        assert!(seeded.keys().is_empty());
        assert!(seeded.has_anchor_for("."));
    }

    #[test]
    fn test_written_state_survives_a_restart() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("rdns-anchors-{unique}"));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("root.key");

        let old = zone_key(1);
        let fresh = zone_key(2);
        let mut anchors = anchored_on(&old);
        let t0 = 1_700_000_000;
        anchors.observe(".", &[old.clone(), fresh.clone()], &[], t0);
        anchors.save(&path).expect("save");

        // A restart the next day must find the hold-down where it left it,
        // rather than starting it over.
        let reloaded = ManagedAnchors::load_or_seed(&path, &TrustAnchors::icann_root(), t0 + DAY)
            .expect("reload");
        let tracked = reloaded
            .keys()
            .iter()
            .find(|k| same_key(&k.key, &fresh))
            .expect("the pending key survived");
        assert_eq!(tracked.state, KeyState::AddPend);
        assert_eq!(tracked.since, t0, "the clock did not restart");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // Timers
    // -----------------------------------------------------------------

    #[test]
    fn test_query_interval_is_bounded_at_both_ends() {
        // An hour at least, whatever the zone says.
        assert_eq!(query_interval(0, 0), 3_600);
        assert_eq!(query_interval(60, 60), 3_600);
        // Half the TTL when that is the smaller half.
        assert_eq!(query_interval(86_400, 30 * 86_400), 43_200);
        // Half the remaining signature life when *that* is smaller.
        assert_eq!(query_interval(30 * 86_400, 86_400), 43_200);
        // And 15 days at most, however long-lived the zone's numbers are.
        assert_eq!(query_interval(u32::MAX, u64::MAX), 15 * 86_400);
    }

    #[test]
    fn test_retry_interval_is_shorter_but_still_bounded() {
        assert_eq!(retry_interval(0, 0), 3_600);
        assert_eq!(retry_interval(u32::MAX, u64::MAX), 86_400);
        assert!(retry_interval(30 * 86_400, 30 * 86_400) <= query_interval(30 * 86_400, 30 * 86_400));
    }

    // -----------------------------------------------------------------
    // Against real signatures
    // -----------------------------------------------------------------
    //
    // Everything above drives the state machine with keys that were never used
    // to sign anything, which is the right way to test *timing* and the wrong
    // way to test the one rule that rests on cryptography: that a key revokes
    // only itself. The DNSSEC work in this repo was written that way throughout
    // and did not work when a genuine signature first reached it, so the roll is
    // also played out here with keys that really sign.

    use crate::dnssec_test_util::{rrsig_record, TestKey};

    const KSK_FLAGS: u16 = crate::dnssec::DNSKEY_FLAG_ZONE | crate::dnssec::DNSKEY_FLAG_SEP;

    /// A DNSKEY RRset and a real signature over it, as an answer section.
    fn signed_dnskey_rrset(
        zone: &str,
        published: &[Dnskey],
        signer: &TestKey,
        signer_flags: u16,
    ) -> Vec<ResourceRecord> {
        let rdatas: Vec<RecordData> = published
            .iter()
            .map(|key| {
                RecordData::from_parsed(&ParsedRecord::DNSKEY {
                    flags: key.flags,
                    protocol: key.protocol,
                    algorithm: key.algorithm,
                    public_key: key.public_key.clone(),
                })
                .expect("encode a DNSKEY")
            })
            .collect();
        let sig = signer.sign_rrset_as(
            &Rrset::new(zone, rt::DNSKEY, 1, &rdatas),
            3600,
            zone,
            signer_flags,
        );

        let mut records: Vec<ResourceRecord> = published
            .iter()
            .map(|key| key_record(key, 3600).expect("a DNSKEY record"))
            .collect();
        records.push(rrsig_record(&sig, 3600));
        records
    }

    /// A whole roll, with signatures that verify: adopt a successor, then let
    /// the original retire itself.
    #[test]
    fn test_a_key_roll_with_real_signatures() {
        let old = TestKey::generate_p256();
        let new = TestKey::generate_p256();
        let old_key = old.ksk(".");
        let new_key = new.ksk(".");
        let t0 = crate::utils::current_unix_timestamp();

        // Anchored on the original key, the way the built-in ICANN anchor is.
        let mut anchors = anchored_on(&old_key);

        // Only the original is published, and it signs the RRset.
        let records = signed_dnskey_rrset(".", std::slice::from_ref(&old_key), &old, KSK_FLAGS);
        let signers = self_signers(".", &records, t0);
        assert!(
            signers.iter().any(|k| same_key(k, &old_key)),
            "the key that signed the RRset is recognised as having signed it"
        );
        anchors.observe(".", std::slice::from_ref(&old_key), &signers, t0);
        assert_eq!(state_of(&anchors, &old_key), Some(KeyState::Valid));

        // The successor appears, still signed by the original.
        let published = vec![old_key.clone(), new_key.clone()];
        let records = signed_dnskey_rrset(".", &published, &old, KSK_FLAGS);
        let signers = self_signers(".", &records, t0);
        assert_eq!(signers.len(), 1, "only the original signed it");
        anchors.observe(".", &published, &signers, t0);
        assert_eq!(state_of(&anchors, &new_key), Some(KeyState::AddPend));

        // Thirty days later it is adopted.
        anchors.observe(".", &published, &signers, t0 + ADD_HOLD_DOWN);
        assert_eq!(state_of(&anchors, &new_key), Some(KeyState::Valid));

        // The original revokes itself: republished with REVOKE set, and the
        // RRset signed by that same key in its revoked form.
        let revoked_key = old.dnskey_with(".", KSK_FLAGS | DNSKEY_FLAG_REVOKE);
        let published = vec![revoked_key.clone(), new_key.clone()];
        let records = signed_dnskey_rrset(".", &published, &old, KSK_FLAGS | DNSKEY_FLAG_REVOKE);
        let signers = self_signers(".", &records, t0);
        assert!(
            signers.iter().any(|k| same_key(k, &old_key)),
            "the revoked key really did sign the set it revokes itself in"
        );

        let changes = anchors.observe(".", &published, &signers, t0 + ADD_HOLD_DOWN + DAY);
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, AnchorChange::Revoked { .. })),
            "got {changes:?}"
        );
        assert_eq!(state_of(&anchors, &old_key), Some(KeyState::Revoked));
        assert_eq!(state_of(&anchors, &new_key), Some(KeyState::Valid));

        // And the roll is complete: the successor is the anchor, and the
        // *configured DS* for the retired key is gone with it. That last part is
        // the one worth pinning — a static anchor that could not be retired by
        // the mechanism designed to retire it would leave the resolver trusting
        // a key its owner has publicly withdrawn.
        let in_force = anchors.trust_anchors();
        assert!(
            in_force.all().iter().any(|ds| ds.key_tag == new_key.key_tag()),
            "the successor is an anchor"
        );
        assert!(
            !in_force
                .all()
                .iter()
                .any(|ds| ds.key_tag == old_key.key_tag()),
            "and the revoked key is not, configured DS or no: {:?}",
            in_force.all()
        );
    }

    /// The signature check is not decoration: a revocation signed by the zone's
    /// *other* key must not retire an anchor. Same shape as the unit test above,
    /// but with signatures that really are and really are not the key's own.
    #[test]
    fn test_a_forged_revocation_does_not_retire_a_key_with_real_signatures() {
        let old = TestKey::generate_p256();
        let other = TestKey::generate_p256();
        let old_key = old.ksk(".");
        let t0 = crate::utils::current_unix_timestamp();

        let mut anchors = anchored_on(&old_key);
        let records = signed_dnskey_rrset(".", std::slice::from_ref(&old_key), &old, KSK_FLAGS);
        anchors.observe(
            ".",
            std::slice::from_ref(&old_key),
            &self_signers(".", &records, t0),
            t0,
        );
        assert_eq!(state_of(&anchors, &old_key), Some(KeyState::Valid));

        // `other` holds a key in the zone and tries to revoke the anchor with it.
        let revoked_key = old.dnskey_with(".", KSK_FLAGS | DNSKEY_FLAG_REVOKE);
        let other_key = other.ksk(".");
        let published = vec![revoked_key.clone(), other_key.clone()];
        let records = signed_dnskey_rrset(".", &published, &other, KSK_FLAGS);

        let signers = self_signers(".", &records, t0);
        assert!(
            !signers.iter().any(|k| same_key(k, &old_key)),
            "the anchor did not sign this, and the check must see that"
        );
        anchors.observe(".", &published, &signers, t0 + DAY);

        assert_eq!(
            state_of(&anchors, &old_key),
            Some(KeyState::Valid),
            "an anchor is not retired by somebody else's signature"
        );
        assert!(anchors
            .trust_anchors()
            .all()
            .iter()
            .any(|ds| ds.key_tag == old_key.key_tag()));
    }

    /// `self_signers` must attribute a signature to the key that made it, not to
    /// whichever key happened to be in the same RRset.
    #[test]
    fn test_self_signers_names_only_the_key_that_signed() {
        let signer = TestKey::generate_p256();
        let bystander = TestKey::generate_p256();
        let t0 = crate::utils::current_unix_timestamp();

        let published = vec![signer.ksk("."), bystander.ksk(".")];
        let records = signed_dnskey_rrset(".", &published, &signer, KSK_FLAGS);

        let signers = self_signers(".", &records, t0);
        assert_eq!(signers.len(), 1);
        assert!(same_key(&signers[0], &signer.ksk(".")));

        // Nothing signed at all is nobody, not everybody.
        let unsigned: Vec<ResourceRecord> = records
            .iter()
            .filter(|rr| rr.rdata.rtype != rt::RRSIG)
            .cloned()
            .collect();
        assert!(self_signers(".", &unsigned, t0).is_empty());
    }

    fn state_of(anchors: &ManagedAnchors, key: &Dnskey) -> Option<KeyState> {
        anchors
            .keys()
            .iter()
            .find(|t| same_key(&t.key, key))
            .map(|t| t.state)
    }
}
