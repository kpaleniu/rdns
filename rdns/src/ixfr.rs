//! Incremental zone transfer: sending only what changed (RFC 1995).
//!
//! Deltas are computed when a new version arrives — BIND's
//! `ixfr-from-differences` semantics — and persisted by `journal.rs`.
//!
//! The response (RFC 1995 §4) is the current SOA, then one difference sequence
//! per version step — old SOA, deletions, new SOA, additions — then the current
//! SOA again. The stream's *second* record is what tells a client which it has:
//! another SOA means an increment, anything else means a full zone.

use crate::error::{TransferError, TransferResult};
use crate::name_keys::NameKeyBuf;
use crate::Class;
use crate::Serial;
use crate::Ttl;
use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::record_types as rt;
use crate::transfer::{axfr_messages, pack_transfer_messages};
use crate::zone::{Zone, ZoneRecord};
use crate::{DnsMessage, Name, NameRef, RecordData, ResourceRecord};

/// How many version steps to remember per zone. Past this a full transfer is
/// both correct and probably cheaper than the chain.
const MAX_DELTAS_PER_ZONE: usize = 32;

/// One version step: what it takes to get from `from_serial` to `to_serial`.
#[derive(Debug, Clone)]
pub struct ZoneDelta {
    pub from_serial: Serial,
    pub to_serial: Serial,
    /// The apex SOA as it was at `from_serial` — the header of the deletions.
    pub from_soa: ResourceRecord,
    /// The apex SOA at `to_serial` — the header of the additions.
    pub to_soa: ResourceRecord,
    pub deleted: Vec<ResourceRecord>,
    pub added: Vec<ResourceRecord>,
}

impl ZoneDelta {
    /// How many records this step moves — what decides whether sending it beats
    /// sending the zone.
    pub fn len(&self) -> usize {
        self.deleted.len() + self.added.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The version steps remembered for every zone.
///
/// Derived state living beside the zone map, so the two must move together:
/// [`DeltaLog::note_change`] takes both versions, and the split into
/// [`plan_change`] plus [`DeltaLog::record`] keeps that by making the token only
/// planning can mint what recording consumes.
#[derive(Debug, Default)]
pub struct DeltaLog {
    by_zone: HashMap<NameKeyBuf, Vec<ZoneDelta>>,
}

/// A version step that has been computed but not yet recorded.
///
/// [`diff`] walks every record of both versions, so `rdnsd` plans under the zone
/// map's read lock and records under the write lock rather than blocking every
/// query for the length of a diff. The zone key is baked in at planning time, so
/// a plan cannot be recorded against the wrong zone.
#[derive(Debug, Clone)]
pub struct PlannedDelta {
    zone: NameKeyBuf,
    delta: ZoneDelta,
}

impl PlannedDelta {
    /// Which zone this step belongs to.
    ///
    /// [`NameKeyBuf`] and not the folded octets it was until `TODO.md` #40d: the
    /// one caller wanted the name back, and re-deriving it from a slice is a
    /// fallible call whose `Err` it handled by ignoring the step.
    pub fn zone(&self) -> NameRef<'_> {
        self.zone.as_name()
    }
}

/// Work out the step from `old` to `new`, without recording it anywhere.
///
/// `None` when there is no step to keep: no previous version, a serial that did
/// not move forward, or two identical versions.
pub fn plan_change(old: Option<&Zone>, new: &Zone) -> Option<PlannedDelta> {
    let (Some(old), Some(from), Some(to)) = (old, old.and_then(Zone::serial), new.serial()) else {
        return None;
    };
    if !to.is_newer_than(from) {
        return None;
    }
    let delta = diff(old, new)?;
    if delta.is_empty() {
        return None;
    }
    Some(PlannedDelta {
        zone: NameKeyBuf::new(new.origin()),
        delta,
    })
}

impl DeltaLog {
    pub fn new() -> Self {
        DeltaLog::default()
    }

    /// Record the step from `old` to `new`, if [`plan_change`] finds one.
    pub fn note_change(&mut self, old: Option<&Zone>, new: &Zone) {
        if let Some(planned) = plan_change(old, new) {
            self.record(planned);
        }
    }

    /// Record a step [`plan_change`] already worked out.
    pub fn record(&mut self, planned: PlannedDelta) {
        let history = self.by_zone.entry(planned.zone.clone()).or_default();
        history.push(planned.delta);
        // Oldest first, so the oldest steps are the ones dropped.
        if history.len() > MAX_DELTAS_PER_ZONE {
            history.remove(0);
        }
    }

    /// A zone that is gone — expired, or deconfigured — takes its history with
    /// it: increments of a withdrawn zone are still answers for it.
    pub fn forget(&mut self, zone: NameRef<'_>) {
        self.by_zone.remove(&*zone.folded());
    }

    /// The chain of steps from `serial` up to the newest one remembered, or
    /// `None` if there is no unbroken chain.
    ///
    /// A gap would skip a change, leaving the secondary holding a zone that
    /// never existed — undetectable by any later serial comparison.
    pub fn chain_from(&self, zone: NameRef<'_>, serial: Serial) -> Option<Vec<&ZoneDelta>> {
        let history = self.by_zone.get(&*zone.folded())?;
        let start = history.iter().position(|d| d.from_serial == serial)?;

        let mut chain = Vec::new();
        let mut expected = serial;
        for delta in &history[start..] {
            if delta.from_serial != expected {
                return None;
            }
            expected = delta.to_serial;
            chain.push(delta);
        }
        Some(chain)
    }

    /// Every step remembered for a zone, oldest first — what
    /// [`crate::journal::Journal::save`] writes out.
    pub fn all(&self, zone: NameRef<'_>) -> Vec<&ZoneDelta> {
        self.by_zone
            .get(&*zone.folded())
            .map(|history| history.iter().collect())
            .unwrap_or_default()
    }

    /// Put a history back, as read from a journal at startup.
    ///
    /// Replaces rather than appends, and bounded on the way in: a hand-grown
    /// journal must not make this process hold more than
    /// `MAX_DELTAS_PER_ZONE` steps. It does not check that the steps link —
    /// [`crate::journal::Journal::load`] already refuses a chain with a gap.
    pub fn restore(&mut self, zone: NameRef<'_>, mut deltas: Vec<ZoneDelta>) {
        if deltas.len() > MAX_DELTAS_PER_ZONE {
            deltas.drain(..deltas.len() - MAX_DELTAS_PER_ZONE);
        }
        if deltas.is_empty() {
            self.by_zone.remove(&*zone.folded());
            return;
        }
        self.by_zone.insert(NameKeyBuf::new(zone), deltas);
    }

    /// How many steps are remembered for a zone, for logging and tests.
    pub fn len(&self, zone: NameRef<'_>) -> usize {
        self.by_zone.get(&*zone.folded()).map_or(0, Vec::len)
    }

    pub fn is_empty(&self) -> bool {
        self.by_zone.is_empty()
    }
}

/// What changed between two versions of a zone. `None` if either has no apex
/// SOA.
///
/// The apex SOA is excluded from both lists: the framing carries it as the
/// header of each half, and a copy among the records would read as a second
/// difference sequence.
pub fn diff(old: &Zone, new: &Zone) -> Option<ZoneDelta> {
    let from_soa = old.apex_soa_record()?;
    let to_soa = new.apex_soa_record()?;
    let from_serial = old.serial()?;
    let to_serial = new.serial()?;

    let mut counts: BTreeMap<RecordKey, i64> = BTreeMap::new();
    for record in old.records() {
        if old.is_apex_soa(record) {
            continue;
        }
        *counts.entry(record_key(old, record)).or_insert(0) += 1;
    }
    for record in new.records() {
        if new.is_apex_soa(record) {
            continue;
        }
        *counts.entry(record_key(new, record)).or_insert(0) -= 1;
    }

    let mut deleted = Vec::new();
    let mut added = Vec::new();
    for (key, count) in counts {
        // A record present in both cancels to zero. A count rather than a set,
        // so removing one of two identical records still reads as a change.
        for _ in 0..count.max(0) {
            deleted.push(key.clone().into_record());
        }
        for _ in 0..(-count).max(0) {
            added.push(key.clone().into_record());
        }
    }

    Some(ZoneDelta {
        from_serial,
        to_serial,
        from_soa,
        to_soa,
        deleted,
        added,
    })
}

/// A record's identity for comparison: everything about it that can change.
///
/// The TTL is part of it — a secondary caches and re-serves that number, so a
/// TTL change is a deletion plus an addition, as BIND's
/// `ixfr-from-differences` produces. Names compare case-insensitively
/// (RFC 4343), so the key holds the down-cased form and the original beside it.
///
/// It carries the whole [`RecordData`] so [`RecordKey::into_record`] hands back
/// the record it was given rather than re-parsing it through the checked
/// constructor.
///
/// `Ord` is written out rather than derived because it must compare TYPE before
/// class and TTL: that order decides how records come out of the diff and
/// therefore how they go onto the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordKey {
    lowercase_name: Vec<u8>,
    class: Class,
    ttl: Ttl,
    rdata: RecordData,
    /// A function of `lowercase_name`, carried so the record can be rebuilt with
    /// the case it was published under.
    name: Name,
}

impl Ord for RecordKey {
    fn cmp(&self, other: &RecordKey) -> std::cmp::Ordering {
        self.lowercase_name
            .cmp(&other.lowercase_name)
            .then_with(|| self.rdata.rtype().cmp(&other.rdata.rtype()))
            .then_with(|| self.class.cmp(&other.class))
            .then_with(|| self.ttl.cmp(&other.ttl))
            .then_with(|| self.rdata.bytes().cmp(other.rdata.bytes()))
            .then_with(|| self.lowercase_name.cmp(&other.lowercase_name))
    }
}

impl PartialOrd for RecordKey {
    fn partial_cmp(&self, other: &RecordKey) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl RecordKey {
    fn into_record(self) -> ResourceRecord {
        ResourceRecord {
            name: self.name,
            class: self.class,
            ttl: self.ttl,
            rdata: self.rdata,
        }
    }
}

fn record_key(_zone: &Zone, record: &ZoneRecord) -> RecordKey {
    // No normalizing: a `Name` is absolute, and the folded copy is what the
    // key is for.
    let name = record.name.clone();
    RecordKey {
        lowercase_name: name.as_ref().folded().into_owned(),
        class: record.class,
        ttl: record.ttl,
        rdata: record.rdata.clone(),
        name,
    }
}

/// A chain of difference sequences, staged so the zone is rebuilt once.
///
/// RFC 1995 §4 sends one sequence per version step, and applying them one at a
/// time means one O(zone) rebuild per step: 32 of them for a client at the end
/// of a full chain, which is what `MAX_DELTAS_PER_ZONE` bounds it at. The steps
/// are staged against the base instead — deletions as a multiset to withhold,
/// additions as a list to append — which is the same arithmetic in one pass,
/// because an intermediate version is never looked at. Its SOA is not looked at either: the framing
/// carries one per step and only the last one survives.
///
/// The bound is the delta, not the zone: nothing here is sized by the base.
#[derive(Debug, Default)]
pub struct Patch {
    /// What to withhold from the base, bucketed by folded owner name so a base
    /// record can be probed with the octets it already holds — no key built per
    /// record of the zone (`CLAUDE.md` §13).
    withhold: HashMap<NameKeyBuf, Vec<Withheld>>,
    /// What to append, in the order the steps asked for it. `None` is an
    /// addition a later step deleted again.
    append: Vec<Option<ResourceRecord>>,
    /// Where each still-pending addition sits in `append`, for that
    /// cancellation.
    pending: HashMap<NameKeyBuf, Vec<usize>>,
    /// How many deletions were asked for, which is what `missing` is measured
    /// against.
    requested: usize,
    /// Deletions that cancelled an addition from an earlier step: they took
    /// effect, and no record of the base answers for them.
    cancelled: usize,
}

/// One record to withhold, and how many copies of it.
///
/// A count rather than a set: a zone may hold two identical records and a
/// sequence may delete one of them.
#[derive(Debug)]
struct Withheld {
    class: Class,
    ttl: Ttl,
    rdata: RecordData,
    count: usize,
}

impl Withheld {
    /// The identity a difference sequence compares by: everything about a
    /// record that can change. The TTL included — a secondary re-serves that
    /// number, so a TTL change is a deletion plus an addition, as BIND's
    /// `ixfr-from-differences` produces.
    fn matches(&self, class: Class, ttl: Ttl, rdata: &RecordData) -> bool {
        self.count > 0 && self.class == class && self.ttl == ttl && &self.rdata == rdata
    }
}

impl Patch {
    pub fn new() -> Patch {
        Patch::default()
    }

    /// Stage one difference sequence. Call once per step, in order.
    ///
    /// Deletions first, as the sequence orders them: a deletion cancels an
    /// addition this patch is still holding from an earlier step, and only
    /// falls through to the base when it cancels nothing.
    pub fn step(&mut self, deleted: &[ResourceRecord], added: &[ResourceRecord]) {
        self.requested += deleted.len();
        for record in deleted {
            if self.cancel_pending(record) {
                self.cancelled += 1;
                continue;
            }
            let key = NameKeyBuf::new(record.name.as_ref());
            let bucket = self.withhold.entry(key).or_default();
            match bucket
                .iter_mut()
                .find(|held| held.matches(record.class, record.ttl, &record.rdata))
            {
                Some(held) => held.count += 1,
                None => bucket.push(Withheld {
                    class: record.class,
                    ttl: record.ttl,
                    rdata: record.rdata.clone(),
                    count: 1,
                }),
            }
        }
        for record in added {
            let position = self.append.len();
            self.append.push(Some(record.clone()));
            self.pending
                .entry(NameKeyBuf::new(record.name.as_ref()))
                .or_default()
                .push(position);
        }
    }

    /// Take back an addition an earlier step made, if this deletion names one.
    ///
    /// Newest first: two steps adding the same record and one deleting it
    /// leaves the older copy, which is what applying them in order does.
    fn cancel_pending(&mut self, record: &ResourceRecord) -> bool {
        let key = record.name.as_ref().folded();
        let Some(positions) = self.pending.get(&*key) else {
            return false;
        };
        let found = positions.iter().rposition(|at| {
            self.append[*at].as_ref().is_some_and(|pending| {
                pending.class == record.class
                    && pending.ttl == record.ttl
                    && pending.rdata == record.rdata
            })
        });
        let Some(found) = found else {
            return false;
        };
        let at = self
            .pending
            .get_mut(&*key)
            .expect("the bucket a position was just read from")
            .remove(found);
        self.append[at] = None;
        true
    }

    /// Rebuild `base` with the staged steps applied and `new_soa` at the apex.
    ///
    /// Returns the zone and the deletions no record answered — not an error:
    /// the record is meant to be gone either way, and refusing would strand a
    /// secondary on a version it can never leave.
    pub fn apply(mut self, base: &Zone, new_soa: &ResourceRecord) -> (Zone, usize) {
        let mut zone = Zone::new(base.origin().to_owned());
        let mut removed = self.cancelled;
        for record in base.records() {
            // The patch's own SOA replaces this one; the framing carries it, so
            // it is never among the deletions.
            if base.is_apex_soa(record) {
                continue;
            }
            if !self.withhold.is_empty() && self.withhold_one(record) {
                removed += 1;
                continue;
            }
            zone.add_record(record.clone());
        }

        zone.add_record(ZoneRecord {
            name: new_soa.name.clone(),
            ttl: new_soa.ttl,
            class: new_soa.class,
            rdata: new_soa.rdata.clone(),
        });
        for record in self.append.into_iter().flatten() {
            zone.add_record(ZoneRecord {
                name: record.name,
                ttl: record.ttl,
                class: record.class,
                rdata: record.rdata,
            });
        }

        (zone, self.requested - removed)
    }

    /// Whether this record of the base is one of the copies being withheld, and
    /// takes it off the count if so.
    ///
    /// Probed with the octets the record already holds: `folded` borrows unless
    /// the name carries upper case (RFC 4343), so the ordinary record costs a
    /// hash and nothing else.
    fn withhold_one(&mut self, record: &ZoneRecord) -> bool {
        let Some(bucket) = self.withhold.get_mut(&*record.name.as_ref().folded()) else {
            return false;
        };
        match bucket
            .iter_mut()
            .find(|held| held.matches(record.class, record.ttl, &record.rdata))
        {
            Some(held) => {
                held.count -= 1;
                true
            }
            None => false,
        }
    }
}

/// Apply one difference sequence to a zone, returning the result and how many
/// of its deletions found a record.
///
/// The zone is rebuilt rather than edited, which is why `Zone` has no
/// record-removal API: its index holds *positions* into the record vector, so an
/// in-place removal invalidates every later one.
pub fn apply_changes(
    base: &Zone,
    deleted: &[ResourceRecord],
    added: &[ResourceRecord],
    new_soa: &ResourceRecord,
) -> (Zone, usize) {
    let mut patch = Patch::new();
    patch.step(deleted, added);
    let (zone, missing) = patch.apply(base, new_soa);
    (zone, deleted.len() - missing)
}

/// What an IXFR request turned into.
pub enum IxfrResponse {
    /// The client is already current: a single SOA and nothing else
    /// (RFC 1995 §2).
    UpToDate(Vec<DnsMessage>),
    /// The increments the client is missing.
    Incremental {
        messages: Vec<DnsMessage>,
        /// How many version steps it covers, for the log.
        steps: usize,
        records: usize,
    },
    /// No usable chain, so the whole zone — always permitted (RFC 1995 §4).
    ///
    /// The messages are not in here: the caller builds them, and can stream
    /// them, rather than materializing the zone twice.
    FullTransfer { why: &'static str },
}

impl IxfrResponse {
    /// This response as messages, in hand.
    ///
    /// A full transfer needs `zone` and `request` back, since it carries no copy
    /// of the zone. A caller writing to a socket wants
    /// [`crate::transfer::axfr_envelopes`] for that case instead.
    pub fn messages(self, request: &DnsMessage, zone: &Zone) -> TransferResult<Vec<DnsMessage>> {
        match self {
            IxfrResponse::UpToDate(messages) | IxfrResponse::Incremental { messages, .. } => {
                Ok(messages)
            }
            IxfrResponse::FullTransfer { .. } => axfr_messages(request, zone),
        }
    }
}

/// The serial an IXFR request is asking to be brought forward from.
///
/// It rides in the *authority* section (RFC 1995 §3), so a validator that
/// forbids authority sections in requests makes IXFR unreceivable.
fn requested_serial(request: &DnsMessage) -> Option<Serial> {
    request
        .authorities
        .iter()
        .filter(|rr| rr.rdata.rtype() == rt::SOA)
        .find_map(|rr| rr.rdata.soa_serial())
}

/// Answer an IXFR.
///
/// `Err` only when the zone cannot be transferred at all — no apex SOA — which
/// is the same broken-zone case AXFR reports and the same SERVFAIL.
pub fn ixfr_response(
    request: &DnsMessage,
    zone: &Zone,
    deltas: &DeltaLog,
) -> TransferResult<IxfrResponse> {
    let apex = zone.origin();
    let soa = zone
        .apex_soa_record()
        .ok_or_else(|| TransferError::malformed(format!("zone {apex} has no SOA at its apex")))?;
    let current = zone
        .serial()
        .ok_or_else(|| TransferError::malformed(format!("zone {apex} has no serial")))?;

    // RFC 1995 §3 requires the request to carry an SOA; without one the only
    // answerable question is "give me everything".
    let Some(client_serial) = requested_serial(request) else {
        return Ok(IxfrResponse::FullTransfer {
            why: "the request carried no SOA to compare against",
        });
    };

    // Already current, or ahead of us — a secondary of a primary that was rolled
    // back, which more data would not fix.
    if !current.is_newer_than(client_serial) {
        return Ok(IxfrResponse::UpToDate(pack_transfer_messages(
            request,
            vec![soa],
        )));
    }

    let Some(chain) = deltas.chain_from(apex, client_serial) else {
        return Ok(IxfrResponse::FullTransfer {
            why: "no unbroken chain of changes back to the client's serial",
        });
    };
    if chain.last().map(|d| d.to_serial) != Some(current) {
        // The zone moved by some route the log did not see; sending the chain
        // would leave the client short of where it thinks it got to.
        return Ok(IxfrResponse::FullTransfer {
            why: "the remembered changes do not reach the zone's current serial",
        });
    }

    // RFC 1995 §4: if the increment is not smaller than the zone, send the zone.
    let records: usize = chain.iter().map(|d| d.len()).sum();
    if records >= zone.records().len() {
        return Ok(IxfrResponse::FullTransfer {
            why: "the changes are no smaller than the zone itself",
        });
    }

    // Current SOA, then one difference sequence per step — old SOA, deletions,
    // new SOA, additions — then the current SOA again.
    let mut out = Vec::with_capacity(records + 2 * chain.len() + 2);
    out.push(soa.clone());
    for delta in &chain {
        out.push(delta.from_soa.clone());
        out.extend(delta.deleted.iter().cloned());
        out.push(delta.to_soa.clone());
        out.extend(delta.added.iter().cloned());
    }
    out.push(soa);

    Ok(IxfrResponse::Incremental {
        messages: pack_transfer_messages(request, out),
        steps: chain.len(),
        records,
    })
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test_records::{nm, zone_at};
    use crate::zone::parse_zone_file;
    use crate::Qtype;
    use crate::{OpCode, QueryClass, QuerySection, ResponseCode};

    fn request(client_serial: Option<u32>) -> DnsMessage {
        let mut msg = DnsMessage {
            id: 0x2222,
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
                qname: nm("example.com."),
                qtype: Qtype::of(rt::IXFR),
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        };
        if let Some(serial) = client_serial {
            msg.authorities = vec![zone_at(serial, "").apex_soa_record().unwrap()];
        }
        msg
    }

    fn answers(messages: &[DnsMessage]) -> Vec<&ResourceRecord> {
        messages.iter().flat_map(|m| m.answers.iter()).collect()
    }

    /// The steps of a chain, as `xfr` stages them.
    fn steps() -> Vec<(Vec<ResourceRecord>, Vec<ResourceRecord>)> {
        let base = zone_at(1, "www IN A 192.0.2.1\nmail IN A 192.0.2.2\n");
        let second = zone_at(2, "www IN A 192.0.2.9\nmail IN A 192.0.2.2\n");
        // `ftp` arrives in step two and is gone again in step three, which is
        // the case a patch staged against the base alone gets wrong: no record
        // of the base answers that deletion, so `ftp` survives into a version
        // that never had it.
        let third = zone_at(
            3,
            "www IN A 192.0.2.9\nmail IN A 192.0.2.2\nftp IN A 192.0.2.3\n",
        );
        let fourth = zone_at(4, "www IN A 192.0.2.9\n");

        [(&base, &second), (&second, &third), (&third, &fourth)]
            .into_iter()
            .map(|(from, to)| {
                let delta = diff(from, to).expect("both versions have an SOA");
                (delta.deleted, delta.added)
            })
            .collect()
    }

    fn contents(zone: &Zone) -> Vec<String> {
        let mut out: Vec<String> = zone
            .records()
            .iter()
            .map(|r| format!("{} {} {:?}", r.name, r.ttl, r.rdata))
            .collect();
        out.sort();
        out
    }

    /// A chain applied in one pass is the zone the steps applied one at a time
    /// produce.
    ///
    /// Fails against a patch that stages every deletion against the base: the
    /// third step deletes a record the second step added, which no record of
    /// the base answers for, so `ftp` would survive and the deletion would be
    /// reported missing. It is also what stops the one-pass rewrite being a
    /// claim — the reference here is the old behaviour, applied step by step.
    #[test]
    fn test_a_chain_applies_as_if_each_step_had_been_applied_in_turn() {
        let base = zone_at(1, "www IN A 192.0.2.1\nmail IN A 192.0.2.2\n");
        let final_soa = zone_at(4, "").apex_soa_record().expect("an apex SOA");

        let mut sequential = base.clone();
        let mut missing_sequentially = 0;
        for (deleted, added) in steps() {
            let (next, removed) = apply_changes(&sequential, &deleted, &added, &final_soa);
            missing_sequentially += deleted.len() - removed;
            sequential = next;
        }

        let mut patch = Patch::new();
        for (deleted, added) in steps() {
            patch.step(&deleted, &added);
        }
        let (staged, missing) = patch.apply(&base, &final_soa);

        assert_eq!(contents(&staged), contents(&sequential));
        assert_eq!(missing, missing_sequentially);
        assert_eq!(missing, 0, "every deletion in this chain names a record");
        assert!(
            !contents(&staged).iter().any(|r| r.contains("mail")),
            "the last step deletes mail: {:?}",
            contents(&staged)
        );
        assert_eq!(staged.serial(), Some(Serial::new(4)));
    }

    /// A deletion naming a record nobody holds is counted, not refused:
    /// refusing would strand a secondary on a version it can never leave.
    #[test]
    fn test_a_deletion_of_something_absent_is_counted_and_not_an_error() {
        let base = zone_at(1, "www IN A 192.0.2.1\n");
        let phantom = zone_at(2, "gone IN A 192.0.2.8\n")
            .records()
            .iter()
            .find(|r| r.name == nm("gone.example.com."))
            .map(|r| ResourceRecord {
                name: r.name.clone(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.clone(),
            })
            .expect("the fixture holds it");
        let soa = zone_at(2, "").apex_soa_record().expect("an apex SOA");

        let (zone, removed) = apply_changes(&base, &[phantom], &[], &soa);
        assert_eq!(removed, 0, "nothing was there to remove");
        assert_eq!(zone.records().len(), base.records().len());
    }

    /// Two identical records and one deletion leaves one: a count, not a set.
    #[test]
    fn test_one_of_two_identical_records_can_be_deleted() {
        let base = zone_at(1, "www IN A 192.0.2.1\nwww IN A 192.0.2.1\n");
        let soa = zone_at(2, "").apex_soa_record().expect("an apex SOA");
        let one = base
            .records()
            .iter()
            .find(|r| r.name == nm("www.example.com."))
            .map(|r| ResourceRecord {
                name: r.name.clone(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.clone(),
            })
            .expect("the fixture holds two");

        let (zone, removed) = apply_changes(&base, &[one], &[], &soa);
        assert_eq!(removed, 1);
        assert_eq!(
            zone.records()
                .iter()
                .filter(|r| r.name == nm("www.example.com."))
                .count(),
            1,
            "one copy deleted, one left"
        );
    }

    #[test]
    fn test_diff_finds_what_moved() {
        let old = zone_at(1, "www IN A 192.0.2.1\nmail IN A 192.0.2.2\n");
        let new = zone_at(2, "www IN A 192.0.2.9\nftp IN A 192.0.2.3\n");

        let delta = diff(&old, &new).expect("both zones have an SOA");
        assert_eq!(delta.from_serial, Serial::new(1));
        assert_eq!(delta.to_serial, Serial::new(2));

        let deleted: Vec<Name> = delta.deleted.iter().map(|r| r.name.clone()).collect();
        let added: Vec<Name> = delta.added.iter().map(|r| r.name.clone()).collect();
        assert!(deleted.contains(&nm("www.example.com.")), "{deleted:?}");
        assert!(deleted.contains(&nm("mail.example.com.")), "{deleted:?}");
        assert!(added.contains(&nm("www.example.com.")), "{added:?}");
        assert!(added.contains(&nm("ftp.example.com.")), "{added:?}");
        assert_eq!(delta.deleted.len(), 2);
        assert_eq!(delta.added.len(), 2);
    }

    /// A record that did not move appears in neither list; otherwise an
    /// "incremental" transfer is the whole zone with extra steps.
    #[test]
    fn test_unchanged_records_are_not_in_the_delta() {
        let old = zone_at(1, "www IN A 192.0.2.1\nns1 IN A 192.0.2.53\n");
        let new = zone_at(
            2,
            "www IN A 192.0.2.1\nns1 IN A 192.0.2.53\nnew IN A 192.0.2.7\n",
        );

        let delta = diff(&old, &new).unwrap();
        assert!(delta.deleted.is_empty(), "{:?}", delta.deleted);
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.added[0].name, nm("new.example.com."));
    }

    /// The apex SOA is framing: a copy among the changes reads as the start of
    /// another sequence.
    #[test]
    fn test_the_apex_soa_is_never_in_the_delta() {
        let old = zone_at(1, "www IN A 192.0.2.1\n");
        let new = zone_at(2, "www IN A 192.0.2.1\n");

        let delta = diff(&old, &new).unwrap();
        assert!(delta.is_empty(), "only the serial moved: {delta:?}");
        assert_eq!(delta.from_soa.rdata.rtype(), rt::SOA);
        assert_eq!(delta.to_soa.rdata.rtype(), rt::SOA);
    }

    /// A TTL change is a change: a secondary caches and re-serves that number.
    #[test]
    fn test_a_ttl_change_is_a_deletion_and_an_addition() {
        let old = zone_at(1, "www 3600 IN A 192.0.2.1\n");
        let new = zone_at(2, "www 60 IN A 192.0.2.1\n");

        let delta = diff(&old, &new).unwrap();
        assert_eq!(delta.deleted.len(), 1);
        assert_eq!(delta.added.len(), 1);
        assert_eq!(delta.deleted[0].ttl, Ttl::from_secs(3600));
        assert_eq!(delta.added[0].ttl, Ttl::from_secs(60));
    }

    #[test]
    fn test_the_log_chains_steps_together() {
        let mut log = DeltaLog::new();
        let v1 = zone_at(1, "www IN A 192.0.2.1\n");
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");
        let v3 = zone_at(3, "www IN A 192.0.2.3\n");

        log.note_change(None, &v1);
        log.note_change(Some(&v1), &v2);
        log.note_change(Some(&v2), &v3);
        assert_eq!(
            log.len(nm("example.com.").as_ref()),
            2,
            "the first load is not a step"
        );

        let chain = log
            .chain_from(nm("example.com.").as_ref(), Serial::new(1))
            .expect("a chain from 1");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].from_serial, Serial::new(1));
        assert_eq!(chain[1].to_serial, Serial::new(3));

        assert_eq!(
            log.chain_from(nm("example.com.").as_ref(), Serial::new(2))
                .map(|c| c.len()),
            Some(1),
            "a client one step behind gets one step"
        );
        assert!(
            log.chain_from(nm("example.com.").as_ref(), Serial::new(99))
                .is_none(),
            "a serial we never held has no chain"
        );
        assert!(log
            .chain_from(nm("other.test.").as_ref(), Serial::new(1))
            .is_none());
    }

    /// The history is bounded and the oldest steps go first; a client far enough
    /// behind falls back to a full transfer.
    #[test]
    fn test_the_history_is_bounded() {
        let mut log = DeltaLog::new();
        let mut previous = zone_at(1, "www IN A 192.0.2.1\n");
        log.note_change(None, &previous);

        for serial in 2..=(MAX_DELTAS_PER_ZONE as u32 + 10) {
            let next = zone_at(serial, &format!("www IN A 192.0.2.{}\n", serial % 250));
            log.note_change(Some(&previous), &next);
            previous = next;
        }

        assert_eq!(log.len(nm("example.com.").as_ref()), MAX_DELTAS_PER_ZONE);
        assert!(
            log.chain_from(nm("example.com.").as_ref(), Serial::new(1))
                .is_none(),
            "aged out"
        );
        let newest = Serial::new(MAX_DELTAS_PER_ZONE as u32 + 9);
        assert_eq!(
            log.chain_from(nm("example.com.").as_ref(), newest)
                .map(|c| c.len()),
            Some(1)
        );
    }

    /// A serial that did not move forward is not a version step: inventing one
    /// hands secondaries a change they can never ask for again.
    #[test]
    fn test_a_serial_that_did_not_advance_is_not_a_step() {
        let mut log = DeltaLog::new();
        let v1 = zone_at(5, "www IN A 192.0.2.1\n");
        let same_serial = zone_at(5, "www IN A 192.0.2.99\n");
        let backwards = zone_at(4, "www IN A 192.0.2.98\n");

        log.note_change(Some(&v1), &same_serial);
        log.note_change(Some(&v1), &backwards);
        assert_eq!(log.len(nm("example.com.").as_ref()), 0);
    }

    #[test]
    fn test_a_withdrawn_zone_takes_its_history_with_it() {
        let mut log = DeltaLog::new();
        let v1 = zone_at(1, "www IN A 192.0.2.1\n");
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");
        log.note_change(Some(&v1), &v2);
        assert_eq!(log.len(nm("example.com.").as_ref()), 1);

        log.forget(nm("EXAMPLE.COM.").as_ref());
        assert_eq!(
            log.len(nm("example.com.").as_ref()),
            0,
            "and case-insensitively"
        );
    }

    /// RFC 1995 §4's shape, which a client reads positionally: current SOA, then
    /// (old SOA, deletions, new SOA, additions) per step, then the current SOA.
    #[test]
    fn test_an_incremental_response_has_the_shape_the_rfc_describes() {
        let mut log = DeltaLog::new();
        let v1 = zone_at(
            1,
            "www IN A 192.0.2.1\nkeep IN A 192.0.2.50\nb IN A 192.0.2.60\n",
        );
        let v2 = zone_at(
            2,
            "www IN A 192.0.2.2\nkeep IN A 192.0.2.50\nb IN A 192.0.2.60\n",
        );
        log.note_change(Some(&v1), &v2);

        let response = ixfr_response(&request(Some(1)), &v2, &log).expect("response");
        let IxfrResponse::Incremental {
            messages,
            steps,
            records,
        } = response
        else {
            panic!("expected an incremental response");
        };
        assert_eq!(steps, 1);
        assert_eq!(records, 2, "one deletion, one addition");

        let all = answers(&messages);
        assert_eq!(all[0].rdata.rtype(), rt::SOA, "opens with the current SOA");
        assert_eq!(
            all[1].rdata.rtype(),
            rt::SOA,
            "then the old SOA: deletions follow"
        );
        assert_eq!(all[2].name, nm("www.example.com."));
        assert_eq!(
            all[3].rdata.rtype(),
            rt::SOA,
            "then the new SOA: additions follow"
        );
        assert_eq!(all[4].name, nm("www.example.com."));
        assert_eq!(all[5].rdata.rtype(), rt::SOA, "closes with the current SOA");
        assert_eq!(all.len(), 6);

        // The second record being an SOA is how a client tells this from a full
        // transfer, so pin the distinction.
        let full = axfr_messages(&request(Some(1)), &v2).unwrap();
        assert_ne!(answers(&full)[1].rdata.rtype(), rt::SOA);
    }

    #[test]
    fn test_a_client_that_is_current_gets_one_soa() {
        let zone = zone_at(7, "www IN A 192.0.2.1\n");
        let response = ixfr_response(&request(Some(7)), &zone, &DeltaLog::new()).expect("response");
        let IxfrResponse::UpToDate(messages) = response else {
            panic!("expected an up-to-date response");
        };
        let all = answers(&messages);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].rdata.rtype(), rt::SOA);

        // A client ahead of us gets the same answer.
        let ahead = ixfr_response(&request(Some(9)), &zone, &DeltaLog::new()).expect("response");
        assert!(matches!(ahead, IxfrResponse::UpToDate(_)));
    }

    /// Falling back to a full transfer is not a failure: RFC 1995 §4 permits it
    /// unconditionally.
    #[test]
    fn test_falls_back_to_a_full_transfer_when_it_cannot_do_better() {
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");

        // No chain at all.
        let response = ixfr_response(&request(Some(1)), &v2, &DeltaLog::new()).unwrap();
        let IxfrResponse::FullTransfer { why } = response else {
            panic!("expected a full transfer");
        };
        let messages = axfr_messages(&request(Some(1)), &v2).expect("build the full transfer");
        assert!(why.contains("no unbroken chain"), "got: {why}");
        assert_eq!(answers(&messages)[0].rdata.rtype(), rt::SOA);
        assert_ne!(answers(&messages)[1].rdata.rtype(), rt::SOA, "a full zone");

        // No SOA in the request: nothing to compare against.
        let response = ixfr_response(&request(None), &v2, &DeltaLog::new()).unwrap();
        assert!(
            matches!(response, IxfrResponse::FullTransfer { why, .. } if why.contains("no SOA"))
        );
    }

    /// An increment no smaller than the zone is sent as the zone (RFC 1995 §4).
    #[test]
    fn test_a_change_bigger_than_the_zone_is_sent_as_a_full_transfer() {
        let mut log = DeltaLog::new();
        let v1 = zone_at(1, "a IN A 192.0.2.1\nb IN A 192.0.2.2\nc IN A 192.0.2.3\n");
        let v2 = zone_at(
            2,
            "x IN A 192.0.2.11\ny IN A 192.0.2.12\nz IN A 192.0.2.13\n",
        );
        log.note_change(Some(&v1), &v2);

        // Three deleted plus three added is six, against a zone of five records.
        let response = ixfr_response(&request(Some(1)), &v2, &log).unwrap();
        assert!(
            matches!(&response, IxfrResponse::FullTransfer { why, .. } if why.contains("no smaller")),
            "expected a full transfer"
        );
    }

    /// A chain stopping short of what we serve leaves the client believing it
    /// caught up when it did not.
    #[test]
    fn test_a_chain_that_does_not_reach_the_current_serial_is_not_used() {
        let mut log = DeltaLog::new();
        let v1 = zone_at(1, "www IN A 192.0.2.1\n");
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");
        log.note_change(Some(&v1), &v2);

        // The zone has since moved to 3 by some route the log never saw.
        let v3 = zone_at(3, "www IN A 192.0.2.3\n");
        let response = ixfr_response(&request(Some(1)), &v3, &log).unwrap();
        assert!(
            matches!(&response, IxfrResponse::FullTransfer { why, .. } if why.contains("current serial")),
            "expected a full transfer"
        );
    }

    #[test]
    fn test_a_zone_without_an_soa_cannot_be_transferred() {
        let zone = parse_zone_file("www IN A 192.0.2.1\n", "example.com.").unwrap();
        let Err(err) = ixfr_response(&request(Some(1)), &zone, &DeltaLog::new()) else {
            panic!("a zone with no SOA cannot be transferred at all");
        };
        assert!(err.to_string().contains("no SOA"), "got: {err}");
    }

    #[test]
    fn test_requested_serial_reads_the_authority_section() {
        assert_eq!(requested_serial(&request(Some(42))), Some(Serial::new(42)));
        assert_eq!(requested_serial(&request(None)), None);
    }
}
