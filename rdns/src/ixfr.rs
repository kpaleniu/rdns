//! Incremental zone transfer: sending only what changed (RFC 1995).
//!
//! An AXFR moves the whole zone every time any part of it moves. For a zone of
//! any size that is almost all waste — a serial bump and one changed address
//! costs the same as a fresh copy — and it is why a secondary with a short
//! REFRESH is expensive to be.
//!
//! **Where the deltas come from is the design decision.** BIND keeps a journal
//! on disk (`.jnl`), which is what you need when the zone is edited in place by
//! dynamic UPDATE: the journal *is* the record of what happened. Here a zone
//! comes from a file and changes in discrete events — a reload, or a transfer
//! from a master — so the difference between two versions can simply be computed
//! when the new one arrives and kept in memory. That is BIND's
//! `ixfr-from-differences` semantics without the journal, and it is the same
//! decision NSD made: it answered AXFR as a primary for years rather than carry
//! one. A journal earns its keep when dynamic UPDATE arrives (#7 step 6) and not
//! before.
//!
//! The consequence, stated plainly so nobody is surprised by it: **a restart
//! forgets the deltas**. Every secondary that asks for an increment across a
//! restart gets a full transfer instead, which is correct, permitted
//! unconditionally by RFC 1995 §4, and self-correcting — the next change after
//! that has a delta again.
//!
//! **The response format** (RFC 1995 §4) is the part that is easy to get subtly
//! wrong. It is not "the changed records": it is the current SOA, then one
//! *difference sequence* per version step — the old SOA, the records deleted,
//! the new SOA, the records added — and then the current SOA again. A client
//! reads the second record of the stream to decide what it is holding: another
//! SOA means an increment, anything else means the server has fallen back to
//! sending the whole zone.

use crate::error::{TransferError, TransferResult};
use crate::Class;
use crate::Qtype;
use crate::Serial;
use crate::Ttl;
use std::collections::BTreeMap;
use std::collections::HashMap;

use crate::transfer::{axfr_messages, pack_transfer_messages};
use crate::utils::{absolute_lowered, record_types as rt, NameKeyBuf};
use crate::zone::{Zone, ZoneRecord};
use crate::{DnsMessage, RecordData, ResourceRecord};

/// How many version steps to remember per zone.
///
/// A secondary that has missed more than this many changes is one that has been
/// away a long time, and a full transfer is both correct and probably cheaper
/// than the chain would have been.
pub const MAX_DELTAS_PER_ZONE: usize = 32;

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
    /// How many records this step moves, which is what decides whether sending
    /// it is actually cheaper than sending the zone.
    pub fn len(&self) -> usize {
        self.deleted.len() + self.added.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The version steps remembered for every zone.
///
/// One of these beside the zone map, updated wherever a zone is replaced. It is
/// derived state, so the two have to move together — the same hazard the zone
/// index has, and the reason [`DeltaLog::note_change`] takes both versions
/// rather than being something a caller can forget to call with the old one.
/// [`plan_change`] and [`DeltaLog::record`] split that in two without giving the
/// property up: the token only planning can mint is what the recording step
/// consumes.
#[derive(Debug, Default)]
pub struct DeltaLog {
    by_zone: HashMap<NameKeyBuf, Vec<ZoneDelta>>,
}

/// A version step that has been computed but not yet recorded.
///
/// This exists because computing one is the expensive part — [`diff`] walks
/// every record of both versions into a `BTreeMap` — and `rdnsd` needs that
/// work to happen off the zone map's *write* lock, where it blocks every query
/// for as long as it takes. So the daemon plans under the read lock and records
/// under the write lock; see `Zones` in `rdnsd`, which carries the counter that
/// says whether a plan made under one lock is still true under the other.
///
/// The zone key is baked in at planning time, so a plan cannot be recorded
/// against the wrong zone.
#[derive(Debug, Clone)]
pub struct PlannedDelta {
    zone: String,
    delta: ZoneDelta,
}

impl PlannedDelta {
    /// Which zone this step belongs to, folded — so a caller persisting the log
    /// after recording knows which history to write out without re-deriving the
    /// key from the zone it no longer holds.
    pub fn zone(&self) -> &str {
        &self.zone
    }
}

/// Work out the step from `old` to `new`, without recording it anywhere.
///
/// `None` when there is no step worth keeping, which is the same three cases
/// [`DeltaLog::note_change`] declines: no previous version (a zone loaded at
/// startup has no history and never did), a serial that did not move forward,
/// or two versions that are identical — a serial bump with no change is a
/// legitimate thing to publish, but there is no increment in it to remember.
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
        zone: key(new.origin()),
        delta,
    })
}

impl DeltaLog {
    pub fn new() -> Self {
        DeltaLog::default()
    }

    /// Record the step from `old` to `new`, if there is one to record.
    ///
    /// Nothing is stored when there was no previous version (a zone loaded at
    /// startup has no history and never did), when the serial did not move
    /// forward, or when the two versions are identical — a serial bump with no
    /// change is a legitimate thing to publish, but there is no increment in it
    /// worth keeping.
    pub fn note_change(&mut self, old: Option<&Zone>, new: &Zone) {
        if let Some(planned) = plan_change(old, new) {
            self.record(planned);
        }
    }

    /// Record a step [`plan_change`] already worked out.
    ///
    /// The two-phase caller is `rdnsd`, which plans under the zone map's read
    /// lock and records under its write lock so that a diff of every record in
    /// the zone is not something every query waits behind.
    pub fn record(&mut self, planned: PlannedDelta) {
        let history = self
            .by_zone
            .entry(NameKeyBuf::new(&planned.zone))
            .or_default();
        history.push(planned.delta);
        // Oldest first, so the oldest steps are the ones dropped.
        if history.len() > MAX_DELTAS_PER_ZONE {
            history.remove(0);
        }
    }

    /// A zone that is gone — expired, or removed from the configuration — takes
    /// its history with it. Serving increments of a zone we no longer hold would
    /// be answering for something we have withdrawn.
    pub fn forget(&mut self, zone: &str) {
        self.by_zone.remove(key(zone).as_str());
    }

    /// The chain of steps from `serial` up to the newest one remembered, or
    /// `None` if there is no unbroken chain.
    ///
    /// Unbroken is the whole requirement: a gap means some change would be
    /// skipped, and a secondary that applied the rest would hold a zone that
    /// never existed — which no serial comparison afterwards could detect.
    pub fn chain_from(&self, zone: &str, serial: Serial) -> Option<Vec<&ZoneDelta>> {
        let history = self.by_zone.get(key(zone).as_str())?;
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
    ///
    /// Borrowed rather than cloned: a caller persisting these is holding the
    /// lock anyway, and the whole history of a busy zone is not a thing to copy
    /// on the way to a file.
    pub fn all(&self, zone: &str) -> Vec<&ZoneDelta> {
        self.by_zone
            .get(key(zone).as_str())
            .map(|history| history.iter().collect())
            .unwrap_or_default()
    }

    /// Put a history back, as read from a journal at startup.
    ///
    /// Replaces rather than appends, and bounded on the way in like everything
    /// else here: a journal an operator has grown by hand must not be able to
    /// make this process hold more than [`MAX_DELTAS_PER_ZONE`] steps, which is
    /// the same argument `CLAUDE.md` §5 makes about every other table keyed on
    /// something outside this process's control.
    ///
    /// It does *not* check that the steps link, because
    /// [`crate::journal::Journal::load`] already refused a chain with a gap and
    /// doing it twice would make the second copy the one nobody maintains (§7).
    pub fn restore(&mut self, zone: &str, mut deltas: Vec<ZoneDelta>) {
        if deltas.len() > MAX_DELTAS_PER_ZONE {
            deltas.drain(..deltas.len() - MAX_DELTAS_PER_ZONE);
        }
        if deltas.is_empty() {
            self.by_zone.remove(key(zone).as_str());
            return;
        }
        self.by_zone.insert(NameKeyBuf::new(&key(zone)), deltas);
    }

    /// How many steps are remembered for a zone, for logging and tests.
    pub fn len(&self, zone: &str) -> usize {
        self.by_zone.get(key(zone).as_str()).map_or(0, Vec::len)
    }

    pub fn is_empty(&self) -> bool {
        self.by_zone.is_empty()
    }
}

/// The form a zone name is filed under here: absolute and ASCII-folded.
///
/// One line, because the rule lives in [`crate::utils::absolute_lowered`] — this
/// was a seventh hand-written copy of it (`TODO.md` #13b), and the copies were
/// worth removing not because any of them was wrong but because the next one
/// would have been.
fn key(zone: &str) -> String {
    absolute_lowered(zone).into_owned()
}

/// What changed between two versions of a zone.
///
/// `None` if either version has no apex SOA — there is no version step between
/// zones that cannot say which version they are.
///
/// The apex SOA is excluded from both lists: it is carried by the framing, as
/// the header of each half, and a copy of it among the records would read as a
/// second difference sequence.
pub fn diff(old: &Zone, new: &Zone) -> Option<ZoneDelta> {
    let from_soa = apex_soa(old)?;
    let to_soa = apex_soa(new)?;
    let from_serial = old.serial()?;
    let to_serial = new.serial()?;

    let mut counts: BTreeMap<RecordKey, i64> = BTreeMap::new();
    for record in old.records() {
        if is_apex_soa(old, record) {
            continue;
        }
        *counts.entry(record_key(old, record)).or_insert(0) += 1;
    }
    for record in new.records() {
        if is_apex_soa(new, record) {
            continue;
        }
        *counts.entry(record_key(new, record)).or_insert(0) -= 1;
    }

    let mut deleted = Vec::new();
    let mut added = Vec::new();
    for (key, count) in counts {
        // A record present in both cancels to zero and is not part of the step.
        // The count, rather than a set, is what keeps a zone that holds the same
        // record twice from reading as a change when one copy is removed.
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
/// The TTL is part of it deliberately. Two records that differ only in TTL are
/// not the same record to a secondary — it caches and re-serves that number — so
/// a TTL change is a deletion and an addition, which is what BIND's
/// `ixfr-from-differences` produces too. Names compare case-insensitively
/// (RFC 4343), so the key holds the down-cased form and the original beside it.
///
/// **It carries the whole [`RecordData`] rather than its two fields**, so that
/// [`RecordKey::into_record`] hands back the record it was given instead of
/// rebuilding one. Once `RecordData`'s fields were sealed (`TODO.md` #14c) a
/// rebuild would have had to go through the checked constructor — re-parsing
/// every changed record to re-establish an invariant these bytes never left, on
/// a path that already walks both versions of the zone.
///
/// `Ord` is written out rather than derived for the same reason: it has to keep
/// comparing TYPE *before* class and TTL, which is the order the derive gave
/// while those were separate fields, and which decides the order records come
/// out of the diff in and therefore go onto the wire in.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordKey {
    lowercase_name: String,
    class: Class,
    ttl: Ttl,
    rdata: RecordData,
    /// Not part of the ordering in practice — it is a function of
    /// `lowercase_name` — but carried so the record can be rebuilt with the case
    /// it was published under.
    name: String,
}

impl Ord for RecordKey {
    fn cmp(&self, other: &RecordKey) -> std::cmp::Ordering {
        self.lowercase_name
            .cmp(&other.lowercase_name)
            .then_with(|| self.rdata.rtype().cmp(&other.rdata.rtype()))
            .then_with(|| self.class.cmp(&other.class))
            .then_with(|| self.ttl.cmp(&other.ttl))
            .then_with(|| self.rdata.bytes().cmp(other.rdata.bytes()))
            .then_with(|| self.name.cmp(&other.name))
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

fn record_key(zone: &Zone, record: &ZoneRecord) -> RecordKey {
    let name = zone.normalize_name(&record.name);
    RecordKey {
        lowercase_name: name.to_ascii_lowercase(),
        class: record.class,
        ttl: record.ttl,
        rdata: record.rdata.clone(),
        name: name.into_owned(),
    }
}

fn is_apex_soa(zone: &Zone, record: &ZoneRecord) -> bool {
    record.rdata.rtype() == rt::SOA
        && zone
            .normalize_name(&record.name)
            .eq_ignore_ascii_case(zone.origin())
}

fn apex_soa(zone: &Zone) -> Option<ResourceRecord> {
    zone.query(zone.origin(), Qtype::of(rt::SOA))
        .first()
        .map(|soa| ResourceRecord {
            name: zone.origin().to_string(),
            class: soa.class,
            ttl: soa.ttl,
            rdata: soa.rdata.clone(),
        })
}

/// Apply one difference sequence to a zone, returning the result.
///
/// **This is why `Zone` has no record-removal API and should never get one.** The
/// index holds *positions* into the record vector, so removing a record in place
/// shifts every later position and invalidates it. Rebuilding instead is
/// O(zone size) per sequence rather than per record, which at any zone size this
/// serves is nothing — and it means the zone that results is one built by the
/// ordinary constructor, with an index that cannot disagree with its contents.
///
/// A deletion naming a record the zone does not hold is not an error. RFC 1995
/// says nothing about it, and the only sensible reading is that the master and we
/// disagree about a record that is, either way, meant to be gone — refusing the
/// whole transfer over it would strand a secondary on a version it can never
/// leave. `removed` reports the count so a caller can say so.
pub fn apply_changes(
    base: &Zone,
    deleted: &[ResourceRecord],
    added: &[ResourceRecord],
    new_soa: &ResourceRecord,
) -> (Zone, usize) {
    let mut to_remove: BTreeMap<RecordKey, usize> = BTreeMap::new();
    for record in deleted {
        *to_remove.entry(resource_key(base, record)).or_insert(0) += 1;
    }

    let mut zone = Zone::new(base.origin().to_string());
    let mut removed = 0;
    for record in base.records() {
        // The apex SOA is replaced wholesale by the sequence's own, so the old
        // one is dropped here rather than being expected among the deletions —
        // which is exactly where it is *not*, because the framing carries it.
        if is_apex_soa(base, record) {
            continue;
        }
        let key = record_key(base, record);
        if let Some(count) = to_remove.get_mut(&key) {
            if *count > 0 {
                *count -= 1;
                removed += 1;
                continue;
            }
        }
        zone.add_record(ZoneRecord {
            name: base.normalize_name(&record.name).into_owned(),
            ttl: record.ttl,
            class: record.class,
            rdata: record.rdata.clone(),
        });
    }

    zone.add_record(ZoneRecord {
        name: new_soa.name.clone(),
        ttl: new_soa.ttl,
        class: new_soa.class,
        rdata: new_soa.rdata.clone(),
    });
    for record in added {
        zone.add_record(ZoneRecord {
            name: record.name.clone(),
            ttl: record.ttl,
            class: record.class,
            rdata: record.rdata.clone(),
        });
    }

    (zone, removed)
}

fn resource_key(zone: &Zone, record: &ResourceRecord) -> RecordKey {
    let name = zone.normalize_name(&record.name);
    RecordKey {
        lowercase_name: name.to_ascii_lowercase(),
        class: record.class,
        ttl: record.ttl,
        rdata: record.rdata.clone(),
        name: name.into_owned(),
    }
}

/// What an IXFR request turned into.
pub enum IxfrResponse {
    /// The client is already current: a single SOA and nothing else
    /// (RFC 1995 §2). Not an error — it is the cheapest possible answer, and the
    /// reason a secondary can afford a short REFRESH.
    UpToDate(Vec<DnsMessage>),
    /// The increments the client is missing.
    Incremental {
        messages: Vec<DnsMessage>,
        /// How many version steps it covers, for the log.
        steps: usize,
        records: usize,
    },
    /// No usable chain, so the whole zone — always permitted (RFC 1995 §4), and
    /// what a client is required to cope with.
    FullTransfer {
        messages: Vec<DnsMessage>,
        why: &'static str,
    },
}

impl IxfrResponse {
    pub fn messages(self) -> Vec<DnsMessage> {
        match self {
            IxfrResponse::UpToDate(messages)
            | IxfrResponse::Incremental { messages, .. }
            | IxfrResponse::FullTransfer { messages, .. } => messages,
        }
    }
}

/// The serial an IXFR request is asking to be brought forward from.
///
/// It rides in the *authority* section (RFC 1995 §3), which is the one thing
/// about an IXFR request that differs from an AXFR one — and the reason a
/// validator that forbids authority sections in requests makes IXFR unreceivable
/// without ever saying so.
pub fn requested_serial(request: &DnsMessage) -> Option<Serial> {
    request
        .authorities
        .iter()
        .filter(|rr| rr.rdata.rtype() == rt::SOA)
        .find_map(|rr| match rr.rdata.parse() {
            Ok(crate::ParsedRecord::SOA { serial, .. }) => Some(serial),
            _ => None,
        })
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
    let soa = apex_soa(zone)
        .ok_or_else(|| TransferError::malformed(format!("zone {apex} has no SOA at its apex")))?;
    let current = zone
        .serial()
        .ok_or_else(|| TransferError::malformed(format!("zone {apex} has no serial")))?;

    // No SOA in the request is an IXFR that did not say what it holds. RFC 1995
    // §3 requires one; without it the only answerable question is "give me
    // everything".
    let Some(client_serial) = requested_serial(request) else {
        return Ok(IxfrResponse::FullTransfer {
            messages: axfr_messages(request, zone)?,
            why: "the request carried no SOA to compare against",
        });
    };

    // Already current — or ahead of us, which happens to a secondary of a
    // primary that was rolled back, and which more data would not fix.
    if !current.is_newer_than(client_serial) {
        return Ok(IxfrResponse::UpToDate(pack_transfer_messages(
            request,
            vec![soa],
        )));
    }

    let Some(chain) = deltas.chain_from(apex, client_serial) else {
        return Ok(IxfrResponse::FullTransfer {
            messages: axfr_messages(request, zone)?,
            why: "no unbroken chain of changes back to the client's serial",
        });
    };
    if chain.last().map(|d| d.to_serial) != Some(current) {
        // The chain exists but does not reach the version we are serving, which
        // means the zone moved by some route the log did not see. Sending it
        // would leave the client short of where it thinks it got to.
        return Ok(IxfrResponse::FullTransfer {
            messages: axfr_messages(request, zone)?,
            why: "the remembered changes do not reach the zone's current serial",
        });
    }

    // RFC 1995 §4: if the increment is not smaller than the zone, send the zone.
    // The condition is about what actually crosses the wire, and the point of an
    // incremental transfer is that less of it does.
    let records: usize = chain.iter().map(|d| d.len()).sum();
    if records >= zone.records().len() {
        return Ok(IxfrResponse::FullTransfer {
            messages: axfr_messages(request, zone)?,
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
    use crate::zone::parse_zone_file;
    use crate::{OpCode, QueryClass, QuerySection, ResponseCode};

    fn zone_at(serial: u32, body: &str) -> Zone {
        parse_zone_file(
            &format!(
                "$TTL 3600\n\
                 @    IN SOA ns1.example.com. admin.example.com. {serial} 3600 1800 604800 86400\n\
                 @    IN NS  ns1.example.com.\n\
                 {body}"
            ),
            "example.com.",
        )
        .expect("zone should parse")
    }

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
                qname: "example.com.".to_string(),
                qtype: Qtype::of(rt::IXFR),
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            edns: None,
        };
        if let Some(serial) = client_serial {
            msg.authorities = vec![apex_soa(&zone_at(serial, "")).unwrap()];
        }
        msg
    }

    fn answers(messages: &[DnsMessage]) -> Vec<&ResourceRecord> {
        messages.iter().flat_map(|m| m.answers.iter()).collect()
    }

    // -----------------------------------------------------------------
    // Diffing
    // -----------------------------------------------------------------

    #[test]
    fn test_diff_finds_what_moved() {
        let old = zone_at(1, "www IN A 192.0.2.1\nmail IN A 192.0.2.2\n");
        let new = zone_at(2, "www IN A 192.0.2.9\nftp IN A 192.0.2.3\n");

        let delta = diff(&old, &new).expect("both zones have an SOA");
        assert_eq!(delta.from_serial, Serial::new(1));
        assert_eq!(delta.to_serial, Serial::new(2));

        let deleted: Vec<&str> = delta.deleted.iter().map(|r| r.name.as_str()).collect();
        let added: Vec<&str> = delta.added.iter().map(|r| r.name.as_str()).collect();
        assert!(deleted.contains(&"www.example.com."), "{deleted:?}");
        assert!(deleted.contains(&"mail.example.com."), "{deleted:?}");
        assert!(added.contains(&"www.example.com."), "{added:?}");
        assert!(added.contains(&"ftp.example.com."), "{added:?}");
        assert_eq!(delta.deleted.len(), 2);
        assert_eq!(delta.added.len(), 2);
    }

    /// A record that did not move must not appear in either list — otherwise an
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
        assert_eq!(delta.added[0].name, "new.example.com.");
    }

    /// The apex SOA is the framing, not a record of the difference: a copy of it
    /// among the changes would read as the start of another sequence.
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

    // -----------------------------------------------------------------
    // The log
    // -----------------------------------------------------------------

    #[test]
    fn test_the_log_chains_steps_together() {
        let mut log = DeltaLog::new();
        let v1 = zone_at(1, "www IN A 192.0.2.1\n");
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");
        let v3 = zone_at(3, "www IN A 192.0.2.3\n");

        log.note_change(None, &v1);
        log.note_change(Some(&v1), &v2);
        log.note_change(Some(&v2), &v3);
        assert_eq!(log.len("example.com."), 2, "the first load is not a step");

        let chain = log
            .chain_from("example.com.", Serial::new(1))
            .expect("a chain from 1");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].from_serial, Serial::new(1));
        assert_eq!(chain[1].to_serial, Serial::new(3));

        assert_eq!(
            log.chain_from("example.com.", Serial::new(2))
                .map(|c| c.len()),
            Some(1),
            "a client one step behind gets one step"
        );
        assert!(
            log.chain_from("example.com.", Serial::new(99)).is_none(),
            "a serial we never held has no chain"
        );
        assert!(log.chain_from("other.test.", Serial::new(1)).is_none());
    }

    /// The history is bounded, and it is the oldest steps that go — a client far
    /// enough behind falls back to a full transfer, which is what that fallback
    /// is for.
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

        assert_eq!(log.len("example.com."), MAX_DELTAS_PER_ZONE);
        assert!(
            log.chain_from("example.com.", Serial::new(1)).is_none(),
            "aged out"
        );
        let newest = Serial::new(MAX_DELTAS_PER_ZONE as u32 + 9);
        assert_eq!(
            log.chain_from("example.com.", newest).map(|c| c.len()),
            Some(1)
        );
    }

    /// A serial that did not move forward is not a version step. A zone edited
    /// without bumping its serial is a mistake, and inventing a step for it would
    /// hand secondaries a change they can never ask for again.
    #[test]
    fn test_a_serial_that_did_not_advance_is_not_a_step() {
        let mut log = DeltaLog::new();
        let v1 = zone_at(5, "www IN A 192.0.2.1\n");
        let same_serial = zone_at(5, "www IN A 192.0.2.99\n");
        let backwards = zone_at(4, "www IN A 192.0.2.98\n");

        log.note_change(Some(&v1), &same_serial);
        log.note_change(Some(&v1), &backwards);
        assert_eq!(log.len("example.com."), 0);
    }

    #[test]
    fn test_a_withdrawn_zone_takes_its_history_with_it() {
        let mut log = DeltaLog::new();
        let v1 = zone_at(1, "www IN A 192.0.2.1\n");
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");
        log.note_change(Some(&v1), &v2);
        assert_eq!(log.len("example.com."), 1);

        log.forget("EXAMPLE.COM.");
        assert_eq!(log.len("example.com."), 0, "and case-insensitively");
    }

    // -----------------------------------------------------------------
    // The response
    // -----------------------------------------------------------------

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
        assert_eq!(all[2].name, "www.example.com.");
        assert_eq!(
            all[3].rdata.rtype(),
            rt::SOA,
            "then the new SOA: additions follow"
        );
        assert_eq!(all[4].name, "www.example.com.");
        assert_eq!(all[5].rdata.rtype(), rt::SOA, "closes with the current SOA");
        assert_eq!(all.len(), 6);

        // The second record being an SOA is exactly how a client tells this from
        // a full transfer, so pin the distinction.
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

        // A client *ahead* of us gets the same answer: more data would not fix a
        // primary that was rolled back.
        let ahead = ixfr_response(&request(Some(9)), &zone, &DeltaLog::new()).expect("response");
        assert!(matches!(ahead, IxfrResponse::UpToDate(_)));
    }

    /// Falling back to a full transfer is not a failure — RFC 1995 §4 permits it
    /// unconditionally, and it is what makes forgetting the deltas on restart
    /// survivable.
    #[test]
    fn test_falls_back_to_a_full_transfer_when_it_cannot_do_better() {
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");

        // No chain at all.
        let response = ixfr_response(&request(Some(1)), &v2, &DeltaLog::new()).unwrap();
        let IxfrResponse::FullTransfer { messages, why } = response else {
            panic!("expected a full transfer");
        };
        assert!(why.contains("no unbroken chain"), "got: {why}");
        assert_eq!(answers(&messages)[0].rdata.rtype(), rt::SOA);
        assert_ne!(answers(&messages)[1].rdata.rtype(), rt::SOA, "a full zone");

        // No SOA in the request: nothing to compare against.
        let response = ixfr_response(&request(None), &v2, &DeltaLog::new()).unwrap();
        assert!(
            matches!(response, IxfrResponse::FullTransfer { why, .. } if why.contains("no SOA"))
        );
    }

    /// If the increment is not smaller than the zone, the zone is the cheaper
    /// answer and the RFC says to send it.
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

    /// A chain that stops short of what we are serving would leave the client
    /// believing it had caught up when it had not.
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
