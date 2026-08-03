//! Persisting the version steps a zone has been through (`TODO.md` #7 step 6).
//!
//! **Why this exists now and did not before.** `ixfr::DeltaLog` remembers what
//! changed between versions so a secondary can be sent an increment. Until
//! dynamic UPDATE arrived those steps were recomputed from two versions that
//! were both still in memory, and forgetting them on restart was correct,
//! permitted unconditionally by RFC 1995 §4, and self-correcting — the next
//! change after a restart has a delta again. `ixfr.rs`'s module docs say so, and
//! they were right.
//!
//! Two things changed when UPDATE started being served. The zone now moves
//! **between** reloads rather than only at them, so a restart discards work that
//! nothing will recreate: the previous versions no longer exist anywhere. And
//! `MAX_DELTAS_PER_ZONE` is 32, which is a generous history when the only source
//! of change is an operator editing a file and **thirty-two updates** when it is
//! a DHCP client. Both of those are capacity arguments the in-memory design
//! never had to answer.
//!
//! **The format is the zone file's, and the framing is RFC 1995's.** Each delta
//! is written as the difference sequence a client would receive — the old SOA,
//! the records deleted, the new SOA, the records added — in the presentation
//! format `zone_writer` already emits and `zone::parse_zone_file` already reads.
//! Two reasons, and the second is the one that matters. The obvious one is §7:
//! no second definition of what a record looks like on disk, and the round trip
//! is already tested. The other is that the *positional* read below — first
//! record is the old SOA, records until the next apex SOA are deletions, the
//! rest are additions — is the same read `ixfr_response` writes and `secondary`
//! consumes, so a journal entry and a wire increment cannot drift into meaning
//! different things. It is safe because `ixfr::diff` excludes the apex SOA from
//! both lists: the only apex SOAs in a sequence are the two framing it.
//!
//! **Rewritten whole rather than appended to.** A partial append corrupts the
//! tail of a file whose reader is this same server at its next start, and
//! getting append-atomicity right is a protocol to design and test.
//! `persist::write_atomically` already gives all-or-nothing by writing a
//! temporary file and renaming it, and the journal is bounded at
//! `MAX_DELTAS_PER_ZONE` entries of a handful of records each — so rewriting
//! costs a few tens of kilobytes per update and buys a file that cannot be
//! half-written. That trade is stated rather than hidden: it is the wrong one
//! for a journal of unbounded size, and this one is not.
//!
//! **A journal that will not read is not fatal.** This is the opposite of the
//! secondary's state file, where `TODO.md` records that a corrupt file must stop
//! the server — forgetting a serial there costs a refresh, and forgetting a
//! *last-contact time* is the difference between a withdrawn zone and a stale
//! one served with AA set (`CLAUDE.md` §4). Nothing here has teeth: a journal
//! that cannot be read means some secondaries take a full transfer, which is
//! what RFC 1995 §4 permits at any time and what happened on every restart
//! before this file existed. So [`Journal::load`] reports the failure to its
//! caller to log and carries on, and the caller starts with an empty history.

use std::path::{Path, PathBuf};

use crate::error::ZoneError;
use crate::ixfr::ZoneDelta;
use crate::utils::{absolute_lowered, record_types as rt};
use crate::zone::{parse_zone_file, Zone, ZoneRecord};
use crate::zone_writer::record_to_string;
use crate::{ParsedRecord, ResourceRecord, Serial};

/// The line that separates one difference sequence from the next.
///
/// A zone-file comment, so that a journal is also a readable — if odd — zone
/// file fragment, and so an operator looking at one is not reading an invented
/// syntax. The split happens before parsing; the parser only ever sees records.
const SEPARATOR: &str = "; ---- delta ----";

/// Where a zone's persisted version steps live.
#[derive(Debug, Clone)]
pub struct Journal {
    dir: PathBuf,
}

impl Journal {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Journal { dir: dir.into() }
    }

    /// The file a zone's journal lives in.
    ///
    /// Named from the folded zone name rather than from whatever file the zone
    /// was loaded out of, because those are not the same thing: a zone's origin
    /// comes from its `$ORIGIN` and the file name is only a default
    /// (`enumerate_zone_files`). Keying on the origin means the journal follows
    /// the zone, not the path.
    pub fn path_for(&self, zone: &str) -> PathBuf {
        self.dir.join(format!("{}journal", absolute_lowered(zone)))
    }

    /// Write a zone's history, replacing whatever was there.
    ///
    /// An empty history removes the file rather than leaving a stale one: a
    /// zone we no longer hold increments for must not appear to offer them
    /// after a restart.
    pub fn save(&self, zone: &str, deltas: &[&ZoneDelta]) -> Result<(), ZoneError> {
        let path = self.path_for(zone);
        if deltas.is_empty() {
            // A missing file and an empty one mean the same thing to `load`, so
            // failing to remove one is not worth propagating.
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }

        let mut out = String::new();
        out.push_str("; rdnsd journal — RFC 1995 difference sequences, newest last.\n");
        out.push_str("; Regenerated whole on every change; safe to delete.\n");
        for delta in deltas {
            out.push_str(SEPARATOR);
            out.push('\n');
            write_record(&mut out, &delta.from_soa)?;
            for record in &delta.deleted {
                write_record(&mut out, record)?;
            }
            write_record(&mut out, &delta.to_soa)?;
            for record in &delta.added {
                write_record(&mut out, record)?;
            }
        }

        crate::persist::write_atomically_str(&path, &out).map_err(|source| ZoneError::Io {
            path: path.display().to_string(),
            source,
        })
    }

    /// Read a zone's history back, oldest first.
    ///
    /// `Ok(vec![])` when there is no journal, which is the ordinary case for a
    /// zone that has never changed and for the first start after this existed.
    /// An unreadable or malformed journal is an `Err` the caller logs and
    /// otherwise ignores — see the module docs for why that is right here and
    /// wrong for the secondary's state file.
    pub fn load(&self, zone: &str) -> Result<Vec<ZoneDelta>, ZoneError> {
        let path = self.path_for(zone);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(ZoneError::Io {
                    path: path.display().to_string(),
                    source,
                })
            }
        };

        let origin = absolute_lowered(zone).into_owned();
        let mut deltas = Vec::new();
        for (index, block) in text.split(SEPARATOR).skip(1).enumerate() {
            let delta = read_delta(block, &origin).map_err(|e| {
                ZoneError::invalid(format!(
                    "{}: difference sequence {} is unreadable: {e}",
                    path.display(),
                    index + 1
                ))
            })?;
            deltas.push(delta);
        }

        // A chain with a gap in it would send a secondary a version that never
        // existed, which no serial comparison afterwards could detect —
        // `DeltaLog::chain_from` refuses one at read time and this refuses one at
        // load time, because a journal is a thing an operator can edit.
        for pair in deltas.windows(2) {
            if pair[0].to_serial != pair[1].from_serial {
                return Err(ZoneError::invalid(format!(
                    "{}: the sequences do not link — one ends at {} and the next starts at {}",
                    path.display(),
                    pair[0].to_serial,
                    pair[1].from_serial
                )));
            }
        }

        Ok(deltas)
    }

    /// Forget a zone's history, as `DeltaLog::forget` does in memory.
    ///
    /// A zone that has been withdrawn — expired, or removed from the
    /// configuration — must not come back after a restart offering increments of
    /// something nobody serves.
    pub fn forget(&self, zone: &str) {
        let _ = std::fs::remove_file(self.path_for(zone));
    }
}

fn write_record(out: &mut String, record: &ResourceRecord) -> Result<(), ZoneError> {
    let line = record_to_string(&ZoneRecord {
        name: record.name.clone(),
        ttl: record.ttl,
        class: record.class,
        rdata: record.rdata.clone(),
    })?;
    out.push_str(&line);
    if !line.ends_with('\n') {
        out.push('\n');
    }
    Ok(())
}

/// One difference sequence, read positionally in RFC 1995 §4's order.
fn read_delta(block: &str, origin: &str) -> Result<ZoneDelta, ZoneError> {
    // The parser, not a second reader for the same syntax. What comes back is a
    // `Zone` whose `records()` preserve insertion order and duplicates, which is
    // what a sequence needs — it is a list, not a set.
    let parsed = parse_zone_file(block, origin)?;
    let records: Vec<ResourceRecord> = parsed
        .records()
        .iter()
        .map(|r| ResourceRecord {
            name: parsed.normalize_name(&r.name).into_owned(),
            class: r.class,
            ttl: r.ttl,
            rdata: r.rdata.clone(),
        })
        .collect();

    let is_apex_soa = |record: &ResourceRecord| {
        record.rdata.rtype() == rt::SOA && record.name.eq_ignore_ascii_case(origin)
    };

    let [from_soa, rest @ ..] = records.as_slice() else {
        return Err(ZoneError::invalid("it is empty"));
    };
    if !is_apex_soa(from_soa) {
        return Err(ZoneError::invalid(
            "it does not open with the apex SOA that RFC 1995 §4 frames a \
             difference sequence with",
        ));
    }
    let split = rest.iter().position(is_apex_soa).ok_or_else(|| {
        ZoneError::invalid("it has no second apex SOA, so nothing marks the additions")
    })?;
    let (deleted, with_to_soa) = rest.split_at(split);
    let [to_soa, added @ ..] = with_to_soa else {
        unreachable!("position() found the record that split_at just kept")
    };

    Ok(ZoneDelta {
        from_serial: serial_of(from_soa)?,
        to_serial: serial_of(to_soa)?,
        from_soa: from_soa.clone(),
        to_soa: to_soa.clone(),
        deleted: deleted.to_vec(),
        added: added.to_vec(),
    })
}

fn serial_of(soa: &ResourceRecord) -> Result<Serial, ZoneError> {
    match soa.rdata.parse() {
        Ok(ParsedRecord::SOA { serial, .. }) => Ok(serial),
        _ => Err(ZoneError::invalid("an SOA framing it does not parse")),
    }
}

/// Every zone with a journal in this directory, for priming the log at startup.
///
/// Reading the directory rather than being told which zones to look for, so a
/// journal left behind by a zone that has since been removed is *found* and can
/// be cleaned up, instead of sitting there until someone re-adds the zone and is
/// handed a history from before it left.
pub fn journalled_zones(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut zones = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("journal") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            zones.push(format!("{stem}."));
        }
    }
    Ok(zones)
}

/// The zone a journal describes, for a caller that already has one loaded.
///
/// A journal whose last sequence does not end at the zone's current serial is
/// one the zone has moved past by some route the journal did not see — a reload
/// from an edited file, or a transfer. Chaining onto it would offer a secondary
/// a path to a version we are not serving, which is exactly what
/// `DeltaLog::chain_from`'s caller checks for at answer time; checking it here
/// as well means the bad history is dropped rather than carried and rejected on
/// every query.
pub fn usable_against(deltas: &[ZoneDelta], zone: &Zone) -> bool {
    match (deltas.last(), zone.serial()) {
        (Some(last), Some(current)) => last.to_serial == current,
        (None, _) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ixfr::{diff, DeltaLog};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!("rdns-journal-{tag}-{unique}"));
            std::fs::create_dir_all(&dir).expect("scratch dir");
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

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

    /// **A delta survives a round trip through the disk unchanged.**
    ///
    /// Record for record, TTL included, because a secondary applies these and a
    /// TTL that shifted in the journal is a TTL that shifts on the replica.
    #[test]
    fn a_delta_round_trips_through_the_journal() {
        let scratch = Scratch::new("round-trip");
        let journal = Journal::new(&scratch.0);

        let v1 = zone_at(1, "www IN A 192.0.2.1\nmail 60 IN A 192.0.2.2\n");
        let v2 = zone_at(2, "www IN A 192.0.2.9\nftp IN AAAA 2001:db8::1\n");
        let delta = diff(&v1, &v2).expect("a step");

        journal.save("example.com.", &[&delta]).expect("saves");
        let back = journal
            .load("EXAMPLE.COM.")
            .expect("and loads, case-folded");

        assert_eq!(back.len(), 1);
        assert_eq!(back[0].from_serial, Serial::new(1));
        assert_eq!(back[0].to_serial, Serial::new(2));

        let shape = |d: &ZoneDelta| {
            let render = |rs: &[ResourceRecord]| {
                let mut lines: Vec<String> = rs
                    .iter()
                    .map(|r| format!("{} {} {:?}", r.name, r.ttl, r.rdata))
                    .collect();
                lines.sort();
                lines
            };
            (render(&d.deleted), render(&d.added))
        };
        assert_eq!(shape(&back[0]), shape(&delta), "record for record");
    }

    /// A chain of steps reloads as a chain, and `DeltaLog` can answer from it —
    /// which is the whole point, so it is asserted through `chain_from` rather
    /// than by inspecting the vector.
    #[test]
    fn a_restored_chain_answers_an_ixfr_from_before_the_restart() {
        let scratch = Scratch::new("chain");
        let journal = Journal::new(&scratch.0);

        let versions: Vec<Zone> = (1..=4)
            .map(|n| zone_at(n, &format!("www IN A 192.0.2.{n}\n")))
            .collect();
        let mut log = DeltaLog::new();
        for pair in versions.windows(2) {
            log.note_change(Some(&pair[0]), &pair[1]);
        }
        assert_eq!(log.len("example.com."), 3);

        journal
            .save("example.com.", &log.all("example.com."))
            .expect("saves");

        // A fresh process: nothing in memory, everything on disk.
        let mut restored = DeltaLog::new();
        let loaded = journal.load("example.com.").expect("loads");
        assert!(usable_against(&loaded, versions.last().unwrap()));
        restored.restore("example.com.", loaded);

        let chain = restored
            .chain_from("example.com.", Serial::new(1))
            .expect("a chain from before the restart");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[2].to_serial, Serial::new(4));
    }

    /// A journal whose sequences do not link is refused rather than half-used.
    ///
    /// A gap means some change would be skipped, and a secondary that applied
    /// the rest would hold a zone that never existed — with a serial saying it
    /// is current, which nothing downstream could detect. `DeltaLog::chain_from`
    /// refuses a gap at answer time; this refuses one at load time, because a
    /// file on disk is a thing an operator can edit.
    ///
    /// **Watched failing** against a `load` with no linkage check: the truncated
    /// journal loaded as two unrelated sequences and `chain_from` then happily
    /// returned the second one on its own.
    #[test]
    fn a_journal_with_a_gap_is_refused() {
        let scratch = Scratch::new("gap");
        let journal = Journal::new(&scratch.0);

        let v1 = zone_at(1, "www IN A 192.0.2.1\n");
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");
        let v3 = zone_at(3, "www IN A 192.0.2.3\n");
        let v4 = zone_at(4, "www IN A 192.0.2.4\n");
        let first = diff(&v1, &v2).unwrap();
        let skipped = diff(&v3, &v4).unwrap();

        journal
            .save("example.com.", &[&first, &skipped])
            .expect("saves");
        let err = journal.load("example.com.").expect_err("a gap is refused");
        assert!(err.to_string().contains("do not link"), "got: {err}");
    }

    /// Nothing on disk is not an error: it is the first start, and every zone
    /// that has never changed.
    #[test]
    fn a_missing_journal_is_an_empty_history() {
        let scratch = Scratch::new("missing");
        let journal = Journal::new(&scratch.0);
        assert!(journal
            .load("example.com.")
            .expect("no journal is not a failure")
            .is_empty());
    }

    /// An empty history removes the file. A zone that has been withdrawn must
    /// not come back after a restart offering increments of itself.
    #[test]
    fn saving_nothing_removes_the_file_and_so_does_forgetting() {
        let scratch = Scratch::new("withdraw");
        let journal = Journal::new(&scratch.0);
        let v1 = zone_at(1, "www IN A 192.0.2.1\n");
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");
        let delta = diff(&v1, &v2).unwrap();

        journal.save("example.com.", &[&delta]).unwrap();
        assert!(journal.path_for("example.com.").exists());
        journal.save("example.com.", &[]).unwrap();
        assert!(!journal.path_for("example.com.").exists());

        journal.save("example.com.", &[&delta]).unwrap();
        journal.forget("example.com.");
        assert!(!journal.path_for("example.com.").exists());
    }

    /// A journal that does not match the zone it belongs to is not used.
    ///
    /// The zone moved past it by some route the journal did not see — a reload
    /// from an edited file, or a transfer. Chaining onto it would offer a
    /// secondary a path to a version nobody is serving.
    #[test]
    fn a_journal_that_does_not_reach_the_current_serial_is_not_used() {
        let v1 = zone_at(1, "www IN A 192.0.2.1\n");
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");
        let delta = diff(&v1, &v2).unwrap();

        assert!(usable_against(std::slice::from_ref(&delta), &v2));
        let v5 = zone_at(5, "www IN A 192.0.2.5\n");
        assert!(!usable_against(std::slice::from_ref(&delta), &v5));
        assert!(usable_against(&[], &v5), "no history is always usable");
    }

    /// A journal whose records will not parse is an error the caller logs, not
    /// a panic and not a silently empty history.
    #[test]
    fn a_corrupt_journal_is_an_error_rather_than_an_empty_one() {
        let scratch = Scratch::new("corrupt");
        let journal = Journal::new(&scratch.0);
        std::fs::write(
            journal.path_for("example.com."),
            format!("{SEPARATOR}\nthis is not a record at all\n"),
        )
        .expect("write");

        let err = journal
            .load("example.com.")
            .expect_err("garbage does not read as an empty history");
        assert!(err.to_string().contains("unreadable"), "got: {err}");
    }

    /// A sequence that does not open with the apex SOA has lost its framing, and
    /// reading it positionally anyway would take a deletion for the header.
    #[test]
    fn a_sequence_without_its_framing_is_refused() {
        let scratch = Scratch::new("framing");
        let journal = Journal::new(&scratch.0);
        std::fs::write(
            journal.path_for("example.com."),
            format!("{SEPARATOR}\nwww.example.com. 3600 IN A 192.0.2.1\n"),
        )
        .expect("write");

        let err = journal.load("example.com.").expect_err("no framing");
        assert!(err.to_string().contains("apex SOA"), "got: {err}");
    }
}
