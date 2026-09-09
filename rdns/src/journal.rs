//! Persisting the version steps a zone has been through.
//!
//! The format is the zone file's and the framing is RFC 1995's: old SOA, records
//! deleted, new SOA, records added. `ixfr::diff` excludes the apex SOA from both
//! lists, so the only apex SOAs in a sequence are the two framing it.
//!
//! Rewritten whole rather than appended to; all-or-nothing is affordable for a
//! few tens of kilobytes per update.
//!
//! A journal that will not read is not fatal — it costs some secondaries a full
//! transfer, which RFC 1995 §4 permits at any time.

use std::path::PathBuf;

use crate::error::ZoneError;
use crate::ixfr::ZoneDelta;
use crate::utils::record_types as rt;
use crate::zone::{parse_zone_file, Zone, ZoneRecord};
use crate::zone_writer::record_to_string;
use crate::{NameRef, ResourceRecord, Serial};

/// The line that separates one difference sequence from the next.
///
/// A zone-file comment, so a journal is still a readable zone file fragment. The
/// split happens before parsing; the parser only ever sees records.
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
    /// Keyed on the folded origin, not the file the zone was loaded from, so the
    /// journal follows the zone rather than the path.
    fn path_for(&self, zone: NameRef<'_>) -> PathBuf {
        self.dir.join(format!(
            "{}journal",
            zone.to_presentation().to_ascii_lowercase()
        ))
    }

    /// Write a zone's history, replacing whatever was there.
    ///
    /// An empty history removes the file: a zone we no longer hold increments
    /// for must not appear to offer them after a restart.
    pub fn save(&self, zone: NameRef<'_>, deltas: &[&ZoneDelta]) -> Result<(), ZoneError> {
        let path = self.path_for(zone);
        if deltas.is_empty() {
            // A missing file and an empty one mean the same thing to `load`.
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
    /// `Ok(vec![])` when there is no journal. An unreadable or malformed journal
    /// is an `Err` the caller logs and otherwise ignores.
    pub fn load(&self, zone: NameRef<'_>) -> Result<Vec<ZoneDelta>, ZoneError> {
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

        let origin = zone.to_owned();
        let mut deltas = Vec::new();
        for (index, block) in text.split(SEPARATOR).skip(1).enumerate() {
            let delta = read_delta(block, origin.as_ref()).map_err(|e| {
                ZoneError::invalid(format!(
                    "{}: difference sequence {} is unreadable: {e}",
                    path.display(),
                    index + 1
                ))
            })?;
            deltas.push(delta);
        }

        // A gap would send a secondary a version that never existed, and no
        // serial comparison afterwards could detect it. A journal is a file an
        // operator can edit, so check here as well as in `chain_from`.
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
    /// A withdrawn zone must not come back after a restart offering increments
    /// of something nobody serves.
    pub fn forget(&self, zone: NameRef<'_>) {
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
fn read_delta(block: &str, origin: NameRef<'_>) -> Result<ZoneDelta, ZoneError> {
    // The zone parser, not a second reader for the same syntax. `records()`
    // preserves insertion order and duplicates; a sequence is a list, not a set.
    let parsed = parse_zone_file(block, &origin.to_presentation())?;
    let records: Vec<ResourceRecord> = parsed
        .records()
        .iter()
        .map(|r| ResourceRecord {
            name: r.name.clone(),
            class: r.class,
            ttl: r.ttl,
            rdata: r.rdata.clone(),
        })
        .collect();

    let is_apex_soa =
        |record: &ResourceRecord| record.rdata.rtype() == rt::SOA && record.name.as_ref() == origin;

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
    soa.rdata
        .soa_serial()
        .ok_or_else(|| ZoneError::invalid("an SOA framing it does not parse"))
}

/// Whether a journal still describes this zone.
///
/// A last sequence not ending at the zone's current serial means the zone moved
/// by some route the journal did not see (an edited file, a transfer); chaining
/// onto it would offer a secondary a version nobody serves.
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
    use crate::test_records::nm;

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

    /// A delta round trips record for record, TTL included: a secondary applies
    /// these, so a TTL that shifts in the journal shifts on the replica.
    #[test]
    fn a_delta_round_trips_through_the_journal() {
        let scratch = Scratch::new("round-trip");
        let journal = Journal::new(&scratch.0);

        let v1 = zone_at(1, "www IN A 192.0.2.1\nmail 60 IN A 192.0.2.2\n");
        let v2 = zone_at(2, "www IN A 192.0.2.9\nftp IN AAAA 2001:db8::1\n");
        let delta = diff(&v1, &v2).expect("a step");

        journal
            .save(nm("example.com.").as_ref(), &[&delta])
            .expect("saves");
        let back = journal
            .load(nm("EXAMPLE.COM.").as_ref())
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

    /// A chain reloads as a chain. Asserted through `chain_from` rather than by
    /// inspecting the vector, because answering is the point.
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
        assert_eq!(log.len(nm("example.com.").as_ref()), 3);

        journal
            .save(
                nm("example.com.").as_ref(),
                &log.all(nm("example.com.").as_ref()),
            )
            .expect("saves");

        // A fresh process: nothing in memory, everything on disk.
        let mut restored = DeltaLog::new();
        let loaded = journal.load(nm("example.com.").as_ref()).expect("loads");
        assert!(usable_against(&loaded, versions.last().unwrap()));
        restored.restore(nm("example.com.").as_ref(), loaded);

        let chain = restored
            .chain_from(nm("example.com.").as_ref(), Serial::new(1))
            .expect("a chain from before the restart");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[2].to_serial, Serial::new(4));
    }

    /// A journal whose sequences do not link is refused rather than half-used: a
    /// secondary applying the rest would hold a zone that never existed, with a
    /// serial claiming it is current.
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
            .save(nm("example.com.").as_ref(), &[&first, &skipped])
            .expect("saves");
        let err = journal
            .load(nm("example.com.").as_ref())
            .expect_err("a gap is refused");
        assert!(err.to_string().contains("do not link"), "got: {err}");
    }

    /// Nothing on disk is not an error: it is every zone that has never changed.
    #[test]
    fn a_missing_journal_is_an_empty_history() {
        let scratch = Scratch::new("missing");
        let journal = Journal::new(&scratch.0);
        assert!(journal
            .load(nm("example.com.").as_ref())
            .expect("no journal is not a failure")
            .is_empty());
    }

    /// An empty history removes the file: a withdrawn zone must not come back
    /// after a restart offering increments of itself.
    #[test]
    fn saving_nothing_removes_the_file_and_so_does_forgetting() {
        let scratch = Scratch::new("withdraw");
        let journal = Journal::new(&scratch.0);
        let v1 = zone_at(1, "www IN A 192.0.2.1\n");
        let v2 = zone_at(2, "www IN A 192.0.2.2\n");
        let delta = diff(&v1, &v2).unwrap();

        journal
            .save(nm("example.com.").as_ref(), &[&delta])
            .unwrap();
        assert!(journal.path_for(nm("example.com.").as_ref()).exists());
        journal.save(nm("example.com.").as_ref(), &[]).unwrap();
        assert!(!journal.path_for(nm("example.com.").as_ref()).exists());

        journal
            .save(nm("example.com.").as_ref(), &[&delta])
            .unwrap();
        journal.forget(nm("example.com.").as_ref());
        assert!(!journal.path_for(nm("example.com.").as_ref()).exists());
    }

    /// A journal that does not reach the zone's current serial is not used.
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

    /// Garbage is an error the caller logs, not a silently empty history.
    #[test]
    fn a_corrupt_journal_is_an_error_rather_than_an_empty_one() {
        let scratch = Scratch::new("corrupt");
        let journal = Journal::new(&scratch.0);
        std::fs::write(
            journal.path_for(nm("example.com.").as_ref()),
            format!("{SEPARATOR}\nthis is not a record at all\n"),
        )
        .expect("write");

        let err = journal
            .load(nm("example.com.").as_ref())
            .expect_err("garbage does not read as an empty history");
        assert!(err.to_string().contains("unreadable"), "got: {err}");
    }

    /// Without the opening apex SOA a positional read would take a deletion for
    /// the header.
    #[test]
    fn a_sequence_without_its_framing_is_refused() {
        let scratch = Scratch::new("framing");
        let journal = Journal::new(&scratch.0);
        std::fs::write(
            journal.path_for(nm("example.com.").as_ref()),
            format!("{SEPARATOR}\nwww.example.com. 3600 IN A 192.0.2.1\n"),
        )
        .expect("write");

        let err = journal
            .load(nm("example.com.").as_ref())
            .expect_err("no framing");
        assert!(err.to_string().contains("apex SOA"), "got: {err}");
    }
}
