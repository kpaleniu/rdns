//! Being a replica of somebody else's zone: what to fetch, when, and what to
//! remember between restarts.
//!
//! [`crate::xfr`] knows how to obtain a zone; this knows when it is due, when it
//! has gone stale, and what survives a restart. The split matters because the
//! timing rules are the half with no I/O in them and every interesting edge case:
//! they can be tested by moving a clock rather than by waiting.
//!
//! **The shape of replication here** is single-writer, asynchronous and
//! pull-based. One primary holds the editable copy; a secondary asks for it, is
//! read-only, and never resolves a conflict because it never accepts a write. A
//! NOTIFY is a hint that shortens the wait, not a channel the data arrives on —
//! which is why losing one costs a delay and nothing else.
//!
//! **EXPIRE is the timer with teeth.** REFRESH and RETRY only decide how eagerly
//! we ask. EXPIRE says how long a secondary may keep answering *authoritatively*
//! for a zone it has lost contact with — and past it the honest answer is to stop
//! serving the zone rather than to keep handing out data that may be arbitrarily
//! stale, with the AA bit claiming otherwise (RFC 1035 §3.3.13, RFC 1912 §2.2).

use crate::error::{ConfigError, ConfigResult};
use crate::Qtype;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::utils::record_types as rt;
use crate::zone::Zone;
use crate::{ParsedRecord, Serial};

/// The floor under REFRESH and RETRY.
///
/// A zone whose SOA says refresh every 0 seconds would otherwise be a loop that
/// asks its master as fast as the network allows. The RFCs set no floor because
/// they did not imagine one being needed; every implementation has learned to.
pub const MIN_TIMER_SECS: u64 = 60;

/// What to use before we have ever seen the zone's SOA — a zone we have not
/// fetched yet has no timers of its own to obey.
pub const DEFAULT_REFRESH_SECS: u64 = 3600;

/// The three timers a secondary lives by, from the zone's apex SOA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshTimers {
    /// How long after a successful check before asking again.
    pub refresh: u64,
    /// How long after a failed one.
    pub retry: u64,
    /// How long out of contact before the zone must stop being served.
    pub expire: u64,
}

impl Default for RefreshTimers {
    fn default() -> Self {
        RefreshTimers {
            refresh: DEFAULT_REFRESH_SECS,
            retry: MIN_TIMER_SECS,
            // A zone we have never reached cannot expire — there is nothing to
            // withdraw, and this value is replaced the moment one arrives.
            expire: u64::MAX,
        }
    }
}

impl RefreshTimers {
    /// The timers in a zone's apex SOA, clamped to something a server can obey.
    ///
    /// The SOA fields are signed and written by hand, so a negative or absurd
    /// value is not a theoretical concern. Clamping rather than rejecting is
    /// deliberate: a secondary that refuses to serve a zone because its master
    /// wrote `retry 0` has turned a cosmetic mistake into an outage.
    pub fn from_soa(refresh: i32, retry: i32, expire: i32) -> Self {
        let floor = |value: i32| (value.max(0) as u64).max(MIN_TIMER_SECS);
        RefreshTimers {
            refresh: floor(refresh),
            retry: floor(retry),
            // EXPIRE has no floor of its own: it is a limit on staleness, and
            // raising a small one would keep a zone alive longer than its
            // operator said to. Zero means "expire as soon as contact is lost",
            // which is a strange thing to write but an unambiguous one.
            expire: expire.max(0) as u64,
        }
    }

    /// The timers from a zone's apex SOA, if it has one.
    pub fn from_zone(zone: &Zone) -> Option<Self> {
        zone.query(zone.origin(), Qtype::of(rt::SOA))
            .first()
            .and_then(|soa| match soa.rdata.parse() {
                Ok(ParsedRecord::SOA {
                    refresh,
                    retry,
                    expire,
                    ..
                }) => Some(RefreshTimers::from_soa(refresh, retry, expire)),
                _ => None,
            })
    }

    /// How long to wait after reaching the master.
    pub fn after_success(&self) -> Duration {
        Duration::from_secs(self.refresh)
    }

    /// How long to wait after failing to.
    pub fn after_failure(&self) -> Duration {
        Duration::from_secs(self.retry)
    }

    /// Whether a zone last reached at `last_contact` may still be served at `now`.
    ///
    /// Measured from the last time the master *answered*, not from the last time
    /// the zone changed: a zone that has not changed in a year is not stale, and
    /// one whose master vanished an hour ago may be.
    pub fn has_expired(&self, last_contact: u64, now: u64) -> bool {
        now.saturating_sub(last_contact) > self.expire
    }
}

/// One zone to replicate, and where from: `zone@master[:port][#keyname]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterSpec {
    /// The zone's apex, absolute.
    pub zone: String,
    pub master: SocketAddr,
    /// The TSIG key to sign the transfer with, by name — looked up in the keys
    /// `--tsig-key` defines, so a secret is written down in exactly one place.
    pub key_name: Option<String>,
}

impl MasterSpec {
    pub fn parse(spec: &str) -> ConfigResult<Self> {
        let spec = spec.trim();
        let (rest, key_name) = match spec.split_once('#') {
            Some((rest, key)) if !key.is_empty() => (rest, Some(key.to_string())),
            Some(_) => {
                return Err(ConfigError::new(format!(
                    "{spec:?}: '#' with no key name after it"
                )))
            }
            None => (spec, None),
        };
        let Some((zone, master)) = rest.split_once('@') else {
            return Err(ConfigError::new(format!(
                "{spec:?} is not zone@master[:port][#key]: no '@' separating the \
                 zone from the address it comes from"
            )));
        };
        if zone.is_empty() {
            return Err(ConfigError::new(format!(
                "{spec:?}: no zone before the '@'"
            )));
        }

        Ok(MasterSpec {
            zone: absolute(zone),
            master: parse_address(master, spec)?,
            key_name,
        })
    }
}

/// `addr` or `addr:port`, defaulting to 53.
///
/// A bare IPv6 address has colons of its own, so `[::1]:5353` is the only
/// unambiguous way to give one a port — the shape `SocketAddr` already parses,
/// rather than a convention of ours.
fn parse_address(text: &str, spec: &str) -> ConfigResult<SocketAddr> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    match text.parse::<IpAddr>() {
        Ok(ip) => Ok(SocketAddr::new(ip, 53)),
        Err(e) => Err(ConfigError::new(format!(
            "{spec:?}: {text:?} is not an address or address:port: {e}"
        ))),
    }
}

/// [`crate::utils::absolute`], owned — this module's callers all keep the
/// result. One line rather than the three it replaces (`TODO.md` #19c).
fn absolute(name: &str) -> String {
    crate::utils::absolute(name).into_owned()
}

// ---------------------------------------------------------------------------
// The state sidecar
// ---------------------------------------------------------------------------

/// What is known about one replicated zone between restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferState {
    pub zone: String,
    /// The serial of the copy on disk.
    pub serial: Serial,
    /// When the master last answered, as a Unix timestamp. The EXPIRE clock runs
    /// from here.
    pub refreshed_at: u64,
    pub master: SocketAddr,
}

/// The sidecar file: one line per replicated zone.
///
/// Kept out of the zone file itself on purpose. BIND leans on the zone file's
/// mtime for this and pays in imprecision — an unrelated touch resets the
/// refresh clock, and a copy preserves a timestamp that then describes the wrong
/// event (this repo has already been bitten by `Copy-Item` doing exactly that).
/// A line of text says what it means.
///
/// Text rather than anything structured because it is a few hundred bytes that a
/// person may need to read, edit or delete while a server is down, and because
/// every alternative costs a dependency to store less than a kilobyte.
pub struct StateFile {
    path: PathBuf,
    entries: Vec<TransferState>,
}

impl StateFile {
    /// Read the sidecar, or start empty.
    ///
    /// **Never fails.** A missing file means nothing has been fetched yet; an
    /// unreadable or half-written one means the same thing, because the only
    /// consequence of forgetting is fetching again. Refusing to start over a
    /// corrupt cache of something re-obtainable would turn a scratch file into a
    /// single point of failure. Lines that do not parse are skipped and named on
    /// stderr rather than silently dropped — a state file going bad is worth
    /// seeing even though it is survivable.
    pub fn load(path: &Path) -> Self {
        let mut entries = Vec::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for (number, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                match parse_state_line(line) {
                    Ok(state) => entries.push(state),
                    Err(e) => tracing::warn!(
                        file = %path.display(),
                        line = number + 1,
                        "ignoring unreadable state line ({e})"
                    ),
                }
            }
        }
        StateFile {
            path: path.to_path_buf(),
            entries,
        }
    }

    /// What is known about this zone from this master.
    pub fn get(&self, zone: &str, master: SocketAddr) -> Option<&TransferState> {
        self.entries
            .iter()
            .find(|e| e.master == master && e.zone.eq_ignore_ascii_case(zone))
    }

    pub fn entries(&self) -> &[TransferState] {
        &self.entries
    }

    /// Record what is now true, and write the file.
    ///
    /// Written whole and atomically every time rather than appended to: the file
    /// is small, and a reader must never see a line half-updated.
    ///
    /// **The write is the expensive half**, and a caller that holds a lock or
    /// runs on an async runtime should not do it here — see [`StateFile::set`].
    pub fn record(&mut self, state: TransferState) -> ConfigResult<()> {
        self.set(state);
        let (path, text) = self.snapshot();
        write_snapshot(&path, &text)
    }

    /// Update what is known, writing nothing.
    ///
    /// Split out of [`StateFile::record`] because the write ends in an `fsync`
    /// of the file *and* of its directory, and `rdnsd` reaches this through an
    /// `Arc<Mutex<StateFile>>` from an async task. Doing the write here would
    /// hold a `std::sync::Mutex` across that fsync — which every other
    /// secondary's refresh loop then spins on rather than yielding — and would
    /// block a runtime worker that is also answering queries (`CLAUDE.md` §9).
    /// The caller updates under the guard, takes a [`StateFile::snapshot`],
    /// drops the guard, and writes.
    pub fn set(&mut self, state: TransferState) {
        match self
            .entries
            .iter_mut()
            .find(|e| e.master == state.master && e.zone.eq_ignore_ascii_case(&state.zone))
        {
            Some(existing) => *existing = state,
            None => self.entries.push(state),
        }
    }

    /// The path and the exact contents [`StateFile::record`] would write.
    ///
    /// Owned rather than borrowed, so it can outlive the guard it was taken
    /// under — which is the entire point of it existing.
    pub fn snapshot(&self) -> (PathBuf, String) {
        let mut text = String::from(
            "# rdnsd transfer state: zone serial refreshed-at master\n\
             # Written by the server. Deleting this only costs a refresh.\n",
        );
        for entry in &self.entries {
            text.push_str(&format!(
                "{} {} {} {}\n",
                entry.zone, entry.serial, entry.refreshed_at, entry.master
            ));
        }
        (self.path.clone(), text)
    }
}

/// Write a snapshot taken by [`StateFile::snapshot`].
///
/// Free-standing because by the time this runs the caller has deliberately let
/// go of the `StateFile` — and of whatever lock it sits behind.
pub fn write_snapshot(path: &Path, text: &str) -> ConfigResult<()> {
    crate::persist::write_atomically_str(path, text)
        .map_err(|e| ConfigError::new(format!("writing {}: {e}", path.display())))
}

fn parse_state_line(line: &str) -> ConfigResult<TransferState> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let [zone, serial, refreshed_at, master] = fields[..] else {
        return Err(ConfigError::new(format!(
            "expected 4 fields, got {}",
            fields.len()
        )));
    };
    Ok(TransferState {
        zone: absolute(zone),
        serial: serial
            .parse()
            .map_err(|e| ConfigError::new(format!("serial: {e}")))?,
        refreshed_at: refreshed_at
            .parse()
            .map_err(|e| ConfigError::new(format!("refresh time: {e}")))?,
        master: master
            .parse()
            .map_err(|e| ConfigError::new(format!("master address: {e}")))?,
    })
}

/// Where a replicated zone's file goes, given the directory zones live in.
///
/// The name is the origin, which is how `rdnsd` already decides what a zone file
/// on disk is a zone *of* — so a fetched zone is loaded by the ordinary path on
/// the next start, with nothing to tell it apart from one an operator wrote.
pub fn zone_file_path(dir: &Path, zone: &str) -> PathBuf {
    dir.join(format!("{}zone", absolute(zone)))
}

/// Where the sidecar goes.
pub fn state_file_path(dir: &Path) -> PathBuf {
    dir.join("rdnsd.state")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::parse_zone_file;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("test address")
    }

    // -----------------------------------------------------------------
    // Master specs
    // -----------------------------------------------------------------

    #[test]
    fn test_master_spec_parses() {
        assert_eq!(
            MasterSpec::parse("example.com@192.0.2.1").unwrap(),
            MasterSpec {
                zone: "example.com.".to_string(),
                master: addr("192.0.2.1:53"),
                key_name: None,
            },
            "the zone is made absolute and the port defaults to 53"
        );
        assert_eq!(
            MasterSpec::parse("example.com.@192.0.2.1:5353#transfer.key.").unwrap(),
            MasterSpec {
                zone: "example.com.".to_string(),
                master: addr("192.0.2.1:5353"),
                key_name: Some("transfer.key.".to_string()),
            }
        );
    }

    /// An IPv6 master has colons of its own, so the bracketed form is the only
    /// one that can carry a port — and the unbracketed one must still work.
    #[test]
    fn test_master_spec_takes_ipv6() {
        assert_eq!(
            MasterSpec::parse("example.com@[2001:db8::1]:5353")
                .unwrap()
                .master,
            addr("[2001:db8::1]:5353")
        );
        assert_eq!(
            MasterSpec::parse("example.com@2001:db8::1").unwrap().master,
            addr("[2001:db8::1]:53")
        );
    }

    /// A spec that does not parse stops the server. A secondary silently not
    /// replicating a zone it was told to replicate is the failure nobody notices
    /// until the primary is gone.
    #[test]
    fn test_a_malformed_master_spec_is_an_error() {
        for spec in [
            "example.com", // no master
            "@192.0.2.1",  // no zone
            "example.com@not-an-address",
            "example.com@192.0.2.1#", // '#' promising a key that is not there
        ] {
            assert!(
                MasterSpec::parse(spec).is_err(),
                "{spec:?} should not parse"
            );
        }
    }

    // -----------------------------------------------------------------
    // Timers
    // -----------------------------------------------------------------

    #[test]
    fn test_timers_come_from_the_soa() {
        let zone = parse_zone_file(
            "@ IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 300\n",
            "example.com.",
        )
        .unwrap();
        assert_eq!(
            RefreshTimers::from_zone(&zone),
            Some(RefreshTimers {
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
            })
        );
        assert_eq!(
            RefreshTimers::from_zone(&zone).unwrap().after_success(),
            Duration::from_secs(7200)
        );
        assert_eq!(
            RefreshTimers::from_zone(&zone).unwrap().after_failure(),
            Duration::from_secs(3600)
        );

        // No SOA, no timers to obey.
        let bare = parse_zone_file("www IN A 192.0.2.1\n", "example.com.").unwrap();
        assert_eq!(RefreshTimers::from_zone(&bare), None);
    }

    /// A zone that says "refresh every 0 seconds" must not become a loop that
    /// asks its master as fast as the network allows.
    #[test]
    fn test_absurd_timers_are_clamped_rather_than_refused() {
        let timers = RefreshTimers::from_soa(0, -5, 86400);
        assert_eq!(timers.refresh, MIN_TIMER_SECS);
        assert_eq!(timers.retry, MIN_TIMER_SECS);
        assert_eq!(
            timers.expire, 86400,
            "EXPIRE keeps its value: raising it would serve a zone longer than \
             its operator said to"
        );
    }

    #[test]
    fn test_expiry_measures_from_the_last_contact() {
        let timers = RefreshTimers::from_soa(3600, 600, 86400);
        let fetched_at = 1_000_000;

        assert!(
            !timers.has_expired(fetched_at, fetched_at + 86_400),
            "exactly at the limit"
        );
        assert!(
            timers.has_expired(fetched_at, fetched_at + 86_401),
            "past it"
        );
        assert!(
            !timers.has_expired(fetched_at, fetched_at - 5),
            "a clock that went backwards does not expire a zone"
        );
    }

    /// The default is what applies before any zone has arrived: ask soon, never
    /// expire, because there is nothing yet to withdraw.
    #[test]
    fn test_default_timers_cannot_expire() {
        let timers = RefreshTimers::default();
        assert!(!timers.has_expired(0, u64::MAX));
        assert_eq!(
            timers.after_success(),
            Duration::from_secs(DEFAULT_REFRESH_SECS)
        );
    }

    // The serial comparison this module used to own is now `Serial::is_newer_than`
    // in `lib.rs`, with its tests beside it — there were two implementations of
    // RFC 1982 §3.2 in this crate and the type is the one copy (`TODO.md` #14a).

    // -----------------------------------------------------------------
    // The sidecar
    // -----------------------------------------------------------------

    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!("rdns-secondary-{tag}-{unique}"));
            std::fs::create_dir_all(&dir).expect("scratch dir");
            ScratchDir(dir)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_state_survives_a_restart() {
        let dir = ScratchDir::new("state");
        let path = state_file_path(&dir.0);

        let mut state = StateFile::load(&path);
        assert!(state.entries().is_empty(), "nothing fetched yet");
        state
            .record(TransferState {
                zone: "example.com.".to_string(),
                serial: Serial::new(42),
                refreshed_at: 1_700_000_000,
                master: addr("192.0.2.1:53"),
            })
            .expect("record");

        // A fresh process reads it back.
        let reloaded = StateFile::load(&path);
        let entry = reloaded
            .get("example.com.", addr("192.0.2.1:53"))
            .expect("the entry is there");
        assert_eq!(entry.serial, Serial::new(42));
        assert_eq!(entry.refreshed_at, 1_700_000_000);

        // Keyed by both: the same zone from another master is another entry.
        assert!(reloaded.get("example.com.", addr("192.0.2.2:53")).is_none());
        assert!(reloaded.get("other.test.", addr("192.0.2.1:53")).is_none());
    }

    #[test]
    fn test_recording_the_same_zone_twice_updates_it() {
        let dir = ScratchDir::new("update");
        let path = state_file_path(&dir.0);
        let master = addr("192.0.2.1:53");

        let mut state = StateFile::load(&path);
        for serial in [1u32, 2, 3] {
            state
                .record(TransferState {
                    zone: "example.com.".to_string(),
                    serial: Serial::new(serial),
                    refreshed_at: 1_700_000_000 + serial as u64,
                    master,
                })
                .expect("record");
        }

        let reloaded = StateFile::load(&path);
        assert_eq!(reloaded.entries().len(), 1, "one line, not three");
        assert_eq!(
            reloaded.get("example.com.", master).unwrap().serial,
            Serial::new(3)
        );
    }

    /// An expired zone's entry is *kept*, because it is the record of when
    /// contact was last made — and that is what makes expiry survive a restart.
    /// Deleting it would read as "never fetched", which means "fetch", which
    /// means serving the stale copy again until the next failure.
    #[test]
    fn test_expiry_is_derived_from_the_state_rather_than_stored() {
        let dir = ScratchDir::new("expiry");
        let path = state_file_path(&dir.0);
        let master = addr("192.0.2.1:53");
        let timers = RefreshTimers::from_soa(3600, 600, 86400);

        let mut state = StateFile::load(&path);
        state
            .record(TransferState {
                zone: "example.com.".to_string(),
                serial: Serial::new(1),
                refreshed_at: 1_000_000,
                master,
            })
            .expect("record");

        let after_restart = StateFile::load(&path);
        let entry = after_restart.get("example.com.", master).unwrap();
        assert!(
            timers.has_expired(entry.refreshed_at, 1_000_000 + 86_401),
            "a restart a day later still knows the zone is out of contact"
        );
    }

    /// Nothing here is worth failing to start over: the only cost of forgetting
    /// is a refresh, and refusing to run because a scratch file went bad would
    /// make it a single point of failure.
    #[test]
    fn test_a_damaged_state_file_degrades_to_knowing_nothing() {
        let dir = ScratchDir::new("damaged");
        let path = state_file_path(&dir.0);
        std::fs::write(
            &path,
            "# a comment\n\
             \n\
             example.com. 42 1700000000 192.0.2.1:53\n\
             this line is nonsense\n\
             broken.test. notaserial 1 192.0.2.1:53\n\
             good.test. 7 1700000000 192.0.2.2:53\n",
        )
        .expect("seed");

        let state = StateFile::load(&path);
        assert_eq!(state.entries().len(), 2, "the readable lines survive");
        assert_eq!(
            state
                .get("example.com.", addr("192.0.2.1:53"))
                .unwrap()
                .serial,
            Serial::new(42)
        );
        assert_eq!(
            state
                .get("good.test.", addr("192.0.2.2:53"))
                .unwrap()
                .serial,
            Serial::new(7)
        );

        // And a file that is not there at all is the same thing: fetch.
        assert!(StateFile::load(&dir.0.join("no-such-file"))
            .entries()
            .is_empty());
    }

    #[test]
    fn test_where_the_files_go() {
        let dir = Path::new("/var/db");
        assert_eq!(
            zone_file_path(dir, "example.com"),
            Path::new("/var/db/example.com.zone"),
            "the name is the origin, so the ordinary load path reads it back"
        );
        assert_eq!(
            zone_file_path(dir, "example.com."),
            Path::new("/var/db/example.com.zone"),
            "given absolute or not"
        );
        assert_eq!(state_file_path(dir), Path::new("/var/db/rdnsd.state"));
    }
}
