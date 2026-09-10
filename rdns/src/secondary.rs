//! Being a replica of somebody else's zone: what to fetch, when, and what to
//! remember between restarts.
//!
//! [`crate::xfr`] obtains a zone; this decides when it is due, when it has gone
//! stale, and what survives a restart. Split so the timing rules — the half with
//! no I/O and every edge case — are testable by moving a clock.
//!
//! Replication is single-writer, asynchronous and pull-based. A secondary is
//! read-only and never resolves a conflict because it never accepts a write. A
//! NOTIFY only shortens the wait, so losing one costs a delay and nothing else.
//!
//! EXPIRE is the timer with teeth: past it, a secondary must stop serving rather
//! than keep handing out arbitrarily stale data with AA set (RFC 1035 §3.3.13,
//! RFC 1912 §2.2).

use crate::error::{ConfigError, ConfigResult};
use crate::Qtype;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::record_types as rt;
use crate::zone::Zone;
use crate::{Name, ParsedRecord, Serial};

/// The floor under REFRESH and RETRY. A SOA saying "refresh every 0 seconds" is
/// otherwise a loop asking the master as fast as the network allows; the RFCs
/// set no floor, every implementation does.
const MIN_TIMER_SECS: u64 = 60;

/// Before the zone's SOA has been seen, there are no timers of its own to obey.
const DEFAULT_REFRESH_SECS: u64 = 3600;

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
            // A zone never reached cannot expire: there is nothing to withdraw.
            expire: u64::MAX,
        }
    }
}

impl RefreshTimers {
    /// The timers in a zone's apex SOA, clamped to something a server can obey.
    ///
    /// Clamped rather than rejected: a secondary refusing a zone because its
    /// master wrote `retry 0` turns a cosmetic mistake into an outage.
    pub fn from_soa(refresh: i32, retry: i32, expire: i32) -> Self {
        let floor = |value: i32| (value.max(0) as u64).max(MIN_TIMER_SECS);
        RefreshTimers {
            refresh: floor(refresh),
            retry: floor(retry),
            // No floor on EXPIRE: it limits staleness, and raising a small one
            // keeps a zone alive longer than its operator said to.
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

    /// Measured from when the master last *answered*, not when the zone last
    /// changed: a zone unchanged for a year is not stale.
    pub fn has_expired(&self, last_contact: u64, now: u64) -> bool {
        now.saturating_sub(last_contact) > self.expire
    }
}

/// One zone to replicate, and where from: `zone@master[:port][#keyname]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterSpec {
    /// The zone's apex. Parsed here, at the one place the flag's text
    /// becomes a name, so a bad `--secondary` is a startup error rather than a
    /// zone that silently never matches.
    pub zone: Name,
    pub master: SocketAddr,
    /// By name, looked up in the keys `--tsig-key` defines, so a secret is
    /// written down in one place.
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
            zone: Name::from_presentation(zone).map_err(|e| {
                ConfigError::new(format!("{spec:?}: {zone:?} is not a domain name: {e}"))
            })?,
            master: parse_address(master, spec)?,
            key_name,
        })
    }
}

/// `addr` or `addr:port`, defaulting to 53. A bare IPv6 address has colons, so
/// `[::1]:5353` is the only unambiguous way to give one a port — which is what
/// `SocketAddr` already parses.
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

/// [`crate::text_names::absolute`], owned: this module's callers all keep the result.
fn absolute(name: &str) -> String {
    crate::text_names::absolute(name).into_owned()
}

// The state sidecar

/// What is known about one replicated zone between restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferState {
    pub zone: String,
    /// The serial of the copy on disk.
    pub serial: Serial,
    /// When the master last answered. The EXPIRE clock runs from here.
    pub refreshed_at: u64,
    pub master: SocketAddr,
}

/// The sidecar file: one line per replicated zone.
///
/// Not the zone file's mtime, which is what BIND uses: an unrelated touch resets
/// the refresh clock, and a copy preserves a timestamp describing the wrong
/// event. Text, because it is a few hundred bytes a person may need to read or
/// delete while a server is down.
pub struct StateFile {
    path: PathBuf,
    entries: Vec<TransferState>,
}

impl StateFile {
    /// Read the sidecar, or start empty.
    ///
    /// Never fails: the only cost of forgetting is fetching again, and refusing
    /// to start over a corrupt cache of something re-obtainable makes a scratch
    /// file a single point of failure. Unparseable lines are skipped and logged;
    /// survivable is not the same as unremarkable.
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
    /// Written whole and atomically, never appended to: a reader must not see a
    /// line half-updated. A caller holding a lock or on an async runtime wants
    /// [`StateFile::set`] instead — the write is the expensive half.
    pub fn record(&mut self, state: TransferState) -> ConfigResult<()> {
        self.set(state);
        let (path, text) = self.snapshot();
        write_snapshot(&path, &text)
    }

    /// Update what is known, writing nothing.
    ///
    /// The write ends in an fsync of the file *and* its directory, and `rdnsd`
    /// reaches this through an `Arc<Mutex<StateFile>>` from an async task —
    /// writing here would hold a `std::sync::Mutex` across that fsync on a
    /// worker also answering queries. The caller updates under the guard, takes
    /// a [`StateFile::snapshot`], drops the guard, and writes.
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

    /// The path and the exact contents [`StateFile::record`] would write, owned
    /// so they outlive the guard they were taken under.
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

/// Write a snapshot taken by [`StateFile::snapshot`]. Free-standing because by
/// now the caller has let go of the `StateFile` and its lock.
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

/// Where a replicated zone's file goes. The name is the origin, which is how
/// `rdnsd` decides what a zone file is a zone *of*, so a fetched zone loads by
/// the ordinary path on the next start.
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
    use crate::test_records::nm;
    use crate::testutil::ScratchDir;
    use crate::zone::parse_zone_file;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("test address")
    }

    #[test]
    fn test_master_spec_parses() {
        assert_eq!(
            MasterSpec::parse("example.com@192.0.2.1").unwrap(),
            MasterSpec {
                zone: nm("example.com."),
                master: addr("192.0.2.1:53"),
                key_name: None,
            },
            "the zone is made absolute and the port defaults to 53"
        );
        assert_eq!(
            MasterSpec::parse("example.com.@192.0.2.1:5353#transfer.key.").unwrap(),
            MasterSpec {
                zone: nm("example.com."),
                master: addr("192.0.2.1:5353"),
                key_name: Some("transfer.key.".to_string()),
            }
        );
    }

    /// Only the bracketed form can carry a port; the bare one must still work.
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

    /// Before any zone has arrived: ask soon, never expire.
    #[test]
    fn test_default_timers_cannot_expire() {
        let timers = RefreshTimers::default();
        assert!(!timers.has_expired(0, u64::MAX));
        assert_eq!(
            timers.after_success(),
            Duration::from_secs(DEFAULT_REFRESH_SECS)
        );
    }

    #[test]
    fn test_state_survives_a_restart() {
        let dir = ScratchDir::new("secondary-state");
        let path = state_file_path(dir.path());

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
        let dir = ScratchDir::new("secondary-update");
        let path = state_file_path(dir.path());
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

    /// An expired zone's entry is kept: it records when contact was last made,
    /// and deleting it reads as "never fetched", which means "fetch and serve".
    #[test]
    fn test_expiry_is_derived_from_the_state_rather_than_stored() {
        let dir = ScratchDir::new("secondary-expiry");
        let path = state_file_path(dir.path());
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

    #[test]
    fn test_a_damaged_state_file_degrades_to_knowing_nothing() {
        let dir = ScratchDir::new("secondary-damaged");
        let path = state_file_path(dir.path());
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

        // A file that is not there at all is the same thing: fetch.
        assert!(StateFile::load(&dir.join("no-such-file"))
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
