//! A catalog zone generated from the zones this server is primary for
//! (RFC 9432, `TODO.md` #182), so a zone file dropped into `--zone-dir` is
//! provisioned on every consuming secondary with no second edit. The other
//! half of `catalog`, which consumes one.
//!
//! The zone itself is `rdns::catalog::generate`'s; here is what it is built
//! from, and when its serial moves.
//!
//! - Members: every zone this server is primary for, minus the catalog
//!   itself and any zone whose `[zones.*]` says `catalog-member = false`.
//!   Opt-out rather than Knot's and PowerDNS's opt-in, because zones arrive
//!   here as files with no configuration entry. Never a secondary zone.
//! - Rebuilt after every reload, from the same all-or-nothing load: a
//!   directory that cannot be read fails the reload and the catalog keeps
//!   its members, rather than §6's empty catalog taking every member off
//!   every consumer.
//! - The serial moves on a membership change and only then.

use std::collections::HashSet;
use std::sync::{Mutex, PoisonError};

use anyhow::{bail, Result};
use rdns::zone::Zone;
use rdns::{Name, NameRef, Serial};

pub(crate) struct GeneratedCatalog {
    name: Name,
    /// `catalog-member = false`.
    excluded: HashSet<Name>,
    /// The last members published, and the serial they went out under.
    last: Mutex<Option<(HashSet<Name>, Serial)>>,
}

impl GeneratedCatalog {
    pub(crate) fn new(name: Name, excluded: HashSet<Name>) -> GeneratedCatalog {
        GeneratedCatalog {
            name,
            excluded,
            last: Mutex::new(None),
        }
    }

    pub(crate) fn name(&self) -> &Name {
        &self.name
    }

    /// Whether `name` is at or under the catalog: what ordinary queries are
    /// refused for.
    pub(crate) fn covers(&self, name: NameRef<'_>) -> bool {
        name.is_at_or_under(self.name.as_ref())
    }

    /// The catalog listing the primary zones among `zones` at `now`.
    pub(crate) fn build<'a>(
        &self,
        zones: impl Iterator<Item = NameRef<'a>>,
        is_secondary: impl Fn(NameRef<'_>) -> bool,
        now: u64,
    ) -> Result<Zone> {
        let members: HashSet<Name> = zones
            .filter(|z| !self.covers(*z) && !is_secondary(*z))
            .map(|z| z.to_owned())
            .filter(|z| !self.excluded.contains(z))
            .collect();
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let serial = match last.as_ref() {
            Some((before, serial)) if *before == members => *serial,
            Some((before, serial)) => {
                for gone in before.difference(&members) {
                    tracing::warn!(
                        catalog = %self.name,
                        "{gone} left the generated catalog: every consumer will stop serving it"
                    );
                }
                for added in members.difference(before) {
                    tracing::info!(catalog = %self.name, "{added} joined the generated catalog");
                }
                next_serial(*serial, now)
            }
            None => Serial::new(now as u32),
        };
        let mut list: Vec<Name> = members.iter().cloned().collect();
        list.sort_by_cached_key(|n| rdns::denial_wire::canonical_sort_key(n.as_ref()));
        let zone = rdns::catalog::generate(self.name.as_ref(), &list, serial)?;
        *last = Some((members, serial));
        Ok(zone)
    }
}

/// The wall clock in seconds when it is ahead of `previous`, else one more.
///
/// Not `signed_serial`'s hours: two membership changes within an hour would
/// share a serial, and a consumer that saw the first would never fetch the
/// second. Seconds since the epoch fit until 2106 and run ahead of any serial
/// this produced before a restart.
fn next_serial(previous: Serial, now: u64) -> Serial {
    let clock = Serial::new(now as u32);
    if clock.is_newer_than(previous) {
        clock
    } else {
        previous.wrapping_add(1)
    }
}

/// §6: "a catalog producer MUST NOT use names that are not under the control
/// of the catalog producer (with the exception of reserved names)". As far as
/// code can check that: at or under `invalid.`, or strictly under a zone this
/// server is primary for.
pub(crate) fn check_name<'a>(
    name: &Name,
    mut primaries: impl Iterator<Item = NameRef<'a>>,
) -> Result<()> {
    let invalid = Name::from_presentation("invalid.").expect("a literal name");
    if name.as_ref().is_at_or_under(invalid.as_ref()) {
        return Ok(());
    }
    if primaries.any(|zone| name.as_ref().is_at_or_under(zone) && name.as_ref() != zone) {
        return Ok(());
    }
    bail!(
        "--generate-catalog {name}: a catalog's name must be under invalid. or strictly under a \
         zone this server is primary for (RFC 9432 §6)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::nm;
    use rdns::catalog::Catalog;

    fn names(list: &[&str]) -> Vec<Name> {
        list.iter().map(|n| nm(n)).collect()
    }

    fn members(zone: &Zone) -> Vec<String> {
        let catalog = Catalog::from_zone(zone).expect("a well-formed catalog");
        let mut m: Vec<String> = catalog
            .members()
            .iter()
            .map(|m| m.zone().to_string())
            .collect();
        m.sort();
        m
    }

    fn labels(zone: &Zone) -> Vec<(String, String)> {
        let catalog = Catalog::from_zone(zone).expect("a well-formed catalog");
        let mut l: Vec<(String, String)> = catalog
            .members()
            .iter()
            .map(|m| (m.zone().to_string(), m.node().to_string()))
            .collect();
        l.sort();
        l
    }

    /// Three zones, the catalog read back by the consumer's own parser; a
    /// fourth moves the serial and keeps the first three labels; nothing
    /// changed keeps the serial; one removed is one fewer.
    #[test]
    fn the_catalog_follows_the_primary_zones() {
        let generator = GeneratedCatalog::new(nm("catalog.invalid."), HashSet::new());
        let three = names(&["a.test.", "b.test.", "c.test.", "catalog.invalid."]);
        let first = generator
            .build(three.iter().map(|n| n.as_ref()), |_| false, 1_000)
            .expect("builds");
        assert_eq!(members(&first), ["a.test.", "b.test.", "c.test."]);

        let four = names(&["a.test.", "b.test.", "c.test.", "d.test."]);
        let second = generator
            .build(four.iter().map(|n| n.as_ref()), |_| false, 1_000)
            .expect("builds");
        assert!(second
            .serial()
            .unwrap()
            .is_newer_than(first.serial().unwrap()));
        assert_eq!(members(&second).len(), 4);
        let before = labels(&first);
        assert!(
            before.iter().all(|l| labels(&second).contains(l)),
            "labels kept"
        );

        let same = generator
            .build(four.iter().map(|n| n.as_ref()), |_| false, 9_999)
            .expect("builds");
        assert_eq!(
            same.serial(),
            second.serial(),
            "nothing changed, no new serial"
        );

        let fewer = generator
            .build(four[..3].iter().map(|n| n.as_ref()), |_| false, 10_000)
            .expect("builds");
        assert_eq!(members(&fewer).len(), 3);
        assert!(fewer
            .serial()
            .unwrap()
            .is_newer_than(same.serial().unwrap()));
    }

    #[test]
    fn opted_out_and_secondary_zones_are_not_members() {
        let generator =
            GeneratedCatalog::new(nm("catalog.invalid."), HashSet::from([nm("private.test.")]));
        let zones = names(&["a.test.", "private.test.", "replica.test."]);
        let zone = generator
            .build(
                zones.iter().map(|n| n.as_ref()),
                |z| z == nm("replica.test.").as_ref(),
                1,
            )
            .expect("builds");
        assert_eq!(members(&zone), ["a.test."]);
    }

    /// No state behind the labels: two generators, as across a restart,
    /// give every member the same node.
    #[test]
    fn labels_survive_a_restart() {
        let zones = names(&["a.test.", "b.test."]);
        let build = || {
            GeneratedCatalog::new(nm("catalog.invalid."), HashSet::new())
                .build(zones.iter().map(|n| n.as_ref()), |_| false, 1)
                .expect("builds")
        };
        assert_eq!(labels(&build()), labels(&build()));
    }

    #[test]
    fn the_name_is_reserved_or_ours() {
        let primaries = names(&["example.com."]);
        let ours = |n: &str| check_name(&nm(n), primaries.iter().map(|z| z.as_ref()));
        assert!(ours("catalog.invalid.").is_ok());
        assert!(ours("cat.example.com.").is_ok());
        assert!(
            ours("example.com.").is_err(),
            "the zone itself is not under it"
        );
        assert!(ours("catalog.example.net.").is_err());
    }

    #[test]
    fn two_changes_in_one_second_still_move_the_serial() {
        let s = next_serial(Serial::new(5_000), 5_000);
        assert_eq!(s, Serial::new(5_001));
        assert_eq!(next_serial(Serial::new(5_000), 6_000), Serial::new(6_000));
    }
}
