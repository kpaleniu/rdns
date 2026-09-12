//! Catalog zones (RFC 9432): reading the list of zones a server is to serve out
//! of a zone that carries it.
//!
//! The catalog is an ordinary DNS zone — transferred, stored and served like any
//! other (§5.1) — so everything up to here is machinery that already exists.
//! This module is only the meaning: which member zones the catalog lists, under
//! which node label, and what the two member properties this build implements
//! say about them.
//!
//! What a *consumer* does with that — provisioning, removal, the clash and
//! ownership rules of §5 — is `rdnsd`'s, because it is about the zones one
//! process holds rather than about the catalog's contents.
//!
//! A catalog that breaks the rules of §4 is "broken", and §5.1 is specific:
//! it loses its catalog meaning, and member zones previously configured from it
//! "MUST NOT be removed or reconfigured in any way". So [`Catalog::from_zone`]
//! returns [`BrokenCatalog`] rather than a best-effort member list — a partial
//! list is exactly the shape that would reconfigure something.

use std::collections::BTreeMap;

use crate::error::{BrokenCatalog, WireError};
use crate::record_types as rt;
use crate::zone::{Zone, ZoneRecord};
use crate::{Name, NameRef, ParsedRecord};

/// The schema version this build implements (§4.2.1). Version "1" was the draft
/// BIND 9.11 shipped, and §4.2.1 makes a version we do not implement one of the
/// conditions that break a catalog, so it is refused rather than guessed at.
const SCHEMA_VERSION: &[u8] = b"2";

/// The global property naming the member list (§4.1).
const ZONES: &[u8] = b"zones";
/// The global property carrying the schema version (§4.2.1).
const VERSION: &[u8] = b"version";
/// The member property naming a new catalog for a zone (§4.3.1).
const COO: &[u8] = b"coo";
/// The member property tagging a member for differing treatment (§4.3.2).
const GROUP: &[u8] = b"group";

/// The member zones a catalog lists.
///
/// Built by [`Catalog::from_zone`] alone, so a `Catalog` in hand is one that
/// passed every check §4 states; there is no way to add a member to one.
#[derive(Debug, Clone)]
pub struct Catalog {
    members: Vec<CatalogMember>,
}

/// One member node: the zone it names, and the properties under it.
#[derive(Debug, Clone)]
pub struct CatalogMember {
    node: Name,
    zone: Name,
    groups: Vec<Vec<u8>>,
    coo: Option<Name>,
}

impl CatalogMember {
    /// The member node, `<unique-N>.zones.$CATZ`.
    pub fn node(&self) -> NameRef<'_> {
        self.node.as_ref()
    }

    /// The `<unique-N>` label alone.
    ///
    /// The label is the member's identity rather than decoration: §5.4 makes a
    /// changed label a removal followed by a re-add, state and all, and §4.3.1
    /// makes an *unchanged* one across two catalogs the thing that carries that
    /// state through a migration. A consumer has to store it, so it is reachable
    /// without taking [`CatalogMember::node`] apart again.
    pub fn id(&self) -> &[u8] {
        // `from_zone` matched this name as `<unique>.zones.$CATZ` before
        // building the member, so there is a first label.
        self.node.as_ref().labels().next().unwrap_or(b"")
    }

    /// The zone this node names: the PTR's target (§4.1).
    pub fn zone(&self) -> NameRef<'_> {
        self.zone.as_ref()
    }

    /// The group values (§4.3.2), each one TXT record's whole RDATA.
    ///
    /// Octets rather than `String`, for the reason [`ParsedRecord::TXT`] holds
    /// bytes: a character-string is arbitrary octets, and a lossy conversion
    /// merges two group values that differ. A consumer matching these against
    /// operator configuration compares bytes.
    ///
    /// More than one is legal and means whatever producer and consumer agreed
    /// (§4.3.2: "The producer MAY assign more than one group property to one
    /// member zone").
    pub fn groups(&self) -> &[Vec<u8>] {
        &self.groups
    }

    /// The catalog this member is being handed to, if the producer has begun a
    /// change of ownership (§4.3.1).
    ///
    /// Not an instruction to migrate now: §4.3.1 makes the migration wait until
    /// the *new* catalog lists the zone, and requires this property still to be
    /// present when it does.
    pub fn coo(&self) -> Option<NameRef<'_>> {
        self.coo.as_ref().map(Name::as_ref)
    }
}

impl Catalog {
    /// Read a zone as a catalog, or say why it is not one.
    ///
    /// Every error is a condition RFC 9432 names as breaking the catalog:
    /// §4.2.1 for the version property, §4.1 for the member nodes, §4.3.1 for
    /// `coo`. Records this build has no processing for are ignored rather than
    /// refused — §3 requires that, and it is what lets a producer publish
    /// properties and custom `*.ext` nodes (§4.4) an older consumer has never
    /// heard of.
    ///
    /// The TTL and the class are not checked. §4.1 says the TTL "has no meaning
    /// in this context and SHOULD be ignored", and the class cannot be anything
    /// but IN because [`crate::zone::parse_zone_file`] refuses a record of
    /// another class outright.
    pub fn from_zone(zone: &Zone) -> Result<Catalog, BrokenCatalog> {
        let origin = zone.origin();
        let depth = origin.label_count();
        // One entry per RR, so §4.2.1's "exactly one RR in the RRset" is a
        // length rather than a flag something has to remember to set.
        let mut version: Vec<Vec<u8>> = Vec::new();
        // Keyed on the folded `<unique-N>` label (RFC 4343), so a property
        // written in another case lands on the node it names.
        let mut nodes: BTreeMap<Vec<u8>, Node> = BTreeMap::new();

        for record in zone.records() {
            let name = record.name.as_ref();
            if !name.is_at_or_under(origin) {
                continue;
            }
            let below = name.label_count() - depth;
            // Nothing processed here is deeper than
            // `<property>.<unique-N>.zones.$CATZ`. A custom property (§4.4) can
            // be, and is ignored by the same rule as anything else unrecognized.
            if below == 0 || below > 3 {
                continue;
            }
            let mut rel: [&[u8]; 3] = [b"", b"", b""];
            for (i, label) in name.labels().take(below).enumerate() {
                rel[i] = label;
            }
            let is = |label: &[u8], want: &[u8]| label.eq_ignore_ascii_case(want);

            match (below, record.rdata.rtype()) {
                (1, rt::TXT) if is(rel[0], VERSION) => version.push(text(record)?),
                (2, rt::PTR) if is(rel[1], ZONES) => nodes
                    .entry(folded(rel[0]))
                    .or_insert_with(|| Node::new(name))
                    .ptr
                    .push(target(record)?),
                (3, rt::TXT) if is(rel[2], ZONES) && is(rel[0], GROUP) => nodes
                    .entry(folded(rel[1]))
                    .or_insert_with(|| Node::new(node_of(name)))
                    .groups
                    .push(text(record)?),
                (3, rt::PTR) if is(rel[2], ZONES) && is(rel[0], COO) => nodes
                    .entry(folded(rel[1]))
                    .or_insert_with(|| Node::new(node_of(name)))
                    .coo
                    .push(target(record)?),
                _ => {}
            }
        }

        // First, because §4.2.1's conditions are about whether this is a
        // catalog at all: a zone with no version property is somebody else's
        // zone that happens to have a `zones` subtree.
        check_version(&version)?;

        let mut members: Vec<CatalogMember> = Vec::new();
        // §4.1's "different <unique-N> labels hold the same PTR value" check,
        // as a lookup: a scan per member would be quadratic in a catalog whose
        // whole point is holding thousands of them.
        let mut by_zone: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
        for (_, node) in nodes {
            // No PTR under the node: a `group` or `coo` property naming a
            // `<unique-N>` that is not a member. There is nothing to apply it
            // to, and §3 says to ignore what has no processing specified.
            let Some(member) = node.into_member()? else {
                continue;
            };
            match by_zone.entry(member.zone.as_ref().folded().into_owned()) {
                std::collections::btree_map::Entry::Occupied(first) => {
                    return Err(BrokenCatalog::DuplicateMember {
                        zone: member.zone,
                        first: members[*first.get()].node.clone(),
                        second: member.node,
                    })
                }
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(members.len());
                }
            }
            members.push(member);
        }

        Ok(Catalog { members })
    }

    pub fn members(&self) -> &[CatalogMember] {
        &self.members
    }

    /// The member naming this zone, if the catalog lists it.
    ///
    /// A scan: a consumer diffing a whole catalog iterates [`Catalog::members`]
    /// and builds its own index, and this is for the handful of one-off
    /// questions — "does the catalog still list it" — around that.
    pub fn member(&self, zone: NameRef<'_>) -> Option<&CatalogMember> {
        self.members.iter().find(|m| m.zone.as_ref() == zone)
    }
}

/// §4.2.1's four conditions, in its order.
fn check_version(version: &[Vec<u8>]) -> Result<(), BrokenCatalog> {
    match version {
        [] => Err(BrokenCatalog::NoVersion),
        [only] if only == SCHEMA_VERSION => Ok(()),
        [only] => Err(BrokenCatalog::Version(
            String::from_utf8_lossy(only).into_owned(),
        )),
        several => Err(BrokenCatalog::VersionRrset(several.len())),
    }
}

/// A member node under construction: the RRs seen so far, uncounted.
///
/// Collected rather than folded into one value as they arrive, because "the
/// RRset holds more than one record" — which §4.1 and §4.3.1 both make an error
/// — cannot be asked of a field that kept only the last one.
struct Node {
    name: Name,
    ptr: Vec<Name>,
    groups: Vec<Vec<u8>>,
    coo: Vec<Name>,
}

impl Node {
    fn new(name: NameRef<'_>) -> Node {
        Node {
            name: name.to_owned(),
            ptr: Vec::new(),
            groups: Vec::new(),
            coo: Vec::new(),
        }
    }

    fn into_member(self) -> Result<Option<CatalogMember>, BrokenCatalog> {
        let Node {
            name,
            ptr,
            groups,
            coo,
        } = self;
        // §4.1: "This PTR record MUST be the only record in the PTR RRset with
        // the same name. The presence of more than one record in the RRset
        // indicates a broken catalog zone."
        let mut ptr = ptr.into_iter();
        let zone = match (ptr.next(), ptr.len()) {
            (None, _) => return Ok(None),
            (Some(zone), 0) => zone,
            (Some(_), rest) => {
                return Err(BrokenCatalog::MemberRrset {
                    node: name,
                    records: rest + 1,
                })
            }
        };
        // §4.3.1: "The PTR RRset MUST consist of a single PTR record."
        let mut coo = coo.into_iter();
        let coo = match (coo.next(), coo.len()) {
            (None, _) => None,
            (Some(catalog), 0) => Some(catalog),
            (Some(_), rest) => {
                return Err(BrokenCatalog::CooRrset {
                    node: name,
                    records: rest + 1,
                })
            }
        };
        Ok(Some(CatalogMember {
            node: name,
            zone,
            groups,
            coo,
        }))
    }
}

/// The member node a property RR at `<property>.<unique-N>.zones.$CATZ` belongs
/// to.
fn node_of(property: NameRef<'_>) -> NameRef<'_> {
    // The caller matched a three-label suffix, so there is a parent; `unwrap_or`
    // rather than `expect` because this is reached from a transferred zone and a
    // parser that panics on what a peer sent is `CLAUDE.md` §2's rule.
    property.parent().unwrap_or(property)
}

/// A PTR's target.
fn target(record: &ZoneRecord) -> Result<Name, BrokenCatalog> {
    match record.rdata.parse() {
        Ok(ParsedRecord::PTR(name)) => Ok(name),
        // `RecordData::parse` dispatches on the same rtype this was matched on,
        // so the second arm is unreachable — and is two lines rather than an
        // `unreachable!`, for the reason `node_of` gives.
        Ok(_) => Err(undecodable(
            record,
            WireError::malformed("PTR", "the RDATA is not a domain name"),
        )),
        Err(source) => Err(undecodable(record, source)),
    }
}

/// A TXT record's whole RDATA, its character-strings joined.
///
/// Joined because §4.2.1 and §4.3.2 both speak of the value of the *record*
/// rather than of a string within it, and §4.3.2's own example writes one group
/// value as two strings (`"operator-y" "bar"`).
fn text(record: &ZoneRecord) -> Result<Vec<u8>, BrokenCatalog> {
    match record.rdata.parse() {
        Ok(ParsedRecord::TXT(strings)) => Ok(strings.concat()),
        Ok(_) => Err(undecodable(
            record,
            WireError::malformed("TXT", "the RDATA is not character-strings"),
        )),
        Err(source) => Err(undecodable(record, source)),
    }
}

fn undecodable(record: &ZoneRecord, source: WireError) -> BrokenCatalog {
    BrokenCatalog::Undecodable {
        name: record.name.clone(),
        source,
    }
}

fn folded(label: &[u8]) -> Vec<u8> {
    label.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_records::nm;
    use crate::zone::parse_zone_file;

    /// RFC 9432 Appendix A, "a full example of a catalog zone containing three
    /// member zones with various properties", copied out with its parentheses
    /// and only the indentation removed: a leading blank in a zone file means
    /// "the owner name of the record before", which would put every record here
    /// at the apex.
    const APPENDIX_A: &str = r#"
catalog.invalid.                                0  SOA   invalid. (
                        invalid. 1625079950 3600 600 2147483646 0 )
catalog.invalid.                                0  NS    invalid.
example.vendor.ext.catalog.invalid.             0  CNAME example.net.
version.catalog.invalid.                        0  TXT   "2"
nj2xg5b.zones.catalog.invalid.                  0  PTR   example.com.
nvxxezj.zones.catalog.invalid.                  0  PTR   example.net.
group.nvxxezj.zones.catalog.invalid.            0  TXT   (
                        "operator-x-foo" )
nfwxa33.zones.catalog.invalid.                  0  PTR   example.org.
coo.nfwxa33.zones.catalog.invalid.              0  PTR   (
                        newcatz.invalid. )
group.nfwxa33.zones.catalog.invalid.            0  TXT   (
                        "operator-y-bar" )
metrics.vendor.ext.nfwxa33.zones.catalog.invalid. 0  CNAME (
                        collector.example.net. )
"#;

    fn catalog(text: &str) -> Result<Catalog, BrokenCatalog> {
        let zone = parse_zone_file(text, "catalog.invalid.").expect("the zone itself parses");
        Catalog::from_zone(&zone)
    }

    /// A correct catalog with nothing in it, to which a test adds what it is
    /// about.
    fn with(extra: &str) -> String {
        format!(
            "catalog.invalid. 0 SOA invalid. invalid. 1 3600 600 2147483646 0\n\
             catalog.invalid. 0 NS invalid.\n\
             version.catalog.invalid. 0 TXT \"2\"\n\
             {extra}"
        )
    }

    /// The same, without the version property, for the tests about its absence.
    fn unversioned(extra: &str) -> String {
        format!(
            "catalog.invalid. 0 SOA invalid. invalid. 1 3600 600 2147483646 0\n\
             catalog.invalid. 0 NS invalid.\n\
             {extra}"
        )
    }

    #[test]
    fn the_rfcs_own_example_reads_as_three_members() {
        let catalog = catalog(APPENDIX_A).expect("Appendix A is a correct catalog");
        let members: Vec<_> = catalog
            .members()
            .iter()
            .map(|m| m.zone().to_owned())
            .collect();
        assert_eq!(
            members,
            // Ordered by node label: nfwxa33, nj2xg5b, nvxxezj.
            vec![nm("example.org."), nm("example.com."), nm("example.net.")]
        );

        let org = catalog
            .member(nm("example.org.").as_ref())
            .expect("example.org. is a member");
        assert_eq!(org.id(), b"nfwxa33");
        assert_eq!(org.node(), nm("nfwxa33.zones.catalog.invalid.").as_ref());
        assert_eq!(org.coo(), Some(nm("newcatz.invalid.").as_ref()));
        assert_eq!(org.groups(), [b"operator-y-bar".to_vec()]);

        let net = catalog
            .member(nm("example.net.").as_ref())
            .expect("example.net. is a member");
        assert_eq!(net.groups(), [b"operator-x-foo".to_vec()]);
        assert_eq!(net.coo(), None, "only one member is being handed over");

        let com = catalog
            .member(nm("example.com.").as_ref())
            .expect("example.com. is a member");
        assert!(
            com.groups().is_empty(),
            "§4.3 makes every member property optional"
        );
    }

    /// §3: "Catalog consumers MUST ignore any RRs in the catalog zone for which
    /// no processing is specified". Appendix A exercises it twice — a global
    /// `*.ext` custom property and a member-level one — and neither is an error
    /// nor a member.
    #[test]
    fn records_with_no_processing_specified_are_ignored() {
        let catalog = catalog(APPENDIX_A).expect("the ext records do not break it");
        assert_eq!(catalog.members().len(), 3);
        assert!(catalog
            .member(nm("example.vendor.ext.catalog.invalid.").as_ref())
            .is_none());
        assert!(catalog
            .member(nm("collector.example.net.").as_ref())
            .is_none());
    }

    /// §4.2.1's conditions, one at a time.
    #[test]
    fn a_catalog_without_a_usable_version_property_is_broken() {
        let none = unversioned("nj2xg5b.zones.catalog.invalid. 0 PTR example.com.\n");
        assert!(matches!(
            catalog(&none).unwrap_err(),
            BrokenCatalog::NoVersion
        ));

        let two = with("version.catalog.invalid. 0 TXT \"2\"\n");
        assert!(matches!(
            catalog(&two).unwrap_err(),
            BrokenCatalog::VersionRrset(2)
        ));

        // "(e.g., version \"1\")" — the draft schema BIND 9.11 shipped.
        let one = unversioned("version.catalog.invalid. 0 TXT \"1\"\n");
        assert!(matches!(
            catalog(&one).unwrap_err(),
            BrokenCatalog::Version(v) if v == "1"
        ));
    }

    /// §4.1: more than one PTR at a member node, and two nodes naming one zone.
    #[test]
    fn a_broken_member_list_is_refused_whole() {
        let two_ptrs = with(
            "nj2xg5b.zones.catalog.invalid. 0 PTR example.com.\n\
             nj2xg5b.zones.catalog.invalid. 0 PTR example.net.\n",
        );
        assert!(matches!(
            catalog(&two_ptrs).unwrap_err(),
            BrokenCatalog::MemberRrset { records: 2, node }
                if node == nm("nj2xg5b.zones.catalog.invalid.")
        ));

        let twice = with(
            "nj2xg5b.zones.catalog.invalid. 0 PTR example.com.\n\
             nvxxezj.zones.catalog.invalid. 0 PTR EXAMPLE.com.\n",
        );
        assert!(
            matches!(
                catalog(&twice).unwrap_err(),
                BrokenCatalog::DuplicateMember { .. }
            ),
            "one zone under two labels, and a difference of case is not a difference (RFC 4343)"
        );
    }

    /// §4.3.1: "The PTR RRset MUST consist of a single PTR record."
    #[test]
    fn two_coo_records_break_the_catalog() {
        let two = with(
            "nj2xg5b.zones.catalog.invalid. 0 PTR example.com.\n\
             coo.nj2xg5b.zones.catalog.invalid. 0 PTR newcatz.invalid.\n\
             coo.nj2xg5b.zones.catalog.invalid. 0 PTR othercatz.invalid.\n",
        );
        assert!(matches!(
            catalog(&two).unwrap_err(),
            BrokenCatalog::CooRrset { records: 2, .. }
        ));
    }

    /// A property naming a `<unique-N>` with no PTR under it is not a member and
    /// not an error: there is nothing for it to apply to.
    #[test]
    fn a_property_without_a_member_node_is_not_a_member() {
        let orphan = with("group.nj2xg5b.zones.catalog.invalid. 0 TXT \"operator-x\"\n");
        assert!(catalog(&orphan).expect("not broken").members().is_empty());
    }

    /// Every label matched here is matched case-insensitively, because the wire
    /// is (RFC 4343): a producer writing `ZONES` or `Version` means the
    /// property, not some other name.
    #[test]
    fn property_labels_fold_ascii_case() {
        let shouted = unversioned(
            "VERSION.catalog.invalid. 0 TXT \"2\"\n\
             nj2xg5b.ZONES.catalog.invalid. 0 PTR example.com.\n\
             GROUP.NJ2XG5B.zones.catalog.invalid. 0 TXT \"operator-x\"\n",
        );
        let catalog = catalog(&shouted).expect("case is not a difference");
        let member = catalog
            .member(nm("example.com.").as_ref())
            .expect("the member is found whatever case its labels were written in");
        assert_eq!(member.groups(), [b"operator-x".to_vec()]);
    }

    /// §4.3.2's own example writes one group value as two character-strings.
    /// The value is "the entire RDATA of a TXT record", so it is one value.
    #[test]
    fn a_group_value_is_the_whole_rdata() {
        let split = with(
            "nj2xg5b.zones.catalog.invalid. 0 PTR example.com.\n\
             group.nj2xg5b.zones.catalog.invalid. 0 TXT \"operator-y\" \"bar\"\n",
        );
        let catalog = catalog(&split).expect("not broken");
        assert_eq!(
            catalog.members()[0].groups(),
            [b"operator-ybar".to_vec()],
            "two strings, one group value"
        );
    }
}
