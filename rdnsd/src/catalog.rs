//! Consuming catalog zones (RFC 9432): provisioning the zones a catalog lists.
//!
//! The catalog itself is an ordinary replicated zone — a `--catalog` spec is a
//! `--secondary` spec that is also read as a member list — so the transfer, the
//! timers, the NOTIFY and the file on disk are [`crate::replication`]'s and are
//! not repeated here. What is here is §5: turning the member list into refresh
//! tasks, and turning its absences into removals.
//!
//! [`rdns::catalog`] does the reading and answers "what does this zone say".
//! This answers "what should this process now hold", which needs three things
//! the catalog does not contain: which zones the operator configured by hand,
//! which zones *this* catalog provisioned last time, and under which node label
//! it did so. The last two are the sidecar, because §5.3 makes removal
//! conditional on having provisioned the zone from the same catalog and §5.4
//! makes a changed label a removal — neither question can be answered from the
//! catalog alone, and forgetting the answer serves a withdrawn zone with AA set
//! (`CLAUDE.md` §4).
//!
//! Readiness deliberately does not wait for members. `/readyz` waits for the
//! zones the configuration names, the catalog among them; a consumer that
//! waited for every member would report not-ready for as long as a cold start
//! takes to transfer a producer's whole list, which for the fleet this feature
//! exists for is the entire point of it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::Mutex;

use rdns::catalog::{Catalog, CatalogMember};
use rdns::name_keys::NameKeyBuf;
use rdns::secondary::{write_snapshot, zone_file_path, MasterSpec};
use rdns::shutdown::Lifecycle;
use rdns::tsig::{TsigKey, TsigKeyring};
use rdns::{Name, NameRef, Serial};

use crate::replication::{
    resolve_key, spawn_secondary, withdraw, withdraw_unvouched_zones, ReplicationContext,
    Secondaries,
};

/// One catalog this server consumes, and how its members are fetched.
///
/// Members inherit the catalog's master and key. RFC 9432 §7 is why the key is
/// inherited rather than named in the catalog: "TSIG shared secrets used for
/// member zones SHOULD NOT be mentioned in the catalog zone data", so the only
/// key a consumer can use for a member is one it was already configured with.
struct CatalogSpec {
    /// The catalog zone as `--catalog` named it. Kept whole rather than
    /// unpacked into three fields, because a member inherits it whole: the
    /// unpacked copy is what silently drops a field added later, and the field
    /// added later was `tls` (`TODO.md` #44d, `CLAUDE.md` §7).
    spec: MasterSpec,
    /// Resolved once at startup, so a member added at three in the morning
    /// cannot fail on a key name that was already known to be missing.
    key: Option<TsigKey>,
    /// Group values that fetch a member from somewhere else (§4.3.2), in the
    /// order the config file wrote them.
    ///
    /// Empty for a catalog with no `[zones."…".groups."…"]` table, which is
    /// every fleet with one class of member zone.
    groups: Vec<GroupMaster>,
}

/// One group value, and where a member carrying it is fetched from.
///
/// §4.3.2 leaves "the exact handling of the group property value ... to the
/// consumer's implementation and configuration", and this is that configuration:
/// a group selects masters and a key, which is the only part of "how to treat
/// this member" a consumer of somebody else's zone actually decides.
struct GroupMaster {
    /// The value as it appears in the catalog: octets, because a TXT record's
    /// character-string is arbitrary octets and a lossy conversion merges two
    /// values that differ.
    value: Vec<u8>,
    /// The config key as the operator wrote it, for the log and the error.
    name: String,
    /// One per master named, each with its own key resolved: a group may name
    /// several, and the ordinary secondary path spawns a refresh task per
    /// (zone, master) too.
    masters: Vec<(MasterSpec, Option<TsigKey>)>,
}

/// Where a member is to be fetched from, once its groups have been read.
enum Fetch<'a> {
    /// No group matched: the catalog's own master and key (§5.1).
    FromCatalog,
    /// Exactly one configuration matched, however many group values named it.
    FromGroup(&'a GroupMaster),
    /// Two groups on one member name different configurations, and §4.3.2 has
    /// no rule for choosing. The string says which, for the log.
    Ambiguous(String),
}

impl CatalogSpec {
    /// Which configuration a member's group values select (§4.3.2).
    ///
    /// "The consumer ... MAY choose to process all, some, or none of them", so
    /// several values naming *one* configuration is not a conflict — only
    /// several naming different ones is, and that is refused rather than
    /// resolved by order: picking the first would be a silent choice about what
    /// is being served (`CLAUDE.md` §15).
    fn fetch(&self, member: &CatalogMember) -> Fetch<'_> {
        let mut chosen: Option<&GroupMaster> = None;
        for rule in &self.groups {
            // Bytes, not text: the config key's UTF-8 encoding is the needle.
            if !member.groups().contains(&rule.value) {
                continue;
            }
            match chosen {
                None => chosen = Some(rule),
                Some(first) if first.fetches_like(rule) => {}
                Some(first) => {
                    return Fetch::Ambiguous(format!(
                        "it carries both group {:?} and group {:?}, which name                          different masters, and RFC 9432 §4.3.2 gives no rule for                          choosing between them",
                        first.name, rule.name
                    ))
                }
            }
        }
        match chosen {
            Some(rule) => Fetch::FromGroup(rule),
            None => Fetch::FromCatalog,
        }
    }

    /// The masters and key for a member, given the group recorded for it.
    ///
    /// Used by the startup pass, where the catalog has not been read yet and
    /// the sidecar is the only thing that knows. A group that has since gone
    /// from the configuration falls back to the catalog's own master, which is
    /// what the next reconcile will move it to anyway.
    fn masters_for(&self, zone: &Name, group: Option<&[u8]>) -> Vec<MasterSpec> {
        let rule = group.and_then(|value| self.groups.iter().find(|rule| rule.value == value));
        match rule {
            Some(rule) => rule
                .masters
                .iter()
                .map(|(spec, _)| spec.for_member(zone.clone()))
                .collect(),
            None => vec![self.spec.for_member(zone.clone())],
        }
    }
}

impl GroupMaster {
    /// Whether two rules would fetch a member the same way, which is what makes
    /// a member carrying both of them unambiguous rather than a conflict.
    fn fetches_like(&self, other: &GroupMaster) -> bool {
        self.masters.len() == other.masters.len()
            && self
                .masters
                .iter()
                .zip(&other.masters)
                .all(|((mine, _), (theirs, _))| {
                    mine.master == theirs.master
                        && mine.key_name == theirs.key_name
                        && mine.tls == theirs.tls
                })
    }
}

/// Every catalog this server consumes.
pub(crate) struct Catalogs {
    by_zone: HashMap<NameKeyBuf, CatalogSpec>,
    secondaries: Arc<Secondaries>,
    /// Zones the operator configured by hand, which no catalog may take over
    /// (§5.2). The catalogs themselves are in `by_zone` and are checked there.
    ///
    /// A set, because it is probed once per member of every catalog and both
    /// sides of that product are what a fleet has thousands of; `Borrow<[u8]>`
    /// keeps the probe free of an allocation.
    configured: HashSet<NameKeyBuf>,
    /// The sidecar and the serials reconciled from, behind one lock: a
    /// reconcile reads both, writes both, and two running at once would each
    /// decide against the other's half-applied membership.
    state: Mutex<CatalogState>,
}

/// How many refused members one catalog reports, of however many there were.
///
/// A bound, because the list is keyed on member names a *producer* chooses and
/// a mistaken one can list millions (§6). A count beside it, because a bound
/// with no visible shortfall is a report that is quietly a lie
/// (`CLAUDE.md` §5). Small on purpose: a fleet with a hundred refusals has one
/// misconfiguration, not a hundred, and the log has every one of them.
const MAX_REFUSALS_REPORTED: usize = 16;

/// What one catalog declined to provision at its last reconcile.
///
/// Rebuilt from scratch each time rather than accumulated: a member refused
/// once and accepted later must stop being reported, and §5.2's clash is a
/// property of the catalog as it stands.
#[derive(Debug, Default, Clone)]
pub(crate) struct Refusals {
    /// The first [`MAX_REFUSALS_REPORTED`], in the order the catalog lists them.
    pub(crate) shown: Vec<(Name, String)>,
    /// How many there were, which is `shown.len()` unless the bound bit.
    pub(crate) total: usize,
}

impl Refusals {
    fn push(&mut self, zone: Name, why: String) {
        self.total += 1;
        if self.shown.len() < MAX_REFUSALS_REPORTED {
            self.shown.push((zone, why));
        }
    }
}

/// One catalog as `rdnsctl catalog` reports it.
///
/// Read by `crate::control` alone, which is `#[cfg(unix)]` because the socket
/// is. Named in backticks rather than linked, because a link to it resolves to
/// nothing on Windows — one of the sixteen shapes `cargo doc` found, in
/// `CLAUDE.md`'s preamble — and built by nothing there, which is what the
/// attribute below says so that the next reader does not have to work it out.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct CatalogReport {
    pub(crate) catalog: Name,
    /// Where the catalog itself comes from, which is also where a member with
    /// no group comes from.
    pub(crate) master: String,
    /// Zone, member node, group — the sidecar's own rows, sorted by zone.
    pub(crate) members: Vec<(Name, Name, Option<Vec<u8>>)>,
    pub(crate) refused: Refusals,
}

struct CatalogState {
    membership: Membership,
    /// What each catalog declined at its last reconcile, by catalog zone.
    ///
    /// §5.2's clash is "an error SHOULD be logged" and was logged and nowhere
    /// else, so the one question `rdnsctl status` could never answer was about
    /// a zone that has no row in it (`TODO.md` #49).
    refused: HashMap<NameKeyBuf, Refusals>,
    /// The serial of each catalog as last reconciled, so an hourly refresh that
    /// changed nothing costs a lookup instead of a parse of every member. A
    /// catalog we could not read is *not* recorded, which is what makes §5.1's
    /// "processing SHALL start (or resume) when the catalog turns into a correct
    /// catalog zone" happen by itself.
    reconciled: HashMap<NameKeyBuf, Serial>,
}

impl Catalogs {
    /// Resolve the `--catalog` specs against the keyring.
    ///
    /// `configured` is every zone the rest of the configuration names, and
    /// `held` every zone loaded from disk at startup. Both are protected from
    /// being taken over by a catalog (§5.2) — `held` minus this server's own
    /// members, because those are exactly the files a previous run wrote.
    ///
    /// Which way that has to fail is the question. A file on disk that no
    /// sidecar row claims is read as somebody's zone rather than as an orphan:
    /// mistaking a member for a configured zone refuses to provision it and
    /// says so, while mistaking a configured zone for a member replicates over
    /// a file the operator wrote.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        specs: Vec<MasterSpec>,
        keys: &TsigKeyring,
        configured: HashSet<NameKeyBuf>,
        held: Vec<Name>,
        zone_dir: &Path,
        secondaries: Arc<Secondaries>,
        groups: &BTreeMap<String, Vec<crate::config::GroupRule>>,
    ) -> Result<Arc<Catalogs>> {
        let membership = Membership::load(&membership_path(zone_dir));
        let mut configured = configured;
        configured.extend(
            held.into_iter()
                .filter(|zone| membership.owner_of(zone.as_ref()).is_none())
                .map(|zone| NameKeyBuf::new(zone.as_ref())),
        );
        let mut by_zone = HashMap::new();
        for spec in specs {
            let key = resolve_key(&spec, keys, "--catalog")?;
            let rules = group_rules(&spec.zone, groups, keys)?;
            tracing::info!(
                "catalog {} from {}{}{}",
                spec.zone,
                spec.master,
                match &spec.key_name {
                    Some(name) => format!(" signed with {name}"),
                    None => String::new(),
                },
                // Printed for the reason every other policy is: a member
                // fetched from somewhere else than the catalog's own master is
                // invisible otherwise (`CLAUDE.md` §14).
                match rules.len() {
                    0 => String::new(),
                    n => format!(
                        ", {n} group rule(s): {}",
                        rules
                            .iter()
                            .map(|rule| rule.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                }
            );
            by_zone.insert(
                NameKeyBuf::new(spec.zone.as_ref()),
                CatalogSpec {
                    spec,
                    key,
                    groups: rules,
                },
            );
        }
        Ok(Arc::new(Catalogs {
            by_zone,
            secondaries,
            configured,
            state: Mutex::new(CatalogState {
                membership,
                refused: HashMap::new(),
                reconciled: HashMap::new(),
            }),
        }))
    }

    /// What each catalog provisioned and what it declined, for the control
    /// socket (RFC 9432 §6: "Implementations are ... advised to provide a tool
    /// ... to perform queries on catalog zones").
    ///
    /// A snapshot under the one lock the reconcile also takes, so a report is
    /// never half of one reconcile and half of the next.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) async fn report(&self) -> Vec<CatalogReport> {
        let state = self.state.lock().await;
        let mut reports: Vec<CatalogReport> = self
            .by_zone
            .values()
            .map(|spec| {
                let mut members: Vec<(Name, Name, Option<Vec<u8>>)> = state
                    .membership
                    .members_of(spec.spec.zone.as_ref())
                    .into_iter()
                    .map(|row| (row.zone, row.node, row.group))
                    .collect();
                members.sort_by_key(|(zone, _, _)| zone.to_string());
                CatalogReport {
                    catalog: spec.spec.zone.clone(),
                    master: spec.spec.master.to_string(),
                    members,
                    refused: state
                        .refused
                        .get(&*spec.spec.zone.as_ref().folded())
                        .cloned()
                        .unwrap_or_default(),
                }
            })
            .collect();
        reports.sort_by_key(|report| report.catalog.to_string());
        reports
    }

    /// Which catalog provisioned each member, for the `catalog` column on
    /// `rdnsctl status`.
    ///
    /// The sidecar's rows rather than the catalogs' contents: a zone is this
    /// server's member because the sidecar says so, which is the same fact
    /// §5.3's removal turns on.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) async fn provenance(&self) -> Vec<(Name, Name)> {
        let state = self.state.lock().await;
        state
            .membership
            .rows()
            .iter()
            .map(|row| (row.zone.clone(), catalog_of(row.node.as_ref()).to_owned()))
            .collect()
    }

    /// Every catalog, for the startup pass.
    pub(crate) fn zones(&self) -> Vec<Name> {
        self.by_zone
            .values()
            .map(|spec| spec.spec.zone.clone())
            .collect()
    }

    /// Apply the EXPIRE rule to the members a previous run provisioned, before
    /// anything is served.
    ///
    /// A member's zone file is in `--zone-dir` like any other, so a restart
    /// loads and serves it with AA set — and its refresh task does not exist
    /// until the catalog arrives and is reconciled. Without this, a member whose
    /// master has been unreachable for a week comes back at the next restart as
    /// a zone nothing vouches for and nothing withdraws. The specs are rebuilt
    /// from the sidecar, since that is where the answer to "whose member is this"
    /// lives; the master is the one its catalog is configured with.
    ///
    /// A row whose catalog is no longer configured cannot be given a master and
    /// so cannot be checked. Those are named at WARN rather than withdrawn: an
    /// operator who took a `--catalog` flag away still has the zone files, and
    /// deleting the data because a flag went is the larger mistake.
    pub(crate) async fn vouch_for_members(&self, replication: &ReplicationContext) {
        let state = self.state.lock().await;
        let mut specs = Vec::new();
        let mut orphaned: Vec<Name> = Vec::new();
        for row in state.membership.rows() {
            match self.by_zone.get(&*catalog_of(row.node.as_ref()).folded()) {
                // The group the row records, not the catalog's own master: a
                // member fetched from a group's master is vouched for against
                // that master or against nothing at all.
                Some(spec) => specs.extend(spec.masters_for(&row.zone, row.group.as_deref())),
                None => orphaned.push(row.zone.clone()),
            }
        }
        if !orphaned.is_empty() {
            tracing::warn!(
                "{} zone(s) were provisioned by a catalog this server no longer \
                 consumes and are being served from disk with nothing refreshing \
                 them: {}",
                orphaned.len(),
                orphaned
                    .iter()
                    .map(|zone| zone.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        withdraw_unvouched_zones(&specs, &replication.served, &replication.zone_dir).await;
    }

    /// Bring the members of `zone` into line with what it now says, if it is a
    /// catalog this server consumes.
    ///
    /// Called after every refresh of every replicated zone, so the first thing
    /// it does is decide the question is about it at all. §5.1 asks for exactly
    /// this: changes applied when a transfer of the catalog completes, "without
    /// any manual intervention".
    pub(crate) async fn reconcile(
        &self,
        zone: NameRef<'_>,
        replication: &ReplicationContext,
        lifecycle: &Lifecycle,
    ) {
        let Some(spec) = self.by_zone.get(&*zone.folded()) else {
            return;
        };
        // A clone, because everything below takes the zone map's write lock.
        let Some(held) = replication
            .served
            .zone_map
            .read()
            .await
            .matching(zone)
            .cloned()
        else {
            // §5.1: "when a catalog zone expires, it loses its catalog meaning
            // and MUST no longer be processed as such. No special processing
            // occurs" — so an expired or not-yet-transferred catalog withdraws
            // nothing.
            return;
        };

        let mut state = self.state.lock().await;
        let key = NameKeyBuf::new(zone);
        // Equality, not order: the question is whether this is the version last
        // reconciled, and `Serial` has no `PartialOrd` for the reason
        // `CLAUDE.md` §17 gives. A producer that edits a catalog without moving
        // its serial is therefore not noticed — the same trade every serial-based
        // decision here makes, and RFC 1982 §3.1 is why the serial is the
        // producer's to move.
        if let (Some(serial), Some(last)) = (held.serial(), state.reconciled.get(&key)) {
            if serial == *last {
                return;
            }
        }

        let catalog = match Catalog::from_zone(&held) {
            Ok(catalog) => catalog,
            Err(e) => {
                // §5.1: a broken catalog "loses its catalog meaning ... Member
                // zones previously configured by this catalog MUST NOT be
                // removed or reconfigured in any way", and the reason "SHOULD be
                // communicated clearly to the operator".
                tracing::warn!(
                    "catalog {zone} is broken and is being ignored, its members left as they are: {e}"
                );
                return;
            }
        };

        self.apply(&mut state, spec, &catalog, replication, lifecycle)
            .await;
        // Where the fact changes, not where it is read (`CLAUDE.md` §14): this
        // is the only moment membership moves.
        replication.served.metrics.set_catalog_members(
            zone,
            state.membership.members_of(spec.spec.zone.as_ref()).len(),
        );
        if let Some(serial) = held.serial() {
            state.reconciled.insert(key, serial);
        }

        let (path, text) = state.membership.snapshot();
        if let Err(e) = write_snapshot(&path, &text) {
            // A warning and not a failure, but the consequence is stated: the
            // rows are how a removal that happens while this process is down is
            // noticed at the next start.
            tracing::warn!(
                "could not write {}: a member removed while this server is not \
                 running would go unnoticed until the file is writable again ({e})",
                path.display()
            );
        }
    }

    /// The diff, once it is known that `catalog` is what `spec`'s zone says.
    async fn apply(
        &self,
        state: &mut CatalogState,
        spec: &CatalogSpec,
        catalog: &Catalog,
        replication: &ReplicationContext,
        lifecycle: &Lifecycle,
    ) {
        let mine: Vec<MemberRow> = state.membership.members_of(spec.spec.zone.as_ref());
        // Rebuilt from scratch: a member refused last time and accepted now
        // must stop being reported (`TODO.md` #49).
        let mut refused = Refusals::default();

        for member in catalog.members() {
            // Which group's configuration this member now falls under, and
            // whether the answer is a conflict (§4.3.2, `TODO.md` #48).
            let fetch = spec.fetch(member);
            if let Fetch::Ambiguous(why) = &fetch {
                // Refused, and *left alone* if it is already ours: §5.1's rule
                // for an instruction that cannot be followed is that member
                // zones "MUST NOT be removed or reconfigured in any way", and
                // an ambiguous group is exactly that instruction.
                tracing::error!(
                    "catalog {}: not provisioning {} — {why}",
                    spec.spec.zone,
                    member.zone()
                );
                refused.push(member.zone().to_owned(), why.clone());
                continue;
            }
            let group = match &fetch {
                Fetch::FromGroup(rule) => Some(rule.value.clone()),
                _ => None,
            };
            let held = mine.iter().find(|row| row.zone.as_ref() == member.zone());
            match held {
                // Already ours, under the same node label and the same group:
                // nothing to do.
                Some(row) if row.node.as_ref() == member.node() && row.group == group => {}
                // The label is the same and the group is not: the same zone,
                // fetched from somewhere else. Not §5.4's removal — that is
                // about the *node* label and deletes the file and the transfer
                // state — so the refresh task is replaced and the data stays.
                // The zone does stop being *served* until the new master
                // answers, because nothing has vouched for the age of a copy
                // that came from the old one; that is `withdraw_unvouched_zones`
                // applying the same rule a configured secondary gets when its
                // `masters` change.
                Some(row) if row.node.as_ref() == member.node() => {
                    tracing::info!(
                        "catalog {}: {} moves from {} to {} (RFC 9432 §4.3.2). Its \
                         copy on disk is kept and it stops being served until the \
                         new master answers, which is the rule every secondary gets",
                        spec.spec.zone,
                        member.zone(),
                        describe_group(row.group.as_deref()),
                        describe_group(group.as_deref())
                    );
                    self.secondaries.retired(member.zone()).await;
                    self.add(state, spec, member, &fetch, replication, lifecycle)
                        .await;
                }
                // §5.4: "When the member node's label value (<unique-N>) changes
                // ... catalog consumers MUST process this as a member zone
                // removal, including the removal of all the zone's associated
                // state ... and then immediately process the member as a newly
                // added zone".
                Some(row) => {
                    let was = row.node.clone();
                    self.remove(
                        state,
                        member.zone(),
                        replication,
                        &format!(
                            "its member node moved from {was} to {}, which RFC 9432 §5.4 \
                             makes a removal and a re-add",
                            member.node()
                        ),
                    )
                    .await;
                    self.add(state, spec, member, &fetch, replication, lifecycle)
                        .await;
                }
                None => match self.ownership(state, spec, member, replication).await {
                    Ownership::Free => {
                        self.add(state, spec, member, &fetch, replication, lifecycle)
                            .await
                    }
                    Ownership::Taken(why) => {
                        // §5.2: "the new instance of the zone MUST be ignored and
                        // an error SHOULD be logged".
                        tracing::error!(
                            "catalog {}: ignoring member {} — {why}",
                            spec.spec.zone,
                            member.zone()
                        );
                        refused.push(member.zone().to_owned(), why);
                    }
                    Ownership::AlreadyHandedOver(to) => {
                        // Not an error, and this is why it is not: §4.3.1 leaves
                        // the member in the old catalog until "it has been
                        // established that all its consumers have processed the
                        // Change of Ownership", so this is the ordinary state of
                        // a migration in progress and would otherwise log one
                        // per refresh, forever.
                        tracing::debug!(
                            "catalog {}: {} has already moved to {to}",
                            spec.spec.zone,
                            member.zone()
                        );
                    }
                    Ownership::HandedOver { from, reset } => {
                        tracing::info!(
                            "catalog {}: taking {} over from {from}, which carries a coo \
                             property naming us (RFC 9432 §4.3.1)",
                            spec.spec.zone,
                            member.zone()
                        );
                        if reset {
                            // §4.3.1: "Unless the member node label ... is the
                            // same in $NEWCATZ, all its associated state for a
                            // just migrated zone MUST be reset."
                            self.remove(
                                state,
                                member.zone(),
                                replication,
                                "its new catalog gives it a different member node, which \
                                 RFC 9432 §4.3.1 makes a state reset",
                            )
                            .await;
                        } else {
                            // The state stays; only who asks for it changes, and
                            // the old catalog's refresh task is asking with the
                            // old catalog's master and key.
                            self.secondaries.retired(member.zone()).await;
                        }
                        self.add(state, spec, member, &fetch, replication, lifecycle)
                            .await;
                    }
                },
            }
        }

        state
            .refused
            .insert(NameKeyBuf::new(spec.spec.zone.as_ref()), refused);

        // §5.3: removed from this catalog, and configured from this catalog, so
        // ours to remove.
        for row in &mine {
            if catalog.member(row.zone.as_ref()).is_none() {
                self.remove(
                    state,
                    row.zone.as_ref(),
                    replication,
                    &format!("catalog {} no longer lists it", spec.spec.zone),
                )
                .await;
            }
        }
    }

    /// Whether this catalog may provision a member somebody else may hold.
    ///
    /// §5.2's rule, with §4.3.1's exception: a zone another catalog owns is a
    /// clash unless that catalog is handing it over, which it does by carrying a
    /// `coo` property naming this one. "Before the actual migration, the
    /// consumer MUST verify that the coo property pointing to $NEWCATZ is still
    /// present in $OLDCATZ" — so the old catalog is read now, from the copy
    /// being served, rather than remembered from when the property appeared.
    async fn ownership(
        &self,
        state: &CatalogState,
        spec: &CatalogSpec,
        member: &CatalogMember,
        replication: &ReplicationContext,
    ) -> Ownership {
        let zone = member.zone();
        if self.configured.contains(&*zone.folded()) {
            return Ownership::Taken("the configuration already names that zone".to_string());
        }
        if let Some(other) = self.by_zone.get(&*zone.folded()) {
            return Ownership::Taken(format!("{} is a catalog zone here", other.spec.zone));
        }
        let Some(owner) = state.membership.owner_of(zone) else {
            return Ownership::Free;
        };
        // Ours already — reachable only if the caller's view of the membership
        // is older than this one, which is a reason to do nothing either way.
        if owner.as_ref() == spec.spec.zone.as_ref() {
            return Ownership::Free;
        }
        // We handed it to that catalog ourselves, and §4.3.1 keeps it listed
        // here until the producer is satisfied every consumer has seen the
        // change.
        if member.coo() == Some(owner.as_ref()) {
            return Ownership::AlreadyHandedOver(owner);
        }

        // The old catalog as it is *now*. If we no longer hold it — it expired,
        // or its `--catalog` spec is gone — then there is nothing saying we may
        // take the zone, and §5.2's default stands.
        let old = replication
            .served
            .zone_map
            .read()
            .await
            .matching(owner.as_ref())
            .cloned();
        let handover = old
            .as_ref()
            .and_then(|held| Catalog::from_zone(held).ok())
            .and_then(|catalog| {
                catalog
                    .member(zone)
                    .filter(|old| old.coo() == Some(spec.spec.zone.as_ref()))
                    // §4.3.1: the same member node label carries the state over,
                    // a different one resets it (§5.6). Folded, because every
                    // other comparison of a label here is (RFC 4343).
                    .map(|old| !old.id().eq_ignore_ascii_case(member.id()))
            });
        match handover {
            Some(reset) => Ownership::HandedOver { from: owner, reset },
            None => Ownership::Taken(format!(
                "catalog {owner} provisioned it and does not carry a coo property \
                 handing it over (RFC 9432 §4.3.1)"
            )),
        }
    }

    /// Start replicating a member, and record that this catalog is why.
    async fn add(
        &self,
        state: &mut CatalogState,
        spec: &CatalogSpec,
        member: &CatalogMember,
        fetch: &Fetch<'_>,
        replication: &ReplicationContext,
        lifecycle: &Lifecycle,
    ) {
        let zone = member.zone().to_owned();
        // One entry for the catalog's own master, or one per master the group
        // names — which is the shape a configured secondary with two masters
        // gets, since `Secondaries` holds a task list per zone.
        let masters: Vec<(MasterSpec, Option<TsigKey>)> = match fetch {
            Fetch::FromGroup(rule) => rule
                .masters
                .iter()
                .map(|(spec, key)| (spec.for_member(zone.clone()), key.clone()))
                .collect(),
            _ => vec![(spec.spec.for_member(zone.clone()), spec.key.clone())],
        };
        tracing::info!(
            "catalog {}: serving {zone} from {}{}",
            spec.spec.zone,
            masters
                .iter()
                .map(|(spec, _)| spec.master.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            describe_groups(member, fetch)
        );
        // The same rule a configured secondary gets at startup: a copy on disk
        // whose age cannot be vouched for is not served until its master answers
        // (`CLAUDE.md` §4). This is the adoption path — the file is already
        // there from a previous run — and a no-op for a member we have never
        // held.
        let specs: Vec<MasterSpec> = masters.iter().map(|(spec, _)| spec.clone()).collect();
        withdraw_unvouched_zones(&specs, &replication.served, &replication.zone_dir).await;
        state.membership.set(MemberRow {
            zone,
            node: member.node().to_owned(),
            group: match fetch {
                Fetch::FromGroup(rule) => Some(rule.value.clone()),
                _ => None,
            },
        });
        for (master, key) in masters {
            spawn_secondary(master, key, replication, lifecycle, &self.secondaries);
        }
    }

    /// Stop replicating a member and take its state with it (§5.3).
    async fn remove(
        &self,
        state: &mut CatalogState,
        zone: NameRef<'_>,
        replication: &ReplicationContext,
        why: &str,
    ) {
        // First, and waited out: nothing may install the zone back or rewrite
        // its file between the withdrawal and the deletion below.
        self.secondaries.retired(zone).await;
        withdraw(&replication.served, zone).await;
        state.membership.forget(zone);

        // "The zone and associated state (such as zone data and DNSSEC keys)
        // MUST be removed": the copy on disk, and the transfer state that would
        // otherwise vouch for the age of a zone of the same name added later.
        let path = zone_file_path(&replication.zone_dir, &zone.to_presentation());
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("could not delete {}: {e}", path.display());
            }
        }
        let snapshot = {
            let mut file = replication.state.lock().expect("state mutex");
            file.forget(&zone.to_presentation());
            file.snapshot()
        };
        if let Err(e) = write_snapshot(&snapshot.0, &snapshot.1) {
            tracing::warn!("could not write {}: {e}", snapshot.0.display());
        }

        // WARN, not INFO: a member leaving a catalog takes a zone off this
        // server, and RFC 9432 §6 is blunt about what a mistaken producer can do
        // with that — "millions of member zones may get deleted from their
        // secondaries within seconds".
        tracing::warn!("no longer serving {zone}: {why}");
    }
}

/// Whether a catalog may provision a member zone (§5.2, §4.3.1).
enum Ownership {
    /// Nothing else holds the name.
    Free,
    /// Something else does, and it is not handing it over. The string says
    /// what, for the log line §5.2 asks for.
    Taken(String),
    /// This catalog hands it to the one that now holds it, which has taken it:
    /// the interim §4.3.1 describes, not a clash.
    AlreadyHandedOver(Name),
    /// Another catalog holds it and carries a `coo` property naming this one.
    HandedOver {
        from: Name,
        /// Whether the zone's state has to be reset: §4.3.1 keeps it when the
        /// member node label is the same in both catalogs and resets it
        /// otherwise.
        reset: bool,
    },
}

/// The group values a member carries and what they did, for the line that says
/// it is being served.
///
/// Both halves, because §4.3.2 makes a group mean whatever producer and
/// consumer agreed and the interesting case is the one where they disagree: a
/// producer sending a value nothing here maps is invisible otherwise, and that
/// is the half of "the consumer ... MAY choose to process all, some, or none of
/// them" that costs something to see.
fn describe_groups(member: &CatalogMember, fetch: &Fetch<'_>) -> String {
    if member.groups().is_empty() {
        return String::new();
    }
    let groups: Vec<String> = member
        .groups()
        .iter()
        .map(|g| String::from_utf8_lossy(g).into_owned())
        .collect();
    let acted = match fetch {
        Fetch::FromGroup(rule) => format!("under group {:?}", rule.name),
        _ => "none of which this server maps to a configuration".to_string(),
    };
    format!(" (group {}: {acted})", groups.join(", "))
}

/// One group value for a log line, or the catalog's own configuration.
fn describe_group(group: Option<&[u8]>) -> String {
    match group {
        Some(value) => format!("group {:?}", String::from_utf8_lossy(value)),
        None => "the catalog's own master".to_string(),
    }
}

/// Resolve one catalog's group table against the keyring.
///
/// At startup, like the catalog's own key and for the same reason: a member
/// added at three in the morning must not fail on a key name that was already
/// known to be missing. The zone in each `MasterSpec` is the catalog's and is a
/// placeholder — `MasterSpec::for_member` replaces it with the member's.
fn group_rules(
    catalog: &Name,
    groups: &BTreeMap<String, Vec<crate::config::GroupRule>>,
    keys: &TsigKeyring,
) -> Result<Vec<GroupMaster>> {
    let Some(rules) = groups.get(&catalog.to_string()) else {
        return Ok(Vec::new());
    };
    let mut resolved = Vec::with_capacity(rules.len());
    for rule in rules {
        let mut masters = Vec::with_capacity(rule.masters.len());
        for master in &rule.masters {
            let spec = MasterSpec::parse(&format!("{catalog}@{master}"))
                .with_context(|| format!("catalog {catalog}, group {:?}", rule.name))?;
            let key = resolve_key(&spec, keys, "a catalog group")
                .with_context(|| format!("catalog {catalog}, group {:?}", rule.name))?;
            masters.push((spec, key));
        }
        resolved.push(GroupMaster {
            value: rule.value.clone(),
            name: rule.name.clone(),
            masters,
        });
    }
    Ok(resolved)
}

/// One row of the sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MemberRow {
    zone: Name,
    /// `<unique-N>.zones.$CATZ`, which carries the catalog too.
    node: Name,
    /// The group whose configuration fetched it, or `None` for the catalog's
    /// own master (§4.3.2, `TODO.md` #48).
    ///
    /// Recorded rather than re-derived, because §5.4's reset is about the
    /// member *node* label: a group changing under an unchanged label means the
    /// same zone fetched from somewhere else, and without this the change is
    /// invisible to the next reconcile.
    group: Option<Vec<u8>>,
}

/// Which catalog provisioned which zone, under which member node, and under
/// which group.
///
/// One line per member: the zone, the member node it came from, then the group.
/// The node carries the catalog — a member node is `<unique-N>.zones.$CATZ` —
/// so the two facts §5.3 and §5.4 need are one name and cannot disagree with
/// each other. Both names are written in presentation form, which escapes
/// whatever octets a producer chose for `<unique-N>`.
///
/// The third field arrived with `TODO.md` #48 and a row may still have two: a
/// file an older build wrote reads as "no group", which is what that build
/// meant. The reverse is not true — an older build reading a three-field row
/// skips it and loses that member's provenance — so a downgrade costs one
/// reconcile's worth of removals going unnoticed, and the file says so.
struct Membership {
    path: PathBuf,
    rows: Vec<MemberRow>,
}

impl Membership {
    /// Read the sidecar, or start empty.
    ///
    /// Never fails, like the transfer state beside it: an unreadable row costs a
    /// member zone its provenance, which the next reconcile re-establishes from
    /// the catalog. Unparseable lines are skipped and logged.
    fn load(path: &Path) -> Membership {
        let mut rows = Vec::new();
        if let Ok(text) = std::fs::read_to_string(path) {
            for (number, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                match parse_row(line) {
                    Ok(row) => rows.push(row),
                    Err(e) => tracing::warn!(
                        file = %path.display(),
                        line = number + 1,
                        "ignoring unreadable catalog membership line ({e})"
                    ),
                }
            }
        }
        Membership {
            path: path.to_path_buf(),
            rows,
        }
    }

    /// Every member row.
    fn rows(&self) -> &[MemberRow] {
        &self.rows
    }

    /// The zones this catalog provisioned.
    fn members_of(&self, catalog: NameRef<'_>) -> Vec<MemberRow> {
        let wanted = catalog.folded();
        self.rows
            .iter()
            .filter(|row| catalog_of(row.node.as_ref()).folded() == wanted)
            .cloned()
            .collect()
    }

    /// Which catalog provisioned this zone, if one did.
    fn owner_of(&self, zone: NameRef<'_>) -> Option<Name> {
        self.row_for(zone)
            .map(|row| catalog_of(row.node.as_ref()).to_owned())
    }

    fn row_for(&self, zone: NameRef<'_>) -> Option<&MemberRow> {
        let wanted = zone.folded();
        self.rows
            .iter()
            .find(|row| row.zone.as_ref().folded() == wanted)
    }

    fn set(&mut self, row: MemberRow) {
        let folded = row.zone.as_ref().folded().into_owned();
        match self
            .rows
            .iter_mut()
            .find(|held| *held.zone.as_ref().folded() == folded[..])
        {
            Some(held) => *held = row,
            None => self.rows.push(row),
        }
    }

    fn forget(&mut self, zone: NameRef<'_>) {
        let folded = zone.folded();
        self.rows.retain(|row| row.zone.as_ref().folded() != folded);
    }

    fn snapshot(&self) -> (PathBuf, String) {
        let mut text = String::from(
            "# rdnsd catalog membership: member-zone member-node group\n\
             # Written by the server. Deleting this makes every member look like\n\
             # a zone no catalog provisioned, which costs a removal nobody sees.\n\
             # The group is `-` for none, and otherwise RFC 1035 §5.1 escaping\n\
             # with spaces as \\032; a build older than TODO.md #48 skips a row\n\
             # that has it.\n",
        );
        for row in &self.rows {
            text.push_str(&format!(
                "{} {} {}\n",
                row.zone,
                row.node,
                write_group(row.group.as_deref())
            ));
        }
        (self.path.clone(), text)
    }
}

/// The group field of a sidecar row.
///
/// `-` for none. Otherwise RFC 1035 §5.1's character-string escaping, which
/// `char_string_escaped` already owns, plus the two cases the row format adds:
/// a space would end the field, and a bare `-` would read as "none".
fn write_group(group: Option<&[u8]>) -> String {
    let Some(group) = group else {
        return "-".to_string();
    };
    let escaped = rdns::codecs::char_string_escaped(group).replace(' ', "\\032");
    if escaped == "-" {
        // `\045` decodes back to `-`, so the round trip holds and the field
        // cannot be mistaken for the no-group marker.
        return "\\045".to_string();
    }
    escaped
}

/// The inverse, for a field an older build may not have written at all.
fn read_group(field: Option<&str>) -> Result<Option<Vec<u8>>> {
    match field {
        None | Some("-") => Ok(None),
        Some(text) => Ok(Some(
            rdns::codecs::char_string_decode(text)
                .map_err(|e| anyhow::anyhow!("{text:?} is not a group value: {e}"))?,
        )),
    }
}

/// The catalog a member node belongs to: `<unique-N>.zones.$CATZ` less its two
/// leading labels.
fn catalog_of(node: NameRef<'_>) -> NameRef<'_> {
    node.suffix(node.label_count().saturating_sub(2))
}

/// Two fields or three: the third arrived with `TODO.md` #48, and a file an
/// older build wrote means "no group", which is what that build did.
fn parse_row(line: &str) -> Result<MemberRow> {
    let mut fields = line.split_whitespace();
    let (Some(zone), Some(node), group, None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err(anyhow::anyhow!("expected 2 or 3 fields"));
    };
    let zone = Name::from_presentation(zone).with_context(|| format!("{zone:?}"))?;
    let node = Name::from_presentation(node).with_context(|| format!("{node:?}"))?;
    if node.as_ref().label_count() < 3 {
        return Err(anyhow::anyhow!(
            "{node} is not a member node: a member node is <unique-N>.zones.$CATZ"
        ));
    }
    Ok(MemberRow {
        zone,
        node,
        group: read_group(group)?,
    })
}

/// Where the sidecar goes, beside the transfer state it is the companion of.
pub(crate) fn membership_path(dir: &Path) -> PathBuf {
    dir.join("rdnsd.catalog")
}

/// Parse every `--catalog`, or stop.
///
/// A spec that does not parse is an error for the reason a `--secondary` one
/// is: a catalog silently not consumed is a fleet that quietly stops being
/// provisioned.
pub(crate) fn parse_catalog_specs(specs: &[String]) -> Result<Vec<MasterSpec>> {
    specs
        .iter()
        .filter(|spec| !spec.trim().is_empty())
        .map(|spec| MasterSpec::parse(spec).map_err(|e| anyhow::anyhow!("--catalog {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{nm, ScratchDir};
    use crate::zones::{ZoneContext, Zones};
    use rdns::ixfr::DeltaLog;
    use rdns::metrics::DnsMetrics;
    use rdns::notify::NotifyPolicy;
    use rdns::readiness::Readiness;
    use rdns::secondary::{state_file_path, StateFile, TransferState};
    use rdns::shutdown::Shutdown;
    use rdns::zone::{parse_zone_file, Zone};
    use std::sync::Mutex as StdMutex;
    use tokio::sync::RwLock;

    const MASTER: &str = "192.0.2.1:53";

    /// A catalog zone at `origin`, at `serial`, listing `<id>.zones` -> zone
    /// pairs. `extra` is appended verbatim, which is how a test adds a property.
    fn catalog_zone(origin: &str, serial: u32, members: &[(&str, &str)], extra: &str) -> Zone {
        let mut text = format!(
            "{origin} 0 SOA invalid. invalid. {serial} 3600 600 2147483646 0\n\
             {origin} 0 NS invalid.\n\
             version.{origin} 0 TXT \"2\"\n"
        );
        for (id, zone) in members {
            text.push_str(&format!("{id}.zones.{origin} 0 PTR {zone}\n"));
        }
        text.push_str(extra);
        parse_zone_file(&text, origin).expect("the catalog parses as a zone")
    }

    /// A zone a member transfer would have produced.
    fn member_zone(origin: &str) -> Zone {
        parse_zone_file(
            &format!(
                "{origin} 3600 SOA ns.{origin} admin.{origin} 1 3600 600 604800 300\n\
                 {origin} 3600 NS ns.{origin}\n"
            ),
            origin,
        )
        .expect("the member parses as a zone")
    }

    struct Harness {
        dir: ScratchDir,
        catalogs: Arc<Catalogs>,
        replication: ReplicationContext,
        secondaries: Arc<Secondaries>,
        zone_map: Arc<RwLock<Zones>>,
        // Kept alive: dropping it would drop the `Busy` the lifecycle holds.
        shutdown: Option<Shutdown>,
        lifecycle: Lifecycle,
    }

    impl Harness {
        /// A consumer of `catalogs`, over a scratch directory, with `configured`
        /// named by the rest of the configuration.
        fn new(tag: &str, catalogs: &[&str], configured: &[&str]) -> Harness {
            Harness::seeded(tag, catalogs, configured, &[], &[])
        }

        /// One catalog with a group table, as a config file's
        /// `[zones."…".groups."…"]` supplies it (`TODO.md` #48).
        fn grouped(tag: &str, catalog: &str, groups: &[(&str, &[&str])]) -> Harness {
            Harness::seeded(tag, &[catalog], &[], &[], groups)
        }

        /// The same, over a directory a previous run left rows in.
        fn seeded(
            tag: &str,
            catalogs: &[&str],
            configured: &[&str],
            rows: &[(&str, &str)],
            groups: &[(&str, &[&str])],
        ) -> Harness {
            let dir = ScratchDir::new(tag);
            if !rows.is_empty() {
                let mut membership = Membership::load(&membership_path(dir.path()));
                for (zone, node) in rows {
                    membership.set(MemberRow {
                        zone: nm(zone),
                        node: nm(node),
                        group: None,
                    });
                }
                let (path, text) = membership.snapshot();
                write_snapshot(&path, &text).expect("seed the sidecar");
            }
            let zone_map = Arc::new(RwLock::new(Zones::default()));
            let served = ZoneContext {
                zone_map: zone_map.clone(),
                deltas: Arc::new(RwLock::new(DeltaLog::new())),
                metrics: Arc::new(DnsMetrics::new()),
                journal: None,
            };
            let secondaries = Arc::new(Secondaries::default());
            let specs: Vec<MasterSpec> = catalogs
                .iter()
                .map(|zone| MasterSpec {
                    zone: nm(zone),
                    master: MASTER.parse().expect("a test address"),
                    key_name: None,
                    tls: None,
                })
                .collect();
            let catalogs = Catalogs::new(
                specs,
                &TsigKeyring::default(),
                configured
                    .iter()
                    .map(|zone| NameKeyBuf::new(nm(zone).as_ref()))
                    .collect(),
                Vec::new(),
                dir.path(),
                secondaries.clone(),
                &catalogs
                    .iter()
                    .map(|zone| {
                        (
                            zone.to_string(),
                            groups
                                .iter()
                                .map(|(name, masters)| crate::config::GroupRule {
                                    value: name.as_bytes().to_vec(),
                                    name: name.to_string(),
                                    masters: masters.iter().map(|m| m.to_string()).collect(),
                                })
                                .collect(),
                        )
                    })
                    .collect(),
            )
            .expect("no key names to resolve");
            let shutdown = Shutdown::new();
            let lifecycle = shutdown.lifecycle();
            Harness {
                replication: ReplicationContext {
                    served,
                    state: Arc::new(StdMutex::new(StateFile::load(&state_file_path(dir.path())))),
                    zone_dir: dir.path().to_path_buf(),
                    notify: Arc::new(NotifyPolicy::default()),
                    readiness: Readiness::ready(),
                    catalogs: catalogs.clone(),
                    xot: None,
                },
                dir,
                catalogs,
                secondaries,
                zone_map,
                shutdown: Some(shutdown),
                lifecycle,
            }
        }

        /// Install a catalog and reconcile against it, as a refresh does.
        async fn publish(&self, zone: Zone) {
            let origin = zone.origin().to_owned();
            drop(self.zone_map.write().await.insert(zone));
            self.catalogs
                .reconcile(origin.as_ref(), &self.replication, &self.lifecycle)
                .await;
        }

        /// A member zone as a previous run would have left it: served, on disk,
        /// and vouched for by a transfer state row.
        async fn as_if_transferred(&self, origin: &str) {
            drop(self.zone_map.write().await.insert(member_zone(origin)));
            std::fs::write(self.member_file(origin), "; a transferred copy\n")
                .expect("write the member file");
            let mut state = self.replication.state.lock().expect("state mutex");
            state.set(TransferState {
                zone: origin.to_string(),
                serial: Serial::new(1),
                refreshed_at: rdns::clock::current_unix_timestamp(),
                master: MASTER.parse().expect("a test address"),
            });
        }

        fn member_file(&self, origin: &str) -> PathBuf {
            zone_file_path(self.dir.path(), origin)
        }

        fn membership(&self) -> String {
            std::fs::read_to_string(membership_path(self.dir.path())).unwrap_or_default()
        }

        async fn holds(&self, origin: &str) -> bool {
            self.zone_map
                .read()
                .await
                .matching(nm(origin).as_ref())
                .is_some()
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            // Stops the refresh tasks the provisioning started, which would
            // otherwise sit retrying against a TEST-NET address.
            if let Some(shutdown) = self.shutdown.take() {
                shutdown.begin();
            }
        }
    }

    /// The ordinary case: what the catalog lists is replicated, and the sidecar
    /// records which catalog and which member node it came from.
    #[tokio::test]
    async fn a_member_is_provisioned_and_recorded() {
        let h = Harness::new("catalog-add", &["catalog.invalid."], &[]);
        h.publish(catalog_zone(
            "catalog.invalid.",
            1,
            &[("nj2xg5b", "example.com.")],
            "",
        ))
        .await;

        assert!(
            h.secondaries.replicates(nm("example.com.").as_ref()),
            "the member is replicated from the catalog's master"
        );
        assert_eq!(
            h.membership().lines().last(),
            Some("example.com. nj2xg5b.zones.catalog.invalid. -"),
            "and the sidecar says which catalog, under which member node"
        );
        assert!(
            h.replication
                .served
                .metrics
                .to_prometheus_format()
                .contains("dns_catalog_members{catalog=\"catalog.invalid.\"} 1"),
            "and the gauge an operator alerts on counts it"
        );
    }

    /// §5.3: removed from the catalog that provisioned it, so the zone and the
    /// state that vouches for it go too.
    #[tokio::test]
    async fn a_member_the_catalog_drops_stops_being_served() {
        let h = Harness::new("catalog-remove", &["catalog.invalid."], &[]);
        h.publish(catalog_zone(
            "catalog.invalid.",
            1,
            &[("nj2xg5b", "example.com.")],
            "",
        ))
        .await;
        h.as_if_transferred("example.com.").await;

        h.publish(catalog_zone("catalog.invalid.", 2, &[], ""))
            .await;

        assert!(!h.holds("example.com.").await, "no longer served");
        assert!(
            !h.secondaries.replicates(nm("example.com.").as_ref()),
            "and no longer asked for"
        );
        assert!(
            !h.member_file("example.com.").exists(),
            "its copy on disk goes with it (§5.3)"
        );
        assert!(
            !h.membership().contains("example.com."),
            "and so does the row saying it was ours"
        );
        assert!(
            h.replication
                .served
                .metrics
                .to_prometheus_format()
                .contains("dns_catalog_members{catalog=\"catalog.invalid.\"} 0"),
            "an emptied catalog reads as zero members, not as an absent gauge:              RFC 9432 §6's failure is the count falling off a cliff"
        );
    }

    /// §5.4: "When the member node's label value (<unique-N>) changes ...
    /// consumers MUST process this as a member zone removal, including the
    /// removal of all the zone's associated state ... and then immediately
    /// process the member as a newly added zone".
    #[tokio::test]
    async fn a_changed_member_node_resets_the_zone() {
        let h = Harness::new("catalog-relabel", &["catalog.invalid."], &[]);
        h.publish(catalog_zone(
            "catalog.invalid.",
            1,
            &[("nj2xg5b", "example.com.")],
            "",
        ))
        .await;
        h.as_if_transferred("example.com.").await;

        h.publish(catalog_zone(
            "catalog.invalid.",
            2,
            &[("nvxxezj", "example.com.")],
            "",
        ))
        .await;

        assert!(
            !h.holds("example.com.").await && !h.member_file("example.com.").exists(),
            "the state is reset, not carried over"
        );
        assert!(
            h.secondaries.replicates(nm("example.com.").as_ref()),
            "and it is a member again straight away"
        );
        assert_eq!(
            h.membership().lines().last(),
            Some("example.com. nvxxezj.zones.catalog.invalid. -"),
            "under its new node"
        );
    }

    /// §5.2: "If there is a clash between an existing zone's name (from either
    /// an existing member zone or an otherwise configured zone) and an incoming
    /// member zone's name ... the new instance of the zone MUST be ignored".
    #[tokio::test]
    async fn a_zone_the_configuration_names_is_not_taken_over() {
        let h = Harness::new("catalog-clash", &["catalog.invalid."], &["example.com."]);
        h.publish(catalog_zone(
            "catalog.invalid.",
            1,
            &[("nj2xg5b", "example.com.")],
            "",
        ))
        .await;

        assert!(
            !h.secondaries.replicates(nm("example.com.").as_ref()),
            "the configured zone is left alone"
        );
        assert!(
            h.membership()
                .lines()
                .all(|l| !l.starts_with("example.com.")),
            "and nothing claims it"
        );
    }

    /// §5.1: a broken catalog "loses its catalog meaning ... Member zones
    /// previously configured by this catalog MUST NOT be removed or
    /// reconfigured in any way".
    #[tokio::test]
    async fn a_catalog_that_turns_broken_changes_nothing() {
        let h = Harness::new("catalog-broken", &["catalog.invalid."], &[]);
        h.publish(catalog_zone(
            "catalog.invalid.",
            1,
            &[("nj2xg5b", "example.com.")],
            "",
        ))
        .await;
        h.as_if_transferred("example.com.").await;

        // The version property gone, which §4.2.1 makes the zone not a catalog.
        let broken = parse_zone_file(
            "catalog.invalid. 0 SOA invalid. invalid. 2 3600 600 2147483646 0\n\
             catalog.invalid. 0 NS invalid.\n",
            "catalog.invalid.",
        )
        .expect("a zone, just not a catalog");
        h.publish(broken).await;

        assert!(
            h.holds("example.com.").await && h.member_file("example.com.").exists(),
            "the member it provisioned is untouched"
        );
        assert!(h.membership().contains("example.com."));
    }

    /// §4.3.1: a member moves between catalogs when the old one carries a `coo`
    /// property naming the new one — and only then.
    #[tokio::test]
    async fn a_coo_property_hands_a_member_to_another_catalog() {
        let h = Harness::new("catalog-coo", &["old.invalid.", "new.invalid."], &[]);
        h.publish(catalog_zone(
            "old.invalid.",
            1,
            &[("nj2xg5b", "example.com.")],
            "",
        ))
        .await;
        assert!(h.membership().contains("nj2xg5b.zones.old.invalid."));

        // Without the coo property the second catalog is a clash and the zone
        // stays with the first.
        h.publish(catalog_zone(
            "new.invalid.",
            1,
            &[("nj2xg5b", "example.com.")],
            "",
        ))
        .await;
        assert!(
            h.membership().contains("nj2xg5b.zones.old.invalid."),
            "a name clash, not a migration (§5.2)"
        );

        // The old catalog now hands it over, and the new one is reconciled
        // again — §4.3.1 makes the migration wait for an update of the new
        // catalog in which the member is present.
        h.publish(catalog_zone(
            "old.invalid.",
            2,
            &[("nj2xg5b", "example.com.")],
            "coo.nj2xg5b.zones.old.invalid. 0 PTR new.invalid.\n",
        ))
        .await;
        h.publish(catalog_zone(
            "new.invalid.",
            2,
            &[("nj2xg5b", "example.com.")],
            "",
        ))
        .await;
        assert!(
            h.membership().contains("nj2xg5b.zones.new.invalid."),
            "the member node label is the same in both, so the zone moves with \
             its state (§4.3.1)"
        );

        // §4.3.1 leaves the member in the old catalog "until it has been
        // established that all its consumers have processed the Change of
        // Ownership", so the old catalog goes on listing it — and reconciling
        // the old catalog again must not read that as a clash and take it back.
        h.publish(catalog_zone(
            "old.invalid.",
            3,
            &[("nj2xg5b", "example.com.")],
            "coo.nj2xg5b.zones.old.invalid. 0 PTR new.invalid.
",
        ))
        .await;
        assert!(
            h.membership().contains("nj2xg5b.zones.new.invalid."),
            "the migration stands"
        );
        // And it is not merely refused as a clash: a clash is logged as an
        // error, and this one is the state §4.3.1 asks the producer to leave the
        // catalog in, so it would be one error per refresh forever.
        let old = h
            .zone_map
            .read()
            .await
            .matching(nm("old.invalid.").as_ref())
            .cloned()
            .expect("the old catalog is held");
        let parsed = Catalog::from_zone(&old).expect("and is a catalog");
        let member = parsed
            .member(nm("example.com.").as_ref())
            .expect("which still lists the member");
        let state = h.catalogs.state.lock().await;
        let spec = h
            .catalogs
            .by_zone
            .get(&*nm("old.invalid.").as_ref().folded())
            .expect("the old catalog is configured");
        assert!(matches!(
            h.catalogs.ownership(&state, spec, member, &h.replication).await,
            Ownership::AlreadyHandedOver(to) if to == nm("new.invalid.")
        ));
    }

    /// A member's zone file is loaded and served at startup like any other, and
    /// its refresh task does not exist until its catalog is reconciled. So the
    /// EXPIRE rule has to reach it from the sidecar, or a copy whose master has
    /// been unreachable for a week comes back at the next restart with AA set.
    #[tokio::test]
    async fn a_members_copy_on_disk_is_not_served_until_its_age_is_vouched_for() {
        let h = Harness::seeded(
            "catalog-vouch",
            &["catalog.invalid."],
            &[],
            &[("example.com.", "nj2xg5b.zones.catalog.invalid.")],
            &[],
        );
        // As a restart finds it: the file was loaded into the map, and nothing
        // records a transfer of it.
        drop(h.zone_map.write().await.insert(member_zone("example.com.")));

        h.catalogs.vouch_for_members(&h.replication).await;

        assert!(
            !h.holds("example.com.").await,
            "no record of ever having transferred it, so its age is unknown"
        );
    }

    /// The same zone, vouched for: a transfer state row inside EXPIRE keeps it.
    #[tokio::test]
    async fn a_member_with_recent_contact_keeps_being_served() {
        let h = Harness::seeded(
            "catalog-vouched",
            &["catalog.invalid."],
            &[],
            &[("example.com.", "nj2xg5b.zones.catalog.invalid.")],
            &[],
        );
        h.as_if_transferred("example.com.").await;
        let (path, text) = h.replication.state.lock().expect("state mutex").snapshot();
        write_snapshot(&path, &text).expect("write the transfer state");

        h.catalogs.vouch_for_members(&h.replication).await;

        assert!(
            h.holds("example.com.").await,
            "its master answered within EXPIRE, so the copy stands"
        );
    }

    /// The master a zone is being replicated from, for the group tests.
    fn master_of(h: &Harness, zone: &str) -> Vec<String> {
        h.secondaries
            .specs()
            .into_iter()
            .filter(|spec| spec.zone.as_ref() == nm(zone).as_ref())
            .map(|spec| spec.master.to_string())
            .collect()
    }

    /// A catalog whose member carries `group.<id>` values.
    fn grouped_catalog(serial: u32, id: &str, zone: &str, groups: &[&str]) -> Zone {
        let extra: String = groups
            .iter()
            .map(|g| format!("group.{id}.zones.catalog.invalid. 0 TXT \"{g}\"\n"))
            .collect();
        catalog_zone("catalog.invalid.", serial, &[(id, zone)], &extra)
    }

    /// RFC 9432 §4.3.2, the point of #48: a group value the operator mapped
    /// fetches the member from somewhere else than the catalog's own master.
    ///
    /// Watched failing with the group table empty: the member came from
    /// 192.0.2.1, the catalog's master.
    #[tokio::test]
    async fn a_mapped_group_fetches_the_member_from_its_own_master() {
        let h = Harness::grouped(
            "catalog-group",
            "catalog.invalid.",
            &[("operator-x", &["192.0.2.9"])],
        );
        h.publish(grouped_catalog(
            1,
            "nj2xg5b",
            "example.com.",
            &["operator-x"],
        ))
        .await;

        assert_eq!(
            master_of(&h, "example.com."),
            vec!["192.0.2.9:53".to_string()],
            "the group's master, not the catalog's"
        );
        assert_eq!(
            h.membership().lines().last(),
            Some("example.com. nj2xg5b.zones.catalog.invalid. operator-x"),
            "and the sidecar records which group was in force"
        );
    }

    /// A group nothing maps is ignored, which is §4.3.2's "the consumer ... MAY
    /// choose to process all, some, or none of them" — and is what every fleet
    /// with one class of member zone gets.
    #[tokio::test]
    async fn an_unmapped_group_changes_nothing() {
        let h = Harness::grouped(
            "catalog-group-unmapped",
            "catalog.invalid.",
            &[("operator-x", &["192.0.2.9"])],
        );
        h.publish(grouped_catalog(
            1,
            "nj2xg5b",
            "example.com.",
            &["somebody-else"],
        ))
        .await;

        assert_eq!(
            master_of(&h, "example.com."),
            vec!["192.0.2.1:53".to_string()],
            "the catalog's own master"
        );
        assert_eq!(
            h.membership().lines().last(),
            Some("example.com. nj2xg5b.zones.catalog.invalid. -")
        );
    }

    /// Two mapped groups naming different masters is an instruction with no
    /// answer in §4.3.2, so the member is not provisioned at all: choosing the
    /// first would be a silent decision about what is being served.
    #[tokio::test]
    async fn two_groups_naming_different_masters_refuse_the_member() {
        let h = Harness::grouped(
            "catalog-group-clash",
            "catalog.invalid.",
            &[
                ("operator-x", &["192.0.2.9"]),
                ("operator-y", &["192.0.2.8"]),
            ],
        );
        h.publish(grouped_catalog(
            1,
            "nj2xg5b",
            "example.com.",
            &["operator-x", "operator-y"],
        ))
        .await;

        assert!(
            !h.secondaries.replicates(nm("example.com.").as_ref()),
            "a member nobody can say how to fetch is not fetched"
        );
        assert!(
            !h.membership().contains("example.com."),
            "and nothing claims to have provisioned it"
        );
    }

    /// The same two values naming the *same* configuration is not a conflict:
    /// §4.3.2 lets a producer assign more than one group to a member, and two
    /// labels for one arrangement is the ordinary way that happens.
    #[tokio::test]
    async fn two_groups_naming_one_master_are_not_a_conflict() {
        let h = Harness::grouped(
            "catalog-group-agree",
            "catalog.invalid.",
            &[("operator-x", &["192.0.2.9"]), ("also-x", &["192.0.2.9"])],
        );
        h.publish(grouped_catalog(
            1,
            "nj2xg5b",
            "example.com.",
            &["operator-x", "also-x"],
        ))
        .await;

        assert_eq!(
            master_of(&h, "example.com."),
            vec!["192.0.2.9:53".to_string()]
        );
    }

    /// §5.4's reset is about the member *node* label. A group changing under an
    /// unchanged label is the same zone fetched from somewhere else, so the
    /// refresh task is replaced and the data is not.
    ///
    /// Watched failing without the group in the sidecar row: the reconcile saw
    /// an unchanged node, did nothing, and the member kept coming from the old
    /// master.
    #[tokio::test]
    async fn a_changed_group_re_points_the_member_without_resetting_it() {
        let h = Harness::grouped(
            "catalog-group-move",
            "catalog.invalid.",
            &[
                ("operator-x", &["192.0.2.9"]),
                ("operator-y", &["192.0.2.8"]),
            ],
        );
        h.publish(grouped_catalog(
            1,
            "nj2xg5b",
            "example.com.",
            &["operator-x"],
        ))
        .await;
        h.as_if_transferred("example.com.").await;

        h.publish(grouped_catalog(
            2,
            "nj2xg5b",
            "example.com.",
            &["operator-y"],
        ))
        .await;

        assert_eq!(
            master_of(&h, "example.com."),
            vec!["192.0.2.8:53".to_string()],
            "fetched from the new group's master"
        );
        assert!(
            h.member_file("example.com.").exists(),
            "and the copy on disk is not thrown away: §5.4's reset is about the \
             node label, which did not change"
        );
        assert!(
            !h.holds("example.com.").await,
            "though it stops being *served* until the new master answers, which \
             is the rule every secondary gets: nothing has vouched for the age \
             of a copy that came from somewhere else"
        );
        assert_eq!(
            h.membership().lines().last(),
            Some("example.com. nj2xg5b.zones.catalog.invalid. operator-y")
        );
    }

    /// RFC 9432 §6, the point of #49: the refusals §5.2 says to log are also
    /// reported, because a member this server declined has no zone and so no
    /// row in `rdnsctl status`.
    ///
    /// Rebuilt every reconcile, so a member refused once and accepted later
    /// stops being reported — which the second half asserts.
    #[tokio::test]
    async fn a_refused_member_is_reported_until_it_stops_being_refused() {
        let h = Harness::new("catalog-report", &["catalog.invalid."], &["example.com."]);
        h.publish(catalog_zone(
            "catalog.invalid.",
            1,
            &[("nj2xg5b", "example.com."), ("nvxxezj", "example.net.")],
            "",
        ))
        .await;

        let report = h.catalogs.report().await;
        assert_eq!(report.len(), 1);
        assert_eq!(
            report[0].members.len(),
            1,
            "one provisioned: {:?}",
            report[0].members
        );
        assert_eq!(report[0].refused.total, 1);
        assert_eq!(report[0].refused.shown[0].0, nm("example.com."));
        assert!(
            report[0].refused.shown[0].1.contains("configuration"),
            "and why: {}",
            report[0].refused.shown[0].1
        );

        // The clash goes away because the catalog stops listing it.
        h.publish(catalog_zone(
            "catalog.invalid.",
            2,
            &[("nvxxezj", "example.net.")],
            "",
        ))
        .await;
        assert_eq!(
            h.catalogs.report().await[0].refused.total,
            0,
            "a refusal is a property of the catalog as it stands, not a log"
        );
    }

    /// The refusal list is bounded, and says how much it is not showing: a
    /// producer's member list is what §6 warns can be millions.
    #[tokio::test]
    async fn the_refusal_list_is_bounded_and_says_so() {
        let refused: Vec<String> = (0..MAX_REFUSALS_REPORTED + 4)
            .map(|i| format!("clash{i}.test."))
            .collect();
        let configured: Vec<&str> = refused.iter().map(String::as_str).collect();
        let h = Harness::new("catalog-report-bound", &["catalog.invalid."], &configured);
        let members: Vec<(String, &str)> = refused
            .iter()
            .enumerate()
            .map(|(i, zone)| (format!("m{i}"), zone.as_str()))
            .collect();
        let members: Vec<(&str, &str)> = members
            .iter()
            .map(|(id, zone)| (id.as_str(), *zone))
            .collect();
        h.publish(catalog_zone("catalog.invalid.", 1, &members, ""))
            .await;

        let report = h.catalogs.report().await;
        assert_eq!(report[0].refused.total, MAX_REFUSALS_REPORTED + 4);
        assert_eq!(
            report[0].refused.shown.len(),
            MAX_REFUSALS_REPORTED,
            "bounded, and the total says how many it is not showing"
        );
    }

    /// A group value is octets, and the sidecar is whitespace-separated text.
    /// Every byte has to survive the round trip or the next reconcile reads a
    /// different group than the one in force.
    #[test]
    fn a_group_value_survives_the_sidecar() {
        for group in [
            Some(b"plain".to_vec()),
            Some(b"two words".to_vec()),
            Some(b"-".to_vec()),
            Some(b"say \"hi\"".to_vec()),
            Some(vec![0x00, 0xff, b'\\']),
            Some(Vec::new()),
            None,
        ] {
            let field = write_group(group.as_deref());
            assert!(
                !field.contains(char::is_whitespace),
                "{field:?} would end the field early"
            );
            assert_eq!(
                read_group(Some(&field)).expect("it decodes"),
                group,
                "{field:?}"
            );
        }
    }

    /// A file a build older than #48 wrote has two fields, and meant "no
    /// group", which is what that build did.
    #[test]
    fn a_two_field_sidecar_row_reads_as_no_group() {
        let row = parse_row("example.com. nj2xg5b.zones.catalog.invalid.").expect("two fields");
        assert_eq!(row.zone, nm("example.com."));
        assert_eq!(row.group, None);
        assert!(parse_row("example.com. a.zones.b. - extra").is_err());
    }

    /// The sidecar reads back as what was written, member node included: it is
    /// the only record of which catalog a zone came from, and §5.3 turns on it.
    #[test]
    fn the_membership_sidecar_round_trips() {
        let dir = ScratchDir::new("catalog-sidecar");
        let path = membership_path(dir.path());
        let mut membership = Membership::load(&path);
        membership.set(MemberRow {
            zone: nm("example.com."),
            node: nm("nj2xg5b.zones.catalog.invalid."),
            group: None,
        });
        membership.set(MemberRow {
            zone: nm("example.net."),
            node: nm("nvxxezj.zones.other.invalid."),
            group: None,
        });
        membership.forget(nm("example.net.").as_ref());
        let (path, text) = membership.snapshot();
        write_snapshot(&path, &text).expect("write");

        let read = Membership::load(&path);
        assert_eq!(
            read.owner_of(nm("example.com.").as_ref()),
            Some(nm("catalog.invalid.")),
            "the catalog is the member node less its two leading labels"
        );
        assert_eq!(read.owner_of(nm("example.net.").as_ref()), None);
        assert_eq!(
            read.members_of(nm("catalog.invalid.").as_ref()),
            vec![MemberRow {
                zone: nm("example.com."),
                node: nm("nj2xg5b.zones.catalog.invalid."),
                group: None,
            }]
        );
    }
}
