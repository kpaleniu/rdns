use crate::denial_wire::{base32hex_decode, canonical_sort_key};
use crate::record_types as rt;
use crate::Class;
use crate::Rtype;
use crate::Serial;
use crate::Ttl;
use crate::{Name, NameRef, Qtype, RecordData, ResourceRecord};
use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

mod checks;
mod parse;
mod rdata;

pub use parse::{parse_zone_file, parse_zone_file_at};
pub(crate) use rdata::format_dnssec_time;

/// A single DNS resource record stored in a zone
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub name: Name,
    pub ttl: Ttl,
    pub class: Class,
    pub rdata: RecordData,
}

/// In-memory DNS zone storage.
///
/// Records live in one vector, reached through an index keyed by owner name
/// only. Keying on (name, type) would answer "which records of this type are
/// here" but not "does this name exist at all" — the question that tells
/// NXDOMAIN from NODATA — without probing 65535 types.
///
/// `origin` and `records` are private because the index is derived from both:
/// a record appended behind its back leaves the zone answering NXDOMAIN for
/// data it holds.
#[derive(Debug, Clone)]
pub struct Zone {
    origin: Name,
    records: Vec<ZoneRecord>,
    /// Positions in `records`, by the folded wire form of the owner name.
    ///
    /// A name that exists only because something below it does — an empty
    /// non-terminal (RFC 4592 §2.2.2) — is a key with **no positions**. It was
    /// a second `HashSet` until 2026-09-05, which made every level of a miss
    /// walk hash the name twice to ask two halves of one question
    /// (`TODO.md` #22): "is this a node of the zone, and does it have records".
    /// Keyed on the *folded* wire form, because a `HashMap` probe needs a
    /// borrowed key and `Name`'s own case-insensitive `Hash` cannot be reached
    /// through `Borrow` without the `unsafe` cast `str` uses. `Box<[u8]>`
    /// borrows as `[u8]`, so a lookup costs a fold only when the name arrived
    /// in mixed case.
    index: HashMap<Box<[u8]>, Vec<usize>>,
    /// The NSEC chain, keyed by canonical sort order, and the NSEC3 chain,
    /// keyed by hash — both empty for an unsigned zone.
    ///
    /// Ordered, where the name index is not, because a denial asks a range
    /// question: which record's span contains this name.
    nsec_chain: BTreeMap<Vec<u8>, usize>,
    nsec3_chain: BTreeMap<Vec<u8>, usize>,
    /// The per-query ancestor walks this zone can skip. See [`Shortcuts`].
    shortcuts: Shortcuts,
}

/// Which of the per-query ancestor walks a zone never needs, because it holds
/// nothing that could answer one.
///
/// Each is false for the ordinary zone and saves a hash lookup per label of a
/// name the client chose — and, for two of them, the fold that builds the key.
///
/// One value rather than three `bool` fields, because two places maintain them:
/// [`Zone::add_record`] as records arrive and [`Zone::reindex`] when the origin
/// moves. Adding `dnames` as a fourth field went to `reindex` alone, so a zone
/// built a record at a time held a DNAME that [`Zone::dname_above`] could not
/// find — caught by its own test, and the reason this is one value
/// (`CLAUDE.md` §7).
///
/// Stale in the false direction each one serves a wrong answer: no wildcard
/// synthesis, no referral — which answers authoritatively for a child's names,
/// the defect `CLAUDE.md` §8 opens with — and no redirection.
#[derive(Debug, Clone, Copy, Default)]
struct Shortcuts {
    /// Any record owned by a wildcard name. 23% of a miss in a 10k-record zone
    /// with no wildcards.
    wildcards: bool,
    /// Any NS RRset below the apex, which is what a zone cut is
    /// (RFC 1034 §4.2.1).
    delegations: bool,
    /// Any DNAME, which redirects every name below its owner (RFC 6672 §2.2).
    dnames: bool,
}

impl Shortcuts {
    /// Turn on whatever one record makes possible.
    ///
    /// `at_apex` is the caller's to say, because [`Zone::reindex`] decides it
    /// against a *new* origin: moving the apex up turns the old apex's own NS
    /// RRset into a delegation.
    fn note(&mut self, key: &[u8], rtype: Rtype, at_apex: bool) {
        // The wildcard label, in wire form: one octet of length, then `*`.
        self.wildcards |= key.starts_with(b"\x01*");
        self.delegations |= rtype == rt::NS && !at_apex;
        self.dnames |= rtype == rt::DNAME;
    }
}

/// A name resolved against a zone: what kind of name it is, and where its
/// records are. From [`Zone::locate`].
///
/// Holds positions rather than records so that asking for a second type costs
/// nothing, and so that a caller testing for existence allocates nothing at all.
pub struct Located<'a> {
    zone: &'a Zone,
    kind: NameKind,
    positions: &'a [usize],
}

impl<'a> Located<'a> {
    /// What kind of name this is, which is what tells NXDOMAIN from NODATA when
    /// [`Located::of_type`] comes back empty (RFC 4592 §2.2.2).
    pub fn kind(&self) -> &NameKind {
        &self.kind
    }

    /// The zone this was located in, so a caller that already has a `Located`
    /// need not carry the zone beside it — one argument that can disagree with
    /// another is one too many (`CLAUDE.md` §17).
    pub fn zone(&self) -> &'a Zone {
        self.zone
    }

    pub fn into_kind(self) -> NameKind {
        self.kind
    }

    /// The records here that `qtype` selects. What ANY means, and why the DNSSEC
    /// meta types are excluded, is [`Qtype::matches`]'s to say.
    pub fn of_type(&self, qtype: Qtype) -> impl Iterator<Item = &'a ZoneRecord> + '_ {
        let zone = self.zone;
        self.positions
            .iter()
            .map(move |&i| &zone.records[i])
            .filter(move |r| qtype.matches(r.rdata.rtype()))
    }

    /// Whether anything here is of `qtype`. The question `query(..).is_empty()`
    /// was asking, without building the `Vec` it threw away.
    pub fn has_type(&self, qtype: Qtype) -> bool {
        self.of_type(qtype).next().is_some()
    }
}

/// Why a name has an answer in this zone, or has none (RFC 1034 §4.3.2).
///
/// Not a bool: three of the four are "the name exists", and an empty
/// non-terminal and a wildcard match each owe a *different* DNSSEC proof (see
/// [`crate::dnssec_answer::push_negative_proof`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameKind {
    /// The zone holds records at this exact name.
    Exact,
    /// The name has descendants and no records of its own (RFC 4592 §2.2.2).
    /// It exists, and every type at it is NODATA.
    EmptyNonTerminal,
    /// The name is not in the zone, and this wildcard is its source of
    /// synthesis (RFC 4592 §3.3.1). Absolute and down-cased.
    Wildcard(Name),
    /// Not in the zone at all: NXDOMAIN.
    NotFound,
}

/// Which of the two chains a denial record belongs to.
enum Chain {
    Nsec,
    Nsec3,
}

impl Zone {
    /// Create a new zone with the given origin (e.g., `example.com.`)
    pub fn new(origin: Name) -> Self {
        Zone {
            origin,
            records: Vec::new(),
            index: HashMap::new(),
            nsec_chain: BTreeMap::new(),
            nsec3_chain: BTreeMap::new(),
            shortcuts: Shortcuts::default(),
        }
    }

    /// The zone's apex name, absolute — as every [`Name`] is.
    pub fn origin(&self) -> NameRef<'_> {
        self.origin.as_ref()
    }

    /// Every record in the zone, in load order.
    pub fn records(&self) -> &[ZoneRecord] {
        &self.records
    }

    /// Move the zone's apex, as a top-level `$ORIGIN` does.
    ///
    /// No record moves: a [`Name`] is absolute, so an owner name means the same
    /// thing before and after. What the reindex rebuilds is the bookkeeping that
    /// is *about* the apex — an NS RRset at the old apex becomes a zone cut
    /// under the new one.
    pub fn set_origin(&mut self, origin: Name) {
        self.origin = origin;
        self.reindex();
    }

    /// Add a record to the zone
    pub fn add_record(&mut self, record: ZoneRecord) {
        // Owned: the key becomes an index entry, and the statements below need
        // `&mut self`.
        let key = record.name.as_ref().folded().into_owned();
        let position = self.records.len();
        let at_apex = key == *self.origin_key();
        self.shortcuts.note(&key, record.rdata.rtype(), at_apex);
        self.note_non_terminals(&key);
        self.index
            .entry(key.into_boxed_slice())
            .or_default()
            .push(position);
        match self.chain_key(&record) {
            Some((Chain::Nsec, k)) => {
                self.nsec_chain.insert(k, position);
            }
            Some((Chain::Nsec3, k)) => {
                self.nsec3_chain.insert(k, position);
            }
            None => {}
        }
        self.records.push(record);
    }

    /// Whether the zone holds records at exactly this name — no wildcard.
    ///
    /// Denial of existence needs the literal question, because a name reached
    /// only through a wildcard is exactly the name a wildcard answer must prove
    /// does *not* exist (RFC 4035 §3.1.3). [`Zone::name_exists`] is the other
    /// question.
    pub fn holds_name(&self, name: NameRef<'_>) -> bool {
        // Records, not merely a node: an empty non-terminal is in `index` with
        // no positions, and it is exactly the name a wildcard answer has to
        // prove does not exist.
        let mut buf = Vec::new();
        self.index
            .get(name.folded_in(&mut buf).as_wire())
            .is_some_and(|positions| !positions.is_empty())
    }

    pub fn has_nsec_chain(&self) -> bool {
        !self.nsec_chain.is_empty()
    }

    pub fn has_nsec3_chain(&self) -> bool {
        !self.nsec3_chain.is_empty()
    }

    /// Any one record from the NSEC3 chain, for reading the salt and iteration
    /// count the chain was built with.
    pub fn any_nsec3(&self) -> Option<&ZoneRecord> {
        self.nsec3_chain
            .values()
            .next()
            .map(|position| &self.records[*position])
    }

    /// The NSEC whose span contains `name` — the record that denies it exists.
    ///
    /// Exclusive at the low end: an NSEC *at* `name` proves the opposite. When
    /// nothing sorts before `name` the answer is the last record, because the
    /// chain is a loop back to the apex (RFC 4034 §4.1.1).
    pub fn nsec_covering(&self, name: NameRef<'_>) -> Option<&ZoneRecord> {
        let key = canonical_sort_key(name);
        let position = self
            .nsec_chain
            .range(..key)
            .next_back()
            .or_else(|| self.nsec_chain.iter().next_back())?;
        Some(&self.records[*position.1])
    }

    /// The NSEC3 whose span contains `hash`. Same rule, in hash order.
    pub fn nsec3_covering(&self, hash: &[u8]) -> Option<&ZoneRecord> {
        // `..hash`, not `..hash.to_vec()`: the bound only has to compare, and
        // the copy was an allocation per covering lookup.
        let position = self
            .nsec3_chain
            .range::<[u8], (Bound<&[u8]>, Bound<&[u8]>)>((Bound::Unbounded, Bound::Excluded(hash)))
            .next_back()
            .or_else(|| self.nsec3_chain.iter().next_back())?;
        Some(&self.records[*position.1])
    }

    /// Where a denial record belongs in the ordered chains, if it is one.
    ///
    /// An NSEC is filed under its owner name; an NSEC3 under the hash in its
    /// owner's first label, which is what the chain is ordered by. A label that
    /// will not decode is left out rather than filed under something wrong.
    fn chain_key(&self, record: &ZoneRecord) -> Option<(Chain, Vec<u8>)> {
        match record.rdata.rtype() {
            crate::record_types::NSEC => {
                Some((Chain::Nsec, canonical_sort_key(record.name.as_ref())))
            }
            crate::record_types::NSEC3 => {
                // The hash is the first label, and a label is octets — so it is
                // taken as octets rather than by splitting text on a `.` that
                // may be inside one.
                let label = record.name.as_ref().labels().next()?;
                Some((
                    Chain::Nsec3,
                    base32hex_decode(std::str::from_utf8(label).ok()?).ok()?,
                ))
            }
            _ => None,
        }
    }

    /// Query records by name and type.
    ///
    /// A wildcard is consulted only when the queried name does not exist at
    /// all: an existing name shadows it entirely, types it does not carry
    /// included, and so does an empty non-terminal (RFC 1034 §4.3.3,
    /// RFC 4592 §2.2.1 and §4.4).
    pub fn query(&self, name: NameRef<'_>, qtype: Qtype) -> Vec<&ZoneRecord> {
        self.query_with_kind(name, qtype).1
    }

    /// [`Zone::query`], and the [`NameKind`] it had to work out anyway.
    ///
    /// For the caller that needs both, which is the answer path: what kind of
    /// name this is decides NXDOMAIN against NODATA (RFC 4592 §2.2.2) when the
    /// records come back empty. Asking `name_kind` separately walks the
    /// ancestors a second time and folds the name a second time to do it —
    /// twice per negative answer, which is the shape a random-subdomain flood
    /// sends.
    fn query_with_kind(&self, name: NameRef<'_>, qtype: Qtype) -> (NameKind, Vec<&ZoneRecord>) {
        let located = self.locate(name);
        let records: Vec<&ZoneRecord> = located.of_type(qtype).collect();
        (located.kind, records)
    }

    /// Where `name` lands in this zone, without deciding a type yet.
    ///
    /// One closest-encloser walk, then as many type filters as the caller wants
    /// — and the caller that wants only "is there anything here" pays no `Vec`
    /// for the answer. [`Zone::query`] is this plus a `collect`.
    pub fn locate(&self, name: NameRef<'_>) -> Located<'_> {
        let mut buf = Vec::new();
        let key = name.folded_in(&mut buf);
        let kind = self.name_kind_of_key(key);
        let at = match kind {
            NameKind::Exact => self.index.get(key.as_wire()),
            NameKind::Wildcard(ref wildcard) => self.index.get(wildcard.as_ref().as_wire()),
            NameKind::EmptyNonTerminal | NameKind::NotFound => None,
        };
        Located {
            zone: self,
            kind,
            positions: at.map_or(&[][..], Vec::as_slice),
        }
    }

    /// The apex SOA, borrowed.
    ///
    /// `Option` because a `Zone` can be built record by record; one that came
    /// from a file has an SOA or it did not load.
    fn apex_soa(&self) -> Option<&ZoneRecord> {
        self.query(self.origin(), Qtype::of(rt::SOA))
            .first()
            .copied()
    }

    /// The apex SOA as a standalone record, owner name absolute — the form that
    /// goes into a message.
    ///
    /// Lived in three places at once (`TODO.md` #33d): `notify::soa_record`,
    /// public and in a module about a different protocol, plus byte-identical
    /// private copies in `xfr` and `ixfr`. It belongs where the data is.
    pub fn apex_soa_record(&self) -> Option<ResourceRecord> {
        self.apex_soa().map(|soa| ResourceRecord {
            name: self.origin.clone(),
            class: soa.class,
            ttl: soa.ttl,
            rdata: soa.rdata.clone(),
        })
    }

    /// The serial from the apex SOA, if the zone has one.
    pub fn serial(&self) -> Option<Serial> {
        self.apex_soa().and_then(|soa| match soa.rdata.parse() {
            Ok(crate::ParsedRecord::SOA { serial, .. }) => Some(serial),
            _ => None,
        })
    }

    /// Whether `record` is this zone's apex SOA.
    ///
    /// The normalization is the point: an owner name in a `Zone` may be `@` or
    /// relative, and two of the five places that asked this question compared
    /// [`ZoneRecord::name`] raw (`TODO.md` #33f). Callers holding a
    /// [`ResourceRecord`] off the wire and a zone *name* — `xfr`, `journal` —
    /// have no `Zone` to ask and still write it out.
    pub fn is_apex_soa(&self, record: &ZoneRecord) -> bool {
        record.rdata.rtype() == rt::SOA && record.name == self.origin
    }

    /// Whether the zone holds anything at `name` — by that name, because
    /// something below it exists, or through a wildcard. The NXDOMAIN question;
    /// an existing name with no record of the queried type is NODATA.
    pub fn name_exists(&self, name: NameRef<'_>) -> bool {
        !matches!(self.name_kind(name), NameKind::NotFound)
    }

    /// Why `name` has an answer here, or has none. See [`NameKind`].
    pub fn name_kind(&self, name: NameRef<'_>) -> NameKind {
        let mut buf = Vec::new();
        self.name_kind_of_key(name.folded_in(&mut buf))
    }

    /// [`Zone::name_kind`] for a name already folded.
    ///
    /// A closest-encloser walk, not a single lookup: synthesis reaches any
    /// depth (RFC 4592 §3.3.2 answers `_telnet._tcp.host1.example.` from
    /// `*.example.`). The walk stops at the first ancestor that exists and only
    /// the wildcard directly below it may answer (§3.3.1) — an existing name,
    /// empty non-terminal included, ends the search (§4.4).
    fn name_kind_of_key(&self, key: NameRef<'_>) -> NameKind {
        // One hash for both questions: present with records is `Exact`, present
        // without is an empty non-terminal (`TODO.md` #22).
        match self.index.get(key.as_wire()) {
            Some(positions) if !positions.is_empty() => return NameKind::Exact,
            Some(_) => return NameKind::EmptyNonTerminal,
            None => {}
        }

        let origin = self.origin_key();
        // `ancestors` yields this name first, which the lookup above has
        // already answered for, so the walk starts at the parent.
        for encloser in key.ancestors().skip(1) {
            if encloser.as_wire().len() < origin.len() {
                // Out of the zone: the query was never in it.
                return NameKind::NotFound;
            }
            if !self.node_exists(encloser) {
                continue;
            }
            // The closest encloser. A wildcard below a zone cut is the child's
            // data, not ours (RFC 4592 §2.2.1), so a delegation between here
            // and the apex means a referral rather than synthesis.
            if !self.shortcuts.wildcards {
                return NameKind::NotFound;
            }
            if self.delegation_for_key(encloser).is_some() {
                return NameKind::NotFound;
            }
            let Ok(wildcard) = Name::prefixed(b"*", encloser) else {
                // Only if the wildcard would break the 255-octet limit, which
                // means nothing could be stored at it either.
                return NameKind::NotFound;
            };
            return if self.index.contains_key(wildcard.as_ref().as_wire()) {
                NameKind::Wildcard(wildcard)
            } else {
                NameKind::NotFound
            };
        }
        NameKind::NotFound
    }

    /// Whether this name is a node of the zone: it has records, or it has
    /// descendants (RFC 4592 §2.2.2). Takes a lookup key.
    ///
    /// One lookup, because both kinds of node are in `index`. This is the walk's
    /// inner loop — once per label of a name the client chose — and it asked
    /// two maps until #22.
    fn node_exists(&self, key: NameRef<'_>) -> bool {
        self.index.contains_key(key.as_wire())
    }

    /// The delegation point at or above `name`: the deepest ancestor-or-self
    /// other than the apex with an NS RRset (RFC 1034 §4.2.1).
    ///
    /// `Some` means the answer owes a referral — NS RRset, glue, and AA
    /// clear. The apex is excluded: its NS RRset is this zone's own.
    pub fn delegation_for(&self, name: NameRef<'_>) -> Option<Name> {
        // Before the fold, not only inside `delegation_for_key`: with no cut to
        // find, folding the name is a copy made for nothing.
        if !self.shortcuts.delegations {
            return None;
        }
        let mut buf = Vec::new();
        self.delegation_for_key(name.folded_in(&mut buf))
    }

    fn delegation_for_key(&self, key: NameRef<'_>) -> Option<Name> {
        if !self.shortcuts.delegations {
            return None;
        }
        let origin = self.origin_key();
        for candidate in key.ancestors() {
            let at_apex = candidate.as_wire() == origin.as_ref();
            if !at_apex && self.has_type(candidate, rt::NS) {
                return Some(candidate.to_owned());
            }
            if at_apex || candidate.as_wire().len() < origin.len() {
                return None;
            }
        }
        None
    }

    /// The DNAME that redirects `name`: the shallowest **strict** ancestor
    /// owning one (RFC 6672 §2.2).
    ///
    /// Strict, because "a DNAME RR redirects DNS names subordinate to its owner
    /// name; the owner name of a DNAME is not redirected itself" (§2.3). Table
    /// 1's second row is the case: QNAME `example.com.` against owner
    /// `example.com.` is `<no match>` unless QTYPE is DNAME, and then the DNAME
    /// is an ordinary record at the name rather than a redirection.
    ///
    /// Shallowest rather than deepest, which is the order RFC 1034 §4.3.2's
    /// "start matching down, label by label" meets them in. It can only differ
    /// in a zone `checks::check_dname_rules` refuses, since a second DNAME below
    /// the first is a record at a subdomain of a DNAME owner (§2.4) — but a zone
    /// that arrived by transfer never met that check, and occluding from the
    /// top is the answer that does not depend on how deep the violation goes.
    ///
    /// Returns the record, not the name: the caller needs its owner to echo,
    /// its target to substitute and its TTL for the synthesized CNAME (§3.1),
    /// and looking any of them up again is the repeat `TODO.md` #25a removed.
    pub fn dname_above(&self, name: NameRef<'_>) -> Option<&ZoneRecord> {
        // Before the fold, as `delegation_for` does it: with no DNAME in the
        // zone the folded copy is made for nothing.
        if !self.shortcuts.dnames {
            return None;
        }
        let mut buf = Vec::new();
        self.dname_above_key(name.folded_in(&mut buf))
    }

    /// [`Zone::dname_above`] for a name already folded.
    fn dname_above_key(&self, key: NameRef<'_>) -> Option<&ZoneRecord> {
        if !self.shortcuts.dnames {
            return None;
        }
        let origin = self.origin_key();
        let mut found = None;
        // From the parent, so the owner is not redirected by its own DNAME, and
        // on to the apex without stopping: the last one seen is the shallowest.
        for candidate in key.ancestors().skip(1) {
            if candidate.as_wire().len() < origin.len() {
                break;
            }
            if let Some(record) = self.first_of_type(candidate, rt::DNAME) {
                found = Some(record);
            }
            if candidate.as_wire() == origin.as_ref() {
                break;
            }
        }
        found
    }

    /// Whether there is an RRset of `rtype` at exactly this key. An empty
    /// non-terminal has no positions, so it answers false without a special
    /// case.
    fn has_type(&self, key: NameRef<'_>, rtype: Rtype) -> bool {
        self.first_of_type(key, rtype).is_some()
    }

    /// The first record of `rtype` at exactly this key, or `None`.
    ///
    /// [`Zone::has_type`] is this question with the answer thrown away. DNAME
    /// is a singleton type (RFC 6672 §2.4), so for that one "the first" is
    /// "the one".
    fn first_of_type(&self, key: NameRef<'_>, rtype: Rtype) -> Option<&ZoneRecord> {
        self.index
            .get(key.as_wire())?
            .iter()
            .map(|&i| &self.records[i])
            .find(|r| r.rdata.rtype() == rtype)
    }

    /// Record every ancestor of `key`, up to the apex, as a name that exists.
    ///
    /// Stops at the first ancestor already known: ancestors are always noted
    /// all the way to the apex, so one present means the rest are. Keeps index
    /// construction linear in the zone rather than in names × labels.
    ///
    /// "Known" now includes an ancestor that has records of its own, which is
    /// the same guarantee for the same reason — a record's own insertion noted
    /// *its* ancestors.
    fn note_non_terminals(&mut self, key: &[u8]) {
        // Owned: the loop below takes `&mut self`.
        let origin = self.origin_key().into_owned();
        let mut name = key.to_vec();
        while let Some(parent) = parent_key(&name) {
            if parent.len() < origin.len() {
                // An owner outside the zone — foreign glue, say. Its ancestors
                // are somebody else's names and do not exist here.
                return;
            }
            let parent = parent.to_vec();
            let reached_apex = parent == origin;
            match self.index.entry(parent.clone().into_boxed_slice()) {
                Entry::Occupied(_) => return,
                Entry::Vacant(slot) => slot.insert(Vec::new()),
            };
            if reached_apex {
                return;
            }
            name = parent;
        }
    }

    /// The apex, folded. Borrowed for an already
    /// lower-case origin: two walks ask for this per query.
    fn origin_key(&self) -> Cow<'_, [u8]> {
        self.origin.as_ref().folded()
    }

    /// Rebuild the index from `records`.
    fn reindex(&mut self) {
        let origin_key = self.origin_key().into_owned();
        let keys: Vec<(Vec<u8>, Rtype, bool)> = self
            .records
            .iter()
            .map(|r| {
                let key = r.name.as_ref().folded().into_owned();
                let at_apex = key == origin_key;
                (key, r.rdata.rtype(), at_apex)
            })
            .collect();
        self.index.clear();
        // Recomputed, not carried: `set_origin` turns an apex NS RRset into a
        // zone cut, and a wildcard at the old apex into one below the new.
        self.shortcuts = Shortcuts::default();
        for (position, (key, rtype, at_apex)) in keys.into_iter().enumerate() {
            self.shortcuts.note(&key, rtype, at_apex);
            self.note_non_terminals(&key);
            self.index
                .entry(key.into_boxed_slice())
                .or_default()
                .push(position);
        }

        // The chains are keyed by the absolute name too, so moving the origin
        // moves them.
        let chain_keys: Vec<Option<(Chain, Vec<u8>)>> =
            self.records.iter().map(|r| self.chain_key(r)).collect();
        self.nsec_chain.clear();
        self.nsec3_chain.clear();
        for (position, key) in chain_keys.into_iter().enumerate() {
            match key {
                Some((Chain::Nsec, k)) => {
                    self.nsec_chain.insert(k, position);
                }
                Some((Chain::Nsec3, k)) => {
                    self.nsec3_chain.insert(k, position);
                }
                None => {}
            }
        }
    }

    /// Whether `record_name` answers `query_name`, wildcards included. The
    /// definition of matching the index encodes; a test holds the two to the
    /// same answers.
    pub fn matches_query(&self, record_name: NameRef<'_>, query_name: NameRef<'_>) -> bool {
        if record_name == query_name {
            return true;
        }
        // Which wildcard reaches a name is a question about the whole zone —
        // the closest encloser decides it — so ask `name_kind` rather than
        // re-deriving it here.
        let mut buf = Vec::new();
        matches!(
            self.name_kind_of_key(query_name.folded_in(&mut buf)),
            NameKind::Wildcard(w) if w.as_ref() == record_name
        )
    }
}

/// The parent of a name in wire form, as octets.
///
/// [`NameRef::parent`] is the same step over a validated name; this one is for
/// the index's keys, which are octets because a `HashMap` probe has to borrow.
fn parent_key(key: &[u8]) -> Option<&[u8]> {
    let (&len, tail) = key.split_first()?;
    let len = len as usize;
    if len == 0 || tail.len() < len {
        return None;
    }
    Some(&tail[len..])
}

#[cfg(test)]
mod tests {

    use super::parse::absolutize;
    use super::rdata::{parse_dnssec_time, rdata_from_fields};
    use super::*;
    use crate::error::ZoneError;
    use crate::record_types;
    use crate::test_records::nm;
    use crate::testutil::ScratchDir;
    use crate::ParsedRecord;
    use std::net::Ipv4Addr;

    #[test]
    fn test_zone_creation() {
        let zone = Zone::new(nm("example.com"));
        assert_eq!(zone.origin, nm("example.com."));
    }

    /// Every question about "is this the apex SOA" compares owner names, and
    /// two of the five places that asked it compared the stored name raw
    /// (`TODO.md` #33f). Relativity is gone with the type — a `Name` is
    /// absolute — but case is not: RFC 4343 makes `EXAMPLE.com.` the same apex.
    #[test]
    fn the_apex_soa_is_found_under_a_differently_cased_owner_name() {
        let mut zone = Zone::new(nm("example.com."));
        zone.add_record(ZoneRecord {
            name: nm("ExAmPlE.CoM."),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::SOA {
                mname: nm("ns1.example.com."),
                rname: nm("admin.example.com."),
                serial: Serial::new(7),
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 300,
            })
            .unwrap(),
        });

        let soa = zone.apex_soa().expect("the apex SOA, however it is cased");
        assert!(zone.is_apex_soa(soa));
        assert_eq!(zone.serial(), Some(Serial::new(7)));
        assert_eq!(
            zone.apex_soa_record().expect("as a record").name,
            nm("example.com."),
            "the owner name compares case-insensitively (RFC 4343)"
        );
    }

    /// `has_delegations` skips the ancestor walk, so it decides whether a
    /// referral is found at all. Which NS records count is a fact about the
    /// *apex*, and `set_origin` moves the apex: raising it turns the old apex's
    /// own NS RRset into a zone cut (RFC 1034 §4.2.1).
    ///
    /// The mistake it catches is a `reindex` that rebuilds the index without
    /// re-deciding which NS records are cuts: the flag then keeps the answer the
    /// *old* apex gave, stays `false`, and the server answers authoritatively
    /// for a child's names — `CLAUDE.md` §8's opening defect, reached through an
    /// optimization rather than through the resolution logic. Watched failing
    /// that way, and it is the only test in the tree that catches it.
    ///
    /// Dropping the `= false` reset alone does *not* fail, which is worth
    /// knowing: that leaves the flag stale only in the direction that costs a
    /// wasted walk.
    #[test]
    fn test_moving_the_apex_turns_the_old_apex_ns_into_a_delegation() {
        let mut zone = parse_zone_file(
            concat!(
                "@   IN SOA ns1 admin ( 1 3600 600 604800 300 )\n",
                "@   IN NS  ns1.example.com.\n",
                "www IN A   192.0.2.10\n",
            ),
            "example.com.",
        )
        .unwrap();
        assert_eq!(
            zone.delegation_for(nm("www.example.com.").as_ref()),
            None,
            "at its own apex an NS RRset is the zone's own, not a cut"
        );

        zone.set_origin(nm("com."));
        assert_eq!(
            zone.delegation_for(nm("www.example.com.").as_ref()),
            Some(nm("example.com.")),
            "example.com. is a child now, and it has an NS RRset"
        );
    }

    /// The other way the flag is maintained: a zone gaining its first cut after
    /// it was built, which is the incremental path rather than the reindex.
    #[test]
    fn test_a_delegation_added_after_load_is_still_found() {
        let mut zone = parse_zone_file("www IN A 192.0.2.10\n", "example.com.").unwrap();
        assert_eq!(
            zone.delegation_for(nm("host.sub.example.com.").as_ref()),
            None
        );

        zone.add_record(ZoneRecord {
            name: nm("sub.example.com."),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::NS(nm("ns1.sub.example.com."))).unwrap(),
        });
        assert_eq!(
            zone.delegation_for(nm("host.sub.example.com.").as_ref()),
            Some(nm("sub.example.com."))
        );
    }

    #[test]
    fn test_simple_zone_file_parse() {
        let zone_content = r#"
$ORIGIN example.com.
$TTL 3600
@   IN  SOA ns1.example.com. admin.example.com. 2021010101 3600 1800 604800 86400
@   IN  NS  ns1.example.com.
@   IN  A   192.0.2.1
www IN  A   192.0.2.2
mail IN A   192.0.2.3
        "#;

        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        assert_eq!(zone.origin, nm("example.com."));
        assert!(zone.records.len() >= 4);
    }

    /// A record in a class this zone does not serve must not load: the index is
    /// class-blind, so it would answer IN questions.
    #[test]
    fn a_record_in_a_class_this_zone_does_not_serve_is_refused_at_load() {
        for class in ["CH", "HS"] {
            let zone_content = format!(
                "$ORIGIN example.com.\n\
                 $TTL 3600\n\
                 @   IN  SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 300\n\
                 @   IN  NS  ns1.example.com.\n\
                 ver {class} TXT \"1.0\"\n"
            );
            let err = parse_zone_file(&zone_content, "example.com.")
                .expect_err("a class this server cannot serve must not load silently");
            assert!(
                matches!(err, ZoneError::Syntax { line: 5, .. }),
                "{class}: want a syntax error naming line 5, got {err:?}"
            );
        }
    }

    /// The class field stays optional: `$TTL`-only lines are ordinary syntax.
    #[test]
    fn an_in_record_loads_whether_or_not_it_names_its_class() {
        let zone_content = r#"$ORIGIN example.com.
$TTL 3600
@    IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 300
@    IN NS  ns1.example.com.
named IN A  192.0.2.1
bare     A  192.0.2.2
timed 60 IN A 192.0.2.3
"#;
        let zone = parse_zone_file(zone_content, "example.com.").expect("parses");
        for name in [
            "named.example.com.",
            "bare.example.com.",
            "timed.example.com.",
        ] {
            assert_eq!(
                zone.query(nm(name).as_ref(), Qtype::of(record_types::A))
                    .len(),
                1,
                "{name} should have loaded"
            );
        }
    }

    #[test]
    fn test_malformed_rdata_surfaces_error() {
        // A bad IPv4 address must fail the load, not be silently dropped.
        let zone_content = "www IN A 999.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(
            matches!(err, ZoneError::Syntax { line: 1, .. }),
            "the line number is a field, not a prefix: {err:?}"
        );
        assert!(
            err.to_string().contains("A address"),
            "error should name the failure: {err}"
        );
    }

    #[test]
    fn test_unsupported_record_type_surfaces_error() {
        let zone_content = "www IN WKS 192.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(
            err.to_string().contains("unsupported record type"),
            "got: {err}"
        );
    }

    #[test]
    fn test_fully_qualified_owner_name_parses() {
        let zone = parse_zone_file("www.example.com. IN A 192.0.2.5\n", "example.com.").unwrap();
        assert_eq!(zone.records.len(), 1);
        assert_eq!(zone.records[0].name, nm("www.example.com."));
        assert_eq!(
            zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
    }

    #[test]
    fn test_owner_name_may_contain_digits() {
        let zone = parse_zone_file("www2 IN A 192.0.2.6\n", "example.com.").unwrap();
        assert_eq!(
            zone.records[0].name,
            nm("www2.example.com."),
            "stored absolute"
        );
        assert_eq!(
            zone.query(nm("www2.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
    }

    #[test]
    fn test_owner_name_may_look_like_a_record_type() {
        // Position, not the token's spelling, decides what the first field is.
        let zone = parse_zone_file("ns IN A 192.0.2.7\n", "example.com.").unwrap();
        assert_eq!(zone.records[0].name, nm("ns.example.com."));
        assert_eq!(
            zone.query(nm("ns.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "should be an A record"
        );
    }

    #[test]
    fn test_indented_line_inherits_previous_owner() {
        // RFC 1035 §5.1: a line beginning with whitespace reuses the last owner.
        let zone_content = "www IN A 192.0.2.1\n    IN A 192.0.2.2\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        assert_eq!(zone.records.len(), 2);
        assert_eq!(zone.records[1].name, nm("www.example.com."));
        assert_eq!(
            zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            2
        );
    }

    #[test]
    fn test_indented_line_without_a_previous_owner_errors() {
        let err = parse_zone_file("    IN A 192.0.2.1\n", "example.com.").unwrap_err();
        assert!(
            err.to_string().contains("omits its owner name"),
            "got: {err}"
        );
    }

    #[test]
    fn test_apex_and_relative_names_match_absolute_queries() {
        let zone_content = "@ IN A 192.0.2.1\nwww IN A 192.0.2.2\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        assert_eq!(
            zone.query(nm("example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "@ should match the apex"
        );
        assert_eq!(
            zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
        // DNS names are case-insensitive (RFC 4343).
        assert_eq!(
            zone.query(nm("WWW.Example.COM.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
    }

    /// A name *inside* RDATA is relative to the origin too — RFC 1035 §5.1,
    /// "domain names in the RDATA section of RRs ... are also relative".
    ///
    /// This did not hold. `rdata_from_fields` took the raw text and made a
    /// record out of it, so `www IN CNAME host` stored the target as the
    /// six-octet name `host.` and the chain went nowhere. Owner names were
    /// resolved and RDATA names were not, in the same loop. The type is what
    /// fixed it rather than a check: a `Name` cannot be relative, so the parser
    /// has to say what every name is relative *to* before it can build one.
    #[test]
    fn a_name_inside_rdata_is_relative_to_the_origin_too() {
        let zone = parse_zone_file(
            "@     IN SOA ns1 admin ( 1 3600 600 604800 300 )\n\
             @     IN NS  ns1\n\
             ns1   IN A   192.0.2.1\n\
             host  IN A   192.0.2.10\n\
             www   IN CNAME host\n\
             mail  IN MX  10 host\n\
             10    IN PTR host\n",
            "example.com.",
        )
        .expect("parse");

        let host = nm("host.example.com.");
        let of = |name: &str, qtype: Rtype| {
            zone.query(nm(name).as_ref(), Qtype::of(qtype))[0]
                .rdata
                .parse()
                .expect("parses")
        };

        assert_eq!(
            of("www.example.com.", rt::CNAME),
            ParsedRecord::CNAME(host.clone())
        );
        assert_eq!(
            of("10.example.com.", rt::PTR),
            ParsedRecord::PTR(host.clone())
        );
        assert_eq!(
            of("mail.example.com.", rt::MX),
            ParsedRecord::MX {
                preference: 10,
                exchange: host.clone(),
            }
        );
        // The SOA's two names, from the same line as the origin itself.
        let ParsedRecord::SOA { mname, rname, .. } = of("example.com.", rt::SOA) else {
            panic!("not an SOA");
        };
        assert_eq!(mname, nm("ns1.example.com."));
        assert_eq!(rname, nm("admin.example.com."));

        // And the chain actually resolves, which is what the bug cost.
        assert_eq!(zone.query(host.as_ref(), Qtype::of(rt::A)).len(), 1);
    }

    /// `absolutize`'s three cases: already absolute, the origin itself, and
    /// relative. RFC 1035 §5.1 gives `@` and the empty name the origin.
    #[test]
    fn a_relative_name_is_completed_against_the_origin() {
        let origin = nm("example.com.");

        for (text, want) in [
            ("www.example.com.", "www.example.com."),
            ("@", "example.com."),
            ("", "example.com."),
            ("www", "www.example.com."),
            ("a.b", "a.b.example.com."),
        ] {
            assert_eq!(
                absolutize(text, origin.as_ref()).expect("a well-formed name"),
                nm(want),
                "{text} under {origin}"
            );
        }
    }

    #[test]
    fn test_wildcard_answers_a_name_that_does_not_exist() {
        let zone = parse_zone_file("* IN A 192.0.2.9\n", "example.com.").unwrap();
        assert_eq!(
            zone.query(nm("anything.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
        // And it does not answer for the name it hangs off.
        assert!(zone
            .query(nm("example.com.").as_ref(), Qtype::of(rt::A))
            .is_empty());
    }

    /// RFC 4592 §3.3.2's worked example: `*.example.` answers
    /// `_telnet._tcp.host1.example.`, three labels below the wildcard's parent.
    /// §2.1.1 is about `*` in zone-file syntax and says nothing about depth.
    #[test]
    fn test_a_wildcard_synthesizes_at_any_depth() {
        let zone = parse_zone_file("* IN A 192.0.2.9\n", "example.").unwrap();
        assert_eq!(
            zone.query(nm("_telnet._tcp.host1.example.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "RFC 4592 §3.3.2 synthesizes this from *.example."
        );
        assert_eq!(
            zone.query(nm("a.b.example.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
        assert!(zone.name_exists(nm("a.b.c.d.e.f.example.").as_ref()));
        assert_eq!(
            zone.name_kind(nm("a.b.example.").as_ref()),
            NameKind::Wildcard(nm(&nm("*.example.").to_string()))
        );
    }

    /// `query_with_kind` must answer exactly what the two calls it replaced
    /// answered, for every kind of name — the kind is what decides NXDOMAIN
    /// against NODATA, so a disagreement is a wrong rcode, not a slow one.
    ///
    /// The kind is the live half: `query` delegates here now, so comparing the
    /// records to `query`'s is a tautology, while the kind is still checked
    /// against `name_kind`'s own walk. Watched failing with the kind forced to
    /// `NotFound` — which `an_empty_non_terminal_is_nodata_not_nxdomain` in
    /// `rdnsd` also catches, since that is a NODATA turning into NXDOMAIN.
    #[test]
    fn test_query_with_kind_answers_what_the_two_calls_did() {
        let zone = parse_zone_file(
            "@       IN SOA ns1 admin ( 1 3600 600 604800 300 )\n\
             @       IN NS  ns1\n\
             ns1     IN A   192.0.2.1\n\
             www     IN A   192.0.2.10\n\
             www     IN AAAA 2001:db8::10\n\
             *.wild  IN A   192.0.2.20\n\
             deep.a.b IN TXT \"x\"\n\
             sub     IN NS  ns1.sub.example.com.\n",
            "example.com.",
        )
        .unwrap();

        for name in [
            "www.example.com.",           // exact, has the type
            "WwW.eXaMpLe.CoM.",           // the same, case randomized
            "ns1.example.com.",           // exact, lacks the type
            "anything.wild.example.com.", // answered by a wildcard
            "a.b.example.com.",           // an empty non-terminal
            "b.example.com.",             // another one, one label up
            "nope.example.com.",          // not found
            "example.com.",               // the apex
            "host.sub.example.com.",      // below a delegation
            "elsewhere.test.",            // outside the zone
        ] {
            for qtype in [rt::A, rt::TXT, rt::SOA] {
                let qtype = Qtype::of(qtype);
                let (kind, records) = zone.query_with_kind(nm(name).as_ref(), qtype);
                assert_eq!(
                    kind,
                    zone.name_kind(nm(name).as_ref()),
                    "kind for {name} {qtype:?}"
                );
                assert_eq!(
                    records.len(),
                    zone.query(nm(name).as_ref(), qtype).len(),
                    "records for {name} {qtype:?}"
                );
            }
        }
    }

    /// An existing name ends the search, empty non-terminals included
    /// (RFC 4592 §4.4).
    #[test]
    fn test_an_existing_name_stops_the_wildcard_search() {
        let zone =
            parse_zone_file("* IN A 192.0.2.9\ndeep.a.b IN TXT \"x\"\n", "example.com.").unwrap();

        assert_eq!(
            zone.query(nm("other.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "nothing above it"
        );
        assert!(
            zone.query(nm("x.a.b.example.com.").as_ref(), Qtype::of(rt::A))
                .is_empty(),
            "a.b exists, so *.example.com. is not this name's source of synthesis"
        );
        assert_eq!(
            zone.name_kind(nm("x.a.b.example.com.").as_ref()),
            NameKind::NotFound,
            "NXDOMAIN: the closest encloser is a.b, and *.a.b does not exist"
        );
    }

    /// A wildcard below a zone cut is the child's data, not ours (RFC 4592
    /// §2.2.1), so it synthesizes nothing here — the answer owes a referral.
    #[test]
    fn test_no_synthesis_at_or_below_a_delegation() {
        let zone = parse_zone_file(
            "@ IN SOA ns1 admin 1 3600 600 604800 300\n\
             @ IN NS ns1\n\
             ns1 IN A 192.0.2.1\n\
             sub IN NS ns.sub\n\
             ns.sub IN A 192.0.2.2\n\
             *.sub IN A 192.0.2.3\n",
            "example.com.",
        )
        .unwrap();

        assert_eq!(
            zone.delegation_for(nm("anything.sub.example.com.").as_ref()),
            Some(nm("sub.example.com.")),
        );
        assert_eq!(
            zone.name_kind(nm("anything.sub.example.com.").as_ref()),
            NameKind::NotFound,
            "occluded: the wildcard is below the cut, so it is not ours to expand"
        );
        // The apex NS RRset is not a cut.
        assert_eq!(zone.delegation_for(nm("www.example.com.").as_ref()), None);
        // A query at the cut itself is still a referral.
        assert_eq!(
            zone.delegation_for(nm("sub.example.com.").as_ref()),
            Some(nm("sub.example.com."))
        );
    }

    /// A name with descendants exists (RFC 4592 §2.2.2): NODATA, not NXDOMAIN,
    /// which an RFC 8020 resolver would extend downwards over the zone's own
    /// data.
    /// A node's kind is what it holds, not the order the zone file arrived in.
    ///
    /// The two maps became one in #22, so "is this a node" and "does it have
    /// records" are one lookup — which makes insertion *order* the thing that
    /// could go wrong. A name noted as an ancestor and then given records must
    /// read `Exact`, and a record added below a name that already has records
    /// must not stop the ancestor walk early.
    #[test]
    fn a_non_terminal_that_gains_records_is_an_ordinary_name() {
        for (order, text) in [
            (
                "ancestor first",
                "deep.a.b IN TXT \"x\"
a.b IN A 192.0.2.1
",
            ),
            (
                "records first",
                "a.b IN A 192.0.2.1
deep.a.b IN TXT \"x\"
",
            ),
        ] {
            let zone = parse_zone_file(text, "example.com.").unwrap();
            assert_eq!(
                zone.name_kind(nm("a.b.example.com.").as_ref()),
                NameKind::Exact,
                "{order}"
            );
            assert!(zone.holds_name(nm("a.b.example.com.").as_ref()), "{order}");
            assert_eq!(
                zone.name_kind(nm("b.example.com.").as_ref()),
                NameKind::EmptyNonTerminal,
                "{order}: still only an ancestor"
            );
            assert!(!zone.holds_name(nm("b.example.com.").as_ref()), "{order}");
            assert_eq!(
                zone.name_kind(nm("nope.b.example.com.").as_ref()),
                NameKind::NotFound,
                "{order}: and the walk still says no to what is not there"
            );
        }
    }

    #[test]
    fn test_empty_non_terminals_exist() {
        let zone = parse_zone_file("deep.a.b IN TXT \"down here\"\n", "example.com.").unwrap();

        for ent in ["a.b.example.com.", "b.example.com.", "example.com."] {
            assert_eq!(
                zone.name_kind(nm(ent).as_ref()),
                NameKind::EmptyNonTerminal,
                "{ent} has descendants, so it exists"
            );
            assert!(zone.name_exists(nm(ent).as_ref()), "{ent}");
            assert!(
                !zone.holds_name(nm(ent).as_ref()),
                "{ent} still holds no records of its own — the denial path needs that answer"
            );
            assert!(
                zone.query(nm(ent).as_ref(), Qtype::of(rt::TXT)).is_empty(),
                "{ent}: NODATA, no records"
            );
        }

        assert_eq!(
            zone.name_kind(nm("deep.a.b.example.com.").as_ref()),
            NameKind::Exact
        );
        assert_eq!(
            zone.name_kind(nm("gone.a.b.example.com.").as_ref()),
            NameKind::NotFound
        );
        // The walk does not conjure names outside the zone into existence.
        assert_eq!(zone.name_kind(nm("com.").as_ref()), NameKind::NotFound);
        assert_eq!(
            zone.name_kind(nm("elsewhere.test.").as_ref()),
            NameKind::NotFound
        );
    }

    /// RFC 1034 §3.6.2: a CNAME is the only type at its owner.
    #[test]
    fn test_a_cname_may_not_share_its_owner_name() {
        let err = parse_zone_file(
            "www IN CNAME host.example.com.\nwww IN A 192.0.2.1\n",
            "example.com.",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("CNAME"),
            "the error should say why: {err}"
        );

        // RRSIG, NSEC and NSEC3 describe the name rather than name it
        // (RFC 4035 §2.5).
        parse_zone_file(
            "www IN CNAME host.example.com.\n\
             www IN NSEC x.example.com. CNAME RRSIG NSEC\n",
            "example.com.",
        )
        .expect("a signed CNAME is not a conflict");
    }

    /// The zone shapes RFC 6672 says a server should not load, and the three it
    /// says are fine.
    #[test]
    fn a_zone_breaking_a_dname_rule_is_refused() {
        for (what, text) in [
            (
                "two DNAMEs at one name (§2.4)",
                "sub IN DNAME a.example.net.\nsub IN DNAME b.example.net.\n",
            ),
            (
                "a DNAME on a zone cut (§2.3)",
                "sub IN DNAME a.example.net.\nsub IN NS ns1.example.net.\n",
            ),
            (
                "data below the owner (§2.4)",
                "sub IN DNAME a.example.net.\nx.sub IN A 192.0.2.1\n",
            ),
            ("a wildcard DNAME (§3.3)", "*.sub IN DNAME a.example.net.\n"),
        ] {
            let err = parse_zone_file(text, "example.com.")
                .expect_err(&format!("{what} should not load"));
            assert!(
                err.to_string().contains("6672"),
                "{what}: the error should cite the section: {err}"
            );
        }

        // §2.4 forbids a CNAME at a DNAME's owner name too. That one is refused
        // by `check_cname_exclusivity`, citing RFC 1034 §3.6.2 — the older
        // statement of the same rule — so it is not in the loop above.
        let err = parse_zone_file(
            "sub IN DNAME a.example.net.\nsub IN CNAME b.example.net.\n",
            "example.com.",
        )
        .expect_err("a DNAME and a CNAME at one name should not load");
        assert!(err.to_string().contains("3.6.2"), "{err}");

        // §2.3: the apex may hold a DNAME beside the customary SOA and NS, and
        // the owner name of a DNAME may hold other types.
        parse_zone_file(
            "@ IN SOA ns1.example.com. root.example.com. 1 3600 600 86400 300\n\
             @ IN NS ns1.example.com.\n\
             @ IN DNAME example.net.\n",
            "example.com.",
        )
        .expect("§2.3 allows a DNAME at the zone apex");
        parse_zone_file(
            "sub IN DNAME a.example.net.\nsub IN A 192.0.2.1\n",
            "example.com.",
        )
        .expect("§2.3 allows other types at the DNAME's own owner name");
        // Whole labels: `sub2` is a sibling of `sub`, not a child of it.
        parse_zone_file(
            "sub IN DNAME a.example.net.\nsub2 IN A 192.0.2.1\n",
            "example.com.",
        )
        .expect("a sibling of the DNAME owner is not below it");
    }

    /// RFC 6672 §2.2 and §2.3: a DNAME redirects the names *below* its owner,
    /// and not the owner itself.
    #[test]
    fn a_dname_is_found_above_a_name_and_not_at_it() {
        let zone = parse_zone_file("sub IN DNAME target.example.net.\n", "example.com.").unwrap();

        let found = zone
            .dname_above(nm("a.b.sub.example.com.").as_ref())
            .expect("a DNAME two labels up redirects");
        assert_eq!(found.name, nm("sub.example.com."));

        assert!(
            zone.dname_above(nm("sub.example.com.").as_ref()).is_none(),
            "§2.3: the owner name of a DNAME is not redirected itself"
        );
        assert!(
            zone.dname_above(nm("other.example.com.").as_ref())
                .is_none(),
            "a name that is not below the owner is not redirected"
        );
        // Table 1: QNAME `ab.example.com.` against owner `b.example.com.` is
        // `<no match>`. Whole labels only, never a string suffix.
        assert!(
            zone.dname_above(nm("absub.example.com.").as_ref())
                .is_none(),
            "the match is on whole labels"
        );
    }

    /// A zone with no DNAME never walks a name's ancestors looking for one.
    #[test]
    fn a_zone_with_no_dname_answers_without_walking() {
        let zone = parse_zone_file("www IN A 192.0.2.1\n", "example.com.").unwrap();
        assert!(zone
            .dname_above(nm("deep.down.www.example.com.").as_ref())
            .is_none());
    }

    /// An existing name shadows the wildcard completely, types it does not carry
    /// included (RFC 1034 §4.3.3, RFC 4592 §2.2.1).
    #[test]
    fn test_an_existing_name_shadows_the_wildcard() {
        let zone = parse_zone_file(
            "* IN A 192.0.2.9\nwww IN AAAA 2001:db8::1\n",
            "example.com.",
        )
        .unwrap();

        let a = zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A));
        assert!(
            a.is_empty(),
            "www exists, so the wildcard must not answer for it: {a:?}"
        );
        assert_eq!(
            zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::AAAA))
                .len(),
            1,
            "its own AAAA"
        );
        // Any other name still gets the wildcard.
        assert_eq!(
            zone.query(nm("other.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
    }

    #[test]
    fn test_name_exists_distinguishes_nodata_from_nxdomain() {
        let zone = parse_zone_file(
            "* IN A 192.0.2.9\nwww IN AAAA 2001:db8::1\n",
            "example.com.",
        )
        .unwrap();

        assert!(
            zone.name_exists(nm("www.example.com.").as_ref()),
            "by its own records"
        );
        assert!(
            zone.name_exists(nm("other.example.com.").as_ref()),
            "through the wildcard — NODATA, not NXDOMAIN"
        );
        assert!(
            zone.name_exists(nm("a.b.example.com.").as_ref()),
            "the wildcard reaches any depth (RFC 4592 §3.3.2) — NODATA, not NXDOMAIN"
        );
        assert!(!zone.name_exists(nm("elsewhere.test.").as_ref()));
    }

    /// The index encodes what `matches_query` defines; separate code, so hold
    /// them to the same answers.
    #[test]
    fn test_the_index_and_matches_query_agree() {
        let zone = parse_zone_file(
            "@ IN A 192.0.2.1\nwww IN A 192.0.2.2\n* IN A 192.0.2.9\n",
            "example.com.",
        )
        .unwrap();

        for name in [
            "example.com.",
            "www.example.com.",
            "WWW.EXAMPLE.COM.",
            "other.example.com.",
            "a.b.example.com.",
            "*.example.com.",
            "elsewhere.test.",
            "com.",
        ] {
            let by_scan = zone
                .records()
                .iter()
                .any(|r| zone.matches_query(r.name.as_ref(), nm(name).as_ref()));
            assert_eq!(
                zone.name_exists(nm(name).as_ref()),
                by_scan,
                "the index and matches_query disagree about {name}"
            );
        }
    }

    /// `$ORIGIN` applies to the lines below it (RFC 1035 §5.1): a name already
    /// read keeps the origin it was read under.
    #[test]
    fn test_origin_applies_only_to_the_lines_below_it() {
        let zone_content = "www IN A 192.0.2.1\n$ORIGIN other.test.\nmail IN A 192.0.2.2\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();

        assert_eq!(
            zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "www was read before the $ORIGIN and stays where it was"
        );
        assert_eq!(
            zone.query(nm("mail.other.test.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
        assert!(zone
            .query(nm("www.other.test.").as_ref(), Qtype::of(rt::A))
            .is_empty());
    }

    /// `set_origin` moves the apex and nothing else. It re-keyed records while
    /// an owner name was text that might be relative; a `Name` is absolute, so
    /// the question no longer arises and a record stays where it was put.
    #[test]
    fn test_set_origin_moves_the_apex_and_not_the_records() {
        let mut zone = Zone::new(nm("example.com."));
        zone.add_record(ZoneRecord {
            name: nm("www.example.com."),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });
        assert_eq!(
            zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );

        zone.set_origin(nm("com."));
        assert_eq!(zone.origin(), nm("com.").as_ref());
        assert_eq!(
            zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "the record is at the name it was given, whatever the apex is"
        );
    }

    /// A record added after the zone is built has to be reachable.
    #[test]
    fn test_records_added_later_are_indexed() {
        let mut zone = Zone::new(nm("example.com."));
        assert!(zone
            .query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
            .is_empty());

        zone.add_record(ZoneRecord {
            name: nm("www.example.com."),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });
        assert_eq!(
            zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
        assert!(zone.name_exists(nm("www.example.com.").as_ref()));
    }

    /// A parenthesized SOA, which is how every zone file writes one.
    #[test]
    fn test_parenthesized_soa_loads() {
        let zone_content = r#"
$TTL 3600
@   IN  SOA ns1.example.com. admin.example.com. (
                2021010101  ; serial
                3600        ; refresh
                1800        ; retry
                604800      ; expire
                86400 )     ; minimum
@   IN  A   192.0.2.1
"#;
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        let soa = zone.query(
            nm("example.com.").as_ref(),
            Qtype::of(crate::record_types::SOA),
        );
        assert_eq!(soa.len(), 1, "the SOA should have loaded");
        match soa[0].rdata.parse().unwrap() {
            ParsedRecord::SOA {
                mname,
                serial,
                minimum,
                ..
            } => {
                assert_eq!(mname, nm("ns1.example.com."));
                assert_eq!(
                    serial,
                    Serial::new(2021010101),
                    "comments inside the group are not data"
                );
                assert_eq!(minimum, 86400);
            }
            other => panic!("expected an SOA, got {other:?}"),
        }
        // The record after the group is still read as its own line.
        assert_eq!(
            zone.query(nm("example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
    }

    /// A `;` inside a quoted string is data, not a comment — SPF and DKIM
    /// records are mostly semicolons.
    #[test]
    fn test_semicolon_inside_a_quoted_string_survives() {
        let zone_content = "txt IN TXT \"v=spf1 include:example.net; -all\"\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        let txt = zone.query(
            nm("txt.example.com.").as_ref(),
            Qtype::of(crate::record_types::TXT),
        );
        assert_eq!(txt.len(), 1);
        match txt[0].rdata.parse().unwrap() {
            ParsedRecord::TXT(strings) => {
                assert_eq!(
                    strings.len(),
                    1,
                    "one quoted string is one character-string"
                );
                assert_eq!(strings[0], b"v=spf1 include:example.net; -all");
            }
            other => panic!("expected TXT, got {other:?}"),
        }
    }

    /// Quotes say where one `<character-string>` ends (RFC 1035 §3.3.14):
    /// `"a b"` is one string and `a b` is two.
    #[test]
    fn test_txt_character_strings_are_split_on_quotes_not_whitespace() {
        let strings_of = |line: &str| -> Vec<Vec<u8>> {
            let zone = parse_zone_file(line, "example.com.").unwrap();
            match zone.query(
                nm("txt.example.com.").as_ref(),
                Qtype::of(crate::record_types::TXT),
            )[0]
            .rdata
            .parse()
            .unwrap()
            {
                ParsedRecord::TXT(strings) => strings,
                other => panic!("expected TXT, got {other:?}"),
            }
        };

        assert_eq!(
            strings_of("txt IN TXT \"two words\"\n"),
            vec![b"two words".to_vec()],
            "a quoted string is one character-string, spaces and all"
        );
        assert_eq!(
            strings_of("txt IN TXT \"first\" \"second\"\n"),
            vec![b"first".to_vec(), b"second".to_vec()],
            "two quoted strings are two character-strings"
        );
        assert_eq!(
            strings_of("txt IN TXT bare words\n"),
            vec![b"bare".to_vec(), b"words".to_vec()],
            "unquoted fields are one character-string each"
        );
        assert_eq!(
            strings_of("txt IN TXT \"\"\n"),
            vec![Vec::<u8>::new()],
            "an empty string is legal, and survives being empty"
        );
        assert_eq!(
            strings_of("txt IN TXT \"say \\\"hi\\\"\"\n"),
            vec![b"say \"hi\"".to_vec()],
            "an escaped quote is data, not the end of the string"
        );
    }

    /// A string too long for its one-byte length fails the load; splitting it
    /// silently would change what it says.
    #[test]
    fn test_txt_string_over_255_bytes_fails_the_load() {
        let long = "z".repeat(256);
        let err = parse_zone_file(&format!("txt IN TXT \"{long}\"\n"), "example.com.").unwrap_err();
        assert!(err.to_string().contains("255"), "got: {err}");
        assert!(
            matches!(err, ZoneError::Syntax { line: 1, .. }),
            "the line number is a field, not a prefix: {err:?}"
        );
    }

    #[test]
    fn test_unbalanced_parentheses_are_an_error() {
        let err = parse_zone_file("@ IN SOA ns1. admin. ( 1 2 3 4\n", "example.com.").unwrap_err();
        assert!(err.to_string().contains("never closed"), "got: {err}");
        assert!(
            matches!(err, ZoneError::Syntax { line: 1, .. }),
            "the line number is a field, not a prefix: {err:?}"
        );

        let err = parse_zone_file("@ IN A 192.0.2.1 )\n", "example.com.").unwrap_err();
        assert!(err.to_string().contains("unmatched"), "got: {err}");
    }

    #[test]
    fn test_unterminated_quote_is_an_error() {
        let err = parse_zone_file("txt IN TXT \"no closing quote\n", "example.com.").unwrap_err();
        assert!(err.to_string().contains("unterminated"), "got: {err}");
    }

    /// A scratch directory that removes itself. The include tests need real
    /// files, since resolving `$INCLUDE` is what is under test.
    #[test]
    fn test_include_pulls_in_records_relative_to_the_including_file() {
        let dir = ScratchDir::new("zone-include");
        dir.write("hosts.inc", "mail IN A 192.0.2.20\nwww IN A 192.0.2.21\n");
        let main = dir.write(
            "example.com.zone",
            "@ IN A 192.0.2.1\n$INCLUDE hosts.inc\nftp IN A 192.0.2.22\n",
        );

        let zone = parse_zone_file_at(&main, "example.com.").unwrap();
        assert_eq!(
            zone.query(nm("mail.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "from the include"
        );
        assert_eq!(
            zone.query(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
        assert_eq!(
            zone.query(nm("ftp.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "parsing continues after the include"
        );
        assert_eq!(
            zone.query(nm("example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1
        );
    }

    /// `$INCLUDE file origin` reads the file under that origin and does not
    /// change the including file's (RFC 1035 §5.1).
    #[test]
    fn test_include_origin_applies_to_the_included_file_only() {
        let dir = ScratchDir::new("zone-include-origin");
        dir.write(
            "sub.inc",
            "$ORIGIN deeper.example.com.\nns IN A 192.0.2.30\n",
        );
        let main = dir.write(
            "example.com.zone",
            "$INCLUDE sub.inc sub.example.com.\nafter IN A 192.0.2.31\n",
        );

        let zone = parse_zone_file_at(&main, "example.com.").unwrap();
        assert_eq!(
            zone.query(nm("ns.deeper.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "the included file's own $ORIGIN applies inside it"
        );
        assert_eq!(
            zone.query(nm("after.example.com.").as_ref(), Qtype::of(rt::A))
                .len(),
            1,
            "and neither origin leaks back out to the including file"
        );
        assert_eq!(
            zone.origin(),
            nm("example.com.").as_ref(),
            "the apex is untouched"
        );
    }

    #[test]
    fn test_include_of_a_missing_file_is_an_error() {
        let dir = ScratchDir::new("zone-include-missing");
        let main = dir.write("example.com.zone", "$INCLUDE nope.inc\n");
        let err = parse_zone_file_at(&main, "example.com.").unwrap_err();
        assert!(
            err.to_string().contains("nope.inc"),
            "the error should name the file: {err}"
        );
        assert!(
            matches!(err, ZoneError::Syntax { line: 1, .. }),
            "the line number is a field, not a prefix: {err:?}"
        );
    }

    /// A file that includes itself recurses until the stack runs out.
    #[test]
    fn test_include_cycle_is_refused() {
        let dir = ScratchDir::new("zone-include-cycle");
        let main = dir.write("example.com.zone", "$INCLUDE example.com.zone\n");
        let err = parse_zone_file_at(&main, "example.com.").unwrap_err();
        assert!(err.to_string().contains("cycle"), "got: {err}");
    }

    #[test]
    fn test_include_without_a_file_name_is_an_error() {
        let err = parse_zone_file("$INCLUDE\n", "example.com.").unwrap_err();
        assert!(err.to_string().contains("needs a file name"), "got: {err}");
    }

    #[test]
    fn test_generic_rdata_carries_a_type_we_do_not_parse() {
        let zone = parse_zone_file("odd IN TYPE1234 \\# 4 DEADBEEF\n", "example.com.").unwrap();
        let record = zone.query(nm("odd.example.com.").as_ref(), Qtype::of(Rtype::new(1234)));
        assert_eq!(record.len(), 1);
        assert_eq!(record[0].rdata.bytes(), [0xde, 0xad, 0xbe, 0xef]);
    }

    /// RFC 3597 §5 permits the generic form for a known type too.
    #[test]
    fn test_generic_rdata_is_accepted_for_a_known_type() {
        let zone = parse_zone_file("www IN A \\# 4 C0000201\n", "example.com.").unwrap();
        assert!(matches!(
            zone.query(nm("www.example.com.").as_ref(), Qtype::of(record_types::A))[0].rdata.parse(),
            Ok(ParsedRecord::A(addr)) if addr == Ipv4Addr::new(192, 0, 2, 1)
        ));
    }

    #[test]
    fn test_generic_rdata_of_zero_length() {
        let zone = parse_zone_file("empty IN TYPE4321 \\# 0\n", "example.com.").unwrap();
        assert!(zone.query(
            nm("empty.example.com.").as_ref(),
            Qtype::of(Rtype::new(4321))
        )[0]
        .rdata
        .bytes()
        .is_empty());
    }

    /// The stated length is checked against the digits, not trusted.
    #[test]
    fn test_generic_rdata_length_must_match_the_digits() {
        let err = parse_zone_file("odd IN TYPE1234 \\# 8 DEADBEEF\n", "example.com.").unwrap_err();
        assert!(
            err.to_string().contains("says 8 bytes but carries 4"),
            "got: {err}"
        );
    }

    #[test]
    fn test_generic_rdata_that_is_not_the_type_it_claims_fails_the_load() {
        // Three bytes cannot be an A record.
        let err = parse_zone_file("www IN A \\# 3 C00002\n", "example.com.").unwrap_err();
        assert!(err.to_string().contains("not valid A"), "got: {err}");
    }

    #[test]
    fn test_generic_rdata_needs_a_length() {
        let err = parse_zone_file("odd IN TYPE1234 \\#\n", "example.com.").unwrap_err();
        assert!(err.to_string().contains("needs a length"), "got: {err}");
    }

    /// A bitmap may list a type with no mnemonic; `TYPEnnn` (RFC 3597 §5) is how
    /// it is written, and dropping it would change a signed NSEC.
    #[test]
    fn test_nsec_bitmap_accepts_a_generic_type_name() {
        let zone =
            parse_zone_file("@ IN NSEC www.example.com. A TYPE1234\n", "example.com.").unwrap();
        let record = zone.query(nm("example.com.").as_ref(), Qtype::of(record_types::NSEC))[0];
        let ParsedRecord::NSEC { type_bitmap, .. } = record.rdata.parse().unwrap() else {
            panic!("not an NSEC");
        };
        assert!(crate::denial_wire::bitmap_has_type(
            &type_bitmap,
            record_types::A
        ));
        assert!(crate::denial_wire::bitmap_has_type(
            &type_bitmap,
            Rtype::new(1234)
        ));
    }

    #[test]
    fn test_nsec_bitmap_rejects_a_name_that_is_no_type_at_all() {
        let err =
            parse_zone_file("@ IN NSEC www.example.com. A NOTATYPE\n", "example.com.").unwrap_err();
        assert!(
            err.to_string().contains("unknown record type"),
            "got: {err}"
        );
    }

    /// The formatter and the parser are inverses, or a rewritten RRSIG claims a
    /// different validity period from the one it was signed with.
    #[test]
    fn test_dnssec_time_round_trips() {
        for (epoch, text) in [
            (0u32, "19700101000000"),
            (1, "19700101000001"),
            (951_868_800, "20000301000000"), // the day after a leap day
            (1_078_012_800, "20040229000000"), // a leap day itself
            (1_609_459_199, "20201231235959"),
            (2_147_483_647, "20380119031407"),
            (u32::MAX, "21060207062815"),
        ] {
            assert_eq!(format_dnssec_time(epoch), text, "formatting {epoch}");
            assert_eq!(parse_dnssec_time(text), Ok(epoch), "parsing {text}");
        }
    }

    /// A 14-*byte* string is not fourteen characters, and the slicing is by
    /// byte: a multi-byte character must not panic on a char boundary.
    #[test]
    fn a_fourteen_byte_time_that_is_not_fourteen_digits_is_an_error() {
        let multibyte = "abcé123456789";
        assert_eq!(multibyte.len(), 14, "the byte-length check passes");
        assert!(parse_dnssec_time(multibyte).is_err(), "must not panic");

        // The same shape with the multi-byte character at each slice boundary.
        for probe in ["é12345678901", "1234é678901234", "123456789012é"] {
            let _ = parse_dnssec_time(probe);
        }
    }

    /// Every field is range-checked: an out-of-range one otherwise produces a
    /// plausible epoch for a date that does not exist.
    #[test]
    fn an_out_of_range_field_is_an_error_not_a_plausible_number() {
        for bad in [
            "20250013000000", // month 13
            "20250000000000", // month 0
            "20250132000000", // 32 January
            "20250230000000", // 30 February, in a non-leap year
            "20230229000000", // 29 February, in a non-leap year
            "20250101240000", // hour 24
            "20250101006000", // minute 60
            "20250101000060", // second 60 — POSIX time has no leap second
            "19690101000000", // before the epoch: negative
        ] {
            assert!(
                parse_dnssec_time(bad).is_err(),
                "{bad} should not parse, got {:?}",
                parse_dnssec_time(bad)
            );
        }

        // 29 February is a day in a leap year: the check is not refusing
        // everything near the boundary.
        assert!(parse_dnssec_time("20240229000000").is_ok());
    }

    /// The field is 32 bits (RFC 4034 §3.2). One second past it must fail, not
    /// truncate a far-future signature into one that expired in 1970.
    #[test]
    fn a_time_past_the_end_of_the_field_is_an_error() {
        // The last representable instant still parses.
        assert_eq!(parse_dnssec_time("21060207062815"), Ok(u32::MAX));
        assert!(parse_dnssec_time("21060207062816").is_err(), "one past");
        assert!(parse_dnssec_time("99991231235959").is_err(), "far past");
    }

    /// The RDATA half is a pure function: a type's field handling is testable
    /// without a zone file, an origin, a TTL and an owner name around it. Not a
    /// regression test.
    #[test]
    fn the_rdata_half_can_be_tested_without_a_zone_file() {
        let fields = ["10", "mx.example.com."];
        let text: Vec<String> = fields.iter().map(|s| s.to_string()).collect();
        let origin = nm("example.com.");
        let mx = rdata_from_fields(
            "MX",
            "10 mx.example.com.".into(),
            &fields,
            &text,
            origin.as_ref(),
            1,
        )
        .expect("a well-formed MX");
        assert_eq!(
            mx.parse().unwrap(),
            ParsedRecord::MX {
                preference: 10,
                exchange: nm("mx.example.com."),
            }
        );

        // The line number travels with the error: the helpers return a detail
        // and this function attaches the position.
        let bad = ["notanumber", "mx.example.com."];
        let text: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
        let err = rdata_from_fields(
            "MX",
            "notanumber mx.example.com.".into(),
            &bad,
            &text,
            origin.as_ref(),
            42,
        )
        .expect_err("preference is not a number");
        assert!(err.to_string().contains("42"), "got {err}");
    }

    #[test]
    fn test_malformed_ttl_directive_surfaces_error() {
        let zone_content = "$TTL notanumber\nwww IN A 192.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(err.to_string().contains("$TTL"), "got: {err}");
    }
    /// A *quoted* escape in a name was eaten by the tokenizer, so `"a\.b"`
    /// reached the parser as `a.b` and became two labels — while the unquoted
    /// form was refused outright. The tokenizer keeps the backslash now, so
    /// both spellings take the same path and mean the same one label.
    ///
    /// Found while writing RFC 9460's SvcParamValue decoding, which needed the
    /// backslash to survive tokenizing for `\DDD` to mean anything.
    #[test]
    fn a_quoted_escape_in_a_name_means_the_same_as_an_unquoted_one() {
        for line in [
            r#"www IN CNAME a\.b.example.com."#,
            r#"www IN CNAME "a\.b.example.com.""#,
        ] {
            let zone = parse_zone_file(line, "example.com.")
                .unwrap_or_else(|e| panic!("{line:?} should load: {e}"));
            let ParsedRecord::CNAME(target) = zone.records()[0].rdata.parse().expect("a CNAME")
            else {
                panic!("not a CNAME");
            };
            assert_eq!(
                target.as_ref().labels().next().expect("a first label"),
                b"a.b",
                "{line:?}: one label of three octets, dot included"
            );
        }
    }

    /// RFC 1035 §5.1 makes `a\.b` one label of three octets. Storing a name as
    /// presentation text could not hold that — `.` was the separator — so it
    /// was refused; wire storage has no such problem (`TODO.md` D-1).
    #[test]
    fn an_escaped_dot_is_one_label_not_two() {
        let zone = parse_zone_file("a\\.b IN A 192.0.2.1\n", "example.com.")
            .expect("an escaped dot in an owner name");
        let name = &zone.records()[0].name;
        assert_eq!(
            name.as_ref().label_count(),
            3,
            "`a.b`, `example`, `com` — not four"
        );
        assert_eq!(
            name.as_ref().labels().next().expect("a first label"),
            b"a.b"
        );
        // It goes back out as it came in, so a zone file round trips.
        assert_eq!(name.to_string(), "a\\.b.example.com.");

        // And it is reachable under the name it really has, not under `a.b...`.
        assert_eq!(
            zone.query(name.as_ref(), Qtype::of(rt::A)).len(),
            1,
            "reachable under the name it was stored as"
        );
        assert!(zone
            .query(nm("a.b.example.com.").as_ref(), Qtype::of(rt::A))
            .is_empty());
    }
}
