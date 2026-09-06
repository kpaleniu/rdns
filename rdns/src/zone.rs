use crate::denial_wire::{base32hex_decode, canonical_sort_key};
use crate::error::ZoneError;
use crate::utils::record_type_code;
use crate::utils::record_types as rt;
use crate::utils::{ascii_lowered_cow, hex_decode, is_at_or_under, parent_name, NameKeyBuf};
use crate::Class;
use crate::Rtype;
use crate::Serial;
use crate::Ttl;
use crate::{ParsedRecord, Qtype, RecordData, ResourceRecord};
use std::borrow::Cow;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Bound;
use std::path::{Path, PathBuf};

/// A single DNS resource record stored in a zone
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub name: String,
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
    origin: String,
    records: Vec<ZoneRecord>,
    /// Positions in `records`, by [`Zone::lookup_key`] of the owner name.
    ///
    /// A name that exists only because something below it does — an empty
    /// non-terminal (RFC 4592 §2.2.2) — is a key with **no positions**. It was
    /// a second `HashSet` until 2026-09-05, which made every level of a miss
    /// walk hash the name twice to ask two halves of one question
    /// (`TODO.md` #22): "is this a node of the zone, and does it have records".
    index: HashMap<NameKeyBuf, Vec<usize>>,
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
    fn note(&mut self, key: &str, rtype: Rtype, at_apex: bool) {
        self.wildcards |= key.starts_with("*.");
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
            .filter(move |r| qtype.matches(record_type_code(&r.rdata)))
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
/// [`crate::dnssec_answer::negative_proof`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameKind {
    /// The zone holds records at this exact name.
    Exact,
    /// The name has descendants and no records of its own (RFC 4592 §2.2.2).
    /// It exists, and every type at it is NODATA.
    EmptyNonTerminal,
    /// The name is not in the zone, and this wildcard is its source of
    /// synthesis (RFC 4592 §3.3.1). Absolute and down-cased.
    Wildcard(String),
    /// Not in the zone at all: NXDOMAIN.
    NotFound,
}

/// Which of the two chains a denial record belongs to.
enum Chain {
    Nsec,
    Nsec3,
}

impl Zone {
    /// Create a new zone with the given origin (e.g., "example.com.")
    pub fn new(origin: String) -> Self {
        Zone {
            origin: absolute(&origin),
            records: Vec::new(),
            index: HashMap::new(),
            nsec_chain: BTreeMap::new(),
            nsec3_chain: BTreeMap::new(),
            shortcuts: Shortcuts::default(),
        }
    }

    /// The zone's apex name, absolute.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Every record in the zone, in load order.
    pub fn records(&self) -> &[ZoneRecord] {
        &self.records
    }

    /// Move the zone's apex, as a top-level `$ORIGIN` does.
    ///
    /// Index keys are absolute, so a record held under a *relative* name has to
    /// be re-keyed; the parser's records are already absolute, so only names
    /// added relative through [`Zone::add_record`] move.
    pub fn set_origin(&mut self, origin: &str) {
        self.origin = absolute(origin);
        self.reindex();
    }

    /// Add a record to the zone
    pub fn add_record(&mut self, record: ZoneRecord) {
        // Owned: the key becomes an index entry, and the statements below need
        // `&mut self`.
        let key = self.lookup_key(&record.name).into_owned();
        let position = self.records.len();
        let at_apex = key == *self.origin_key();
        self.shortcuts
            .note(&key, record_type_code(&record.rdata), at_apex);
        self.note_non_terminals(&key);
        self.index
            .entry(NameKeyBuf::from_folded(key))
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
    pub fn holds_name(&self, name: &str) -> bool {
        // Records, not merely a node: an empty non-terminal is in `index` with
        // no positions, and it is exactly the name a wildcard answer has to
        // prove does not exist.
        self.index
            .get(self.lookup_key(name).as_ref())
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
    pub fn nsec_covering(&self, name: &str) -> Option<&ZoneRecord> {
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
            crate::utils::record_types::NSEC => Some((
                Chain::Nsec,
                canonical_sort_key(&self.normalize_name(&record.name)),
            )),
            crate::utils::record_types::NSEC3 => {
                let owner = self.normalize_name(&record.name);
                let label = owner.split('.').next()?;
                Some((Chain::Nsec3, base32hex_decode(label).ok()?))
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
    pub fn query(&self, name: &str, qtype: Qtype) -> Vec<&ZoneRecord> {
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
    pub fn query_with_kind(&self, name: &str, qtype: Qtype) -> (NameKind, Vec<&ZoneRecord>) {
        let located = self.locate(name);
        let records: Vec<&ZoneRecord> = located.of_type(qtype).collect();
        (located.kind, records)
    }

    /// Where `name` lands in this zone, without deciding a type yet.
    ///
    /// One closest-encloser walk, then as many type filters as the caller wants
    /// — and the caller that wants only "is there anything here" pays no `Vec`
    /// for the answer. [`Zone::query`] is this plus a `collect`.
    pub fn locate(&self, name: &str) -> Located<'_> {
        let key = self.lookup_key(name);
        let kind = self.name_kind_of_key(&key);
        let at = match kind {
            NameKind::Exact => self.index.get(key.as_ref()),
            NameKind::Wildcard(ref wildcard) => self.index.get(wildcard.as_str()),
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
    pub fn apex_soa(&self) -> Option<&ZoneRecord> {
        self.query(&self.origin, Qtype::of(rt::SOA))
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
        record.rdata.rtype() == rt::SOA
            && self
                .normalize_name(&record.name)
                .eq_ignore_ascii_case(&self.origin)
    }

    /// Whether the zone holds anything at `name` — by that name, because
    /// something below it exists, or through a wildcard. The NXDOMAIN question;
    /// an existing name with no record of the queried type is NODATA.
    pub fn name_exists(&self, name: &str) -> bool {
        !matches!(self.name_kind(name), NameKind::NotFound)
    }

    /// Why `name` has an answer here, or has none. See [`NameKind`].
    pub fn name_kind(&self, name: &str) -> NameKind {
        self.name_kind_of_key(&self.lookup_key(name))
    }

    /// [`Zone::name_kind`] for a name already in [`Zone::lookup_key`] form.
    ///
    /// A closest-encloser walk, not a single lookup: synthesis reaches any
    /// depth (RFC 4592 §3.3.2 answers `_telnet._tcp.host1.example.` from
    /// `*.example.`). The walk stops at the first ancestor that exists and only
    /// the wildcard directly below it may answer (§3.3.1) — an existing name,
    /// empty non-terminal included, ends the search (§4.4).
    fn name_kind_of_key(&self, key: &str) -> NameKind {
        // One hash for both questions: present with records is `Exact`, present
        // without is an empty non-terminal (`TODO.md` #22).
        match self.index.get(key) {
            Some(positions) if !positions.is_empty() => return NameKind::Exact,
            Some(_) => return NameKind::EmptyNonTerminal,
            None => {}
        }

        let origin = self.origin_key();
        let mut name = key;
        while let Some(encloser) = parent_name(name) {
            if !is_at_or_under(encloser, &origin) {
                // Out of the zone: the query was never in it.
                return NameKind::NotFound;
            }
            if !self.node_exists(encloser) {
                name = encloser;
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
            let wildcard = format!("*.{encloser}");
            return if self.index.contains_key(wildcard.as_str()) {
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
    fn node_exists(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    /// The delegation point at or above `name`: the deepest ancestor-or-self
    /// other than the apex with an NS RRset (RFC 1034 §4.2.1).
    ///
    /// `Some` means the answer owes a referral — NS RRset, glue, and AA
    /// clear. The apex is excluded: its NS RRset is this zone's own.
    pub fn delegation_for(&self, name: &str) -> Option<String> {
        // Before `lookup_key`, not only inside `delegation_for_key`: with no cut
        // to find, the folded key is a copy of the name made for nothing.
        if !self.shortcuts.delegations {
            return None;
        }
        self.delegation_for_key(&self.lookup_key(name))
    }

    fn delegation_for_key(&self, key: &str) -> Option<String> {
        if !self.shortcuts.delegations {
            return None;
        }
        let origin = self.origin_key();
        let mut candidate = key;
        loop {
            if candidate != origin && self.has_type(candidate, rt::NS) {
                return Some(candidate.to_string());
            }
            if candidate == origin {
                return None;
            }
            candidate = parent_name(candidate)?;
            if !is_at_or_under(candidate, &origin) {
                return None;
            }
        }
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
    /// in a zone [`check_dname_rules`] refuses, since a second DNAME below the
    /// first is a record at a subdomain of a DNAME owner (§2.4) — but a zone
    /// that arrived by transfer never met that check, and occluding from the
    /// top is the answer that does not depend on how deep the violation goes.
    ///
    /// Returns the record, not the name: the caller needs its owner to echo,
    /// its target to substitute and its TTL for the synthesized CNAME (§3.1),
    /// and looking any of them up again is the repeat `TODO.md` #25a removed.
    pub fn dname_above(&self, name: &str) -> Option<&ZoneRecord> {
        // Before `lookup_key`, as `delegation_for` does it: with no DNAME in
        // the zone the folded key is a copy made for nothing.
        if !self.shortcuts.dnames {
            return None;
        }
        self.dname_above_key(&self.lookup_key(name))
    }

    /// [`Zone::dname_above`] for a name already in [`Zone::lookup_key`] form.
    pub fn dname_above_key(&self, key: &str) -> Option<&ZoneRecord> {
        if !self.shortcuts.dnames {
            return None;
        }
        let origin = self.origin_key();
        let mut found = None;
        // From the parent, so the owner is not redirected by its own DNAME, and
        // on to the apex without stopping: the last one seen is the shallowest.
        let mut candidate = parent_name(key)?;
        loop {
            if !is_at_or_under(candidate, &origin) {
                break;
            }
            if let Some(record) = self.first_of_type(candidate, rt::DNAME) {
                found = Some(record);
            }
            if candidate == origin {
                break;
            }
            candidate = parent_name(candidate)?;
        }
        found
    }

    /// Whether there is an RRset of `rtype` at exactly this key. An empty
    /// non-terminal has no positions, so it answers false without a special
    /// case.
    fn has_type(&self, key: &str, rtype: Rtype) -> bool {
        self.first_of_type(key, rtype).is_some()
    }

    /// The first record of `rtype` at exactly this key, or `None`.
    ///
    /// [`Zone::has_type`] is this question with the answer thrown away. DNAME
    /// is a singleton type (RFC 6672 §2.4), so for that one "the first" is
    /// "the one".
    fn first_of_type(&self, key: &str, rtype: Rtype) -> Option<&ZoneRecord> {
        self.index
            .get(key)?
            .iter()
            .map(|&i| &self.records[i])
            .find(|r| record_type_code(&r.rdata) == rtype)
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
    fn note_non_terminals(&mut self, key: &str) {
        // Owned: the loop below takes `&mut self`.
        let origin = self.origin_key().into_owned();
        let mut name = key.to_string();
        while let Some(parent) = parent_name(&name) {
            if !is_at_or_under(parent, &origin) {
                // An owner outside the zone — foreign glue, say. Its ancestors
                // are somebody else's names and do not exist here.
                return;
            }
            let parent = parent.to_string();
            let reached_apex = parent == origin;
            match self.index.entry(NameKeyBuf::new(&parent)) {
                Entry::Occupied(_) => return,
                Entry::Vacant(slot) => slot.insert(Vec::new()),
            };
            if reached_apex {
                return;
            }
            name = parent;
        }
    }

    /// The apex in [`Zone::lookup_key`] form. Borrowed for an already
    /// lower-case origin: two walks ask for this per query.
    fn origin_key(&self) -> Cow<'_, str> {
        ascii_lowered_cow(&self.origin)
    }

    /// Rebuild the index from `records`.
    fn reindex(&mut self) {
        let origin_key = self.origin_key().into_owned();
        let keys: Vec<(String, Rtype, bool)> = self
            .records
            .iter()
            .map(|r| {
                let key = self.lookup_key(&r.name).into_owned();
                let at_apex = key == origin_key;
                (key, record_type_code(&r.rdata), at_apex)
            })
            .collect();
        self.index.clear();
        // Recomputed, not carried: `set_origin` can turn a relative `*` into an
        // absolute wildcard name, and an apex NS RRset into a zone cut.
        self.shortcuts = Shortcuts::default();
        for (position, (key, rtype, at_apex)) in keys.into_iter().enumerate() {
            self.shortcuts.note(&key, rtype, at_apex);
            self.note_non_terminals(&key);
            self.index
                .entry(NameKeyBuf::from_folded(key))
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

    /// The form a name is indexed and looked up under: absolute, and down-cased
    /// because DNS names compare case-insensitively (RFC 4343 — ASCII only,
    /// hence `make_ascii_lowercase` rather than `to_lowercase`).
    ///
    /// A key needing neither step is handed back borrowed, so the ordinary
    /// query reaches the index without allocating.
    fn lookup_key<'a>(&'a self, name: &'a str) -> Cow<'a, str> {
        match self.normalize_name(name) {
            Cow::Borrowed(key) => ascii_lowered_cow(key),
            Cow::Owned(mut key) => {
                key.make_ascii_lowercase();
                Cow::Owned(key)
            }
        }
    }

    /// Whether `record_name` answers `query_name`, wildcards and relative names
    /// included. The definition of matching the index encodes; a test holds the
    /// two to the same answers.
    pub fn matches_query(&self, record_name: &str, query_name: &str) -> bool {
        let record_name = self.lookup_key(record_name);
        let query_name = self.lookup_key(query_name);

        if record_name == query_name {
            return true;
        }
        // Which wildcard reaches a name is a question about the whole zone —
        // the closest encloser decides it — so ask `name_kind` rather than
        // re-deriving it here.
        matches!(self.name_kind_of_key(&query_name), NameKind::Wildcard(w) if w == record_name)
    }

    /// Normalize a domain name to absolute form with a trailing dot. Borrows
    /// back a name that is already absolute. See [`absolutize`].
    pub fn normalize_name<'a>(&'a self, name: &'a str) -> Cow<'a, str> {
        absolutize(name, &self.origin)
    }
}

/// A zone-file owner name in absolute form, resolved against `origin`: `@` and
/// the empty name are the origin itself, a name ending in `.` is already
/// absolute, and anything else is relative to it.
///
/// Only the relative case allocates, and it is the zone parser's; a name off
/// the wire is absolute, and a query takes four of these.
fn absolutize<'a>(name: &'a str, origin: &'a str) -> Cow<'a, str> {
    let name = name.trim();
    if name.is_empty() || name == "@" {
        Cow::Borrowed(origin)
    } else if name.ends_with('.') {
        Cow::Borrowed(name)
    } else {
        Cow::Owned(format!("{name}.{origin}"))
    }
}

/// [`crate::utils::absolute`], owned — this module's callers all keep it.
fn absolute(name: &str) -> String {
    crate::utils::absolute(name).into_owned()
}

/// The small parse helpers below return `Result<_, String>` on purpose: they
/// produce a *detail*, and only their caller — the zone parser — knows the line
/// number to attach it to. A `ZoneError` here would have to invent one.
fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// How many days `month` (1-12) has in `year`, or `None` if that is not a
/// month. `None` and not zero: zero reads as an answer to a caller summing
/// days, which turns month 13 into a plausible epoch for a date that does not
/// exist.
fn days_in_month(month: i32, year: i32) -> Option<i32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap(year) { 29 } else { 28 }),
        _ => None,
    }
}

/// An RRSIG's inception or expiration: a bare epoch, or `YYYYMMDDHHmmSS` in UTC
/// (RFC 4034 §3.2). Every field is range-checked and the result is checked to
/// fit. The inverse is [`format_dnssec_time`].
pub(crate) fn parse_dnssec_time(time_str: &str) -> Result<u32, String> {
    if let Ok(epoch) = time_str.parse::<u32>() {
        return Ok(epoch);
    }

    // Fourteen ASCII digits, established before anything is sliced: the
    // slicing below is by byte, so a 14-byte string holding a multi-byte
    // character would panic on a boundary rather than fail to parse.
    if time_str.len() != 14 || !time_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "Invalid DNSSEC time format: {time_str} (want a bare epoch or 14 digits)"
        ));
    }

    let year = time_str[0..4].parse::<i32>().map_err(|e| e.to_string())?;
    let month = time_str[4..6].parse::<i32>().map_err(|e| e.to_string())?;
    let day = time_str[6..8].parse::<i32>().map_err(|e| e.to_string())?;
    let hour = time_str[8..10].parse::<i32>().map_err(|e| e.to_string())?;
    let min = time_str[10..12].parse::<i32>().map_err(|e| e.to_string())?;
    let sec = time_str[12..14].parse::<i32>().map_err(|e| e.to_string())?;

    // A year before 1970 makes `total_days` negative, which widens into the far
    // future rather than failing.
    if year < 1970 {
        return Err(format!("{time_str}: year {year} is before the POSIX epoch"));
    }
    let days_this_month = days_in_month(month, year)
        .ok_or_else(|| format!("{time_str}: month {month} is not a month"))?;
    if !(1..=days_this_month).contains(&day) {
        return Err(format!(
            "{time_str}: day {day} is not a day of month {month}"
        ));
    }
    // Seconds stop at 59: this converts to POSIX time, which has no leap
    // seconds, so there is no instant for a `:60` to name.
    if hour > 23 || min > 59 || sec > 59 {
        return Err(format!(
            "{time_str}: {hour:02}:{min:02}:{sec:02} is not a time"
        ));
    }

    let mut total_days = 0;
    for y in 1970..year {
        total_days += if is_leap(y) { 366 } else { 365 };
    }
    for m in 1..month {
        // Cannot be `None`: `month` is 1-12 by the check above, so `m` is 1-11.
        total_days += days_in_month(m, year).unwrap_or(0);
    }
    total_days += day - 1;

    let epoch = total_days as i64 * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    // Checked, not `as`: one second past the field truncates to 0, turning a
    // signature dated the far future into one that expired in 1970.
    u32::try_from(epoch)
        .map_err(|_| format!("{time_str} is outside the range a 32-bit DNSSEC timestamp can hold"))
}

/// The `YYYYMMDDHHmmSS` form an RRSIG's times are written in, UTC
/// (RFC 4034 §3.2). The inverse of [`parse_dnssec_time`].
///
/// The parser also accepts a bare epoch and writing that would be shorter, but
/// nothing else in the ecosystem does.
pub(crate) fn format_dnssec_time(epoch: u32) -> String {
    let mut days = (epoch / 86400) as i32;
    let seconds = epoch % 86400;

    let mut year = 1970;
    loop {
        let in_year = if is_leap(year) { 366 } else { 365 };
        if days < in_year {
            break;
        }
        days -= in_year;
        year += 1;
    }

    // Bounded at December rather than trusting the day count to run out: a
    // month contributing zero days would spin until `month` overflowed.
    let mut month = 1;
    while month < 12 {
        let Some(in_month) = days_in_month(month, year) else {
            break;
        };
        if days < in_month {
            break;
        }
        days -= in_month;
        month += 1;
    }

    format!(
        "{year:04}{month:02}{:02}{:02}{:02}{:02}",
        days + 1,
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

/// The type bitmap for a list of type names, as an NSEC or NSEC3 line writes
/// them.
///
/// An unrecognized name is an error, not a silent omission: dropping one turns
/// an NSEC denying six types into one denying five. `TYPEnnn` (RFC 3597 §5)
/// gives every type a spelling, so there is no case where dropping is better.
fn construct_type_bitmap(types: &[String]) -> Result<Vec<u8>, String> {
    let mut codes = Vec::with_capacity(types.len());
    for name in types {
        let code = crate::utils::record_type_name_to_code(&name.to_uppercase())
            .ok_or_else(|| format!("unknown record type {name:?} in type bitmap"))?;
        codes.push(code);
    }
    codes.sort_unstable();
    codes.dedup();
    Ok(crate::denial_wire::build_type_bitmap(&codes))
}

/// Read `\# <length> <hex>` (RFC 3597 §5) into stored form.
///
/// The stated length is checked against the digits rather than trusted, and a
/// known type is parsed once to reject RDATA that is not that type: a malformed
/// record fails the load rather than waiting to fail a query.
fn parse_generic_rdata(record_type: &str, fields: &[&str]) -> Result<RecordData, String> {
    let rtype = crate::utils::record_type_name_to_code(record_type)
        .ok_or_else(|| format!("unknown record type {record_type:?}"))?;

    let Some((length, hex)) = fields.split_first() else {
        return Err("generic rdata needs a length after '\\#'".to_string());
    };
    let length: usize = length
        .parse()
        .map_err(|e| format!("invalid generic rdata length {length:?}: {e}"))?;

    let bytes = hex_decode(&hex.concat()).map_err(|e| format!("invalid generic rdata: {e}"))?;
    if bytes.len() != length {
        return Err(format!(
            "generic rdata says {length} bytes but carries {}",
            bytes.len()
        ));
    }

    // `RecordData::new` is the check: a type with no parser reads back as
    // `Unknown`, so it only rejects a known type whose bytes are not that type.
    RecordData::new(rtype, bytes)
        .map_err(|e| format!("generic rdata is not valid {record_type}: {e}"))
}

/// One record or directive, assembled from as many physical lines as it spans.
struct LogicalLine {
    /// The physical line it started on, so an error still points at the file.
    line_no: usize,
    /// Comments stripped, parentheses removed, continuation lines joined.
    text: String,
    /// The first physical line began with whitespace, so the record inherits the
    /// previous owner name (RFC 1035 §5.1).
    omits_owner: bool,
}

/// Split a zone file into logical lines (RFC 1035 §5.1).
///
/// Not `content.lines()`: parentheses group data across a line boundary, and `;`
/// begins a comment except inside a quoted string.
fn logical_lines(content: &str) -> Result<Vec<LogicalLine>, ZoneError> {
    let mut out: Vec<LogicalLine> = Vec::new();
    let mut pending: Option<LogicalLine> = None;
    let mut depth = 0usize;

    for (idx, raw) in content.lines().enumerate() {
        let ln = idx + 1;
        let mut text = String::with_capacity(raw.len());
        let mut quoted = false;
        let mut escaped = false;

        for c in raw.chars() {
            if escaped {
                text.push(c);
                escaped = false;
                continue;
            }
            match c {
                '\\' => {
                    text.push(c);
                    escaped = true;
                }
                '"' => {
                    quoted = !quoted;
                    text.push(c);
                }
                ';' if !quoted => break, // comment, to the end of the line
                // Replaced with a space, not dropped: `(1` must not be a token.
                '(' if !quoted => {
                    depth += 1;
                    text.push(' ');
                }
                ')' if !quoted => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| ZoneError::syntax(ln, "unmatched ')'"))?;
                    text.push(' ');
                }
                _ => text.push(c),
            }
        }
        if quoted {
            return Err(ZoneError::syntax(ln, "unterminated quoted string"));
        }

        match &mut pending {
            // Inside a group: this line continues the one that opened it.
            Some(open) => {
                let more = text.trim();
                if !more.is_empty() {
                    open.text.push(' ');
                    open.text.push_str(more);
                }
            }
            None => {
                // A blank line outside a group is nothing at all. Inside one —
                // a lone `(` on its own line — it still starts the record, so
                // the line number and indentation come from there.
                if text.trim().is_empty() && depth == 0 {
                    continue;
                }
                pending = Some(LogicalLine {
                    line_no: ln,
                    omits_owner: text.starts_with(|c: char| c.is_whitespace()),
                    text: text.trim().to_string(),
                });
            }
        }

        if depth == 0 {
            if let Some(done) = pending.take() {
                out.push(done);
            }
        }
    }

    if let Some(open) = pending {
        return Err(ZoneError::syntax(
            open.line_no,
            "'(' is never closed before the end of the file",
        ));
    }
    Ok(out)
}

/// Split an assembled line into fields, keeping a quoted string whole.
///
/// Quotes are what say where one `<character-string>` ends, and an empty one
/// (`""`) is legal — neither survives `split_whitespace`. Escapes are resolved
/// inside quotes only: a bare `a\.b` is a name, and names are not this
/// function's business.
fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut in_quotes = false;
    let mut escaped = false;

    for c in text.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if in_quotes => escaped = true,
            '"' => {
                in_quotes = !in_quotes;
                started = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if started {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            c => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        out.push(current);
    }
    out
}

/// How deep `$INCLUDE` may nest. A file that includes itself is otherwise a
/// loop with nothing to stop it.
const MAX_INCLUDE_DEPTH: usize = 8;

/// What the parser carries from one line to the next.
struct ParseState {
    /// The origin relative owner names are resolved against — `$ORIGIN`, or the
    /// origin an `$INCLUDE` named for the file being read.
    origin: String,
    /// The default TTL for records that do not state one (`$TTL`).
    ttl: Ttl,
    /// The last owner name seen, absolute, for lines that omit theirs.
    owner: Option<String>,
}

/// Parse a BIND-format zone file.
///
/// `$INCLUDE` resolves against the working directory: a string of content has no
/// directory of its own. Use [`parse_zone_file_at`] for a file on disk.
pub fn parse_zone_file(content: &str, origin: &str) -> Result<Zone, ZoneError> {
    parse_zone_file_with_base(content, origin, None)
}

/// Parse the zone file at `path`, resolving `$INCLUDE` relative to its directory.
pub fn parse_zone_file_at(path: &Path, origin: &str) -> Result<Zone, ZoneError> {
    let content = std::fs::read_to_string(path).map_err(|source| ZoneError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_zone_file_with_base(&content, origin, path.parent())
}

fn parse_zone_file_with_base(
    content: &str,
    origin: &str,
    base_dir: Option<&Path>,
) -> Result<Zone, ZoneError> {
    let mut zone = Zone::new(origin.to_string());
    let mut state = ParseState {
        origin: absolute(origin),
        ttl: Ttl::from_secs(3600),
        owner: None,
    };
    parse_into(&mut zone, content, &mut state, base_dir, 0)?;
    check_cname_exclusivity(&zone)?;
    check_dname_rules(&zone)?;
    Ok(zone)
}

/// RFC 1034 §3.6.2: a CNAME must be the only type at its owner name. Refused at
/// load, because there is no correct answer to give at query time.
///
/// RRSIG, NSEC and NSEC3 are excepted — they describe the name rather than name
/// it (RFC 4035 §2.5).
fn check_cname_exclusivity(zone: &Zone) -> Result<(), ZoneError> {
    let mut by_name: HashMap<String, (bool, Vec<Rtype>)> = HashMap::new();
    for record in zone.records() {
        let rtype = record_type_code(&record.rdata);
        if matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3) {
            continue;
        }
        let entry = by_name
            .entry(zone.lookup_key(&record.name).into_owned())
            .or_insert((false, Vec::new()));
        if rtype == rt::CNAME {
            entry.0 = true;
        }
        if !entry.1.contains(&rtype) {
            entry.1.push(rtype);
        }
    }

    for (name, (has_cname, types)) in by_name {
        if has_cname && types.len() > 1 {
            let others: Vec<String> = types
                .iter()
                .filter(|&&t| t != rt::CNAME)
                .map(|t| t.to_string())
                .collect();
            return Err(ZoneError::invalid(format!(
                "{name} has a CNAME and also type(s) {} — RFC 1034 §3.6.2 allows a CNAME to be \
                 the only type at a name, and a resolver given both has no way to know which \
                 answer it was meant to get",
                others.join(", ")
            )));
        }
    }
    Ok(())
}

/// What RFC 6672 says a zone holding a DNAME may not do. Refused at load, for
/// the reason [`check_cname_exclusivity`] is: each of these is a name with two
/// answers and no rule for choosing between them.
///
/// The RFC hedges — "ought to refuse" for the singleton rule (§2.4), "MAY
/// refuse" for data below a DNAME (§2.4) and for a wildcard DNAME (§3.3). All
/// three are refused here, because the alternative is a zone that loads and
/// then cannot serve what it holds: a name below a DNAME is occluded
/// (RFC 2136 §7.18) whatever the file says.
///
/// This is the *loader's* check, so a zone that arrives by transfer or is built
/// by dynamic update never meets it — §5.2 has dynamic update adding a DNAME
/// over existing names on purpose. That is why the answer path occludes rather
/// than trusting this: [`Zone::dname_above`] decides the answer for any zone,
/// however it got here.
fn check_dname_rules(zone: &Zone) -> Result<(), ZoneError> {
    let apex = zone.lookup_key(zone.origin()).into_owned();
    let mut owners: Vec<String> = Vec::new();

    for record in zone.records() {
        if record_type_code(&record.rdata) != rt::DNAME {
            continue;
        }
        let key = zone.lookup_key(&record.name).into_owned();

        // §3.3: "records of the form `*.example.com DNAME example.net` SHOULD
        // NOT be used", because "the interaction between the expansion of the
        // wildcard and the redirection of the DNAME is non-deterministic".
        // Non-deterministic is not a thing a server can be asked to serve.
        if key.starts_with("*.") {
            return Err(ZoneError::invalid(format!(
                "{key} is a wildcard DNAME — RFC 6672 §3.3 says the interaction between \
                 wildcard expansion and DNAME redirection is non-deterministic, so there is \
                 no one answer for a server to give"
            )));
        }

        // §2.4: "The owner name of a DNAME can only have one DNAME RR, and no
        // CNAME RRs can exist at that name." Only the first half is here: a
        // CNAME sharing its owner with anything at all is already refused by
        // `check_cname_exclusivity` citing RFC 1034 §3.6.2, the older statement
        // of the same rule. A second check would be a second message for one
        // condition, and the two would drift (`CLAUDE.md` §7).
        if owners.contains(&key) {
            return Err(ZoneError::invalid(format!(
                "{key} has two DNAME records — RFC 6672 §2.4 makes DNAME a singleton type, \
                 so that one name has one redirection and nothing has to choose between them"
            )));
        }

        // §2.3: "DNAME RRs MUST NOT appear at the same owner name as an NS RR
        // unless the owner name is the zone apex; if it is not the zone apex,
        // then the NS RR signifies a delegation point, and the DNAME RR must in
        // that case appear below the zone cut at the zone apex of the child
        // zone."
        if key != apex && zone.has_type(&key, rt::NS) {
            return Err(ZoneError::invalid(format!(
                "{key} has both a DNAME and an NS RRset below the apex — RFC 6672 §2.3 \
                 forbids it, because the NS makes this a zone cut and the DNAME then belongs \
                 in the child zone"
            )));
        }

        owners.push(key);
    }

    if owners.is_empty() {
        return Ok(());
    }

    // §2.4: "Resource records MUST NOT exist at any subdomain of the owner of a
    // DNAME RR."
    //
    // The denial types are exempt. They describe the zone's shape rather than
    // being names it answers for, and a DNAME at the apex — which §2.3 allows
    // outright, SOA and NS beside it — puts every NSEC3 record in the zone
    // below a DNAME owner, so counting them would refuse a zone the RFC spells
    // out as legal.
    for record in zone.records() {
        let rtype = record_type_code(&record.rdata);
        if matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3 | rt::NSEC3PARAM) {
            continue;
        }
        let key = zone.lookup_key(&record.name);
        for owner in &owners {
            if key.as_ref() != owner && is_at_or_under(&key, owner) {
                return Err(ZoneError::invalid(format!(
                    "{key} is below the DNAME at {owner} — RFC 6672 §2.4 says resource \
                     records must not exist at any subdomain of a DNAME owner, and this one \
                     could never be answered with: the redirection is applied before the name \
                     is looked up"
                )));
            }
        }
    }
    Ok(())
}

/// The RDATA half of a zone-file line: everything after the owner name, TTL,
/// class and type have been read off it. Pure, unlike [`parse_into`], which
/// mutates parser state.
///
/// Three views of the fields: `rdata` joined by a space (what every type but TXT
/// wants), `fields` unquoted, and `text_fields` still quoted — a TXT RR is a
/// sequence of character-strings and the quotes say where each ends
/// (RFC 1035 §3.3.14).
fn rdata_from_fields(
    record_type: &str,
    rdata: String,
    fields: &[&str],
    text_fields: &[String],
    ln: usize,
) -> Result<RecordData, ZoneError> {
    Ok(match record_type {
        "A" => {
            let addr = rdata
                .parse::<Ipv4Addr>()
                .map_err(|e| ZoneError::syntax(ln, format!("invalid A address {rdata:?}: {e}")))?;
            RecordData::from_parsed(&ParsedRecord::A(addr))
                .map_err(|e| ZoneError::syntax(ln, format!("A record: {e}")))?
        }
        "AAAA" => {
            let addr = rdata.parse::<Ipv6Addr>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid AAAA address {rdata:?}: {e}"))
            })?;
            RecordData::from_parsed(&ParsedRecord::AAAA(addr))
                .map_err(|e| ZoneError::syntax(ln, format!("AAAA record: {e}")))?
        }
        "NS" => RecordData::from_parsed(&ParsedRecord::NS(rdata))
            .map_err(|e| ZoneError::syntax(ln, format!("NS record: {e}")))?,
        "CNAME" => RecordData::from_parsed(&ParsedRecord::CNAME(rdata))
            .map_err(|e| ZoneError::syntax(ln, format!("CNAME record: {e}")))?,
        "MX" => {
            let mx_parts: Vec<&str> = rdata.split_whitespace().collect();
            if mx_parts.len() < 2 {
                return Err(ZoneError::syntax(
                    ln,
                    format!("MX record needs preference and exchange, got {:?}", rdata),
                ));
            }
            let preference = mx_parts[0].parse::<u16>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid MX preference {:?}: {e}", mx_parts[0]))
            })?;
            RecordData::from_parsed(&ParsedRecord::MX {
                preference,
                exchange: mx_parts[1..].join(" "),
            })
            .map_err(|e| ZoneError::syntax(ln, format!("MX record: {e}")))?
        }
        "TXT" => {
            // Every field after the type is one `<character-string>`
            // (RFC 1035 §3.3.14): `"a b" c` is two, `a b c` is three. The
            // 255-byte ceiling is the encoder's, for every caller.
            let strings: Vec<Vec<u8>> = text_fields.iter().map(|t| t.as_bytes().to_vec()).collect();
            if strings.is_empty() {
                return Err(ZoneError::syntax(ln, "TXT record has no text"));
            }
            RecordData::from_parsed(&ParsedRecord::TXT(strings))
                .map_err(|e| ZoneError::syntax(ln, format!("TXT record: {e}")))?
        }
        "PTR" => RecordData::from_parsed(&ParsedRecord::PTR(rdata))
            .map_err(|e| ZoneError::syntax(ln, format!("PTR record: {e}")))?,
        "DNAME" => RecordData::from_parsed(&ParsedRecord::DNAME(rdata))
            .map_err(|e| ZoneError::syntax(ln, format!("DNAME record: {e}")))?,
        "SOA" => {
            let soa_parts: Vec<&str> = rdata.split_whitespace().collect();
            if soa_parts.len() < 7 {
                return Err(ZoneError::syntax(
                    ln,
                    format!("SOA record needs 7 fields, got {}", soa_parts.len()),
                ));
            }
            let serial = soa_parts[2].parse::<Serial>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid SOA serial {:?}: {e}", soa_parts[2]))
            })?;
            let refresh = soa_parts[3].parse::<i32>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid SOA refresh {:?}: {e}", soa_parts[3]))
            })?;
            let retry = soa_parts[4].parse::<i32>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid SOA retry {:?}: {e}", soa_parts[4]))
            })?;
            let expire = soa_parts[5].parse::<i32>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid SOA expire {:?}: {e}", soa_parts[5]))
            })?;
            let minimum = soa_parts[6].parse::<u32>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid SOA minimum {:?}: {e}", soa_parts[6]))
            })?;
            RecordData::from_parsed(&ParsedRecord::SOA {
                mname: soa_parts[0].to_string(),
                rname: soa_parts[1].to_string(),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("SOA record: {e}")))?
        }
        "DNSKEY" => {
            let key_parts = fields;
            if key_parts.len() < 4 {
                return Err(ZoneError::syntax(
                    ln,
                    format!("DNSKEY record needs 4 fields, got {}", key_parts.len()),
                ));
            }
            let flags = key_parts[0].parse::<u16>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid DNSKEY flags {:?}: {e}", key_parts[0]))
            })?;
            let protocol = key_parts[1].parse::<u8>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid DNSKEY protocol {:?}: {e}", key_parts[1]),
                )
            })?;
            let algorithm = key_parts[2].parse::<u8>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid DNSKEY algorithm {:?}: {e}", key_parts[2]),
                )
            })?;
            let b64_key = key_parts[3..].join("");
            let public_key = base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &b64_key)
                .map_err(|e| ZoneError::syntax(ln, format!("invalid DNSKEY base64 key: {e}")))?;
            RecordData::from_parsed(&ParsedRecord::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("DNSKEY record: {e}")))?
        }
        "DS" => {
            let ds_parts = fields;
            if ds_parts.len() < 4 {
                return Err(ZoneError::syntax(
                    ln,
                    format!("DS record needs 4 fields, got {}", ds_parts.len()),
                ));
            }
            let key_tag = ds_parts[0].parse::<u16>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid DS key tag {:?}: {e}", ds_parts[0]))
            })?;
            let algorithm = ds_parts[1].parse::<u8>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid DS algorithm {:?}: {e}", ds_parts[1]))
            })?;
            let digest_type = ds_parts[2].parse::<u8>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid DS digest type {:?}: {e}", ds_parts[2]))
            })?;
            let hex_digest = ds_parts[3..].join("");
            let digest = hex_decode(&hex_digest)
                .map_err(|e| ZoneError::syntax(ln, format!("invalid DS digest: {e}")))?;
            RecordData::from_parsed(&ParsedRecord::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("DS record: {e}")))?
        }
        "RRSIG" => {
            let rrsig_parts = fields;
            if rrsig_parts.len() < 9 {
                return Err(ZoneError::syntax(
                    ln,
                    format!("RRSIG record needs 9 fields, got {}", rrsig_parts.len()),
                ));
            }
            let type_covered =
                crate::utils::record_type_name_to_code(rrsig_parts[0]).ok_or_else(|| {
                    ZoneError::syntax(
                        ln,
                        format!("unknown RRSIG type covered {:?}", rrsig_parts[0]),
                    )
                })?;
            let algorithm = rrsig_parts[1].parse::<u8>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG algorithm {:?}: {e}", rrsig_parts[1]),
                )
            })?;
            let labels = rrsig_parts[2].parse::<u8>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG labels {:?}: {e}", rrsig_parts[2]),
                )
            })?;
            let original_ttl = rrsig_parts[3].parse::<u32>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG original TTL {:?}: {e}", rrsig_parts[3]),
                )
            })?;
            let expiration = parse_dnssec_time(rrsig_parts[4]).map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG expiration {:?}: {e}", rrsig_parts[4]),
                )
            })?;
            let inception = parse_dnssec_time(rrsig_parts[5]).map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG inception {:?}: {e}", rrsig_parts[5]),
                )
            })?;
            let key_tag = rrsig_parts[6].parse::<u16>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid RRSIG key tag {:?}: {e}", rrsig_parts[6]),
                )
            })?;
            let signer_name = rrsig_parts[7].to_string();
            let b64_sig = rrsig_parts[8..].join("");
            let signature = base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &b64_sig)
                .map_err(|e| {
                    ZoneError::syntax(ln, format!("invalid RRSIG base64 signature: {e}"))
                })?;
            RecordData::from_parsed(&ParsedRecord::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name,
                signature,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("RRSIG record: {e}")))?
        }
        "NSEC" => {
            let nsec_parts = fields;
            if nsec_parts.len() < 2 {
                return Err(ZoneError::syntax(
                    ln,
                    format!(
                        "NSEC record needs next domain and at least one type, got {}",
                        nsec_parts.len()
                    ),
                ));
            }
            let next_domain_name = nsec_parts[0].to_string();
            let type_names: Vec<String> = nsec_parts[1..].iter().map(|s| s.to_string()).collect();
            let type_bitmap = construct_type_bitmap(&type_names)
                .map_err(|e| ZoneError::syntax(ln, format!("NSEC record: {e}")))?;
            RecordData::from_parsed(&ParsedRecord::NSEC {
                next_domain_name,
                type_bitmap,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("NSEC record: {e}")))?
        }
        "NSEC3" => {
            let nsec3_parts = fields;
            if nsec3_parts.len() < 5 {
                return Err(ZoneError::syntax(
                    ln,
                    format!(
                        "NSEC3 record needs at least 5 fields, got {}",
                        nsec3_parts.len()
                    ),
                ));
            }
            let hash_algorithm = nsec3_parts[0].parse::<u8>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid NSEC3 hash algorithm {:?}: {e}", nsec3_parts[0]),
                )
            })?;
            let flags = nsec3_parts[1].parse::<u8>().map_err(|e| {
                ZoneError::syntax(ln, format!("invalid NSEC3 flags {:?}: {e}", nsec3_parts[1]))
            })?;
            let iterations = nsec3_parts[2].parse::<u16>().map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid NSEC3 iterations {:?}: {e}", nsec3_parts[2]),
                )
            })?;
            let salt_str = nsec3_parts[3];
            let salt = if salt_str == "-" {
                Vec::new()
            } else {
                hex_decode(salt_str).map_err(|e| {
                    ZoneError::syntax(ln, format!("invalid NSEC3 salt {:?}: {e}", salt_str))
                })?
            };
            // `denial_wire`'s decoder, not a second one: the copy that used to
            // live here folded case with `str::to_uppercase`, which is the
            // Unicode fold RFC 4343 forbids (`TODO.md` #26b).
            let next_hashed_owner = base32hex_decode(nsec3_parts[4]).map_err(|e| {
                ZoneError::syntax(
                    ln,
                    format!("invalid NSEC3 next hashed owner {:?}: {e}", nsec3_parts[4]),
                )
            })?;
            let type_names: Vec<String> = nsec3_parts[5..].iter().map(|s| s.to_string()).collect();
            let type_bitmap = construct_type_bitmap(&type_names)
                .map_err(|e| ZoneError::syntax(ln, format!("NSEC3 record: {e}")))?;
            RecordData::from_parsed(&ParsedRecord::NSEC3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner,
                type_bitmap,
            })
            .map_err(|e| ZoneError::syntax(ln, format!("NSEC3 record: {e}")))?
        }
        other => {
            return Err(ZoneError::syntax(
                ln,
                format!("unsupported record type {other:?}"),
            ));
        }
    })
}

fn parse_into(
    zone: &mut Zone,
    content: &str,
    state: &mut ParseState,
    base_dir: Option<&Path>,
    depth: usize,
) -> Result<(), ZoneError> {
    for logical in logical_lines(content)? {
        let ln = logical.line_no;
        // Quoted strings stay whole; `parts` is the plain view of the same
        // fields, which is all any record but TXT needs.
        let tokens = tokenize(&logical.text);
        let parts: Vec<&str> = tokens.iter().map(String::as_str).collect();
        let Some(&first) = parts.first() else {
            continue;
        };

        if first.eq_ignore_ascii_case("$ORIGIN") {
            if let Some(new_origin) = parts.get(1) {
                state.origin = absolutize(new_origin, &state.origin).into_owned();
                // Only the top-level file may move the apex: RFC 1035 §5.1 keeps
                // an include's origin to the included file.
                if depth == 0 {
                    zone.set_origin(&state.origin.clone());
                }
            }
            continue;
        }

        if first.eq_ignore_ascii_case("$TTL") {
            if let Some(value) = parts.get(1) {
                state.ttl = value
                    .parse::<u32>()
                    .map(Ttl::from_secs)
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid $TTL {value:?}: {e}")))?;
            }
            continue;
        }

        // `$INCLUDE <file> [origin]`
        if first.eq_ignore_ascii_case("$INCLUDE") {
            let Some(&file) = parts.get(1) else {
                return Err(ZoneError::syntax(ln, "$INCLUDE needs a file name"));
            };
            if depth + 1 >= MAX_INCLUDE_DEPTH {
                return Err(ZoneError::syntax(
                    ln,
                    format!("$INCLUDE nested more than {MAX_INCLUDE_DEPTH} deep — a cycle?"),
                ));
            }
            let path = match base_dir {
                Some(dir) => dir.join(file),
                None => PathBuf::from(file),
            };
            let included = std::fs::read_to_string(&path)
                .map_err(|e| ZoneError::syntax(ln, format!("$INCLUDE {}: {e}", path.display())))?;

            // RFC 1035 §5.1: the origin is for the included file only, so the
            // state goes in as a copy and none of it comes back. The owner name
            // does not carry across either.
            let mut inner = ParseState {
                origin: parts
                    .get(2)
                    .map(|o| absolutize(o, &state.origin).into_owned())
                    .unwrap_or_else(|| state.origin.clone()),
                ttl: state.ttl,
                owner: None,
            };
            parse_into(zone, &included, &mut inner, path.parent(), depth + 1)?;
            continue;
        }

        // `[name] [ttl] [class] type rdata...` — position tells the owner name
        // from a TTL/class/type, not the token's shape: `ns IN A …` is a host
        // called `ns`, not an NS record.
        //
        // Resolved against the origin in force here, which is what makes
        // `$ORIGIN` apply to the lines below it only.
        let mut idx = 0;
        let record_name = if logical.omits_owner {
            state.owner.clone().ok_or_else(|| {
                ZoneError::syntax(
                    ln,
                    "record omits its owner name but no previous record supplies one",
                )
            })?
        } else {
            // RFC 1035 §5.1 makes `a\.b` one label of three octets, which a
            // name stored as presentation text with `.` as the separator cannot
            // represent. Refused at load rather than mis-encoded into two
            // labels; resolving would need a different stored form.
            if first.contains('\\') {
                return Err(ZoneError::syntax(
                    ln,
                    format!(
                        "owner name {first:?} contains an escape, which this parser does not \
                         resolve and cannot represent; see RFC 1035 §5.1"
                    ),
                ));
            }
            let name = absolutize(first, &state.origin).into_owned();
            state.owner = Some(name.clone());
            idx += 1;
            name
        };

        let mut ttl = state.ttl;
        // Always IN: the branch below refuses any other class outright. A zone
        // is single-class by construction, which is what makes the class-blind
        // index correct rather than merely untested. A CH zone needs its own
        // apex and its own place in the zone map.
        let mut class = Class::IN;

        while idx < parts.len() {
            if let Ok(parsed_ttl) = parts[idx].parse::<i32>() {
                ttl = Ttl::from_wire(parsed_ttl);
                state.ttl = ttl;
                idx += 1;
            } else if parts[idx].eq_ignore_ascii_case("IN")
                || parts[idx].eq_ignore_ascii_case("CH")
                || parts[idx].eq_ignore_ascii_case("HS")
            {
                if !parts[idx].eq_ignore_ascii_case("IN") {
                    return Err(ZoneError::syntax(
                        ln,
                        format!(
                            "class {} is not served: a zone here is IN, and a record of another \
                             class in it would answer IN queries with a class it never matched",
                            parts[idx].to_uppercase()
                        ),
                    ));
                }
                class = Class::IN;
                idx += 1;
            } else {
                break;
            }
        }

        if idx >= parts.len() {
            continue;
        }

        let record_type = parts[idx].to_uppercase();
        idx += 1;
        let rdata = parts[idx..].join(" ");

        // RFC 3597 §5's generic form, `\# <length> <hex>`: the only way to write
        // a type with no parser here, and what the zone writer emits when the
        // type-specific spelling would not read back as the same bytes. §5
        // permits it for known types too, so it is accepted for them.
        if parts.get(idx).is_some_and(|token| *token == "\\#") {
            let rdata = parse_generic_rdata(&record_type, &parts[idx + 1..])
                .map_err(|e| ZoneError::syntax(ln, format!("{record_type} record: {e}")))?;
            zone.add_record(ZoneRecord {
                name: record_name,
                ttl,
                class,
                rdata,
            });
            continue;
        }

        let rdata: RecordData =
            rdata_from_fields(&record_type, rdata, &parts[idx..], &tokens[idx..], ln)?;

        zone.add_record(ZoneRecord {
            name: record_name,
            ttl,
            class,
            rdata,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::record_types;

    #[test]
    fn test_zone_creation() {
        let zone = Zone::new("example.com".to_string());
        assert_eq!(zone.origin, "example.com.");
    }

    /// A `Zone` built record by record can hold the apex SOA under `@`, which
    /// is what the zone file said. Every question about "is this the apex SOA"
    /// therefore has to normalize first, and two of the five places that asked
    /// it compared the stored name raw (`TODO.md` #33f).
    #[test]
    fn the_apex_soa_is_found_under_an_unabsolutized_owner_name() {
        let mut zone = Zone::new("example.com.".to_string());
        zone.add_record(ZoneRecord {
            name: "@".to_string(),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::SOA {
                mname: "ns1.example.com.".to_string(),
                rname: "admin.example.com.".to_string(),
                serial: Serial::new(7),
                refresh: 3600,
                retry: 600,
                expire: 604800,
                minimum: 300,
            })
            .unwrap(),
        });

        let soa = zone.apex_soa().expect("the apex SOA, stored as `@`");
        assert!(zone.is_apex_soa(soa));
        assert_eq!(zone.serial(), Some(Serial::new(7)));
        assert_eq!(
            zone.apex_soa_record().expect("as a record").name,
            "example.com.",
            "the record that goes on the wire carries the absolute owner name"
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
            zone.delegation_for("www.example.com."),
            None,
            "at its own apex an NS RRset is the zone's own, not a cut"
        );

        zone.set_origin("com.");
        assert_eq!(
            zone.delegation_for("www.example.com."),
            Some("example.com.".to_string()),
            "example.com. is a child now, and it has an NS RRset"
        );
    }

    /// The other way the flag is maintained: a zone gaining its first cut after
    /// it was built, which is the incremental path rather than the reindex.
    #[test]
    fn test_a_delegation_added_after_load_is_still_found() {
        let mut zone = parse_zone_file("www IN A 192.0.2.10\n", "example.com.").unwrap();
        assert_eq!(zone.delegation_for("host.sub.example.com."), None);

        zone.add_record(ZoneRecord {
            name: "sub.example.com.".to_string(),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::NS("ns1.sub.example.com.".to_string()))
                .unwrap(),
        });
        assert_eq!(
            zone.delegation_for("host.sub.example.com."),
            Some("sub.example.com.".to_string())
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
        assert_eq!(zone.origin, "example.com.");
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
                zone.query(name, Qtype::of(record_types::A)).len(),
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
        assert_eq!(zone.records[0].name, "www.example.com.");
        assert_eq!(zone.query("www.example.com.", Qtype::of(rt::A)).len(), 1);
    }

    #[test]
    fn test_owner_name_may_contain_digits() {
        let zone = parse_zone_file("www2 IN A 192.0.2.6\n", "example.com.").unwrap();
        assert_eq!(zone.records[0].name, "www2.example.com.", "stored absolute");
        assert_eq!(zone.query("www2.example.com.", Qtype::of(rt::A)).len(), 1);
    }

    #[test]
    fn test_owner_name_may_look_like_a_record_type() {
        // Position, not the token's spelling, decides what the first field is.
        let zone = parse_zone_file("ns IN A 192.0.2.7\n", "example.com.").unwrap();
        assert_eq!(zone.records[0].name, "ns.example.com.");
        assert_eq!(
            zone.query("ns.example.com.", Qtype::of(rt::A)).len(),
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
        assert_eq!(zone.records[1].name, "www.example.com.");
        assert_eq!(zone.query("www.example.com.", Qtype::of(rt::A)).len(), 2);
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
            zone.query("example.com.", Qtype::of(rt::A)).len(),
            1,
            "@ should match the apex"
        );
        assert_eq!(zone.query("www.example.com.", Qtype::of(rt::A)).len(), 1);
        // DNS names are case-insensitive (RFC 4343).
        assert_eq!(zone.query("WWW.Example.COM.", Qtype::of(rt::A)).len(), 1);
    }

    /// Which of `normalize_name`'s three cases copies. Asserted on the `Cow` arm,
    /// not the value, which is the same either way.
    #[test]
    fn normalizing_a_name_copies_only_when_it_changes() {
        let zone = parse_zone_file("@ IN A 192.0.2.1\n", "example.com.").unwrap();

        assert!(matches!(
            zone.normalize_name("www.example.com."),
            Cow::Borrowed("www.example.com.")
        ));
        // `@` and the empty name are the origin, which the zone already holds.
        assert!(matches!(
            zone.normalize_name("@"),
            Cow::Borrowed("example.com.")
        ));
        // A relative name is the one case where the result exists nowhere yet.
        assert!(matches!(
            zone.normalize_name("www"),
            Cow::Owned(ref name) if name == "www.example.com."
        ));
    }

    #[test]
    fn test_wildcard_answers_a_name_that_does_not_exist() {
        let zone = parse_zone_file("* IN A 192.0.2.9\n", "example.com.").unwrap();
        assert_eq!(
            zone.query("anything.example.com.", Qtype::of(rt::A)).len(),
            1
        );
        // And it does not answer for the name it hangs off.
        assert!(zone.query("example.com.", Qtype::of(rt::A)).is_empty());
    }

    /// RFC 4592 §3.3.2's worked example: `*.example.` answers
    /// `_telnet._tcp.host1.example.`, three labels below the wildcard's parent.
    /// §2.1.1 is about `*` in zone-file syntax and says nothing about depth.
    #[test]
    fn test_a_wildcard_synthesizes_at_any_depth() {
        let zone = parse_zone_file("* IN A 192.0.2.9\n", "example.").unwrap();
        assert_eq!(
            zone.query("_telnet._tcp.host1.example.", Qtype::of(rt::A))
                .len(),
            1,
            "RFC 4592 §3.3.2 synthesizes this from *.example."
        );
        assert_eq!(zone.query("a.b.example.", Qtype::of(rt::A)).len(), 1);
        assert!(zone.name_exists("a.b.c.d.e.f.example."));
        assert_eq!(
            zone.name_kind("a.b.example."),
            NameKind::Wildcard("*.example.".to_string())
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
                let (kind, records) = zone.query_with_kind(name, qtype);
                assert_eq!(kind, zone.name_kind(name), "kind for {name} {qtype:?}");
                assert_eq!(
                    records.len(),
                    zone.query(name, qtype).len(),
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
            zone.query("other.example.com.", Qtype::of(rt::A)).len(),
            1,
            "nothing above it"
        );
        assert!(
            zone.query("x.a.b.example.com.", Qtype::of(rt::A))
                .is_empty(),
            "a.b exists, so *.example.com. is not this name's source of synthesis"
        );
        assert_eq!(
            zone.name_kind("x.a.b.example.com."),
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
            zone.delegation_for("anything.sub.example.com.").as_deref(),
            Some("sub.example.com."),
        );
        assert_eq!(
            zone.name_kind("anything.sub.example.com."),
            NameKind::NotFound,
            "occluded: the wildcard is below the cut, so it is not ours to expand"
        );
        // The apex NS RRset is not a cut.
        assert_eq!(zone.delegation_for("www.example.com."), None);
        // A query at the cut itself is still a referral.
        assert_eq!(
            zone.delegation_for("sub.example.com.").as_deref(),
            Some("sub.example.com.")
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
                zone.name_kind("a.b.example.com."),
                NameKind::Exact,
                "{order}"
            );
            assert!(zone.holds_name("a.b.example.com."), "{order}");
            assert_eq!(
                zone.name_kind("b.example.com."),
                NameKind::EmptyNonTerminal,
                "{order}: still only an ancestor"
            );
            assert!(!zone.holds_name("b.example.com."), "{order}");
            assert_eq!(
                zone.name_kind("nope.b.example.com."),
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
                zone.name_kind(ent),
                NameKind::EmptyNonTerminal,
                "{ent} has descendants, so it exists"
            );
            assert!(zone.name_exists(ent), "{ent}");
            assert!(
                !zone.holds_name(ent),
                "{ent} still holds no records of its own — the denial path needs that answer"
            );
            assert!(
                zone.query(ent, Qtype::of(rt::TXT)).is_empty(),
                "{ent}: NODATA, no records"
            );
        }

        assert_eq!(zone.name_kind("deep.a.b.example.com."), NameKind::Exact);
        assert_eq!(zone.name_kind("gone.a.b.example.com."), NameKind::NotFound);
        // The walk does not conjure names outside the zone into existence.
        assert_eq!(zone.name_kind("com."), NameKind::NotFound);
        assert_eq!(zone.name_kind("elsewhere.test."), NameKind::NotFound);
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
            .dname_above("a.b.sub.example.com.")
            .expect("a DNAME two labels up redirects");
        assert_eq!(found.name, "sub.example.com.");

        assert!(
            zone.dname_above("sub.example.com.").is_none(),
            "§2.3: the owner name of a DNAME is not redirected itself"
        );
        assert!(
            zone.dname_above("other.example.com.").is_none(),
            "a name that is not below the owner is not redirected"
        );
        // Table 1: QNAME `ab.example.com.` against owner `b.example.com.` is
        // `<no match>`. Whole labels only, never a string suffix.
        assert!(
            zone.dname_above("absub.example.com.").is_none(),
            "the match is on whole labels"
        );
    }

    /// A zone with no DNAME never walks a name's ancestors looking for one.
    #[test]
    fn a_zone_with_no_dname_answers_without_walking() {
        let zone = parse_zone_file("www IN A 192.0.2.1\n", "example.com.").unwrap();
        assert!(zone.dname_above("deep.down.www.example.com.").is_none());
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

        let a = zone.query("www.example.com.", Qtype::of(rt::A));
        assert!(
            a.is_empty(),
            "www exists, so the wildcard must not answer for it: {a:?}"
        );
        assert_eq!(
            zone.query("www.example.com.", Qtype::of(rt::AAAA)).len(),
            1,
            "its own AAAA"
        );
        // Any other name still gets the wildcard.
        assert_eq!(zone.query("other.example.com.", Qtype::of(rt::A)).len(), 1);
    }

    #[test]
    fn test_name_exists_distinguishes_nodata_from_nxdomain() {
        let zone = parse_zone_file(
            "* IN A 192.0.2.9\nwww IN AAAA 2001:db8::1\n",
            "example.com.",
        )
        .unwrap();

        assert!(zone.name_exists("www.example.com."), "by its own records");
        assert!(
            zone.name_exists("other.example.com."),
            "through the wildcard — NODATA, not NXDOMAIN"
        );
        assert!(
            zone.name_exists("a.b.example.com."),
            "the wildcard reaches any depth (RFC 4592 §3.3.2) — NODATA, not NXDOMAIN"
        );
        assert!(!zone.name_exists("elsewhere.test."));
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
                .any(|r| zone.matches_query(&r.name, name));
            assert_eq!(
                zone.name_exists(name),
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
            zone.query("www.example.com.", Qtype::of(rt::A)).len(),
            1,
            "www was read before the $ORIGIN and stays where it was"
        );
        assert_eq!(zone.query("mail.other.test.", Qtype::of(rt::A)).len(), 1);
        assert!(zone.query("www.other.test.", Qtype::of(rt::A)).is_empty());
    }

    /// The `set_origin` re-key. Only names added relative through the API need
    /// it; the parser resolves as it goes.
    #[test]
    fn test_set_origin_rekeys_relative_records() {
        let mut zone = Zone::new("example.com.".to_string());
        zone.add_record(ZoneRecord {
            name: "www".to_string(),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });
        assert_eq!(zone.query("www.example.com.", Qtype::of(rt::A)).len(), 1);

        zone.set_origin("other.test.");
        assert_eq!(
            zone.query("www.other.test.", Qtype::of(rt::A)).len(),
            1,
            "a relative name follows the origin it is relative to"
        );
        assert!(zone.query("www.example.com.", Qtype::of(rt::A)).is_empty());
    }

    /// A record added after the zone is built has to be reachable.
    #[test]
    fn test_records_added_later_are_indexed() {
        let mut zone = Zone::new("example.com.".to_string());
        assert!(zone.query("www.example.com.", Qtype::of(rt::A)).is_empty());

        zone.add_record(ZoneRecord {
            name: "www".to_string(),
            ttl: Ttl::from_secs(3600),
            class: Class::new(1),
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });
        assert_eq!(zone.query("www.example.com.", Qtype::of(rt::A)).len(), 1);
        assert!(zone.name_exists("www.example.com."));
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
        let soa = zone.query("example.com.", Qtype::of(crate::utils::record_types::SOA));
        assert_eq!(soa.len(), 1, "the SOA should have loaded");
        match soa[0].rdata.parse().unwrap() {
            ParsedRecord::SOA {
                mname,
                serial,
                minimum,
                ..
            } => {
                assert_eq!(mname, "ns1.example.com.");
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
        assert_eq!(zone.query("example.com.", Qtype::of(rt::A)).len(), 1);
    }

    /// A `;` inside a quoted string is data, not a comment — SPF and DKIM
    /// records are mostly semicolons.
    #[test]
    fn test_semicolon_inside_a_quoted_string_survives() {
        let zone_content = "txt IN TXT \"v=spf1 include:example.net; -all\"\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        let txt = zone.query(
            "txt.example.com.",
            Qtype::of(crate::utils::record_types::TXT),
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
                "txt.example.com.",
                Qtype::of(crate::utils::record_types::TXT),
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
    struct ScratchDir(std::path::PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!("rdns-zone-{tag}-{unique}"));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            ScratchDir(dir)
        }

        fn write(&self, name: &str, content: &str) -> std::path::PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, content).expect("write scratch file");
            path
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_include_pulls_in_records_relative_to_the_including_file() {
        let dir = ScratchDir::new("include");
        dir.write("hosts.inc", "mail IN A 192.0.2.20\nwww IN A 192.0.2.21\n");
        let main = dir.write(
            "example.com.zone",
            "@ IN A 192.0.2.1\n$INCLUDE hosts.inc\nftp IN A 192.0.2.22\n",
        );

        let zone = parse_zone_file_at(&main, "example.com.").unwrap();
        assert_eq!(
            zone.query("mail.example.com.", Qtype::of(rt::A)).len(),
            1,
            "from the include"
        );
        assert_eq!(zone.query("www.example.com.", Qtype::of(rt::A)).len(), 1);
        assert_eq!(
            zone.query("ftp.example.com.", Qtype::of(rt::A)).len(),
            1,
            "parsing continues after the include"
        );
        assert_eq!(zone.query("example.com.", Qtype::of(rt::A)).len(), 1);
    }

    /// `$INCLUDE file origin` reads the file under that origin and does not
    /// change the including file's (RFC 1035 §5.1).
    #[test]
    fn test_include_origin_applies_to_the_included_file_only() {
        let dir = ScratchDir::new("include-origin");
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
            zone.query("ns.deeper.example.com.", Qtype::of(rt::A)).len(),
            1,
            "the included file's own $ORIGIN applies inside it"
        );
        assert_eq!(
            zone.query("after.example.com.", Qtype::of(rt::A)).len(),
            1,
            "and neither origin leaks back out to the including file"
        );
        assert_eq!(zone.origin(), "example.com.", "the apex is untouched");
    }

    #[test]
    fn test_include_of_a_missing_file_is_an_error() {
        let dir = ScratchDir::new("include-missing");
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
        let dir = ScratchDir::new("include-cycle");
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
        let record = zone.query("odd.example.com.", Qtype::of(Rtype::new(1234)));
        assert_eq!(record.len(), 1);
        assert_eq!(record[0].rdata.bytes(), [0xde, 0xad, 0xbe, 0xef]);
    }

    /// RFC 3597 §5 permits the generic form for a known type too.
    #[test]
    fn test_generic_rdata_is_accepted_for_a_known_type() {
        let zone = parse_zone_file("www IN A \\# 4 C0000201\n", "example.com.").unwrap();
        assert!(matches!(
            zone.query("www.example.com.", Qtype::of(record_types::A))[0].rdata.parse(),
            Ok(ParsedRecord::A(addr)) if addr == Ipv4Addr::new(192, 0, 2, 1)
        ));
    }

    #[test]
    fn test_generic_rdata_of_zero_length() {
        let zone = parse_zone_file("empty IN TYPE4321 \\# 0\n", "example.com.").unwrap();
        assert!(
            zone.query("empty.example.com.", Qtype::of(Rtype::new(4321)))[0]
                .rdata
                .bytes()
                .is_empty()
        );
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
        let record = zone.query("example.com.", Qtype::of(record_types::NSEC))[0];
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
        let mx = rdata_from_fields("MX", "10 mx.example.com.".into(), &fields, &text, 1)
            .expect("a well-formed MX");
        assert_eq!(
            mx.parse().unwrap(),
            ParsedRecord::MX {
                preference: 10,
                exchange: "mx.example.com.".into(),
            }
        );

        // The line number travels with the error: the helpers return a detail
        // and this function attaches the position.
        let bad = ["notanumber", "mx.example.com."];
        let text: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
        let err = rdata_from_fields("MX", "notanumber mx.example.com.".into(), &bad, &text, 42)
            .expect_err("preference is not a number");
        assert!(err.to_string().contains("42"), "got {err}");
    }

    #[test]
    fn test_malformed_ttl_directive_surfaces_error() {
        let zone_content = "$TTL notanumber\nwww IN A 192.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(err.to_string().contains("$TTL"), "got: {err}");
    }
    /// An escape in a name is refused rather than mis-encoded. RFC 1035 §5.1
    /// makes `a\.b` one label of three octets, which presentation text with `.`
    /// as the separator cannot hold.
    #[test]
    fn an_escape_in_a_name_is_refused_rather_than_mis_encoded() {
        let err = parse_zone_file("a\\.b IN A 192.0.2.1\n", "example.com.")
            .expect_err("an escaped dot in an owner name");
        assert!(
            err.to_string().contains("escape"),
            "the error should say what it refused: {err}"
        );

        // The same in a name-valued RDATA field.
        assert!(
            parse_zone_file("www IN CNAME a\\.b.example.com.\n", "example.com.").is_err(),
            "an escaped dot in a CNAME target"
        );

        // And an ordinary name with no escape still parses.
        parse_zone_file("www IN A 192.0.2.1\n", "example.com.").expect("no escape, no problem");
    }
}
