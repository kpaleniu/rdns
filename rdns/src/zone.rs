//! One zone in memory, and every question RFC 1034 §4.3.2 asks of it.
//!
//! The membership rule is that the answer is in this zone's own records. A name
//! is looked up once ([`Zone::locate`]) and what comes back says *why* it has an
//! answer or has none ([`NameKind`]) — exact, an empty non-terminal, a wildcard
//! match, or absent — because those four owe four different answers and three of
//! them are "the name exists".
//!
//! What is deliberately not here:
//!
//! - **The reply.** Which section a record goes in, what the AA bit says, what a
//!   negative answer owes as proof: `rdnsd`'s `answer` and
//!   [`crate::dnssec_answer`]. A zone has no opinion about a client.
//! - **Anything across zones.** Which zone a question belongs to is the
//!   daemon's `ZoneMap`, and a referral to a child is a record in *this* zone.
//! - **Signing.** [`crate::zone_signer`] builds the chains; this module stores
//!   them and searches them by range, which is why they are `BTreeMap`s while the
//!   name index is a `HashMap`.
//!
//! `origin` and `records` are private because the index and the shortcuts are
//! derived from both: a record appended behind the type's back leaves the zone
//! answering NXDOMAIN for data it holds.
//!
//! The three submodules are the cuts a 2,000-line file wanted, all private:
//! `parse` is the zone *file*, `rdata` is one record's RDATA from presentation
//! fields, and `checks` is what must be refused at load because it has no correct
//! answer at query time.

use crate::denial_wire::{base32hex_decode, canonical_sort_key, CanonicalKey, Nsec3Hash};
use crate::record_types as rt;
use crate::Class;
use crate::Rtype;
use crate::Serial;
use crate::Ttl;
use crate::{
    Name, NameArena, NameRef, NameSpan, Qtype, RdataArena, RdataSpan, RecordData, RecordDataRef,
    ResourceRecord,
};
use std::borrow::Cow;
use std::collections::BTreeMap;

mod checks;
mod parse;
mod rdata;

pub use parse::{parse_zone_file, parse_zone_file_at, parse_zone_text_at};

/// The origin a zone file's name says it holds: `example.com.zone` is
/// `example.com.`, and a name without the extension is taken whole.
///
/// The rule `rdnsd` reads a zone directory by, and the fallback
/// [`crate::rpz::PolicyZone::load`] uses when a policy zone has no `$ORIGIN`
/// line. It lived in `rdnsd` alone until the second caller (`CLAUDE.md` §7):
/// two files deciding what a zone is called would disagree eventually.
pub fn origin_from_path(path: &str) -> String {
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("zone");
    let origin = file_name.strip_suffix(".zone").unwrap_or(file_name);
    if origin.ends_with('.') {
        origin.to_string()
    } else {
        format!("{origin}.")
    }
}

/// What a zone file held when this process last parsed it, for telling a file
/// that moved from one that did not.
///
/// Not a cryptographic digest: the question is whether the bytes changed, and
/// anybody who can rewrite a zone file already owns the process.
/// `DefaultHasher` is not stable across Rust releases, which does not matter —
/// every comparison is against a value this same process computed, and a
/// restart re-reads anyway.
///
/// One copy for three callers — `rdnsd`'s UPDATE path (`TODO.md` #64b) and its
/// reload path (#64f), and the resolver's policy reload (#71b) — because two
/// implementations of "did these bytes change" is how the two answers come to
/// differ (`CLAUDE.md` §7). It lived in `rdnsd` alone until the third.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileDigest(u64);

impl FileDigest {
    /// The digest of bytes whose content is entirely their own — text this
    /// process wrote, or a file already known to carry no `$INCLUDE`.
    pub fn of(bytes: &[u8]) -> FileDigest {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        bytes.hash(&mut hasher);
        FileDigest(hasher.finish())
    }

    /// The digest of a file read from disk, or `None` when it `$INCLUDE`s
    /// another.
    ///
    /// A digest of the parent says nothing about the included file, so an edit
    /// to that one would be invisible — the exact failure a re-read exists to
    /// prevent (`CLAUDE.md` §4, `TODO.md` #64f). `None` rather than a digest
    /// that would compare equal, so a caller cannot skip work on the strength
    /// of it: the omission is the rule.
    ///
    /// A textual test rather than a report from the parser: it cannot miss one,
    /// because an `$INCLUDE` the parser acts on is by definition in the text,
    /// and a false positive inside a TXT record costs one re-parse.
    pub fn of_self_contained(bytes: &[u8]) -> Option<FileDigest> {
        // `eq_ignore_ascii_case` rather than uppercasing the line:
        // `to_ascii_uppercase` allocates a copy of every line, and a feed is a
        // line per rule.
        const DIRECTIVE: &[u8] = b"$INCLUDE";
        let included = bytes.split(|b| *b == b'\n').any(|line| {
            let head = line.trim_ascii_start();
            head.len() >= DIRECTIVE.len() && head[..DIRECTIVE.len()].eq_ignore_ascii_case(DIRECTIVE)
        });
        (!included).then(|| FileDigest::of(bytes))
    }
}

/// Positions in [`Zone::records`], by the folded wire form of the owner name:
/// every name in one arena, and a table whose entries do not own their key.
///
/// A name that exists only because something below it does — an empty
/// non-terminal (RFC 4592 §2.2.2) — is an entry with **no positions**. It was a
/// second `HashSet` until 2026-09-05, which made every level of a miss walk
/// hash the name twice to ask two halves of one question (`TODO.md` #22): "is
/// this a node of the zone, and does it have records". An ENT costs no arena
/// bytes either: it is a suffix of a name already interned, so it is a range
/// into that one.
///
/// **Why not a `HashMap`, which is what this was until `TODO.md` #71d.** A
/// `HashMap` reaches its key only through `Borrow`, so the key must own and
/// hash its own bytes — `Box<[u8]>` here, because `Name` cannot borrow to
/// `NameRef` without the `unsafe` cast `str` uses (`rdns_core::name_keys`
/// makes the same argument for the same reason). That is a `Box` per name,
/// which is a heap allocation per name to load and another per name to copy:
/// cloning a million-record zone's index was two million of them, 244 ms where
/// the same table keyed on a `u64` takes 6.
///
/// [`hashbrown::HashTable`] takes the hash and an equality closure from the
/// caller, so an entry can be a range into the arena and nothing here allocates
/// per name. It is the API `std` keeps behind the unstable `hash_raw_entry`,
/// and hashbrown is what `std::collections::HashMap` is built on — already in
/// `Cargo.lock` through `toml`, and already linked into both daemons, so
/// naming it costs no package.
///
/// A hash collision is hashbrown's business rather than this type's: the
/// closure compares the arena bytes, so two names that hash alike stay two
/// names. See `an_index_keeps_two_names_that_hash_alike_apart`.
#[derive(Debug, Clone, Default)]
struct NameIndex {
    names: Vec<u8>,
    table: hashbrown::HashTable<Interned>,
}

/// One name in the index: where its bytes are, what is at it, and how many
/// names directly below it the index holds.
///
/// `children` is what makes a record removable. A name is in the index either
/// because it owns records or because something below it does (RFC 4592
/// §2.2.2), and dropping the last record at a name may not drop the name while
/// a descendant still needs it to exist — an empty non-terminal that vanishes
/// turns a NODATA into an NXDOMAIN, which an RFC 8020 resolver then extends
/// over the whole subtree (`CLAUDE.md` §8).
///
/// Direct children rather than all descendants, because that is the count an
/// insertion can keep in O(1): a new name credits its parent, and only a parent
/// that was itself new walks on up. Counting descendants would make every
/// insertion walk to the apex, which is the cost
/// [`Zone::note_non_terminals`] exists to avoid. It fits in `len`'s padding, so
/// the table is the same size it was.
#[derive(Debug, Clone, Copy)]
struct Interned {
    off: usize,
    len: u32,
    children: u32,
    slot: Slot,
}

/// FxHash, as rustc uses, over the folded name.
///
/// **Not collision-resistant, and that is a decision rather than an oversight.**
/// A weak hash is dangerous where an attacker can *insert*, because they choose
/// what shares a bucket; here every key is one of the operator's own zone names,
/// and a query only probes. So a chosen QNAME reaches at worst the longest
/// collision cluster among names already loaded — a load-time property of the
/// zone, which no packet can grow. Measured over a million-rule feed, where Fx
/// collides on 2.5% of names, that cluster is 2.
///
/// The names are the reason it is not the default hasher: SipHash over ~38
/// octets, twice per label of an ancestor walk, is the single largest thing a
/// miss pays. 114 ns against 82 for a miss on a million-record zone
/// (`TODO.md` #71d).
fn name_hash(key: &[u8]) -> u64 {
    const K: u64 = 0x517c_c1b7_2722_0a95;
    let mut h: u64 = 0;
    let (chunks, remainder) = key.as_chunks::<8>();
    for c in chunks {
        h = (h.rotate_left(5) ^ u64::from_le_bytes(*c)).wrapping_mul(K);
    }
    let mut tail = 0u64;
    for (i, b) in remainder.iter().enumerate() {
        tail |= u64::from(*b) << (i * 8);
    }
    (h.rotate_left(5) ^ tail).wrapping_mul(K)
}

impl Interned {
    fn range(&self) -> std::ops::Range<usize> {
        self.off..self.off + self.len as usize
    }
}

impl NameIndex {
    fn find(&self, key: &[u8]) -> Option<&Interned> {
        let names = &self.names;
        self.table
            .find(name_hash(key), |at| &names[at.range()] == key)
    }

    fn get(&self, key: &[u8]) -> Option<&Slot> {
        self.find(key).map(|at| &at.slot)
    }

    fn contains_key(&self, key: &[u8]) -> bool {
        self.find(key).is_some()
    }

    fn len(&self) -> usize {
        self.table.len()
    }

    fn values(&self) -> impl Iterator<Item = &Slot> {
        self.table.iter().map(|at| &at.slot)
    }

    #[cfg(test)]
    fn iter(&self) -> impl Iterator<Item = (&[u8], &Slot)> {
        self.table
            .iter()
            .map(|at| (&self.names[at.range()], &at.slot))
    }

    fn clear(&mut self) {
        self.names.clear();
        self.table.clear();
    }

    fn reserve(&mut self, entries: usize, bytes: usize) {
        let names = &self.names;
        self.table
            .reserve(entries, |at| name_hash(&names[at.range()]));
        self.names.reserve(bytes);
    }

    /// The entry at `key`, inserting an empty non-terminal with no children if
    /// the name is new, and saying which of the two happened.
    ///
    /// One probe for a caller that wants to read the slot and write it back —
    /// [`Zone::file`] spent two or three doing that through the `&mut Slot`
    /// this replaced.
    ///
    /// `bytes` is where `key` already lives in the arena, for a caller that has
    /// just interned it or knows it is a suffix of something interned; `None`
    /// appends a copy.
    fn node_mut(&mut self, key: &[u8], bytes: Option<(usize, u32)>) -> (&mut Interned, bool) {
        // Destructured, so the closures can borrow the arena while the table is
        // borrowed mutably beside it.
        let NameIndex { names, table, .. } = self;
        let entry = table.entry(
            name_hash(key),
            |at| &names[at.range()] == key,
            |at| name_hash(&names[at.range()]),
        );
        match entry {
            hashbrown::hash_table::Entry::Occupied(at) => (at.into_mut(), false),
            hashbrown::hash_table::Entry::Vacant(slot) => {
                let (off, len) = bytes.unwrap_or_else(|| {
                    let off = names.len();
                    names.extend_from_slice(key);
                    (off, key.len() as u32)
                });
                (
                    slot.insert(Interned {
                        off,
                        len,
                        children: 0,
                        slot: Slot::Ent,
                    })
                    .into_mut(),
                    true,
                )
            }
        }
    }

    /// Take `key` out of the table, leaving its octets in the arena.
    ///
    /// The arena is append-only: a name's bytes may be a suffix another entry
    /// still points into ([`Zone::note_non_terminals`]), so nothing here can
    /// know whether they are free. A removal therefore costs a few octets that
    /// come back on the next rebuild — bounded by what the *deltas* since that
    /// rebuild named, never by the zone.
    fn remove(&mut self, key: &[u8]) {
        let names = &self.names;
        if let Ok(at) = self
            .table
            .find_entry(name_hash(key), |at| &names[at.range()] == key)
        {
            at.remove();
        }
    }

    /// The slot at `key`, for a caller that must not create the name.
    ///
    /// [`NameIndex::node_mut`] inserts; every removal path here is about a name
    /// the index already holds, and a probe that could conjure an empty
    /// non-terminal out of a typo is the wrong tool for it.
    fn slot_of_mut(&mut self, key: &[u8]) -> Option<&mut Slot> {
        let names = &self.names;
        self.table
            .find_mut(name_hash(key), |at| &names[at.range()] == key)
            .map(|at| &mut at.slot)
    }

    /// Add `by` to the count of names directly below `key`.
    ///
    /// A no-op for a name the index does not hold, which is the foreign-owner
    /// case [`Zone::parent_in_zone`] stops at.
    fn credit(&mut self, key: &[u8], by: i32) {
        let names = &self.names;
        if let Some(at) = self
            .table
            .find_mut(name_hash(key), |at| &names[at.range()] == key)
        {
            at.children = at.children.saturating_add_signed(by);
        }
    }

    /// Copy `key` into the arena and give back its range, or the range it
    /// already has.
    fn intern(&mut self, key: &[u8]) -> (usize, u32) {
        if let Some(at) = self.find(key) {
            return (at.off, at.len);
        }
        let off = self.names.len();
        self.names.extend_from_slice(key);
        (off, key.len() as u32)
    }
}

/// Where one owner name's records are.
///
/// A `Vec<usize>` per key was 24 bytes in the table plus a 32-byte allocation to
/// hold a single 8-byte position — and in a policy feed *every* name owns one
/// record, so that was a million allocations of one element (`TODO.md` #61e).
/// The single case is handed out through `slice::from_ref`, so it has nothing on
/// the heap and one fewer pointer to chase.
#[derive(Debug, Clone, Copy)]
enum Slot {
    /// An empty non-terminal: a node of the zone with no records of its own
    /// (RFC 4592 §2.2.2). Distinct from `One`/`Spilled` because "does this name
    /// exist at all" and "does it have records" are the two halves of
    /// NXDOMAIN-versus-NODATA and this answers both in one probe.
    Ent,
    /// The one record at this name.
    One(usize),
    /// More than one: the index into [`Zone::spills`] of the list.
    Spilled(usize),
}

/// A single DNS resource record, owned — what a caller builds to hand
/// [`Zone::add_record`], and what `Zone::remove_record` gives back.
///
/// Not what a zone stores. A zone keeps every owner name in one arena and every
/// RDATA in another, and hands out [`ZoneRecordRef`], which borrows both:
/// a `Box` per field was two heap allocations per record to build, two to copy
/// and two to free, which at a million records was 78 ms and 2 000 001
/// allocations to copy a zone against 3.8 ms and two (`TODO.md` #71e).
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub name: Name,
    pub ttl: Ttl,
    pub class: Class,
    pub rdata: RecordData,
}

/// One record of a zone, borrowed from its arenas.
///
/// The same four fields as [`ZoneRecord`] in the borrowed forms, so a reader
/// writes `record.name` and `record.rdata` as it always did. `Copy`, because it
/// is two slices and two scalars.
///
/// Equality is the four fields, the owner name case-insensitively (RFC 4343) as
/// [`NameRef`]'s own is. Not pointer identity: a record is a pair of spans, so
/// there is no `&ZoneRecord` to compare addresses of, and two records that
/// agree on all four fields are the same record for every purpose a reader has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneRecordRef<'a> {
    pub name: NameRef<'a>,
    pub ttl: Ttl,
    pub class: Class,
    pub rdata: RecordDataRef<'a>,
}

impl ZoneRecord {
    /// Borrow the name and the octets, for a caller that has an owned record
    /// and wants to ask a zone's questions of it.
    pub fn as_ref(&self) -> ZoneRecordRef<'_> {
        ZoneRecordRef {
            name: self.name.as_ref(),
            ttl: self.ttl,
            class: self.class,
            rdata: self.rdata.as_ref(),
        }
    }
}

impl ZoneRecordRef<'_> {
    /// A copy that owns its name and its octets.
    pub fn to_owned(&self) -> ZoneRecord {
        ZoneRecord {
            name: self.name.to_owned(),
            ttl: self.ttl,
            class: self.class,
            rdata: self.rdata.to_owned(),
        }
    }
}

/// What a zone keeps per record: two spans and two scalars, 24 bytes against
/// the 48 an owned [`ZoneRecord`] takes, and nothing on the heap of its own.
#[derive(Debug, Clone, Copy)]
struct Stored {
    name: NameSpan,
    ttl: Ttl,
    class: Class,
    rdata: RdataSpan,
}

/// A zone's records, in the order it holds them.
///
/// A view rather than a slice, because the records are spans into two arenas
/// and a `&[ZoneRecord]` would mean materializing them. It answers what a slice
/// answered — [`len`], [`is_empty`], [`iter`], and `for record in ..` — so a
/// reader that only counted or walked reads the same.
///
/// [`len`]: Records::len
/// [`is_empty`]: Records::is_empty
/// [`iter`]: Records::iter
#[derive(Debug, Clone, Copy)]
pub struct Records<'a> {
    zone: &'a Zone,
}

impl<'a> Records<'a> {
    pub fn len(&self) -> usize {
        self.zone.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.zone.records.is_empty()
    }

    /// The record at `at`, or `None` past the end.
    pub fn get(&self, at: usize) -> Option<ZoneRecordRef<'a>> {
        (at < self.len()).then(|| self.zone.record(at))
    }

    pub fn iter(&self) -> RecordIter<'a> {
        RecordIter {
            zone: self.zone,
            at: 0,
            end: self.len(),
        }
    }
}

impl<'a> IntoIterator for Records<'a> {
    type Item = ZoneRecordRef<'a>;
    type IntoIter = RecordIter<'a>;

    fn into_iter(self) -> RecordIter<'a> {
        self.iter()
    }
}

/// [`Records::iter`]'s iterator: a position and the zone behind it.
#[derive(Debug, Clone, Copy)]
pub struct RecordIter<'a> {
    zone: &'a Zone,
    at: usize,
    end: usize,
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = ZoneRecordRef<'a>;

    fn next(&mut self) -> Option<ZoneRecordRef<'a>> {
        (self.at < self.end).then(|| {
            let record = self.zone.record(self.at);
            self.at += 1;
            record
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.end - self.at;
        (left, Some(left))
    }
}

impl ExactSizeIterator for RecordIter<'_> {}

impl DoubleEndedIterator for RecordIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        (self.at < self.end).then(|| {
            self.end -= 1;
            self.zone.record(self.end)
        })
    }
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
    records: Vec<Stored>,
    /// Every owner name's octets, and every RDATA's, one allocation each.
    ///
    /// Append-only: a span names octets that do not move, so a removal leaves
    /// what it held behind and `removed_since_rebuild` is what reclaims it.
    names: NameArena,
    rdata: RdataArena,
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
    index: NameIndex,
    /// The position lists of the names that own more than one record. See
    /// [`Slot`]; a name that owns one keeps its position in the table.
    spills: Vec<Vec<usize>>,
    /// Removals since the index was last built, which is when what they left
    /// behind is worth rebuilding it for.
    ///
    /// Everything under `index` is append-only. A name removed and added again
    /// — which is what a *changed* record is, since a difference sequence
    /// spells one as a deletion and an addition (RFC 1995 §2) — appends a
    /// second copy of its octets to the arena, and a name that falls back to
    /// one record leaves its position list behind. Measured: 4 000 changes to
    /// a 1 000-name zone took the arena from 24 031 octets to 120 031 and the
    /// spill list from 1 entry to 101, with the entry count, the record count
    /// and every answer unchanged. Unbounded in a process that refreshes a
    /// feed for a year without restarting (`TODO.md` #71a).
    ///
    /// One counter and not one per vector, because [`Zone::reindex`] rebuilds
    /// both and a removal can only ever add to either — and because it is the
    /// *rebuild* that has to be paid for. Against `records`, which is what a
    /// rebuild costs: against the entry count instead, a zone of one name with
    /// a million records would rebuild all of them on every removal.
    removed_since_rebuild: u32,
    /// The NSEC chain, keyed by canonical sort order, and the NSEC3 chain,
    /// keyed by hash — both empty for an unsigned zone.
    ///
    /// Ordered, where the name index is not, because a denial asks a range
    /// question: which record's span contains this name.
    nsec_chain: BTreeMap<CanonicalKey, usize>,
    nsec3_chain: BTreeMap<Nsec3Hash, usize>,
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
    pub fn of_type(&self, qtype: Qtype) -> impl Iterator<Item = ZoneRecordRef<'a>> + '_ {
        let zone = self.zone;
        self.positions
            .iter()
            .filter(move |&&i| qtype.matches(zone.records[i].rdata.rtype()))
            .map(move |&i| zone.record(i))
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
/// Where a denial record belongs, carrying the key of the chain it belongs to.
///
/// The two keys are different encodings of different things — one a name in
/// RFC 4034 §6.1 order, the other an RFC 5155 owner hash — and as
/// `(Chain, Vec<u8>)` the tuple's second element meant whichever the first
/// element said (`CLAUDE.md` §2, `TODO.md` #40a).
enum ChainKey {
    Nsec(CanonicalKey),
    Nsec3(Nsec3Hash),
}

impl Zone {
    /// Create a new zone with the given origin (e.g., `example.com.`)
    pub fn new(origin: Name) -> Self {
        Zone {
            origin,
            records: Vec::new(),
            names: NameArena::new(),
            rdata: RdataArena::new(),
            index: NameIndex::default(),
            spills: Vec::new(),
            removed_since_rebuild: 0,
            nsec_chain: BTreeMap::new(),
            nsec3_chain: BTreeMap::new(),
            shortcuts: Shortcuts::default(),
        }
    }

    /// The zone's apex name, absolute — as every [`Name`] is.
    pub fn origin(&self) -> NameRef<'_> {
        self.origin.as_ref()
    }

    /// Every record in the zone.
    ///
    /// Load order, until something is removed: a removal fills its hole from
    /// the end, and `Zone::remove_record` says why nothing reads one.
    pub fn records(&self) -> Records<'_> {
        Records { zone: self }
    }

    /// The record at `at`, which must be one this zone holds.
    ///
    /// Panics past the end, as indexing a slice did, and every caller holds a
    /// position [`Zone::positions_of`] gave it — the same visibility, for the
    /// same reason. [`Records::get`] is the checked door for anyone else.
    pub(crate) fn record(&self, at: usize) -> ZoneRecordRef<'_> {
        let stored = self.records[at];
        ZoneRecordRef {
            name: self.names.get(stored.name),
            ttl: stored.ttl,
            class: stored.class,
            rdata: self.rdata.get(stored.rdata),
        }
    }

    /// The records at each owner name, as positions in [`Zone::records`]: the
    /// grouping `index` already is, for a zone-wide check that would otherwise
    /// build a second map to get it (`super::checks`). Empty for an empty
    /// non-terminal.
    fn groups(&self) -> impl Iterator<Item = &[usize]> {
        self.index.values().map(|slot| self.positions(slot))
    }

    /// Move the zone's apex, as a top-level `$ORIGIN` does.
    ///
    /// No record moves: a [`Name`] is absolute, so an owner name means the same
    /// thing before and after. What the reindex rebuilds is the bookkeeping that
    /// is *about* the apex — an NS RRset at the old apex becomes a zone cut
    /// under the new one.
    ///
    /// **Costs a pass over every record already loaded**, so a loader that moves
    /// the apex while filling a zone moves it once, at one end or the other, and
    /// not per `$ORIGIN` line (`TODO.md` #62c).
    pub fn set_origin(&mut self, origin: Name) {
        self.origin = origin;
        self.reindex();
    }

    /// Room for `records` more records, and for the index entries they bring.
    ///
    /// A loader that knows how many records are coming should say so: growing
    /// the index from empty rehashes every key already in it at each doubling,
    /// which was 320 ms of a million-rule RPZ load. Twice `records` because an
    /// owner name below the apex also enters its ancestors
    /// ([`Zone::note_non_terminals`]) — right for a feed of `<name>.<origin>`
    /// rules, and one doubling of the table too many for a zone whose names are
    /// all children of the apex.
    pub(crate) fn reserve(&mut self, records: usize) {
        self.records.reserve(records);
        // A name is ~25 octets and an RPZ rule's CNAME RDATA one; both arenas
        // grow past a low guess without moving a span, so these are hints.
        self.names.reserve(25 * records);
        self.rdata.reserve(8 * records);
        // A name is ~25 bytes on the wire for an ordinary zone; the arena grows
        // past a low guess without moving a key, so this is a hint not a bound.
        self.index.reserve(2 * records, 25 * records);
    }

    /// Room for a rebuild of `base`, plus `extra` records it will gain.
    ///
    /// [`Zone::reserve`] for a caller that holds the zone it is rebuilding, and
    /// so knows the two counts instead of estimating one from the other. The
    /// index gets `base`'s own entry count, which is right for every zone
    /// shape: `reserve`'s `2 * records` is the ratio a feed of
    /// `<name>.<origin>` rules has, and twice the table a zone whose names are
    /// all apex children needs. On such a feed, where the two agree on size,
    /// the exact form still measured 386 ms against 401 at a million records.
    ///
    /// The three callers that rebuild a zone record by record all had the
    /// counts and none of them passed them — `TODO.md` #61b reserved the parse
    /// and stopped at one of four sites (#71c). One caller is left:
    /// `ixfr::Patch::apply` copies the base now instead of rebuilding it
    /// (#71a), and `xfr::AxfrAccumulator` has no base to be like.
    pub(crate) fn reserve_like(&mut self, base: &Zone, extra: usize) {
        self.records.reserve(base.records.len() + extra);
        self.names.reserve(base.names.len());
        self.rdata.reserve(base.rdata.len());
        self.index
            .reserve(base.index.len() + extra, base.index.names.len());
        self.spills.reserve(base.spills.len());
    }

    /// Add a record to the zone.
    ///
    /// The owned door. A caller that already holds the octets borrowed wants
    /// [`Zone::add`]: a zone copies both fields into its arenas either way, so
    /// building a `ZoneRecord` to hand over is a heap allocation and a free per
    /// record for a value nothing keeps.
    pub fn add_record(&mut self, record: ZoneRecord) {
        self.add(record.as_ref());
    }

    /// Add a record whose name and RDATA the caller only borrows.
    pub fn add(&mut self, record: ZoneRecordRef<'_>) {
        // Folded onto the stack, not into an allocation: `into_owned` here was
        // one heap allocation and one free per record for a copy nothing keeps
        // — `intern` copies the octets into the index's own arena.
        let mut fold = [0u8; rdns_core::dname::MAX_NAME_LEN];
        let key = record.name.folded_into(&mut fold);
        let key = key.as_wire();
        let position = self.records.len();
        // Through the field rather than `origin_key()`, so the borrow is of
        // `self.origin` alone and `self.index` can be taken mutably beside it.
        let origin_key = self.origin.as_ref().folded();
        let at_apex = key == &*origin_key;
        self.shortcuts.note(key, record.rdata.rtype(), at_apex);
        let at = self.index.intern(key);
        // Ancestors only when the name is new to the index: one name notes them
        // and every later record at it would find them present. That probe was
        // the walk's own first step until #71a moved it here, where it is the
        // insertion's answer rather than a second lookup.
        if Zone::file(&mut self.index, &mut self.spills, key, at, position) {
            Zone::note_non_terminals(&mut self.index, key, at, &origin_key);
        }
        drop(origin_key);
        match self.chain_key(record) {
            Some(ChainKey::Nsec(k)) => {
                self.nsec_chain.insert(k, position);
            }
            Some(ChainKey::Nsec3(k)) => {
                self.nsec3_chain.insert(k, position);
            }
            None => {}
        }
        let stored = Stored {
            name: self.names.push(record.name),
            ttl: record.ttl,
            class: record.class,
            rdata: self.rdata.push(record.rdata),
        };
        self.records.push(stored);
    }

    /// The positions of the records at exactly this folded owner name, empty
    /// for a name that is an empty non-terminal or is not here at all.
    ///
    /// The index's grouping, for a caller that means to *change* those records
    /// and so cannot hold the `&ZoneRecord`s [`Zone::locate`] hands out.
    pub(crate) fn positions_of(&self, key: &[u8]) -> &[usize] {
        match self.index.get(key) {
            Some(slot) => self.positions(slot),
            None => &[],
        }
    }

    /// Take the record at `position` out of the zone and give it back.
    ///
    /// **O(the name's labels), not O(the zone)**, which is what lets a delta be
    /// applied to a copy rather than rebuilt from one (`TODO.md` #71a). The
    /// index holds positions into `records`, so a removal that shifted them
    /// would invalidate every later one; `swap_remove` shifts exactly one — the
    /// record that was last — and the index reaches that one entry by that
    /// record's own owner name.
    ///
    /// **What it costs is the record order.** `records()` is no longer load
    /// order once anything has been removed. Nothing reads it as one: the
    /// serializer writes the apex SOA itself and then the rest
    /// ([`crate::zone_writer`]), and an AXFR brackets its own SOA
    /// (RFC 5936 §2.2, [`crate::transfer`]). The alternative that keeps order
    /// is a tombstone per removed record, and it was not built: it buys an
    /// order nothing reads, and costs `records()` its slice — which is the
    /// blast radius `TODO.md` #71e counted at 98 compiler errors.
    ///
    /// [`Zone::shortcuts`] is not recomputed. Each one stale in the *true*
    /// direction costs a walk that finds nothing; stale in the false direction
    /// would serve a wrong answer, and removal cannot move one that way.
    pub(crate) fn remove_record(&mut self, position: usize) -> ZoneRecord {
        let record = self.record(position).to_owned();
        let key = self.record(position).name.folded().into_owned();
        match self.chain_key(self.record(position)) {
            Some(ChainKey::Nsec(k)) => {
                self.nsec_chain.remove(&k);
            }
            Some(ChainKey::Nsec3(k)) => {
                self.nsec3_chain.remove(&k);
            }
            None => {}
        }
        let records_left = self.unfile(&key, position);
        let moved_from = self.records.len() - 1;
        self.records.swap_remove(position);
        if moved_from != position {
            let moved = self.record(position).name.folded().into_owned();
            self.refile(&moved, moved_from, position);
            match self.chain_key(self.record(position)) {
                Some(ChainKey::Nsec(k)) => {
                    self.nsec_chain.insert(k, position);
                }
                Some(ChainKey::Nsec3(k)) => {
                    self.nsec3_chain.insert(k, position);
                }
                None => {}
            }
        }
        if !records_left {
            self.prune(&key);
        }
        // Nothing under this type gives an octet back on its own — not the
        // two record arenas, not the index's, not the spill lists — so a
        // long-lived process applying deltas grows whatever its zone does. A
        // rebuild reclaims all of them, and it re-shares the index arena's
        // suffixes an empty non-terminal borrows, which a compaction written
        // for the purpose would not. See `removed_since_rebuild`.
        self.removed_since_rebuild = self.removed_since_rebuild.saturating_add(1);
        if self.removed_since_rebuild as usize * 2 >= self.records.len() {
            self.rebuild();
        }
        record
    }

    /// Drop `key` from the index if nothing needs it, and its ancestors after
    /// it.
    ///
    /// A name is in the index because it owns records or because something
    /// below it does (RFC 4592 §2.2.2). The first is gone by the time this is
    /// called; the second is [`Interned::children`], and a name that loses its
    /// last child may be the last child of its own parent, so the walk carries
    /// on up.
    ///
    /// Leaving the name behind instead would answer NODATA where the zone has
    /// nothing at all, which is a different answer with a different proof
    /// (`CLAUDE.md` §8) — and leaving an ancestor behind after a subtree is
    /// deleted leaves an empty non-terminal over nothing.
    fn prune(&mut self, key: &[u8]) {
        // Through the field, so the borrow is of `self.origin` alone and
        // `self.index` can be taken mutably beside it — `add_record` does the
        // same and for the same reason. `origin_key()` would borrow all of
        // `self`, and owning a copy is an allocation per removal.
        let origin_key = self.origin.as_ref().folded();
        let mut name = key;
        loop {
            let Some(at) = self.index.find(name) else {
                return;
            };
            if at.children > 0 || !matches!(at.slot, Slot::Ent) {
                return;
            }
            self.index.remove(name);
            let Some(parent) = Zone::parent_in_zone(name, &origin_key) else {
                return;
            };
            self.index.credit(parent, -1);
            name = parent;
        }
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
            .is_some_and(|slot| !matches!(slot, Slot::Ent))
    }

    pub fn has_nsec_chain(&self) -> bool {
        !self.nsec_chain.is_empty()
    }

    pub fn has_nsec3_chain(&self) -> bool {
        !self.nsec3_chain.is_empty()
    }

    /// Any one record from the NSEC3 chain, for reading the salt and iteration
    /// count the chain was built with.
    pub fn any_nsec3(&self) -> Option<ZoneRecordRef<'_>> {
        self.nsec3_chain
            .values()
            .next()
            .map(|position| self.record(*position))
    }

    /// The NSEC whose span contains `name` — the record that denies it exists.
    ///
    /// Exclusive at the low end: an NSEC *at* `name` proves the opposite. When
    /// nothing sorts before `name` the answer is the last record, because the
    /// chain is a loop back to the apex (RFC 4034 §4.1.1).
    pub fn nsec_covering(&self, name: NameRef<'_>) -> Option<ZoneRecordRef<'_>> {
        let key = canonical_sort_key(name);
        let position = self
            .nsec_chain
            .range(..key)
            .next_back()
            .or_else(|| self.nsec_chain.iter().next_back())?;
        Some(self.record(*position.1))
    }

    /// The NSEC3 whose span contains `hash`. Same rule, in hash order.
    pub fn nsec3_covering(&self, hash: Nsec3Hash) -> Option<ZoneRecordRef<'_>> {
        let position = self
            .nsec3_chain
            .range(..hash)
            .next_back()
            .or_else(|| self.nsec3_chain.iter().next_back())?;
        Some(self.record(*position.1))
    }

    /// Where a denial record belongs in the ordered chains, if it is one.
    ///
    /// An NSEC is filed under its owner name; an NSEC3 under the hash in its
    /// owner's first label, which is what the chain is ordered by. A label that
    /// will not decode is left out rather than filed under something wrong.
    fn chain_key(&self, record: ZoneRecordRef<'_>) -> Option<ChainKey> {
        match record.rdata.rtype() {
            crate::record_types::NSEC => Some(ChainKey::Nsec(canonical_sort_key(record.name))),
            crate::record_types::NSEC3 => {
                // The hash is the first label, and a label is octets — so it is
                // taken as octets rather than by splitting text on a `.` that
                // may be inside one.
                let label = record.name.labels().next()?;
                let decoded = base32hex_decode(std::str::from_utf8(label).ok()?).ok()?;
                Some(ChainKey::Nsec3(Nsec3Hash::from_wire(&decoded)?))
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
    pub fn query(&self, name: NameRef<'_>, qtype: Qtype) -> Vec<ZoneRecordRef<'_>> {
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
    fn query_with_kind(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
    ) -> (NameKind, Vec<ZoneRecordRef<'_>>) {
        let located = self.locate(name);
        let records: Vec<ZoneRecordRef<'_>> = located.of_type(qtype).collect();
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
            positions: at.map_or(&[][..], |slot| self.positions(slot)),
        }
    }

    /// The apex SOA, borrowed.
    ///
    /// `Option` because a `Zone` can be built record by record; one that came
    /// from a file has an SOA or it did not load.
    fn apex_soa(&self) -> Option<ZoneRecordRef<'_>> {
        self.query(self.origin(), Qtype::of(rt::SOA))
            .first()
            .copied()
    }

    /// Where the apex SOA sits in `records`, for a caller that means to replace
    /// it ([`Zone::remove_record`]).
    pub(crate) fn apex_soa_position(&self) -> Option<usize> {
        let origin = self.origin_key();
        self.positions_of(&origin)
            .iter()
            .copied()
            .find(|at| self.records[*at].rdata.rtype() == rt::SOA)
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
            rdata: soa.rdata.to_owned(),
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
    pub fn is_apex_soa(&self, record: ZoneRecordRef<'_>) -> bool {
        record.rdata.rtype() == rt::SOA && record.name == self.origin.as_ref()
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
            Some(Slot::Ent) => return NameKind::EmptyNonTerminal,
            Some(_) => return NameKind::Exact,
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
    pub fn dname_above(&self, name: NameRef<'_>) -> Option<ZoneRecordRef<'_>> {
        // Before the fold, as `delegation_for` does it: with no DNAME in the
        // zone the folded copy is made for nothing.
        if !self.shortcuts.dnames {
            return None;
        }
        let mut buf = Vec::new();
        self.dname_above_key(name.folded_in(&mut buf))
    }

    /// [`Zone::dname_above`] for a name already folded.
    fn dname_above_key(&self, key: NameRef<'_>) -> Option<ZoneRecordRef<'_>> {
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
    fn first_of_type(&self, key: NameRef<'_>, rtype: Rtype) -> Option<ZoneRecordRef<'_>> {
        self.positions(self.index.get(key.as_wire())?)
            .iter()
            .map(|&i| self.record(i))
            .find(|r| r.rdata.rtype() == rtype)
    }

    /// File `position` under `key`, spilling at the *second* record. Says
    /// whether `key` was new to the index, which is what tells the caller its
    /// ancestors have yet to be noted.
    ///
    /// An owner name with one record keeps its position in the table; the names
    /// that hold an RRset of several, or several types, get a list. Which way a
    /// zone leans decides the cost, and a policy feed leans entirely one way.
    ///
    /// The two fields rather than `&mut self`, as [`Zone::note_non_terminals`]
    /// takes them and for the same reason: the caller holds the folded origin,
    /// which borrows `self.origin`.
    fn file(
        index: &mut NameIndex,
        spills: &mut Vec<Vec<usize>>,
        key: &[u8],
        at: (usize, u32),
        position: usize,
    ) -> bool {
        let next_list = spills.len();
        let (node, fresh) = index.node_mut(key, Some(at));
        match node.slot {
            // Vacant, or a name noted as an ancestor that now has a record of
            // its own.
            Slot::Ent => node.slot = Slot::One(position),
            Slot::One(first) => {
                node.slot = Slot::Spilled(next_list);
                spills.push(vec![first, position]);
            }
            Slot::Spilled(list) => spills[list].push(position),
        }
        fresh
    }

    /// Take `position` out of whatever `key`'s slot holds, and say whether the
    /// name has records left.
    ///
    /// The inverse of [`Zone::file`] down to the spill list, which is *not*
    /// given back: a `Slot::Spilled` that falls to one record leaves its `Vec`
    /// in `self.spills` unreferenced. Reclaiming it would mean either moving
    /// the last list into the hole — which renumbers a `Slot` somewhere else —
    /// or a free list, and a delta's worth of empty `Vec`s costs less than
    /// either. They come back on the next rebuild.
    fn unfile(&mut self, key: &[u8], position: usize) -> bool {
        let slot = self
            .index
            .slot_of_mut(key)
            .expect("a record's owner name is in the index");
        match *slot {
            Slot::Ent => false,
            Slot::One(only) => {
                debug_assert_eq!(only, position, "the index disagrees with the record vector");
                *slot = Slot::Ent;
                false
            }
            Slot::Spilled(list) => {
                let positions = &mut self.spills[list];
                let found = positions
                    .iter()
                    .rposition(|held| *held == position)
                    .expect("the index disagrees with the record vector");
                positions.remove(found);
                let left = match positions.len() {
                    0 => Slot::Ent,
                    1 => Slot::One(positions[0]),
                    _ => return true,
                };
                // Nothing names this list now. The buffer goes back at once;
                // the header waits for the rebuild, which is what renumbers
                // every `Slot::Spilled`.
                positions.clear();
                positions.shrink_to_fit();
                *self
                    .index
                    .slot_of_mut(key)
                    .expect("a record's owner name is in the index") = left;
                !matches!(left, Slot::Ent)
            }
        }
    }

    /// Point `key`'s slot at `to` where it pointed at `from`.
    ///
    /// What a `swap_remove` owes: the record that was last is now somewhere
    /// else, and exactly one name's slot names it.
    fn refile(&mut self, key: &[u8], from: usize, to: usize) {
        let slot = self
            .index
            .slot_of_mut(key)
            .expect("a record's owner name is in the index");
        match *slot {
            Slot::Ent => debug_assert!(false, "a record's owner name is not an empty non-terminal"),
            Slot::One(only) => {
                debug_assert_eq!(only, from, "the index disagrees with the record vector");
                *slot = Slot::One(to);
            }
            Slot::Spilled(list) => {
                let at = self.spills[list]
                    .iter_mut()
                    .find(|held| **held == from)
                    .expect("the index disagrees with the record vector");
                *at = to;
            }
        }
    }

    /// The positions a slot names, empty for an empty non-terminal — which is
    /// what lets one probe answer both halves of NXDOMAIN-versus-NODATA.
    fn positions<'a>(&'a self, slot: &'a Slot) -> &'a [usize] {
        match slot {
            Slot::Ent => &[],
            Slot::One(position) => std::slice::from_ref(position),
            Slot::Spilled(list) => &self.spills[*list],
        }
    }

    /// The parent of `name` when this zone is the one that holds it.
    ///
    /// `None` at the apex, and `None` for an owner outside the zone — foreign
    /// glue, say, whose ancestors are somebody else's names. One function
    /// because the insertion walk and the removal walk have to stop in the same
    /// place or a name's `children` count outlives its children
    /// (`CLAUDE.md` §7).
    fn parent_in_zone<'a>(name: &'a [u8], origin: &[u8]) -> Option<&'a [u8]> {
        if name == origin {
            return None;
        }
        let parent = parent_key(name)?;
        (parent.len() >= origin.len()).then_some(parent)
    }

    /// Record every ancestor of `key`, up to the apex, as a name that exists,
    /// and credit each one with the child below it.
    ///
    /// Called only for a `key` the index did not already hold, since an
    /// ancestor is noted by the first name under it and by nobody else.
    ///
    /// Stops at the first ancestor already known, and credits that one for the
    /// new name below it: ancestors are always noted all the way to the apex,
    /// so one present means the rest are, and one present means *its* own
    /// parent has already counted it. Keeps index construction linear in the
    /// zone rather than in names × labels.
    ///
    /// "Known" includes an ancestor that has records of its own, which is the
    /// same guarantee for the same reason — a record's own insertion noted
    /// *its* ancestors.
    ///
    /// A free function taking the two fields it needs rather than `&mut self`,
    /// so the walk can slice `key` in place: owning each ancestor to satisfy one
    /// `&mut self` cost four allocations per record and 0.65 s of a million-rule
    /// load.
    fn note_non_terminals(index: &mut NameIndex, key: &[u8], at: (usize, u32), origin: &[u8]) {
        let (off, len) = at;
        let mut name = key;
        while let Some(parent) = Zone::parent_in_zone(name, origin) {
            // A suffix of a name already in the arena, so it stores no bytes of
            // its own — which is half the arena for a feed whose every rule
            // brings one ancestor with it.
            let skipped = len as usize - parent.len();
            let (node, fresh) = index.node_mut(parent, Some((off + skipped, len - skipped as u32)));
            node.children += 1;
            if !fresh {
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

    /// Rebuild both record arenas and then the index, dropping whatever
    /// removals left behind.
    ///
    /// Everything a zone holds under `records` is append-only, so this is the
    /// only thing that gives an octet back: the records are copied into fresh
    /// arenas in the order they are held, which is O(the zone) and amortized
    /// against the removals that paid for it (`removed_since_rebuild`).
    fn rebuild(&mut self) {
        let mut names = NameArena::new();
        let mut rdata = RdataArena::new();
        names.reserve(self.names.len());
        rdata.reserve(self.rdata.len());
        for at in 0..self.records.len() {
            let stored = self.records[at];
            let moved = Stored {
                name: names.push(self.names.get(stored.name)),
                ttl: stored.ttl,
                class: stored.class,
                rdata: rdata.push(self.rdata.get(stored.rdata)),
            };
            self.records[at] = moved;
        }
        self.names = names;
        self.rdata = rdata;
        self.reindex();
    }

    /// Rebuild the index from `records`.
    fn reindex(&mut self) {
        let origin_key = self.origin_key().into_owned();
        let keys: Vec<(Vec<u8>, Rtype, bool)> = (0..self.records.len())
            .map(|at| {
                let record = self.record(at);
                let key = record.name.folded().into_owned();
                let at_apex = key == origin_key;
                (key, record.rdata.rtype(), at_apex)
            })
            .collect();
        self.index.clear();
        self.spills.clear();
        self.removed_since_rebuild = 0;
        // Recomputed, not carried: `set_origin` turns an apex NS RRset into a
        // zone cut, and a wildcard at the old apex into one below the new.
        self.shortcuts = Shortcuts::default();
        for (position, (key, rtype, at_apex)) in keys.into_iter().enumerate() {
            self.shortcuts.note(&key, rtype, at_apex);
            let at = self.index.intern(&key);
            if Zone::file(&mut self.index, &mut self.spills, &key, at, position) {
                Zone::note_non_terminals(&mut self.index, &key, at, &origin_key);
            }
        }

        // The chains are not rebuilt. [`Zone::chain_key`] reads the record's own
        // owner name and nothing else, and a `Name` is absolute, so every key
        // and every position is the one already filed: the rebuild here was a
        // base32 decode per NSEC3 and an n-element `Vec` to arrive at the map
        // it started from. Its comment said the chains move with the origin
        // (`CLAUDE.md` §4 — a claim to verify).
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
    use super::rdata::rdata_from_fields;
    use super::*;
    use crate::error::ZoneError;
    use crate::record_types;
    use crate::test_records::nm;
    use crate::testutil::ScratchDir;
    use crate::ParsedRecord;
    use rdns_present::dnssec_time::parse_dnssec_time;
    use std::net::Ipv4Addr;

    /// The `$INCLUDE` rule is matched the way the parser matches it — case
    /// insensitively, after leading whitespace — or the test and the thing it
    /// is a test of disagree (`CLAUDE.md` §7). `parse_into` uses
    /// `eq_ignore_ascii_case` on the first field.
    #[test]
    fn a_file_that_includes_another_has_no_digest() {
        let plain = b"@ IN SOA ns. host. 1 2 3 4 5\nwww IN A 192.0.2.1\n";
        assert!(FileDigest::of_self_contained(plain).is_some());
        assert_eq!(
            FileDigest::of_self_contained(plain),
            Some(FileDigest::of(plain)),
            "the same bytes, either way in"
        );

        for included in [
            &b"$INCLUDE other.db\n"[..],
            b"$include other.db\n",
            b"   $Include other.db\n",
            b"@ IN SOA ns. host. 1 2 3 4 5\n$INCLUDE other.db",
        ] {
            assert!(
                FileDigest::of_self_contained(included).is_none(),
                "a digest of this file says nothing about the one it includes"
            );
        }

        // A prefix test, so a name beginning with the directive reads as one
        // too. Deliberate and stated in the doc comment: erring towards a
        // re-parse is the direction that cannot lose an edit.
        assert!(FileDigest::of_self_contained(b"$INCLUDED IN TXT nope\n").is_none());
    }

    /// Two names whose folded octets hash to the same `u64` are still two
    /// names — `TODO.md` #71d.
    ///
    /// Not hypothetical and not synthetic: FxHash collides on 2.5% of a
    /// million-rule feed's names, and this pair is one of 236 found in the ten
    /// thousand `bench_zone_lookup` already builds. The first version of the
    /// arena index filed both records under one of them, because its
    /// hand-rolled collision chain handed back the *incumbent's* slot on an
    /// insert — `bench_zone_lookup` failed on the first run and this test names
    /// the reason. The shipped index leaves collisions to hashbrown, which is
    /// the argument for using it.
    #[test]
    fn an_index_keeps_two_names_that_hash_alike_apart() {
        let a = nm("host1319.example.com.");
        let b = nm("host1392.example.com.");
        assert_eq!(
            name_hash(&a.as_ref().folded()),
            name_hash(&b.as_ref().folded()),
            "this pair has to still collide, or the test is a regression for nothing"
        );

        let mut zone = Zone::new(nm("example.com."));
        for name in [&a, &b] {
            zone.add_record(ZoneRecord {
                name: name.clone(),
                ttl: Ttl::from_secs(3600),
                class: Class::new(1),
                rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1)))
                    .expect("an A record"),
            });
        }

        for name in [&a, &b] {
            let found = zone.query(name.as_ref(), Qtype::of(record_types::A));
            assert_eq!(
                found.len(),
                1,
                "{} answered with {} records",
                name.as_ref().to_presentation(),
                found.len()
            );
            assert_eq!(found[0].name, *name, "and with the other name's record");
        }

        // The ancestor they share is one node, not two: an empty non-terminal
        // is interned as a range into whichever name reached it first.
        assert!(zone.name_exists(nm("example.com.").as_ref()));
    }

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
        assert_eq!(zone.record(0).name, nm("www.example.com."));
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
            zone.record(0).name,
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
        assert_eq!(zone.record(0).name, nm("ns.example.com."));
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
        assert_eq!(zone.record(1).name, nm("www.example.com."));
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
                .any(|r| zone.matches_query(r.name, nm(name).as_ref()));
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

    /// The index as a sorted list, for comparing two zones that must be one
    /// zone. `Slot` is three shapes for one answer, so it is the answer that is
    /// compared.
    /// Every name the index holds and the records at each, in a form two zones
    /// built different ways compare by.
    ///
    /// Not `index_of`: a removal fills its hole from the end, so positions are
    /// a permutation of a straight load's and nothing reads a zone in load
    /// order ([`Zone::remove_record`]).
    fn shape_of(zone: &Zone) -> Vec<(Vec<u8>, Vec<String>)> {
        let mut out: Vec<(Vec<u8>, Vec<String>)> = zone
            .index
            .iter()
            .map(|(key, slot)| {
                let mut records: Vec<String> = zone
                    .positions(slot)
                    .iter()
                    .map(|at| format!("{:?}", zone.record(*at)))
                    .collect();
                records.sort();
                (key.to_vec(), records)
            })
            .collect();
        out.sort();
        out
    }

    /// Every position the index names is a record of that name, and every
    /// record is named once. What a `swap_remove` can get wrong and a query
    /// would not notice for a hundred more removals.
    fn index_agrees_with_records(zone: &Zone, when: &str) {
        let mut seen = vec![0usize; zone.records.len()];
        for (key, slot) in zone.index.iter() {
            for at in zone.positions(slot) {
                assert!(*at < zone.records.len(), "{when}: position past the end");
                assert_eq!(
                    &*zone.record(*at).name.folded(),
                    key,
                    "{when}: the index files a record under the wrong name"
                );
                seen[*at] += 1;
            }
        }
        for (at, count) in seen.iter().enumerate() {
            assert_eq!(
                *count,
                1,
                "{when}: record {at} ({}) is filed {count} times",
                zone.record(at).name
            );
        }
    }

    /// The position of the one record of `rtype` at `name`.
    fn position_of(zone: &Zone, name: &str, rtype: Rtype) -> usize {
        let key = nm(name).as_ref().folded().into_owned();
        zone.positions_of(&key)
            .iter()
            .copied()
            .find(|at| zone.record(*at).rdata.rtype() == rtype)
            .unwrap_or_else(|| panic!("{name} holds a record of that type"))
    }

    const REMOVAL_ZONE: &str = "@   IN SOA ns admin 1 3600 600 86400 300
@   IN NS  ns
ns  IN A   192.0.2.1
w   IN A   192.0.2.2
w   IN A   192.0.2.3
w   IN MX  10 ns
deep.a.b IN TXT \"down here\"
";

    const DEEP_LINE: &str = "deep.a.b IN TXT \"down here\"\n";

    #[test]
    fn removing_the_last_record_at_a_name_takes_its_empty_non_terminals_with_it() {
        let mut zone = parse_zone_file(REMOVAL_ZONE, "example.com.").unwrap();
        let at = position_of(&zone, "deep.a.b.example.com.", record_types::TXT);
        zone.remove_record(at);
        index_agrees_with_records(&zone, "after the TXT went");

        // NXDOMAIN, not NODATA: an empty non-terminal left over a name with
        // nothing under it says a subtree exists that does not
        // (RFC 4592 §2.2.2).
        for gone in [
            "deep.a.b.example.com.",
            "a.b.example.com.",
            "b.example.com.",
        ] {
            assert_eq!(
                zone.name_kind(nm(gone).as_ref()),
                NameKind::NotFound,
                "{gone} has nothing under it any more"
            );
        }
        assert_eq!(
            zone.name_kind(nm("example.com.").as_ref()),
            NameKind::Exact,
            "the apex still holds its own records"
        );

        let without =
            parse_zone_file(&REMOVAL_ZONE.replace(DEEP_LINE, ""), "example.com.").unwrap();
        assert_eq!(
            shape_of(&zone),
            shape_of(&without),
            "a zone with the record removed is the zone that never held it"
        );
    }

    #[test]
    fn removing_a_name_that_still_has_descendants_leaves_an_empty_non_terminal() {
        let text = format!("{REMOVAL_ZONE}a.b IN A 192.0.2.9\n");
        let mut zone = parse_zone_file(&text, "example.com.").unwrap();
        let at = position_of(&zone, "a.b.example.com.", record_types::A);
        zone.remove_record(at);
        index_agrees_with_records(&zone, "after the A went");

        assert_eq!(
            zone.name_kind(nm("a.b.example.com.").as_ref()),
            NameKind::EmptyNonTerminal,
            "deep.a.b is still under it"
        );
        assert!(!zone.holds_name(nm("a.b.example.com.").as_ref()));
        assert_eq!(
            zone.name_kind(nm("deep.a.b.example.com.").as_ref()),
            NameKind::Exact
        );
        assert_eq!(
            shape_of(&zone),
            shape_of(&parse_zone_file(REMOVAL_ZONE, "example.com.").unwrap())
        );
    }

    #[test]
    fn removing_one_record_of_an_rrset_leaves_the_rest_where_they_were() {
        let mut zone = parse_zone_file(REMOVAL_ZONE, "example.com.").unwrap();
        let at = position_of(&zone, "w.example.com.", record_types::MX);
        zone.remove_record(at);
        index_agrees_with_records(&zone, "after the MX went");

        assert_eq!(
            zone.query(nm("w.example.com.").as_ref(), Qtype::of(record_types::A))
                .len(),
            2,
            "both A records survive"
        );
        assert!(zone
            .query(nm("w.example.com.").as_ref(), Qtype::of(record_types::MX))
            .is_empty());
        assert_eq!(
            zone.name_kind(nm("w.example.com.").as_ref()),
            NameKind::Exact
        );
    }

    /// The one a missing `refile` fails: removing anything but the last record
    /// moves the last one, and its index entry still names where it was.
    #[test]
    fn the_record_a_removal_relocates_is_still_found_under_its_own_name() {
        let mut zone = parse_zone_file(REMOVAL_ZONE, "example.com.").unwrap();
        let last = zone.records.len() - 1;
        let moved = zone.record(last).name.to_owned();
        let rtype = zone.record(last).rdata.rtype();

        let at = position_of(&zone, "ns.example.com.", record_types::A);
        assert_ne!(at, last, "this test is about a removal from the middle");
        zone.remove_record(at);
        index_agrees_with_records(&zone, "after the middle went");

        assert!(
            !zone.query(moved.as_ref(), Qtype::of(rtype)).is_empty(),
            "{moved} moved into the hole, and the index has to have followed it"
        );
    }

    #[test]
    fn a_name_removed_and_added_again_is_an_ordinary_name() {
        let mut zone = parse_zone_file(REMOVAL_ZONE, "example.com.").unwrap();
        let at = position_of(&zone, "deep.a.b.example.com.", record_types::TXT);
        let record = zone.remove_record(at);
        assert_eq!(
            zone.name_kind(nm("b.example.com.").as_ref()),
            NameKind::NotFound
        );

        zone.add_record(record);
        index_agrees_with_records(&zone, "after it came back");
        assert_eq!(
            shape_of(&zone),
            shape_of(&parse_zone_file(REMOVAL_ZONE, "example.com.").unwrap()),
            "the ancestors have to be counted again, and counted once"
        );
        assert_eq!(
            zone.name_kind(nm("b.example.com.").as_ref()),
            NameKind::EmptyNonTerminal
        );
    }

    /// The chains hold positions too, so a removal owes them both halves: the
    /// entry of the record that went, and the entry of the record that moved
    /// into its place.
    ///
    /// An NSEC and an NSEC3 together, because they are two maps and a fix that
    /// reached one of them would pass a test that asked about the other.
    #[test]
    fn a_removal_moves_the_denial_chains_with_the_records() {
        let text = "$TTL 3600\n\
                    @ IN SOA ns1.example.com. admin.example.com. 1 3600 600 86400 3600\n\
                    @ IN NSEC www.example.com. A SOA RRSIG NSEC\n\
                    www IN A 192.0.2.1\n\
                    www IN NSEC example.com. A RRSIG NSEC\n\
                    1avvmb2l1oba4jvim8ie7t8ml1l7ch7c IN NSEC3 1 0 0 - \
                    2avvmb2l1oba4jvim8ie7t8ml1l7ch7c A RRSIG\n\
                    2avvmb2l1oba4jvim8ie7t8ml1l7ch7c IN NSEC3 1 0 0 - \
                    1avvmb2l1oba4jvim8ie7t8ml1l7ch7c A RRSIG\n";
        let mut zone = parse_zone_file(text, "example.com.").unwrap();
        let hash_of = |name: &str| {
            let label = nm(name).as_ref().labels().next().expect("a label").to_vec();
            let decoded =
                base32hex_decode(std::str::from_utf8(&label).expect("base32 is ASCII")).unwrap();
            Nsec3Hash::from_wire(&decoded).expect("a hash")
        };
        let probe = hash_of("3avvmb2l1oba4jvim8ie7t8ml1l7ch7c.example.com.");
        assert_eq!(
            zone.nsec3_covering(probe).map(|r| r.name.to_string()),
            Some("2avvmb2l1oba4jvim8ie7t8ml1l7ch7c.example.com.".to_string()),
            "the chain answers before anything is removed"
        );

        // The A at www is neither a denial record nor the last one, so removing
        // it moves the last NSEC3 and leaves both chains to be repaired.
        let at = position_of(&zone, "www.example.com.", record_types::A);
        assert!(
            at < zone.records.len() - 1,
            "this test needs a denial record after the one it removes"
        );
        zone.remove_record(at);
        index_agrees_with_records(&zone, "after the A went");

        assert_eq!(
            zone.nsec3_covering(probe).map(|r| r.name.to_string()),
            Some("2avvmb2l1oba4jvim8ie7t8ml1l7ch7c.example.com.".to_string()),
            "the NSEC3 that moved has to still be the one its hash names"
        );
        assert_eq!(
            zone.nsec_covering(nm("mail.example.com.").as_ref())
                .map(|r| r.name.to_string()),
            Some("example.com.".to_string()),
            "and so does the NSEC"
        );

        // And the record that went takes its own chain entry with it.
        let at = position_of(&zone, "www.example.com.", record_types::NSEC);
        zone.remove_record(at);
        index_agrees_with_records(&zone, "after the NSEC went");
        assert_eq!(
            zone.nsec_covering(nm("zzz.example.com.").as_ref())
                .map(|r| r.name.to_string()),
            Some("example.com.".to_string()),
            "the only NSEC left is the apex's"
        );
    }

    /// Every record out, one at a time, starting from each position in turn:
    /// the child counts have to come back to nothing whichever way the walk
    /// went.
    #[test]
    fn removing_every_record_empties_the_index() {
        let template = parse_zone_file(REMOVAL_ZONE, "example.com.").unwrap();
        for first in 0..template.records.len() {
            let mut zone = template.clone();
            for step in 0..template.records.len() {
                let at = (first + step) % zone.records.len();
                zone.remove_record(at);
                index_agrees_with_records(&zone, &format!("from {first}, step {step}"));
            }
            assert_eq!(zone.records.len(), 0, "from {first}");
            assert_eq!(
                zone.index.len(),
                0,
                "from {first}: an index entry outlived every record under it"
            );
            assert_eq!(
                zone.name_kind(nm("example.com.").as_ref()),
                NameKind::NotFound,
                "from {first}"
            );
        }
    }

    /// Applying deltas forever must not grow a zone that is not growing.
    ///
    /// **All four of the append-only stores**: the index's name arena, the
    /// spill lists, and — since `TODO.md` #71e — the record name and RDATA
    /// arenas. A difference sequence spells a changed record as a deletion and
    /// an addition (RFC 1995 §2), so every publication appends the same octets
    /// again and a name that falls back to one record leaves its position list
    /// behind. Unbounded in a process that refreshes a feed for a year without
    /// restarting, and invisible: the entry count, the record count and every
    /// answer stay right while the process grows.
    ///
    /// Four times the rounds and the same peak, rather than a size: a bound is
    /// a statement about what a number does *not* depend on (`CLAUDE.md` §10).
    /// The peak and not the final figure, because the rebuild is periodic and
    /// where a run stops between two of them is not the question.
    ///
    /// Against the version without the rebuild `remove_record` triggers, the
    /// index arena peaks at 120 031 octets over 100 rounds and 408 031 over
    /// 400; against one that reindexes without compacting the record arenas,
    /// the name arena reads 121 849 and 415 249. With both, 35 647 and 35 719,
    /// and the spill list 14 either way.
    #[test]
    fn applying_deltas_forever_does_not_grow_the_index() {
        fn churn(rounds: u32) -> (usize, usize, usize, usize, usize, usize) {
            let mut text = String::from("$TTL 3600\n@ IN SOA ns admin 1 3600 600 86400 300\n");
            for i in 0..1000 {
                text.push_str(&format!("host{i:06} IN A 192.0.2.1\n"));
            }
            // One name with an RRset, which is what leaves a list behind.
            text.push_str("many IN A 192.0.2.7\nmany IN A 192.0.2.8\n");
            let mut zone = parse_zone_file(&text, "example.com.").unwrap();
            let mut peak_arena = zone.index.names.len();
            let mut peak_spills = zone.spills.len();
            let mut peak_names = zone.names.len();
            let mut peak_rdata = zone.rdata.len();

            for round in 0..rounds {
                // Forty rules change, each the only record at its own name,
                // plus one of the two at `many`.
                for i in 0..40 {
                    let name = format!("host{i:06}.example.com.");
                    let at = position_of(&zone, &name, record_types::A);
                    let mut record = zone.remove_record(at);
                    record.ttl = Ttl::from_secs(3600 + round);
                    zone.add_record(record);
                }
                let at = position_of(&zone, "many.example.com.", record_types::A);
                let mut record = zone.remove_record(at);
                record.ttl = Ttl::from_secs(3600 + round);
                zone.add_record(record);
                index_agrees_with_records(&zone, &format!("round {round}"));
                // The peak, not the end: the rebuild is periodic, so where a
                // run stops between two of them moves the final figure and not
                // the bound this is about.
                peak_arena = peak_arena.max(zone.index.names.len());
                peak_spills = peak_spills.max(zone.spills.len());
                peak_names = peak_names.max(zone.names.len());
                peak_rdata = peak_rdata.max(zone.rdata.len());
            }
            (
                peak_arena,
                peak_spills,
                zone.index.len(),
                zone.records.len(),
                peak_names,
                peak_rdata,
            )
        }

        let short = churn(100);
        let long = churn(400);
        assert_eq!(
            (short.2, short.3),
            (long.2, long.3),
            "no name and no record arrived or left"
        );
        // Within a few parts in a thousand: which names a cycle happens to
        // re-intern before the rebuild moves the peak a little, and the
        // question is whether it moves with the *rounds*.
        assert!(
            100 * long.0 <= 105 * short.0,
            "the arena's peak grew with the number of publications: {} then {}",
            short.0,
            long.0
        );
        assert!(
            100 * long.4 <= 105 * short.4,
            "the name arena's peak grew with the number of publications: {} then {}",
            short.4,
            long.4
        );
        assert!(
            100 * long.5 <= 105 * short.5,
            "the RDATA arena's peak grew with the number of publications: {} then {}",
            short.5,
            long.5
        );
        assert!(
            long.1 <= short.1 + 1,
            "the spill list's peak grew with the number of publications: {} then {}",
            short.1,
            long.1
        );
    }

    fn index_of(zone: &Zone) -> Vec<(Vec<u8>, Vec<usize>)> {
        let mut out: Vec<(Vec<u8>, Vec<usize>)> = zone
            .index
            .iter()
            .map(|(key, slot)| (key.to_vec(), zone.positions(slot).to_vec()))
            .collect();
        out.sort();
        out
    }

    /// A top-level `$ORIGIN` after a record leaves the zone that setting the
    /// apex first would have built — the bookkeeping that is *about* the apex
    /// included, not merely the records.
    ///
    /// The parser reindexed per `$ORIGIN` and now owes one rebuild at the end
    /// (`TODO.md` #62c), so this is what "the same zone" has to mean. The
    /// records here are the three things the apex decides: an NS RRset that is
    /// a delegation under one apex and the apex's own under the other, a
    /// wildcard, and a name whose ancestors become empty non-terminals only for
    /// an apex above them.
    #[test]
    fn a_late_origin_leaves_the_zone_setting_the_apex_first_would_have() {
        let text = "ns1.old.test. IN A 192.0.2.1\n\
                    sub.deep.old.test. IN A 192.0.2.2\n\
                    *.wild.old.test. IN A 192.0.2.3\n\
                    child.old.test. IN NS ns1.old.test.\n\
                    $ORIGIN old.test.\n\
                    @ IN NS ns1\n\
                    host IN A 192.0.2.4\n";
        let parsed = parse_zone_file(text, "example.com.").unwrap();
        assert_eq!(parsed.origin(), nm("old.test.").as_ref());

        let mut direct = Zone::new(nm("old.test."));
        for record in parsed.records() {
            direct.add_record(record.to_owned());
        }

        assert_eq!(index_of(&parsed), index_of(&direct), "the same index");
        assert_eq!(parsed.shortcuts, direct.shortcuts, "the same shortcuts");
        assert_eq!(
            parsed.name_kind(nm("deep.old.test.").as_ref()),
            NameKind::EmptyNonTerminal,
            "an ancestor inside the new apex is a node of the zone"
        );
        assert!(
            parsed
                .delegation_for(nm("www.child.old.test.").as_ref())
                .is_some(),
            "an NS RRset below the new apex is a zone cut"
        );
    }

    /// Moving the apex leaves the denial chains alone: they are keyed by the
    /// record's own absolute name, which no apex moves (`TODO.md` #62c).
    #[test]
    fn set_origin_leaves_the_denial_chains_where_they_are() {
        let text = "$TTL 3600\n\
                    @ IN SOA ns1.example.com. admin.example.com. 1 3600 600 86400 3600\n\
                    @ IN NSEC www.example.com. A SOA RRSIG NSEC\n\
                    www IN A 192.0.2.1\n\
                    www IN NSEC example.com. A RRSIG NSEC\n";
        let mut zone = parse_zone_file(text, "example.com.").unwrap();
        let covering = |zone: &Zone, name: &str| {
            zone.nsec_covering(nm(name).as_ref())
                .map(|r| r.name.to_owned())
        };
        let before = covering(&zone, "mail.example.com.");
        assert!(before.is_some(), "the chain answers before the move");

        zone.set_origin(nm("com."));
        assert_eq!(covering(&zone, "mail.example.com."), before);
        assert!(zone.has_nsec_chain());
    }

    /// Parsing must not cost more per record because the file has more
    /// `$ORIGIN` lines.
    ///
    /// A ratio, not a wall-clock floor (`CLAUDE.md` §10): doubling a file whose
    /// every record carries its own `$ORIGIN` must roughly double the work.
    /// `set_origin` rebuilds the index over every record so far, so calling it
    /// per line was O(sections x records) — 3.81 s at 8 000 records and 13.64 s
    /// at 16 000 in release, ~4x per doubling — and fails this at 3x with room
    /// to spare. Deferring the move to one rebuild reads ~2x.
    #[test]
    fn parsing_does_not_cost_more_per_record_when_every_record_moves_the_origin() {
        fn parse(records: usize) -> std::time::Duration {
            let mut text = String::from("$TTL 3600\n");
            for i in 0..records {
                text.push_str(&format!("$ORIGIN s{i}.example.com.\nhost IN A 192.0.2.1\n"));
            }
            let start = std::time::Instant::now();
            let zone = parse_zone_file(&text, "example.com.").expect("parses");
            let took = start.elapsed();
            assert_eq!(zone.records().len(), records);
            took
        }

        let small = parse(1_000);
        let large = parse(2_000);
        assert!(
            large < small * 3,
            "twice the records must not cost four times the work: \
             {small:?} at 1k against {large:?} at 2k"
        );
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

    /// `logical_lines` borrows a line that holds no comment, quote, escape or
    /// parenthesis and copies one that does. The two paths must agree, which is
    /// what a fast path added for speed can quietly stop doing: a regression
    /// test for the split, not for any bug.
    #[test]
    fn a_trailing_comment_changes_nothing_but_the_path_through_the_lexer() {
        let bare = "www IN A 192.0.2.1\n   IN A 192.0.2.2\n";
        let commented = "www IN A 192.0.2.1  ; the first\n   IN A 192.0.2.2 ; and the second\n";
        let of = |text: &str| -> Vec<(String, Vec<u8>)> {
            parse_zone_file(text, "example.com.")
                .unwrap()
                .records()
                .iter()
                .map(|r| (r.name.to_presentation(), r.rdata.bytes().to_vec()))
                .collect()
        };
        assert_eq!(of(bare), of(commented));
        // The owner name carried over from the previous line is the half a
        // fast path can lose: it is read off the *raw* line's indentation.
        assert_eq!(of(bare).len(), 2);
        assert_eq!(of(bare)[1].0, "www.example.com.");
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
        let text: Vec<Cow<'_, str>> = fields.iter().map(|s| Cow::Borrowed(*s)).collect();
        let origin = nm("example.com.");
        let mx = rdata_from_fields(
            "MX",
            Cow::Borrowed("10 mx.example.com."),
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
        let text: Vec<Cow<'_, str>> = bad.iter().map(|s| Cow::Borrowed(*s)).collect();
        let err = rdata_from_fields(
            "MX",
            Cow::Borrowed("notanumber mx.example.com."),
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
            let ParsedRecord::CNAME(target) = zone
                .records()
                .get(0)
                .expect("a record of the zone")
                .rdata
                .parse()
                .expect("a CNAME")
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
        let name = zone.records().get(0).expect("a record of the zone").name;
        assert_eq!(name.label_count(), 3, "`a.b`, `example`, `com` — not four");
        assert_eq!(name.labels().next().expect("a first label"), b"a.b");
        // It goes back out as it came in, so a zone file round trips.
        assert_eq!(name.to_string(), "a\\.b.example.com.");

        // And it is reachable under the name it really has, not under `a.b...`.
        assert_eq!(
            zone.query(name, Qtype::of(rt::A)).len(),
            1,
            "reachable under the name it was stored as"
        );
        assert!(zone
            .query(nm("a.b.example.com.").as_ref(), Qtype::of(rt::A))
            .is_empty());
    }
}
