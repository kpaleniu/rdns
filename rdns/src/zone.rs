use crate::error::ZoneError;
use crate::{ParsedRecord, RecordData};
use crate::utils::record_type_code;
use crate::utils::record_types as rt;
use crate::dnssec_denial::{base32hex_decode, canonical_sort_key};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// A single DNS resource record stored in a zone
#[derive(Debug, Clone)]
pub struct ZoneRecord {
    pub name: String,
    pub ttl: i32,
    pub class: u16, // typically 1 for IN
    pub rdata: RecordData,
}

/// In-memory DNS zone storage.
///
/// Records are held in one vector and reached through an index built as they are
/// added: the absolute, down-cased owner name to the positions of the records at
/// it. Without it, answering a query means filtering the whole vector and
/// normalizing *both* names into fresh `String`s for every record touched — two
/// allocations per record per query, which on a 10k-record zone measured 4.4 ms
/// and 20k allocations for a single lookup.
///
/// Keying on the name rather than on (name, type) is deliberate. A server needs
/// two questions answered, and the second one is what tells NXDOMAIN from
/// NODATA: "which records of this type are at this name", and "does this name
/// exist at all". A (name, type) map answers the first and cannot answer the
/// second without probing 65535 types, whereas the records at one name are a
/// handful, so selecting a type from them costs nothing measurable. It is also
/// how NSD and Knot store a zone — a node per name, holding its RRsets.
///
/// `origin` and `records` are private because the index is derived from both: a
/// record appended behind its back, or an origin changed without a rebuild,
/// leaves the zone answering NXDOMAIN for data it holds. That bug has already
/// happened here once, before there was an index to get wrong.
#[derive(Debug, Clone)]
pub struct Zone {
    origin: String,
    records: Vec<ZoneRecord>,
    /// Positions in `records`, by [`Zone::lookup_key`] of the owner name.
    index: HashMap<String, Vec<usize>>,
    /// The NSEC chain, keyed by canonical sort order, and the NSEC3 chain,
    /// keyed by hash — both empty for the unsigned zones that are most of them.
    ///
    /// Ordered, where the name index is not, because the question a denial asks
    /// is a range one: "which record's span contains this name". A hash map
    /// cannot answer that without looking at every entry, and answering it by
    /// scanning the zone would put an O(records) walk on the negative-answer
    /// path — the same mistake the name index exists to have fixed.
    nsec_chain: BTreeMap<Vec<u8>, usize>,
    nsec3_chain: BTreeMap<Vec<u8>, usize>,
    /// Every ancestor, up to the apex, of a name that is in `index` — the names
    /// that exist because something below them does.
    ///
    /// `index` cannot answer this: a zone holding only `deep.a.b.example.com.`
    /// has records at one name and *four* names that exist. RFC 4592 §2.2.2
    /// says so, and the difference is NODATA against NXDOMAIN for `a.b` and
    /// `b` — which an RFC 8020 resolver then extends downwards, taking the
    /// zone's own data off the internet. Kept as its own set rather than folded
    /// into `index` because the denial path needs the literal question too, and
    /// [`Zone::holds_name`] is where that lives.
    non_terminals: HashSet<String>,
}

/// Why a name has an answer in this zone, or has none — the distinction
/// RFC 1034 §4.3.2 and RFC 2308 both turn on.
///
/// Three of these are "the name exists" and only one is NXDOMAIN, which is the
/// whole reason it is an enum rather than a bool: an empty non-terminal and a
/// wildcard match are NODATA, and each owes a *different* DNSSEC proof (see
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
            non_terminals: HashSet::new(),
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
    /// The index keys are absolute names, so any record still held under a
    /// *relative* name has to be re-keyed — that is what the rebuild is for.
    /// Records the zone parser added are already absolute (it resolves each owner
    /// name against the origin in force at its line, which is what makes
    /// `$ORIGIN` apply to the lines below it), so this only moves records added
    /// through [`Zone::add_record`] with a relative name.
    pub fn set_origin(&mut self, origin: &str) {
        self.origin = absolute(origin);
        self.reindex();
    }

    /// Add a record to the zone
    pub fn add_record(&mut self, record: ZoneRecord) {
        let key = self.lookup_key(&record.name);
        let position = self.records.len();
        self.note_non_terminals(&key);
        self.index.entry(key).or_default().push(position);
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
    /// [`Zone::name_exists`] answers a different question, the one a query
    /// needs: it says yes for a name a wildcard reaches. Denial of existence
    /// needs the literal one, because a name that only exists through a
    /// wildcard is precisely the name a wildcard answer has to prove does
    /// *not* exist (RFC 4035 §3.1.3).
    pub fn holds_name(&self, name: &str) -> bool {
        self.index.contains_key(&self.lookup_key(name))
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
    /// Strictly *between* two names: an NSEC sitting at `name` itself proves
    /// the opposite, that the name is there, so the search is exclusive at the
    /// low end. When nothing sorts before `name` the answer is the last record
    /// in the chain, because the chain is a loop — its final NSEC points back
    /// at the apex and so covers everything after the last name in the zone
    /// *and* everything before the first (RFC 4034 §4.1.1).
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
        let position = self
            .nsec3_chain
            .range(..hash.to_vec())
            .next_back()
            .or_else(|| self.nsec3_chain.iter().next_back())?;
        Some(&self.records[*position.1])
    }

    /// Where a denial record belongs in the ordered chains, if it is one.
    ///
    /// An NSEC is filed under its owner name; an NSEC3 under the hash in its
    /// owner's first label, which is the value the chain is actually ordered
    /// by. A record whose label will not decode is left out rather than filed
    /// under something wrong — it cannot be part of a chain a validator can
    /// walk either.
    fn chain_key(&self, record: &ZoneRecord) -> Option<(Chain, Vec<u8>)> {
        match record.rdata.rtype {
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
    /// all: an existing name shadows the wildcard entirely, types it does not
    /// carry included, and so does an empty non-terminal (RFC 1034 §4.3.3,
    /// RFC 4592 §2.2.1 and §4.4). The linear scan this replaced returned the
    /// exact *and* the wildcard records together, merging two owners' data into
    /// one RRset.
    pub fn query(&self, name: &str, qtype: u16) -> Vec<&ZoneRecord> {
        let key = self.lookup_key(name);
        let positions = match self.name_kind_of_key(&key) {
            NameKind::Exact => self.index.get(&key),
            NameKind::Wildcard(ref wildcard) => self.index.get(wildcard),
            NameKind::EmptyNonTerminal | NameKind::NotFound => None,
        };
        match positions {
            Some(positions) => self.of_type(positions, qtype),
            None => Vec::new(),
        }
    }

    /// The serial from the apex SOA, if the zone has one.
    ///
    /// The serial is how every other server decides whether what it holds is
    /// stale, so it is the one field a zone is compared by — NOTIFY sends it,
    /// and a secondary's refresh check is a comparison of it.
    pub fn serial(&self) -> Option<u32> {
        self.query(&self.origin, crate::utils::record_types::SOA)
            .first()
            .and_then(|soa| match soa.rdata.parse() {
                Ok(crate::ParsedRecord::SOA { serial, .. }) => Some(serial),
                _ => None,
            })
    }

    /// Whether the zone holds anything at `name` — by that name, because
    /// something below it exists, or through a wildcard. This is the NXDOMAIN
    /// question: a name that exists with no record of the queried type is
    /// NODATA, which is a different answer.
    pub fn name_exists(&self, name: &str) -> bool {
        !matches!(self.name_kind(name), NameKind::NotFound)
    }

    /// Why `name` has an answer here, or has none. See [`NameKind`].
    pub fn name_kind(&self, name: &str) -> NameKind {
        self.name_kind_of_key(&self.lookup_key(name))
    }

    /// [`Zone::name_kind`] for a name already in [`Zone::lookup_key`] form.
    ///
    /// The wildcard search is a closest-encloser walk, not a single lookup, and
    /// that is the whole of the correction here. A wildcard synthesizes to any
    /// depth: RFC 4592 §3.3.2's worked example answers `_telnet._tcp.host1.example.`
    /// from `*.example.`, two labels down. The single `split_once` this replaced
    /// reached exactly one label, citing §2.1.1 — which is about `*` being
    /// special only as the leftmost label of a zone-file owner name, and says
    /// nothing about how deep synthesis reaches.
    ///
    /// The walk stops at the first ancestor that exists, and the *only* wildcard
    /// that may answer is the one directly below it (§3.3.1). Going on to try
    /// `*.<grandparent>` would answer for a name whose parent exists, which
    /// §4.4 forbids: an existing name — an empty non-terminal included — ends
    /// the search whether or not it has the type asked for.
    fn name_kind_of_key(&self, key: &str) -> NameKind {
        if self.index.contains_key(key) {
            return NameKind::Exact;
        }
        if self.non_terminals.contains(key) {
            return NameKind::EmptyNonTerminal;
        }

        let origin = self.origin_key();
        let mut name = key;
        while let Some(encloser) = parent_name(name) {
            if !is_at_or_under(encloser, &origin) {
                // Walked out of the zone without finding anything, which means
                // the query was never in it to begin with.
                return NameKind::NotFound;
            }
            if !self.node_exists(encloser) {
                name = encloser;
                continue;
            }
            // The closest encloser. A wildcard below a zone cut is occluded —
            // it is the child's data, not ours (RFC 4592 §2.2.1) — so a
            // delegation between here and the apex means no synthesis at all,
            // and the caller owes a referral instead.
            if self.delegation_for_key(encloser).is_some() {
                return NameKind::NotFound;
            }
            let wildcard = format!("*.{encloser}");
            return if self.index.contains_key(&wildcard) {
                NameKind::Wildcard(wildcard)
            } else {
                NameKind::NotFound
            };
        }
        NameKind::NotFound
    }

    /// Whether this name is a node of the zone: it has records, or it has
    /// descendants (RFC 4592 §2.2.2). Takes a lookup key.
    fn node_exists(&self, key: &str) -> bool {
        self.index.contains_key(key) || self.non_terminals.contains(key)
    }

    /// The delegation point at or above `name`, if the zone's authority stops
    /// before reaching it.
    ///
    /// The deepest ancestor-or-self other than the apex with an NS RRset
    /// (RFC 1034 §4.2.1). `Some` means the answer owes a referral — the NS
    /// RRset, its glue, and AA **clear** — rather than data or a denial. The
    /// apex is excluded because its NS RRset is this zone's own, not a cut.
    pub fn delegation_for(&self, name: &str) -> Option<String> {
        self.delegation_for_key(&self.lookup_key(name))
    }

    fn delegation_for_key(&self, key: &str) -> Option<String> {
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

    /// Whether there is an RRset of `rtype` at exactly this key.
    fn has_type(&self, key: &str, rtype: u16) -> bool {
        self.index.get(key).is_some_and(|positions| {
            positions
                .iter()
                .any(|&i| record_type_code(&self.records[i].rdata) == rtype)
        })
    }

    /// Record every ancestor of `key`, up to the apex, as a name that exists.
    ///
    /// Stops as soon as an ancestor is already known, because ancestors are
    /// always noted all the way to the apex — so one being present means the
    /// rest are too. That makes the whole of index construction linear in the
    /// zone rather than in names × labels.
    fn note_non_terminals(&mut self, key: &str) {
        let origin = self.origin_key();
        let mut name = key.to_string();
        while let Some(parent) = parent_name(&name) {
            if !is_at_or_under(parent, &origin) {
                // A record whose owner is outside the zone — glue written with
                // a foreign absolute name, say. Its ancestors are somebody
                // else's names and must not be claimed to exist here.
                return;
            }
            let parent = parent.to_string();
            let reached_apex = parent == origin;
            if !self.non_terminals.insert(parent.clone()) || reached_apex {
                return;
            }
            name = parent;
        }
    }

    /// The apex in [`Zone::lookup_key`] form.
    fn origin_key(&self) -> String {
        self.origin.to_ascii_lowercase()
    }

    /// The records at these positions that are of `qtype`.
    fn of_type(&self, positions: &[usize], qtype: u16) -> Vec<&ZoneRecord> {
        positions
            .iter()
            .map(|&i| &self.records[i])
            .filter(|r| record_type_code(&r.rdata) == qtype)
            .collect()
    }

    /// Rebuild the index from `records`.
    fn reindex(&mut self) {
        let keys: Vec<String> = self
            .records
            .iter()
            .map(|r| self.lookup_key(&r.name))
            .collect();
        self.index.clear();
        self.non_terminals.clear();
        for (position, key) in keys.into_iter().enumerate() {
            self.note_non_terminals(&key);
            self.index.entry(key).or_default().push(position);
        }

        // The chains are keyed by the *absolute* name too, so moving the origin
        // moves them — an NSEC filed under a relative name would be findable
        // only by a query that happened to ask the same way.
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
    /// which is why this is `make_ascii_lowercase` and not `to_lowercase`).
    fn lookup_key(&self, name: &str) -> String {
        let mut key = self.normalize_name(name);
        key.make_ascii_lowercase();
        key
    }

    /// Helper to match domain names, handling wildcards and relative names.
    ///
    /// Both sides are normalized to absolute form first, so a record stored as
    /// `@` or `www` matches a query for the origin or `www.<origin>.`. This is
    /// the definition of matching that the index encodes; a test holds the two
    /// to the same answers.
    pub fn matches_query(&self, record_name: &str, query_name: &str) -> bool {
        let record_name = self.lookup_key(record_name);
        let query_name = self.lookup_key(query_name);

        if record_name == query_name {
            return true;
        }
        // Which wildcard reaches a name is a question about the whole zone, not
        // about the two names — the closest encloser decides it. Asking
        // `name_kind` rather than re-deriving it here is what keeps this in step
        // with the index instead of drifting from it.
        matches!(self.name_kind_of_key(&query_name), NameKind::Wildcard(w) if w == record_name)
    }

    /// Normalize domain names to absolute form with trailing dot
    pub fn normalize_name(&self, name: &str) -> String {
        absolutize(name, &self.origin)
    }
}

/// A zone-file owner name in absolute form, resolved against `origin`: `@` and
/// the empty name are the origin itself, a name ending in `.` is already
/// absolute, and anything else is relative to it.
fn absolutize(name: &str, origin: &str) -> String {
    let name = name.trim();
    if name.is_empty() || name == "@" {
        origin.to_string()
    } else if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.{origin}")
    }
}

/// The parent of an absolute name: its first label removed. `None` at the root,
/// which is what terminates every walk up the tree.
fn parent_name(name: &str) -> Option<&str> {
    if name == "." {
        return None;
    }
    let (_first_label, rest) = name.split_once('.')?;
    Some(if rest.is_empty() { "." } else { rest })
}

/// Whether `name` is `origin` or sits below it. Both absolute and down-cased.
fn is_at_or_under(name: &str, origin: &str) -> bool {
    if origin == "." {
        return true;
    }
    if name == origin {
        return true;
    }
    // Suffix alone is not enough: `notexample.com.` ends with `example.com.`
    // and is a different zone's name entirely, so the boundary has to land on
    // a label separator.
    name.len() > origin.len()
        && name.ends_with(origin)
        && name.as_bytes()[name.len() - origin.len() - 1] == b'.'
}

/// A name with its trailing dot.
fn absolute(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// The small parse helpers below return `Result<_, String>` on purpose, and it
/// is the one place in this library that shape is right: they produce a *detail*
/// — "odd number of hexadecimal digits" — and the caller is the zone parser,
/// which is the only thing that knows the line number to attach it to. Giving
/// them a `ZoneError` would mean inventing a line number they do not have. See
/// `CLAUDE.md` §3.
fn parse_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    let hex_str = hex_str.trim();
    if !hex_str.len().is_multiple_of(2) {
        return Err("Odd number of hexadecimal digits".to_string());
    }
    let mut res = Vec::with_capacity(hex_str.len() / 2);
    let chars: Vec<char> = hex_str.chars().collect();
    for i in (0..chars.len()).step_by(2) {
        let high = chars[i].to_digit(16).ok_or("Invalid hex digit")? as u8;
        let low = chars[i+1].to_digit(16).ok_or("Invalid hex digit")? as u8;
        res.push((high << 4) | low);
    }
    Ok(res)
}

fn parse_base32_hex(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim().to_uppercase();
    let alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let char_to_val = |c: u8| -> Option<u8> {
        alphabet.iter().position(|&x| x == c).map(|p| p as u8)
    };
    
    let mut bits = 0u64;
    let mut count = 0;
    let mut res = Vec::new();
    
    for &c in input.as_bytes() {
        if c == b'=' {
            break; // Skip padding
        }
        let val = char_to_val(c).ok_or_else(|| format!("Invalid Base32 hex character: {}", c as char))?;
        bits = (bits << 5) | (val as u64);
        count += 5;
        if count >= 8 {
            res.push((bits >> (count - 8)) as u8);
            count -= 8;
        }
    }
    Ok(res)
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(month: i32, year: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => if is_leap(year) { 29 } else { 28 },
        _ => 0,
    }
}

pub(crate) fn parse_dnssec_time(time_str: &str) -> Result<u32, String> {
    if let Ok(epoch) = time_str.parse::<u32>() {
        return Ok(epoch);
    }
    if time_str.len() == 14 {
        let year = time_str[0..4].parse::<i32>().map_err(|e| e.to_string())?;
        let month = time_str[4..6].parse::<i32>().map_err(|e| e.to_string())?;
        let day = time_str[6..8].parse::<i32>().map_err(|e| e.to_string())?;
        let hour = time_str[8..10].parse::<i32>().map_err(|e| e.to_string())?;
        let min = time_str[10..12].parse::<i32>().map_err(|e| e.to_string())?;
        let sec = time_str[12..14].parse::<i32>().map_err(|e| e.to_string())?;

        let mut total_days = 0;
        for y in 1970..year {
            total_days += if is_leap(y) { 366 } else { 365 };
        }
        for m in 1..month {
            total_days += days_in_month(m, year);
        }
        total_days += day - 1;

        let epoch = total_days as i64 * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
        return Ok(epoch as u32);
    }
    Err(format!("Invalid DNSSEC time format: {}", time_str))
}

/// The `YYYYMMDDHHmmSS` form an RRSIG's times are written in (RFC 4034 §3.2).
///
/// The inverse of [`parse_dnssec_time`], and deliberately next to it: the two
/// share the calendar arithmetic, and a formatter that disagreed with the parser
/// would write signature validity times that read back as different instants.
/// Kept in UTC, which is the only zone a DNSSEC timestamp has.
///
/// The parser also accepts a bare epoch, and writing that would be shorter — but
/// nothing else in the ecosystem does, and a dumped zone whose signatures cannot
/// be read at a glance is a zone nobody can debug.
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

    let mut month = 1;
    while days >= days_in_month(month, year) {
        days -= days_in_month(month, year);
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
/// A name with no type code is an error rather than a silent omission: this used
/// to drop what it did not recognize, which turns an NSEC that denies six types
/// into one that denies five — a signed record quietly changed into a different
/// signed record. `TYPEnnn` (RFC 3597 §5) means every type has a spelling, so
/// there is no longer a case where dropping one would be the lesser evil.
///
/// The bits are laid out by [`crate::dnssec_denial::build_type_bitmap`], the
/// same function the validator's own denials are built with, so a bitmap read
/// here and one synthesized there cannot drift apart.
fn construct_type_bitmap(types: &[String]) -> Result<Vec<u8>, String> {
    let mut codes = Vec::with_capacity(types.len());
    for name in types {
        let code = crate::utils::record_type_name_to_code(&name.to_uppercase())
            .ok_or_else(|| format!("unknown record type {name:?} in type bitmap"))?;
        codes.push(code);
    }
    codes.sort_unstable();
    codes.dedup();
    Ok(crate::dnssec_denial::build_type_bitmap(&codes))
}

/// Read `\# <length> <hex>` (RFC 3597 §5) into stored form.
///
/// The stated length is checked against the digits rather than trusted: the two
/// disagreeing means the record was mangled somewhere, and a length field is
/// exactly the sort of thing a hand-edit gets wrong.
///
/// A known type is parsed once after decoding, purely to reject it — the bytes
/// are kept either way, but RDATA that cannot be read as the type it claims is a
/// malformed record, and this parser's rule is that a malformed record fails the
/// load rather than waiting to fail a query.
fn parse_generic_rdata(record_type: &str, fields: &[&str]) -> Result<RecordData, String> {
    let rtype = crate::utils::record_type_name_to_code(record_type)
        .ok_or_else(|| format!("unknown record type {record_type:?}"))?;

    let Some((length, hex)) = fields.split_first() else {
        return Err("generic rdata needs a length after '\\#'".to_string());
    };
    let length: usize = length
        .parse()
        .map_err(|e| format!("invalid generic rdata length {length:?}: {e}"))?;

    let bytes = parse_hex(&hex.concat()).map_err(|e| format!("invalid generic rdata: {e}"))?;
    if bytes.len() != length {
        return Err(format!(
            "generic rdata says {length} bytes but carries {}",
            bytes.len()
        ));
    }

    let stored = RecordData {
        rtype,
        rdata: bytes.into_boxed_slice(),
    };
    // A type with no parser reads back as `Unknown` rather than failing, so this
    // only ever rejects a known type whose bytes are not that type.
    stored
        .parse()
        .map_err(|e| format!("generic rdata is not valid {record_type}: {e}"))?;
    Ok(stored)
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
/// Three things make this more than `content.lines()`:
///
/// - **Parentheses group data across a line boundary**, which is how every real
///   SOA is written. A parenthesized SOA used to fail the load outright, so the
///   zone files this server could read were the ones nothing else writes.
/// - **A `;` begins a comment — except inside a quoted string**, where it is
///   data. TXT records are full of semicolons (SPF, DKIM), and cutting the line
///   at the first one turned them silently into something shorter.
/// - **A quoted string may hold parentheses too**, which must not open or close
///   a group, and `\` escapes whatever follows it.
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
                // The parentheses themselves are not data. Replacing them with a
                // space keeps `(1` and `1)` from becoming tokens.
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
/// Whitespace splitting alone cannot express a TXT record: `"two words"` is one
/// `<character-string>` and `two words` is two, and the quotes are the only
/// thing that says which. A quoted field also survives being empty (`""`), which
/// is a legal TXT string and disappears under `split_whitespace`.
///
/// Escapes are resolved inside quotes and nowhere else — a bare token like
/// `a\.b` is a name whose meaning changes if the backslash is dropped, and names
/// are not this function's business.
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

/// How deep `$INCLUDE` may nest. A file that includes itself is a loop, and the
/// only way to notice is to stop counting somewhere.
const MAX_INCLUDE_DEPTH: usize = 8;

/// What the parser carries from one line to the next.
struct ParseState {
    /// The origin relative owner names are resolved against — `$ORIGIN`, or the
    /// origin an `$INCLUDE` named for the file being read.
    origin: String,
    /// The default TTL for records that do not state one (`$TTL`).
    ttl: i32,
    /// The last owner name seen, absolute, for lines that omit theirs.
    owner: Option<String>,
}

/// Parse a BIND-format zone file.
///
/// `$INCLUDE` resolves relative paths against the process's working directory
/// here, because a string of content has no directory of its own. Use
/// [`parse_zone_file_at`] when the file is on disk — that resolves them the way
/// an operator expects, next to the file doing the including.
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
        ttl: 3600,
        owner: None,
    };
    parse_into(&mut zone, content, &mut state, base_dir, 0)?;
    check_cname_exclusivity(&zone)?;
    Ok(zone)
}

/// RFC 1034 §3.6.2: a CNAME must be the only type at its owner name.
///
/// Refused at load rather than coped with at query time, because there is no
/// correct answer for the shape. An alias says "this name is really that name",
/// so data beside it contradicts it, and a server has to pick one — which means
/// two servers loading the same file answer differently. The exceptions are the
/// three types that describe the name rather than name it: RRSIG signs the
/// CNAME, and NSEC/NSEC3 deny the types around it (RFC 4035 §2.5).
fn check_cname_exclusivity(zone: &Zone) -> Result<(), ZoneError> {
    let mut by_name: HashMap<String, (bool, Vec<u16>)> = HashMap::new();
    for record in zone.records() {
        let rtype = record_type_code(&record.rdata);
        if matches!(rtype, rt::RRSIG | rt::NSEC | rt::NSEC3) {
            continue;
        }
        let entry = by_name
            .entry(zone.lookup_key(&record.name))
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

/// Read `content` into `zone`. Recurses for `$INCLUDE`, hence `depth`.
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

        // Handle $ORIGIN directive
        if first.eq_ignore_ascii_case("$ORIGIN") {
            if let Some(new_origin) = parts.get(1) {
                state.origin = absolutize(new_origin, &state.origin);
                // The apex is the zone's identity, so only the file that *is*
                // the zone may move it — an included fragment redefining the
                // zone it was pulled into would be a surprise, and RFC 1035
                // §5.1 keeps an include's origin to the included file anyway.
                if depth == 0 {
                    zone.set_origin(&state.origin.clone());
                }
            }
            continue;
        }

        // Handle $TTL directive
        if first.eq_ignore_ascii_case("$TTL") {
            if let Some(value) = parts.get(1) {
                state.ttl = value
                    .parse()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid $TTL {value:?}: {e}")))?;
            }
            continue;
        }

        // Handle $INCLUDE directive: `$INCLUDE <file> [origin]`
        if first.eq_ignore_ascii_case("$INCLUDE") {
            let Some(&file) = parts.get(1) else {
                return Err(ZoneError::syntax(ln, "$INCLUDE needs a file name"));
            };
            if depth + 1 >= MAX_INCLUDE_DEPTH {
                return Err(ZoneError::syntax(ln, format!(
                    "$INCLUDE nested more than {MAX_INCLUDE_DEPTH} deep — a cycle?"
                )));
            }
            let path = match base_dir {
                Some(dir) => dir.join(file),
                None => PathBuf::from(file),
            };
            let included = std::fs::read_to_string(&path)
                .map_err(|e| ZoneError::syntax(ln, format!("$INCLUDE {}: {e}", path.display())))?;

            // RFC 1035 §5.1: the origin an $INCLUDE names is for the included
            // file, and nothing the included file does changes the origin of the
            // file that included it. So the state goes in as a copy and none of
            // it comes back — the owner name does not carry across either, since
            // a fragment inheriting an owner from wherever it happened to be
            // included is not something anyone can read.
            let mut inner = ParseState {
                origin: parts
                    .get(2)
                    .map(|o| absolutize(o, &state.origin))
                    .unwrap_or_else(|| state.origin.clone()),
                ttl: state.ttl,
                owner: None,
            };
            parse_into(zone, &included, &mut inner, path.parent(), depth + 1)?;
            continue;
        }

        // Parse record: [name] [ttl] [class] type rdata...
        //
        // Position is what tells an owner name apart from a TTL/class/type, not
        // the token's shape: a name may end in '.' (an FQDN) or contain digits
        // (`www2`), and common host names collide with type mnemonics (`ns IN A
        // …` — `ns` is the owner there, not an NS record).
        //
        // The name is resolved against the origin *in force here* rather than
        // stored relative, which is what makes `$ORIGIN` apply to the lines
        // below it only and what lets an `$INCLUDE` bring records in under a
        // different origin.
        let mut idx = 0;
        let record_name = if logical.omits_owner {
            state.owner.clone().ok_or_else(|| {
                ZoneError::syntax(ln, "record omits its owner name but no previous record supplies one")
            })?
        } else {
            let name = absolutize(first, &state.origin);
            state.owner = Some(name.clone());
            idx += 1;
            name
        };

        // Parse TTL and class
        let mut ttl = state.ttl;
        let mut class = 1u16; // IN

        while idx < parts.len() {
            if let Ok(parsed_ttl) = parts[idx].parse::<i32>() {
                ttl = parsed_ttl;
                state.ttl = ttl;
                idx += 1;
            } else if parts[idx].eq_ignore_ascii_case("IN")
                || parts[idx].eq_ignore_ascii_case("CH")
                || parts[idx].eq_ignore_ascii_case("HS")
            {
                class = match parts[idx].to_uppercase().as_str() {
                    "IN" => 1,
                    "CH" => 3,
                    "HS" => 4,
                    _ => 1,
                };
                idx += 1;
            } else {
                break;
            }
        }

        if idx >= parts.len() {
            continue;
        }

        // Parse record type and data
        let record_type = parts[idx].to_uppercase();
        idx += 1;
        let rdata = parts[idx..].join(" ");

        // RFC 3597 §5's generic form: `\# <length> <hex>`, which says nothing
        // about what the RDATA means and so can carry any type at all. It is the
        // only way to write a type this library has no parser for — and the way
        // the zone writer emits anything whose type-specific spelling would not
        // read back as the same bytes. Accepted for known types too (§5 permits
        // it), because refusing it would make a written zone unreadable by the
        // program that wrote it.
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

        let rdata: RecordData = match record_type.as_str() {
            "A" => {
                let addr = rdata
                    .parse::<Ipv4Addr>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid A address {rdata:?}: {e}")))?;
                RecordData::from_parsed(&ParsedRecord::A(addr))
                    .map_err(|e| ZoneError::syntax(ln, format!("A record: {e}")))?
            }
            "AAAA" => {
                let addr = rdata
                    .parse::<Ipv6Addr>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid AAAA address {rdata:?}: {e}")))?;
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
                    return Err(ZoneError::syntax(ln, format!(
                        "MX record needs preference and exchange, got {:?}",
                        rdata
                    )));
                }
                let preference = mx_parts[0]
                    .parse::<u16>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid MX preference {:?}: {e}", mx_parts[0])))?;
                RecordData::from_parsed(&ParsedRecord::MX {
                    preference,
                    exchange: mx_parts[1..].join(" "),
                })
                .map_err(|e| ZoneError::syntax(ln, format!("MX record: {e}")))?
            }
            "TXT" => {
                // Every field after the type is one `<character-string>`
                // (RFC 1035 §3.3.14): `"a b" c` is two strings, `a b c` is
                // three, and the quotes are what says which. The 255-byte
                // ceiling is enforced by the encoder, for every caller.
                // The zone file speaks text; a character-string is octets.
                let strings: Vec<Vec<u8>> = tokens[idx..]
                    .iter()
                    .map(|t| t.as_bytes().to_vec())
                    .collect();
                if strings.is_empty() {
                    return Err(ZoneError::syntax(ln, "TXT record has no text"));
                }
                RecordData::from_parsed(&ParsedRecord::TXT(strings))
                    .map_err(|e| ZoneError::syntax(ln, format!("TXT record: {e}")))?
            }
            "PTR" => RecordData::from_parsed(&ParsedRecord::PTR(rdata))
                .map_err(|e| ZoneError::syntax(ln, format!("PTR record: {e}")))?,
            "SOA" => {
                let soa_parts: Vec<&str> = rdata.split_whitespace().collect();
                if soa_parts.len() < 7 {
                    return Err(ZoneError::syntax(ln, format!(
                        "SOA record needs 7 fields, got {}",
                        soa_parts.len()
                    )));
                }
                let serial = soa_parts[2]
                    .parse::<u32>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid SOA serial {:?}: {e}", soa_parts[2])))?;
                let refresh = soa_parts[3]
                    .parse::<i32>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid SOA refresh {:?}: {e}", soa_parts[3])))?;
                let retry = soa_parts[4]
                    .parse::<i32>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid SOA retry {:?}: {e}", soa_parts[4])))?;
                let expire = soa_parts[5]
                    .parse::<i32>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid SOA expire {:?}: {e}", soa_parts[5])))?;
                let minimum = soa_parts[6]
                    .parse::<u32>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid SOA minimum {:?}: {e}", soa_parts[6])))?;
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
                let key_parts = &parts[idx..];
                if key_parts.len() < 4 {
                    return Err(ZoneError::syntax(ln, format!(
                        "DNSKEY record needs 4 fields, got {}",
                        key_parts.len()
                    )));
                }
                let flags = key_parts[0]
                    .parse::<u16>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid DNSKEY flags {:?}: {e}", key_parts[0])))?;
                let protocol = key_parts[1]
                    .parse::<u8>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid DNSKEY protocol {:?}: {e}", key_parts[1])))?;
                let algorithm = key_parts[2]
                    .parse::<u8>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid DNSKEY algorithm {:?}: {e}", key_parts[2])))?;
                let b64_key = key_parts[3..].join("");
                let public_key =
                    base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &b64_key)
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
                let ds_parts = &parts[idx..];
                if ds_parts.len() < 4 {
                    return Err(ZoneError::syntax(ln, format!(
                        "DS record needs 4 fields, got {}",
                        ds_parts.len()
                    )));
                }
                let key_tag = ds_parts[0]
                    .parse::<u16>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid DS key tag {:?}: {e}", ds_parts[0])))?;
                let algorithm = ds_parts[1]
                    .parse::<u8>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid DS algorithm {:?}: {e}", ds_parts[1])))?;
                let digest_type = ds_parts[2]
                    .parse::<u8>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid DS digest type {:?}: {e}", ds_parts[2])))?;
                let hex_digest = ds_parts[3..].join("");
                let digest = parse_hex(&hex_digest)
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
                let rrsig_parts = &parts[idx..];
                if rrsig_parts.len() < 9 {
                    return Err(ZoneError::syntax(ln, format!(
                        "RRSIG record needs 9 fields, got {}",
                        rrsig_parts.len()
                    )));
                }
                let type_covered = crate::utils::record_type_name_to_code(rrsig_parts[0])
                    .ok_or_else(|| {
                        ZoneError::syntax(ln, format!("unknown RRSIG type covered {:?}", rrsig_parts[0]))
                    })?;
                let algorithm = rrsig_parts[1]
                    .parse::<u8>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid RRSIG algorithm {:?}: {e}", rrsig_parts[1])))?;
                let labels = rrsig_parts[2]
                    .parse::<u8>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid RRSIG labels {:?}: {e}", rrsig_parts[2])))?;
                let original_ttl = rrsig_parts[3]
                    .parse::<u32>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid RRSIG original TTL {:?}: {e}", rrsig_parts[3])))?;
                let expiration = parse_dnssec_time(rrsig_parts[4])
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid RRSIG expiration {:?}: {e}", rrsig_parts[4])))?;
                let inception = parse_dnssec_time(rrsig_parts[5])
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid RRSIG inception {:?}: {e}", rrsig_parts[5])))?;
                let key_tag = rrsig_parts[6]
                    .parse::<u16>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid RRSIG key tag {:?}: {e}", rrsig_parts[6])))?;
                let signer_name = rrsig_parts[7].to_string();
                let b64_sig = rrsig_parts[8..].join("");
                let signature =
                    base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &b64_sig)
                        .map_err(|e| ZoneError::syntax(ln, format!("invalid RRSIG base64 signature: {e}")))?;
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
                let nsec_parts = &parts[idx..];
                if nsec_parts.len() < 2 {
                    return Err(ZoneError::syntax(ln, format!(
                        "NSEC record needs next domain and at least one type, got {}",
                        nsec_parts.len()
                    )));
                }
                let next_domain_name = nsec_parts[0].to_string();
                let type_names: Vec<String> =
                    nsec_parts[1..].iter().map(|s| s.to_string()).collect();
                let type_bitmap = construct_type_bitmap(&type_names)
                    .map_err(|e| ZoneError::syntax(ln, format!("NSEC record: {e}")))?;
                RecordData::from_parsed(&ParsedRecord::NSEC {
                    next_domain_name,
                    type_bitmap,
                })
                .map_err(|e| ZoneError::syntax(ln, format!("NSEC record: {e}")))?
            }
            "NSEC3" => {
                let nsec3_parts = &parts[idx..];
                if nsec3_parts.len() < 5 {
                    return Err(ZoneError::syntax(ln, format!(
                        "NSEC3 record needs at least 5 fields, got {}",
                        nsec3_parts.len()
                    )));
                }
                let hash_algorithm = nsec3_parts[0]
                    .parse::<u8>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid NSEC3 hash algorithm {:?}: {e}", nsec3_parts[0])))?;
                let flags = nsec3_parts[1]
                    .parse::<u8>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid NSEC3 flags {:?}: {e}", nsec3_parts[1])))?;
                let iterations = nsec3_parts[2]
                    .parse::<u16>()
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid NSEC3 iterations {:?}: {e}", nsec3_parts[2])))?;
                let salt_str = nsec3_parts[3];
                let salt = if salt_str == "-" {
                    Vec::new()
                } else {
                    parse_hex(salt_str)
                        .map_err(|e| ZoneError::syntax(ln, format!("invalid NSEC3 salt {:?}: {e}", salt_str)))?
                };
                let next_hashed_owner = parse_base32_hex(nsec3_parts[4])
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid NSEC3 next hashed owner {:?}: {e}", nsec3_parts[4])))?;
                let type_names: Vec<String> =
                    nsec3_parts[5..].iter().map(|s| s.to_string()).collect();
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
                return Err(ZoneError::syntax(ln, format!("unsupported record type {other:?}")));
            }
        };

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

    #[test]
    fn test_malformed_rdata_surfaces_error() {
        // A bad IPv4 address must fail the load, not be silently dropped.
        let zone_content = "www IN A 999.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(
            matches!(err, ZoneError::Syntax { line: 1, .. }),
            "the line number is a field, not a prefix: {err:?}"
        );
        assert!(err.to_string().contains("A address"), "error should name the failure: {err}");
    }

    #[test]
    fn test_unsupported_record_type_surfaces_error() {
        let zone_content = "www IN WKS 192.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(err.to_string().contains("unsupported record type"), "got: {err}");
    }

    #[test]
    fn test_fully_qualified_owner_name_parses() {
        // An FQDN owner ends in '.', which the old lookahead mistook for a
        // TTL/class token and then tried to read as a record type.
        let zone = parse_zone_file("www.example.com. IN A 192.0.2.5\n", "example.com.").unwrap();
        assert_eq!(zone.records.len(), 1);
        assert_eq!(zone.records[0].name, "www.example.com.");
        assert_eq!(zone.query("www.example.com.", 1).len(), 1);
    }

    #[test]
    fn test_owner_name_may_contain_digits() {
        let zone = parse_zone_file("www2 IN A 192.0.2.6\n", "example.com.").unwrap();
        assert_eq!(zone.records[0].name, "www2.example.com.", "stored absolute");
        assert_eq!(zone.query("www2.example.com.", 1).len(), 1);
    }

    #[test]
    fn test_owner_name_may_look_like_a_record_type() {
        // "ns IN A ..." is a host called `ns`, not an NS record — position, not
        // the token's spelling, decides what the first field is.
        let zone = parse_zone_file("ns IN A 192.0.2.7\n", "example.com.").unwrap();
        assert_eq!(zone.records[0].name, "ns.example.com.");
        assert_eq!(zone.query("ns.example.com.", 1).len(), 1, "should be an A record");
    }

    #[test]
    fn test_indented_line_inherits_previous_owner() {
        // RFC 1035 §5.1: a line beginning with whitespace reuses the last owner.
        let zone_content = "www IN A 192.0.2.1\n    IN A 192.0.2.2\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        assert_eq!(zone.records.len(), 2);
        assert_eq!(zone.records[1].name, "www.example.com.");
        assert_eq!(zone.query("www.example.com.", 1).len(), 2);
    }

    #[test]
    fn test_indented_line_without_a_previous_owner_errors() {
        let err = parse_zone_file("    IN A 192.0.2.1\n", "example.com.").unwrap_err();
        assert!(err.to_string().contains("omits its owner name"), "got: {err}");
    }

    #[test]
    fn test_apex_and_relative_names_match_absolute_queries() {
        let zone_content = "@ IN A 192.0.2.1\nwww IN A 192.0.2.2\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        assert_eq!(zone.query("example.com.", 1).len(), 1, "@ should match the apex");
        assert_eq!(zone.query("www.example.com.", 1).len(), 1);
        // DNS names are case-insensitive (RFC 4343).
        assert_eq!(zone.query("WWW.Example.COM.", 1).len(), 1);
    }

    // -----------------------------------------------------------------
    // The index: wildcards, existence, and staying in step with the origin
    // -----------------------------------------------------------------

    #[test]
    fn test_wildcard_answers_a_name_that_does_not_exist() {
        let zone = parse_zone_file("* IN A 192.0.2.9\n", "example.com.").unwrap();
        assert_eq!(zone.query("anything.example.com.", 1).len(), 1);
        // And it does not answer for the name it hangs off.
        assert!(zone.query("example.com.", 1).is_empty());
    }

    /// RFC 4592 §3.3.2's own worked example, which is the authority on how deep
    /// synthesis reaches: `*.example.` answers `_telnet._tcp.host1.example.` —
    /// three labels below the wildcard's parent.
    ///
    /// This asserted the opposite for a long time, citing §2.1.1. That section
    /// is about `*` being special only as the **leftmost label of a zone-file
    /// owner name**; it says nothing about matching depth. The test agreed with
    /// the code because both were written from the same misreading, which is why
    /// a green suite was no evidence here.
    #[test]
    fn test_a_wildcard_synthesizes_at_any_depth() {
        let zone = parse_zone_file("* IN A 192.0.2.9\n", "example.").unwrap();
        assert_eq!(
            zone.query("_telnet._tcp.host1.example.", 1).len(),
            1,
            "RFC 4592 §3.3.2 synthesizes this from *.example."
        );
        assert_eq!(zone.query("a.b.example.", 1).len(), 1);
        assert!(zone.name_exists("a.b.c.d.e.f.example."));
        assert_eq!(
            zone.name_kind("a.b.example."),
            NameKind::Wildcard("*.example.".to_string())
        );
    }

    /// An existing name ends the search, whether or not it has the type asked
    /// for and whether or not it has records at all (RFC 4592 §4.4).
    ///
    /// The wildcard at the apex must not reach past `b.example.com.` — which
    /// exists as an empty non-terminal — to answer for names under it. Only
    /// `*.b.example.com.` could do that, and there isn't one.
    #[test]
    fn test_an_existing_name_stops_the_wildcard_search() {
        let zone =
            parse_zone_file("* IN A 192.0.2.9\ndeep.a.b IN TXT \"x\"\n", "example.com.").unwrap();

        assert_eq!(zone.query("other.example.com.", 1).len(), 1, "nothing above it");
        assert!(
            zone.query("x.a.b.example.com.", 1).is_empty(),
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
        // The apex NS RRset is not a cut — the zone starts there, it does not
        // stop there.
        assert_eq!(zone.delegation_for("www.example.com."), None);
        // A query at the cut itself is still a referral.
        assert_eq!(
            zone.delegation_for("sub.example.com.").as_deref(),
            Some("sub.example.com.")
        );
    }

    /// An empty non-terminal exists (RFC 4592 §2.2.2): a name with descendants
    /// and no records of its own is NODATA, not NXDOMAIN.
    ///
    /// The consequence of getting this wrong is that the zone takes *its own
    /// data* offline — an RFC 8020 resolver caches the NXDOMAIN for `a.b` and
    /// extends it to everything below, `deep.a.b` included.
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
            assert!(zone.query(ent, 16).is_empty(), "{ent}: NODATA, no records");
        }

        assert_eq!(zone.name_kind("deep.a.b.example.com."), NameKind::Exact);
        assert_eq!(zone.name_kind("gone.a.b.example.com."), NameKind::NotFound);
        // Names outside the zone are not conjured into existence by the walk.
        assert_eq!(zone.name_kind("com."), NameKind::NotFound);
        assert_eq!(zone.name_kind("elsewhere.test."), NameKind::NotFound);
    }

    /// RFC 1034 §3.6.2: a CNAME is the only type at its owner, and the load
    /// fails rather than the server picking one at query time.
    #[test]
    fn test_a_cname_may_not_share_its_owner_name() {
        let err = parse_zone_file(
            "www IN CNAME host.example.com.\nwww IN A 192.0.2.1\n",
            "example.com.",
        )
        .unwrap_err();
        assert!(err.to_string().contains("CNAME"), "the error should say why: {err}");

        // RRSIG, NSEC and NSEC3 are the exceptions — they describe the name
        // rather than name it (RFC 4035 §2.5), and a signed zone with a CNAME in
        // it has all three.
        parse_zone_file(
            "www IN CNAME host.example.com.\n\
             www IN NSEC x.example.com. CNAME RRSIG NSEC\n",
            "example.com.",
        )
        .expect("a signed CNAME is not a conflict");
    }

    /// An existing name shadows the wildcard completely — including for types it
    /// does not carry (RFC 1034 §4.3.3, RFC 4592 §2.2.1). The linear scan this
    /// replaced returned both the exact and the wildcard record for one query,
    /// merging two owners' data into a single RRset.
    #[test]
    fn test_an_existing_name_shadows_the_wildcard() {
        let zone =
            parse_zone_file("* IN A 192.0.2.9\nwww IN AAAA 2001:db8::1\n", "example.com.").unwrap();

        let a = zone.query("www.example.com.", 1);
        assert!(
            a.is_empty(),
            "www exists, so the wildcard must not answer for it: {a:?}"
        );
        assert_eq!(zone.query("www.example.com.", 28).len(), 1, "its own AAAA");
        // Any other name still gets the wildcard.
        assert_eq!(zone.query("other.example.com.", 1).len(), 1);
    }

    #[test]
    fn test_name_exists_distinguishes_nodata_from_nxdomain() {
        let zone =
            parse_zone_file("* IN A 192.0.2.9\nwww IN AAAA 2001:db8::1\n", "example.com.").unwrap();

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

    /// The index encodes what `matches_query` defines, so the two must agree.
    /// They are separate code, and a divergence would show up as a zone serving
    /// NXDOMAIN for records it holds.
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

    /// `$ORIGIN` applies to the lines *below* it (RFC 1035 §5.1): a name already
    /// read keeps the origin it was read under. Owner names are resolved as they
    /// are parsed, which is what makes that true — and what `$INCLUDE`'s optional
    /// origin needs in order to mean anything.
    #[test]
    fn test_origin_applies_only_to_the_lines_below_it() {
        let zone_content = "www IN A 192.0.2.1\n$ORIGIN other.test.\nmail IN A 192.0.2.2\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();

        assert_eq!(
            zone.query("www.example.com.", 1).len(),
            1,
            "www was read before the $ORIGIN and stays where it was"
        );
        assert_eq!(zone.query("mail.other.test.", 1).len(), 1);
        assert!(zone.query("www.other.test.", 1).is_empty());
    }

    /// The `set_origin` re-key, which is what the index needs when a *relative*
    /// name is added through the API and the origin moves afterwards. The parser
    /// resolves names as it goes, so this is the path that still depends on it.
    #[test]
    fn test_set_origin_rekeys_relative_records() {
        let mut zone = Zone::new("example.com.".to_string());
        zone.add_record(ZoneRecord {
            name: "www".to_string(),
            ttl: 3600,
            class: 1,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });
        assert_eq!(zone.query("www.example.com.", 1).len(), 1);

        zone.set_origin("other.test.");
        assert_eq!(
            zone.query("www.other.test.", 1).len(),
            1,
            "a relative name follows the origin it is relative to"
        );
        assert!(zone.query("www.example.com.", 1).is_empty());
    }

    /// A record added after the zone is built has to be reachable, or the index
    /// is a cache that silently hides data.
    #[test]
    fn test_records_added_later_are_indexed() {
        let mut zone = Zone::new("example.com.".to_string());
        assert!(zone.query("www.example.com.", 1).is_empty());

        zone.add_record(ZoneRecord {
            name: "www".to_string(),
            ttl: 3600,
            class: 1,
            rdata: RecordData::from_parsed(&ParsedRecord::A(Ipv4Addr::new(192, 0, 2, 1))).unwrap(),
        });
        assert_eq!(zone.query("www.example.com.", 1).len(), 1);
        assert!(zone.name_exists("www.example.com."));
    }

    // -----------------------------------------------------------------
    // Logical lines: parentheses, comments and quoted strings
    // -----------------------------------------------------------------

    /// The SOA as every zone file in the world actually writes it. This failed
    /// the load outright before: the first line ended after `(`, so the record
    /// had no type and the numbers on the lines below were parsed as owner names.
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
        let soa = zone.query("example.com.", crate::utils::record_types::SOA);
        assert_eq!(soa.len(), 1, "the SOA should have loaded");
        match soa[0].rdata.parse().unwrap() {
            ParsedRecord::SOA {
                mname,
                serial,
                minimum,
                ..
            } => {
                assert_eq!(mname, "ns1.example.com.");
                assert_eq!(serial, 2021010101, "comments inside the group are not data");
                assert_eq!(minimum, 86400);
            }
            other => panic!("expected an SOA, got {other:?}"),
        }
        // The record after the group is still read as its own line.
        assert_eq!(zone.query("example.com.", 1).len(), 1);
    }

    /// A `;` inside a quoted string is data, not a comment. SPF and DKIM records
    /// are mostly semicolons, and cutting the line at the first one silently
    /// shortened them.
    #[test]
    fn test_semicolon_inside_a_quoted_string_survives() {
        let zone_content = "txt IN TXT \"v=spf1 include:example.net; -all\"\n";
        let zone = parse_zone_file(zone_content, "example.com.").unwrap();
        let txt = zone.query("txt.example.com.", crate::utils::record_types::TXT);
        assert_eq!(txt.len(), 1);
        match txt[0].rdata.parse().unwrap() {
            ParsedRecord::TXT(strings) => {
                assert_eq!(strings.len(), 1, "one quoted string is one character-string");
                assert_eq!(strings[0], b"v=spf1 include:example.net; -all");
            }
            other => panic!("expected TXT, got {other:?}"),
        }
    }

    /// Quotes are what says where one `<character-string>` ends and the next
    /// begins (RFC 1035 §3.3.14), which whitespace splitting alone cannot
    /// express: `"a b"` is one string and `a b` is two.
    #[test]
    fn test_txt_character_strings_are_split_on_quotes_not_whitespace() {
        let strings_of = |line: &str| -> Vec<Vec<u8>> {
            let zone = parse_zone_file(line, "example.com.").unwrap();
            match zone
                .query("txt.example.com.", crate::utils::record_types::TXT)[0]
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

    /// A string too long for its one-byte length is the zone's mistake, and has
    /// to fail the load — splitting it silently would change what it says.
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

    // -----------------------------------------------------------------
    // $INCLUDE
    // -----------------------------------------------------------------

    /// A scratch directory that removes itself, for the include tests — they
    /// need real files, because resolving `$INCLUDE` is the thing being tested.
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
        assert_eq!(zone.query("mail.example.com.", 1).len(), 1, "from the include");
        assert_eq!(zone.query("www.example.com.", 1).len(), 1);
        assert_eq!(
            zone.query("ftp.example.com.", 1).len(),
            1,
            "parsing continues after the include"
        );
        assert_eq!(zone.query("example.com.", 1).len(), 1);
    }

    /// `$INCLUDE file origin` reads the file under that origin — and RFC 1035
    /// §5.1 is explicit that it does not change the origin of the file doing the
    /// including, however the included file plays with it.
    #[test]
    fn test_include_origin_applies_to_the_included_file_only() {
        let dir = ScratchDir::new("include-origin");
        dir.write("sub.inc", "$ORIGIN deeper.example.com.\nns IN A 192.0.2.30\n");
        let main = dir.write(
            "example.com.zone",
            "$INCLUDE sub.inc sub.example.com.\nafter IN A 192.0.2.31\n",
        );

        let zone = parse_zone_file_at(&main, "example.com.").unwrap();
        assert_eq!(
            zone.query("ns.deeper.example.com.", 1).len(),
            1,
            "the included file's own $ORIGIN applies inside it"
        );
        assert_eq!(
            zone.query("after.example.com.", 1).len(),
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
        assert!(err.to_string().contains("nope.inc"), "the error should name the file: {err}");
        assert!(
            matches!(err, ZoneError::Syntax { line: 1, .. }),
            "the line number is a field, not a prefix: {err:?}"
        );
    }

    /// A file that includes itself would recurse until the stack ran out.
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

    // -----------------------------------------------------------------
    // RFC 3597: types with no mnemonic, and rdata written as raw bytes
    // -----------------------------------------------------------------

    #[test]
    fn test_generic_rdata_carries_a_type_we_do_not_parse() {
        let zone = parse_zone_file("odd IN TYPE1234 \\# 4 DEADBEEF\n", "example.com.").unwrap();
        let record = zone.query("odd.example.com.", 1234);
        assert_eq!(record.len(), 1);
        assert_eq!(&*record[0].rdata.rdata, &[0xde, 0xad, 0xbe, 0xef]);
    }

    /// RFC 3597 §5 permits the generic form for a known type too, and the writer
    /// uses it whenever the type-specific spelling would not read back exactly.
    #[test]
    fn test_generic_rdata_is_accepted_for_a_known_type() {
        let zone = parse_zone_file("www IN A \\# 4 C0000201\n", "example.com.").unwrap();
        assert!(matches!(
            zone.query("www.example.com.", record_types::A)[0].rdata.parse(),
            Ok(ParsedRecord::A(addr)) if addr == Ipv4Addr::new(192, 0, 2, 1)
        ));
    }

    #[test]
    fn test_generic_rdata_of_zero_length() {
        let zone = parse_zone_file("empty IN TYPE4321 \\# 0\n", "example.com.").unwrap();
        assert!(zone.query("empty.example.com.", 4321)[0].rdata.rdata.is_empty());
    }

    /// The length is checked rather than trusted — it is exactly the field a
    /// hand-edit gets wrong, and believing it would store the wrong bytes.
    #[test]
    fn test_generic_rdata_length_must_match_the_digits() {
        let err = parse_zone_file("odd IN TYPE1234 \\# 8 DEADBEEF\n", "example.com.").unwrap_err();
        assert!(err.to_string().contains("says 8 bytes but carries 4"), "got: {err}");
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

    /// A type bitmap may list a type this library has no name for; `TYPEnnn` is
    /// how RFC 3597 §5 says to write it, and dropping it would turn a signed
    /// NSEC into a different signed NSEC.
    #[test]
    fn test_nsec_bitmap_accepts_a_generic_type_name() {
        let zone = parse_zone_file(
            "@ IN NSEC www.example.com. A TYPE1234\n",
            "example.com.",
        )
        .unwrap();
        let record = zone.query("example.com.", record_types::NSEC)[0];
        let ParsedRecord::NSEC { type_bitmap, .. } = record.rdata.parse().unwrap() else {
            panic!("not an NSEC");
        };
        assert!(crate::dnssec_denial::bitmap_has_type(&type_bitmap, record_types::A));
        assert!(crate::dnssec_denial::bitmap_has_type(&type_bitmap, 1234));
    }

    #[test]
    fn test_nsec_bitmap_rejects_a_name_that_is_no_type_at_all() {
        let err = parse_zone_file("@ IN NSEC www.example.com. A NOTATYPE\n", "example.com.")
            .unwrap_err();
        assert!(err.to_string().contains("unknown record type"), "got: {err}");
    }

    // -----------------------------------------------------------------
    // DNSSEC timestamps
    // -----------------------------------------------------------------

    /// The formatter and the parser are inverses, or a rewritten RRSIG would
    /// claim a different validity period from the one it was signed with.
    #[test]
    fn test_dnssec_time_round_trips() {
        for (epoch, text) in [
            (0u32, "19700101000000"),
            (1, "19700101000001"),
            (951_868_800, "20000301000000"),   // the day after a leap day
            (1_078_012_800, "20040229000000"), // a leap day itself
            (1_609_459_199, "20201231235959"),
            (2_147_483_647, "20380119031407"),
            (u32::MAX, "21060207062815"),
        ] {
            assert_eq!(format_dnssec_time(epoch), text, "formatting {epoch}");
            assert_eq!(parse_dnssec_time(text), Ok(epoch), "parsing {text}");
        }
    }

    #[test]
    fn test_malformed_ttl_directive_surfaces_error() {
        let zone_content = "$TTL notanumber\nwww IN A 192.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(err.to_string().contains("$TTL"), "got: {err}");
    }
}
