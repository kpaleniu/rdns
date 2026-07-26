use crate::{ParsedRecord, RecordData};
use crate::utils::record_type_code;
use std::collections::HashMap;
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
}

impl Zone {
    /// Create a new zone with the given origin (e.g., "example.com.")
    pub fn new(origin: String) -> Self {
        Zone {
            origin: absolute(&origin),
            records: Vec::new(),
            index: HashMap::new(),
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
        self.index.entry(key).or_default().push(self.records.len());
        self.records.push(record);
    }

    /// Query records by name and type.
    ///
    /// A wildcard is consulted only when the queried name has no records of its
    /// own: an existing name shadows the wildcard entirely, types it does not
    /// carry included (RFC 1034 §4.3.3, RFC 4592 §2.2.1). The linear scan this
    /// replaced returned the exact *and* the wildcard records together, merging
    /// two owners' data into one RRset.
    pub fn query(&self, name: &str, qtype: u16) -> Vec<&ZoneRecord> {
        let key = self.lookup_key(name);
        if let Some(at_name) = self.index.get(&key) {
            return self.of_type(at_name, qtype);
        }
        match wildcard_for(&key).and_then(|w| self.index.get(&w)) {
            Some(at_wildcard) => self.of_type(at_wildcard, qtype),
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

    /// Whether the zone holds anything at `name` — by that name or through a
    /// wildcard. This is the NXDOMAIN question: a name that exists with no
    /// record of the queried type is NODATA, which is a different answer.
    pub fn name_exists(&self, name: &str) -> bool {
        let key = self.lookup_key(name);
        self.index.contains_key(&key)
            || wildcard_for(&key).is_some_and(|w| self.index.contains_key(&w))
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
        for (position, key) in keys.into_iter().enumerate() {
            self.index.entry(key).or_default().push(position);
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
        wildcard_for(&query_name).is_some_and(|w| w == record_name)
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

/// The wildcard name that could answer for `name`: its first label replaced by
/// `*`. A wildcard covers one label and only one (RFC 4592 §2.1.1) — nothing
/// deeper — so this single lookup is the whole of wildcard matching.
///
/// `None` only for a name with no labels at all.
fn wildcard_for(name: &str) -> Option<String> {
    let (_first_label, rest) = name.split_once('.')?;
    Some(format!("*.{rest}"))
}

/// A name with its trailing dot.
fn absolute(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

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

fn parse_dnssec_time(time_str: &str) -> Result<u32, String> {
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
        
        let is_leap = |y| (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        let days_in_month = |m, y| match m {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 => if is_leap(y) { 29 } else { 28 },
            _ => 0,
        };
        
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

fn construct_type_bitmap(types: &[String]) -> Vec<u8> {
    let mut codes = Vec::new();
    for t in types {
        if let Some(code) = crate::utils::record_type_name_to_code(t) {
            codes.push(code);
        }
    }
    codes.sort();
    codes.dedup();
    
    let mut blocks: std::collections::BTreeMap<u8, Vec<u8>> = std::collections::BTreeMap::new();
    for code in codes {
        let block_num = (code / 256) as u8;
        let block_offset = (code % 256) as u8;
        let byte_offset = (block_offset / 8) as usize;
        let bit_offset = block_offset % 8;
        
        let bitmap = blocks.entry(block_num).or_insert_with(|| vec![0u8; 32]);
        bitmap[byte_offset] |= 1 << (7 - bit_offset);
    }
    
    let mut result = Vec::new();
    for (block_num, bitmap) in blocks {
        let mut len = 32;
        while len > 0 && bitmap[len - 1] == 0 {
            len -= 1;
        }
        if len > 0 {
            result.push(block_num);
            result.push(len as u8);
            result.extend_from_slice(&bitmap[..len]);
        }
    }
    result
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
fn logical_lines(content: &str) -> Result<Vec<LogicalLine>, String> {
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
                        .ok_or_else(|| format!("line {ln}: unmatched ')'"))?;
                    text.push(' ');
                }
                _ => text.push(c),
            }
        }
        if quoted {
            return Err(format!("line {ln}: unterminated quoted string"));
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
        return Err(format!(
            "line {}: '(' is never closed before the end of the file",
            open.line_no
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
pub fn parse_zone_file(content: &str, origin: &str) -> Result<Zone, String> {
    parse_zone_file_with_base(content, origin, None)
}

/// Parse the zone file at `path`, resolving `$INCLUDE` relative to its directory.
pub fn parse_zone_file_at(path: &Path, origin: &str) -> Result<Zone, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    parse_zone_file_with_base(&content, origin, path.parent())
}

fn parse_zone_file_with_base(
    content: &str,
    origin: &str,
    base_dir: Option<&Path>,
) -> Result<Zone, String> {
    let mut zone = Zone::new(origin.to_string());
    let mut state = ParseState {
        origin: absolute(origin),
        ttl: 3600,
        owner: None,
    };
    parse_into(&mut zone, content, &mut state, base_dir, 0)?;
    Ok(zone)
}

/// Read `content` into `zone`. Recurses for `$INCLUDE`, hence `depth`.
fn parse_into(
    zone: &mut Zone,
    content: &str,
    state: &mut ParseState,
    base_dir: Option<&Path>,
    depth: usize,
) -> Result<(), String> {
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
                    .map_err(|e| format!("line {ln}: invalid $TTL {value:?}: {e}"))?;
            }
            continue;
        }

        // Handle $INCLUDE directive: `$INCLUDE <file> [origin]`
        if first.eq_ignore_ascii_case("$INCLUDE") {
            let Some(&file) = parts.get(1) else {
                return Err(format!("line {ln}: $INCLUDE needs a file name"));
            };
            if depth + 1 >= MAX_INCLUDE_DEPTH {
                return Err(format!(
                    "line {ln}: $INCLUDE nested more than {MAX_INCLUDE_DEPTH} deep — a cycle?"
                ));
            }
            let path = match base_dir {
                Some(dir) => dir.join(file),
                None => PathBuf::from(file),
            };
            let included = std::fs::read_to_string(&path)
                .map_err(|e| format!("line {ln}: $INCLUDE {}: {e}", path.display()))?;

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
                format!("line {ln}: record omits its owner name but no previous record supplies one")
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

        let rdata: RecordData = match record_type.as_str() {
            "A" => {
                let addr = rdata
                    .parse::<Ipv4Addr>()
                    .map_err(|e| format!("line {ln}: invalid A address {rdata:?}: {e}"))?;
                RecordData::from_parsed(&ParsedRecord::A(addr))
                    .map_err(|e| format!("line {ln}: A record: {e}"))?
            }
            "AAAA" => {
                let addr = rdata
                    .parse::<Ipv6Addr>()
                    .map_err(|e| format!("line {ln}: invalid AAAA address {rdata:?}: {e}"))?;
                RecordData::from_parsed(&ParsedRecord::AAAA(addr))
                    .map_err(|e| format!("line {ln}: AAAA record: {e}"))?
            }
            "NS" => RecordData::from_parsed(&ParsedRecord::NS(rdata))
                .map_err(|e| format!("line {ln}: NS record: {e}"))?,
            "CNAME" => RecordData::from_parsed(&ParsedRecord::CNAME(rdata))
                .map_err(|e| format!("line {ln}: CNAME record: {e}"))?,
            "MX" => {
                let mx_parts: Vec<&str> = rdata.split_whitespace().collect();
                if mx_parts.len() < 2 {
                    return Err(format!(
                        "line {ln}: MX record needs preference and exchange, got {:?}",
                        rdata
                    ));
                }
                let preference = mx_parts[0]
                    .parse::<u16>()
                    .map_err(|e| format!("line {ln}: invalid MX preference {:?}: {e}", mx_parts[0]))?;
                RecordData::from_parsed(&ParsedRecord::MX {
                    preference,
                    exchange: mx_parts[1..].join(" "),
                })
                .map_err(|e| format!("line {ln}: MX record: {e}"))?
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
                    return Err(format!("line {ln}: TXT record has no text"));
                }
                RecordData::from_parsed(&ParsedRecord::TXT(strings))
                    .map_err(|e| format!("line {ln}: TXT record: {e}"))?
            }
            "PTR" => RecordData::from_parsed(&ParsedRecord::PTR(rdata))
                .map_err(|e| format!("line {ln}: PTR record: {e}"))?,
            "SOA" => {
                let soa_parts: Vec<&str> = rdata.split_whitespace().collect();
                if soa_parts.len() < 7 {
                    return Err(format!(
                        "line {ln}: SOA record needs 7 fields, got {}",
                        soa_parts.len()
                    ));
                }
                let serial = soa_parts[2]
                    .parse::<u32>()
                    .map_err(|e| format!("line {ln}: invalid SOA serial {:?}: {e}", soa_parts[2]))?;
                let refresh = soa_parts[3]
                    .parse::<i32>()
                    .map_err(|e| format!("line {ln}: invalid SOA refresh {:?}: {e}", soa_parts[3]))?;
                let retry = soa_parts[4]
                    .parse::<i32>()
                    .map_err(|e| format!("line {ln}: invalid SOA retry {:?}: {e}", soa_parts[4]))?;
                let expire = soa_parts[5]
                    .parse::<i32>()
                    .map_err(|e| format!("line {ln}: invalid SOA expire {:?}: {e}", soa_parts[5]))?;
                let minimum = soa_parts[6]
                    .parse::<u32>()
                    .map_err(|e| format!("line {ln}: invalid SOA minimum {:?}: {e}", soa_parts[6]))?;
                RecordData::from_parsed(&ParsedRecord::SOA {
                    mname: soa_parts[0].to_string(),
                    rname: soa_parts[1].to_string(),
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
                .map_err(|e| format!("line {ln}: SOA record: {e}"))?
            }
            "DNSKEY" => {
                let key_parts = &parts[idx..];
                if key_parts.len() < 4 {
                    return Err(format!(
                        "line {ln}: DNSKEY record needs 4 fields, got {}",
                        key_parts.len()
                    ));
                }
                let flags = key_parts[0]
                    .parse::<u16>()
                    .map_err(|e| format!("line {ln}: invalid DNSKEY flags {:?}: {e}", key_parts[0]))?;
                let protocol = key_parts[1]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid DNSKEY protocol {:?}: {e}", key_parts[1]))?;
                let algorithm = key_parts[2]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid DNSKEY algorithm {:?}: {e}", key_parts[2]))?;
                let b64_key = key_parts[3..].join("");
                let public_key =
                    base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &b64_key)
                        .map_err(|e| format!("line {ln}: invalid DNSKEY base64 key: {e}"))?;
                RecordData::from_parsed(&ParsedRecord::DNSKEY {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                })
                .map_err(|e| format!("line {ln}: DNSKEY record: {e}"))?
            }
            "DS" => {
                let ds_parts = &parts[idx..];
                if ds_parts.len() < 4 {
                    return Err(format!(
                        "line {ln}: DS record needs 4 fields, got {}",
                        ds_parts.len()
                    ));
                }
                let key_tag = ds_parts[0]
                    .parse::<u16>()
                    .map_err(|e| format!("line {ln}: invalid DS key tag {:?}: {e}", ds_parts[0]))?;
                let algorithm = ds_parts[1]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid DS algorithm {:?}: {e}", ds_parts[1]))?;
                let digest_type = ds_parts[2]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid DS digest type {:?}: {e}", ds_parts[2]))?;
                let hex_digest = ds_parts[3..].join("");
                let digest = parse_hex(&hex_digest)
                    .map_err(|e| format!("line {ln}: invalid DS digest: {e}"))?;
                RecordData::from_parsed(&ParsedRecord::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                })
                .map_err(|e| format!("line {ln}: DS record: {e}"))?
            }
            "RRSIG" => {
                let rrsig_parts = &parts[idx..];
                if rrsig_parts.len() < 9 {
                    return Err(format!(
                        "line {ln}: RRSIG record needs 9 fields, got {}",
                        rrsig_parts.len()
                    ));
                }
                let type_covered = crate::utils::record_type_name_to_code(rrsig_parts[0])
                    .ok_or_else(|| {
                        format!("line {ln}: unknown RRSIG type covered {:?}", rrsig_parts[0])
                    })?;
                let algorithm = rrsig_parts[1]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid RRSIG algorithm {:?}: {e}", rrsig_parts[1]))?;
                let labels = rrsig_parts[2]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid RRSIG labels {:?}: {e}", rrsig_parts[2]))?;
                let original_ttl = rrsig_parts[3]
                    .parse::<u32>()
                    .map_err(|e| format!("line {ln}: invalid RRSIG original TTL {:?}: {e}", rrsig_parts[3]))?;
                let expiration = parse_dnssec_time(rrsig_parts[4])
                    .map_err(|e| format!("line {ln}: invalid RRSIG expiration {:?}: {e}", rrsig_parts[4]))?;
                let inception = parse_dnssec_time(rrsig_parts[5])
                    .map_err(|e| format!("line {ln}: invalid RRSIG inception {:?}: {e}", rrsig_parts[5]))?;
                let key_tag = rrsig_parts[6]
                    .parse::<u16>()
                    .map_err(|e| format!("line {ln}: invalid RRSIG key tag {:?}: {e}", rrsig_parts[6]))?;
                let signer_name = rrsig_parts[7].to_string();
                let b64_sig = rrsig_parts[8..].join("");
                let signature =
                    base64::Engine::decode(&base64::prelude::BASE64_STANDARD, &b64_sig)
                        .map_err(|e| format!("line {ln}: invalid RRSIG base64 signature: {e}"))?;
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
                .map_err(|e| format!("line {ln}: RRSIG record: {e}"))?
            }
            "NSEC" => {
                let nsec_parts = &parts[idx..];
                if nsec_parts.len() < 2 {
                    return Err(format!(
                        "line {ln}: NSEC record needs next domain and at least one type, got {}",
                        nsec_parts.len()
                    ));
                }
                let next_domain_name = nsec_parts[0].to_string();
                let type_names: Vec<String> =
                    nsec_parts[1..].iter().map(|s| s.to_string()).collect();
                let type_bitmap = construct_type_bitmap(&type_names);
                RecordData::from_parsed(&ParsedRecord::NSEC {
                    next_domain_name,
                    type_bitmap,
                })
                .map_err(|e| format!("line {ln}: NSEC record: {e}"))?
            }
            "NSEC3" => {
                let nsec3_parts = &parts[idx..];
                if nsec3_parts.len() < 5 {
                    return Err(format!(
                        "line {ln}: NSEC3 record needs at least 5 fields, got {}",
                        nsec3_parts.len()
                    ));
                }
                let hash_algorithm = nsec3_parts[0]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid NSEC3 hash algorithm {:?}: {e}", nsec3_parts[0]))?;
                let flags = nsec3_parts[1]
                    .parse::<u8>()
                    .map_err(|e| format!("line {ln}: invalid NSEC3 flags {:?}: {e}", nsec3_parts[1]))?;
                let iterations = nsec3_parts[2]
                    .parse::<u16>()
                    .map_err(|e| format!("line {ln}: invalid NSEC3 iterations {:?}: {e}", nsec3_parts[2]))?;
                let salt_str = nsec3_parts[3];
                let salt = if salt_str == "-" {
                    Vec::new()
                } else {
                    parse_hex(salt_str)
                        .map_err(|e| format!("line {ln}: invalid NSEC3 salt {:?}: {e}", salt_str))?
                };
                let next_hashed_owner = parse_base32_hex(nsec3_parts[4])
                    .map_err(|e| format!("line {ln}: invalid NSEC3 next hashed owner {:?}: {e}", nsec3_parts[4]))?;
                let type_names: Vec<String> =
                    nsec3_parts[5..].iter().map(|s| s.to_string()).collect();
                let type_bitmap = construct_type_bitmap(&type_names);
                RecordData::from_parsed(&ParsedRecord::NSEC3 {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                    next_hashed_owner,
                    type_bitmap,
                })
                .map_err(|e| format!("line {ln}: NSEC3 record: {e}"))?
            }
            other => {
                return Err(format!("line {ln}: unsupported record type {other:?}"));
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
        assert!(err.contains("line 1"), "error should carry line number: {err}");
        assert!(err.contains("A address"), "error should name the failure: {err}");
    }

    #[test]
    fn test_unsupported_record_type_surfaces_error() {
        let zone_content = "www IN WKS 192.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(err.contains("unsupported record type"), "got: {err}");
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
        assert!(err.contains("omits its owner name"), "got: {err}");
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
        // A wildcard covers one label and only one (RFC 4592 §2.1.1).
        assert!(zone.query("a.b.example.com.", 1).is_empty());
        // And it does not answer for the name it hangs off.
        assert!(zone.query("example.com.", 1).is_empty());
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
            !zone.name_exists("a.b.example.com."),
            "two labels down, past what the wildcard reaches"
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
        assert!(err.contains("255"), "got: {err}");
        assert!(err.contains("line 1"), "got: {err}");
    }

    #[test]
    fn test_unbalanced_parentheses_are_an_error() {
        let err = parse_zone_file("@ IN SOA ns1. admin. ( 1 2 3 4\n", "example.com.").unwrap_err();
        assert!(err.contains("never closed"), "got: {err}");
        assert!(err.contains("line 1"), "should point at the opening line: {err}");

        let err = parse_zone_file("@ IN A 192.0.2.1 )\n", "example.com.").unwrap_err();
        assert!(err.contains("unmatched"), "got: {err}");
    }

    #[test]
    fn test_unterminated_quote_is_an_error() {
        let err = parse_zone_file("txt IN TXT \"no closing quote\n", "example.com.").unwrap_err();
        assert!(err.contains("unterminated"), "got: {err}");
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
        assert!(err.contains("nope.inc"), "the error should name the file: {err}");
        assert!(err.contains("line 1"), "and the line: {err}");
    }

    /// A file that includes itself would recurse until the stack ran out.
    #[test]
    fn test_include_cycle_is_refused() {
        let dir = ScratchDir::new("include-cycle");
        let main = dir.write("example.com.zone", "$INCLUDE example.com.zone\n");
        let err = parse_zone_file_at(&main, "example.com.").unwrap_err();
        assert!(err.contains("cycle"), "got: {err}");
    }

    #[test]
    fn test_include_without_a_file_name_is_an_error() {
        let err = parse_zone_file("$INCLUDE\n", "example.com.").unwrap_err();
        assert!(err.contains("needs a file name"), "got: {err}");
    }

    #[test]
    fn test_malformed_ttl_directive_surfaces_error() {
        let zone_content = "$TTL notanumber\nwww IN A 192.0.2.1\n";
        let err = parse_zone_file(zone_content, "example.com.").unwrap_err();
        assert!(err.contains("$TTL"), "got: {err}");
    }
}
