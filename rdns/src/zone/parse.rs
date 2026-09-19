//! The zone *file*: RFC 1035 §5 presentation format in, a [`super::Zone`] out.
//!
//! The membership rule is the text. Everything here is about what an operator
//! wrote — logical lines and their parentheses, `$TTL`/`$ORIGIN`/`$INCLUDE`,
//! tokenizing with quotes and escapes, an owner name omitted because the
//! previous record's carries over, and names made absolute against the origin.
//! What a record *means* once its fields are split is [`super::rdata`]'s, and
//! what a whole zone must not contain is [`super::checks`]'.
//!
//! A name here is text and so carries RFC 1035 §5.1's escapes: `absolutize` goes
//! through [`crate::Name`]'s own text decoder rather than splitting on `.`, since
//! a second decoder disagreed with it about `\.` (`TODO.md` #35, #36).

use super::checks::{check_cname_exclusivity, check_dname_rules};
use super::rdata::{parse_generic_rdata, rdata_from_fields};
use super::{Zone, ZoneRecordRef};
use crate::error::{WireError, ZoneError};
use crate::{Class, Name, NameRef, Ttl};
use rdns_core::dname::MAX_NAME_LEN;
use std::borrow::Cow;
use std::path::{Path, PathBuf};

/// A zone-file owner name in absolute form, resolved against `origin`: `@` and
/// the empty name are the origin itself, a name ending in `.` is already
/// absolute, and anything else is relative to it.
///
/// Only the relative case allocates, and it is the zone parser's; a name off
/// the wire is absolute, and a query takes four of these.
pub(super) fn absolutize(name: &str, origin: NameRef<'_>) -> Result<Name, WireError> {
    let mut buf = [0u8; MAX_NAME_LEN];
    Ok(Name::absolutized_in(name, origin, &mut buf)?.to_owned())
}

/// What a name that is not one reads as, wherever a zone file spells one.
fn not_a_name(name: &str, ln: usize, e: WireError) -> ZoneError {
    ZoneError::syntax(ln, format!("the name {name:?} is not a name: {e}"))
}

/// The same, as a zone error that names the line.
///
/// Every name in a zone file goes through here — owner names *and* the names
/// inside RDATA, which RFC 1035 §5.1 makes relative to the origin in exactly
/// the same way ("domain names in the RDATA section... are also relative").
pub(super) fn name_at(name: &str, origin: NameRef<'_>, ln: usize) -> Result<Name, ZoneError> {
    absolutize(name, origin).map_err(|e| not_a_name(name, ln, e))
}

/// One record or directive, assembled from as many physical lines as it spans.
struct LogicalLine<'a> {
    /// The physical line it started on, so an error still points at the file.
    line_no: usize,
    /// Comments stripped, parentheses removed, continuation lines joined.
    ///
    /// Borrowed from the file when there was nothing to strip and nothing to
    /// join, which is every line of a blocklist: a `String` per line was 140 ms
    /// of a million-rule load.
    text: Cow<'a, str>,
    /// The first physical line began with whitespace, so the record inherits the
    /// previous owner name (RFC 1035 §5.1).
    omits_owner: bool,
}

/// The five characters that make a physical line anything but its own text:
/// a comment, a quoted string, an escape, or a parenthesized group.
fn needs_assembling(raw: &str) -> bool {
    raw.bytes()
        .any(|b| matches!(b, b';' | b'"' | b'\\' | b'(' | b')'))
}

/// Split a zone file into logical lines (RFC 1035 §5.1).
///
/// Not `content.lines()`: parentheses group data across a line boundary, and `;`
/// begins a comment except inside a quoted string.
fn logical_lines(content: &str) -> Result<Vec<LogicalLine<'_>>, ZoneError> {
    let mut out: Vec<LogicalLine<'_>> = Vec::new();
    let mut pending: Option<LogicalLine<'_>> = None;
    let mut depth = 0usize;

    for (idx, raw) in content.lines().enumerate() {
        let ln = idx + 1;
        // Nothing to strip, nothing open: the line is its own text. The loop
        // below would copy it character by character to the same result.
        if depth == 0 && pending.is_none() && !needs_assembling(raw) {
            let text = raw.trim();
            if text.is_empty() {
                continue;
            }
            out.push(LogicalLine {
                line_no: ln,
                omits_owner: raw.starts_with(|c: char| c.is_whitespace()),
                text: Cow::Borrowed(text),
            });
            continue;
        }
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
                    let joined = open.text.to_mut();
                    joined.push(' ');
                    joined.push_str(more);
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
                    text: Cow::Owned(text.trim().to_string()),
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
///
/// Borrowed unless a quote or an escape means the token is not a contiguous
/// run of the input: a `String` per token was 240 ms of a million-rule load.
fn tokenize_into<'a>(text: &'a str, out: &mut Vec<Cow<'a, str>>) {
    out.clear();
    if !text.bytes().any(|b| matches!(b, b'"' | b'\\')) {
        out.extend(text.split_whitespace().map(Cow::Borrowed));
        return;
    }
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
            // Kept, not consumed: RFC 1035 §5.1's escapes are resolved by the
            // value that needs them (`codecs::char_string_decode`), because only
            // that value knows whether `\\120` is three characters or one
            // octet. Eating it here made `\\DDD` unspellable and silently
            // turned a quoted `"a\\.b"` into two labels.
            '\\' => {
                current.push(c);
                escaped = true;
                started = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                started = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if started {
                    out.push(Cow::Owned(std::mem::take(&mut current)));
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
        out.push(Cow::Owned(current));
    }
}

/// `text` upper-cased into `buf`, or `None` if it does not fit or is not ASCII.
fn upper_into<'b>(text: &str, buf: &'b mut [u8; 32]) -> Option<&'b str> {
    if !text.is_ascii() || text.len() > buf.len() {
        return None;
    }
    let n = text.len();
    for (out, &b) in buf[..n].iter_mut().zip(text.as_bytes()) {
        *out = b.to_ascii_uppercase();
    }
    std::str::from_utf8(&buf[..n]).ok()
}

/// How deep `$INCLUDE` may nest. A file that includes itself is otherwise a
/// loop with nothing to stop it.
const MAX_INCLUDE_DEPTH: usize = 8;

/// What the parser carries from one line to the next.
struct ParseState {
    /// The origin relative owner names are resolved against — `$ORIGIN`, or the
    /// origin an `$INCLUDE` named for the file being read.
    origin: Name,
    /// The default TTL for records that do not state one (`$TTL`).
    ttl: Ttl,
    /// The last owner name seen, for lines that omit theirs: wire octets in a
    /// buffer the parser refills, `owner_len` 0 for none yet. A `Name` here was
    /// an allocation per record for a value the zone copies into its arena
    /// anyway (`TODO.md` #72).
    owner: [u8; MAX_NAME_LEN],
    owner_len: usize,
}

impl ParseState {
    /// The owner name in force, or `None` before the file's first record.
    fn owner(&self) -> Option<NameRef<'_>> {
        (self.owner_len > 0)
            .then(|| NameRef::from_wire_slice(&self.owner[..self.owner_len]).expect("a name in"))
    }
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
    parse_zone_text_at(&content, origin, path)
}

/// [`parse_zone_file_at`] for a caller that has already read the file.
///
/// `path` is where the content came from, for `$INCLUDE` alone. A loader that
/// digests the bytes to decide whether to parse them at all would otherwise read
/// the file twice (`TODO.md` #64f).
pub fn parse_zone_text_at(content: &str, origin: &str, path: &Path) -> Result<Zone, ZoneError> {
    parse_zone_file_with_base(content, origin, path.parent())
}

fn parse_zone_file_with_base(
    content: &str,
    origin: &str,
    base_dir: Option<&Path>,
) -> Result<Zone, ZoneError> {
    let apex = Name::from_presentation(origin)
        .map_err(|e| ZoneError::invalid(format!("the origin {origin:?} is not a name: {e}")))?;
    let mut zone = Zone::new(apex.clone());
    let mut state = ParseState {
        origin: apex,
        ttl: Ttl::from_secs(3600),
        owner: [0u8; MAX_NAME_LEN],
        owner_len: 0,
    };
    let mut moved_apex = None;
    parse_into(&mut zone, content, &mut state, base_dir, 0, &mut moved_apex)?;
    // The one rebuild a file with a mid-zone `$ORIGIN` owes, paid once.
    if let Some(apex) = moved_apex {
        zone.set_origin(apex);
    }
    check_cname_exclusivity(&zone)?;
    check_dname_rules(&zone)?;
    Ok(zone)
}

/// `moved_apex` is the last top-level `$ORIGIN` that arrived after a record,
/// which the caller owes [`Zone::set_origin`] once the file is read. Only
/// `depth == 0` ever writes it; an `$INCLUDE` cannot move the apex.
fn parse_into(
    zone: &mut Zone,
    content: &str,
    state: &mut ParseState,
    base_dir: Option<&Path>,
    depth: usize,
    moved_apex: &mut Option<Name>,
) -> Result<(), ZoneError> {
    let lines = logical_lines(content)?;
    // An upper bound on the records this file adds, and the only cheap one
    // there is: directives and blank lines are the slack.
    zone.reserve(lines.len());
    // Refilled per line rather than rebuilt, which is one `Vec` for the file
    // and not one per record. It could not be until #72a: there was a second
    // vector of `&str` borrowed from this one, so this one could not be
    // touched while it lived.
    let mut tokens: Vec<Cow<'_, str>> = Vec::new();
    for logical in &lines {
        let ln = logical.line_no;
        tokenize_into(&logical.text, &mut tokens);
        let Some(first) = tokens.first().map(Cow::as_ref) else {
            continue;
        };

        if first.eq_ignore_ascii_case("$ORIGIN") {
            if let Some(new_origin) = tokens.get(1) {
                state.origin = name_at(new_origin, state.origin.as_ref(), ln)?;
                // Only the top-level file may move the apex: RFC 1035 §5.1 keeps
                // an include's origin to the included file.
                if depth == 0 {
                    if zone.records().is_empty() {
                        // Where a zone file's `$ORIGIN` usually is, and the
                        // rebuild is over nothing: take it now and owe nothing.
                        zone.set_origin(state.origin.clone());
                        *moved_apex = None;
                    } else {
                        // `set_origin` rebuilds the index over every record so
                        // far, so one `$ORIGIN` per section was
                        // O(sections x records) — 13.6 s for 16 000 records
                        // with one before each (`TODO.md` #62c). Only the last
                        // decides the apex and the rebuild is a clean sweep, so
                        // the caller does it once at the end instead.
                        *moved_apex = Some(state.origin.clone());
                    }
                }
            }
            continue;
        }

        if first.eq_ignore_ascii_case("$TTL") {
            if let Some(value) = tokens.get(1) {
                state.ttl = value
                    .parse::<u32>()
                    .map(Ttl::from_secs)
                    .map_err(|e| ZoneError::syntax(ln, format!("invalid $TTL {value:?}: {e}")))?;
            }
            continue;
        }

        // `$INCLUDE <file> [origin]`
        if first.eq_ignore_ascii_case("$INCLUDE") {
            let Some(file) = tokens.get(1).map(Cow::as_ref) else {
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
                origin: match tokens.get(2) {
                    Some(o) => name_at(o, state.origin.as_ref(), ln)?,
                    None => state.origin.clone(),
                },
                ttl: state.ttl,
                owner: [0u8; MAX_NAME_LEN],
                owner_len: 0,
            };
            parse_into(
                zone,
                &included,
                &mut inner,
                path.parent(),
                depth + 1,
                moved_apex,
            )?;
            continue;
        }

        // `[name] [ttl] [class] type rdata...` — position tells the owner name
        // from a TTL/class/type, not the token's shape: `ns IN A …` is a host
        // called `ns`, not an NS record.
        //
        // Resolved against the origin in force here, which is what makes
        // `$ORIGIN` apply to the lines below it only.
        let mut idx = 0;
        if !logical.omits_owner {
            // RFC 1035 §5.1's escapes are resolved here, `a\.b` included —
            // one label of three octets. This was refused at load until names
            // became wire form, because presentation storage with `.` as the
            // separator could not tell that name from two labels (D-1).
            let mut buf = [0u8; MAX_NAME_LEN];
            let len = Name::absolutized_in(first, state.origin.as_ref(), &mut buf)
                .map_err(|e| not_a_name(first, ln, e))?
                .as_wire()
                .len();
            state.owner[..len].copy_from_slice(&buf[..len]);
            state.owner_len = len;
            idx += 1;
        }
        if state.owner_len == 0 {
            return Err(ZoneError::syntax(
                ln,
                "record omits its owner name but no previous record supplies one",
            ));
        }

        let mut ttl = state.ttl;
        // Always IN: the branch below refuses any other class outright. A zone
        // is single-class by construction, which is what makes the class-blind
        // index correct rather than merely untested. A CH zone needs its own
        // apex and its own place in the zone map.
        let mut class = Class::IN;

        while idx < tokens.len() {
            if let Ok(parsed_ttl) = tokens[idx].parse::<i32>() {
                ttl = Ttl::from_wire(parsed_ttl);
                state.ttl = ttl;
                idx += 1;
            } else if tokens[idx].eq_ignore_ascii_case("IN")
                || tokens[idx].eq_ignore_ascii_case("CH")
                || tokens[idx].eq_ignore_ascii_case("HS")
            {
                if !tokens[idx].eq_ignore_ascii_case("IN") {
                    return Err(ZoneError::syntax(
                        ln,
                        format!(
                            "class {} is not served: a zone here is IN, and a record of another \
                             class in it would answer IN queries with a class it never matched",
                            tokens[idx].to_uppercase()
                        ),
                    ));
                }
                class = Class::IN;
                idx += 1;
            } else {
                break;
            }
        }

        if idx >= tokens.len() {
            continue;
        }

        // Upper-cased on the stack: a `String` per record for a token that is
        // almost always one or two octets. A token too long or not ASCII is no
        // type name either way, so it goes on unchanged to the same error.
        let mut type_buf = [0u8; 32];
        let record_type: &str = upper_into(&tokens[idx], &mut type_buf).unwrap_or(&tokens[idx]);
        idx += 1;
        // One field is the whole RDATA text, which is most records; joining a
        // one-element slice copies it for nothing.
        let rdata: Cow<'_, str> = match &tokens[idx..] {
            [one] => Cow::Borrowed(one.as_ref()),
            rest => Cow::Owned(rest.join(" ")),
        };

        // RFC 3597 §5's generic form, `\# <length> <hex>`: the only way to write
        // a type with no parser here, and what the zone writer emits when the
        // type-specific spelling would not read back as the same bytes. §5
        // permits it for known types too, so it is accepted for them.
        if tokens.get(idx).is_some_and(|token| token == "\\#") {
            let rdata = parse_generic_rdata(record_type, &tokens[idx + 1..])
                .map_err(|e| ZoneError::syntax(ln, format!("{record_type} record: {e}")))?;
            zone.add(ZoneRecordRef {
                name: state.owner().expect("an owner name"),
                ttl,
                class,
                rdata: rdata.as_ref(),
            });
            continue;
        }

        let parsed = rdata_from_fields(
            record_type,
            rdata,
            &tokens[idx..],
            state.origin.as_ref(),
            ln,
        )?;

        // Encoded into the zone's own arena. The `RecordData` this used to
        // build was a heap allocation and a free per record for octets the
        // zone copies either way (`TODO.md` #72b), and the line number is what
        // the encode's own error has no way to carry.
        zone.add_parsed(state.owner().expect("an owner name"), ttl, class, &parsed)
            .map_err(|e| ZoneError::syntax(ln, format!("{record_type} record: {e}")))?;
    }

    Ok(())
}
