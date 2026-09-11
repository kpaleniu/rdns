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
use super::{Zone, ZoneRecord};
use crate::error::{WireError, ZoneError};
use crate::{Class, Name, NameRef, RecordData, Ttl};
use std::path::{Path, PathBuf};

/// A zone-file owner name in absolute form, resolved against `origin`: `@` and
/// the empty name are the origin itself, a name ending in `.` is already
/// absolute, and anything else is relative to it.
///
/// Only the relative case allocates, and it is the zone parser's; a name off
/// the wire is absolute, and a query takes four of these.
pub(super) fn absolutize(name: &str, origin: NameRef<'_>) -> Result<Name, WireError> {
    let name = name.trim();
    if name.is_empty() || name == "@" {
        Ok(origin.to_owned())
    } else if name.ends_with('.') {
        Name::from_presentation(name)
    } else {
        Name::relative_to(name, origin)
    }
}

/// The same, as a zone error that names the line.
///
/// Every name in a zone file goes through here — owner names *and* the names
/// inside RDATA, which RFC 1035 §5.1 makes relative to the origin in exactly
/// the same way ("domain names in the RDATA section... are also relative").
pub(super) fn name_at(name: &str, origin: NameRef<'_>, ln: usize) -> Result<Name, ZoneError> {
    absolutize(name, origin)
        .map_err(|e| ZoneError::syntax(ln, format!("the name {name:?} is not a name: {e}")))
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
    origin: Name,
    /// The default TTL for records that do not state one (`$TTL`).
    ttl: Ttl,
    /// The last owner name seen, for lines that omit theirs.
    owner: Option<Name>,
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
    let apex = Name::from_presentation(origin)
        .map_err(|e| ZoneError::invalid(format!("the origin {origin:?} is not a name: {e}")))?;
    let mut zone = Zone::new(apex.clone());
    let mut state = ParseState {
        origin: apex,
        ttl: Ttl::from_secs(3600),
        owner: None,
    };
    parse_into(&mut zone, content, &mut state, base_dir, 0)?;
    check_cname_exclusivity(&zone)?;
    check_dname_rules(&zone)?;
    Ok(zone)
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
                state.origin = name_at(new_origin, state.origin.as_ref(), ln)?;
                // Only the top-level file may move the apex: RFC 1035 §5.1 keeps
                // an include's origin to the included file.
                if depth == 0 {
                    zone.set_origin(state.origin.clone());
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
                origin: match parts.get(2) {
                    Some(o) => name_at(o, state.origin.as_ref(), ln)?,
                    None => state.origin.clone(),
                },
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
            // RFC 1035 §5.1's escapes are resolved here, `a\.b` included —
            // one label of three octets. This was refused at load until names
            // became wire form, because presentation storage with `.` as the
            // separator could not tell that name from two labels (D-1).
            let name = name_at(first, state.origin.as_ref(), ln)?;
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

        let rdata: RecordData = rdata_from_fields(
            &record_type,
            rdata,
            &parts[idx..],
            &tokens[idx..],
            state.origin.as_ref(),
            ln,
        )?;

        zone.add_record(ZoneRecord {
            name: record_name,
            ttl,
            class,
            rdata,
        });
    }

    Ok(())
}
