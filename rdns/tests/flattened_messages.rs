//! A `\` line continuation lost from an operator-facing string literal
//! (`TODO.md` #60).
//!
//! `"a \` + newline + indentation + `b"` is `"a b"` — Rust eats the newline and
//! every leading space after it. Join those two source lines without putting
//! the backslash back and the indentation becomes the message: `rdnsd
//! --transfer-tls-cert` with no `--transfer-tls-ca` printed fourteen spaces
//! mid-sentence. Nothing in the toolchain catches it — `cargo fmt` does not
//! touch string literals (`CLAUDE.md` §12) and clippy has no lint for it — and
//! these are `bail!` and `serving_error!` strings, which is to say the
//! sentences an operator reads when something is wrong.
//!
//! A test rather than a probe because a count taken once is a count that rots:
//! every one of the 19 found on 2026-09-14 was introduced by an ordinary edit
//! to a message, and nothing stops the next one.
//!
//! **Two exclusions, and they are what make this quiet enough to be a test.**
//! A literal written across source lines is using the `\` idiom already, so it
//! is correct by construction. A literal containing a `\n` escape is rendered
//! output — a table, a zone file, `--help` text — where a run of spaces is the
//! alignment and not a mistake.
//!
//! The threshold is what the tree measures, not a guess. Runs inside a
//! single-source-line literal came in two populations with nothing between
//! them: 2 to 5 spaces, every one a `{:>9}` table or a zone-file fixture, and
//! 14 to 34, every one a flattened sentence. Six is the middle of that gap. A
//! legitimate table that needs six aligned spaces *and* fits on one source line
//! *and* carries no `\n` would be a false positive; none exists here, and the
//! fix for one would be to give it a `\n` or break the line.

use std::fs;
use std::path::Path;

/// Minimum run of spaces between two non-space characters to report.
const THRESHOLD: usize = 6;

/// One string literal, as the scanner found it.
struct Literal {
    line: usize,
    /// True when the literal's closing quote is on a later source line, which
    /// means it is using `\` continuation (or embedded newlines) already.
    multiline: bool,
    text: String,
}

/// Every non-raw string literal in `src`, skipping comments, char literals and
/// raw strings.
///
/// A real lexer would be `syn` plus `proc-macro2` in dev-dependencies to find a
/// run of spaces; this is the state machine that costs nothing. It errs toward
/// *missing* a literal rather than inventing one: an unterminated string runs
/// to the end of the file and reports whatever it swallowed as one literal,
/// which cannot compile anyway.
fn literals(src: &str) -> Vec<Literal> {
    let b: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1usize;
    while i < b.len() {
        let rest: String = b[i..(i + 4).min(b.len())].iter().collect();
        if b[i] == '\n' {
            line += 1;
            i += 1;
        } else if rest.starts_with("//") {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if rest.starts_with("/*") {
            let mut depth = 1;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    if b[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
        } else if let Some(skip) = raw_string(&b, i, &mut line) {
            i = skip;
        } else if b[i] == '\'' {
            // A char literal, or a lifetime; either way nothing to scan.
            if b.get(i + 1) == Some(&'\\') {
                i += 4;
            } else if b.get(i + 2) == Some(&'\'') {
                i += 3;
            } else {
                i += 1;
            }
        } else if b[i] == '"' {
            let start_line = line;
            let mut text = String::new();
            let mut j = i + 1;
            while j < b.len() {
                if b[j] == '\\' {
                    if b.get(j + 1) == Some(&'\n') {
                        line += 1;
                    }
                    text.push(b[j]);
                    if let Some(c) = b.get(j + 1) {
                        text.push(*c);
                    }
                    j += 2;
                    continue;
                }
                if b[j] == '"' {
                    break;
                }
                if b[j] == '\n' {
                    line += 1;
                }
                text.push(b[j]);
                j += 1;
            }
            out.push(Literal {
                line: start_line,
                multiline: line != start_line,
                text,
            });
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// If a raw string starts at `i`, its end offset, counting its newlines into
/// `line`. Raw strings cannot carry a `\` continuation, so nothing inside one
/// is this test's business.
fn raw_string(b: &[char], i: usize, line: &mut usize) -> Option<usize> {
    let mut j = i;
    if b.get(j) == Some(&'b') {
        j += 1;
    }
    if b.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let hashes = {
        let start = j;
        while b.get(j) == Some(&'#') {
            j += 1;
        }
        j - start
    };
    if b.get(j) != Some(&'"') {
        return None;
    }
    j += 1;
    while j < b.len() {
        if b[j] == '\n' {
            *line += 1;
        }
        if b[j] == '"' && b[j + 1..].iter().take(hashes).all(|c| *c == '#') {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    Some(b.len())
}

/// The longest run of spaces between two non-space characters.
fn widest_internal_run(text: &str) -> usize {
    let mut widest = 0;
    let mut run = 0;
    let mut seen_before = false;
    for c in text.chars() {
        if c == ' ' {
            run += 1;
        } else {
            if seen_before && run > widest {
                widest = run;
            }
            run = 0;
            seen_before = true;
        }
    }
    widest
}

#[test]
fn no_operator_message_carries_a_flattened_line_continuation() {
    // CARGO_MANIFEST_DIR is this crate; the check is workspace-wide.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate has a workspace root above it")
        .to_path_buf();
    let sources = rdns::testutil::rust_sources(&root);
    assert!(
        sources.len() > 20,
        "found {} source files under {}: the walk is wrong, not the tree",
        sources.len(),
        root.display()
    );

    let mut flattened = Vec::new();
    for path in &sources {
        let Ok(src) = fs::read_to_string(path) else {
            continue;
        };
        for lit in literals(&src) {
            if lit.multiline || lit.text.contains("\\n") {
                continue;
            }
            let run = widest_internal_run(&lit.text);
            if run >= THRESHOLD {
                let shown: String = lit.text.chars().take(90).collect();
                flattened.push(format!(
                    "{}:{}: {run} spaces inside {shown:?}",
                    path.strip_prefix(&root).unwrap_or(path).display(),
                    lit.line,
                ));
            }
        }
    }

    assert!(
        flattened.is_empty(),
        "a `\\` line continuation was lost from {} message(s); put it back so the \
         indentation stops being part of the sentence (`TODO.md` #60):\n{}",
        flattened.len(),
        flattened.join("\n")
    );
}
