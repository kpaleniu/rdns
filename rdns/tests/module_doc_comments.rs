//! A `///` above a `mod` declaration that no longer describes that module
//! (`TODO.md` #89).
//!
//! `e26a479` moved `rdns/src/testutil.rs` into `rdns-core` and left its
//! `/// Scratch directories, for tests only.` behind, where it attached to the
//! `pub mod tls_identity;` on the next line and rendered on the crate index.
//! `cargo doc` cannot catch it, because a wrong doc comment is a valid one.
//!
//! #20 hit the same hazard twice in one sitting and wrote the remedy as prose
//! — "after any move, grep the seam for an orphaned `///`" — so nobody ran it.
//! This is that grep, as a test.
//!
//! **What "describes it" is taken to mean.** One content word shared between
//! the `///` and either the module's name or the first paragraph of its own
//! `//!`, after dropping stopwords and a trailing plural. That is weak on
//! purpose: the two comments are written to say *different* things, so
//! anything stricter flags prose that is right. The tree's eight declarations
//! measure 4, 1, 4, 5, 2, 1 and 4 words of overlap and one of zero — the
//! ones at 1 are `mod eviction`, which agrees only through its own name, and
//! `mod dispatch`, on "request". A threshold of two would flag both.
//!
//! A module the resolver cannot find is a failure rather than a skip: a check
//! that reports nothing because it read nothing is the shape of §4.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Words that carry no subject, so sharing one means nothing.
const STOP: &[&str] = &[
    "the", "and", "are", "for", "from", "its", "not", "one", "only", "that", "this", "than",
    "then", "there", "these", "they", "was", "were", "what", "when", "where", "which", "with",
    "into", "over", "under", "own", "out", "each", "their", "shared", "here", "has", "have", "how",
    "why", "can", "cannot", "does", "did", "but", "all", "any", "because",
];

/// Content words, lowercased, with a crude plural stripped so `record` and
/// `records` are one word.
fn words(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .map(|w| w.to_ascii_lowercase())
        .filter(|w| w.len() >= 3 && !STOP.contains(&w.as_str()))
        .map(|w| match () {
            _ if w.len() > 4 && w.ends_with("es") => w[..w.len() - 2].to_string(),
            _ if w.len() > 3 && w.ends_with('s') => w[..w.len() - 1].to_string(),
            _ => w,
        })
        .collect()
}

/// `foo` from `mod foo;`, `pub mod foo;` or `pub(crate) mod foo;`.
///
/// An inline `mod foo {` is not one: its contents are right there, and it
/// cannot be left behind by a move.
fn declared_module(line: &str) -> Option<&str> {
    let line = line.trim();
    let line = line.strip_prefix("pub").map_or(line, |rest| {
        rest.strip_prefix(char::is_whitespace)
            .or_else(|| rest.split_once(')').map(|(_, after)| after))
            .unwrap_or(rest)
            .trim_start()
    });
    let name = line.strip_prefix("mod ")?.strip_suffix(';')?.trim();
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        .then_some(name)
}

/// One `mod` declaration that carries a `///`.
struct Declared {
    line: usize,
    name: String,
    doc: String,
}

fn declarations(src: &str) -> Vec<Declared> {
    let mut out = Vec::new();
    let mut doc = String::new();
    for (i, line) in src.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(text) = trimmed.strip_prefix("///") {
            // `////` is an ordinary comment, not a doc comment.
            if !text.starts_with('/') {
                doc.push(' ');
                doc.push_str(text.trim());
                continue;
            }
        }
        // An attribute between the comment and the item it documents.
        if trimmed.starts_with("#[") {
            continue;
        }
        if let Some(name) = declared_module(trimmed) {
            if !doc.trim().is_empty() {
                out.push(Declared {
                    line: i + 1,
                    name: name.to_string(),
                    doc: doc.trim().to_string(),
                });
            }
        }
        doc.clear();
    }
    out
}

/// Where `mod name;` in `declaring` looks for its file.
fn module_file(declaring: &Path, name: &str) -> Option<PathBuf> {
    let parent = declaring.parent()?;
    let dir = match declaring.file_name()?.to_str()? {
        "lib.rs" | "main.rs" | "mod.rs" => parent.to_path_buf(),
        _ => parent.join(declaring.file_stem()?),
    };
    [
        dir.join(format!("{name}.rs")),
        dir.join(name).join("mod.rs"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}

/// The first paragraph of a module's own `//!`.
fn module_header(src: &str) -> String {
    let mut out = String::new();
    for line in src.lines() {
        let trimmed = line.trim();
        match trimmed.strip_prefix("//!") {
            Some(text) if text.trim().is_empty() => break,
            Some(text) => {
                out.push(' ');
                out.push_str(text.trim());
            }
            None if out.is_empty() => continue,
            None => break,
        }
    }
    out.trim().to_string()
}

#[test]
fn no_mod_declaration_carries_another_modules_doc_comment() {
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

    let mut checked = 0usize;
    let mut orphaned = Vec::new();
    for path in &sources {
        let Ok(src) = fs::read_to_string(path) else {
            continue;
        };
        for decl in declarations(&src) {
            let shown = path.strip_prefix(&root).unwrap_or(path).display();
            let file = module_file(path, &decl.name).unwrap_or_else(|| {
                panic!(
                    "{shown}:{}: cannot find the file for `mod {}`: the resolver is wrong, \
                     not the tree",
                    decl.line, decl.name
                )
            });
            let header = module_header(&fs::read_to_string(&file).expect("read the module"));
            checked += 1;
            let describes = words(&decl.name.replace('_', " "));
            let shares = words(&decl.doc)
                .intersection(&(&describes | &words(&header)))
                .count();
            if shares == 0 {
                orphaned.push(format!(
                    "{shown}:{}: `/// {}` shares no word with `mod {}` or its own header \
                     ({header:?})",
                    decl.line, decl.doc, decl.name
                ));
            }
        }
    }

    assert!(
        checked >= 5,
        "only {checked} `mod` declarations carry a `///`: the scanner is wrong, not the tree"
    );
    assert!(
        orphaned.is_empty(),
        "{} `mod` declaration(s) carry a doc comment that describes something else — usually \
         one left behind by a move (`TODO.md` #89):\n{}",
        orphaned.len(),
        orphaned.join("\n")
    );
}
