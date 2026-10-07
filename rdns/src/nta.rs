//! Negative trust anchors (RFC 7646): a subtree the validator is told to treat
//! as unsigned, for a limited time, because its owner broke its DNSSEC.
//!
//! What the RFC fixes, and what this module therefore refuses to make
//! configurable:
//!
//! - §2.1: "An NTA MUST only be used for a limited duration", so every entry
//!   has an absolute `until`, and §4's "SHOULD NOT exceed a week" is a refusal
//!   at load. Absolute rather than a lifetime: a relative one would restart at
//!   every reload and never expire.
//! - §2.1: "Use of an NTA MUST NOT be automatic" — entries come from the
//!   operator's file and nowhere else.
//! - §1.1 and §2.1: names at and below the node are affected, nothing above
//!   it, and "Validation starts again if there is a positive trust anchor
//!   further down".
//! - §3: an NTA "placed at a node where there is a configured positive trust
//!   anchor MUST take precedence over that trust anchor".
//!
//! The set is data; the daemon owns the file, the expiry timer and the
//! recheck (`TODO.md` #176).

use std::sync::{Arc, PoisonError, RwLock};

use crate::dnssec_chain::TrustAnchors;
use crate::error::{ConfigError, ConfigResult};
use crate::{Name, NameRef};

/// RFC 7646 §4: "The lifetime SHOULD NOT exceed a week."
pub const MAX_LIFETIME_SECS: u64 = 7 * 86_400;

/// One anchor: the node, when it lapses, and whether the daemon may lift it
/// early once the zone validates again (§4's recheck).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nta {
    pub name: Name,
    /// Unix seconds. In force while `now < until`.
    pub until: u64,
    pub recheck: bool,
}

/// The anchors in force.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NegativeTrustAnchors {
    ntas: Vec<Nta>,
}

/// What a load said besides the set: lines skipped as expired, and anchors
/// that override a configured positive one. The caller logs them.
#[derive(Debug, Default)]
pub struct LoadNotes {
    pub warnings: Vec<String>,
}

impl NegativeTrustAnchors {
    /// Parse the file's text: one `NAME UNTIL [norecheck]` per line, `UNTIL`
    /// as an RRSIG writes a time (`YYYYMMDDHHmmSS`, UTC) or Unix seconds.
    /// Blank lines and `;` comments are skipped.
    ///
    /// All or nothing (`CLAUDE.md` §4): a line that does not parse, or one
    /// more than a week ahead of `now`, fails the file, and the caller keeps
    /// the set it had. A line already past is skipped with a warning — it is
    /// what the file will say for a while after it lapses, and refusing it
    /// would make a SIGHUP fail on a file nobody edited.
    pub fn parse(
        text: &str,
        now: u64,
        anchors: Option<&TrustAnchors>,
    ) -> ConfigResult<(NegativeTrustAnchors, LoadNotes)> {
        let mut ntas: Vec<Nta> = Vec::new();
        let mut notes = LoadNotes::default();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.split(';').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let at = |what: String| ConfigError::new(format!("line {}: {what}", index + 1));
            let mut fields = line.split_whitespace();
            let (Some(name), Some(until)) = (fields.next(), fields.next()) else {
                return Err(at(format!("{line:?} is not `NAME UNTIL [norecheck]`")));
            };
            let recheck = match fields.next() {
                None => true,
                Some(flag) if flag.eq_ignore_ascii_case("norecheck") => false,
                Some(other) => return Err(at(format!("{other:?} is not `norecheck`"))),
            };
            if let Some(extra) = fields.next() {
                return Err(at(format!("{extra:?} after the line's end")));
            }
            let name = Name::from_presentation(name).map_err(|e| at(format!("{name:?}: {e}")))?;
            let until = u64::from(
                rdns_present::dnssec_time::parse_dnssec_time(until)
                    .map_err(|e| at(format!("{until:?}: {e}")))?,
            );
            if until <= now {
                notes.warnings.push(format!(
                    "line {}: the negative trust anchor for {name} lapsed at {until}; skipped",
                    index + 1
                ));
                continue;
            }
            if until.saturating_sub(now) > MAX_LIFETIME_SECS {
                return Err(at(format!(
                    "{name} until {until} is more than a week ahead; RFC 7646 §4 says an \
                     NTA's lifetime SHOULD NOT exceed one"
                )));
            }
            if ntas.iter().any(|n| n.name == name) {
                return Err(at(format!("{name} has a negative trust anchor already")));
            }
            if anchors.is_some_and(|a| a.all().iter().any(|ds| ds.owner == name)) {
                notes.warnings.push(format!(
                    "the negative trust anchor for {name} overrides a configured trust \
                     anchor at the same name (RFC 7646 §3)"
                ));
            }
            ntas.push(Nta {
                name,
                until,
                recheck,
            });
        }
        Ok((NegativeTrustAnchors { ntas }, notes))
    }

    /// Read and parse `path`; see [`NegativeTrustAnchors::parse`].
    pub fn load(
        path: &std::path::Path,
        now: u64,
        anchors: Option<&TrustAnchors>,
    ) -> ConfigResult<(NegativeTrustAnchors, LoadNotes)> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            ConfigError::new(format!(
                "reading negative trust anchors {}: {e}",
                path.display()
            ))
        })?;
        Self::parse(&text, now, anchors)
            .map_err(|e| ConfigError::new(format!("{}: {e}", path.display())))
    }

    /// The anchor that exempts `qname` from validation at `now`, if one does.
    ///
    /// The most specific covering one, and none when a positive anchor lies
    /// strictly below it and above `qname` — validation resumes there (§1.1).
    /// A positive anchor *at* the node does not resume it (§3).
    pub fn covering(&self, qname: NameRef<'_>, now: u64, anchors: &TrustAnchors) -> Option<&Nta> {
        let nta = self
            .ntas
            .iter()
            .filter(|n| now < n.until && qname.is_at_or_under(n.name.as_ref()))
            .max_by_key(|n| n.name.as_ref().label_count())?;
        let resumes = anchors.all().iter().any(|ds| {
            ds.owner != nta.name
                && ds.owner.as_ref().is_at_or_under(nta.name.as_ref())
                && qname.is_at_or_under(ds.owner.as_ref())
        });
        (!resumes).then_some(nta)
    }

    /// Remove and return the anchors that have lapsed at `now`.
    pub fn expire(&mut self, now: u64) -> Vec<Nta> {
        let (gone, kept) = std::mem::take(&mut self.ntas)
            .into_iter()
            .partition(|n| n.until <= now);
        self.ntas = kept;
        gone
    }

    /// Remove the anchor at `name`, as a recheck that validated does.
    pub fn lift(&mut self, name: NameRef<'_>) -> Option<Nta> {
        let at = self.ntas.iter().position(|n| n.name == name)?;
        Some(self.ntas.remove(at))
    }

    /// When the next anchor lapses.
    pub fn next_expiry(&self) -> Option<u64> {
        self.ntas.iter().map(|n| n.until).min()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Nta> {
        self.ntas.iter()
    }

    pub fn len(&self) -> usize {
        self.ntas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ntas.is_empty()
    }
}

/// The set the resolver consults, replaceable while it runs: a SIGHUP reload,
/// an expiry and a recheck each swap or edit it.
///
/// `std::sync::RwLock` for [`crate::resolver::SharedAnchors`]'s reason: no
/// await is ever held across it.
#[derive(Debug, Clone, Default)]
pub struct SharedNtas(Arc<RwLock<NegativeTrustAnchors>>);

impl SharedNtas {
    pub fn new(ntas: NegativeTrustAnchors) -> Self {
        SharedNtas(Arc::new(RwLock::new(ntas)))
    }

    /// The anchor covering `qname`, cloned out from under the lock.
    pub fn covering(&self, qname: NameRef<'_>, now: u64, anchors: &TrustAnchors) -> Option<Nta> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .covering(qname, now, anchors)
            .cloned()
    }

    /// Run `f` on the set under the write lock.
    pub fn update<T>(&self, f: impl FnOnce(&mut NegativeTrustAnchors) -> T) -> T {
        f(&mut self.0.write().unwrap_or_else(PoisonError::into_inner))
    }

    /// Whether no anchor is configured: the answer path's way to skip the
    /// rest for nothing.
    pub fn is_empty(&self) -> bool {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }

    /// A copy of the set as it stands.
    pub fn snapshot(&self) -> NegativeTrustAnchors {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_records::nm;

    const NOW: u64 = 1_800_000_000;

    fn parse(text: &str) -> ConfigResult<NegativeTrustAnchors> {
        NegativeTrustAnchors::parse(text, NOW, None).map(|(set, _)| set)
    }

    fn anchors(owners: &[&str]) -> TrustAnchors {
        TrustAnchors::new(
            owners
                .iter()
                .map(|o| crate::dnssec::Ds {
                    owner: nm(o),
                    key_tag: 1,
                    algorithm: 13,
                    digest_type: 2,
                    digest: vec![0; 32],
                })
                .collect(),
        )
    }

    /// Unix seconds or an RRSIG's UTC form; NOW is 2027-01-15T08:00:00Z.
    #[test]
    fn a_file_reads_names_times_and_the_recheck_flag() {
        let set = parse(&format!(
            "; broken until they fix it\n\
             broken.example. {}\n\
             other.example. 20270116000000 norecheck\n",
            NOW + 3600
        ))
        .expect("parses");
        assert_eq!(set.len(), 2);
        let other = set.iter().find(|n| n.name == nm("other.example.")).unwrap();
        assert_eq!(other.until, NOW + 16 * 3600);
        assert!(!other.recheck);
        assert!(
            set.iter()
                .find(|n| n.name == nm("broken.example."))
                .unwrap()
                .recheck
        );
    }

    /// §4: more than a week ahead is refused, a lapsed line is skipped with a
    /// warning, and a malformed one fails the file.
    #[test]
    fn the_load_rules() {
        let eight_days = format!("x.example. {}\n", NOW + 8 * 86_400);
        assert!(parse(&eight_days).unwrap_err().to_string().contains("week"));

        let (set, notes) =
            NegativeTrustAnchors::parse(&format!("x.example. {}\n", NOW - 1), NOW, None)
                .expect("a lapsed line is not an error");
        assert!(set.is_empty());
        assert!(notes.warnings[0].contains("lapsed"), "{:?}", notes.warnings);

        for bad in [
            "x.example.\n",
            "x.example. tomorrow\n",
            "x.example. 1800003600 recheck\n",
            "x.example. 1800003600 norecheck extra\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    /// §1.1 and §2.1: at and below the node, nothing above or beside it; a
    /// positive anchor below resumes validation; one at the node does not (§3).
    #[test]
    fn coverage() {
        let set = parse(&format!("broken.example. {}\n", NOW + 3600)).unwrap();
        let none = anchors(&["."]);
        assert!(set
            .covering(nm("broken.example.").as_ref(), NOW, &none)
            .is_some());
        assert!(set
            .covering(nm("a.b.broken.example.").as_ref(), NOW, &none)
            .is_some());
        assert!(set.covering(nm("example.").as_ref(), NOW, &none).is_none());
        assert!(set
            .covering(nm("sibling.example.").as_ref(), NOW, &none)
            .is_none());
        assert!(
            set.covering(nm("broken.example.").as_ref(), NOW + 3600, &none)
                .is_none(),
            "lapsed at UNTIL"
        );

        let below = anchors(&[".", "deep.broken.example."]);
        assert!(set
            .covering(nm("x.deep.broken.example.").as_ref(), NOW, &below)
            .is_none());
        assert!(set
            .covering(nm("x.broken.example.").as_ref(), NOW, &below)
            .is_some());

        let at = anchors(&[".", "broken.example."]);
        assert!(set
            .covering(nm("x.broken.example.").as_ref(), NOW, &at)
            .is_some());
        let (_, notes) = NegativeTrustAnchors::parse(
            &format!("broken.example. {}\n", NOW + 3600),
            NOW,
            Some(&at),
        )
        .unwrap();
        assert!(
            notes.warnings[0].contains("overrides"),
            "{:?}",
            notes.warnings
        );
    }

    #[test]
    fn expiry_and_lifting() {
        let mut set = parse(&format!(
            "a.example. {}\nb.example. {}\n",
            NOW + 60,
            NOW + 120
        ))
        .unwrap();
        assert_eq!(set.next_expiry(), Some(NOW + 60));
        assert!(set.expire(NOW + 59).is_empty());
        let gone = set.expire(NOW + 60);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].name, nm("a.example."));
        assert!(set.lift(nm("B.EXAMPLE.").as_ref()).is_some(), "names fold");
        assert!(set.is_empty());
    }
}
