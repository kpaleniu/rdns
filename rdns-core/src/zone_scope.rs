//! Which zone apexes a credential may transfer.
//!
//! One type because there are two credentials that answer this question — a
//! TSIG key (RFC 8945) and, since `TODO.md` #59, a client certificate
//! (RFC 9103 §7.5) — and the answer decides whether a stranger walks away with
//! a zone. Written twice they would drift over the two things that are easy to
//! get wrong and impossible to notice: whether the comparison folds case
//! (RFC 4343, and a key list an operator typed is not down-cased) and whether
//! a *child* of a listed zone is in scope. It is not: a transfer hands over
//! everything under an apex, so a rule matching anything less specific
//! authorizes more than it names (`CLAUDE.md` §16).
//!
//! **Empty means every zone**, which is the wide case and is deliberate. A
//! version bump must not stop every transfer on a working deployment, so the
//! default is what the deployment already had; what makes it safe is that the
//! startup banner prints each credential's scope, so "this key transfers
//! everything" is a line an operator reads rather than a thing they assume
//! (§16 again).

use crate::text_names::absolute_lowered;

/// The zone apexes a credential may transfer. Empty is every zone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneScope {
    apexes: Vec<String>,
}

impl ZoneScope {
    /// Every zone this server holds.
    pub fn everything() -> ZoneScope {
        ZoneScope { apexes: Vec::new() }
    }

    /// Only these apexes. An empty iterator is [`ZoneScope::everything`], which
    /// is why a caller that means "nothing" has to not hand out the credential
    /// at all.
    pub fn of<I, S>(apexes: I) -> ZoneScope
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        ZoneScope {
            apexes: apexes
                .into_iter()
                .map(|apex| absolute_lowered(apex.as_ref().trim()).into_owned())
                .collect(),
        }
    }

    /// Whether a transfer of the zone at `apex` is in scope.
    ///
    /// An exact match on the apex, not an enclosing-zone test: `example.com.`
    /// in the list does not authorize `sub.example.com.`, which is a zone of
    /// its own with its own data.
    pub fn allows(&self, apex: &str) -> bool {
        if self.apexes.is_empty() {
            return true;
        }
        let apex = absolute_lowered(apex.trim());
        self.apexes.iter().any(|listed| *listed == *apex)
    }

    /// The apexes, or `None` for the everything case — what a banner prints.
    pub fn listed(&self) -> Option<&[String]> {
        if self.apexes.is_empty() {
            None
        } else {
            Some(&self.apexes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two things a second copy of this would get wrong.
    #[test]
    fn a_scope_folds_case_and_does_not_reach_below_an_apex() {
        let scope = ZoneScope::of(["Example.COM"]);
        assert!(scope.allows("example.com."));
        assert!(scope.allows("EXAMPLE.com"));
        assert!(
            !scope.allows("sub.example.com."),
            "a child is its own zone (`CLAUDE.md` §16)"
        );
        assert!(!scope.allows("other.test."));
    }

    /// The wide case is a value, not an absence to be read as a denial.
    #[test]
    fn an_empty_scope_is_every_zone_and_says_so() {
        let scope = ZoneScope::everything();
        assert!(scope.allows("anything.test."));
        assert_eq!(scope.listed(), None);
        assert_eq!(ZoneScope::of(Vec::<String>::new()), scope);
    }
}
