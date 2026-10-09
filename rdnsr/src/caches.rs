//! What `rdnsr` remembers between queries.
//!
//! A file of its own so the three fields are private to it: `store` is the one
//! way anything gets in, and a second writer that forgets a cache does not
//! compile.

use rdns::cache::{Cached, StalePolicy};
use rdns::clock::Clock;
use rdns::dnssec_chain::{Outcome, ValidationState};
use rdns::negative_cache::{NegativeAnswer, NegativeCache};
use rdns::nsec_cache::NsecCache;
use rdns::{DnsCache, DnsMessage, NameRef, Qtype, QuerySection, ResourceRecord, ResponseCode};

/// What [`Caches::lookup`] found.
pub(crate) enum Held {
    /// The answer cache's, the one holding a prefetch can refresh.
    Answer(Cached),
    /// Anything else, which is the reply as it stands.
    Reply {
        rcode: ResponseCode,
        answers: Vec<ResourceRecord>,
        authority: Vec<ResourceRecord>,
        outcome: Outcome,
    },
}

/// What [`Caches::stale`] found.
pub(crate) enum Stale {
    Answer(Cached),
    Negative(NegativeAnswer),
}

/// Three caches with three shapes, which is why they are not one.
///
/// - `answers`: a question to the records that answered it.
/// - `negatives`: a question to an absence; TTL from the SOA (RFC 2308).
/// - `denials`: a range of names to a signed denial (RFC 8198); validated
///   only, so empty without `--dnssec-validate`.
pub(crate) struct Caches {
    answers: DnsCache,
    negatives: NegativeCache,
    denials: NsecCache,
}

impl Caches {
    /// `answers` at 0 holds nothing, which is `--no-cache`; `denial_zones` is 0
    /// without validation, as aggressive use needs checked proofs.
    ///
    /// `stale` reaches the first two only: an expired proof proves nothing, and
    /// RFC 8767 cannot extend RFC 8198 §5's validity period. `clock` is the
    /// daemon's, so one process has one time and a test can move it.
    pub(crate) fn new(
        capacity: usize,
        denial_zones: usize,
        stale: StalePolicy,
        clock: Clock,
    ) -> Caches {
        Caches {
            answers: DnsCache::with_stale(capacity, stale, clock.clone()),
            // Negative answers are answers: `--no-cache` means no cache.
            negatives: NegativeCache::with_stale(capacity, stale, clock.clone()),
            denials: NsecCache::with_clock(denial_zones, clock),
        }
    }

    /// Keep what a resolution of `query` concluded, in every cache it belongs
    /// in.
    ///
    /// The one way in for a resolution, whoever asked — the query path, a
    /// prefetch and DNS64 — so none of them can skip `denials`.
    pub(crate) fn store(
        &self,
        query: &QuerySection,
        response: &DnsMessage,
        state: &ValidationState,
    ) {
        // A bogus answer in the cache is an attack that outlives the query
        // that carried it.
        if state.is_bogus() {
            return;
        }
        let outcome = state.outcome();
        let secure = outcome.is_secure();
        let (name, qtype) = (query.qname.as_ref(), query.qtype);
        if !response.answers.is_empty() {
            self.answers
                .put_validated(name, qtype, response.answers.clone(), outcome);
            // Lookups ask `negatives` first, so retire the "no" this refutes; a
            // bogus contradiction was returned above.
            self.negatives.forget_refuted(name, qtype);
        }
        // A "no" is an answer, so a typo storm costs one walk; the SOA says for
        // how long (RFC 2308).
        self.negatives.insert(name, qtype, response, outcome);
        // A validated "no" covers a range, so it goes in the denial cache too;
        // an unvalidated NSEC is an attacker's claim.
        if !secure {
            return;
        }
        if response.answers.is_empty() {
            self.denials.insert_validated(response);
        } else {
            // A validated wildcard answer is a statement about a range too (RFC
            // 8198 §5.3), kept under the wildcard.
            self.denials.insert_validated_wildcard(response);
        }
    }

    /// What is held for this question, unexpired.
    ///
    /// The order is the caches' business: whether it is right depends on what
    /// `store` retires. `synthesize` false skips the RFC 8198 arms, for CD.
    pub(crate) fn lookup(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
        synthesize: bool,
        prefetching: bool,
    ) -> Option<Held> {
        // A newer "no" outranks an older "yes"; nothing is synthesized, so a CD
        // client may have it.
        if let Some(negative) = self.negatives.get(name, qtype) {
            return Some(Held::Reply {
                rcode: negative.rcode,
                answers: Vec::new(),
                authority: negative.authority,
                outcome: negative.outcome,
            });
        }
        if let Some(hit) = self.answers.lookup(name, qtype, prefetching) {
            return Some(Held::Answer(hit));
        }
        // Synthesis only once the question missed, as RFC 8198 Appendix A
        // orders it; a random name still costs no upstream query.
        if !synthesize {
            return None;
        }
        // The positive half (RFC 8198 §5.3) first; it and a denied wildcard
        // exclude each other. The signature verifies unchanged.
        if let Some(wildcard) = self.denials.synthesize_wildcard(name, qtype) {
            return Some(Held::Reply {
                rcode: ResponseCode::Ok,
                answers: wildcard.answers,
                authority: wildcard.authority,
                outcome: Outcome::Secure,
            });
        }
        // The proofs were validated before storage, so what is derived from
        // them is authentic on the same terms.
        self.denials
            .synthesize(name, qtype)
            .map(|denial| Held::Reply {
                rcode: denial.rcode,
                answers: Vec::new(),
                authority: denial.authority,
                outcome: Outcome::Secure,
            })
    }

    /// One cache at a time, for tests about which caches `store` reached.
    #[cfg(test)]
    pub(crate) fn answer(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
        prefetching: bool,
    ) -> Option<Cached> {
        self.answers.lookup(name, qtype, prefetching)
    }

    #[cfg(test)]
    pub(crate) fn negative(&self, name: NameRef<'_>, qtype: Qtype) -> Option<NegativeAnswer> {
        self.negatives.get(name, qtype)
    }

    #[cfg(test)]
    pub(crate) fn synthesize_wildcard(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
    ) -> Option<rdns::nsec_cache::WildcardSynthesis> {
        self.denials.synthesize_wildcard(name, qtype)
    }

    #[cfg(test)]
    pub(crate) fn synthesize_denial(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
    ) -> Option<rdns::nsec_cache::Synthesis> {
        self.denials.synthesize(name, qtype)
    }

    /// The last thing learned about this question, expired but inside the stale
    /// window (RFC 8767).
    ///
    /// If both caches hold it the later wins, a tie going to the "no": an
    /// NXDomain has "refreshed the data at the resolver" (RFC 8767 §4), and a
    /// taken-down name is the case. Both lookups spend their entry's refresh.
    pub(crate) fn stale(&self, name: NameRef<'_>, qtype: Qtype, refreshing: bool) -> Option<Stale> {
        let answer = self.answers.get_stale(name, qtype, refreshing);
        let negative = self.negatives.get_stale(name, qtype, refreshing);
        match (answer, negative) {
            (Some(answer), Some(negative)) if answer.learned_at > negative.learned_at => {
                Some(Stale::Answer(answer))
            }
            (_, Some(negative)) => Some(Stale::Negative(negative)),
            (Some(answer), None) => Some(Stale::Answer(answer)),
            (None, None) => None,
        }
    }

    /// Put an answer in without resolving for it.
    ///
    /// For tests about *serving* a cached answer, which must not pay for or
    /// depend on the storing rules — `crate::allocations` among them.
    #[cfg(test)]
    pub(crate) fn remember(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
        records: Vec<rdns::ResourceRecord>,
    ) {
        self.answers.put(name, qtype, records);
    }

    /// Forget what any cache holds at or below `node`: a negative trust
    /// anchor changed how that subtree validates.
    pub(crate) fn forget_at_or_below(&self, node: NameRef<'_>) -> usize {
        self.answers.forget_at_or_below(node)
            + self.negatives.forget_at_or_below(node)
            + self.denials.forget_at_or_below(node)
    }

    /// Forget everything held, positive and negative.
    ///
    /// All three skip the delegation walk where nameserver triggers are asked,
    /// a synthesized NXDOMAIN (RFC 8198) as much as a hit, and nothing indexes
    /// a nameserver to the names it served.
    pub(crate) fn clear(&self) {
        self.answers.clear();
        self.negatives.clear();
        self.denials.clear();
    }

    /// Answers and negative answers at exactly `name`, every type. Not the
    /// denials: an NSEC range is not *at* a name (`TODO.md` #178).
    pub(crate) fn forget_name(&self, name: NameRef<'_>) -> usize {
        self.answers.forget_name(name) + self.negatives.forget_name(name)
    }

    pub(crate) fn sizes(&self) -> [(&'static str, usize); 3] {
        [
            ("answers", self.answers.len()),
            ("negatives", self.negatives.len()),
            ("denials", self.denials.len()),
        ]
    }

    pub(crate) fn dump(&self, node: NameRef<'_>) -> Vec<rdns::cache::Dumped> {
        self.answers.dump(node)
    }
}
