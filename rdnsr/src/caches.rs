//! What `rdnsr` remembers between queries.
//!
//! A file of its own so the three fields are private to it: `store` is the one
//! way anything gets in, and a second writer that forgets a cache does not
//! compile (`TODO.md` #117 — two writers had drifted, and one never fed
//! `denials`).

use rdns::cache::{Cached, StalePolicy};
use rdns::clock::Clock;
use rdns::dnssec_chain::ValidationState;
use rdns::negative_cache::{NegativeAnswer, NegativeCache};
use rdns::nsec_cache::{NsecCache, Synthesis, WildcardSynthesis};
use rdns::{DnsCache, DnsMessage, NameRef, Qtype, QuerySection};

/// What [`Caches::stale`] found.
pub(crate) enum Stale {
    Answer(Cached),
    Negative(NegativeAnswer),
}

/// Three caches with three shapes, which is why they are not one.
///
/// - `answers` maps a question to the records that answered it.
/// - `negatives` maps a question to the *absence* of records (RFC 2308): a
///   different thing, because there are no records to key on and the TTL comes
///   from the SOA rather than from an answer.
/// - `denials` maps a *range* of names to the signed statement that none exist —
///   a lookup neither of the others can express (RFC 8198). Validated material
///   only, so it is empty without `--dnssec-validate`, which is why `negatives`
///   is not redundant with it.
pub(crate) struct Caches {
    answers: DnsCache,
    negatives: NegativeCache,
    denials: NsecCache,
}

impl Caches {
    /// `answers` at 0 is a cache that holds nothing (`DnsCache::put` is a
    /// no-op), which is what `--no-cache` means. `denial_zones` is separately 0
    /// without validation: aggressive use rests on the proofs having been
    /// checked.
    ///
    /// `stale` reaches the first two and not `denials`: a denial is served
    /// because its signature proves it, and an expired proof proves nothing —
    /// RFC 8198 §5 rests on the validity period the signer chose, which
    /// RFC 8767 has no standing to extend.
    /// `clock` is the daemon's, the one `ServeContext` reads: one process, one
    /// idea of the time, and a test that can move it (`TODO.md` #52). All
    /// three, since #107a — it reached two of them for a year, three lines
    /// above the one it did not.
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
    /// The one way in for a resolution, whoever asked: the query path, a
    /// prefetch and DNS64 each wrote their own copy until `TODO.md` #117, and
    /// the two that ask on nobody's behalf never fed `denials`.
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
        let secure = state.is_secure();
        let (name, qtype) = (query.qname.as_ref(), query.qtype);
        if !response.answers.is_empty() {
            self.answers
                .put_validated(name, qtype, response.answers.clone(), secure);
        }
        // A "no" is an answer; re-resolving it makes a typo storm cost one
        // upstream walk per repeat. The SOA in the authority section says how
        // long it is good for (RFC 2308).
        self.negatives.insert(name, qtype, response, secure);
        // A *validated* "no" covers a whole range of names, so it also goes in
        // the denial cache. Only when Secure: an unvalidated NSEC is an
        // attacker's claim about which names do not exist.
        if !secure {
            return;
        }
        if response.answers.is_empty() {
            self.denials.insert_validated(response);
        } else {
            // A validated wildcard answer is the same kind of statement about
            // a range (RFC 8198 §5.3), so it is kept under the wildcard rather
            // than the name asked for.
            self.denials.insert_validated_wildcard(response);
        }
    }

    /// [`DnsCache::lookup`].
    pub(crate) fn answer(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
        prefetching: bool,
    ) -> Option<Cached> {
        self.answers.lookup(name, qtype, prefetching)
    }

    /// [`NegativeCache::get`].
    pub(crate) fn negative(&self, name: NameRef<'_>, qtype: Qtype) -> Option<NegativeAnswer> {
        self.negatives.get(name, qtype)
    }

    /// [`NsecCache::synthesize_wildcard`].
    pub(crate) fn synthesize_wildcard(
        &self,
        name: NameRef<'_>,
        qtype: Qtype,
    ) -> Option<WildcardSynthesis> {
        self.denials.synthesize_wildcard(name, qtype)
    }

    /// [`NsecCache::synthesize`].
    pub(crate) fn synthesize_denial(&self, name: NameRef<'_>, qtype: Qtype) -> Option<Synthesis> {
        self.denials.synthesize(name, qtype)
    }

    /// The last thing learned about this question, expired but inside the
    /// stale window (RFC 8767).
    ///
    /// Both caches can hold the question at once: `store` retires neither, and
    /// an NXDOMAIN is keyed by name, so one learned for AAAA covers an A held
    /// from before. The later one wins, because RFC 8767 §4 has an NXDomain
    /// answer "considered to have refreshed the data at the resolver"; serving
    /// the older "yes" hands out an address its zone has since denied
    /// (`TODO.md` #132). BIND, Unbound and Knot Resolver hold one entry per
    /// question and get this by overwriting.
    ///
    /// Stored in the same second is a tie, and the "no" takes it: a name taken
    /// down is the case this ordering exists for.
    ///
    /// Both lookups spend their entry's refresh, which is right: they are one
    /// question, and one refresh answers it.
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

    /// Forget everything held, positive and negative.
    ///
    /// All three, because all three answer without walking a delegation, and
    /// the walk is where a nameserver trigger is asked — a synthesized
    /// NXDOMAIN (RFC 8198) skips it exactly as a cache hit does. The one
    /// caller is the policy reload (`TODO.md` #57); there is no index from a
    /// nameserver to the names it served, so the sweep is the whole cache.
    pub(crate) fn clear(&self) {
        self.answers.clear();
        self.negatives.clear();
        self.denials.clear();
    }
}
