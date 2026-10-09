//! Negative caching, the plain kind (RFC 2308).
//!
//! A "no" costs the same to obtain as a "yes", so without this every repeat of a
//! failing lookup is a fresh walk from the root.
//!
//! [`crate::nsec_cache`] caches denials too, but only validated ones, and
//! validation is opt-in. This is the other half: no signatures, no synthesis.
//!
//! The rules:
//!
//! - An SOA is required — RFC 2308 §5 takes the negative TTL from it, so a "no"
//!   without one has not said how long it is good for.
//! - The TTL is `min(SOA MINIMUM, the SOA record's own TTL)`, capped at
//!   `MAX_NEGATIVE_TTL` so a week-long negative TTL cannot make us deny a name
//!   the zone fixed an hour ago (RFC 2308 §5, §7).
//! - NXDOMAIN denies every type at the name and everything below it (RFC 8020);
//!   NODATA denies exactly one type.
//! - Nothing bogus is stored, and whether an answer validated is stored with it,
//!   so the AD bit a second client sees is the one the first client saw.
//! - **A "no" goes stale like a "yes"** (RFC 8767): past its TTL it stops being
//!   an answer and stays usable for [`crate::cache::StalePolicy`]'s window, so
//!   an outage does not turn a cached NXDOMAIN into a SERVFAIL.

use crate::cache::{StalePolicy, STALE_ANSWER_TTL};
use crate::clock::Clock;
use crate::deadline::Deadline;
use crate::dnssec_chain::Outcome;
use crate::eviction::Halving;
use crate::name_keys::{NameKeyBuf, NameType, NameTypeKey};
use crate::record_types as rt;
use crate::NameRef;
use crate::Qtype;
use crate::Ttl;
use crate::{DnsMessage, ParsedRecord, ResourceRecord, ResponseCode};
use std::collections::HashMap;
use std::sync::Mutex;

/// The longest a negative answer is held, whatever the SOA claims. RFC 2308 §7
/// recommends one to three hours; this is the low end, matching the validated
/// denial cache.
const MAX_NEGATIVE_TTL: u32 = 3600;

/// A cached "no", ready to be turned back into a response.
#[derive(Debug, Clone)]
pub struct NegativeAnswer {
    /// NXDOMAIN, or NOERROR for NODATA.
    pub rcode: ResponseCode,
    /// The authority section as it arrived — SOA, any NSEC/NSEC3, and the
    /// signatures over them — with TTLs counted down to what is left.
    pub authority: Vec<ResourceRecord>,
    /// What validation concluded when it was stored. The AD bit has to survive
    /// the cache, and must never be picked up on the way out.
    pub outcome: Outcome,
    /// What is left of the negative TTL.
    pub ttl: u32,
    /// A stale "no" whose caller is owed its refresh — the negative half of
    /// [`crate::cache::Cached::refresh`]. Always false from
    /// [`NegativeCache::get`].
    pub refresh: bool,
    /// When this was stored: [`crate::cache::Cached::learned_at`]'s reason.
    pub learned_at: u64,
}

#[derive(Debug, Clone)]
struct Entry {
    rcode: ResponseCode,
    authority: Vec<ResourceRecord>,
    outcome: Outcome,
    expires_at: Deadline,
    /// When a stale answer may next hand out a refresh
    /// ([`crate::cache::STALE_REFRESH_INTERVAL`]). The epoch on a new entry.
    stale_refresh_after: Deadline,
    learned_at: u64,
}

impl Entry {
    fn live(&self, now: u64) -> bool {
        self.expires_at.is_live(now)
    }

    /// Expired, but inside the stale window: an answer only for a caller that
    /// has already failed to refresh it (RFC 8767 §4).
    fn stale(&self, now: u64, policy: StalePolicy) -> bool {
        !self.live(now) && policy.keeps(self.expires_at, now)
    }

    fn remaining(&self, now: u64) -> u32 {
        self.expires_at.remaining_ttl(now)
    }
}

/// The two kinds of "no", each keyed the way it applies.
///
/// One lock, not two: the capacity bound is on the cache as a whole, and a mutex
/// per map means checking one while holding the other.
#[derive(Debug, Default)]
struct Entries {
    /// By name: this name does not exist, so no type at it does either.
    nxdomain: HashMap<NameKeyBuf, Entry>,
    /// By (name, type): the name exists, this type at it does not.
    nodata: HashMap<NameTypeKey, Entry>,
}

impl Entries {
    fn len(&self) -> usize {
        self.nxdomain.len() + self.nodata.len()
    }
}

/// Negative answers, keyed the way each kind of "no" applies.
#[derive(Debug)]
pub struct NegativeCache {
    entries: Mutex<Entries>,
    /// Entries held across both kinds. Zero disables the cache entirely — the
    /// same idiom `--no-cache` uses for the answer cache.
    max_entries: usize,
    stale: StalePolicy,
    /// Where "now" comes from — [`crate::cache::DnsCache`]'s reason, and the
    /// same clock in the daemon that holds both.
    clock: Clock,
}

impl NegativeCache {
    pub fn new(max_entries: usize) -> Self {
        NegativeCache {
            entries: Mutex::new(Entries::default()),
            max_entries,
            stale: StalePolicy::OFF,
            clock: Clock::system(),
        }
    }

    /// The same, holding expired entries for [`StalePolicy`]'s window and
    /// reading the time from `clock`.
    pub fn with_stale(max_entries: usize, stale: StalePolicy, clock: Clock) -> Self {
        NegativeCache {
            stale,
            clock,
            ..NegativeCache::new(max_entries)
        }
    }

    /// Store the "no" in `response`, if that is what it is and it may be
    /// cached.
    ///
    /// `outcome` is validation's verdict, never bogus. Answer records skip it:
    /// a CNAME chain's data has nowhere to go here.
    pub fn insert(
        &self,
        qname: NameRef<'_>,
        qtype: Qtype,
        response: &DnsMessage,
        outcome: Outcome,
    ) {
        if self.max_entries == 0 || !response.answers.is_empty() {
            return;
        }
        let nxdomain = match response.rcode {
            ResponseCode::NoSuchDomain => true,
            ResponseCode::Ok => false,
            // A failure, not an answer. Caching SERVFAIL turns a transient
            // upstream problem into a lasting one.
            _ => return,
        };

        // The SOA says how long the answer is good for (RFC 2308 §5). Requiring
        // one is also what keeps a referral out of the cache.
        let Some(soa_rr) = response
            .authorities
            .iter()
            .find(|rr| rr.rdata.rtype() == rt::SOA)
        else {
            return;
        };
        let Ok(ParsedRecord::SOA { minimum, .. }) = soa_rr.rdata.parse() else {
            return;
        };
        let ttl = Ttl::negative_answer(soa_rr.ttl, minimum)
            .capped_at(MAX_NEGATIVE_TTL)
            .as_secs();
        if ttl == 0 {
            return;
        }

        let now = self.clock.now();
        let entry = Entry {
            rcode: response.rcode,
            authority: response.authorities.clone(),
            outcome,
            expires_at: Deadline::after(now, u64::from(ttl)),
            stale_refresh_after: Deadline::default(),
            learned_at: now,
        };
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };

        if nxdomain {
            let name = NameKeyBuf::new(qname);
            if !entries.nxdomain.contains_key(qname.folded().as_ref())
                && entries.len() >= self.max_entries
            {
                make_room(&mut entries, self.max_entries, now, self.stale);
            }
            entries.nxdomain.insert(name, entry);
        } else {
            let key = NameTypeKey::new(qname, qtype);
            if !entries.nodata.contains_key(&key) && entries.len() >= self.max_entries {
                make_room(&mut entries, self.max_entries, now, self.stale);
            }
            entries.nodata.insert(key, entry);
        }
    }

    /// The cached "no" for this question, or `None` to go and ask.
    pub fn get(&self, qname: NameRef<'_>, qtype: Qtype) -> Option<NegativeAnswer> {
        if self.max_entries == 0 {
            return None;
        }
        let now = self.clock.now();
        // Borrowed: a question that arrived folded — which is most of them —
        // costs this lookup nothing at all.
        let mut fold_buf = Vec::new();
        let name = qname.folded_in(&mut fold_buf);
        let entries = self.entries.lock().ok()?;

        // A cached NXDOMAIN denies its subtree (RFC 8020), so the lookup walks
        // the ancestors, deepest first.
        for ancestor in name.ancestors() {
            if let Some(entry) = entries
                .nxdomain
                .get(ancestor.as_wire())
                .filter(|e| e.live(now))
            {
                return Some(entry.answer(now));
            }
        }

        let key: &dyn NameType = &(name.as_wire(), qtype);
        entries
            .nodata
            .get(key)
            .filter(|e| e.live(now))
            .map(|entry| entry.answer(now))
    }

    /// The cached "no" that has expired but is still inside the stale window
    /// (RFC 8767), with [`STALE_ANSWER_TTL`] on it.
    ///
    /// The same walk [`NegativeCache::get`] does and the same rule about who may
    /// ask as [`crate::cache::DnsCache::get_stale`], `refreshing` included.
    /// `None` when the policy is off.
    pub fn get_stale(
        &self,
        qname: NameRef<'_>,
        qtype: Qtype,
        refreshing: bool,
    ) -> Option<NegativeAnswer> {
        if self.max_entries == 0 || !self.stale.is_on() {
            return None;
        }
        let now = self.clock.now();
        let mut fold_buf = Vec::new();
        let name = qname.folded_in(&mut fold_buf);
        let mut entries = self.entries.lock().ok()?;

        for ancestor in name.ancestors() {
            if let Some(entry) = entries
                .nxdomain
                .get_mut(ancestor.as_wire())
                .filter(|e| e.stale(now, self.stale))
            {
                return Some(entry.stale_answer(now, refreshing));
            }
        }

        let key: &dyn NameType = &(name.as_wire(), qtype);
        entries
            .nodata
            .get_mut(key)
            .filter(|e| e.stale(now, self.stale))
            .map(|entry| entry.stale_answer(now, refreshing))
    }

    /// Forget what an answer for this question has just proved wrong: its
    /// NODATA, and NXDOMAIN at the name or an ancestor (RFC 8020).
    ///
    /// Called by the answer's writer: this cache is asked first, so a stale
    /// "no" would beat the newer "yes" (`TODO.md` #133). One probe per label.
    pub fn forget_refuted(&self, qname: NameRef<'_>, qtype: Qtype) {
        let mut fold_buf = Vec::new();
        let name = qname.folded_in(&mut fold_buf);
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let key: &dyn NameType = &(name.as_wire(), qtype);
        entries.nodata.remove(key);
        for ancestor in name.ancestors() {
            entries.nxdomain.remove(ancestor.as_wire());
        }
    }

    /// How many negative answers are held. For tests and diagnostics.
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every entry at or below `node`, returning how many went.
    ///
    /// For a validation decision that changed under them — a negative trust
    /// anchor added, lifted or expired (RFC 7646 §4, `TODO.md` #176). A scan,
    /// which is fine for an operator's action and would not be per query.
    pub fn forget_at_or_below(&self, node: NameRef<'_>) -> usize {
        let Ok(mut entries) = self.entries.lock() else {
            return 0;
        };
        let before = entries.len();
        entries
            .nxdomain
            .retain(|key, _| !key.as_name().is_at_or_under(node));
        entries
            .nodata
            .retain(|key, _| !crate::name_keys::is_at_or_below(key.name(), node));
        before - entries.len()
    }

    /// Drop the "no" for every type at exactly `name`, NXDOMAIN included,
    /// returning how many went.
    pub fn forget_name(&self, name: NameRef<'_>) -> usize {
        let Ok(mut entries) = self.entries.lock() else {
            return 0;
        };
        let folded = name.folded();
        let before = entries.len();
        entries.nxdomain.remove(folded.as_ref());
        entries
            .nodata
            .retain(|key, _| key.name() != folded.as_ref());
        before - entries.len()
    }

    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.nxdomain.clear();
            entries.nodata.clear();
        }
    }
}

impl Entry {
    /// This entry as an answer, TTLs counted down. Handing back the original
    /// would let each cache in a chain restart the clock.
    fn answer(&self, now: u64) -> NegativeAnswer {
        self.with_ttl(self.remaining(now))
    }

    /// The same, with the TTL a stale answer carries: there is none left to
    /// count down (RFC 8767 §4). Claims the refresh if `refreshing` and one is
    /// due.
    fn stale_answer(&mut self, now: u64, refreshing: bool) -> NegativeAnswer {
        let refresh = self
            .stale_refresh_after
            .claim_stale_refresh(refreshing, now);
        NegativeAnswer {
            refresh,
            ..self.with_ttl(STALE_ANSWER_TTL)
        }
    }

    fn with_ttl(&self, ttl: u32) -> NegativeAnswer {
        NegativeAnswer {
            rcode: self.rcode,
            authority: self
                .authority
                .iter()
                .map(|rr| ResourceRecord {
                    ttl: Ttl::from_secs(ttl),
                    ..rr.clone()
                })
                .collect(),
            outcome: self.outcome,
            ttl,
            refresh: false,
            learned_at: self.learned_at,
        }
    }
}

/// Make room: drop what has expired across both kinds, and if that freed
/// nothing, halve what is left, soonest to expire going first.
///
/// One victim per insert was the old policy, and a full cache is full forever,
/// so it was a two-map `min_by_key` scan plus a key clone on *every* insert —
/// 14.6 µs at `max_entries` 10 000, with the lock every lookup needs held for
/// it. See [`crate::eviction`]; the bound spans both maps, so one plan drives
/// both `retain`s.
fn make_room(entries: &mut Entries, max_entries: usize, now: u64, stale: StalePolicy) {
    let before = entries.len();
    // Usable, not live: with serve-stale on, an expired "no" is still the last
    // thing known.
    entries
        .nxdomain
        .retain(|_, e| stale.keeps(e.expires_at, now));
    entries.nodata.retain(|_, e| stale.keeps(e.expires_at, now));
    if entries.len() < before {
        return;
    }

    let expiries = entries
        .nxdomain
        .values()
        .chain(entries.nodata.values())
        .map(|e| e.expires_at.unix_secs())
        .collect();
    let Some(mut plan) = Halving::plan(expiries, max_entries / 2) else {
        return;
    };
    entries
        .nxdomain
        .retain(|_, e| plan.keep(e.expires_at.unix_secs()));
    entries
        .nodata
        .retain(|_, e| plan.keep(e.expires_at.unix_secs()));
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::cache::STALE_REFRESH_INTERVAL;
    use crate::clock::Clock;
    use crate::test_records::nm;
    use crate::test_records::soa_record;
    use crate::{Class, OpCode, QueryClass, QuerySection, RecordData};

    /// A cache whose clock the test moves: a negative TTL is whole seconds, so
    /// every other way of reaching expiry is a sleep.
    fn fixed_cache(max_entries: usize, stale: StalePolicy) -> (NegativeCache, Clock) {
        let clock = Clock::fixed(1_000_000_000);
        (
            NegativeCache::with_stale(max_entries, stale, clock.clone()),
            clock,
        )
    }

    /// A cached "no" goes stale like a "yes" (RFC 8767): past its TTL it stops
    /// being an answer and stays usable until the window closes.
    #[test]
    fn an_expired_nxdomain_is_a_miss_and_a_stale_hit() {
        let (cache, clock) = fixed_cache(16, StalePolicy::seconds(3600));
        cache.insert(
            nm("gone.example.com.").as_ref(),
            Qtype::of(rt::A),
            &negative(
                "gone.example.com.",
                ResponseCode::NoSuchDomain,
                vec![soa_record("example.com.", 60, Ttl::from_secs(60))],
            ),
            Outcome::Indeterminate,
        );
        clock.advance(61);

        assert!(
            cache
                .get(nm("gone.example.com.").as_ref(), Qtype::of(rt::A))
                .is_none(),
            "expired is not an answer"
        );
        let stale = cache
            .get_stale(nm("gone.example.com.").as_ref(), Qtype::of(rt::A), false)
            .expect("but it is the last thing known");
        assert_eq!(stale.rcode, ResponseCode::NoSuchDomain);
        assert_eq!(stale.ttl, STALE_ANSWER_TTL);
        assert_eq!(stale.authority[0].ttl.as_secs(), STALE_ANSWER_TTL);

        // RFC 8020: the denial still covers everything beneath the name.
        assert!(cache
            .get_stale(
                nm("a.b.gone.example.com.").as_ref(),
                Qtype::of(rt::A),
                false
            )
            .is_some());

        clock.advance(3600);
        assert!(
            cache
                .get_stale(nm("gone.example.com.").as_ref(), Qtype::of(rt::A), false)
                .is_none(),
            "and the window closes"
        );
    }

    #[test]
    fn an_expired_nodata_is_a_stale_hit_for_its_type_alone() {
        let (cache, clock) = fixed_cache(16, StalePolicy::seconds(3600));
        cache.insert(
            nm("example.com.").as_ref(),
            Qtype::of(rt::AAAA),
            &negative(
                "example.com.",
                ResponseCode::Ok,
                vec![soa_record("example.com.", 60, Ttl::from_secs(60))],
            ),
            Outcome::Indeterminate,
        );
        clock.advance(61);
        assert!(cache
            .get_stale(nm("example.com.").as_ref(), Qtype::of(rt::AAAA), false)
            .is_some());
        assert!(
            cache
                .get_stale(nm("example.com.").as_ref(), Qtype::of(rt::A), false)
                .is_none(),
            "a NODATA denies one type"
        );
    }

    /// A stale "no" answered first hands out one refresh per interval, as a
    /// stale answer does — and the NXDOMAIN that answers for a name's
    /// descendants is one entry, so they share it.
    #[test]
    fn a_stale_denial_hands_out_one_refresh_per_recheck_interval() {
        let (cache, clock) = fixed_cache(16, StalePolicy::seconds(3600));
        cache.insert(
            nm("gone.example.com.").as_ref(),
            Qtype::of(rt::A),
            &negative(
                "gone.example.com.",
                ResponseCode::NoSuchDomain,
                vec![soa_record("example.com.", 60, Ttl::from_secs(60))],
            ),
            Outcome::Indeterminate,
        );
        clock.advance(61);
        let owed = |name: &str| {
            cache
                .get_stale(nm(name).as_ref(), Qtype::of(rt::A), true)
                .expect("inside the window")
                .refresh
        };

        assert!(owed("gone.example.com."), "the first caller refreshes");
        assert!(!owed("gone.example.com."), "the second does not");
        assert!(!owed("a.gone.example.com."), "nor one below it: one entry");
        clock.advance(STALE_REFRESH_INTERVAL);
        assert!(owed("gone.example.com."), "and after the interval, again");
        assert!(
            !cache
                .get(nm("gone.example.com.").as_ref(), Qtype::of(rt::A))
                .is_some_and(|a| a.refresh),
            "and `get` never owes one"
        );
    }

    /// Eviction keeps what the window keeps, the way the answer cache's does:
    /// otherwise the window is one only a quiet resolver has.
    ///
    /// Eleven entries into a cache of ten, all expired and all inside the
    /// window, so the insert that triggers `make_room` has to halve rather than
    /// sweep. Fails with `retain(|_, e| e.live(now))`: **1** survives, being
    /// the one inserted after the sweep.
    #[test]
    fn eviction_keeps_what_is_still_inside_the_stale_window() {
        let (cache, clock) = fixed_cache(10, StalePolicy::seconds(3600));
        let deny = |name: &str| {
            negative(
                name,
                ResponseCode::NoSuchDomain,
                vec![soa_record("example.com.", 60, Ttl::from_secs(60))],
            )
        };
        for i in 0..10 {
            let name = format!("gone{i}.example.com.");
            cache.insert(
                nm(&name).as_ref(),
                Qtype::of(rt::A),
                &deny(&name),
                Outcome::Indeterminate,
            );
        }
        clock.advance(61);
        cache.insert(
            nm("eleventh.example.com.").as_ref(),
            Qtype::of(rt::A),
            &deny("eleventh.example.com."),
            Outcome::Indeterminate,
        );

        let held = cache.len();
        assert!(
            held >= 5,
            "halved to five and one more inserted, not swept: {held} survived"
        );
        assert!(held <= 10, "still bounded, got {held}");
    }

    #[test]
    fn with_the_policy_off_nothing_is_stale() {
        let (cache, clock) = fixed_cache(16, StalePolicy::OFF);
        cache.insert(
            nm("gone.example.com.").as_ref(),
            Qtype::of(rt::A),
            &negative(
                "gone.example.com.",
                ResponseCode::NoSuchDomain,
                vec![soa_record("example.com.", 60, Ttl::from_secs(60))],
            ),
            Outcome::Indeterminate,
        );
        clock.advance(61);
        assert!(cache
            .get_stale(nm("gone.example.com.").as_ref(), Qtype::of(rt::A), false)
            .is_none());
    }

    /// A negative response as a server would send it.
    fn negative(qname: &str, rcode: ResponseCode, authority: Vec<ResourceRecord>) -> DnsMessage {
        DnsMessage {
            id: 1,
            response: true,
            opcode: OpCode::Query,
            authoritive: true,
            truncation: false,
            recursion: true,
            recursion_ok: true,
            ad: false,
            cd: false,
            rcode,
            queries: vec![QuerySection {
                qname: nm(qname),
                qtype: Qtype::of(rt::A),
                qclass: QueryClass::IN,
            }],
            answers: Vec::new(),
            authorities: authority,
            additionals: Vec::new(),
            edns: None,
        }
    }

    fn nxdomain_for(qname: &str) -> DnsMessage {
        negative(
            qname,
            ResponseCode::NoSuchDomain,
            vec![soa_record("example.com.", 300, Ttl::from_secs(3600))],
        )
    }

    #[test]
    fn test_nxdomain_is_cached_for_every_type_at_the_name() {
        let cache = NegativeCache::new(16);
        cache.insert(
            nm("nope.example.com.").as_ref(),
            Qtype::of(rt::A),
            &nxdomain_for("nope.example.com."),
            Outcome::Indeterminate,
        );

        for qtype in [rt::A, rt::AAAA, rt::MX, rt::TXT] {
            let answer = cache
                .get(nm("nope.example.com.").as_ref(), Qtype::of(qtype))
                .unwrap_or_else(|| panic!("type {qtype} should be denied too"));
            assert_eq!(answer.rcode, ResponseCode::NoSuchDomain);
        }
        assert!(cache
            .get(nm("other.example.com.").as_ref(), Qtype::of(rt::A))
            .is_none());
    }

    /// RFC 8020: nothing exists below a name that does not exist.
    #[test]
    fn test_nxdomain_denies_names_below_it() {
        let cache = NegativeCache::new(16);
        cache.insert(
            nm("gone.example.com.").as_ref(),
            Qtype::of(rt::A),
            &nxdomain_for("gone.example.com."),
            Outcome::Indeterminate,
        );

        assert!(cache
            .get(nm("a.gone.example.com.").as_ref(), Qtype::of(rt::A))
            .is_some());
        assert!(cache
            .get(nm("deep.b.gone.example.com.").as_ref(), Qtype::of(rt::AAAA))
            .is_some());
        // But not above it, and not beside it.
        assert!(cache
            .get(nm("example.com.").as_ref(), Qtype::of(rt::A))
            .is_none());
        assert!(cache
            .get(nm("gone2.example.com.").as_ref(), Qtype::of(rt::A))
            .is_none());
    }

    /// NODATA is about one type: the name is there, so other types may be too.
    #[test]
    fn test_nodata_is_cached_for_that_type_only() {
        let cache = NegativeCache::new(16);
        let response = negative(
            "www.example.com.",
            ResponseCode::Ok,
            vec![soa_record("example.com.", 300, Ttl::from_secs(3600))],
        );
        cache.insert(
            nm("www.example.com.").as_ref(),
            Qtype::of(rt::AAAA),
            &response,
            Outcome::Indeterminate,
        );

        let answer = cache
            .get(nm("www.example.com.").as_ref(), Qtype::of(rt::AAAA))
            .expect("cached");
        assert_eq!(answer.rcode, ResponseCode::Ok, "NODATA is NOERROR");
        assert!(
            cache
                .get(nm("www.example.com.").as_ref(), Qtype::of(rt::A))
                .is_none(),
            "another type at the same name says nothing about this one"
        );
        assert!(cache
            .get(nm("sub.www.example.com.").as_ref(), Qtype::of(rt::AAAA))
            .is_none());
    }

    /// An answer for a question retires what it refutes and nothing else
    /// (`TODO.md` #133).
    #[test]
    fn an_answer_retires_the_denials_it_refutes() {
        let cache = NegativeCache::new(16);
        let (a, aaaa) = (Qtype::of(rt::A), Qtype::of(rt::AAAA));
        let nodata = |name: &str| {
            negative(
                name,
                ResponseCode::Ok,
                vec![soa_record("example.com.", 300, Ttl::from_secs(3600))],
            )
        };
        let www = nm("www.example.com.");
        cache.insert(
            www.as_ref(),
            a,
            &nodata("www.example.com."),
            Outcome::Indeterminate,
        );
        cache.insert(
            www.as_ref(),
            aaaa,
            &nodata("www.example.com."),
            Outcome::Indeterminate,
        );
        cache.insert(
            nm("gone.example.com.").as_ref(),
            a,
            &nxdomain_for("gone.example.com."),
            Outcome::Indeterminate,
        );
        cache.insert(
            nm("beside.example.com.").as_ref(),
            a,
            &nxdomain_for("beside.example.com."),
            Outcome::Indeterminate,
        );

        cache.forget_refuted(www.as_ref(), a);
        assert!(
            cache.get(www.as_ref(), a).is_none(),
            "the NODATA it answers"
        );
        assert!(
            cache.get(www.as_ref(), aaaa).is_some(),
            "another type is still absent"
        );

        // A name below an NXDOMAIN exists, so the NXDOMAIN above it goes.
        let below = nm("host.gone.example.com.");
        cache.forget_refuted(below.as_ref(), a);
        assert!(cache.get(below.as_ref(), a).is_none());
        assert!(cache.get(nm("gone.example.com.").as_ref(), aaaa).is_none());
        assert!(
            cache.get(nm("beside.example.com.").as_ref(), a).is_some(),
            "a sibling's NXDOMAIN is not refuted"
        );
    }

    /// RFC 2308 §5: the negative TTL is the lesser of the SOA's MINIMUM and the
    /// SOA record's own TTL, and it is bounded whatever the zone says.
    #[test]
    fn test_ttl_is_the_lesser_of_soa_minimum_and_soa_ttl() {
        let cache = NegativeCache::new(16);

        let minimum_wins = negative(
            "a.example.com.",
            ResponseCode::NoSuchDomain,
            vec![soa_record("example.com.", 60, Ttl::from_secs(3600))],
        );
        cache.insert(
            nm("a.example.com.").as_ref(),
            Qtype::of(rt::A),
            &minimum_wins,
            Outcome::Indeterminate,
        );
        assert!(
            cache
                .get(nm("a.example.com.").as_ref(), Qtype::of(rt::A))
                .unwrap()
                .ttl
                <= 60
        );

        let record_ttl_wins = negative(
            "b.example.com.",
            ResponseCode::NoSuchDomain,
            vec![soa_record("example.com.", 3600, Ttl::from_secs(30))],
        );
        cache.insert(
            nm("b.example.com.").as_ref(),
            Qtype::of(rt::A),
            &record_ttl_wins,
            Outcome::Indeterminate,
        );
        assert!(
            cache
                .get(nm("b.example.com.").as_ref(), Qtype::of(rt::A))
                .unwrap()
                .ttl
                <= 30
        );

        // A zone asking for a week gets the ceiling.
        let greedy = negative(
            "c.example.com.",
            ResponseCode::NoSuchDomain,
            vec![soa_record("example.com.", 604800, Ttl::from_secs(604800))],
        );
        cache.insert(
            nm("c.example.com.").as_ref(),
            Qtype::of(rt::A),
            &greedy,
            Outcome::Indeterminate,
        );
        let answer = cache
            .get(nm("c.example.com.").as_ref(), Qtype::of(rt::A))
            .unwrap();
        assert!(answer.ttl <= MAX_NEGATIVE_TTL, "got {}", answer.ttl);
    }

    /// The records handed back count down too, or a client re-caching them
    /// holds the answer longer than we may.
    #[test]
    fn test_the_authority_records_count_down() {
        let cache = NegativeCache::new(16);
        let response = negative(
            "a.example.com.",
            ResponseCode::NoSuchDomain,
            vec![soa_record("example.com.", 90, Ttl::from_secs(3600))],
        );
        cache.insert(
            nm("a.example.com.").as_ref(),
            Qtype::of(rt::A),
            &response,
            Outcome::Indeterminate,
        );

        let answer = cache
            .get(nm("a.example.com.").as_ref(), Qtype::of(rt::A))
            .unwrap();
        assert!(
            answer
                .authority
                .iter()
                .all(|rr| rr.ttl <= Ttl::from_secs(90)),
            "authority TTLs must not exceed the negative TTL"
        );
        assert!(
            answer
                .authority
                .iter()
                .any(|rr| rr.rdata.rtype() == rt::SOA),
            "RFC 2308 §2.1 wants the SOA on a negative answer"
        );
    }

    /// No SOA, no negative TTL — which also keeps referrals out.
    #[test]
    fn test_a_negative_answer_without_an_soa_is_not_cached() {
        let cache = NegativeCache::new(16);
        cache.insert(
            nm("a.example.com.").as_ref(),
            Qtype::of(rt::A),
            &negative("a.example.com.", ResponseCode::NoSuchDomain, Vec::new()),
            Outcome::Indeterminate,
        );
        assert!(cache.is_empty());
        assert!(cache
            .get(nm("a.example.com.").as_ref(), Qtype::of(rt::A))
            .is_none());
    }

    #[test]
    fn test_zero_ttl_is_not_cached() {
        let cache = NegativeCache::new(16);
        cache.insert(
            nm("a.example.com.").as_ref(),
            Qtype::of(rt::A),
            &negative(
                "a.example.com.",
                ResponseCode::NoSuchDomain,
                vec![soa_record("example.com.", 0, Ttl::from_secs(3600))],
            ),
            Outcome::Indeterminate,
        );
        assert!(
            cache
                .get(nm("a.example.com.").as_ref(), Qtype::of(rt::A))
                .is_none(),
            "0 means do not reuse"
        );
    }

    #[test]
    fn test_servfail_is_not_cached() {
        let cache = NegativeCache::new(16);
        cache.insert(
            nm("a.example.com.").as_ref(),
            Qtype::of(rt::A),
            &negative(
                "a.example.com.",
                ResponseCode::ServerFailure,
                vec![soa_record("example.com.", 300, Ttl::from_secs(3600))],
            ),
            Outcome::Indeterminate,
        );
        assert!(cache.is_empty());
    }

    /// A CNAME chain ending in NODATA is data the client needs.
    #[test]
    fn test_a_response_with_answers_is_not_cached() {
        let cache = NegativeCache::new(16);
        let mut response = negative(
            "www.example.com.",
            ResponseCode::Ok,
            vec![soa_record("example.com.", 300, Ttl::from_secs(3600))],
        );
        response.answers.push(ResourceRecord {
            name: nm("www.example.com."),
            class: Class::IN,
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::CNAME(nm("elsewhere.test."))).unwrap(),
        });
        cache.insert(
            nm("www.example.com.").as_ref(),
            Qtype::of(rt::AAAA),
            &response,
            Outcome::Indeterminate,
        );
        assert!(cache.is_empty());
    }

    /// The AD bit has to survive the cache, and must never be gained in it.
    #[test]
    fn test_validation_state_is_remembered() {
        let cache = NegativeCache::new(16);
        cache.insert(
            nm("a.example.com.").as_ref(),
            Qtype::of(rt::A),
            &nxdomain_for("a.example.com."),
            Outcome::Secure,
        );
        cache.insert(
            nm("b.example.com.").as_ref(),
            Qtype::of(rt::A),
            &nxdomain_for("b.example.com."),
            Outcome::Indeterminate,
        );

        assert!(cache
            .get(nm("a.example.com.").as_ref(), Qtype::of(rt::A))
            .unwrap()
            .outcome
            .is_secure());
        assert!(!cache
            .get(nm("b.example.com.").as_ref(), Qtype::of(rt::A))
            .unwrap()
            .outcome
            .is_secure());
    }

    #[test]
    fn test_names_are_matched_case_insensitively() {
        let cache = NegativeCache::new(16);
        cache.insert(
            nm("NoPe.Example.COM.").as_ref(),
            Qtype::of(rt::A),
            &nxdomain_for("NoPe.Example.COM."),
            Outcome::Indeterminate,
        );
        assert!(cache
            .get(nm("nope.example.com.").as_ref(), Qtype::of(rt::A))
            .is_some());
    }

    #[test]
    fn test_zero_capacity_stores_nothing() {
        let cache = NegativeCache::new(0);
        cache.insert(
            nm("a.example.com.").as_ref(),
            Qtype::of(rt::A),
            &nxdomain_for("a.example.com."),
            Outcome::Indeterminate,
        );
        assert!(cache.is_empty());
        assert!(cache
            .get(nm("a.example.com.").as_ref(), Qtype::of(rt::A))
            .is_none());
    }

    #[test]
    fn test_capacity_is_bounded_across_both_kinds() {
        let cache = NegativeCache::new(4);
        for i in 0..10 {
            let name = format!("nope{i}.example.com.");
            cache.insert(
                nm(&name).as_ref(),
                Qtype::of(rt::A),
                &nxdomain_for(&name),
                Outcome::Indeterminate,
            );
            let nodata = negative(
                &name,
                ResponseCode::Ok,
                vec![soa_record("example.com.", 300, Ttl::from_secs(3600))],
            );
            cache.insert(
                nm(&name).as_ref(),
                Qtype::of(rt::AAAA),
                &nodata,
                Outcome::Indeterminate,
            );
        }
        assert!(cache.len() <= 4, "held {} entries", cache.len());
    }

    /// What an insert costs must not depend on the bound: a ratio, not a floor
    /// (`CLAUDE.md` §10). Fails with a `min_by_key`-per-victim eviction, at
    /// `rdnsr`'s default `--cache-size` (`TODO.md` #33a).
    #[test]
    fn inserting_into_a_full_cache_costs_what_inserting_with_room_does() {
        use std::time::Instant;

        const BOUND: usize = 10_000;

        let fill = |cache: &NegativeCache, names: std::ops::Range<usize>| {
            for i in names {
                let name = format!("nope{i}.example.com.");
                cache.insert(
                    nm(&name).as_ref(),
                    Qtype::of(rt::A),
                    &nxdomain_for(&name),
                    Outcome::Indeterminate,
                );
            }
        };
        // Best of five, each sample on caches of its own: the timed inserts
        // fill them, so timing one twice times a different cache.
        let time = |capacity: usize| {
            let cache = NegativeCache::new(capacity);
            fill(&cache, 0..BOUND);
            assert_eq!(cache.len(), BOUND, "the bound is reached, not passed");
            let start = Instant::now();
            fill(&cache, BOUND..2 * BOUND);
            start.elapsed()
        };
        let (with_room, at_the_bound) =
            crate::testutil::fastest_of_each(5, || time(BOUND * 4), || time(BOUND));

        let ratio = at_the_bound.as_secs_f64() / with_room.as_secs_f64().max(1e-9);
        assert!(
            ratio < 3.0,
            "an insert at the bound cost {ratio:.1}x one with room to spare \
             ({with_room:?} -> {at_the_bound:?}); eviction is scanning for one \
             victim per insert again"
        );
    }

    /// An expiry is `now` plus a TTL, saturating: a clock near the end of `u64`
    /// keeps the entry until the end of time rather than overflowing.
    #[test]
    fn an_entry_cached_at_the_end_of_time_is_kept() {
        let clock = Clock::fixed(u64::MAX - 10);
        let cache = NegativeCache::with_stale(16, StalePolicy::OFF, clock);
        cache.insert(
            nm("gone.example.com.").as_ref(),
            Qtype::of(rt::A),
            &negative(
                "gone.example.com.",
                ResponseCode::NoSuchDomain,
                vec![soa_record("example.com.", 60, Ttl::from_secs(60))],
            ),
            Outcome::Indeterminate,
        );
        assert!(cache
            .get(nm("gone.example.com.").as_ref(), Qtype::of(rt::A))
            .is_some());
    }
}
