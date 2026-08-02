//! Negative caching, the plain kind (RFC 2308).
//!
//! A "no" is an answer and costs the same to obtain as a "yes", so not caching
//! it means every repeat of a failing lookup is a fresh walk to the
//! authoritative server. That is not a rare case: a typo, a stale link, a
//! Windows box asking for a name that will never exist, a random-name flood —
//! all of it re-resolved from the root, every time.
//!
//! [`crate::nsec_cache`] already caches denials, but only ones that *validated*,
//! because everything it does rests on the proof having been checked. Validation
//! is opt-in, so for most deployments that cache is switched off entirely and
//! nothing here was cached at all. This is the other half: no signatures
//! required, no synthesis, no cleverness — the same question asked again gets the
//! same answer back, and nothing else does.
//!
//! What keeps it honest:
//!
//! - **An SOA is required.** RFC 2308 §5 takes the negative TTL from the SOA in
//!   the authority section, so a "no" that arrives without one has not told us
//!   how long it is good for and is not cached at all.
//! - **The TTL is the SOA's, bounded.** `min(SOA MINIMUM, the SOA record's own
//!   TTL)`, then capped at [`MAX_NEGATIVE_TTL`] — RFC 2308 §5 and §7 both want a
//!   ceiling, because a zone that publishes a week-long negative TTL should not
//!   be able to make us deny a name it fixed an hour ago.
//! - **NXDOMAIN is about the name, NODATA about one type.** "No such name" denies
//!   every type at it, and everything below it (RFC 8020) — the resolver's walk
//!   already takes that position, and it would be strange for the cache not to.
//!   "No such type" denies exactly that type, and says nothing about any other.
//! - **Nothing bogus is stored**, and whether an answer validated is stored with
//!   it, so the AD bit a second client sees is the one the first client saw.

use crate::dnssec::{canonical_name, label_count, suffix_labels};
use crate::utils::{current_unix_timestamp, record_types as rt, NameKeyBuf};
use crate::Qtype;
use crate::Ttl;
use crate::{DnsMessage, ParsedRecord, ResourceRecord, ResponseCode};
use std::collections::HashMap;
use std::sync::Mutex;

/// The longest a negative answer is held, whatever the zone's SOA claims.
///
/// RFC 2308 §5 asks for a configurable ceiling and §7 recommends one in the
/// range of one to three hours; this is the low end of that, which is also what
/// the validated denial cache uses.
pub const MAX_NEGATIVE_TTL: u32 = 3600;

/// A cached "no", ready to be turned back into a response.
#[derive(Debug, Clone)]
pub struct NegativeAnswer {
    /// NXDOMAIN, or NOERROR for NODATA.
    pub rcode: ResponseCode,
    /// The authority section as it arrived — SOA, any NSEC/NSEC3, and the
    /// signatures over them — with TTLs counted down to what is left.
    pub authority: Vec<ResourceRecord>,
    /// Whether the answer was DNSSEC-validated when it was stored. The AD bit
    /// has to survive the cache, and must never be picked up on the way out.
    pub secure: bool,
    /// What is left of the negative TTL.
    pub ttl: u32,
}

#[derive(Debug, Clone)]
struct Entry {
    rcode: ResponseCode,
    authority: Vec<ResourceRecord>,
    secure: bool,
    expires_at: u64,
}

impl Entry {
    fn live(&self, now: u64) -> bool {
        self.expires_at > now
    }

    fn remaining(&self, now: u64) -> u32 {
        self.expires_at.saturating_sub(now).min(u32::MAX as u64) as u32
    }
}

/// The two kinds of "no", each keyed the way it applies.
///
/// Under one lock rather than two, because the capacity bound is on the cache as
/// a whole: with a mutex per map, checking one while holding the other is a
/// deadlock waiting for the first caller who does it.
#[derive(Debug, Default)]
struct Entries {
    /// By name: this name does not exist, so no type at it does either.
    nxdomain: HashMap<NameKeyBuf, Entry>,
    /// By (name, type): the name exists, this type at it does not.
    nodata: HashMap<(String, Qtype), Entry>,
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
}

impl NegativeCache {
    pub fn new(max_entries: usize) -> Self {
        NegativeCache {
            entries: Mutex::new(Entries::default()),
            max_entries,
        }
    }

    /// Store the "no" in `response`, if that is what it is and it may be cached.
    ///
    /// `secure` must be what validation actually concluded, and a bogus answer
    /// must not be offered here at all: a cache is the one place a mistake
    /// outlives the query that carried it.
    ///
    /// Does nothing for a response that carries answer records — a CNAME chain
    /// ending in NODATA is a negative answer in RFC 2308's terms, but the chain
    /// is data the client needs and this cache has nowhere to put it.
    pub fn insert(&self, qname: &str, qtype: Qtype, response: &DnsMessage, secure: bool) {
        if self.max_entries == 0 || !response.answers.is_empty() {
            return;
        }
        let nxdomain = match response.rcode {
            ResponseCode::NoSuchDomain => true,
            ResponseCode::Ok => false,
            // Anything else is a failure rather than an answer. RFC 2308 §7
            // allows caching those briefly; a SERVFAIL we cached would be a
            // transient upstream problem turned into a lasting one.
            _ => return,
        };

        // The SOA is what says how long this answer is good for (RFC 2308 §5).
        // Without one there is no negative TTL to honour, so there is nothing to
        // store — this is also what keeps a referral out of the cache.
        let Some(soa_rr) = response
            .authorities
            .iter()
            .find(|rr| rr.rdata.rtype == rt::SOA)
        else {
            return;
        };
        let Ok(ParsedRecord::SOA { minimum, .. }) = soa_rr.rdata.parse() else {
            return;
        };
        let ttl = soa_rr.ttl.as_secs().min(minimum).min(MAX_NEGATIVE_TTL);
        if ttl == 0 {
            return;
        }

        let now = current_unix_timestamp();
        let entry = Entry {
            rcode: response.rcode,
            authority: response.authorities.clone(),
            secure,
            expires_at: now + ttl as u64,
        };
        let name = canonical_name(qname);
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };

        if nxdomain {
            if !entries.nxdomain.contains_key(name.as_str()) && entries.len() >= self.max_entries {
                make_room(&mut entries, now);
            }
            entries.nxdomain.insert(NameKeyBuf::new(&name), entry);
        } else {
            let key = (name, qtype);
            if !entries.nodata.contains_key(&key) && entries.len() >= self.max_entries {
                make_room(&mut entries, now);
            }
            entries.nodata.insert(key, entry);
        }
    }

    /// The cached "no" for this question, or `None` to go and ask.
    pub fn get(&self, qname: &str, qtype: Qtype) -> Option<NegativeAnswer> {
        if self.max_entries == 0 {
            return None;
        }
        let now = current_unix_timestamp();
        let name = canonical_name(qname);
        let entries = self.entries.lock().ok()?;

        // A cached NXDOMAIN denies every type at the name, and every name
        // beneath it: nothing can exist under a name that does not exist, since
        // a name with descendants is an empty non-terminal and answers NODATA
        // (RFC 8020). So the walk up the ancestors *is* the lookup, deepest
        // first, bounded by the label count.
        for depth in (0..=label_count(&name)).rev() {
            let ancestor = suffix_labels(&name, depth);
            if let Some(entry) = entries
                .nxdomain
                .get(ancestor.as_str())
                .filter(|e| e.live(now))
            {
                return Some(entry.answer(now));
            }
        }

        entries
            .nodata
            .get(&(name, qtype))
            .filter(|e| e.live(now))
            .map(|entry| entry.answer(now))
    }

    /// How many negative answers are held. For tests and diagnostics.
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.nxdomain.clear();
            entries.nodata.clear();
        }
    }
}

impl Entry {
    /// This entry as an answer, with the TTLs counted down.
    ///
    /// Counting down matters as much here as in any cache: handing back the
    /// original TTL lets the client hold the answer for its full life starting
    /// now, which is how a five-minute negative answer becomes an hour-long one
    /// passed from cache to cache.
    fn answer(&self, now: u64) -> NegativeAnswer {
        let ttl = self.remaining(now);
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
            secure: self.secure,
            ttl,
        }
    }
}

/// Make room: drop what has expired across both kinds, and if that freed
/// nothing, the entry that expires soonest — the one whose loss costs least.
fn make_room(entries: &mut Entries, now: u64) {
    let before = entries.len();
    entries.nxdomain.retain(|_, e| e.live(now));
    entries.nodata.retain(|_, e| e.live(now));
    if entries.len() < before {
        return;
    }

    let soonest_nx = entries
        .nxdomain
        .iter()
        .min_by_key(|(_, e)| e.expires_at)
        .map(|(k, e)| (k.clone(), e.expires_at));
    let soonest_nd = entries
        .nodata
        .iter()
        .min_by_key(|(_, e)| e.expires_at)
        .map(|(k, e)| (k.clone(), e.expires_at));

    match (soonest_nx, soonest_nd) {
        (Some((key, nx_at)), Some((_, nd_at))) if nx_at <= nd_at => {
            entries.nxdomain.remove(&key);
        }
        (_, Some((key, _))) => {
            entries.nodata.remove(&key);
        }
        (Some((key, _)), None) => {
            entries.nxdomain.remove(&key);
        }
        (None, None) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Class;
    use crate::{OpCode, QueryClass, QuerySection, RecordData};

    fn soa_record(zone: &str, minimum: u32, ttl: Ttl) -> ResourceRecord {
        ResourceRecord {
            name: zone.to_string(),
            class: Class::new(1),
            ttl,
            rdata: RecordData::from_parsed(&ParsedRecord::SOA {
                mname: format!("ns1.{zone}"),
                rname: format!("admin.{zone}"),
                serial: 1,
                refresh: 10800,
                retry: 3600,
                expire: 604800,
                minimum,
            })
            .unwrap(),
        }
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
                qname: qname.to_string(),
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
            "nope.example.com.",
            Qtype::of(rt::A),
            &nxdomain_for("nope.example.com."),
            false,
        );

        for qtype in [rt::A, rt::AAAA, rt::MX, rt::TXT] {
            let answer = cache
                .get("nope.example.com.", Qtype::of(qtype))
                .unwrap_or_else(|| panic!("type {qtype} should be denied too"));
            assert_eq!(answer.rcode, ResponseCode::NoSuchDomain);
        }
        assert!(cache.get("other.example.com.", Qtype::of(rt::A)).is_none());
    }

    /// RFC 8020: nothing exists below a name that does not exist. The resolver's
    /// walk already stops on an ancestor's NXDOMAIN; the cache agrees with it.
    #[test]
    fn test_nxdomain_denies_names_below_it() {
        let cache = NegativeCache::new(16);
        cache.insert(
            "gone.example.com.",
            Qtype::of(rt::A),
            &nxdomain_for("gone.example.com."),
            false,
        );

        assert!(cache.get("a.gone.example.com.", Qtype::of(rt::A)).is_some());
        assert!(cache
            .get("deep.b.gone.example.com.", Qtype::of(rt::AAAA))
            .is_some());
        // But not above it, and not beside it.
        assert!(cache.get("example.com.", Qtype::of(rt::A)).is_none());
        assert!(cache.get("gone2.example.com.", Qtype::of(rt::A)).is_none());
    }

    /// NODATA is about one type. Denying the others would deny records that
    /// exist — the name is there, after all.
    #[test]
    fn test_nodata_is_cached_for_that_type_only() {
        let cache = NegativeCache::new(16);
        let response = negative(
            "www.example.com.",
            ResponseCode::Ok,
            vec![soa_record("example.com.", 300, Ttl::from_secs(3600))],
        );
        cache.insert("www.example.com.", Qtype::of(rt::AAAA), &response, false);

        let answer = cache
            .get("www.example.com.", Qtype::of(rt::AAAA))
            .expect("cached");
        assert_eq!(answer.rcode, ResponseCode::Ok, "NODATA is NOERROR");
        assert!(
            cache.get("www.example.com.", Qtype::of(rt::A)).is_none(),
            "another type at the same name says nothing about this one"
        );
        assert!(cache
            .get("sub.www.example.com.", Qtype::of(rt::AAAA))
            .is_none());
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
        cache.insert("a.example.com.", Qtype::of(rt::A), &minimum_wins, false);
        assert!(cache.get("a.example.com.", Qtype::of(rt::A)).unwrap().ttl <= 60);

        let record_ttl_wins = negative(
            "b.example.com.",
            ResponseCode::NoSuchDomain,
            vec![soa_record("example.com.", 3600, Ttl::from_secs(30))],
        );
        cache.insert("b.example.com.", Qtype::of(rt::A), &record_ttl_wins, false);
        assert!(cache.get("b.example.com.", Qtype::of(rt::A)).unwrap().ttl <= 30);

        // A zone asking for a week gets the ceiling.
        let greedy = negative(
            "c.example.com.",
            ResponseCode::NoSuchDomain,
            vec![soa_record("example.com.", 604800, Ttl::from_secs(604800))],
        );
        cache.insert("c.example.com.", Qtype::of(rt::A), &greedy, false);
        let answer = cache.get("c.example.com.", Qtype::of(rt::A)).unwrap();
        assert!(answer.ttl <= MAX_NEGATIVE_TTL, "got {}", answer.ttl);
    }

    /// The records handed back must count down too, or a client re-caching them
    /// holds the answer for longer than we may.
    #[test]
    fn test_the_authority_records_count_down() {
        let cache = NegativeCache::new(16);
        let response = negative(
            "a.example.com.",
            ResponseCode::NoSuchDomain,
            vec![soa_record("example.com.", 90, Ttl::from_secs(3600))],
        );
        cache.insert("a.example.com.", Qtype::of(rt::A), &response, false);

        let answer = cache.get("a.example.com.", Qtype::of(rt::A)).unwrap();
        assert!(
            answer
                .authority
                .iter()
                .all(|rr| rr.ttl <= Ttl::from_secs(90)),
            "authority TTLs must not exceed the negative TTL"
        );
        assert!(
            answer.authority.iter().any(|rr| rr.rdata.rtype == rt::SOA),
            "RFC 2308 §2.1 wants the SOA on a negative answer"
        );
    }

    /// Without an SOA there is no negative TTL, so there is nothing to store.
    /// This is also what keeps a referral — NS records, no SOA — out of here.
    #[test]
    fn test_a_negative_answer_without_an_soa_is_not_cached() {
        let cache = NegativeCache::new(16);
        cache.insert(
            "a.example.com.",
            Qtype::of(rt::A),
            &negative("a.example.com.", ResponseCode::NoSuchDomain, Vec::new()),
            false,
        );
        assert!(cache.is_empty());
        assert!(cache.get("a.example.com.", Qtype::of(rt::A)).is_none());
    }

    #[test]
    fn test_zero_ttl_is_not_cached() {
        let cache = NegativeCache::new(16);
        cache.insert(
            "a.example.com.",
            Qtype::of(rt::A),
            &negative(
                "a.example.com.",
                ResponseCode::NoSuchDomain,
                vec![soa_record("example.com.", 0, Ttl::from_secs(3600))],
            ),
            false,
        );
        assert!(
            cache.get("a.example.com.", Qtype::of(rt::A)).is_none(),
            "0 means do not reuse"
        );
    }

    /// A failure is not an answer. Caching SERVFAIL would turn a transient
    /// upstream problem into a lasting one.
    #[test]
    fn test_servfail_is_not_cached() {
        let cache = NegativeCache::new(16);
        cache.insert(
            "a.example.com.",
            Qtype::of(rt::A),
            &negative(
                "a.example.com.",
                ResponseCode::ServerFailure,
                vec![soa_record("example.com.", 300, Ttl::from_secs(3600))],
            ),
            false,
        );
        assert!(cache.is_empty());
    }

    /// A response with records in the answer section is not this cache's to
    /// hold: a CNAME chain ending in NODATA is data the client needs.
    #[test]
    fn test_a_response_with_answers_is_not_cached() {
        let cache = NegativeCache::new(16);
        let mut response = negative(
            "www.example.com.",
            ResponseCode::Ok,
            vec![soa_record("example.com.", 300, Ttl::from_secs(3600))],
        );
        response.answers.push(ResourceRecord {
            name: "www.example.com.".into(),
            class: Class::new(1),
            ttl: Ttl::from_secs(300),
            rdata: RecordData::from_parsed(&ParsedRecord::CNAME("elsewhere.test.".into())).unwrap(),
        });
        cache.insert("www.example.com.", Qtype::of(rt::AAAA), &response, false);
        assert!(cache.is_empty());
    }

    /// The AD bit has to survive the cache, and must never be gained in it.
    #[test]
    fn test_validation_state_is_remembered() {
        let cache = NegativeCache::new(16);
        cache.insert(
            "a.example.com.",
            Qtype::of(rt::A),
            &nxdomain_for("a.example.com."),
            true,
        );
        cache.insert(
            "b.example.com.",
            Qtype::of(rt::A),
            &nxdomain_for("b.example.com."),
            false,
        );

        assert!(
            cache
                .get("a.example.com.", Qtype::of(rt::A))
                .unwrap()
                .secure
        );
        assert!(
            !cache
                .get("b.example.com.", Qtype::of(rt::A))
                .unwrap()
                .secure
        );
    }

    #[test]
    fn test_names_are_matched_case_insensitively() {
        let cache = NegativeCache::new(16);
        cache.insert(
            "NoPe.Example.COM.",
            Qtype::of(rt::A),
            &nxdomain_for("NoPe.Example.COM."),
            false,
        );
        assert!(cache.get("nope.example.com.", Qtype::of(rt::A)).is_some());
    }

    #[test]
    fn test_zero_capacity_stores_nothing() {
        let cache = NegativeCache::new(0);
        cache.insert(
            "a.example.com.",
            Qtype::of(rt::A),
            &nxdomain_for("a.example.com."),
            false,
        );
        assert!(cache.is_empty());
        assert!(cache.get("a.example.com.", Qtype::of(rt::A)).is_none());
    }

    #[test]
    fn test_capacity_is_bounded_across_both_kinds() {
        let cache = NegativeCache::new(4);
        for i in 0..10 {
            let name = format!("nope{i}.example.com.");
            cache.insert(&name, Qtype::of(rt::A), &nxdomain_for(&name), false);
            let nodata = negative(
                &name,
                ResponseCode::Ok,
                vec![soa_record("example.com.", 300, Ttl::from_secs(3600))],
            );
            cache.insert(&name, Qtype::of(rt::AAAA), &nodata, false);
        }
        assert!(cache.len() <= 4, "held {} entries", cache.len());
    }
}
