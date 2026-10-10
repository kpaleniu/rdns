//! Holding a key-signing key's retirement until the parent's DS shows its
//! successor (`TODO.md` #180).
//!
//! `KeyTiming` makes a rollover four timestamps and no state. For a ZSK that is
//! the whole story; for a SEP key it is not, because the step that matters
//! happens at the parent: if its DS still names only the old key when that key
//! stops signing the DNSKEY RRset, the zone is bogus at every validator. So a
//! SEP key past `Inactive` or `Delete` keeps signing and stays published until
//!
//! 1. every parental agent's DS RRset holds a DS for another SEP key that is
//!    active and not itself retiring, and
//! 2. that has held for the DS RRset's TTL, which validators may cache it
//!    for (RFC 7583 §3.3.2's DS propagation).
//!
//! Knot's `submission.parent` with `parent-delay`, BIND's `parental-agents`.
//! Every agent must agree, and an agent that does not answer holds the key:
//! a stale anycast node of the parent must not have the key pulled from
//! under it. Unknown is hold, so a restart holds until the first check.
//!
//! The decision lands in [`RetirementHold`], which the key's own predicates
//! read, so the signer, the re-signing timer and verification follow it
//! without being told. DS answers are not validated: the operator chose the
//! agents, and `#key` or `+tls=` is how a path to one is trusted.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use rdns::dnssec::Ds;
use rdns::dnssec_key::{KeyTiming, RetirementHold, SigningKey};
use rdns::secondary::MasterSpec;
use rdns::tsig::{TsigKey, TsigKeyring};
use rdns::xfr::{DsAnswer, Master};
use rdns::xot::{TlsClientTrust, XotClient};
use rdns::Name;

/// How often the parent is asked while a roll is under way: Knot's
/// `check-interval` default. A constant, as the brief asked.
pub(crate) const CHECK_INTERVAL: Duration = Duration::from_secs(3600);

/// One parental agent: where to ask, and how.
#[derive(Clone)]
pub(crate) struct Agent {
    pub(crate) master: Master,
    pub(crate) key: Option<TsigKey>,
}

/// Where DS answers come from: the network, or a test.
pub(crate) trait DsSource: Send + Sync + 'static {
    fn ds(
        &self,
        agent: &Agent,
        zone: &Name,
    ) -> impl std::future::Future<Output = std::result::Result<DsAnswer, String>> + Send;
}

/// [`rdns::xfr::fetch_ds`], over TCP with TSIG or TLS as the agent says.
pub(crate) struct Network;

impl DsSource for Network {
    async fn ds(&self, agent: &Agent, zone: &Name) -> std::result::Result<DsAnswer, String> {
        rdns::xfr::fetch_ds(&agent.master, zone.as_ref(), agent.key.as_ref())
            .await
            .map_err(|e| e.to_string())
    }
}

/// A SEP key under the gate.
struct GatedKey {
    tag: u16,
    algorithm: u8,
    /// As the key file has it: the gate's question is about these times.
    timing: KeyTiming,
    /// The DS this key would have, per digest type, for matching.
    ds: Vec<Ds>,
    hold: RetirementHold,
    /// Retirement let through. One way: a key once let go is not held again.
    released: bool,
    /// The reason last logged, so a hold is logged once and not hourly.
    logged: Option<String>,
}

impl GatedKey {
    fn retiring(&self, now: u64) -> bool {
        self.timing.inactive.is_some_and(|t| now >= t)
            || self.timing.delete.is_some_and(|t| now >= t)
    }

    fn matches(&self, ds: &Ds) -> bool {
        self.ds.iter().any(|own| {
            own.key_tag == ds.key_tag
                && own.algorithm == ds.algorithm
                && own.digest_type == ds.digest_type
                && own.digest == ds.digest
        })
    }
}

struct GatedZone {
    origin: Name,
    agents: Vec<Agent>,
    keys: Vec<GatedKey>,
    /// Since when every agent has shown a successor, unbroken.
    shown_since: Option<u64>,
}

/// Every gated zone, shared by the check task and `rdnsctl status`.
#[derive(Clone, Default)]
pub(crate) struct ParentalGate(Arc<Mutex<Vec<GatedZone>>>);

/// What one check concluded about a zone.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Checked {
    /// A key was let go: the zone needs re-signing now.
    pub(crate) released: bool,
    /// When to look again.
    pub(crate) next: u64,
}

impl ParentalGate {
    /// The gate over `agents`, holding every SEP key that has an `Inactive`
    /// or `Delete` until the first check answers.
    ///
    /// Refused, naming the agent: a zone this server does not sign, which
    /// covers one it does not serve.
    pub(crate) fn new<'k>(
        agents: HashMap<Name, Vec<Agent>>,
        keys_for: impl Fn(&Name) -> Option<Vec<&'k SigningKey>>,
    ) -> Result<ParentalGate> {
        let mut zones = Vec::new();
        for (origin, agents) in agents {
            let Some(keys) = keys_for(&origin) else {
                bail!(
                    "--parental-agent {origin}@...: this server does not sign {origin}, so it \
                     has no key whose retirement the parent's DS could hold"
                );
            };
            let keys = keys
                .into_iter()
                .filter(|k| k.is_sep())
                .map(|k| {
                    let timing = k.file_timing();
                    let hold = k.retirement_hold();
                    let gated = timing.inactive.is_some() || timing.delete.is_some();
                    hold.set(gated);
                    GatedKey {
                        tag: k.key_tag(),
                        algorithm: k.algorithm().code(),
                        timing,
                        // SHA-1, SHA-256, SHA-384 (RFC 3658, 4509, 6605): what
                        // a parent may hold.
                        ds: [1, 2, 4].iter().filter_map(|t| k.ds(*t).ok()).collect(),
                        hold,
                        released: !gated,
                        logged: None,
                    }
                })
                .collect();
            zones.push(GatedZone {
                origin,
                agents,
                keys,
                shown_since: None,
            });
        }
        Ok(ParentalGate(Arc::new(Mutex::new(zones))))
    }

    fn zones(&self) -> std::sync::MutexGuard<'_, Vec<GatedZone>> {
        // Each update is whole; a panic elsewhere leaves nothing half-done.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.zones().is_empty()
    }

    /// The held keys, for `rdnsctl status`: zone, key tag, the reason.
    pub(crate) fn held(&self) -> Vec<(Name, u16, String)> {
        self.zones()
            .iter()
            .flat_map(|z| {
                z.keys.iter().filter(|k| k.hold.is_held()).map(|k| {
                    (
                        z.origin.clone(),
                        k.tag,
                        k.logged.clone().unwrap_or_else(|| "not checked yet".into()),
                    )
                })
            })
            .collect()
    }

    /// Check every zone once at `now`. True if any key was let go.
    pub(crate) async fn check<S: DsSource>(&self, source: &S, now: u64) -> (bool, u64) {
        let work: Vec<(usize, Name, Vec<Agent>, bool)> = self
            .zones()
            .iter()
            .enumerate()
            .map(|(i, z)| (i, z.origin.clone(), z.agents.clone(), needs_asking(z, now)))
            .collect();
        let mut released = false;
        let mut next = now + CHECK_INTERVAL.as_secs();
        for (i, origin, agents, ask) in work {
            // Asked outside the lock: an hour-long hold is no reason for a
            // status read to wait on a TCP connect.
            let answers = if ask {
                let mut answers = Vec::new();
                for agent in &agents {
                    answers.push((agent.master.to_string(), source.ds(agent, &origin).await));
                }
                Some(answers)
            } else {
                None
            };
            let checked = decide(&mut self.zones()[i], now, answers);
            released |= checked.released;
            next = next.min(checked.next);
        }
        (released, next)
    }
}

/// Whether anything at `now` needs the parent asked: a SEP key inside its
/// sync window, or past a retirement time and not yet let go.
fn needs_asking(zone: &GatedZone, now: u64) -> bool {
    zone.keys
        .iter()
        .any(|k| k.timing.is_sync_published(now) || (k.retiring(now) && !k.released))
}

/// One zone's check: the pure part, so the timing is testable without a clock.
fn decide(
    zone: &mut GatedZone,
    now: u64,
    answers: Option<Vec<(String, std::result::Result<DsAnswer, String>)>>,
) -> Checked {
    let interval = CHECK_INTERVAL.as_secs();
    // The next retirement time not yet reached: the gate has to be there when
    // it arrives, or the signer would find nothing to stop it.
    let upcoming = zone
        .keys
        .iter()
        .filter(|k| !k.released)
        .flat_map(|k| [k.timing.inactive, k.timing.delete])
        .flatten()
        .filter(|t| *t > now)
        .min();
    let mut next = upcoming.map_or(now + interval, |t| t.min(now + interval));

    let Some(answers) = answers else {
        return Checked {
            released: false,
            next,
        };
    };
    let retiring: Vec<usize> = (0..zone.keys.len())
        .filter(|i| zone.keys[*i].retiring(now) && !zone.keys[*i].released)
        .collect();

    // A successor: a SEP key active now and not retiring.
    let successors: Vec<usize> = (0..zone.keys.len())
        .filter(|i| {
            let k = &zone.keys[*i];
            k.timing.is_active(now) && !k.retiring(now)
        })
        .collect();
    let mut why = None;
    let mut ttl = 0;
    for (agent, answer) in &answers {
        match answer {
            Err(e) => {
                why.get_or_insert_with(|| format!("parental agent {agent} did not answer: {e}"));
            }
            Ok(answer) => {
                ttl = ttl.max(u64::from(answer.ttl));
                let shown = answer
                    .ds
                    .iter()
                    .any(|ds| successors.iter().any(|s| zone.keys[*s].matches(ds)));
                if !shown {
                    let tags: Vec<String> =
                        answer.ds.iter().map(|d| d.key_tag.to_string()).collect();
                    why.get_or_insert_with(|| {
                        format!(
                            "parental agent {agent} holds DS for key tag(s) [{}], none for an \
                             active successor",
                            tags.join(", ")
                        )
                    });
                }
            }
        }
    }
    let mut released = false;
    let why = match why {
        Some(why) => {
            zone.shown_since = None;
            why
        }
        None => {
            let since = *zone.shown_since.get_or_insert(now);
            let at = since.saturating_add(ttl);
            if now >= at {
                for i in &retiring {
                    let key = &mut zone.keys[*i];
                    key.released = true;
                    key.hold.set(false);
                    key.logged = None;
                    tracing::info!(
                        zone = %zone.origin,
                        "key {} retires: every parental agent has shown a successor's DS \
                         for {ttl}s",
                        key.tag
                    );
                    released = true;
                }
                return Checked { released, next };
            }
            next = next.min(at);
            format!("waiting out the DS TTL of {ttl}s, until {at}")
        }
    };
    for i in retiring {
        let key = &mut zone.keys[i];
        if key.logged.as_deref() != Some(why.as_str()) {
            tracing::warn!(
                zone = %zone.origin,
                "key {} (algorithm {}) is past its retirement time and held: {why}",
                key.tag,
                key.algorithm
            );
            key.logged = Some(why.clone());
        }
    }
    Checked { released, next }
}

/// `--parental-agent ZONE@ENDPOINT`, parsed and resolved, by zone.
///
/// The endpoint is `--secondary`'s (`rdns::endpoint`), so `#key` and
/// `+tls=` mean what they mean there (`CLAUDE.md` §7).
pub(crate) fn parse_agents(
    specs: &[String],
    keys: &TsigKeyring,
    xot: Option<&TlsClientTrust>,
) -> Result<HashMap<Name, Vec<Agent>>> {
    let mut agents: HashMap<Name, Vec<Agent>> = HashMap::new();
    for text in specs {
        let spec = MasterSpec::parse(text).map_err(|e| anyhow!("--parental-agent {e}"))?;
        let key = crate::replication::resolve_key(&spec, keys, "--parental-agent")?;
        let master = match (&spec.tls, xot) {
            (None, _) => Master::plain(spec.master),
            (Some(name), Some(trust)) => {
                Master::over_tls(spec.master, XotClient::new(trust.clone(), name.clone()))
            }
            (Some(name), None) => bail!(
                "--parental-agent {text}: +tls={name} needs --transfer-tls-ca to check the \
                 agent's certificate against"
            ),
        };
        agents
            .entry(spec.zone)
            .or_default()
            .push(Agent { master, key });
    }
    Ok(agents)
}

/// Check every hour, or sooner when a step is due, and ask for a re-sign
/// whenever a key is let go. Ends on `stop`.
#[expect(
    clippy::disallowed_methods,
    reason = "the DS poll interval is the event"
)]
pub(crate) async fn run<S: DsSource>(
    gate: ParentalGate,
    source: S,
    clock: rdns::clock::Clock,
    resign: impl Fn() + Send,
    stop: rdns::shutdown::Stop,
) {
    loop {
        let now = clock.now();
        let (released, next) = gate.check(&source, now).await;
        if released {
            resign();
        }
        let wait = Duration::from_secs(next.saturating_sub(clock.now()).max(1));
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = stop.wait() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rdns::dnssec::{dnskeys_in, rrsigs_in, verify_rrset, Rrset, RrsetProof};
    use rdns::dnssec::{DNSKEY_FLAG_SEP, DNSKEY_FLAG_ZONE};
    use rdns::dnssec_key::SigningAlgorithm;
    use rdns::record_types;
    use rdns::zone_signer::{sign_zone, SigningPolicy};
    use rdns::{Class, Qtype, RecordData, ResourceRecord};

    use super::*;
    use crate::testutil::nm;

    /// A moment well inside every signature's validity.
    fn base() -> u64 {
        rdns::clock::current_unix_timestamp()
    }

    const INACTIVE: u64 = 1000;
    const DELETE: u64 = 2000;

    /// The old KSK retires at `INACTIVE`/`DELETE`; the new one is active and
    /// retires never; the ZSK retires at `INACTIVE` as well.
    struct Keys {
        all: Vec<SigningKey>,
        old: usize,
        new: usize,
        zsk: usize,
    }

    fn keys(t0: u64) -> Keys {
        let make = |flags, timing: KeyTiming| {
            SigningKey::generate(SigningAlgorithm::EcdsaP256Sha256, "example.com.", flags)
                .expect("a key")
                .with_timing(timing)
                .expect("ordered")
        };
        let ksk = DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP;
        let retiring = KeyTiming {
            inactive: Some(t0 + INACTIVE),
            delete: Some(t0 + DELETE),
            ..KeyTiming::default()
        };
        Keys {
            all: vec![
                make(ksk, retiring),
                make(ksk, KeyTiming::default()),
                make(DNSKEY_FLAG_ZONE, retiring),
            ],
            old: 0,
            new: 1,
            zsk: 2,
        }
    }

    /// Answers by agent address; counts what it was asked.
    #[derive(Default)]
    struct Agents {
        answers: Mutex<HashMap<SocketAddr, std::result::Result<DsAnswer, String>>>,
        asked: AtomicUsize,
    }

    impl Agents {
        fn set(&self, agent: SocketAddr, answer: std::result::Result<DsAnswer, String>) {
            self.answers.lock().unwrap().insert(agent, answer);
        }
    }

    impl DsSource for Arc<Agents> {
        async fn ds(&self, agent: &Agent, _: &Name) -> std::result::Result<DsAnswer, String> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            self.answers
                .lock()
                .unwrap()
                .get(&agent.master.addr)
                .cloned()
                .unwrap_or_else(|| Err("no answer".into()))
        }
    }

    fn agent(n: u8) -> Agent {
        Agent {
            master: Master::plain(SocketAddr::from(([192, 0, 2, n], 53))),
            key: None,
        }
    }

    fn ds_of(key: &SigningKey, ttl: u32) -> std::result::Result<DsAnswer, String> {
        Ok(DsAnswer {
            ds: vec![key.ds(2).expect("a DS")],
            ttl,
        })
    }

    fn gate(keys: &Keys, agents: Vec<Agent>) -> ParentalGate {
        let by_zone = HashMap::from([(nm("example.com."), agents)]);
        ParentalGate::new(by_zone, |_| Some(keys.all.iter().collect())).expect("a gate")
    }

    /// The DNSKEY RRset signed at `now`, and which key tags signed it, each
    /// signature checked with `verify_rrset`.
    fn dnskey_signers(keys: &Keys, now: u64) -> Vec<u16> {
        let zone = rdns::zone::parse_zone_file(
            "$TTL 300\n@ IN SOA ns admin 1 3600 600 86400 300\n@ IN NS ns\nns IN A 192.0.2.1\n",
            "example.com.",
        )
        .expect("parses");
        let signed = sign_zone(
            &zone,
            &keys.all,
            &SigningPolicy::valid_for(now, 30 * 86_400),
        )
        .expect("signs");
        let apex: Vec<ResourceRecord> = [record_types::DNSKEY, record_types::RRSIG]
            .into_iter()
            .flat_map(|t| signed.query(nm("example.com.").as_ref(), Qtype::of(t)))
            .map(|r| ResourceRecord {
                name: r.name.to_owned(),
                class: r.class,
                ttl: r.ttl,
                rdata: r.rdata.to_owned(),
            })
            .collect();
        let rrsigs = rrsigs_in(&apex);
        let dnskeys = dnskeys_in(&apex);
        let rdatas: Vec<RecordData> = apex
            .iter()
            .filter(|r| r.rdata.rtype() == record_types::DNSKEY)
            .map(|r| r.rdata.clone())
            .collect();
        let apex_name = nm("example.com.");
        let rrset = Rrset::new(apex_name.as_ref(), record_types::DNSKEY, Class::IN, &rdatas);
        rrsigs
            .iter()
            .filter(|s| s.type_covered == record_types::DNSKEY)
            .map(|sig| {
                let proof = verify_rrset(
                    &rrset,
                    std::slice::from_ref(sig),
                    &dnskeys,
                    nm("example.com.").as_ref(),
                    now,
                );
                assert!(
                    matches!(proof, RrsetProof::Verified { .. }),
                    "key {}: {proof:?}",
                    sig.key_tag
                );
                sig.key_tag
            })
            .collect()
    }

    /// The parent shows only the old KSK's DS: past both its times it still
    /// signs the DNSKEY RRset and is still published, and the hold reason
    /// does not change from check to check (logged once).
    #[tokio::test]
    async fn a_ksk_is_held_while_the_parent_shows_only_its_own_ds() {
        let t0 = base();
        let keys = keys(t0);
        let old = &keys.all[keys.old];
        let gate = gate(&keys, vec![agent(1)]);
        let agents = Arc::new(Agents::default());
        agents.set(agent(1).master.addr, ds_of(old, 3600));

        let now = t0 + DELETE + 10;
        gate.check(&agents, now).await;
        assert!(old.is_active(now) && old.is_published(now));
        let signers = dnskey_signers(&keys, now);
        assert!(
            signers.contains(&old.key_tag()),
            "{signers:?} old {} new {}",
            old.key_tag(),
            keys.all[keys.new].key_tag()
        );
        let held = gate.held();
        assert_eq!(held.len(), 1, "{held:?}");
        assert!(
            held[0].2.contains("none for an active successor"),
            "{held:?}"
        );
        gate.check(&agents, now + 3600).await;
        assert_eq!(gate.held(), held, "the same reason, so not logged again");
    }

    /// The successor's DS appears with TTL 3600: no retirement before the
    /// TTL has passed, then retirement.
    #[tokio::test]
    async fn a_ksk_retires_one_ds_ttl_after_the_successor_appears() {
        let t0 = base();
        let keys = keys(t0);
        let (old, new) = (&keys.all[keys.old], &keys.all[keys.new]);
        let gate = gate(&keys, vec![agent(1)]);
        let agents = Arc::new(Agents::default());
        agents.set(agent(1).master.addr, ds_of(new, 3600));

        let seen = t0 + INACTIVE + 5;
        let (released, next) = gate.check(&agents, seen).await;
        assert!(!released);
        assert_eq!(
            next,
            t0 + DELETE,
            "the Delete comes before the TTL runs out"
        );
        let (released, _) = gate.check(&agents, seen + 3599).await;
        assert!(
            !released && old.is_active(seen + 3599),
            "not a second early"
        );
        let (released, _) = gate.check(&agents, seen + 3600).await;
        assert!(released);
        assert!(!old.is_active(seen + 3600), "retired");
        assert!(!dnskey_signers(&keys, seen + 3600).contains(&old.key_tag()));
        assert!(gate.held().is_empty());
    }

    #[tokio::test]
    async fn every_agent_must_agree_and_one_silent_agent_holds() {
        let t0 = base();
        let keys = keys(t0);
        let (old, new) = (&keys.all[keys.old], &keys.all[keys.new]);
        let gate = gate(&keys, vec![agent(1), agent(2)]);
        let agents = Arc::new(Agents::default());
        let now = t0 + INACTIVE + 5;

        agents.set(agent(1).master.addr, ds_of(new, 60));
        agents.set(agent(2).master.addr, ds_of(old, 60));
        gate.check(&agents, now).await;
        gate.check(&agents, now + 3600).await;
        assert!(old.is_active(now + 3600), "one stale agent holds");

        agents.set(agent(2).master.addr, Err("timed out".into()));
        gate.check(&agents, now + 7200).await;
        assert!(old.is_active(now + 7200), "a silent agent holds");
        assert!(gate.held()[0].2.contains("did not answer"));

        agents.set(agent(2).master.addr, ds_of(new, 60));
        gate.check(&agents, now + 7300).await;
        assert!(old.is_active(now + 7300), "the TTL starts now");
        let (released, _) = gate.check(&agents, now + 7360).await;
        assert!(released && !old.is_active(now + 7360));
    }

    /// Unknown is hold: a new gate, as after a restart, holds before any
    /// check has answered — and a ZSK past the same times retires on them.
    #[test]
    fn a_restart_holds_until_the_first_check_and_a_zsk_is_never_held() {
        let t0 = base();
        let keys = keys(t0);
        let _gate = gate(&keys, vec![agent(1)]);
        let now = t0 + DELETE + 10;
        assert!(keys.all[keys.old].is_active(now), "held with nothing asked");
        assert!(
            !keys.all[keys.zsk].is_published(now),
            "the ZSK went on time"
        );
    }

    #[test]
    fn without_agents_the_timestamps_rule() {
        let t0 = base();
        let keys = keys(t0);
        let gate = ParentalGate::new(HashMap::new(), |_| Some(keys.all.iter().collect()))
            .expect("an empty gate");
        assert!(gate.is_empty());
        assert!(!keys.all[keys.old].is_active(t0 + INACTIVE));
    }

    /// Nothing in a sync window and nothing past a time: no query goes out,
    /// and the next look is at the old KSK's Inactive.
    #[tokio::test]
    async fn nothing_is_asked_while_no_ksk_step_is_near() {
        let t0 = base();
        let keys = keys(t0);
        let gate = gate(&keys, vec![agent(1)]);
        let agents = Arc::new(Agents::default());
        let (_, next) = gate.check(&agents, t0 + 10).await;
        assert_eq!(agents.asked.load(Ordering::SeqCst), 0);
        assert_eq!(next, t0 + INACTIVE);
    }

    #[test]
    fn a_zone_this_server_does_not_sign_is_refused() {
        let by_zone = HashMap::from([(nm("example.com."), vec![agent(1)])]);
        let refused = ParentalGate::new(by_zone, |_| None).err().expect("refused");
        assert!(refused.to_string().contains("does not sign"), "{refused}");
    }
}
