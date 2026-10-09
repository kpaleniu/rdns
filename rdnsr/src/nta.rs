//! The negative trust anchor file and what keeps the set honest while the
//! resolver runs: reload on SIGHUP, expiry at `UNTIL`, and RFC 7646 §4's
//! recheck (`TODO.md` #176). What an NTA *is* is `rdns::nta`'s.
//!
//! Every change to the set — an anchor added, lifted, changed or lapsed —
//! flushes the caches at and below its node (§4, "the implementation SHOULD
//! remove all cached entries at and below the NTA node"), on add as well, so
//! an answer cached under the old decision does not outlive it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rdns::dnssec_chain::{TrustAnchors, ValidationState};
use rdns::nta::{NegativeTrustAnchors, Nta};
use rdns::shutdown::{Busy, Stop};
use rdns::{Qtype, QueryClass, QuerySection};

use crate::answer::Resolving;

/// How often an NTA's zone is asked whether it validates again: BIND's
/// `nta-recheck` default.
pub(crate) const RECHECK_INTERVAL_SECS: u64 = 300;

/// The longest the maintainer sleeps, so a clock that jumps is noticed.
const MAX_SLEEP_SECS: u64 = 60;

/// Read `path`, logging what the load noted.
pub(crate) fn load(
    path: &Path,
    now: u64,
    anchors: Option<&TrustAnchors>,
) -> anyhow::Result<NegativeTrustAnchors> {
    let (set, notes) = NegativeTrustAnchors::load(path, now, anchors)
        .with_context(|| "--negative-trust-anchors".to_string())?;
    for warning in notes.warnings {
        tracing::warn!("negative trust anchors: {warning}");
    }
    Ok(set)
}

/// Re-read the file and put it in force, or keep the set in force if it does
/// not load (§4's "the old set"). Called from the SIGHUP reload, off the
/// worker threads.
///
/// Returns the line a `reload` command reports (`TODO.md` #178).
pub(crate) fn reload(serving: &Resolving, path: &Path) -> String {
    let now = serving.ctx.clock.now();
    let anchors = serving.resolver.trust_anchors();
    match load(path, now, anchors.as_ref()) {
        Ok(set) => {
            let count = set.len();
            install(serving, set);
            format!("negative trust anchors: {count} in force")
        }
        Err(e) => {
            let line = format!("{e:#}; keeping the negative trust anchors in force");
            tracing::warn!("{line}");
            line
        }
    }
}

/// Replace the set, logging and flushing each node whose anchor came, went or
/// changed.
pub(crate) fn install(serving: &Resolving, new: NegativeTrustAnchors) {
    let ntas = serving.resolver.ntas();
    let old = ntas.snapshot();
    for nta in new.iter() {
        match old.iter().find(|o| o.name == nta.name) {
            Some(same) if same == nta => {}
            Some(_) => {
                tracing::info!(name = %nta.name, until = nta.until, "negative trust anchor changed");
                flush(serving, nta);
            }
            None => {
                tracing::info!(name = %nta.name, until = nta.until, "negative trust anchor added");
                flush(serving, nta);
            }
        }
    }
    for gone in old.iter().filter(|o| !new.iter().any(|n| n.name == o.name)) {
        tracing::info!(name = %gone.name, "negative trust anchor removed from the file");
        flush(serving, gone);
    }
    let count = new.len();
    ntas.update(|set| *set = new);
    serving.ctx.metrics.negative_trust_anchors(count);
}

/// Drop the anchors that have lapsed at `now`.
pub(crate) fn expire(serving: &Resolving, now: u64) -> usize {
    let ntas = serving.resolver.ntas();
    let gone = ntas.update(|set| set.expire(now));
    for nta in &gone {
        tracing::info!(name = %nta.name, until = nta.until, "negative trust anchor expired");
        flush(serving, nta);
    }
    if !gone.is_empty() {
        serving
            .ctx
            .metrics
            .negative_trust_anchors(ntas.snapshot().len());
    }
    gone.len()
}

/// Ask whether the zone under `nta` validates again, and lift the anchor if
/// it does: Secure, or provably Insecure (§4). The file is not rewritten; a
/// later SIGHUP reads it back and the next recheck lifts it again.
pub(crate) async fn recheck(serving: &Resolving, nta: &Nta) -> bool {
    let probe = QuerySection {
        qname: nta.name.clone(),
        qtype: Qtype::of(rdns::record_types::SOA),
        qclass: QueryClass::IN,
    };
    let validates = match serving.resolver.resolve_ignoring_ntas(&probe).await {
        Ok((_, state @ (ValidationState::Secure | ValidationState::Insecure))) => {
            tracing::info!(name = %nta.name, "negative trust anchor lifted: the zone validates ({state})");
            true
        }
        Ok((_, state)) => {
            tracing::debug!(name = %nta.name, "negative trust anchor kept: {state}");
            false
        }
        Err(e) => {
            tracing::debug!(name = %nta.name, "negative trust anchor kept: {e}");
            false
        }
    };
    if validates {
        let ntas = serving.resolver.ntas();
        if ntas.update(|set| set.lift(nta.name.as_ref())).is_some() {
            flush(serving, nta);
            serving
                .ctx
                .metrics
                .negative_trust_anchors(ntas.snapshot().len());
        }
    }
    validates
}

fn flush(serving: &Resolving, nta: &Nta) {
    let dropped = serving.caches.forget_at_or_below(nta.name.as_ref());
    tracing::debug!(name = %nta.name, dropped, "flushed the cache under a negative trust anchor");
}

/// The anchors whose recheck is due at `now`: never `norecheck`, and each at
/// most once per [`RECHECK_INTERVAL_SECS`] since `checked` last recorded it.
pub(crate) fn due(
    set: &NegativeTrustAnchors,
    checked: &std::collections::HashMap<rdns::Name, u64>,
    now: u64,
) -> Vec<Nta> {
    set.iter()
        .filter(|n| n.recheck)
        .filter(|n| {
            checked
                .get(&n.name)
                .is_none_or(|at| now.saturating_sub(*at) >= RECHECK_INTERVAL_SECS)
        })
        .cloned()
        .collect()
}

/// The file the set came from, for the SIGHUP reload.
#[derive(Clone)]
pub(crate) struct NtaFile(pub(crate) PathBuf);

/// Expire and recheck until stopped.
///
/// `Busy` across a recheck, which is a resolution a stop should let finish,
/// and never across the sleep (`CLAUDE.md` §9).
pub(crate) fn spawn_maintainer(serving: Arc<Resolving>, stop: Stop, busy: Busy) {
    tokio::spawn(async move {
        let mut checked: std::collections::HashMap<rdns::Name, u64> = Default::default();
        loop {
            let now = serving.ctx.clock.now();
            expire(&serving, now);
            let due = due(&serving.resolver.ntas().snapshot(), &checked, now);
            if !due.is_empty() {
                let _busy = busy.clone();
                for nta in due {
                    checked.insert(nta.name.clone(), now);
                    recheck(&serving, &nta).await;
                }
            }
            let set = serving.resolver.ntas().snapshot();
            checked.retain(|name, _| set.iter().any(|n| &n.name == name));
            let until_expiry = set
                .next_expiry()
                .map_or(MAX_SLEEP_SECS, |at| at.saturating_sub(now));
            let wait = until_expiry.clamp(1, MAX_SLEEP_SECS);
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
                _ = stop.wait() => return,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::answer::handle_query;
    use crate::testutil::*;
    use rdns::rpz::PolicyZones;
    use rdns::validation::Transport;
    use rdns::{DnsMessage, OpCode, ResponseCode};

    fn now() -> u64 {
        rdns::clock::current_unix_timestamp()
    }

    fn set(text: &str) -> NegativeTrustAnchors {
        NegativeTrustAnchors::parse(text, now(), None)
            .expect("parses")
            .0
    }

    async fn ask(serving: &Resolving, name: &str) -> DnsMessage {
        let mut msg = DnsMessage::try_from_bytes(&message(OpCode::Query, false)).expect("parses");
        msg.queries[0].qname = nm(name);
        let mut edns = rdns::Edns::with_payload_size(1232);
        edns.do_bit = true;
        msg.set_edns(edns);
        msg.ad = true;
        let bytes = handle_query(
            msg.to_bytes_within(512).expect("serialize"),
            test_peer(),
            now(),
            serving,
            Transport::Udp,
        )
        .await
        .expect("answered");
        DnsMessage::try_from_bytes(&bytes).expect("a reply")
    }

    /// A signed zone whose every answer carries a broken signature.
    fn broken() -> Arc<Resolving> {
        let (resolver, _) = SignedZone::new().upstream_altering(|reply| {
            for rr in &mut reply.answers {
                if rr.rdata.rtype() == rdns::record_types::RRSIG {
                    let mut bytes = rr.rdata.bytes().to_vec();
                    let last = bytes.len() - 1;
                    bytes[last] ^= 0xff;
                    rr.rdata = rdns::RecordData::new(rdns::record_types::RRSIG, bytes)
                        .expect("still an RRSIG");
                }
            }
        });
        serving(resolver, test_shell(), PolicyZones::default())
    }

    /// RFC 7646 §1.1: under an NTA a zone whose DNSSEC is broken is answered,
    /// AD clear, where without one it is SERVFAIL. Fails with the `covering`
    /// check removed from `resolve_validated`: SERVFAIL both times.
    #[tokio::test]
    async fn an_nta_answers_a_broken_zone_without_ad() {
        let serving = broken();
        assert_eq!(
            ask(&serving, "x.w.example.test.").await.rcode,
            ResponseCode::ServerFailure
        );
        install(&serving, set(&format!("example.test. {}\n", now() + 3600)));
        let reply = ask(&serving, "x.w.example.test.").await;
        assert_eq!(reply.rcode, ResponseCode::Ok);
        assert!(!reply.ad, "AD clear under an NTA");
        assert!(!reply.answers.is_empty());
    }

    /// A secure answer cached before the NTA is flushed when it is added, and
    /// what was cached under it is flushed when it lapses (§4). The gauge
    /// follows. Fails with `flush` doing nothing: the cached secure answer
    /// survives the add.
    #[tokio::test]
    async fn the_subtree_is_flushed_on_add_and_on_expiry() {
        let (resolver, _) = SignedZone::new().upstream();
        let serving = serving(resolver, test_shell(), PolicyZones::default());
        let a = rdns::Qtype::of(rdns::record_types::A);
        let name = nm("x.w.example.test.");

        assert!(ask(&serving, "x.w.example.test.").await.ad, "secure first");
        assert!(serving.caches.answer(name.as_ref(), a, false).is_some());

        let until = now() + 3600;
        install(&serving, set(&format!("w.example.test. {until}\n")));
        assert!(
            serving.caches.answer(name.as_ref(), a, false).is_none(),
            "flushed on add"
        );
        assert!(
            !ask(&serving, "x.w.example.test.").await.ad,
            "now under the NTA"
        );
        assert!(serving.caches.answer(name.as_ref(), a, false).is_some());
        assert!(serving
            .ctx
            .metrics
            .to_prometheus_format()
            .contains("dns_negative_trust_anchors 1"));

        assert_eq!(expire(&serving, until - 1), 0);
        assert_eq!(expire(&serving, until), 1, "lapsed at UNTIL");
        assert!(
            serving.caches.answer(name.as_ref(), a, false).is_none(),
            "flushed on expiry"
        );
        assert!(serving
            .ctx
            .metrics
            .to_prometheus_format()
            .contains("dns_negative_trust_anchors 0"));
    }

    /// §4's recheck: a zone that validates again has its anchor lifted; one
    /// still broken keeps it. `norecheck` is never due.
    #[tokio::test]
    async fn a_recheck_lifts_an_nta_once_the_zone_validates() {
        let (resolver, _) = SignedZone::new().upstream();
        let fixed = serving(resolver, test_shell(), PolicyZones::default());
        install(&fixed, set(&format!("example.test. {}\n", now() + 3600)));
        let nta = fixed
            .resolver
            .ntas()
            .snapshot()
            .iter()
            .next()
            .unwrap()
            .clone();
        assert!(recheck(&fixed, &nta).await, "the zone validates");
        assert!(fixed.resolver.ntas().snapshot().is_empty());

        let still = broken();
        install(&still, set(&format!("example.test. {}\n", now() + 3600)));
        let nta = still
            .resolver
            .ntas()
            .snapshot()
            .iter()
            .next()
            .unwrap()
            .clone();
        assert!(!recheck(&still, &nta).await);
        assert_eq!(still.resolver.ntas().snapshot().len(), 1);

        let both = set(&format!(
            "a.example. {0}\nb.example. {0} norecheck\n",
            now() + 3600
        ));
        let due_now = due(&both, &Default::default(), now());
        assert_eq!(due_now.len(), 1);
        assert_eq!(due_now[0].name, nm("a.example."));
        let checked = [(nm("a.example."), now())].into_iter().collect();
        assert!(due(&both, &checked, now() + RECHECK_INTERVAL_SECS - 1).is_empty());
        assert_eq!(due(&both, &checked, now() + RECHECK_INTERVAL_SECS).len(), 1);
    }

    /// A file that does not load on SIGHUP keeps the set in force.
    #[tokio::test]
    async fn a_malformed_file_keeps_the_set() {
        let (resolver, _) = SignedZone::new().upstream();
        let serving = serving(resolver, test_shell(), PolicyZones::default());
        install(&serving, set(&format!("example.test. {}\n", now() + 3600)));
        let dir = ScratchDir::new("nta-reload");
        let path = dir.write("ntas", "example.test. tomorrow\n");
        reload(&serving, &path);
        assert_eq!(serving.resolver.ntas().snapshot().len(), 1);

        let path = dir.write("ntas", "");
        reload(&serving, &path);
        assert!(
            serving.resolver.ntas().snapshot().is_empty(),
            "an empty file is no NTAs"
        );
    }
}
