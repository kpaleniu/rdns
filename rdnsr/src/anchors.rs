//! Following a zone's DNSKEY RRset and keeping the trust anchors in step
//! (RFC 5011).
//!
//! One task with an owner and a lifetime: it holds the only file this process
//! writes, and it resolves to do its job, so it cannot be part of building the
//! resolver it uses.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context};
use rdns::dnssec_chain::ValidationState;
use rdns::record_types;
use rdns::resolver::{Resolver, SharedAnchors};
use rdns::rfc5011::{self, AnchorChange, ManagedAnchors};
use rdns::shutdown::{Busy, Stop};
use rdns::utils::current_unix_timestamp;
use rdns::{Qtype, QuerySection};

/// Follow the managed zones' DNSKEY RRsets and keep the anchors in step
/// (RFC 5011).
///
/// One task, not one per zone: the zones share a file, and one file wants one
/// writer.
pub(crate) fn spawn_anchor_manager(
    resolver: Arc<Resolver>,
    anchors: SharedAnchors,
    mut managed: ManagedAnchors,
    path: std::path::PathBuf,
    stop: Stop,
    busy: Busy,
) {
    tokio::spawn(async move {
        // Soon after start, not immediately: a resolver that cannot answer
        // its own first query would spend a retry.
        let mut wait = Duration::from_secs(60);
        loop {
            // No `Busy` across the sleep, which is hours long — only across
            // the probe-and-save, where the file is rewritten.
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = stop.wait() => return,
            }
            let _busy = busy.clone();
            wait = Duration::from_secs(rfc5011::retry_interval(0, 0));

            let mut changed = false;
            let mut soonest = u64::MAX;
            for zone in managed.zones() {
                match probe_zone(&resolver, &zone).await {
                    Ok(probe) => {
                        let Ok(zone_name) = rdns::Name::from_presentation(&zone) else {
                            continue;
                        };
                        let changes = managed.observe(
                            zone_name.as_ref(),
                            &probe.keys,
                            &probe.self_signers,
                            current_unix_timestamp(),
                        );
                        for change in &changes {
                            report(change);
                        }
                        changed |= !changes.is_empty();
                        soonest = soonest.min(rfc5011::query_interval(
                            probe.original_ttl,
                            probe.signature_remaining,
                        ));
                    }
                    Err(e) => tracing::warn!(%zone, "trust anchors: {e}"),
                }
            }

            if changed {
                // File first: validating against keys not yet recorded would
                // forget them on restart.
                match managed.save(&path) {
                    Ok(()) => anchors.replace(managed.trust_anchors()),
                    Err(e) => tracing::error!(
                        "trust anchors: {e} — keeping the previous set rather than \
                         validating against keys we could not write down"
                    ),
                }
            }
            if soonest != u64::MAX {
                wait = Duration::from_secs(soonest);
            }
        }
    });
}

/// What one DNSKEY probe learned.
struct AnchorProbe {
    keys: Vec<rdns::dnssec::Dnskey>,
    /// Those of them that signed the RRset — what a revocation rests on.
    self_signers: Vec<rdns::dnssec::Dnskey>,
    original_ttl: u32,
    signature_remaining: u64,
}

/// Resolve a zone's DNSKEY RRset, insisting it validated.
///
/// Secure or nothing. Insecure or Indeterminate for a zone we hold an anchor
/// for is not a zone gone unsigned but an answer we could not tie to the anchor,
/// and adopting keys from one adopts whatever answered. `ManagedAnchors::observe`
/// requires this and cannot check it itself.
async fn probe_zone(resolver: &Resolver, zone: &str) -> anyhow::Result<AnchorProbe> {
    let query = QuerySection {
        qname: rdns::Name::from_presentation(zone)
            .with_context(|| format!("{zone:?} is not a domain name"))?,
        qtype: Qtype::of(record_types::DNSKEY),
        qclass: rdns::QueryClass::IN,
    };
    let (response, state) = resolver
        .resolve_validated(&query)
        .await
        .context("resolving DNSKEY")?;

    if state != ValidationState::Secure {
        return Err(anyhow!(
            "the DNSKEY RRset did not validate ({state:?}) — not adopting anything from it"
        ));
    }

    let now = current_unix_timestamp();
    let keys: Vec<rdns::dnssec::Dnskey> = response
        .answers
        .iter()
        .filter_map(rdns::dnssec::Dnskey::from_record)
        .collect();
    if keys.is_empty() {
        return Err(anyhow!("a validated answer with no DNSKEY in it"));
    }

    // From the RRSIG covering the set: how long to cache it, and how long the
    // signature has left.
    let (original_ttl, signature_remaining) = response
        .answers
        .iter()
        .filter_map(rdns::dnssec::Rrsig::from_record)
        .filter(|sig| sig.type_covered == record_types::DNSKEY)
        .map(|sig| {
            (
                sig.original_ttl,
                (sig.expiration as u64).saturating_sub(now),
            )
        })
        .max_by_key(|(_, remaining)| *remaining)
        .unwrap_or((0, 0));

    Ok(AnchorProbe {
        self_signers: rfc5011::self_signers(query.qname.as_ref(), &response.answers, now),
        keys,
        original_ttl,
        signature_remaining,
    })
}

/// INFO throughout: a key rolls over months, so there is no volume in it, and
/// it is what an operator reconstructs a DNSSEC incident from.
fn report(change: &AnchorChange) {
    match change {
        AnchorChange::Pending { zone, key_tag } => tracing::info!(
            %zone,
            key_tag,
            "trust anchors: new key — trusted in {} days if it stays",
            rfc5011::ADD_HOLD_DOWN / 86_400
        ),
        AnchorChange::Trusted { zone, key_tag } => {
            tracing::info!(%zone, key_tag, "trust anchors: key is now a trust anchor")
        }
        AnchorChange::Withdrawn { zone, key_tag } => tracing::info!(
            %zone,
            key_tag,
            "trust anchors: key went away before its hold-down elapsed"
        ),
        AnchorChange::Absent { zone, key_tag } => tracing::info!(
            %zone,
            key_tag,
            "trust anchors: key is no longer published, but is still trusted \
             (revocation is how a key is retired)"
        ),
        AnchorChange::Returned { zone, key_tag } => {
            tracing::info!(%zone, key_tag, "trust anchors: key is published again")
        }
        AnchorChange::Revoked { zone, key_tag } => tracing::info!(
            %zone,
            key_tag,
            "trust anchors: key REVOKED itself — no longer a trust anchor"
        ),
        AnchorChange::Forgotten { zone, key_tag } => {
            tracing::info!(%zone, key_tag, "trust anchors: key is forgotten")
        }
    }
}
