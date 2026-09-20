//! Telling the secondaries, and who they are (RFC 1996).
//!
//! Split out of `main.rs` by `TODO.md` #83, on #38d's criterion rather than on
//! line count: the cluster has an owner and a lifetime, and its one reach-back
//! into `main` was `build_notify_policy` taking `&Cli` to read one field.

use anyhow::{anyhow, Result};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use rdns::notify::{self, NotifyOutcome, NotifyPeer, NotifyPolicy};
use rdns::shutdown::Busy;
use rdns::socket::bind_addr_for;
use rdns::tsig::{self, TsigKeyring};
use rdns::zone::Zone;
use rdns::{DnsMessage, Name, NameRef, ResourceRecord, Serial};

use crate::absolute_name;
use crate::zones::Zones;

/// `addr[:port][#keyname]` for a secondary, resolved against the keyring.
///
/// The spelling is `rdns::endpoint`'s, shared with `--secondary`, and the key
/// lookup is `NotifyTarget::resolve` — so a `#key` naming nothing is a startup
/// error here for the same reason and in the same words as there.
fn parse_notify_peers(specs: &[String], keys: &TsigKeyring) -> Result<Vec<NotifyPeer>> {
    let mut peers = Vec::new();
    for spec in specs {
        let spec = spec.trim();
        if spec.is_empty() {
            continue;
        }
        peers.push(
            notify::NotifyTarget::parse(spec)
                .map_err(|e| anyhow!("--also-notify {e}"))?
                .resolve(keys)?,
        );
    }
    Ok(peers)
}

/// The global list plus whatever `[zones."x"].also-notify` adds per zone.
///
/// The per-zone half is #46c: it was parsed into `PerZone::notify` and read by
/// nothing, so a config that named extra secondaries for one zone was accepted
/// and silently ignored, with `docs/spec/03-authoritative-server.md` and
/// `06-operations.md` both documenting it as working.
pub(crate) fn build_notify_policy(
    global: &[String],
    per_zone: &BTreeMap<String, Vec<String>>,
    keys: &TsigKeyring,
) -> Result<NotifyPolicy> {
    let mut policy = NotifyPolicy::new(parse_notify_peers(global, keys)?);
    for (origin, specs) in per_zone {
        let zone = Name::from_presentation(&absolute_name(origin))
            .map_err(|e| anyhow!("zone {origin:?}: {e}"))?;
        policy.add_zone(zone.as_ref(), parse_notify_peers(specs, keys)?);
    }
    Ok(policy)
}

/// Tell every secondary about the zones whose serial moved since `announced`,
/// and return the serials now announced.
///
/// Called after each load. A zone whose serial did not move is not news, and one
/// that went backwards is not either — a secondary compares serials and would
/// ignore it, so sending would be noise.
pub(crate) async fn announce_zones(
    zone_map: &Arc<RwLock<Zones>>,
    announced: &[(Name, Serial)],
    notify: &NotifyPolicy,
    busy: &Busy,
) -> Vec<(Name, Serial)> {
    let (current, pending) = {
        let zones = zone_map.read().await;
        let all: Vec<&Zone> = zones.values().map(Arc::as_ref).collect();
        let current = notify::zone_serials(&all);
        let changed = notify::changed_zones(announced, &current);
        // Build the messages under the lock, send them outside it: a NOTIFY that
        // goes unanswered takes seconds to retry, and holding the zone map that
        // long would block a reload behind the network.
        let pending: Vec<(Name, Serial, Option<rdns::ResourceRecord>)> = changed
            .iter()
            .filter_map(|(name, serial)| {
                zones
                    .get(&*name.as_ref().folded())
                    .map(|zone| (name.clone(), *serial, zone.apex_soa_record()))
            })
            .collect();
        (current, pending)
    };

    if notify.is_empty() || pending.is_empty() {
        return current;
    }
    for (zone, serial, soa) in pending {
        // Per zone, not once for the whole run: `[zones."x"].also-notify` adds
        // to the global list for that zone alone (#46c).
        for peer in notify.targets_for(zone.as_ref()) {
            let peer = peer.clone();
            let zone = zone.clone();
            let soa = soa.clone();
            // Fire-and-forget, but not unaccounted-for: a NOTIFY dropped at
            // shutdown is a secondary that waits out a whole REFRESH before it
            // learns of a change we already knew about, so the drain covers it.
            let busy = busy.clone();
            tokio::spawn(async move {
                let _busy = busy;
                send_notify(zone.as_ref(), serial, soa, peer).await;
            });
        }
    }
    current
}

/// Tell the configured secondaries that a zone *we* replicate has moved.
///
/// RFC 1996 §3.2's "master" is whoever serves the zone to someone, which a
/// secondary in the middle of a tree is. Without this, `announce_zones` covers
/// only the moments a *primary* learns of a change — startup and SIGHUP — while a
/// secondary learns of one by transferring it and says nothing, so the first
/// level of a tree updates at once and every level below it waits out a refresh
/// timer.
///
/// Spawned rather than awaited for the same reason the primary's announcements
/// are: an unanswered NOTIFY takes seconds to give up on, and a refresh should
/// not be held behind the network to tell somebody about work it has finished.
pub(crate) fn announce_transfer(
    zone: NameRef<'_>,
    serial: Serial,
    soa: Option<ResourceRecord>,
    notify: &NotifyPolicy,
    busy: &Busy,
) {
    for peer in notify.targets_for(zone) {
        let (zone, soa, peer) = (zone.to_owned(), soa.clone(), peer.clone());
        // Accounted for by the drain, like the primary's announcements: a NOTIFY
        // dropped at shutdown costs the level below us a whole REFRESH before it
        // learns of a change that has already reached us.
        let busy = busy.clone();
        tokio::spawn(async move {
            let _busy = busy;
            send_notify(zone.as_ref(), serial, soa, peer).await;
        });
    }
}

/// Send one NOTIFY, retrying until it is answered (RFC 1996 §3.6).
///
/// Signed when the target carries a key (RFC 8945), because a secondary's notify
/// ACL can demand one and two of the three this tree is tested against do when
/// asked — `TODO.md` #46a. The reply is then verified: an unsigned or wrongly
/// signed answer to a signed request is not an answer.
///
/// Every rcode ends the retries, because the secondary has the message and
/// repeating it would not change its mind — but only NOERROR means it will
/// refresh, and the difference is logged rather than flattened into
/// "acknowledged" (#46b).
///
/// Giving up after [`notify::NOTIFY_ATTEMPTS`] is safe because the secondary's
/// refresh timer is the backstop this is an optimisation over.
async fn send_notify(
    zone: NameRef<'_>,
    serial: Serial,
    soa: Option<rdns::ResourceRecord>,
    peer: NotifyPeer,
) {
    let target = peer.addr;
    let Ok(socket) = UdpSocket::bind(bind_addr_for(target)).await else {
        tracing::warn!("NOTIFY {zone} to {peer}: could not open a socket");
        return;
    };

    let mut wait = Duration::from_secs(notify::NOTIFY_RETRY_SECS);
    let mut last_tsig_error: Option<&'static str> = None;

    for attempt in 1..=notify::NOTIFY_ATTEMPTS {
        let id = rdns::rand_id();
        let msg = notify::notify_request(zone, soa.clone(), id);
        // `to_bytes_within` sizes the buffer to what the message needs and
        // only truncates past the ceiling, so the wire maximum here is not a
        // 64 KiB allocation. It replaces a fixed 512-byte buffer that
        // `to_bytes` would have refused to write into for a zone whose SOA
        // carries long enough names -- losing the notification, with
        // "could not serialize" as the only sign.
        let Ok(mut packet) = msg.to_bytes_within(u16::MAX as usize) else {
            tracing::warn!("NOTIFY {zone}: could not serialize");
            return;
        };
        // The MAC of our request opens the digest the reply is verified against
        // (RFC 8945 §4.3.3), so it has to be kept — the same sequence
        // `rdns::xfr` uses on the client side of a transfer.
        let mut request_mac = Vec::new();
        if let Some(key) = &peer.key {
            match tsig::sign_request(packet, key, tsig::now()) {
                Ok(signed) => {
                    request_mac = tsig::request_mac(&signed).unwrap_or_default();
                    packet = signed;
                }
                Err(e) => {
                    tracing::warn!("NOTIFY {zone} to {peer}: could not sign: {e}");
                    return;
                }
            }
        }
        if socket.send_to(&packet, target).await.is_err() {
            tracing::warn!("NOTIFY {zone} to {peer}: send failed");
            return;
        }

        // A NOTIFY reply echoes the question and carries no data; 4 KiB is well
        // past anything one plus a TSIG can weigh.
        let mut reply = vec![0u8; 4096];
        // Something answered, but not this? Treat it as no answer rather than as
        // an acknowledgement: an off-path reply should not be able to silence a
        // notification. A TSIG that does not verify is the same case — which is
        // why this keeps retrying rather than returning, and remembers the
        // reason for the line at the end.
        if let Ok(Ok((n, _))) = tokio::time::timeout(wait, socket.recv_from(&mut reply)).await {
            let packet = &reply[..n];
            let verified = match &peer.key {
                Some(key) => {
                    match tsig::check_response(packet, key, &request_mac, true, tsig::now()) {
                        Ok(_) => true,
                        Err(e) => {
                            last_tsig_error = Some(e.reason());
                            false
                        }
                    }
                }
                None => true,
            };
            if verified {
                if let Ok(parsed) = DnsMessage::try_from_bytes(packet) {
                    match notify::outcome(&parsed, id) {
                        Some(NotifyOutcome::Accepted) => {
                            tracing::info!("NOTIFY {zone} serial {serial} to {peer}: accepted");
                            return;
                        }
                        // It arrived and was refused, so stop — but say so.
                        // Nothing is going to refresh, and the zone is stale on
                        // that secondary until its REFRESH timer fires.
                        Some(NotifyOutcome::Rejected(rcode)) => {
                            tracing::warn!(
                                "NOTIFY {zone} serial {serial} to {peer}: refused ({rcode:?}) — \
                                 that secondary will not refresh until its REFRESH timer fires{}",
                                if peer.key.is_none() {
                                    ". This NOTIFY was unsigned; if that secondary's \
                                     notify ACL names a key, give it here as \
                                     --also-notify ADDR#KEYNAME"
                                } else {
                                    ""
                                }
                            );
                            return;
                        }
                        None => {}
                    }
                }
            }
        }
        if attempt < notify::NOTIFY_ATTEMPTS {
            wait *= 2;
        }
    }
    tracing::warn!(
        "NOTIFY {zone} serial {serial} to {peer}: no answer after {} attempts{}",
        notify::NOTIFY_ATTEMPTS,
        match last_tsig_error {
            Some(reason) => format!(" (the last reply did not verify: {reason})"),
            None => String::new(),
        }
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::nm;
    use rdns::tsig::{TsigAlgorithm, TsigKey};
    use rdns::ResponseCode;

    /// A refusal ends the sending: it arrived, and repeating it would not change
    /// the secondary's mind.
    ///
    /// **Not a regression test for #46b**, and saying so is the point (§10).
    /// The old code stopped here too — what it did wrong was call it
    /// `acknowledged` at INFO. That distinction lives in `notify::outcome`'s
    /// return type and is tested beside it; this only holds the retry behaviour
    /// that the rewording must not have changed.
    #[tokio::test]
    async fn test_a_refused_notify_is_not_retried() {
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");

        let sender = tokio::spawn(async move {
            send_notify(
                nm("example.com.").as_ref(),
                Serial::new(7),
                None,
                NotifyPeer {
                    addr: target,
                    key: None,
                },
            )
            .await;
        });

        let mut buf = vec![0u8; 4096];
        let (n, from) =
            tokio::time::timeout(Duration::from_secs(5), downstream.recv_from(&mut buf))
                .await
                .expect("the first NOTIFY")
                .expect("recv");
        let request = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");
        let refusal = notify::notify_response(&request, ResponseCode::Refused, 1232, None);
        let bytes = refusal.to_bytes_within(512).expect("serialize");
        downstream.send_to(&bytes, from).await.expect("reply");

        // Nothing further: the message got there, and a second copy would not
        // make a secondary that refused it change its answer.
        assert!(
            tokio::time::timeout(Duration::from_secs(3), downstream.recv_from(&mut buf))
                .await
                .is_err(),
            "a refusal must end the retries"
        );
        sender.await.expect("the sender finishes");
    }

    /// An unsigned answer to a signed NOTIFY is not an answer: otherwise anyone
    /// who can guess the transaction could silence a notification with a forged
    /// datagram, which is the property the retry loop already had for a reply
    /// carrying the wrong id.
    #[tokio::test]
    async fn test_an_unsigned_reply_to_a_signed_notify_is_not_an_acknowledgement() {
        let downstream = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = downstream.local_addr().expect("addr");
        let key = TsigKey::new("notify.key.", TsigAlgorithm::HmacSha256, vec![0x3c; 32]);

        let sender = tokio::spawn(async move {
            send_notify(
                nm("example.com.").as_ref(),
                Serial::new(7),
                None,
                NotifyPeer {
                    addr: target,
                    key: Some(key),
                },
            )
            .await;
        });

        let mut buf = vec![0u8; 4096];
        let mut answered = 0;
        // Every attempt gets an unsigned "yes", and none of them counts.
        while let Ok(Ok((n, from))) =
            tokio::time::timeout(Duration::from_secs(4), downstream.recv_from(&mut buf)).await
        {
            answered += 1;
            let request = DnsMessage::try_from_bytes(&buf[..n]).expect("parse");
            let reply = notify::notify_response(&request, ResponseCode::Ok, 1232, None);
            let bytes = reply.to_bytes_within(512).expect("serialize");
            downstream.send_to(&bytes, from).await.expect("reply");
        }
        assert_eq!(
            answered,
            notify::NOTIFY_ATTEMPTS,
            "an unsigned NOERROR must not stop the retries"
        );
        sender.await.expect("the sender finishes");
    }

    /// #46c: `[zones."x"].also-notify` adds to the global list for that zone
    /// and leaves every other zone's alone.
    ///
    /// There is no old behaviour for this to fail against, which is the finding:
    /// the per-zone list was parsed into `PerZone::notify` and read by nothing.
    #[test]
    fn test_per_zone_notify_targets_add_to_the_global_list() {
        let peer = |s: &str| NotifyPeer {
            addr: s.parse().expect("an address"),
            key: None,
        };
        let mut policy = NotifyPolicy::new(vec![peer("192.0.2.1:53")]);
        policy.add_zone(
            nm("example.com.").as_ref(),
            vec![peer("192.0.2.2:53"), peer("192.0.2.1:53")],
        );

        let addrs = |zone: &str| {
            policy
                .targets_for(nm(zone).as_ref())
                .iter()
                .map(|p| p.addr.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            addrs("example.com."),
            ["192.0.2.1:53", "192.0.2.2:53"],
            "the global list plus this zone's, and the repeat named once"
        );
        assert_eq!(
            addrs("example.net."),
            ["192.0.2.1:53"],
            "a zone with no list of its own gets the global one"
        );
        assert_eq!(
            addrs("EXAMPLE.COM."),
            ["192.0.2.1:53", "192.0.2.2:53"],
            "matched as a name, so case does not decide who is told (RFC 4343)"
        );
    }

    /// A `#key` naming a key nothing defines stops the server, for the reason
    /// `--secondary` already does: the operator asked for authentication and
    /// would otherwise not be able to see that they did not get it.
    #[test]
    fn test_a_notify_key_that_no_tsig_key_defines_is_a_startup_error() {
        let keys = TsigKeyring::new(vec![TsigKey::new(
            "known.key.",
            TsigAlgorithm::HmacSha256,
            vec![0x4d; 32],
        )]);
        let err = parse_notify_peers(&["192.0.2.1#missing.key.".to_string()], &keys)
            .expect_err("a key nobody defines");
        assert!(
            err.to_string().contains("missing.key."),
            "the message names the key that is missing: {err}"
        );

        // And the one that is defined resolves, whatever its algorithm — the
        // operator wrote the algorithm once, beside the secret.
        let peers = parse_notify_peers(&["192.0.2.1#known.key.".to_string()], &keys)
            .expect("a key that exists");
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].key.as_ref().map(|k| k.name.as_str()),
            Some("known.key.")
        );
    }
}
