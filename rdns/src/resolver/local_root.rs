//! A local copy of the root (RFC 8806, `TODO.md` #177): a stub zone at `.`,
//! usually `rdnsd` holding the root as a loopback secondary.
//!
//! The one thing a stub zone does not otherwise do is fall back. §3: "if the
//! contents of the root zone cannot be refreshed before the expire time in
//! the SOA, the resolver MUST immediately switch to using non-local root
//! servers". So the local root is marked down on an unreachable server, a
//! REFUSED (what `rdnsd` answers for a withdrawn zone) or an answer from it
//! that fails validation, and walks start from the root hints until a probe
//! finds it serving again. Only at `.`: below it the fallback would leak an
//! internal name to the public tree (#172).

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::metrics::DnsMetrics;

/// How often a local root marked down is asked whether it is back. A
/// constant: the brief that asked for this asked for no flag.
pub const LOCAL_ROOT_PROBE_INTERVAL: Duration = Duration::from_secs(60);

pub(super) struct LocalRoot {
    servers: Vec<SocketAddr>,
    up: AtomicBool,
    metrics: DnsMetrics,
}

impl LocalRoot {
    pub(super) fn new(servers: Vec<SocketAddr>, metrics: DnsMetrics) -> LocalRoot {
        metrics.local_root_in_use(true);
        LocalRoot {
            servers,
            up: AtomicBool::new(true),
            metrics,
        }
    }

    pub(super) fn in_use(&self) -> bool {
        self.up.load(Ordering::Relaxed)
    }

    /// Whether `servers` are the local root's: the root step of a walk that
    /// started from it.
    pub(super) fn is(&self, zone: NameRef<'_>, servers: &[SocketAddr]) -> bool {
        zone.is_root() && servers == self.servers.as_slice()
    }

    /// Logged once per transition, with the reason.
    pub(super) fn down(&self, why: &str) {
        if self.up.swap(false, Ordering::Relaxed) {
            self.metrics.local_root_in_use(false);
            tracing::warn!("local root (RFC 8806) not in use, walking from the root hints: {why}");
        }
    }

    pub(super) fn restored(&self) {
        if !self.up.swap(true, Ordering::Relaxed) {
            self.metrics.local_root_in_use(true);
            tracing::info!("local root (RFC 8806) answering and validating again; in use");
        }
    }
}

impl Resolver {
    /// While the local root is down, ask it every
    /// [`LOCAL_ROOT_PROBE_INTERVAL`] for the root SOA, validated, and put it
    /// back in use once it answers. Ends on `stop`; returns at once without a
    /// local root.
    #[expect(clippy::disallowed_methods, reason = "the probe interval is the event")]
    pub async fn keep_local_root(self: Arc<Self>, stop: crate::shutdown::Stop) {
        let Some(local) = &self.local_root else {
            return;
        };
        loop {
            tokio::select! {
                () = tokio::time::sleep(LOCAL_ROOT_PROBE_INTERVAL) => {}
                () = stop.wait() => return,
            }
            if local.in_use() {
                continue;
            }
            let soa = QuerySection {
                qname: Name::root(),
                qtype: Qtype::of(crate::record_types::SOA),
                qclass: QueryClass::IN,
            };
            match self
                .resolve_timed(&soa, None, Ntas::Honoured, Probe::LocalRoot)
                .await
            {
                Ok((response, verdict))
                    if response.rcode == ResponseCode::Ok
                        && !response.answers.is_empty()
                        && !verdict.is_bogus() =>
                {
                    local.restored();
                }
                Ok((_, verdict)) => {
                    tracing::debug!("local root probe: not yet ({verdict})");
                }
                Err(e) => tracing::debug!("local root probe: not yet ({e})"),
            }
        }
    }
}

/// Whether a resolution may use a local root that is marked down: only the
/// probe asking whether it is back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Probe {
    None,
    LocalRoot,
}
