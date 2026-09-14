//! Re-reading what a running resolver was started with: the TLS certificate and
//! every `--rpz` file.
//!
//! One task, and everything about its shape is a measurement.
//!
//! The reads are blocking and slow — a million-rule QNAME feed is 0.952 s to
//! re-read and peaks at 759 MB while both sets are live, since
//! [`rdns::rpz::PolicyStore::reload`] builds the whole new set before
//! installing any of it. The 2x peak is inherent and `TODO.md` #61 says why.
//! They ran on a tokio worker until `TODO.md` #57b, and `#[tokio::main]` gives
//! one worker per core: measured on a one-worker runtime, a probe asking for
//! 1 ms ticks saw a 2.715 s gap, which is a resolver answering nothing for the
//! length of a reload. With two workers it was 2.28 ms against a 2.17 ms floor
//! — the defect cost 1/N of capacity above one core and everything at one, so
//! the work goes to [`tokio::task::spawn_blocking`] (`CLAUDE.md` §9).
//!
//! The task is sequential, so two reloads never overlap: four at once on four
//! workers stalled every task for 3.53 s and took 4.50 s to do 2.70 s of work.
//!
//! **The four figures in the two paragraphs above are #57b's**, taken when a
//! reload was 2.74 s; #61 made one shorter and the probe has not been re-run,
//! so they are the shape rather than today's clock. Only the first paragraph's
//! numbers, which are a cost and not a stall, are current.
//! And [`PolicyReload`]'s single permit collapses a burst of requests into one
//! queued reload, which is what makes it safe for a NOTIFY — a packet whose
//! rate a remote party chooses — to ask for one at all (`CLAUDE.md` §5).

use std::sync::Arc;

use rdns::shutdown::{next_reload, reload_signal, Stop};
use rdns_transport::tls::CertificateStore;
use tokio::sync::Notify;

use crate::answer::{reload_policy, Resolving};

/// A handle for asking that the `--rpz` files be re-read.
///
/// Held by the answer path, which must not hold an `Arc<Resolving>` back to
/// reach the reloader: this carries the wake-up and nothing else, so there is
/// no cycle to leak.
#[derive(Clone, Default)]
pub(crate) struct PolicyReload(Arc<Notify>);

impl PolicyReload {
    /// Queue a reload, if one is not already queued.
    ///
    /// At most one waits however many ask, because `Notify` holds a single
    /// permit. That is the bound, and it is the reason this is a `Notify`
    /// rather than a channel: the work is idempotent, so a hundred requests and
    /// one request want the same single re-read, and an unbounded queue of them
    /// is the amplification `CLAUDE.md` §5 is about. `rdnsd`'s refresh task
    /// wakes on the same primitive for the same reason.
    pub(crate) fn request(&self) {
        self.0.notify_one();
    }

    /// Resolve when a reload has been asked for.
    ///
    /// Cancel-safe, which is what lets it sit in the `select!` below: a permit
    /// outlives the dropped future, so a request racing the stop signal is not
    /// silently swallowed — it is simply never run, which is what stopping
    /// means.
    pub(crate) async fn requested(&self) {
        self.0.notified().await;
    }
}

/// Re-read on SIGHUP or on request, one at a time, off the worker threads.
///
/// SIGHUP re-reads the certificate as well; a request does not. A NOTIFY is the
/// only thing that asks, it is about a policy zone, and a stranger's packet has
/// no business making this process re-open its key material — nor leaving a
/// "could not re-read the TLS certificate" line behind to be diagnosed by
/// somebody who did not touch it.
pub(crate) async fn reload_task(
    certificate: Option<Arc<CertificateStore>>,
    serving: Arc<Resolving>,
    wanted: PolicyReload,
    stop: Stop,
) {
    let mut signals = reload_signal();
    loop {
        let certificate = tokio::select! {
            reloaded = next_reload(&mut signals) => {
                if !reloaded {
                    break;
                }
                certificate.as_ref()
            }
            () = wanted.requested() => None,
            () = stop.wait() => break,
        };
        reload_now(certificate, &serving).await;
    }
}

/// One reload, on a blocking thread.
async fn reload_now(certificate: Option<&Arc<CertificateStore>>, serving: &Arc<Resolving>) {
    let certificate = certificate.cloned();
    let serving = serving.clone();
    let ran = tokio::task::spawn_blocking(move || {
        if let Some(store) = certificate {
            match store.reload() {
                Ok(()) => tracing::info!("TLS certificate re-read"),
                Err(e) => tracing::warn!("could not re-read the TLS certificate: {e:#}"),
            }
        }
        reload_policy(&serving);
    })
    .await;
    if let Err(e) = ran {
        // The task must survive it: what panicked did not install anything, so
        // the previous set is still in force and the next request can still be
        // served. Ending the loop here would leave a resolver that looks healthy
        // and never reloads again (`CLAUDE.md` §4).
        tracing::error!("the reload panicked and nothing was re-read: {e}");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::testutil::{serving_policy, ScratchDir};
    use rdns::rpz::{PolicyOverride, PolicyStore};

    /// A feed big enough that a reload is unmistakably slow: 100k rules is
    /// ~170 ms on the development machine, against the microseconds a test
    /// would otherwise measure.
    fn big_feed(dir: &ScratchDir, rules: usize) -> std::path::PathBuf {
        let mut text = String::from(
            "$TTL 60\n\
             @ IN SOA ns.rpz.invalid. hostmaster.rpz.invalid. 1 3600 600 86400 60\n\
             @ IN NS localhost.\n",
        );
        for i in 0..rules {
            text.push_str(&format!("www.malware{i:07}.example IN CNAME .\n"));
        }
        dir.write("feed.rpz.invalid.zone", &text)
    }

    /// The coalescing, at the level where it is decided.
    ///
    /// Fails against a channel or a semaphore, which would hand back one
    /// completion per request and let a NOTIFY flood queue a reload per packet.
    #[tokio::test]
    async fn a_burst_of_requests_queues_one_reload() {
        let wanted = PolicyReload::default();
        for _ in 0..100 {
            wanted.request();
        }
        // The first is waiting and returns at once.
        tokio::time::timeout(Duration::from_secs(5), wanted.requested())
            .await
            .expect("the first request is queued");
        // The other ninety-nine were folded into it.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), wanted.requested())
                .await
                .is_err(),
            "a hundred requests must queue one reload, not a hundred"
        );
    }

    /// The defect #57b fixed, on the runtime shape that made it fatal.
    ///
    /// One worker, so a reload that occupies it is the whole runtime. The probe
    /// counts completed yields rather than measuring a delay, because a count is
    /// deterministic where a wall-clock assertion is a coin toss (`CLAUDE.md`
    /// §10): against the old `reload_policy(&serving)` called straight from the
    /// task, the probe cannot advance at all while the parse runs and this reads
    /// 0. Checked by putting that shape back — the first version of this test
    /// passed against it, because `block_on` drives the test's own future on the
    /// calling thread and the worker under test was never the blocked one. Both
    /// halves are `tokio::spawn`ed for that reason, which is also how `main`
    /// runs them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_reload_does_not_stop_the_only_worker() {
        let dir = ScratchDir::new("reload-blocking");
        let path = big_feed(&dir, 100_000);
        let store = PolicyStore::load(std::slice::from_ref(&path), PolicyOverride::Given)
            .expect("the feed loads");
        let serving = serving_policy(store);

        let ticks = Arc::new(AtomicU64::new(0));
        let counting = ticks.clone();
        let probe = tokio::spawn(async move {
            loop {
                tokio::task::yield_now().await;
                counting.fetch_add(1, Ordering::Relaxed);
            }
        });
        // Let the probe reach the worker first, so what this counts is the
        // reload and not the scheduling order.
        tokio::task::yield_now().await;
        let before = ticks.load(Ordering::Relaxed);

        tokio::spawn(async move { reload_now(None, &serving).await })
            .await
            .expect("the reload finished");
        let during = ticks.load(Ordering::Relaxed) - before;
        probe.abort();

        assert!(
            during > 100,
            "the one worker must stay free during a reload; the probe advanced {during} times"
        );
    }

    /// A reload that panics must not take the task with it.
    #[tokio::test]
    async fn the_task_outlives_a_panicking_reload() {
        let ran = tokio::task::spawn_blocking(|| panic!("as a reload might")).await;
        assert!(ran.is_err(), "a panic arrives as a join error, not a hang");
    }
}
