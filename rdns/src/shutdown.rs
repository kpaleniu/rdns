//! Cooperative shutdown: stop accepting, finish what was accepted, exit.
//!
//! Shared by both daemons because both had the same hole and the same shape of
//! it — no SIGTERM handler of any kind (a grep for SIGTERM, SIGINT or `ctrl_c`
//! across all four crates returned nothing, only SIGHUP), and a `tokio::select!`
//! over two `JoinHandle`s that **dropped the loser**, which detaches a task
//! rather than cancelling it. Writing that twice is how the ICMP predicate
//! ended up with the oversized-datagram case fixed in one copy and not the
//! other; see `CLAUDE.md` §7.
//!
//! The model is two types, deliberately separate:
//!
//! - [`Stop`] is the signal. Cloning it claims nothing, so a loop can watch for
//!   shutdown without being the thing that prevents it.
//! - [`Busy`] is a claim on the drain, held for as long as one unit of work is
//!   unfinished.
//!
//! Splitting them is not fussiness. A single type carrying both would mean the
//! accept loops — which hold the signal for the life of the process — also hold
//! the drain open, so every shutdown would wait out its full budget and the
//! feature would look like it worked while doing nothing.

use std::time::Duration;

use tokio::sync::{mpsc, watch};

/// The stop signal, cloned to everything that runs a loop.
///
/// Holding one claims **nothing**, which is why it is a separate type from
/// [`Busy`].
#[derive(Clone)]
pub struct Stop(watch::Receiver<bool>);

impl Stop {
    /// Whether shutdown has begun. For a loop that can check between units of
    /// work rather than waiting on it.
    pub fn is_set(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves when shutdown begins, immediately if it already has.
    ///
    /// The `borrow` first is load-bearing: `changed()` fires on the *next*
    /// change, so a task that started after the signal would otherwise wait for
    /// a second one that never comes.
    pub async fn wait(&self) {
        let mut rx = self.0.clone();
        if *rx.borrow() {
            return;
        }
        // An error means the sender is gone, which only happens as the process
        // ends — the same answer as being told to stop.
        let _ = rx.changed().await;
    }
}

/// A claim on the shutdown drain, held for as long as one unit of work is
/// unfinished.
///
/// The drain is an `mpsc` nobody ever sends on: `recv()` returns `None` exactly
/// when the last clone of the sender has been dropped. That is a counter that
/// cannot be got wrong and needs no polling — and dropping it is the *only*
/// thing that reports completion, so a `Busy` held by something that never
/// finishes costs the full drain budget every time.
///
/// The field is never read, only held and dropped. That is the whole mechanism.
#[derive(Clone)]
pub struct Busy(#[allow(dead_code)] mpsc::Sender<()>);

/// A [`Stop`] and a [`Busy`] together, which is how a long-lived spawned task
/// almost always wants them: watch for the signal, claim the drain while there
/// is work in hand.
///
/// It exists mostly to keep them travelling as a pair. Passing two more
/// positional parameters into functions that already take five or six is how
/// they end up swapped, and clippy starts objecting at seven.
#[derive(Clone)]
pub struct Lifecycle {
    pub stop: Stop,
    pub busy: Busy,
}

/// Owns the stop signal and the drain, and is consumed by the drain itself.
pub struct Shutdown {
    stop: watch::Sender<bool>,
    /// The template every [`Busy`] is cloned from. Dropped by [`Self::drain`],
    /// which is what lets the receiver ever see `None`.
    busy: Busy,
    done: mpsc::Receiver<()>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (stop, _) = watch::channel(false);
        let (busy, done) = mpsc::channel(1);
        Shutdown {
            stop,
            busy: Busy(busy),
            done,
        }
    }

    pub fn stop_handle(&self) -> Stop {
        Stop(self.stop.subscribe())
    }

    pub fn busy(&self) -> Busy {
        self.busy.clone()
    }

    pub fn lifecycle(&self) -> Lifecycle {
        Lifecycle {
            stop: self.stop_handle(),
            busy: self.busy(),
        }
    }

    /// Begin shutting down. Idempotent, so every path that notices a reason to
    /// stop can just call it.
    pub fn begin(&self) {
        let _ = self.stop.send(true);
    }

    /// Wait for the work already accepted to finish, up to `budget`.
    ///
    /// Returns whether everything drained. Consuming `self` is what drops the
    /// template [`Busy`]; without that the receiver never sees `None` and this
    /// always waits out the budget.
    pub async fn drain(self, budget: Duration) -> bool {
        let Shutdown { busy, mut done, .. } = self;
        drop(busy);
        matches!(tokio::time::timeout(budget, done.recv()).await, Ok(None))
    }

    /// [`Self::drain`] with [`DEFAULT_DRAIN`], reporting what happened.
    ///
    /// Here rather than in each binary so the two daemons say the same thing:
    /// they had already drifted to reporting it differently, which is how a pair
    /// of copies starts (`CLAUDE.md` §7). An operator reading one log after a
    /// restart should not have to know which process wrote it.
    pub async fn drain_reporting(self) {
        if self.drain(DEFAULT_DRAIN).await {
            println!("drained cleanly");
        } else {
            eprintln!(
                "shutdown drain hit its {}s budget with work still running; exiting anyway",
                DEFAULT_DRAIN.as_secs()
            );
        }
    }
}

/// How long a shutdown waits for work already accepted to finish.
///
/// A bound rather than "until it is done", because the point of a graceful stop
/// is that `systemctl stop` returns: systemd's own default is 90 seconds before
/// SIGKILL, and a server that needs more than a few is one the operator will
/// start killing instead. Five is comfortably more than a zone transfer of any
/// size these serve takes once no new work is arriving, and it is also roughly
/// the grace Windows gives on `CTRL_CLOSE_EVENT`.
pub const DEFAULT_DRAIN: Duration = Duration::from_secs(5);

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve when the operating system asks the process to stop, naming which
/// signal it was.
///
/// SIGTERM is the one that matters: it is what every process supervisor sends
/// first, and ignoring it means the grace period before SIGKILL — systemd's
/// default is 90 seconds — is spent doing nothing rather than finishing.
#[cfg(unix)]
pub async fn stop_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(e) => {
            // Nothing to do about it, and it must not stop the server running:
            // Ctrl-C below still works, and a supervisor's SIGTERM will kill the
            // process the old way rather than draining. Say so once, because the
            // difference is invisible until the day it matters.
            eprintln!("could not listen for SIGTERM ({e}); shutdown will not be graceful");
            std::future::pending().await
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => "SIGINT",
        _ = term.recv() => "SIGTERM",
    }
}

/// Windows has no SIGTERM, and **`ctrl_c` alone is not enough** — that was the
/// first version of this, and testing it is what showed it up: a real
/// `CTRL_BREAK_EVENT` sent mid-AXFR went to the default handler and killed the
/// process with exit code `0xC000013A` (STATUS_CONTROL_C_EXIT), cutting the
/// transfer exactly as before. `tokio::signal::ctrl_c` registers for
/// `CTRL_C_EVENT` and nothing else; the other console control events each need
/// their own listener. Claiming otherwise in this comment, without opening the
/// function, is `CLAUDE.md` §4's rule being broken in the same commit that added
/// the feature.
///
/// The four that mean "stop":
///
/// - `CTRL_C_EVENT` and `CTRL_BREAK_EVENT` — a developer at a terminal, and what
///   a parent process sends a child in its own process group.
/// - `CTRL_CLOSE_EVENT` — the console window closing. **Windows allows about
///   five seconds** here before terminating regardless, which is the same order
///   as the drain budget: a long transfer may still be cut, and there is nothing
///   this side of the API to do about it.
/// - `CTRL_SHUTDOWN_EVENT` — system shutdown.
///
/// A Windows *service* stop is none of these; it arrives through the service
/// control manager, which this does not use.
#[cfg(not(unix))]
pub async fn stop_signal() -> &'static str {
    use tokio::signal::windows;

    // Each listener can fail to register; a failure must not stop the server
    // running, so it simply never fires and the others still work.
    async fn never() -> ! {
        std::future::pending().await
    }

    let mut brk = windows::ctrl_break().ok();
    let mut close = windows::ctrl_close().ok();
    let mut shutdown = windows::ctrl_shutdown().ok();

    macro_rules! recv {
        ($opt:expr) => {
            async {
                match $opt.as_mut() {
                    Some(stream) => {
                        stream.recv().await;
                    }
                    None => never().await,
                }
            }
        };
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => "Ctrl-C",
        _ = recv!(brk) => "Ctrl-Break",
        _ = recv!(close) => "console close",
        _ = recv!(shutdown) => "system shutdown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The drain completes as soon as the last claim is dropped, rather than
    /// waiting out its budget. The budget here is long enough that a test which
    /// takes it is unambiguously broken rather than slow.
    #[tokio::test]
    async fn the_drain_ends_when_the_last_claim_is_dropped() {
        let shutdown = Shutdown::new();
        let busy = shutdown.busy();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(busy);
        });

        let started = std::time::Instant::now();
        assert!(shutdown.drain(Duration::from_secs(30)).await);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the drain waited for the budget rather than for the work"
        );
    }

    /// And it gives up at the budget rather than hanging, because a graceful
    /// stop that never returns is just a hang with better intentions.
    #[tokio::test]
    async fn the_drain_gives_up_at_its_budget() {
        let shutdown = Shutdown::new();
        // Never dropped, so the drain can only end by timing out.
        let _forever = shutdown.busy();
        assert!(!shutdown.drain(Duration::from_millis(50)).await);
    }

    /// A `Stop` handed out *before* the signal and one taken *after* it must
    /// both resolve. The second is the case `changed()` alone gets wrong —
    /// it fires on the next change, and there is no next change.
    #[tokio::test]
    async fn a_stop_taken_after_the_signal_still_resolves() {
        let shutdown = Shutdown::new();
        let early = shutdown.stop_handle();
        assert!(!early.is_set());

        shutdown.begin();

        let late = shutdown.stop_handle();
        assert!(early.is_set());
        assert!(late.is_set());
        // Neither of these may hang.
        tokio::time::timeout(Duration::from_secs(5), early.wait())
            .await
            .expect("a stop handle taken before the signal");
        tokio::time::timeout(Duration::from_secs(5), late.wait())
            .await
            .expect("a stop handle taken after the signal");
    }

    /// Holding a `Stop` must not hold the drain open. This is the mistake the
    /// two-type split exists to prevent: the accept loops hold the signal for
    /// the life of the process, so if it claimed the drain too, every shutdown
    /// would wait out its whole budget and the feature would look like it
    /// worked while doing nothing.
    #[tokio::test]
    async fn holding_a_stop_does_not_hold_the_drain() {
        let shutdown = Shutdown::new();
        let _stop = shutdown.stop_handle();
        shutdown.begin();
        assert!(
            shutdown.drain(Duration::from_millis(200)).await,
            "a Stop is a signal, not a claim"
        );
    }

    /// `begin` is idempotent, so every path that notices a reason to stop can
    /// call it without coordinating with the others.
    #[tokio::test]
    async fn beginning_twice_is_harmless() {
        let shutdown = Shutdown::new();
        let stop = shutdown.stop_handle();
        shutdown.begin();
        shutdown.begin();
        assert!(stop.is_set());
        assert!(shutdown.drain(Duration::from_millis(200)).await);
    }
}
