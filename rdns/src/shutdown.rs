//! Cooperative shutdown: stop accepting, finish what was accepted, exit.
//!
//! Two types, deliberately separate:
//!
//! - [`Stop`] is the signal. Cloning it claims nothing, so a loop can watch for
//!   shutdown without preventing it.
//! - [`Busy`] is a claim on the drain, held while one unit of work is unfinished.
//!
//! One type carrying both would mean the accept loops, which hold the signal for
//! the life of the process, also hold the drain open — so every shutdown would
//! wait out its full budget while looking like it worked.

use std::time::Duration;

use tokio::sync::{mpsc, watch};

/// The stop signal, cloned to everything that runs a loop. Holding one claims
/// nothing; that is why it is not [`Busy`].
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
    /// change, and for a task started after the signal there is none.
    pub async fn wait(&self) {
        let mut rx = self.0.clone();
        if *rx.borrow() {
            return;
        }
        // A gone sender only happens as the process ends: same answer.
        let _ = rx.changed().await;
    }
}

/// A claim on the shutdown drain, held while one unit of work is unfinished.
///
/// The drain is an `mpsc` nobody sends on: `recv()` returns `None` exactly when
/// the last sender clone drops — a counter that cannot be got wrong and needs no
/// polling. Dropping it is the only thing that reports completion, so a `Busy`
/// held across a sleep costs the full budget every time.
#[derive(Clone)]
pub struct Busy(#[allow(dead_code)] mpsc::Sender<()>);

/// A [`Stop`] and a [`Busy`] as a pair, which is how a long-lived spawned task
/// wants them. Two more positional parameters on a function already taking five
/// is how two same-shaped arguments end up swapped.
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
    /// stop can call it without coordinating.
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

    /// [`Self::drain`] with `DEFAULT_DRAIN`, reporting what happened. Here so
    /// both daemons log a restart identically.
    pub async fn drain_reporting(self) {
        if self.drain(DEFAULT_DRAIN).await {
            tracing::info!("drained cleanly");
        } else {
            tracing::warn!(
                budget_secs = DEFAULT_DRAIN.as_secs(),
                "shutdown drain hit its budget with work still running; exiting anyway"
            );
        }
    }
}

/// How long a shutdown waits for accepted work to finish.
///
/// Bounded, because the point of a graceful stop is that `systemctl stop`
/// returns before systemd's 90-second SIGKILL. Five seconds is more than a
/// transfer needs once no new work arrives, and roughly the grace Windows gives
/// on `CTRL_CLOSE_EVENT`.
const DEFAULT_DRAIN: Duration = Duration::from_secs(5);

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve when the OS asks the process to stop, naming the signal.
///
/// SIGTERM is what every supervisor sends first; ignoring it spends the grace
/// period before SIGKILL doing nothing rather than finishing.
#[cfg(unix)]
pub async fn stop_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(e) => {
            // Must not stop the server running: Ctrl-C still works, and a
            // SIGTERM will kill rather than drain. Say so, since the
            // difference is invisible until it matters.
            tracing::error!("could not listen for SIGTERM ({e}); shutdown will not be graceful");
            std::future::pending().await
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => "SIGINT",
        _ = term.recv() => "SIGTERM",
    }
}

/// Windows has no SIGTERM, and `ctrl_c` alone is not enough: it registers for
/// `CTRL_C_EVENT` only, so an unlistened `CTRL_BREAK_EVENT` reaches the default
/// handler and kills the process with `0xC000013A`. Each console control event
/// needs its own listener.
///
/// `CTRL_CLOSE_EVENT` allows about five seconds before terminating regardless —
/// the same order as the drain budget, so a long transfer may still be cut.
///
/// A Windows *service* stop is none of these; it arrives through the service
/// control manager, which this does not use.
#[cfg(not(unix))]
pub async fn stop_signal() -> &'static str {
    use tokio::signal::windows;

    // A listener that fails to register never fires; the others still work.
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

    /// The budget is long enough that a test taking it is broken, not slow.
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

    /// A graceful stop that never returns is a hang.
    #[tokio::test]
    async fn the_drain_gives_up_at_its_budget() {
        let shutdown = Shutdown::new();
        // Never dropped, so the drain can only end by timing out.
        let _forever = shutdown.busy();
        assert!(!shutdown.drain(Duration::from_millis(50)).await);
    }

    /// The second is what `changed()` alone gets wrong: it fires on the next
    /// change, and there is none.
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

    /// What the two-type split exists for: the accept loops hold a `Stop` for
    /// the life of the process.
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
