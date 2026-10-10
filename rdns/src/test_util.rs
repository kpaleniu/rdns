//! Async test support, for this crate's tests and, through the `test-util`
//! feature, the other crates' (`[dev-dependencies]` only). The synchronous
//! helpers are `rdns::testutil`, which needs no feature because it has no
//! tokio in it.

use std::future::Future;
use std::time::Duration;

/// How often [`eventually`] looks again.
const POLL: Duration = Duration::from_millis(5);

/// Whether `check` holds before `within` has passed.
///
/// For a condition with nothing to await: a counter, a gauge, a file. A
/// deadline rather than a fixed sleep, so a slow machine makes the test slower
/// and never makes it wrong. On tokio's clock, so a paused test does not wait.
pub async fn eventually<F, Fut>(within: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the one poll in the tests: what it waits for has no event"
        )]
        tokio::time::sleep(POLL).await;
    }
}

/// The dnstap capture at `path` once the pump has written STOP, or `None`
/// if it has not within `within`. A file has no event to await.
pub async fn closed_capture(path: &std::path::Path, within: Duration) -> Option<Vec<u8>> {
    let stop = crate::dnstap::stop_frame();
    let mut bytes = Vec::new();
    let closed = eventually(within, || {
        // Absent until the pump creates it: not closed yet, so look again.
        bytes = std::fs::read(path).unwrap_or_default();
        std::future::ready(bytes.ends_with(&stop))
    })
    .await;
    closed.then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_condition_that_never_holds_ends_at_the_deadline() {
        let began = tokio::time::Instant::now();
        assert!(!eventually(Duration::from_secs(5), || async { false }).await);
        assert!(began.elapsed() >= Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_condition_that_holds_ends_the_wait() {
        let mut asked = 0;
        let held = eventually(Duration::from_secs(5), || {
            asked += 1;
            std::future::ready(asked == 3)
        })
        .await;
        assert!(held);
        assert_eq!(asked, 3);
    }
}
