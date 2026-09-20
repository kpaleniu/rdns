//! Test support that is not DNS.
//!
//! `pub` rather than `pub(crate)`, and in `rdns-core` rather than in `rdns`,
//! because `persist` moved here in `TODO.md` #66c and its tests came with it
//! (#20's rule). A crate boundary cannot see another crate's `#[cfg(test)]`
//! items, so the choice was this or a second `ScratchDir` — which is the thing
//! this module exists to have stopped (§7).
//!
//! Records are `rdns::test_records` and keys are `rdns::dnssec_test_util`;
//! what is left is the scratch directory, which four modules had written out
//! and three more had written the half of that creates one without the half
//! that removes it — so every run of the suite left three directories in `TEMP`
//! behind (`CLAUDE.md` §7, `TODO.md` #38e).

use std::path::{Path, PathBuf};

/// A directory under `TEMP`, removed when it goes out of scope.
pub struct ScratchDir(PathBuf);

impl ScratchDir {
    /// `tag` says which test this is, and the nanosecond stamp keeps two runs —
    /// and two threads inside one run — out of each other's way.
    pub fn new(tag: &str) -> ScratchDir {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("rdns-{tag}-{unique}"));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        ScratchDir(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// A path inside it. Nothing is created.
    pub fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.0.join(name)
    }

    /// Write a file into it, and give back its path.
    pub fn write(&self, name: &str, content: &str) -> PathBuf {
        let path = self.join(name);
        std::fs::write(&path, content).expect("write scratch file");
        path
    }

    /// What is in it, sorted, so an assertion on the set does not depend on the
    /// order a directory happens to be read in.
    pub fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .expect("read scratch dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The `#[ignore]`d benchmarks in one test binary take turns.
///
/// libtest runs what a filter selects in parallel, and a benchmark's own
/// recipe is usually a filter that selects more than one of them — so the
/// documented command times two million-record runs against each other. That
/// is how `TODO.md` #64b came to record a 1-5% saving for a change that saves
/// 38%, and `rdns/tests/rpz_install.rs` read 3 123 ms for a load that takes
/// 2 198 when it had the binary to itself.
///
/// The mutex is per process, which is the right grain: the collision is within
/// one test binary. What is shared here is the reason, not the state
/// (`CLAUDE.md` §7).
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A turn, held for the whole body of a benchmark.
///
/// Poisoning is ignored: one benchmark panicking says nothing about whether the
/// next may run, and the alternative is every later one failing for a reason
/// that is not theirs.
pub fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner())
}

/// An allocator that tallies calls per thread, wrapping whichever one the test
/// binary would otherwise install.
///
/// Two test binaries count allocations — `rdns/tests/allocations.rs` over
/// `dhat::Alloc` and `rdnsr`'s over `System` — and the reason the tally is
/// *per thread* is subtle enough that a second copy would get it wrong (§7):
/// a global counter cannot be made exact by a mutex here, because the threads
/// that allocate inside the window are libtest's. CI once read 10 for a parse
/// that reads 6 on four machines, and passed on a re-run of the same commit.
///
/// Counts `alloc`, `alloc_zeroed` and `realloc`, which is what dhat's
/// `total_blocks` counts, so a number measured either way means the same thing.
pub struct Counting<A>(pub A);

thread_local! {
    /// Allocator calls made by this thread.
    static BLOCKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// True while this thread is inside an allocator call.
    static INSIDE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// This thread's allocator calls so far.
pub fn blocks() -> u64 {
    BLOCKS.with(std::cell::Cell::get)
}

/// How many allocations `body` made on this thread.
///
/// The first profiled block in a process picks up one-off initialization, so
/// call what is measured once before measuring it (`CLAUDE.md` §10).
pub fn allocations<T>(body: impl FnOnce() -> T) -> (T, u64) {
    let before = blocks();
    let out = body();
    (out, blocks() - before)
}

/// Enter one allocator call, counting it if `count` and this is the outermost
/// one on this thread. Nested calls are the wrapped allocator's own
/// bookkeeping, not the caller's cost — which is why every entry point takes
/// this guard, including the one that counts nothing.
///
/// `try_with`: a thread allocating while its own TLS is being destroyed must
/// not resurrect the key. Both cells are `const`-initialized and have no
/// destructor, so the access itself never allocates and cannot recurse.
fn enter(count: bool) -> impl Drop {
    struct Guard(bool);
    impl Drop for Guard {
        fn drop(&mut self) {
            if self.0 {
                let _ = INSIDE.try_with(|c| c.set(false));
            }
        }
    }
    let outermost = INSIDE.try_with(|c| !c.replace(true)).unwrap_or(false);
    if outermost && count {
        let _ = BLOCKS.try_with(|b| b.set(b.get() + 1));
    }
    Guard(outermost)
}

unsafe impl<A: std::alloc::GlobalAlloc> std::alloc::GlobalAlloc for Counting<A> {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        let _entered = enter(true);
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        let _entered = enter(true);
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        let _entered = enter(true);
        unsafe { self.0.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // Allocations are what is counted, so nothing is counted here — the
        // guard is for what the wrapped allocator may allocate while recording
        // the free.
        let _entered = enter(false);
        unsafe { self.0.dealloc(ptr, layout) }
    }
}
