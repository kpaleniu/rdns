//! Test support that is not DNS.
//!
//! `pub` rather than `pub(crate)`, and in `rdns-core` rather than in `rdns`,
//! because `persist` is here and its tests are with it (`TODO.md` #66c). A
//! crate boundary cannot see another crate's `#[cfg(test)]` items, so the
//! alternative is a second `ScratchDir`, which this module exists to prevent
//! (§7).
//!
//! Records are `rdns::test_records` and keys are `rdns::dnssec_test_util`; what
//! is left is the scratch directory, created and removed by one type so that no
//! copy creates one and leaves it in `TEMP` (`CLAUDE.md` §7, `TODO.md` #38e).

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

/// The smallest of `samples` timings of each of `a` and `b`, for a ratio test
/// (`CLAUDE.md` §10).
///
/// Contention only adds time, and a real regression shows in every sample. The
/// sides take turns, so a stretch of contention cannot land on one; each
/// closure rebuilds what its work changes (`TODO.md` #120b, #122).
pub fn fastest_of_each(
    samples: usize,
    mut a: impl FnMut() -> std::time::Duration,
    mut b: impl FnMut() -> std::time::Duration,
) -> (std::time::Duration, std::time::Duration) {
    let mut fastest = (std::time::Duration::MAX, std::time::Duration::MAX);
    for _ in 0..samples.max(1) {
        fastest.0 = fastest.0.min(a());
        fastest.1 = fastest.1.min(b());
    }
    fastest
}

/// Every `.rs` file under `dir`, `target/` and `.git/` skipped.
///
/// Two test binaries read the workspace's own source as data —
/// `rdns/tests/flattened_messages.rs` and `rdns/tests/module_doc_comments.rs` —
/// and a walk that silently returns nothing makes either of them pass by
/// finding no input, so both assert on the count they get back (§7).
pub fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rust_sources(dir, &mut out);
    out
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != ".git" {
                collect_rust_sources(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The `#[ignore]`d benchmarks in one test binary take turns: libtest runs a
/// filter's matches in parallel, and benchmarks timed against each other
/// mismeasure (`TODO.md` #64b). Per process, the grain of the collision.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A turn, held for the whole body of a benchmark.
///
/// Poisoning is ignored: one benchmark panicking says nothing about whether the
/// next may run, and the alternative is every later one failing for a reason
/// that is not theirs.
pub fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// An allocator that tallies calls per thread, wrapping whichever one the test
/// binary would otherwise install.
///
/// Per thread because libtest's threads allocate inside the window, which no
/// global counter excludes. Counts `alloc`, `alloc_zeroed` and `realloc`, as
/// dhat's `total_blocks` does.
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
/// on this thread; nested calls are the wrapped allocator's bookkeeping.
/// `try_with`, so a thread in TLS teardown does not resurrect the key; the
/// cells are `const` with no destructor.
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
        // Nothing counted; the guard covers what the wrapped allocator
        // allocates while freeing.
        let _entered = enter(false);
        unsafe { self.0.dealloc(ptr, layout) }
    }
}
