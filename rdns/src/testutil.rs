//! Test support that is not DNS.
//!
//! Records are [`crate::test_records`] and keys are [`crate::dnssec_test_util`];
//! what is left is the scratch directory, which four modules had written out
//! and three more had written the half of that creates one without the half
//! that removes it — so every run of the suite left three directories in `TEMP`
//! behind (`CLAUDE.md` §7, `TODO.md` #38e).

use std::path::{Path, PathBuf};

/// A directory under `TEMP`, removed when it goes out of scope.
pub(crate) struct ScratchDir(PathBuf);

impl ScratchDir {
    /// `tag` says which test this is, and the nanosecond stamp keeps two runs —
    /// and two threads inside one run — out of each other's way.
    pub(crate) fn new(tag: &str) -> ScratchDir {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("rdns-{tag}-{unique}"));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        ScratchDir(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// A path inside it. Nothing is created.
    pub(crate) fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.0.join(name)
    }

    /// Write a file into it, and give back its path.
    pub(crate) fn write(&self, name: &str, content: &str) -> PathBuf {
        let path = self.join(name);
        std::fs::write(&path, content).expect("write scratch file");
        path
    }

    /// What is in it, sorted, so an assertion on the set does not depend on the
    /// order a directory happens to be read in.
    pub(crate) fn entries(&self) -> Vec<String> {
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
