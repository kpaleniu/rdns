//! Writing a file that a reader can never catch half-written.
//!
//! Every piece of state this server persists — a fetched zone, a transfer
//! timestamp, a trust anchor as it rolls — is rewritten whole rather than
//! edited in place, and each rewrite has to be all-or-nothing. A process that
//! dies mid-`write` leaves a truncated file behind, and the reader of that file
//! is the same server on its next start: a zone file cut off at half a record
//! is not a zone that has lost a record, it is a zone that fails to load.
//!
//! So: write a temporary file in the same directory, flush it to disk, and
//! rename it over the target. `std::fs::rename` replaces an existing file on
//! both Unix and Windows, which is the whole reason this is portable — a reader
//! opening the path either gets the old file or the new one, never a mixture.
//! The same directory matters: a rename across filesystems is a copy, and a
//! copy is exactly the non-atomic thing being avoided.
//!
//! Ordering is the point of the fsync. `sync_all` before the rename is what
//! makes "the rename happened" imply "the contents are there"; without it a
//! crash can leave the directory entry pointing at a file whose blocks were
//! never written. Syncing the *directory* afterwards — so the rename itself
//! survives — has no Windows equivalent and is done only where it exists.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Replace `path`'s contents with `contents`, atomically.
///
/// The temporary file is removed on any failure, so a full disk or a permission
/// error leaves the directory as it was found rather than littered with
/// half-written attempts.
pub fn write_atomically(path: &Path, contents: &[u8]) -> io::Result<()> {
    let temp = temp_path_for(path)?;

    let result = write_and_sync(&temp, contents).and_then(|()| fs::rename(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        return result;
    }

    sync_dir(path.parent());
    Ok(())
}

/// Same, for text — the form every state file here takes.
pub fn write_atomically_str(path: &Path, contents: &str) -> io::Result<()> {
    write_atomically(path, contents.as_bytes())
}

fn write_and_sync(temp: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = File::create(temp)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// A sibling of `path` to write first.
///
/// The process id is in the name because "one writer per file" is a rule about
/// the *target*, and a temporary left behind by a process that crashed must not
/// be something a later run collides with or, worse, renames into place.
fn temp_path_for(path: &Path) -> io::Result<PathBuf> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} names no file to write", path.display()),
        )
    })?;

    let mut temp = std::ffi::OsString::from(".");
    temp.push(name);
    temp.push(format!(".tmp{}", std::process::id()));

    Ok(match dir {
        Some(dir) => dir.join(temp),
        None => PathBuf::from(temp),
    })
}

/// Flush the directory entry the rename created (POSIX only).
///
/// Best-effort by design: it is a durability refinement, not a correctness one —
/// the reader already cannot observe a partial file — and there is nothing
/// useful to tell a caller whose data is written and renamed but whose directory
/// might not survive a power cut.
#[cfg(unix)]
fn sync_dir(dir: Option<&Path>) {
    if let Some(dir) = dir.filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(handle) = File::open(dir) {
            let _ = handle.sync_all();
        }
    }
}

/// Windows has no directory handle to sync; the rename is durable enough there.
#[cfg(not(unix))]
fn sync_dir(_dir: Option<&Path>) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory that removes itself.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!("rdns-persist-{tag}-{unique}"));
            fs::create_dir_all(&dir).expect("create scratch dir");
            ScratchDir(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(&self.0)
                .expect("read scratch dir")
                .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_writes_a_new_file() {
        let dir = ScratchDir::new("new");
        let path = dir.path("state.txt");

        write_atomically_str(&path, "example.com. 2021010101\n").expect("write");

        assert_eq!(
            fs::read_to_string(&path).expect("read back"),
            "example.com. 2021010101\n"
        );
    }

    /// The case the rename exists for: an existing file is replaced, which on
    /// Windows is not what a plain `rename` syscall would do.
    #[test]
    fn test_replaces_an_existing_file() {
        let dir = ScratchDir::new("replace");
        let path = dir.path("zone");
        fs::write(&path, "old, and longer than what replaces it").expect("seed");

        write_atomically_str(&path, "new").expect("write");

        assert_eq!(fs::read_to_string(&path).expect("read back"), "new");
    }

    /// Nothing may be left beside the target: a stray `.zone.tmpNNN` is a file
    /// an operator has to reason about, and one a directory scan would trip on.
    #[test]
    fn test_leaves_no_temporary_behind() {
        let dir = ScratchDir::new("clean");
        write_atomically_str(&dir.path("example.com.zone"), "@ IN A 192.0.2.1\n").expect("write");
        write_atomically_str(&dir.path("example.com.zone"), "@ IN A 192.0.2.2\n").expect("rewrite");

        assert_eq!(dir.entries(), vec!["example.com.zone".to_string()]);
    }

    /// A failed write must not touch what is already there. The target is a
    /// directory here, so the rename cannot succeed.
    #[test]
    fn test_a_failed_write_leaves_the_target_alone() {
        let dir = ScratchDir::new("failure");
        let path = dir.path("in-the-way");
        fs::create_dir(&path).expect("create the obstruction");

        assert!(write_atomically_str(&path, "nope").is_err());
        assert!(path.is_dir(), "the target is untouched");
        assert_eq!(
            dir.entries(),
            vec!["in-the-way".to_string()],
            "and the temporary is cleaned up"
        );
    }

    #[test]
    fn test_a_path_that_names_no_file_is_an_error() {
        let err = write_atomically(Path::new(".."), b"nothing").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// The temporary is a sibling, or the rename would cross a filesystem.
    #[test]
    fn test_temp_path_is_a_sibling_of_the_target() {
        let temp = temp_path_for(Path::new("/var/db/example.com.zone")).expect("temp path");
        assert_eq!(temp.parent(), Path::new("/var/db/example.com.zone").parent());
        assert!(
            temp.file_name()
                .expect("a name")
                .to_string_lossy()
                .starts_with(".example.com.zone.tmp"),
            "got {temp:?}"
        );

        // A bare file name has no parent directory to join against.
        let bare = temp_path_for(Path::new("zone")).expect("temp path");
        assert_eq!(bare, PathBuf::from(format!(".zone.tmp{}", std::process::id())));
    }
}
