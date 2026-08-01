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

/// Same, for a file nobody but the owner may read: a private key, a shared
/// secret.
///
/// **The restriction goes on the temporary file, before the rename.** Setting
/// the mode on the target afterwards leaves a window — however short — in which
/// a freshly written private key is sitting there at whatever the umask allowed,
/// usually 0644. Restricting the temporary first means the key is never
/// reachable by anyone else at any point, because the name it is finally known
/// by only ever refers to a file that was already 0600.
///
/// A failure to restrict is a failure to write. The alternative — carrying on
/// and reporting success — hands back a path the caller believes is private and
/// is not, which is the one outcome worth refusing (`CLAUDE.md` §4).
pub fn write_atomically_private(path: &Path, contents: &str) -> io::Result<()> {
    let temp = temp_path_for(path)?;

    let result = write_and_sync(&temp, contents.as_bytes())
        .and_then(|()| restrict_to_owner(&temp))
        .and_then(|()| fs::rename(&temp, path));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        return result;
    }

    sync_dir(path.parent());
    Ok(())
}

/// Refuse a file holding a secret that anyone but its owner can read.
///
/// `what` names the secret for the error message — "a TSIG secret", "a DNSSEC
/// private key" — because the check is the same and only the noun differs.
///
/// **This is the check the feature exists for.** A secret in a file is only
/// better than a secret in `argv` if the file is actually private, and a key
/// directory restored from backup as 0644, or `chmod -R`'d by a deploy script,
/// is the ordinary way that stops being true. Refusing to start is the right
/// answer: an operator who believes a key is private and is wrong has no other
/// way to find out.
///
/// One implementation, called from both the TSIG and the DNSSEC paths, because
/// two copies of a security check are one copy and one bug waiting (§7).
pub fn ensure_private(path: &Path, what: &str) -> io::Result<()> {
    check_mode(path, what)
}

#[cfg(unix)]
fn check_mode(path: &Path, what: &str) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} is mode {:o}: {what} readable by its group or by everybody is \
                 not a secret, and a file in a config directory is exactly what a \
                 deploy script chmods by accident",
                path.display(),
                mode & 0o777
            ),
        ));
    }
    Ok(())
}

/// Windows has no mode bits worth checking this way — an ACL check would need
/// the security API and would not mean the same thing. Said out loud rather
/// than silently skipped, because "the permissions were checked" is exactly the
/// kind of claim that is only true on one platform.
#[cfg(not(unix))]
fn check_mode(path: &Path, _what: &str) -> io::Result<()> {
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a file", path.display()),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

/// Nothing to do, and nothing to claim. See [`ensure_private`].
#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) -> io::Result<()> {
    Ok(())
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

    /// The mode check, which is the whole of what makes a secret in a file
    /// better than a secret in `argv`.
    ///
    /// Unix only, and that is not a gap being papered over: there are no mode
    /// bits to check on Windows, which is why [`ensure_private`] says so in a
    /// comment rather than quietly returning `Ok`.
    #[cfg(unix)]
    #[test]
    fn test_a_secret_readable_by_anyone_else_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = ScratchDir::new("private");
        let path = dir.path("tsig.secret");

        for (mode, private) in [
            (0o600, true),
            (0o400, true),
            (0o640, false), // the group can read it
            (0o604, false), // everybody can read it
            (0o660, false),
            (0o644, false), // what a restore from backup leaves behind
        ] {
            // Removed first: a previous iteration may have left it 0400, and
            // `fs::write` opens for writing before anything else happens.
            let _ = fs::remove_file(&path);
            fs::write(&path, "c3VwZXItc2VjcmV0\n").expect("write the secret");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");

            let verdict = ensure_private(&path, "a TSIG secret");
            assert_eq!(
                verdict.is_ok(),
                private,
                "mode {mode:o} should {} have been accepted",
                if private { "" } else { "not" }
            );
            if let Err(e) = verdict {
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
                // The mode is in the message: an operator has to be able to see
                // what it is without going to look.
                assert!(
                    e.to_string().contains(&format!("{mode:o}")),
                    "the error should name the mode it refused: {e}"
                );
            }
        }
    }

    /// A private write is never briefly readable under its final name.
    ///
    /// The restriction goes on the temporary file, before the rename — setting
    /// it afterwards would leave a window at whatever the umask allowed, which
    /// for a private key is the whole thing.
    #[cfg(unix)]
    #[test]
    fn test_a_private_write_lands_already_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = ScratchDir::new("private-write");
        let path = dir.path("key.rdnskey");

        write_atomically_private(&path, "PrivateKey: not-really\n").expect("write");

        let mode = fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "got mode {:o}", mode & 0o777);
        // And the file it wrote is the file it says it wrote.
        assert_eq!(
            fs::read_to_string(&path).expect("read back"),
            "PrivateKey: not-really\n"
        );
        assert_eq!(dir.entries(), vec!["key.rdnskey".to_string()]);
        // The check and the write agree, which is the point of them being in
        // one module.
        ensure_private(&path, "a DNSSEC private key").expect("what we just wrote passes");
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
        assert_eq!(
            temp.parent(),
            Path::new("/var/db/example.com.zone").parent()
        );
        assert!(
            temp.file_name()
                .expect("a name")
                .to_string_lossy()
                .starts_with(".example.com.zone.tmp"),
            "got {temp:?}"
        );

        // A bare file name has no parent directory to join against.
        let bare = temp_path_for(Path::new("zone")).expect("temp path");
        assert_eq!(
            bare,
            PathBuf::from(format!(".zone.tmp{}", std::process::id()))
        );
    }
}
