//! Writing a file that a reader can never catch half-written.
//!
//! Write a temporary file in the same directory, `sync_all` it, rename it over
//! the target. `std::fs::rename` replaces an existing file on both Unix and
//! Windows. The same directory matters: a cross-filesystem rename is a copy,
//! which is the non-atomic thing being avoided. The fsync before the rename is
//! what makes "the rename happened" imply "the contents are there".

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Replace `path`'s contents with `contents`, atomically.
///
/// The temporary is removed on any failure, so a full disk leaves the directory
/// as it was found.
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

/// Same, for text.
pub fn write_atomically_str(path: &Path, contents: &str) -> io::Result<()> {
    write_atomically(path, contents.as_bytes())
}

/// Same, for a file nobody but the owner may read: a private key, a shared
/// secret.
///
/// The restriction goes on the temporary, before the rename: setting the mode
/// on the target afterwards leaves a window at whatever the umask allowed. A
/// failure to restrict is a failure to write — reporting success would hand back
/// a path the caller believes is private and is not.
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
/// `what` names the secret for the error message. A secret in a file is only
/// better than a secret in `argv` if the file is private; refusing to start is
/// the only way an operator finds out it is not.
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

/// Windows has no mode bits worth checking this way; an ACL check would not mean
/// the same thing. So "the permissions were checked" is a Unix-only claim.
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

/// Mode 0600 on a path that is not published yet — a temporary about to be
/// renamed into place, a socket about to be. Chmod after the rename leaves a
/// window at whatever the umask allowed, so the caller creates, restricts, then
/// publishes; `rdnsd`'s control socket had its own copy of this line
/// (`TODO.md` #30l).
#[cfg(unix)]
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

/// Nothing to do, and nothing to claim. See [`ensure_private`].
#[cfg(not(unix))]
pub fn restrict_to_owner(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn write_and_sync(temp: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = File::create(temp)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// A sibling of `path` to write first.
///
/// The process id is in the name so a temporary left behind by a crash is not
/// something a later run collides with or renames into place.
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
/// Best-effort: a durability refinement, not a correctness one — the reader
/// already cannot observe a partial file.
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

    /// An existing file is replaced, which a plain Windows `rename` would not do.
    #[test]
    fn test_replaces_an_existing_file() {
        let dir = ScratchDir::new("replace");
        let path = dir.path("zone");
        fs::write(&path, "old, and longer than what replaces it").expect("seed");

        write_atomically_str(&path, "new").expect("write");

        assert_eq!(fs::read_to_string(&path).expect("read back"), "new");
    }

    /// A stray `.zone.tmpNNN` is something a zone-directory scan would trip on.
    #[test]
    fn test_leaves_no_temporary_behind() {
        let dir = ScratchDir::new("clean");
        write_atomically_str(&dir.path("example.com.zone"), "@ IN A 192.0.2.1\n").expect("write");
        write_atomically_str(&dir.path("example.com.zone"), "@ IN A 192.0.2.2\n").expect("rewrite");

        assert_eq!(dir.entries(), vec!["example.com.zone".to_string()]);
    }

    /// The target is a directory, so the rename cannot succeed.
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

    /// Unix only: there are no mode bits to check on Windows.
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
            // Removed first: a previous iteration may have left it 0400.
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
                assert!(
                    e.to_string().contains(&format!("{mode:o}")),
                    "the error should name the mode it refused: {e}"
                );
            }
        }
    }

    /// A private write is never briefly readable under its final name.
    #[cfg(unix)]
    #[test]
    fn test_a_private_write_lands_already_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = ScratchDir::new("private-write");
        let path = dir.path("key.rdnskey");

        write_atomically_private(&path, "PrivateKey: not-really\n").expect("write");

        let mode = fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "got mode {:o}", mode & 0o777);
        assert_eq!(
            fs::read_to_string(&path).expect("read back"),
            "PrivateKey: not-really\n"
        );
        assert_eq!(dir.entries(), vec!["key.rdnskey".to_string()]);
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
