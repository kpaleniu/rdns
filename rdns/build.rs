//! Stamp the build with what git says it is.
//!
//! All three binaries were `version = "0.1.0"`, so `--version` could not identify
//! a build — which matters the moment an operator is asked "which commit is that
//! server running" and the honest answer is "0.1.0, like every other one".
//!
//! In the library rather than once per binary: three copies of this would be
//! three chances for one to drift (`CLAUDE.md` §7). Every binary reads
//! `rdns::VERSION`.
//!
//! `RDNS_GIT_DESCRIBE` in the environment replaces the `git describe` call, for
//! a build that has no repository to ask — the container image is the one that
//! does this, and the reason it has none is below.

use std::process::Command;

fn main() {
    let package = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());

    // A build that has been *told* the description takes that answer instead of
    // running git. This exists for the container image, whose build context
    // deliberately contains no `.git`: shipping the repository into a build stage
    // so that a build script can run `git describe` inside it puts every version
    // of every file ever committed one careless `COPY --from` away from an image
    // layer, and a discarded build stage is a convention rather than a guarantee.
    // The Dockerfile runs `git describe` outside and passes the result in.
    //
    // What is passed is the *description*, not the whole version string, so both
    // paths are formatted by the one `match` below and cannot drift into
    // producing different-looking versions for the same commit (`CLAUDE.md` §7).
    println!("cargo:rerun-if-env-changed=RDNS_GIT_DESCRIBE");
    let told = std::env::var("RDNS_GIT_DESCRIBE")
        .ok()
        .map(|told| told.trim().to_string())
        .filter(|told| !told.is_empty());

    // `--always` so a repository with no tags still yields the short hash,
    // `--dirty` so an uncommitted build says so — a version string that cannot
    // tell a clean build from a modified one is the version string of the thing
    // you were about to blame.
    let described = told.or_else(|| {
        Command::new("git")
            .args(["describe", "--always", "--dirty", "--tags"])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
            .filter(|described| !described.is_empty())
    });

    let version = match described {
        Some(described) => format!("{package} ({described})"),
        // No git, or not a repository: a released tarball, or a shallow CI
        // checkout with no history. The package version alone is honest, and
        // failing the build over it would be absurd.
        None => package,
    };
    println!("cargo:rustc-env=RDNS_VERSION={version}");

    // Re-stamp when the checked-out commit changes. `.git/HEAD` covers a commit
    // or a branch switch; if there is no `.git` this simply never fires, which is
    // the right answer for a build that had no git to ask.
    println!("cargo:rerun-if-changed=../.git/HEAD");
}
