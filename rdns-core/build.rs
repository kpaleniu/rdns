//! Stamp the build with what git says it is, so `--version` identifies a commit.
//!
//! In the library, not once per binary: every binary reads `rdns::VERSION`.

use std::process::Command;

fn main() {
    let package = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());

    // For the container image, whose build context carries no `.git` on purpose:
    // shipping the repository into a build stage puts every committed version of
    // every file one careless `COPY --from` away from an image layer. The
    // Dockerfile runs `git describe` outside and passes the result in.
    //
    // The *description*, not the whole version string, so the `match` below
    // formats both paths and they cannot drift.
    println!("cargo:rerun-if-env-changed=RDNS_GIT_DESCRIBE");
    let told = std::env::var("RDNS_GIT_DESCRIBE")
        .ok()
        .map(|told| told.trim().to_string())
        .filter(|told| !told.is_empty());

    // `--always` so a repository with no tags still yields the short hash,
    // `--dirty` so an uncommitted build cannot pass for a clean one.
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
        // A released tarball, or a shallow CI checkout: the package version
        // alone is honest, and failing the build over it would not be.
        None => package,
    };
    println!("cargo:rustc-env=RDNS_VERSION={version}");

    // Re-stamp on a new commit or a branch switch. With no `.git` it never
    // fires, which is right for a build that had no git to ask.
    println!("cargo:rerun-if-changed=../.git/HEAD");
}
