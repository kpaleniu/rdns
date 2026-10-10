"""Refuse to release a tag that is not releasable (TODO.md #201).

    python tools/release_check.py v0.1.0

Two checks, both before anything is built:

- the tag is `v` + the workspace version, so `--version` and the crate
  metadata agree;
- `ci.yml` succeeded on the tagged commit. CI runs once per push, on its head,
  so a commit in the middle of a batched push has no run and is refused.

Run with the tag checked out: the version is read from the working tree.
Needs `git`, `cargo` and an authenticated `gh` (in Actions, `GH_TOKEN`).
Exit 0 when releasable, 1 with the reason otherwise.
"""

import json
import subprocess
import sys


def out(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def workspace_version():
    meta = json.loads(out("cargo", "metadata", "--no-deps", "--format-version", "1"))
    versions = {p["version"] for p in meta["packages"]}
    if len(versions) != 1:
        sys.exit(f"workspace members disagree on the version: {sorted(versions)}")
    return versions.pop()


def green_ci_runs(sha):
    runs = json.loads(
        out(
            "gh", "api",
            f"repos/{{owner}}/{{repo}}/actions/workflows/ci.yml/runs"
            f"?head_sha={sha}&status=success&per_page=1",
        )
    )
    return runs["total_count"]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    tag = sys.argv[1]

    version = workspace_version()
    if tag != f"v{version}":
        sys.exit(f"tag {tag} is not v + the workspace version {version}")

    try:
        sha = out("git", "rev-parse", f"{tag}^{{commit}}").strip()
    except subprocess.CalledProcessError:
        sys.exit(f"no tag {tag} in this repository")
    if green_ci_runs(sha) == 0:
        sys.exit(f"no successful ci.yml run for {tag} ({sha}); tag the head of a pushed, green commit")

    print(f"{tag} is releasable: version {version}, ci.yml green on {sha}")


if __name__ == "__main__":
    main()
