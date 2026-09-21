# Issue tracker: `TODO.md`

Issues for this repo are numbered items in `TODO.md`. GitHub Issues are not
used: the remote is private, the owner pushes when they choose to, and the
numbers here are already referenced from the code, from `CLAUDE.md` and from
each other.

## Conventions

- An item is a `### <N>. <title>` section under `## Open work`. Sub-items take a
  letter suffix: `#13a`, `#79b`, `#38b`.
- **Numbers are stable identifiers: move a section, never renumber it**
  (`CLAUDE.md` §11). The next free number is one past the highest ever used —
  check `TODO.md` *and* `docs/CLOSED_WORK.md`, which holds every closed section
  in full under the same number. Highest used at the time of writing: #97.
- `## What is open` names the currently open numbers. It is a status line:
  overwrite it. A *claim* that turned out wrong is struck through in place with
  the correction beside it, keeping the reasoning that produced it (§11) — the
  test is whether a reader of the struck version learns why something went wrong.
- Closing an item: move the section to `docs/CLOSED_WORK.md` verbatim,
  strike-throughs and wrong claims included, and leave one line in `## Closed
  work` pointing at it and at the commit.
- Nothing in `TODO.md` describes a particular machine (§20). Paths, the WSL
  image and what is installed belong in the untracked `CLAUDE.local.md`.

## When a skill says "publish to the issue tracker"

Add a section under `## Open work` with the next free number and add the number
to `## What is open`. A review finding with no number is a review finding
nobody schedules (§18).

Before filing:

- Count the instances of the shape before fixing one, and put the count in the
  row (§18).
- Write the sentence that would make the row wrong, and go and look (§19). If
  looking is a `grep` and a function, there is no excuse for filing without it.
- File what you saw; file the fix only if you checked it. A row naming a wrong
  remedy costs more than one naming no remedy at all (§18).

## When a skill says "fetch the relevant ticket"

Read the `### <N>.` section in `TODO.md`. If it is not there, read the section
of the same number in `docs/CLOSED_WORK.md`.

## PRs as a request surface

Off. Nothing arrives from outside; this is a single-owner private repo.
