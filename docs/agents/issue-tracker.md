# Issue tracker: `docs/issues/` and `docs/closed/`

Issues for this repo are numbered markdown files, one per number:
`docs/issues/NNN.md` while open, `docs/closed/NNN.md` once closed, the number
zero-padded to three digits. `TODO.md` lists which are open and holds one row
per closed item. GitHub Issues are not used: the remote is private, the owner
pushes when they choose to, and the numbers are already referenced from the
code, from `CLAUDE.md` and from each other.

One file per number since 2026-10-03; before that open items were sections of
`TODO.md` and closed ones of a single `docs/CLOSED_WORK.md`, which reached
19,845 lines. `docs/closed/log.md` says why it was split.

## Conventions

- A file starts with its `### <N>. <title>` heading and carries the status on
  that line (`**filed …**`, `**closed …**`, the triage role). Sub-items take a
  letter suffix inside their parent's file: `#13a`, `#79b`, `#38b`.
- **Numbers are stable identifiers: move a file, never renumber it**
  (`CLAUDE.md` §11). The next free number is one past the highest ever used:
  `ls docs/issues docs/closed | grep -o '^[0-9]*' | sort -n | tail -1`. #5, #8
  and #9 were used and have no file; they are rows in `TODO.md`'s closed table.
- `## What is open` in `TODO.md` names the currently open numbers. It is a
  status line: overwrite it. A *claim* that turned out wrong is struck through
  in place with the correction beside it, keeping the reasoning that produced it
  (§11) — the test is whether a reader of the struck version learns why
  something went wrong.
- Closing an item: `git mv docs/issues/NNN.md docs/closed/NNN.md`, so history
  follows the file; update the heading's status, append the closing note, and
  add one row to `TODO.md`'s `## Closed work` pointing at the commit. The text is
  kept verbatim, strike-throughs and wrong claims included.
- Nothing in these files describes a particular machine (§20). Paths, the WSL
  image and what is installed belong in the untracked `CLAUDE.local.md`.

## When a skill says "publish to the issue tracker"

Create `docs/issues/NNN.md` with the next free number and add the number to
`TODO.md`'s `## What is open`. A review finding with no number is a review
finding nobody schedules (§18).

Before filing:

- Count the instances of the shape before fixing one, and put the count in the
  row (§18).
- Write the sentence that would make the row wrong, and go and look (§19). If
  looking is a `grep` and a function, there is no excuse for filing without it.
- File what you saw; file the fix only if you checked it. A row naming a wrong
  remedy costs more than one naming no remedy at all (§18).

## When a skill says "fetch the relevant ticket"

Read `docs/issues/NNN.md`, or `docs/closed/NNN.md` if it is not there. A
sub-item (`#13a`) is in its parent's file. To search across items, `grep -l` the
two directories: the file name is the number.

## PRs as a request surface

Off. Nothing arrives from outside; this is a single-owner private repo.
