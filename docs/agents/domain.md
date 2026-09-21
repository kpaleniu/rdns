# Domain Docs

How the engineering skills should consume this repo's domain documentation when
exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root — the glossary. Not present yet.
- **`docs/adr/`** — read the ADRs that touch the area you are about to work in.
  Not present yet.
- **`docs/spec/`** — seven files saying what the code actually does, derived by
  reading it rather than by reading intent, with every known RFC deviation and
  gap in one table. Present, and the nearest thing this repo has to a domain
  reference today.
- **`docs/ARCHITECTURE_REVIEW.md`** and `TODO.md`'s `## Architecture:` sections
  — the decisions an ADR directory would otherwise hold.

If any of these files don't exist, **proceed silently**. Don't flag their
absence; don't suggest creating them upfront. The `/domain-modeling` skill
(reached via `/grill-with-docs` and `/improve-codebase-architecture`) creates
them lazily when terms or decisions actually get resolved.

## File structure

Single-context repo: the nine crates share one domain, and per-crate behaviour
is in `docs/spec/`.

```
/
├── CONTEXT.md
├── docs/adr/
│   ├── 0001-….md
│   └── 0002-….md
└── rdns*/ …
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal,
a hypothesis, a test name), use the term as defined in `CONTEXT.md`. Don't drift
to synonyms the glossary explicitly avoids. Here the vocabulary is largely the
RFCs': cite the section that says it, not the one nearby that sounds relevant
(`CLAUDE.md` §1).

If the concept you need isn't in the glossary yet, that's a signal: either
you're inventing language the project doesn't use (reconsider) or there's a real
gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than
silently overriding:

> _Contradicts ADR-0007 (…), but worth reopening because…_
