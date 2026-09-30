# Domain Docs

How the engineering skills should consume this repo's domain documentation when
exploring the codebase.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root: the glossary. Single context; there is no
  `CONTEXT-MAP.md`.
- **`docs/adr/`**: read ADRs that touch the area you are about to work in.

If either does not exist, **proceed silently**. `/domain-modeling` creates them
lazily, when a term or a decision is actually resolved.

Older decisions are still where they were made: `TODO.md`'s `## Architecture:`
sections and `docs/ARCHITECTURE_REVIEW.md`. When work touches one, move it into
an ADR and leave a one-line pointer in its place (#148).

`docs/spec/` says what the code does. It is not a glossary and not a decision
record.

## File structure

```
/
├── CONTEXT.md
├── docs/adr/
│   └── 0001-<slug>.md
├── rdns-core/  rdns/  rdnsd/  rdnsr/  rdnsc/ ...
```

## Use the glossary's vocabulary

When your output names a domain concept (an issue title, a refactor proposal, a
hypothesis, a test name), use the term as `CONTEXT.md` defines it, and not a
synonym it lists under _Avoid_.

A protocol term is the RFC's: cite the section that says it (`CLAUDE.md` §1).
`CONTEXT.md` holds the terms this project coined or narrowed. It says what the
concept *is*; the doc comment on the type says what the type does. Neither
restates the other, because the second copy is where drift goes (§7).

If the concept you need is not in the glossary, either you are inventing
language the project does not use (reconsider), or there is a real gap: resolve
it with `/domain-modeling`.

## Flag ADR conflicts

If your output contradicts an ADR, a decision in `TODO.md`'s architecture
sections, or a rule in `CLAUDE.md`, surface it rather than silently overriding:

> _Contradicts ADR-0007, but worth reopening because…_
