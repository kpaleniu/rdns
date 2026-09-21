# Domain Docs

How the engineering skills should consume this repo's domain documentation when
exploring the codebase.

**There is no `CONTEXT.md` and no `docs/adr/`, on purpose.** The vocabulary is
mostly the RFCs', which are cited in place rather than paraphrased into a
glossary (`CLAUDE.md` §1, §7), and the decisions are recorded where they were
made. `TODO.md` #98 is the reasoning and the two shapes that were declined; do
not file the absence again.

## Before exploring, read these

- **`docs/spec/`** — seven files saying what the code actually does, derived by
  reading it rather than by reading intent, with every known RFC deviation and
  gap in one table. `README.md` there defines the few terms that are this
  project's rather than the protocol's.
- **`docs/ARCHITECTURE_REVIEW.md`** and `TODO.md`'s `## Architecture:` sections
  — the decisions an ADR directory would otherwise hold, each stating what was
  rejected and why.
- The **doc comment on the type**, for a name this project coined
  (`ServeContext`, `Reloading`, the denial cache). That is where a definition
  lives; a second copy is where the drift goes (§7).

## Use the project's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal,
a hypothesis, a test name), use the RFC's term and cite the section that says
it, not the one nearby that sounds relevant (§1). For a coined name, use it as
its doc comment defines it.

If there is no term for what you mean, that is a signal: either you are
inventing language the project does not use (reconsider), or there is a real gap
— which is a numbered item in `TODO.md`, not a sentence in a doc comment (§18).

## Flag conflicts with a recorded decision

If your output contradicts a decision in `TODO.md`'s architecture sections, a
deviation in `docs/spec/07-rfc-conformance.md`, or a rule in `CLAUDE.md`,
surface it explicitly rather than silently overriding:

> _Contradicts #30's "What must not be unified", but worth reopening because…_
