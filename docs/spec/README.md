# rdns — behavioural specification

**This describes what the code does today**, derived by reading it on 2026-08-03
at commit `6882b1e` and revised the same day at `e2ebaef`, not what it is meant
to do. Nine commits landed between those two and closed most of what the first
reading recorded as a gap; every such entry is struck through and kept rather
than deleted, because what a gap *was*, and the reasoning that found it, is the
half worth having. Where the code and an RFC
disagree, the disagreement is written down as a deviation rather than smoothed
over; where a behaviour is a deliberate local choice, the choice is named.

It exists because `TODO.md` says *where the work is*, `CLAUDE.md` says *which
mistakes not to repeat*, and neither says *what the thing does* in a form you
could hand to someone writing a conformance test or a second implementation.
That gap is what these files fill.

## Reading order

| file | what it specifies |
|---|---|
| [`01-wire-format.md`](01-wire-format.md) | message codec, domain names, EDNS0, TCP framing, TSIG |
| [`02-zone-model.md`](02-zone-model.md) | zone-file syntax, the in-memory zone, name lookup |
| [`03-authoritative-server.md`](03-authoritative-server.md) | `rdnsd`: answering, transfers, NOTIFY, the secondary role, dynamic UPDATE, reload, control |
| [`04-dnssec.md`](04-dnssec.md) | signing, denial of existence, validation, RFC 5011 |
| [`05-resolver.md`](05-resolver.md) | `rdns::resolver` and `rdnsr`: recursion, forwarding, caching |
| [`06-operations.md`](06-operations.md) | configuration, limits, metrics, shutdown, `rdnsc`, `rdnsctl` |
| [`07-rfc-conformance.md`](07-rfc-conformance.md) | the RFC matrix, and every known deviation in one place |

## Conventions

- **MUST / MUST NOT / SHOULD** carry their RFC 2119 senses and describe the
  *implementation's* obligations as currently coded. A statement with no such
  keyword is a description of observed behaviour.
- **`file.rs:NNN`** anchors a claim to the code that implements it. Line numbers
  drift; the function name beside them does not.
- A **deviation** is behaviour that a reading of the cited RFC would not predict.
  Deviations are listed in each file and collected in `07-rfc-conformance.md`.
- "the library" is the `rdns` crate. "the daemons" are `rdnsd` and `rdnsr`.

## Scope of the implementation, in one paragraph

`rdns` is an authoritative nameserver (`rdnsd`), a recursive/forwarding resolver
(`rdnsr`), a query client (`rdnsc`), a control client (`rdnsctl`), and the
library all four share. It serves and validates DNSSEC (ECDSA P-256/P-384,
RSA/SHA-256, Ed25519 on the read side; ECDSA and Ed25519 on the signing side),
speaks AXFR and IXFR in both directions with TSIG, implements NOTIFY and the
secondary role including EXPIRE, and answers Prometheus scrapes. It serves dynamic UPDATE
(RFC 2136), TSIG-only and scoped per key, writing each accepted update back to
the zone file before answering. It handles
class IN only. It does **not** implement DNS over TLS/HTTPS/QUIC, DNS Cookies as
anything but opaque bytes, SIG(0), DNAME, SVCB/HTTPS, or any record type outside
the thirteen listed in `02-zone-model.md` — unknown types round-trip as opaque
RDATA per RFC 3597 but cannot be written in a zone file except in `\#` form.

## Overlap with `docs/CLI_USAGE.md`, stated so it does not drift

`CLI_USAGE.md` came first and is the **operator's guide**: what a flag is for,
what to type, what goes wrong. [`06-operations.md`](06-operations.md) is a
**specification**: the default, the unit, and what happens on breach. They
necessarily name the same flags, which is `CLAUDE.md` §7's shape and worth being
explicit about rather than discovering later:

- A **default value** belongs in `06-operations.md`. If the two disagree, the
  code decides and `06-operations.md` is the one to correct first.
- **Prose about when to reach for a flag** belongs in `CLI_USAGE.md`, and the
  spec should not repeat it.
- Neither is currently complete: `CLI_USAGE.md` covers 14 of `rdnsd`'s 27 flags
  (see `docs/ARCHITECTURE_REVIEW.md` B7).

## What is deliberately not specified here

Performance figures, allocation counts and benchmark baselines. Those live in
`TODO.md` and in `rdns/tests/allocations.rs`, where they are asserted rather
than described, and a spec that repeats them would be a second copy to drift.
