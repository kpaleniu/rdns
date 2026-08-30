# rdns — behavioural specification

What the code does today, derived by reading it on 2026-08-03 at commit `5506612`
and revised the same day at `262b5f3`. Nine commits landed between those two and
closed most of what the first reading recorded as a gap; those entries are struck
through and kept. Where the code and an RFC disagree, the disagreement is
recorded as a deviation.

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

- MUST / MUST NOT / SHOULD carry their RFC 2119 senses and describe the
  implementation's obligations as currently coded. A statement with no such
  keyword describes observed behaviour.
- `file.rs:NNN` anchors a claim to the code implementing it. Line numbers drift;
  the function name beside them does not.
- A deviation is behaviour a reading of the cited RFC would not predict.
  Deviations are listed per file and collected in `07-rfc-conformance.md`.
- "the library" is the `rdns` crate. "the daemons" are `rdnsd` and `rdnsr`.

## Scope

`rdns` is an authoritative nameserver (`rdnsd`), a recursive/forwarding resolver
(`rdnsr`), a query client (`rdnsc`), a control client (`rdnsctl`), and the
library all four share. It serves and validates DNSSEC (ECDSA P-256/P-384,
RSA/SHA-256, Ed25519 on the read side; ECDSA and Ed25519 on the signing side),
speaks AXFR and IXFR in both directions with TSIG, implements NOTIFY and the
secondary role including EXPIRE, answers Prometheus scrapes, and serves dynamic
UPDATE (RFC 2136) — TSIG-only, scoped per key, writing each accepted update back
to the zone file before answering. Class IN only.

Not implemented: DNS over TLS/HTTPS/QUIC, DNS Cookies as anything but opaque
bytes, SIG(0), DNAME, SVCB/HTTPS, and any record type outside the thirteen listed
in `02-zone-model.md` — unknown types round-trip as opaque RDATA per RFC 3597 but
cannot be written in a zone file except in `\#` form.

## Overlap with `docs/CLI_USAGE.md`

`CLI_USAGE.md` is the operator's guide: what a flag is for and what to type.
[`06-operations.md`](06-operations.md) is the specification: the default, the
unit, and what happens on breach. A default value belongs in `06-operations.md`;
if the two disagree, the code decides.

## Not specified here

Performance figures, allocation counts and benchmark baselines. Those live in
`TODO.md` and `rdns/tests/allocations.rs`, where they are asserted rather than
described.
