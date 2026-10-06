---
status: accepted
---

# An empty zone beats a less specific routed domain

Between an empty zone and a routed domain, the more specific name decides,
and a tie goes to the routed domain. So `--forward-zone 10.in-addr.arpa.=…`
overrides the empty zone, while `--upstream` (a forward zone at `.`) and a
routed `in-addr.arpa.` do not: private PTR queries still never leave the
host. Decided in `TODO.md` #173.

## Considered Options

- BIND's rule: an empty zone is not created when "covered by a forward-only
  forwarding declaration", so a global `forward only` turns them all off.
  Declined: forwarding everything to a public resolver is common, and sending
  it every private PTR lookup is the leak RFC 6303 exists to stop.
- Unbound's rule: no routed domain overrides a default zone; the operator
  adds `local-zone: <name> nodefault` as well. Declined: a forward zone for
  `10.in-addr.arpa.` that is silently ignored is a setting the operator
  believes is in force and is not (`CLAUDE.md` §15).

## Consequences

An operator coming from BIND who forwards globally and expects private PTRs
to go upstream must say so with `--no-empty-zones` or
`--disable-empty-zone`. The startup banner names each empty zone that is
off and each one a routed domain overrides.
