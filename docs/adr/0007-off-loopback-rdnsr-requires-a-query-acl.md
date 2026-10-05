---
status: accepted
---

# `rdnsr` bound off loopback refuses to start without a query ACL

If any listener (`--host`, `--tls-listen`, `--quic-listen`, `--https-listen`)
binds outside `127.0.0.0/8` and `::1`, `--allow-query` must be given. An open
resolver is written down as `0.0.0.0/0` and `::/0`, never reached by default.
No list with loopback binds only is open, as before. Decided in `TODO.md` #171.

## Considered Options

- Loopback-only when no list is given, as Unbound and BIND do. Declined: a
  deployment already on `--host 0.0.0.0` would answer nobody after an upgrade,
  with nothing failing — the silent narrowing `CLAUDE.md` §16 forbids.
- Open when no list is given, plus a startup warning. Declined: a warning in
  a log nobody reads is how an open resolver ships, and it is an
  amplification vector for other people's victims.

## Consequences

An upgrade that binds off loopback stops at startup and names the flag: one
restart, and the operator states the policy. A bind to a specific internal
address needs the list too, because "internal" is not something the code can
check. Loopback is never allowed implicitly once a list is given.
