---
status: accepted
---

# `::` is dual-stack on every platform

A listener bound to the IPv6 wildcard serves IPv4 clients too, on Linux and
Windows alike: `IPV6_V6ONLY` is set to 0 explicitly on every IPv6 listener
bind rather than left to the OS, whose defaults differ (0 on Linux, 1 on
Windows). An operator who wants IPv6 only binds a specific IPv6 address,
which cannot receive IPv4. Implemented by `TODO.md` #159.

## Considered Options

IPv6-only everywhere, with a repeatable `--host` so `0.0.0.0` and `::`
together serve both — Knot's model ("`::` for all configured IPv6
addresses"), and NSD's repeatable `ip-address`. Declined: it needs a
repeatable listen address across every bind site and the `[server]` table,
and it would make #158 the wrong fix. With no dual-stack socket, an
IPv4-mapped peer can only be a spoofed UDPv6 datagram, which `TransferAcl`'s
family rule refuses correctly; canonicalizing it, as #158 does, would open
that datagram's one grant for nothing.

## Consequences

IPv4 clients on `::` arrive as IPv4-mapped addresses, so #158's `Peer`
canonicalization is a prerequisite, not a cleanup. Windows starts answering
IPv4 on `::`, which it did not before.
