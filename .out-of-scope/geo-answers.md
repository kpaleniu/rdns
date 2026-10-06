# Geo answers

`rdnsd` does not choose an answer by where the client is: no GeoIP-selected
records, as BIND's `geoip` ACLs, Knot's `mod-geoip` and PowerDNS's GeoIP
backend and LUA records provide.

## Why this is out of scope

- **Tied to the ECS decision.** EDNS Client Subnet is declined on purpose
  (`docs/spec/07`, RFC 7871 row; `TODO.md` #45e). Without it, the address an
  authoritative server sees is the resolver's, so a geo answer is placed by
  the resolver's location, which for a large public resolver says little
  about the client. Reopening one decision means reopening the other.
- **A dependency that has to be fed.** A GeoIP database is a crate, a
  licence (MaxMind's GeoLite2 needs an account), and a file that goes stale
  unless something updates it — for answers whose accuracy the ECS decision
  has already capped.

Operators who need traffic steered by location use anycast, or a DNS provider
that does geo with ECS.

Reopen together with ECS (#45e), if that decision is ever reversed.

## Prior requests

- #181: no views, no geo (filed 2026-10-05, closed 2026-10-06)
