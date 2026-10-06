# Views

`rdnsd` answers every client from the same zones. There is no split horizon:
no zone set chosen by the client's address or TSIG key, as BIND's `view`,
Knot's per-ACL zone sets, or PowerDNS's views (5.0.0, experimental, LMDB
only) provide.

## Why this is out of scope

The case views are reached for is internal clients seeing internal data. Two
setups already give it without one:

- `rdnsr` local zones (#174): the internal clients' resolver holds the
  internal zone and answers it; `rdnsd` serves the public one.
- A second `rdnsd` on the internal address, with its own zone directory.

A view is not one feature but a per-view copy of every zone-scoped subsystem:
reload, catalog consumption, the secondary role and EXPIRE, NOTIFY, transfer
ACLs, UPDATE and its journal, metrics labels, the control socket's `status`
and `dump`. The cost is that whole surface; what it buys over the two setups
above is one process instead of two.

Reopen if a deployment needs per-client answers that neither setup can give,
such as one zone name served from two different data sets to clients that
share a resolver.

## Prior requests

- #181: no views, no geo (filed 2026-10-05, closed 2026-10-06)
