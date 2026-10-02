# Connection turnover limits

No cap on DNS transactions per TCP connection, and no maximum connection
duration, on any stream listener (TCP, DoT, DoH, DoQ).

## Why this is out of scope

RFC 7766 §10 lists both among five "configurable connection management
options". Neither bounds anything the other limits do not:

- A client cut off by either reconnects. The resources at stake —
  descriptors, slots — are bounded by `max-connections` (#155) and by the
  per-source limit (#156), which is what stops one client holding every slot.
- The case for them is forced turnover when a listener is full, so waiting
  clients get in. A per-source limit gives the same fairness without
  dropping a well-behaved client mid-session.
- A duration cap truncates a long AXFR unless transfers are exempt. NSD's
  `tcp-timeout` (120 s), the only shipped analogue, "also affects zone
  transfers over TCP".

Of the peers checked: NSD has `tcp-query-count` (default 0, "no maximum");
Knot has neither; Unbound's `max-reuse-tcp-queries` is for its outgoing
connections.

Reopen if #155's `dns_connection_accept_waits_total` shows a listener
saturated by many distinct sources, which the per-source limit cannot help.

## Prior requests

- #156: RFC 7766 §10's other connection limits (split 2026-10-02)
