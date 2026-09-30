# With RPZ or DNS64, `rdnsr` answers with data no zone holds

A policy rewrite replaces the answer with what a policy zone says, and a DNS64
synthesis answers with an address that exists in no zone. Both are opt-in and
both are the feature rather than a side effect; a reader of RFC 1034 would
predict neither. Every such answer goes out with AD clear, so a validating
client finds the signatures missing: neither answer is authentic and neither
claims to be.

## Considered Options

Two departures from BIND's RPZ, both stated in `rdns/src/rpz.rs`'s header:

- A rewrite applies to a client that set DO. BIND's `break-dnssec no` declines,
  which makes a block bypassable by one bit.
- Zone precedence is per pass, not per zone: every zone's QNAME and client-IP
  triggers are tried before any response-IP trigger, because a response-IP
  match costs the resolution a QNAME block exists to avoid.

For DNS64, RFC 6147 §5.5 is why a client that set both CD and DO gets the
denial instead of a synthesis.
