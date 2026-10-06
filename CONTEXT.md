# rdns

A DNS implementation: a wire-format library, an authoritative server (`rdnsd`)
and a recursive resolver (`rdnsr`). Protocol terms are the RFCs'; this file
holds only the terms the project coined or narrowed.

## Language

**Zone answer**:
What one zone says to one question — records, a referral, or a no — together
with the DNSSEC records that reply owes.
_Avoid_: authoritative answer (a referral is a zone answer with AA clear,
RFC 1035 §4.1.1)

**Source**:
The address block a per-client limit counts as one client: an IPv4 address,
or an IPv6 /56, of a peer.
_Avoid_: client IP, address (when the block is meant)

**Response target**:
The address block a response budget is charged to: an IPv4 /24, or an IPv6
/56, of a peer.
_Avoid_: source, victim

**Peer**:
The exact address a message or connection came from, in canonical form: an
IPv4-mapped IPv6 address is the IPv4 address it maps. Many peers can be one
source.
_Avoid_: source (when the exact address is meant)

**Allowed client**:
A peer `rdnsr`'s query ACL admits. Matched as a peer, never as a source: the
ACL names hosts and networks, not the blocks a limit counts.
_Avoid_: trusted client, whitelisted source

**Idle**:
Of a stream connection: the client has started no new message or request,
whatever is still being answered. A connection mid-handshake is idle.
_Avoid_: silent (a client's pings are not a request), quiescent (nothing in
flight)

**Trusted start**:
A zone a resolution began from whose DNSKEY set was already validated to a
trust anchor, held with the keys as they were read at that moment.
_Avoid_: trust point, resume point (and not a trust anchor, RFC 4033 §2, or a
secure entry point, RFC 4034 §2.1.1)

**Resolution**:
One question pursued to an answer or a failure, with every upstream query it
makes on the way: referrals, CNAME hops, nameserver addresses, and the DNSKEY
and DS sets validation needs. A prefetch is one; DNS64's A query is a second.
_Avoid_: lookup, fetch, query (one upstream exchange is a query)

**Query budget**:
The upstream queries one resolution may make, however long they take.
_Avoid_: budget alone (a response budget is RRL's, charged to a response
target)

**Resolution timer**:
RFC 8767 §5's query resolution timer: the time one resolution may take, from
its start, waiting included. When it fires the resolution is abandoned.
_Avoid_: timeout (one upstream exchange has its own), deadline, client response
timer (RFC 8767 §5's other timer, about when a client is answered)

**Routed domain**:
A subtree `rdnsr` resolves through servers the operator named, or answers
from data it holds, rather than from the root: a forward zone, a stub zone or
a local zone. The most specific one covering a name decides; the root is one
when `rdnsr` forwards everything.
_Avoid_: zone alone (only a local zone holds data; the others are routes),
conditional forwarder

**Forward zone**:
A routed domain whose servers are asked with recursion desired and do the
resolving themselves.
_Avoid_: forwarder (the server, not the route)

**Stub zone**:
A routed domain whose servers are where the delegation walk starts, asked
without recursion as any authority would be.
_Avoid_: stub resolver (RFC 1034's client, an unrelated thing)

**Local zone**:
A routed domain whose data `rdnsr` holds and answers from, as `rdnsd` would
answer for a zone it serves. The operator's data, not a policy rewrite.
_Avoid_: local data (RPZ's action), auth zone

**Authentication name**:
The name a TLS peer's certificate must carry, written by the operator beside
the peer's address (RFC 8310 §2, "authentication domain name"). Required
wherever this project speaks TLS as a client; there is no unauthenticated
mode.
_Avoid_: SNI (what is sent, not what is checked), hostname, XoT name

**Empty zone**:
A reverse zone for address space that is not globally unique, which `rdnsr`
answers itself as holding nothing but its SOA and NS (RFC 6303 §4). Each can
be switched off; a routed domain at the same name or below overrides it.
_Avoid_: local zone (the operator's data), locally served zone

**Special-use name**:
A name answered here by specification and never configurable: `localhost.`
and its reverse names, `local.`, `invalid.` (RFC 6761, RFC 6762).
_Avoid_: empty zone (those can be switched off), reserved name

**In-flight query**:
A UDP query `rdnsr` admitted to resolution and not yet answered or abandoned,
holding one of `--max-inflight-udp` places. Every place held, the oldest gives
way once past the client response timer; otherwise the newcomer is dropped.
_Avoid_: permit, slot
