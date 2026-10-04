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
