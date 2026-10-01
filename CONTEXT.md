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

**Trusted start**:
A zone a resolution began from whose DNSKEY set was already validated to a
trust anchor, held with the keys as they were read at that moment.
_Avoid_: trust point, resume point (and not a trust anchor, RFC 4033 §2, or a
secure entry point, RFC 4034 §2.1.1)
