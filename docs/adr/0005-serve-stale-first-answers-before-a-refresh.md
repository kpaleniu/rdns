# `--serve-stale-first` answers stale before any refresh is tried

RFC 8767 §4 allows stale data only when it "is unable to be authoritatively
refreshed". `rdnsr --serve-stale-first` answers from the stale window at once
and refreshes behind the answer, as BIND's `stale-answer-client-timeout 0`
does, so a slow authoritative server costs the client nothing. Off by default,
and refused without a `--serve-stale` window.

## Considered Options

RFC 8767 §5's 1.8-second client response timer, the conforming shape, was
declined: BIND removed its non-zero form after two CVEs, and it needs a
resolution that outlives the query that started it (`TODO.md` #58).
