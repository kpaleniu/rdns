# 5. The resolver (`rdns::resolver`, `rdnsr`)

Recursion and forwarding are two modes of one resolver; only the means of
obtaining an answer differs. `rdnsr` is a separate binary from `rdnsd`.

Everything is async `tokio::net`. Each hop is an `await` on a socket.

---

## 5.1 Configuration and defaults

`ResolverConfig`:

| field | default | note |
|---|---|---|
| `mode` | `Recurse` | any `--upstream` switches to `Forward` |
| `upstream_servers` | 8.8.8.8:53, 1.1.1.1:53 | Forward mode only |
| `root_hints` | built-in, v4/v6 interleaved | so either family is reached in the first hop or two, before RTT selection has data |
| `timeout_ms` | 5000 | per query |
| `max_delegations` | 16 | referrals followed before giving up |
| `max_cname_hops` | 8 | |
| `query_budget` | 64 | total upstream queries one `resolve` may spend |
| `udp_payload_size` | 4096 | advertised upstream |
| `delegation_cache_size` | 10 000 | 0 disables, which restarts every query at the root |
| `qname_minimization` | on | RFC 9156 |
| `zero_x20` | on | draft-vixie-dnsext-dns0x20 |
| `server_port` | 53 | configurable so tests can stand up a fake hierarchy |
| `dnssec` | `None` | off by default |

`--root-hints <file>` reads named.root format. A stray line is skipped rather
than sinking the file (`parse_root_hints` returns a `Vec`).

---

## 5.2 Query hygiene — what goes out

Every outgoing query carries a random transaction id, a random source port (a
fresh socket per query), and 0x20 case randomization of the QNAME when enabled.

Every response is checked against the query it answers (`response_matches`):
transaction id, question count, QNAME byte-exact when 0x20 is on and
case-insensitively when it is off, QTYPE and QCLASS. A mismatch is discarded, not
answered from.

With `--dnssec-validate`, every query also carries DO and CD — an upstream that
validates on our behalf and returns SERVFAIL leaves us nothing to check.

---

## 5.3 Recursion

### The walk

```
start = the deepest cached delegation covering the qname, else the root hints
loop, bounded by max_delegations and by the query budget:
    ask the servers for that zone, in RTT order
    classify the response:
        answer          -> done (or follow a CNAME or a DNAME, bounded by
                                    max_cname_hops)
        referral        -> descend, if in bailiwick
        negative        -> done
```

`walk` and `resolve_from_root` return an `Answered` — the response *and* the zone
whose servers gave it, which is what bailiwick is judged against.

### Bailiwick rules

- A referral must be a descendant of the zone that gave it; anything above or
  beside is ignored.
- Glue is used only when in bailiwick. A nameserver with no usable glue is
  resolved separately, spending from the same budget.
- An answer record is kept only if its owner is on the chain: the name asked
  about, or a target of a CNAME already followed.
- A DNAME is the exception, because it never owns the name asked about — it owns
  an *ancestor* of it (RFC 6672 §2.2). It is kept when its owner is at or below
  the answering zone and strictly above a name on the chain. Bailiwick is the
  whole of the guard here: without it a server for `example.com.` answers with
  `com. DNAME evil.test.` and redirects every name under `com.` in this cache.

### DNAME (RFC 6672 §3.4, §3.4.1 step 4D)

The DNAME is kept in the answer rather than stripped, because it is the only
signed half of the redirection — "the CNAME will never be signed" (§5.3.1), so a
validating client handed the CNAME alone has nothing to check.

When the response carries a DNAME but no CNAME for the name being sought, the
substitution is done here and the CNAME synthesized with the DNAME's arrived
(already decremented) TTL: §3.4 makes that a recursive server's obligation —
"recursive caching name servers MUST perform CNAME synthesis on behalf of
clients" — because a conforming authoritative server sends one (§3.1) but a cache
holding the DNAME alone does not. The first applicable DNAME is the only one:
"there will be at most one ancestor with a DNAME" (§3.2).

A substitution past 255 octets is `ResolveError::NoResponse`, which is step 4D's
"return an implementation-dependent error to the application". The authoritative
side's YXDOMAIN (§2.2) has no resolver-side spelling, and a NOERROR carrying the
partial chain would say the name resolved to nothing rather than that it could
not be built.

### The budget

One `resolve` may spend `query_budget` upstream queries in total, across
delegations, CNAME hops and nameserver-address lookups — the NXNSAttack defence.
Exhausting it is `ResolveError::BudgetExhausted`.

### QNAME minimisation (RFC 9156)

Each server up the chain is asked only for the label being delegated.

- The probe QTYPE is A, not NS (RFC 9156 §2.3).
- `MAX_MINIMISE_COUNT` is 10, the RFC's recommendation; past it the resolver
  degrades to a full-QNAME query.
- An empty non-terminal encountered mid-walk is probed and passed through.

### Server selection — `RttStore`

Smoothed RTT per server address, capacity-bounded, evicting the slowest. Servers
for a zone are tried fastest-first; a server that fails is deprioritised
immediately.

### The delegation cache

`zone -> (servers, expiry)`, keyed by name, longest-match. The root is consulted
roughly once per TLD per TTL. A stale entry falls back to the root.

### Truncation

A UDP response with TC=1 is retried over TCP (`query_upstream_tcp`). A TCP
response that is still truncated is returned as it is. A zero-length TCP frame
from an upstream is an error, not an empty answer.

---

## 5.4 `rdnsr` — the daemon

UDP and TCP on one host:port, both spawned; whichever fails first takes the
process down. Binds 127.0.0.1 by default.

### Per-query path (`handle_query`, shared by both transports)

1. `validation::Request::from_bytes` — parses and refuses QR=1. Both failures are
   silence.
2. Opcode: anything but QUERY is NOTIMP with the opcode echoed.
3. EDNS sanity: malformed option list → FORMERR; version > 0 → BADVERS.
4. Special-use names (`special_names::lookup`) — answered locally, never
   forwarded, before every cache and before any resolution. AD is never set. Not
   skipped for a client with CD. See §5.6.
5. RFC 8198 synthesis from validated denials, skipped when the client set CD.
   Checked before the answer cache, so a flood of random names under one zone
   costs one upstream query rather than one per name. The positive half (a
   validated wildcard) is tried first; the two are mutually exclusive by
   construction.
6. Answer cache, then negative cache.
7. Miss → `Resolver::resolve`.
8. Validation, if `--dnssec-validate`: AD is set only on `Secure`; `Bogus` is
   SERVFAIL unless the client set CD.
9. Cache store by (name, type) with the answer's TTL, and its validation state
   alongside it, so a cached answer carries the same AD bit the first client saw.
10. Reply, echoing the transaction id with RA set and the OPT record mirrored
    only if the client used EDNS, sized by transport (`Transport::Udp` uses the
    client's advertised payload size; `Transport::Tcp` uses the 2-byte frame).

### Concurrency

| bound | value | note |
|---|---|---|
| `--max-inflight-udp` | 1024 | a task per datagram; a recursion is seconds of waiting. Floored at 1, no off switch |
| `MAX_TCP_CONNECTIONS` | 128 | |
| `MAX_INFLIGHT_PER_CONNECTION` | 16 | also the reply channel's depth, so a client pipelining faster than it reads pushes back on the read loop |

Over the UDP ceiling the datagram is dropped before it is copied and before any
task is spawned, silently, logged at `debug`.

> Gaps G-1 and G-2 — fixed 2026-08-03. ~~`rdnsr` runs no per-source rate limiter,
> response-byte budget, query logger, metrics, readiness probe or request
> validator.~~ `--query-rate` (200/s, burst 100, with exemptions),
> `--response-rate` (8192), `--metrics-listen` and `AdmissionCheck` are all wired
> in through the shared library types. No `/readyz`: a resolver has nothing to
> wait for. See `07-rfc-conformance.md`.

---

## 5.5 Caching

| cache | keys | bound | TTL cap |
|---|---|---|---|
| `DnsCache` (answers) | (folded name, qtype) | `--cache-size`, default 10 000 | `MAX_CACHE_TTL` = 86 400 s |
| `NegativeCache` (RFC 2308) | (folded name, qtype) | its own | `MAX_NEGATIVE_TTL` = 3600 s |
| `NsecCache` (RFC 8198) | zone → validated denial records | 1000 zones | the records' own |

- Keys go through `utils::NameKeyBuf`, whose only constructor folds.
- The negative TTL is `min(SOA MINIMUM, the SOA record's own TTL)`
  (RFC 2308 §3).
- `--no-cache` is a zero-capacity `DnsCache` (`put` is a no-op at 0), not an
  `Option`.
- Eviction halves the map with `select_nth_unstable`. Expiries are whole seconds,
  so a burst-filled cache has every entry on one value and a `retain` on the
  cutoff would empty it instead of halving it.

---

## 5.6 Names that never leave (`special_names.rs`)

Answered locally, never forwarded, each with a reason recorded for the log. Local
TTL 3600.

| name | answer | RFC |
|---|---|---|
| `localhost.`, `*.localhost.` | 127.0.0.1 / ::1; NODATA for other types | 6761 §6.3 |
| `1.0.0.127.in-addr.arpa.` PTR | `localhost.` | 6303 §4.2 |
| `127.in-addr.arpa.` and below | NXDOMAIN | 6303 §4.2 |
| `local.` and below | NXDOMAIN — mDNS, not DNS | 6762 §3 |
| `invalid.` and below | NXDOMAIN | 6761 §6.4 |
| RFC 1918 reverse zones (`10.`, `16–31.172.`, `168.192.in-addr.arpa.`) | NXDOMAIN | 6303 §4 |

---

## 5.7 Managed trust anchors in `rdnsr`

With `--auto-trust-anchor`, a background task probes the anchored zone's DNSKEY
RRset on a timer, applies RFC 5011's add-hold-down (30 days) and revocation
rules, rewrites the file, and swaps the live anchor set through `SharedAnchors`
without a restart. Every change is reported at `info`.

`SharedAnchors` is a `std::sync::RwLock`, not tokio's: every use is a
clone-and-release with no await inside. A poisoned lock uses the recovered value
rather than panicking.
