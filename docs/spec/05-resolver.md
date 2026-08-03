# 5. The resolver (`rdns::resolver`, `rdnsr`)

Recursion and forwarding are **two modes of one resolver**, not two programs —
the client-facing half is identical and only the means of obtaining an answer
differs, which is how BIND, Unbound, Knot Resolver and PowerDNS Recursor all
model it. Mixed deployments (forward one zone, recurse the rest) are ordinary.

`rdnsr` is a **separate binary from `rdnsd`**, following the NSD/Unbound and
Knot/Knot-Resolver precedent: opposite trust models (serving the public versus
serving your clients), different data (zones versus a cache), independent
lifecycle, and no risk of an accidental open resolver.

Everything is async `tokio::net`. Each hop is an `await` on a socket, so a
resolution taking several round trips yields at every one rather than pinning a
thread for the sum of them.

---

## 5.1 Configuration and defaults

`ResolverConfig`:

| field | default | note |
|---|---|---|
| `mode` | `Recurse` | any `--upstream` switches to `Forward` |
| `upstream_servers` | 8.8.8.8:53, 1.1.1.1:53 | Forward mode only |
| `root_hints` | built-in, **v4/v6 interleaved** | so whichever family the host has is reached in the first hop or two, before RTT selection has data |
| `timeout_ms` | 5000 | per query |
| `max_delegations` | 16 | referrals followed before giving up |
| `max_cname_hops` | 8 | |
| `query_budget` | **64** | total upstream queries one `resolve` may spend |
| `udp_payload_size` | 4096 | advertised upstream |
| `delegation_cache_size` | 10 000 | 0 disables, which restarts every query at the root |
| `qname_minimization` | **on** | RFC 9156 |
| `zero_x20` | **on** | draft-vixie-dnsext-dns0x20 |
| `server_port` | 53 | configurable only so tests can stand up a fake hierarchy |
| `dnssec` | `None` | off by default: validation costs round trips and turns a misconfigured zone into a failure |

`--root-hints <file>` reads named.root format. A stray line is skipped rather
than sinking the file (`parse_root_hints` returns a `Vec`), and the caller decides
what an empty result means.

---

## 5.2 Query hygiene — what goes out

Every outgoing query carries:

- a **random transaction id**;
- a **random source port** (a fresh socket per query);
- **0x20 case randomization** of the QNAME when enabled. A response must echo the
  question, so the casing is entropy an off-path spoofer must guess on top of the
  id and the port.

Every response is checked against the query it answers (`response_matches`):
transaction id, question count, QNAME **byte-exact** when 0x20 is on and
case-insensitively when it is off, QTYPE and QCLASS. A mismatch is discarded, not
answered from.

With `--dnssec-validate`, every query also carries **DO** (so servers include
signatures) and **CD** (so a forwarded query reaches us unfiltered — an upstream
that validates on our behalf and hands back SERVFAIL leaves us nothing to check,
which is the same as trusting it).

---

## 5.3 Recursion

### The walk

```
start = the deepest cached delegation covering the qname, else the root hints
loop, bounded by max_delegations and by the query budget:
    ask the servers for that zone, in RTT order
    classify the response:
        answer          -> done (or follow a CNAME, bounded by max_cname_hops)
        referral        -> descend, if in bailiwick
        negative        -> done
```

### Bailiwick rules

- **A referral must be a descendant of the zone that gave it.** A zone answering
  with a referral to something above or beside itself is ignored — that is a
  redirection out of its authority.
- **Glue is used only when in bailiwick.** An address record for a name outside
  the referring zone is discarded; a nameserver with no usable glue is resolved
  separately (a "glueless delegation"), and that resolution spends from the same
  budget.

### The budget — the NXNSAttack defence

One `resolve` may spend `query_budget` upstream queries **in total**, across
delegations, CNAME hops and nameserver-address lookups. A hostile zone can answer
with a referral naming dozens of glueless nameservers, each costing a full
resolution; bounding the *total* is what stops one client query becoming hundreds.

Exhausting it is `ResolveError::BudgetExhausted` — a distinct variant because it
is an operational signal, not a lookup failure.

### QNAME minimisation (RFC 9156)

Each server up the chain is asked only for the label being delegated, so the root
learns the TLD and no more; the leaf is revealed only to the server authoritative
for it.

- The probe QTYPE is **A**, not NS. RFC 9156 §2.3 replaced RFC 7816's NS advice
  with "the QTYPE least likely to raise issues in DNS software and middleboxes".
- **`MAX_MINIMISE_COUNT` is capped at the RFC's recommended 10.** Without the
  ceiling a 34-label reverse-IPv6 PTR spent ~30 round trips and exhausted the
  budget, so a deep name failed outright where it should degrade to a full-QNAME
  query that still resolves.
- An empty non-terminal encountered mid-walk is probed and passed through rather
  than mistaken for the end of the chain.

### Server selection — `RttStore`

Smoothed RTT per server address, capacity-bounded, evicting the slowest. Servers
for a zone are tried fastest-first; a server that fails is deprioritised
immediately rather than after the next timeout.

### The delegation cache

`zone -> (servers, expiry)`, keyed by name, longest-match. This is the difference
between a toy recursor and a usable one: without it every client query costs a
root round trip, which is slow and — at volume — abusive enough that root
operators rate-limit it. With it, the root is consulted roughly once per TLD per
TTL. A stale entry falls back to the root.

### Truncation

A UDP response with TC=1 is retried over TCP by the resolver itself
(`query_upstream_tcp`). A TCP response that is *still* truncated is returned as
it is — there is nowhere further to go. A zero-length TCP frame from an upstream
is an error, not an empty answer.

---

## 5.4 `rdnsr` — the daemon

UDP and TCP on one host:port, both spawned; whichever fails first takes the
process down. Binds **127.0.0.1 by default**, so it is not accidentally exposed
as an open resolver.

### Per-query path (`handle_query`, shared by both transports)

1. **`validation::Request::from_bytes`** — parses and refuses QR=1. Both failures
   are silence: the peer did not ask anything, and answering a response is how a
   resolver becomes a packet engine between two instances pointed at each other.
2. **Opcode**: anything but QUERY is NOTIMP with the opcode echoed.
3. **EDNS sanity**: malformed option list → FORMERR; version > 0 → BADVERS.
4. **Special-use names** (`special_names::lookup`) — answered locally, never
   forwarded, **before every cache and before any resolution**: for these the
   table *is* the answer. AD is never set — nothing here was validated, it was
   decided by specification. Not skipped for a client with CD, which is a
   statement about DNSSEC and not a request to be told what a public server
   thinks `localhost` is. See §5.6.
5. **RFC 8198 synthesis from validated denials**, skipped when the client set CD
   (an answer we invented from cached proofs is exactly what CD asks us not to
   do). Checked **before** the answer cache: a cached NSEC answers every question
   in its gap, so a flood of random names under one zone costs one upstream query
   rather than one per name. The **positive** half (§5.3, a validated wildcard
   answering a name nobody has asked about yet) is tried first — the two are
   mutually exclusive by construction, since a cached NXDOMAIN needs the wildcard
   *denied*.
6. **Answer cache**, then **negative cache**.
7. **Miss** → `Resolver::resolve` (recursion or forwarding).
8. **Validation**, if `--dnssec-validate`: AD is set only on `Secure`; `Bogus` is
   SERVFAIL unless the client set CD.
9. **Cache store** by (name, type) with the answer's TTL, **and its validation
   state alongside it** — so an answer served from cache carries the same AD bit
   the first client saw and no other.
10. **Reply**, echoing the transaction id with RA set and the OPT record mirrored
   only if the client used EDNS, sized by transport (`Transport::Udp` uses the
   client's advertised payload size; `Transport::Tcp` uses the 2-byte frame).

### Concurrency

| bound | value | note |
|---|---|---|
| `--max-inflight-udp` | 1024 | a task per datagram; a recursion is *seconds* of waiting, so a small worker pool would be idle and slow at once. Floored at 1, no off switch: "off" here is the defect this closes |
| `MAX_TCP_CONNECTIONS` | 128 | without one, an accept loop that spawns per connection is a free fd-exhaustion vector |
| `MAX_INFLIGHT_PER_CONNECTION` | 16 | also the reply channel's depth, so a client pipelining faster than it reads pushes back on the read loop rather than growing a queue |

Over the UDP ceiling the datagram is dropped **before** it is copied and before
any task is spawned. Dropping is silent and logged at `debug` — a reply to a
spoofed source is what an amplifier sends.

> **Gap G-1 — fixed 2026-08-03.** ~~`rdnsr` runs no per-source rate limiter, no
> response-byte budget, no query logger, no metrics and no readiness probe.
> `rdnsd` has all five, and the implementations are in the shared library.~~
> `--query-rate` (200/s, burst 100, with exemptions), `--response-rate` (8192)
> and `--metrics-listen` are all wired in through those same library types. No
> `/readyz` that means anything: a resolver has nothing to wait for before it can
> answer. See `07-rfc-conformance.md`.

> **Gap G-2 — fixed 2026-08-03.** ~~`rdnsr` does not run `RequestValidator`, so
> a request over the UDP size cap or with absurd section counts reaches the
> parser rather than being refused before it.~~ It runs `AdmissionCheck` on the
> pre-admission path now, after the rate limit and before the in-flight
> semaphore. See `07-rfc-conformance.md`.

---

## 5.5 Caching

| cache | keys | bound | TTL cap |
|---|---|---|---|
| `DnsCache` (answers) | (folded name, qtype) | `--cache-size`, default 10 000 | `MAX_CACHE_TTL` = 86 400 s |
| `NegativeCache` (RFC 2308) | (folded name, qtype) | its own | `MAX_NEGATIVE_TTL` = 3600 s |
| `NsecCache` (RFC 8198) | zone → validated denial records | 1000 zones | the records' own |

- Keys go through `utils::NameKeyBuf`, whose only constructor folds — so
  `WWW.example.com.` and `www.example.com.` cannot become two entries.
- **The negative TTL is `min(SOA MINIMUM, the SOA record's own TTL)`**
  (RFC 2308 §3).
- `--no-cache` is a **zero-capacity `DnsCache`** (`put` is a no-op at 0) rather
  than an `Option`, so there is no second code path to keep in step.
- Eviction halves the map with `select_nth_unstable` rather than re-scanning for
  a single victim. Expiries are whole seconds, so a cache filled in one burst has
  every entry on one value — `retain(|e| e.expires_at > cutoff)` would empty the
  whole cache instead of halving it, and the tie case has its own test.

---

## 5.6 Names that never leave (`special_names.rs`)

Answered locally, never forwarded, each with a reason recorded for the log
because "the resolver said this name does not exist" is a thing people debug.
Local TTL 3600.

| name | answer | RFC |
|---|---|---|
| `localhost.`, `*.localhost.` | 127.0.0.1 / ::1; NODATA for other types | 6761 §6.3 |
| `1.0.0.127.in-addr.arpa.` PTR | `localhost.` | 6303 §4.2 |
| `127.in-addr.arpa.` and below | NXDOMAIN | 6303 §4.2 |
| `local.` and below | NXDOMAIN — mDNS, not DNS | 6762 §3 |
| `invalid.` and below | NXDOMAIN — reserved to not exist | 6761 §6.4 |
| RFC 1918 reverse zones (`10.`, `16–31.172.`, `168.192.in-addr.arpa.`) | NXDOMAIN | 6303 §4 |

---

## 5.7 Managed trust anchors in `rdnsr`

With `--auto-trust-anchor`, a background task probes the anchored zone's DNSKEY
RRset on a timer, applies RFC 5011's add-hold-down (30 days) and revocation
rules, rewrites the file, and swaps the live anchor set through `SharedAnchors`
without a restart. Every change is reported at `info`.

`SharedAnchors` is a `std::sync::RwLock`, not tokio's: every use is a
clone-and-release with no await inside, so an async lock would buy nothing and
cost the chance of holding a guard across a suspension point. A **poisoned** lock
uses the recovered value rather than panicking — validating against a set nobody
finished writing is worse than not validating.
