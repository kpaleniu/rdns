# 5. The resolver (`rdns::resolver`, `rdnsr`)

Recursion and forwarding are two modes of one resolver; only the means of
obtaining an answer differs. `rdnsr` is a separate binary from `rdnsd`.

Everything is async `tokio::net`. Each hop is an `await` on a socket.

---

## 5.1 Configuration and defaults

`ResolverConfig`:

| field | default | note |
|---|---|---|
| ~~`mode`~~ | ~~`Recurse`~~ | ~~any `--upstream` switches to `Forward`~~ **gone** (2026-10-07, `TODO.md` #172) |
| ~~`upstream_servers`~~ | ~~8.8.8.8:53, 1.1.1.1:53~~ | ~~Forward mode only~~ **gone** (2026-10-07, `TODO.md` #172) |
| `routes` | none | routed domains, each a forward zone (RD=1, take the answer) or a stub zone (walk from its servers, RD=0); `--upstream` is a forward zone at `.`. See §5.1a |
| `root_hints` | built-in, v4/v6 interleaved | so either family is reached in the first hop or two, before RTT selection has data |
| `timeout_ms` | 5000 | per query |
| `max_delegations` | 16 | referrals followed before giving up |
| `max_cname_hops` | 8 | |
| `query_budget` | 64 | total upstream queries one `resolve` may spend |
| `resolution_timer` | 10 s | wall clock for one `resolve`, validation included; `--resolution-timer`, 1–30 |
| `udp_payload_size` | 1232 | advertised upstream (RFC 6891 §6.2.3). `rdnsr` sets it from `--udp-payload-size`, the same number it advertises to its own clients: one host, one reassembly claim. Not the size an upstream answer is read into, which is `upstream::UPSTREAM_RECEIVE_BUFFER` = 4096 — the two were one number until #41c |
| `delegation_cache_size` | 10 000 | 0 disables, which restarts every query at the root |
| `qname_minimization` | on | RFC 9156 |
| `zero_x20` | on | draft-vixie-dnsext-dns0x20 |
| `dnssec` | `None` | off by default |

### 5.1a Routed domains (`--forward-zone`, `--stub-zone`, `--no-validate-zone`)

`NAME=ADDR[,ADDR...]`, repeatable, or `[[forward-zone]]` / `[[stub-zone]]` with
`name`, `servers`, `validate`. Routing happens in `resolve_from_root`, which
every lookup passes through: CNAME hops, glueless nameserver lookups and
validation's DNSKEY fetches are routed too. The most specific covering route
wins and beats any cached delegation at or above it; under a stub zone a
delegation cached below it is still a shortcut. No fallback to recursion: a
route whose servers fail is SERVFAIL with EDE 22, because falling back leaks an
internal name to the public tree and caches its NXDOMAIN over the subtree
(RFC 8020). The RPZ nameserver policy is asked about a route's servers at entry.

Validated unless `validate = false`, which answers `Indeterminate`, AD clear —
not `Insecure`, which means proven unsigned. A route at or below an RFC 6303
empty zone overrides it for its subtree, a tie included (ADR 0008).

Forwarded answers pass the same CNAME-chain filter and DNAME synthesis as
recursed ones, which is stricter than before: records a forwarder volunteers
for names off the chain are not cached. The chain loop follows the CNAMEs a
response already carries, so a forwarder's whole chain is not re-asked.

**Local zones** (`--local-zone NAME=PATH`, `[[local-zone]]` with `name` and
`file`, `TODO.md` #174) are the third kind: the file is read by the zone parser
`rdnsd` uses and answered by `zone_answer`, through the walk, so a referral
inside it is followed as a stub zone's would be and a CNAME out of it is
resolved. AA set (cleared on a referral), AD never, no EDE; `Indeterminate`
whenever the question or any answer record lies in one, and never validated.
Answers touching a local zone are not cached, so a reload is seen at once —
which means a public name whose chain enters one is not cached either, since
the cache holds whole answers per question. RPZ runs before them. SIGHUP
re-reads the files, all or nothing, skipping a file whose bytes did not move,
and logs each serial that did. Refused at startup: a file that does not parse
or has no SOA at its name, and a name at or under a special-use name.

Refused at startup, naming the entry: a name that does not parse, one routed
twice or as both kinds, an empty server list, `--no-validate-zone` naming no
route, `--upstream` with a route at `.`, `--root-hints` with `.` routed.

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

The budget counts queries and not time, so `resolution_timer` bounds the
other axis: RFC 8767 §5's query resolution timer, 10 s by default as in BIND
and Knot Resolver. The resolution is cancelled when it fires, an exchange in
flight included, and the client gets SERVFAIL with EDE 22, or a stale answer
under `--serve-stale` (step 12 below). Before it, 70 silent glued nameservers
took 157.5 s while holding a UDP permit (`TODO.md` #168). DNS64's A query
is a resolution of its own, so a DNS64 client can wait two timers.

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

### Who is answered (`--allow-query`, `TODO.md` #171)

No list is open, and allowed only while every listener — `--host`,
`--tls-listen`, `--quic-listen`, `--https-listen` — is on `127.0.0.0/8` or
`::1`; off loopback with no list refuses to start, `--check-config` included
(`docs/adr/0007`). A list allows exactly what it names, loopback included, and
must contain every `--rpz-notify-from` rule.

The check is the first thing a packet or connection meets. Over UDP an unlisted
peer's well-formed question is answered REFUSED, question echoed, OPT mirrored
with EDE 18 (Prohibited) and no EXTRA-TEXT, within the response budget; it never
reaches the rate limiter. A stream connection is closed before the rate limiter,
the per-source count and any TLS or QUIC handshake. DoH matches the TCP peer,
never a forwarding header. Counted in `dns_queries_refused_by_acl_total` and
`dns_connections_refused_by_acl_total{transport}`. Read once at startup.

### Per-query path (`handle_query`, shared by both transports)

1. `validation::Request::from_bytes` — parses and refuses QR=1. Both failures are
   silence.
2. Opcode: NOTIFY goes to §5.6's policy re-read when `--rpz-notify-from` names
   anybody; anything else but QUERY is NOTIMP with the opcode echoed, carrying
   EDE 21 (Not Supported).
3. EDNS sanity: malformed option list → FORMERR; version > 0 → BADVERS.
   Neither carries an Extended DNS Error, for the reason `03`'s §3.2.1 gives.
4. Special-use names and the empty zones left on (`special_names::lookup`) —
   answered locally with AA=1, never forwarded, before every cache and before
   any resolution. AD is never set. Not skipped for a client with CD. See §5.8.
5. Response policy (`rpz::PolicyZones::before_query`), when `--rpz` named a
   zone: the client's address, then the name, zone by zone in order. After the
   special-use table, because that half is a protocol requirement and a policy
   zone is a preference; after an empty zone that is on, because switching it
   off is how a feed reaches inside it. See §5.6.
6. DNS64 reverse mapping, when `--dns64` is on and the question is a PTR under
   `ip6.arpa` for an address inside the NAT64 prefix: the question is rewritten
   rather than answered. See §5.7.
7. Negative cache, then answer cache. A "no" is asked first because an answer
   retires the "no" it refutes when stored (`TODO.md` #133), so whatever "no"
   is left is the newer.
8. RFC 8198 synthesis from validated denials, skipped when the client set CD.
   Only after both exact-match caches missed, as RFC 8198 Appendix A, Unbound,
   BIND and Knot Resolver do: a gap or wildcard cached before an answer for
   the name must not outrank it (`TODO.md` #134). A random name misses both,
   so a flood under one zone still costs one upstream query. The positive half
   (a validated wildcard) is tried first; the two are mutually exclusive by
   construction.
9. With `--serve-stale-first`, an expired answer or "no" inside the window,
   answered at once with its refresh queued. See §5.5.
10. Miss → `Resolver::resolve`.
11. Validation, if `--dnssec-validate`: AD is set only on `Secure`; `Bogus` is
    SERVFAIL unless the client set CD.
12. On a resolution that failed and `--serve-stale` non-zero: the expired answer
    or the expired "no", if either is still inside the window. See §5.5.
13. Cache store by (name, type) with the answer's TTL, and its validation state
    alongside it, so a cached answer carries the same AD bit the first client
    saw.
14. Response policy again (`rpz::PolicyZones::on_answer`): the addresses in the
    answer against the `rpz-ip` triggers. See §5.6. A stale answer is policed
    here as a cache hit is.
15. DNS64 synthesis (`finish_dns64`), when the answer carries no usable AAAA.
    See §5.7.
16. Reply, echoing the transaction id with RA set and the OPT record mirrored
    only if the client used EDNS, sized by transport (`Transport::Udp` uses the
    client's advertised payload size; `Transport::Tcp` uses the 2-byte frame).
16. A prefetch, if the answer came from a cache entry in the last tenth of its
    TTL and `--prefetch` is on: offered to a queue at the lookup and run by a
    pool of its own, never in the task that answered. See §5.5.

Steps 5, 6, 11, 13, 14 and 16 do nothing at all unless the flag that turns them
on was given; each costs one `is_empty`, one `Option` test or one comparison
otherwise.

### Extended DNS Errors on a SERVFAIL (RFC 8914)

A bare SERVFAIL says a lookup failed and nothing about where to look. The code
is chosen by the check that found the fault and carried up unchanged —
`dnssec::Bogus { code, why }` inside `RrsetProof::Bogus`,
`ValidationState::Bogus` and `DelegationVerdict::Bogus` — because nothing above
that check can tell "expired" from "did not verify" without reading the message
back.

| INFO-CODE | when |
|---|---|
| 7, Signature Expired / 8, Signature Not Yet Valid | `Rrsig::is_current` failed, split by which side of the window `now` is on |
| 9, DNSKEY Missing | a DS exists and no DNSKEY matches it, or no RRSIG's key tag and algorithm match a key we hold |
| 10, RRSIGs Missing | an RRset, a DNSKEY RRset or a no-DS denial came back unsigned from a zone the chain says is signed |
| 12, NSEC Missing | a denial with no NSEC or NSEC3, one that does not prove what was asked, or a wildcard answer with no denial of the name served |
| 6, DNSSEC Bogus | everything else bogus: a signature that did not verify, a signer outside the zone, a chain that does not terminate, an answer that is not the chain asked for |
| 22, No Reachable Authority | `ResolveError::NoResponse` and `::Delegation` |
| 23, Network Error | `ResolveError::Io` |
| 0, Other | `ResolveError::BudgetExhausted` (the NXNSAttack defence firing) and an upstream answer that did not parse |

EXTRA-TEXT is a fixed `&'static str` in every case. `Bogus::why` names the
zone, the owner and the key tag, all of them out of an answer a stranger sent,
and RFC 8914 §2 asks that EXTRA-TEXT leak nothing; the detail goes to the WARN
line beside the counter instead.

### Concurrency

| bound | value | note |
|---|---|---|
| `--max-inflight-udp` | 1024 | a task per datagram; a recursion is seconds of waiting. Full, the oldest is abandoned if past the 1.8 s client response timer, else the newcomer is dropped (`TODO.md` #169). Floored at 1, no off switch |
| `--max-connections` | 128 | per stream listener; see `06-operations.md` §6.2 |
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

- Keys go through `text_names::NameKeyBuf`, whose only constructor folds.
- The negative TTL is `min(SOA MINIMUM, the SOA record's own TTL)`
  (RFC 2308 §3).
- `--no-cache` is a zero-capacity `DnsCache` (`put` is a no-op at 0), not an
  `Option`.
- Eviction halves the map with `select_nth_unstable`. Expiries are whole seconds,
  so a burst-filled cache has every entry on one value and a `retain` on the
  cutoff would empty it instead of halving it.
- Both the answer cache and the negative cache read the time from
  `rdns::clock::Clock`, which is the daemon's — one process, one instant, and a
  test can move it.

### Serving stale (RFC 8767) — `--serve-stale SECONDS`

Off at 0, which is the default. Non-zero, an entry has two lifetimes: its TTL,
after which it is not an answer, and `max_stale` seconds after that, in which it
is the last thing known. `cache::StalePolicy` holds both and is the only place
the window is arithmetic; with the policy off its predicate is exactly "has not
expired", so nothing branches on the mode.

- Only reached from the arm where a resolution has already failed (§4 of
  RFC 8767 has the resolver try the authoritative servers first), unless
  `--serve-stale-first` says otherwise. A cache that can answer normally never
  gets here.
- The answer carries `STALE_ANSWER_TTL` = 30 s (§4), EDE 3 (Stale Answer) or
  EDE 19 (Stale NXDOMAIN Answer), and AD as validation concluded when it was
  stored.
- The `NsecCache` is **not** covered: RFC 8198 serves a denial because its
  signature proves it, and an expired proof proves nothing.
- Eviction keeps what the window keeps in both caches. Sweeping the expired
  entries when making room would leave the window to a resolver nobody is
  querying.

#### Answering stale first — `--serve-stale-first`

Off by default, and refused without a window. On a live miss, an entry inside
the window is answered at once and its refresh is queued to the prefetch pool:
BIND's `stale-answer-client-timeout 0`.

- **A deviation from RFC 8767 §4**, whose normative text lets a record be used
  past its TTL only "if the data is unable to be authoritatively refreshed".
  Nothing has been tried here. Listed in `07-rfc-conformance.md`.
- **Not §5's 1.8 s client response timer.** BIND removed its non-zero form in
  9.19.22/9.20 after CVE-2022-3736 and CVE-2022-3924, both of which need a
  positive value; Knot Resolver answers stale at 3 s and does not finish the
  resolution; PowerDNS has no client timer (`TODO.md` #58).
  `dns_slow_resolutions_total{outcome="completed"}` counts the clients a
  timer — or this switch — would have spared.
- One refresh per entry per `STALE_REFRESH_INTERVAL` = 30 s, §5's failure
  recheck timer, claimed under the cache's lock. A period and not a flag: a
  stale entry is answered without resolving, so a refresh that failed once
  would otherwise never be tried again.
- The EDE text says a refresh is under way, not that the servers could not be
  reached. Counted as a cache hit and in `dns_stale_answers_total`; the refresh
  in `dns_stale_refreshes_total`.
- The negative cache takes part: an expired NXDOMAIN or NODATA is answered
  first the same way, with EDE 19 or 3.

### Prefetching — `--prefetch`

Off by default. A cache hit with less than a tenth of its TTL left
(`PREFETCH_AT` = 10, Unbound's rule) is re-resolved once the client's reply is
away.

- The obligation is handed to **exactly one** caller: `Cached::refresh` is true
  at most once per entry, flipped under the lock the lookup already holds. A
  popular name in its last tenth otherwise starts one walk per client.
- The refresh is offered to a bounded queue (`--prefetch-queue`, 256) and run
  by a pool (`--prefetch-workers`, 16). `--serve-stale-first` shares both, and
  the handle says which of the two uses are on (`prefetch::Refreshes`), so the
  pool running is not what switches prefetching on. A full queue drops the question and
  counts it in `dns_prefetches_dropped_total`; the entry stays claimed and
  expires like a failed refresh.
- Not in the task that answered. DoH builds its response only once the
  handler task is joined and DoQ sends FIN only once the sink closes, so a
  refresh there put an upstream resolution in front of the reply
  (`TODO.md` #114).
- The pool holds no shutdown guard: nobody waits on a prefetch, so the stop
  aborts one part-way rather than waiting out an upstream timeout.
- A failure leaves the entry claimed and expiring: the next client either finds
  it or resolves it the ordinary way.

---

## 5.6 Response Policy Zones (`rdns::rpz`, `--rpz`)

Not an RFC — ISC's `draft-vixie-dns-rpz-04`, as BIND, Knot Resolver, Unbound and
PowerDNS implement it. A policy zone is an ordinary DNS zone whose owner names
are triggers and whose RRsets are actions; the trigger name is the thing matched
with the policy zone's origin appended, so the lookup is `Zone::locate` and the
RPZ wildcard rule is RFC 1034 §4.3.3's.

Data the operator owns, rather than a rewrite of somebody else's, belongs in a
local zone (§5.1a): authoritative, its own owners, no EDE 4.

| action | spelling | effect |
|---|---|---|
| NXDOMAIN | `CNAME .` | the name does not exist; the policy zone's SOA in the authority section |
| NODATA | `CNAME *.` | no records of this type; the same SOA |
| PASSTHRU | `CNAME rpz-passthru.` | matched, resolved normally |
| DROP | `CNAME rpz-drop.` | no reply at all |
| TCP-Only | `CNAME rpz-tcp-only.` | TC=1 over UDP; over TCP, resolved normally |
| local data | anything else | the RRset answers, owner rewritten to the name asked for |

- All five trigger types are enforced. QNAME, `rpz-client-ip` and `rpz-ip` are
  answerable from the request and the answer. `rpz-nsdname` and `rpz-nsip` are
  asked of each delegation the resolver is about to follow, through
  `resolver::NameserverPolicy`, and a match **stops the resolution** rather than
  rewriting its result (`TODO.md` #56) — so the refused server is never asked
  and nothing enters the cache. NSDNAME is tried before NSIP, and both after
  everything above. The delegation cache keeps each referral's NS names, because
  a walk starts at the deepest zone already known and a policy asked only at
  referrals would hold for one client and not the next. `rpz-passthru` at a
  delegation does not stop the walk. The startup banner counts all five kinds.
- Zones are consulted in the order they are named; the first with a rule
  decides. A policy
  (`given`/`disabled`/`passthru`/`drop`/`nxdomain`/`nodata`/`tcp-only`)
  overrides every action in the zone it applies to. `--rpz-policy` says it of
  every `--rpz` at once, which is all a command line can express; the config
  file's `[[rpz.feeds]]` says it per feed, inheriting `[rpz].policy` where a
  feed does not — a new feed is introduced by measuring it in `passthru` while
  the others stay enforced (`TODO.md` #63j). The policy is `rpz::Feed`'s, held
  by the `PolicyZone` it loaded, so it costs the match path nothing.
- A policy zone without an apex SOA is refused at load, since a negative rewrite
  owes one (RFC 2308 §5). An address trigger that is not an address is refused
  too. Loading is all-or-nothing.
- **SIGHUP re-reads every `--rpz` file** (`rpz::PolicyStore`, `TODO.md` #57),
  all-or-nothing as at startup: a feed that will not parse leaves the previous
  set in force and says so, because a half-written file must not lift a block.
  Unix only, as every SIGHUP here is. One query is decided by one snapshot of
  the set, taken at its start. A reload also clears the three caches, but only
  when a zone carrying a nameserver trigger is at a new SOA serial: a QNAME or
  `rpz-client-ip` rule is consulted before every cache and an `rpz-ip` rule is
  applied to what leaves, so either binds the next query whatever is held,
  while `rpz-nsdname` and `rpz-nsip` are asked only while a delegation is
  walked — which a cache hit never does.
- **A NOTIFY from a `--rpz-notify-from` address asks for the same re-read**
  (`TODO.md` #57c), which is how a feed `rdnsd` replicates reaches `rdnsr`:
  `announce_transfer` already notifies every `--also-notify` peer after every
  transfer. NOERROR and the re-read queued, because RFC 1996 §4.7 wants the
  reply before the work; REFUSED from an address the list does not name;
  NOTAUTH for a zone no feed carries; NOTIMP when the list is empty, since then
  the resolver really does not implement one. The message's serial is not read:
  it is unauthenticated, and all it could do here is let a re-read be skipped.
- **A feed with a `master` is transferred by `rdnsr` itself** (`rpz_transfer`,
  `TODO.md` #57d shape A, #57e), one task per feed on the zone's own SOA
  timers, woken early by a NOTIFY naming that zone. A refresh asks for the
  master's serial first and stops there unless it moved; otherwise it asks for
  the difference from the version in force (IXFR, RFC 1995) or for the whole
  zone when it holds none. What arrives is written to the feed's own file — so
  a restart begins with the last transfer rather than with nothing — and handed
  to the store beside the digest of the bytes written, so the reload above
  installs that zone instead of parsing the file back into a copy of it
  (`TODO.md` #71f). The reload still reads every file; the digest is what
  decides, and a feed somebody else rewrote in between is parsed. Signed when the master names a key with `#name`,
  resolved from `[keys]` at startup so an undefined name stops the process
  rather than sending an unsigned request. A feed without a `master` is still
  delivered by whatever writes the file; `rdnsr` has no zone map either way.
- **`on-expire` says what an unrefreshed feed means**, per feed: `enforce` (the
  default) keeps its rules in force past EXPIRE, `lift` removes the file and
  stops applying them. Not derivable from the zone — `rpz-passthru` rules make
  a feed an allowlist, where the two directions swap. Either way the transition
  is warned once, and the feed's age is on
  `dns_zone_last_refresh_timestamp_seconds`, absent until it has transferred
  once and forgotten when it is lifted.
- Every rewrite goes out with AD clear and an Extended DNS Error: 15 (Blocked)
  when the answer is a denial, 4 (Forged Answer) when records are still
  provided — RFC 8914 §4.5 draws that line.
- Counted as `dns_policy_rewrites_total` and `dns_policy_drops_total`.

---

## 5.7 DNS64 (RFC 6147, `--dns64`)

Off unless the flag is given; given without a value it is the Well-Known Prefix
`64:ff9b::/96` (RFC 6052 §2.1). `rdns::dns64` holds RFC 6052 §2.2's address
arithmetic — six prefix lengths, the four octets somewhere different in each,
bits 64-71 reserved and zero in every form but the /96.

- **When**: the question is AAAA, the answer carries no AAAA outside the
  exclusion set (§5.1.4), the RCODE is not NXDOMAIN (§5.1.2 passes it through),
  and the client did not set both CD and DO (§5.5 leaves such a client to
  synthesize for itself).
- **Where**: `finish_dns64`, which the four paths that can produce an empty AAAA
  answer end at — the two denial caches, the negative cache, and a fresh
  resolution. The special-use table and a policy-zone rewrite end at `finish`
  instead, deliberately: RFC 6761's `localhost` is not an IPv4 name behind a
  translator, and a blocked name is blocked.
- **What**: an AAAA per A record, owner unchanged, CNAMEs in the chain kept
  (§5.1.5). TTL is the lesser of the A record's and the SOA's (§5.1.7). The
  authority and additional sections are dropped (§5.4). AD is clear, and there
  is no Extended DNS Error — RFC 8914 has no code for it and 4 (Forged Answer)
  says "for policy reasons", which this is not.
- **Exclusions**: `--dns64-exclude` adds to `::ffff:0:0/96`, which §5.1.4 names
  and which is never removed.
- **Reverse**: a PTR under `ip6.arpa` for an address inside the prefix is
  answered with a CNAME into `in-addr.arpa` and whatever that name resolves to
  — §5.3.1's second alternative, since the first means inventing PTR data for a
  translator this resolver knows nothing about.
- §5.1.8's parallel A query is a MAY and is not done; the A lookup follows a
  delegation walk the AAAA lookup just warmed.
- Counted as `dns_synthesized_total`.

---

## 5.7a Negative trust anchors (RFC 7646, `--negative-trust-anchors`)

A file of `NAME UNTIL [norecheck]` lines, `UNTIL` in UTC as `YYYYMMDDHHmmSS` or
Unix seconds. Loaded before the dry run, refused without `--dnssec-validate`,
refused whole for a line that does not parse or one more than a week ahead
(§4); a lapsed line is skipped with a warning. Re-read on SIGHUP; a file that
does not load keeps the set in force.

A name at or below a node is answered `Indeterminate`, AD clear, no EDE —
unless a positive anchor lies strictly between, where validation resumes
(§1.1). An anchor at the node itself is overridden, with a warning (§3).
RFC 8198 synthesis is skipped under one: a proof from the zone above would
answer the exempted names as secure, and cannot be flushed by subtree.

Expiry at `UNTIL` and the recheck run in one task: every 5 minutes (BIND's
`nta-recheck`) an SOA query at the node, validated ignoring the anchors; Secure
or Insecure lifts it in memory and logs. Every add, change, lift and expiry
flushes the answer, negative and denial caches at and below the node, and logs.
`dns_negative_trust_anchors` is the count in force.

## 5.8 Names that never leave (`special_names.rs`)

Answered locally with AA=1, never forwarded, each with a reason recorded for
the log. Local TTL 3600. A reverse zone answers at its apex as RFC 6303 §3's
zone does: SOA, one NS naming the zone itself, NODATA for anything else.

| name | answer | RFC | switchable |
|---|---|---|---|
| `localhost.`, `*.localhost.` | 127.0.0.1 / ::1; NODATA for other types | 6761 §6.3 | no |
| `1.0.0.127.in-addr.arpa.` PTR | `localhost.` | 6303 §4.2 | no |
| `127.in-addr.arpa.` and below, and the `::1` reverse | apex as above; NXDOMAIN below | 6303 §4.2, §4.3 | no |
| `local.` and below | NXDOMAIN — mDNS, not DNS | 6762 §3 | no |
| `invalid.` and below | NXDOMAIN | 6761 §6.4 | no |
| **empty zones**: RFC 1918 (`10.`, `16–31.172.`, `168.192.in-addr.arpa.`), `254.169.`, `0.in-addr.arpa.`, `8–b.e.f.ip6.arpa.`, `c.f.` and `d.f.ip6.arpa.` | apex as above; NXDOMAIN below | 6303 §4.1, §4.2, §4.4, §4.5; `c.f.` is §5's reserve | yes |

RFC 6303 §3: "An implementation of this recommendation MUST provide a mechanism
to disable this new behaviour, and SHOULD allow this decision on a zone-by-zone
basis." `--disable-empty-zone ZONE` (repeatable) and `--no-empty-zones`, or
`disable-empty-zone` and `empty-zones = false` under `[resolver]`, make a zone
an ordinary name: policy, caches, then resolution. Anything that is not exactly
an empty zone is refused at startup, naming it — a special-use name, a name
inside an empty zone, any other name — and so is the pair together
(`TODO.md` #173). A routed domain at least as specific as an empty zone will
override it (`docs/adr/0008`); `--upstream` is a route at `.` and does not.

---

## 5.9 Managed trust anchors in `rdnsr`

With `--auto-trust-anchor`, a background task probes the anchored zone's DNSKEY
RRset on a timer, applies RFC 5011's add-hold-down (30 days) and revocation
rules, rewrites the file, and swaps the live anchor set through `SharedAnchors`
without a restart. Every change is reported at `info`.

`SharedAnchors` is a `std::sync::RwLock`, not tokio's: every use is a
clone-and-release with no await inside. A poisoned lock uses the recovered value
rather than panicking.

---

## 5.10 The control socket (`--control-socket`, `TODO.md` #178)

`rdnsd`'s transport (`03` §3.9): a socket at mode 0600, or a named pipe on
Windows (`TODO.md` #188), refused over a live one. The socket half is
`rdns_transport::control`; each daemon supplies its command table.

| command | does |
|---|---|
| `status` (default) | uptime, entries per cache, NTAs in force, routed domains |
| `reload` | SIGHUP's reload through SIGHUP's task, replying with what it re-read or why not |
| `flush` | every cache: answers, negatives, denials, delegations, keys, RTTs, NSIDs |
| `flushname NAME` | answers and negative answers at exactly `NAME`, every type |
| `flushtree NAME` | answers, negatives, denials, delegations and keys at and below `NAME` |
| `dump [NAME]` | cached answers as zone-file lines, TTL left, outcome, stale ones marked |
| `nta` | the negative trust anchors in force, with expiry and recheck |
| `version`, `help` | |

Each flush replies with the count removed, so one that matched nothing says 0.
Trust anchors and RPZ policy are not caches and no flush touches them. NTAs
change only through the file and `reload` (§5.7a); one lifted by a recheck is
no longer in force and is not listed. `dump` copies under the cache lock and
formats after releasing it; negative answers are not dumped.
