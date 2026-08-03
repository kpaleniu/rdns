# 6. Operations

Configuration, limits, observability, lifecycle, and the two client binaries.

---

## 6.1 Configuration

### Flags or a file, never both

`--config` **conflicts with every flag it could set**. `--config` together with
`--port` is an error, not a precedence rule. Every precedence rule is one
somebody has to remember at 3am to work out why the server is not where the file
says — and the failure is silent, because both values are valid. Refusing costs
one restart.

Flags that are *not* mutually exclusive with `--config`, because the file has no
place for them: `--check-config`, `--log-level`, `--quiet`, `--generate-keys`,
`--key-algorithm`.

### The file

TOML, `deny_unknown_fields` **throughout**. A mistyped key that is silently
ignored is a setting the operator believes is in force and is not; `require-signd
= true` has to fail at startup with a line number, not serve unsigned zones
quietly. This one attribute is most of the difference between a config file and a
config file worth having.

```toml
[server]
host = "127.0.0.1"          # default 0.0.0.0
port = 53
zone-dir = "./zones"
allow-transfer = ["192.0.2.1"]
also-notify = ["192.0.2.2:53"]
response-rate = 8192        # bytes/s per client, 0 = off
query-rate = 1000           # queries/s per client, 0 = off
query-burst = 200
query-rate-exempt = ["10.0.0.0/8"]
udp-workers = 8             # default: parallelism clamped to 2..=32
metrics-listen = "127.0.0.1:9153"
control-socket = "/run/rdns/rdnsd.sock"
allow-partial-load = false

[signing]
key-dir = "./keys"
validity-days = 30
nsec3 = false
nsec3-opt-out = false
require-signed = false

[keys."partner.key."]
algorithm = "hmac-sha256"
secret-file = "/etc/rdns/secrets/partner.key"   # mode 0600, checked
# secret = "base64..."                          # or inline
zones = ["example.com."]                        # or every zone if omitted

[zones."example.com."]
file = "example.com.zone"       # the origin comes from the TABLE KEY, not the name
masters = ["192.0.2.9#partner.key."]
also-notify = ["192.0.2.3"]
nsec3 = true                    # overrides [signing] for this zone only
validity-days = 7
```

Rules the schema encodes:

- **`Option` per field for an override, not a whole struct.** In `[zones.*]`,
  absent means *inherit*, not "the default": an operator who sets `nsec3` for one
  zone must not silently reset that zone's validity to thirty days.
- **A derived global follows the extreme, not the default.** The re-signing
  interval follows the **shortest** validity of any zone, because a seven-day
  zone among thirty-day ones is the one that expires if the timer runs on the
  global number.
- **`[zones."x"].file` takes its origin from the table key**, which removes the
  trap `--zone-file` still has: that derives the origin from the *path*, so
  `example.com.zone` holding `other.test.` yields NXDOMAIN for everything with
  nothing to indicate why.
- **A zone name is absolutized**, so `[zones."example.com"]` and
  `[zones."example.com."]` are the same zone and cannot become two.
- **The config builds `[alg:]name:secret[:zones]` strings and hands them to
  `TsigKey::parse`**, rather than constructing keys directly, so the flag path
  and the file path cannot disagree about what a key means.
- **A zone list requires the algorithm to be spelled out** in the string form,
  because a fourth colon-separated field collides with `[alg:]name:secret` at
  three fields. Failing at startup beats guessing whether the first field looks
  like an algorithm name, and beats reading a zone list as a base64 secret.

### Secret files

`rdns::persist::ensure_private` checks the mode and **refuses a readable one**. A
secret in a file is only better than a secret in `argv` if the file is private,
and a key directory restored from backup as 0644, or `chmod -R`'d by a deploy
script, is the ordinary way a private key stops being private.

> **On Windows there is no equivalent and the check does not apply.** Saying so
> out loud is the point: "the permissions were checked" must not be a claim that
> is only true on one platform.

### `--check-config`

A real dry run: it reads the config, reads and mode-checks every secret, loads
every zone, **signs every zone and verifies every signature**, and exits without
binding a socket. Exit 0 means the server would start.

A shallower check — parse the file and stop — passes for exactly the failures
that break a deploy: a typo in a zone, a chmodded key, signatures that do not
verify.

---

## 6.2 Limits, and how each fails

| control | default | on breach | off switch |
|---|---|---|---|
| `--query-rate` (per source, q/s) | 1000 | **silent drop** | `0` |
| `--query-burst` | 200 | — | floored at 1 |
| `--query-rate-exempt` | none | — | — |
| `--response-rate` (per source, bytes/s) | 8192 | every 2nd over-budget response is an empty TC=1 reply, the rest are **dropped** (`slip = 2`, BIND's default); burst = 4× the rate | `0` |
| `--udp-workers` | parallelism, clamped 2–32 | datagrams queue in the socket buffer; the kernel drops the overflow and counts it (`netstat -su`) | — |
| `MAX_TCP_CONNECTIONS` | 128 | connection waits | — |
| `MAX_INFLIGHT_PER_CONNECTION` | 16 | read loop back-pressures | — |
| `RateLimiter::max_tracked` | 10 000 | an untracked source is **allowed** | — |
| `ResponseLimiter::max_tracked` | 10 000 | an untracked source is **truncated** (TC=1), not dropped and not sent in full | — |

**State keyed on something an attacker chooses must be bounded.** Every per-peer
table has a `max_tracked` and a written-down policy for which way the bound
fails: the rate limiter *allows* an untracked source, because failing closed
would let one flood deny service to everybody; the query logger *decays* counts,
because keeping heavy hitters is the whole signal.

**State a rate in the unit the operator thinks in.** The query limiter was once
configured as "100 tokens per 10-second window, burst 20", which reads as a
hundred queries and *is* ten a second — below what one busy resolver sends.
`RateLimitConfig::per_second(rate, burst)` exists so the number in the config is
the number in the head.

**Silence can be the right answer and still needs to be visible somewhere.**
Rate-limited queries are dropped without a reply, because replying is what an
amplifier does. That is why the **effective policy is printed in the startup
banner** — including what each TSIG key may transfer — and why the metrics
endpoint exists. A control nobody can observe is a control nobody can debug.

**Floor a knob that can turn the server off.** A burst of zero refuses every
query, because a bucket starts full and a full bucket of nothing has no token to
spend. `per_second` floors it at one: a mistyped flag should be wrong, not fatal.

`--query-rate-exempt` and `--allow-transfer` are parsed by the **same**
`security::TransferAcl`, including the rule that a v4 prefix never matches a
v4-mapped v6 peer, which a second implementation would not have.
`TransferAcl::parse_named` carries which list a typo is in.

---

## 6.3 Metrics — `--metrics-listen`

Off by default. `GET /metrics`, `GET /healthz`, `GET /readyz`. **No TLS, no
auth, no keep-alive, no compression** — bind it on loopback or a management
address behind whatever already terminates TLS. Ninety lines over `tokio`'s
`TcpListener`; pulling a second HTTP stack in to answer one method on one path
would repeat the mistake that deleting the OTLP exporter fixed (it took
`Cargo.lock` from 187 packages to 104).

**Scraped, not pushed.** DNS shops scrape.

### Counters (`dns_*_total`)

`queries_received`, `queries_authoritative`, `responses_sent`,
`responses_noerror`, `responses_nxdomain`, `responses_servfail`,
`responses_refused`, `rate_limited`, `validation_errors`, `queries_dropped`,
and `dns_queries_type{type=...}` for A/AAAA/MX/NS/CNAME/TXT/SOA/PTR/OTHER.

**Count what an operator pages on.** REFUSED climbing means a zone went missing;
SERVFAIL climbing means one went wrong; NXDOMAIN is ordinary and noisy. These
replaced `increment_cache_hits`/`increment_cache_misses`, which were standing in
for "found something" and "did not" on a server with no cache — a dashboard built
on that reports a cache hit rate for a thing that has no cache.

> **Gap G-3 — fixed 2026-08-03.** ~~`dns_cache_hits_total`,
> `dns_cache_misses_total` and `dns_queries_recursive_total` are still exported
> and **nothing increments them**.~~ They are `rdnsr`'s now, where all three mean
> something: `cache_hits` on each of its three cache paths, and `cache_misses`
> with `queries_recursive` where a query falls through to a real recursion.
> Nothing was deleted, because nothing about them was wrong — they were in a
> binary with no cache. On `rdnsd` they stay at zero, and so does
> `queries_authoritative` on `rdnsr`. See `07-rfc-conformance.md`.

### Histogram

`dns_answer_latency_seconds` — **base units, per Prometheus convention**, with
buckets that fit the system: an in-memory zone lookup is tens of microseconds, so
a histogram whose first bucket is 5 ms reports every healthy server as identical.

### Per-zone gauges

`dns_zone_serial{zone=...}` and `dns_zone_last_refresh_timestamp_seconds{zone=...}`.

- **A gauge must be able to say "no answer".** Zero is a value, and for a
  timestamp it is 1970 — which fires every staleness alert there is. A zone we
  are primary for has no last-transfer time and a secondary that has never
  fetched has none either, so those series are **omitted**. `absent()` is a
  question PromQL can ask; a wrong number is not.
- **A withdrawn zone stops being reported, it does not freeze.** A serial left at
  its last value shows a zone nobody serves as perfectly healthy — the exact
  condition a staleness alert exists to catch, hidden by the metric meant to
  reveal it. Both paths that stop serving a zone (`withdraw_unvouched_zones` at
  startup/reload, and the runtime EXPIRE) call `forget_zone`.
- **Updated where the fact changes**, not sampled at scrape time. Sampling live
  state puts the scrape behind whatever lock the state is under, and the value is
  still only as fresh as the last scrape.
- **Label values are escaped.** A stray `"` does not corrupt one line, it makes
  the *rest of the scrape* unparseable — and RFC 1035 §5.1 allows escapes in a
  zone name, so "should not contain a quote" is not "cannot".

### The two alerts worth having

```promql
rate(dns_responses_servfail_total[5m]) > 0
time() - dns_zone_last_refresh_timestamp_seconds > 604800   # the zone's EXPIRE
```

**Expose an instant, not an elapsed time.** `time() - x` is the query language's
job; a "seconds since" computed at scrape time is already stale on arrival.

### Probes

- `/healthz` — the process is alive.
- `/readyz` — **503 until every `--secondary` zone has transferred at least
  once**; 200 immediately on a primary, whose zones were all loaded, signed and
  verified before anything bound a socket. A one-way latch
  (`rdns/src/readiness.rs`).

---

## 6.4 Logging

The same flag, levels and default on both daemons, through one initialiser
(`rdns::logging::init`) so they cannot drift about formatting.

| level | what appears |
|---|---|
| `error` (= `--quiet`) | failures that are ours |
| **`info` (default)** | the startup banner and effective policy, every zone load, transfer, NOTIFY and refusal |
| `debug` | **everything per-packet** |
| `trace` | more |

**Nothing per-packet is above `debug`**, which is the point: a malformed packet
is not an operator-actionable event, and at 50k pps of garbage it used to be 50k
journald lines a second with no way to turn it off. Measured: 50 malformed
datagrams produce **0** lines at the default level and 50 at `--log-level debug`.

`RUST_LOG` **overrides** the flag when set, so a server that is already
misbehaving can be turned up without a restart into new flags.

The log macros (`bad_request!`, `serving_error!`) do not evaluate their arguments
unless the level is enabled, so a per-packet message costs nothing when nothing
wants it.

---

## 6.5 Lifecycle

### Startup order (`rdnsd`)

1. Logging.
2. Config or flags; refuse the combination.
3. Read secrets, mode-check them.
4. Load every zone, sign every zone with a key, verify every signature. **All or
   nothing** unless `--allow-partial-load`.
5. `withdraw_unvouched_zones`.
6. Print the banner: effective rate limits, worker count, what each TSIG key may
   transfer.
7. Bind UDP, TCP, and optionally the metrics and control listeners.
8. Mark ready.

### Shutdown

SIGTERM or SIGINT on Unix; **Ctrl-C, Ctrl-Break, console-close and shutdown** on
Windows — all four, because `tokio::signal::ctrl_c()` registers for
`CTRL_C_EVENT` alone and a real `CTRL_BREAK_EVENT` mid-AXFR otherwise reached the
default handler and killed the process with `0xC000013A`.

Both daemons: stop accepting, let accepted work finish (**5 s budget**), print
`drained cleanly`, exit 0. An idle server stops in about 2 ms. So an in-flight
AXFR is not cut, and a client cannot be handed half a zone it believes is whole.

`rdns::shutdown` splits the two roles, and the split is the whole design:

- **`Stop`** — watch for the signal. Accept loops hold one for the life of the
  process.
- **`Busy`** — hold the drain open across a unit of *work*, never across a sleep
  (a refresh timer is hours long). One type carrying both would keep the drain
  open forever and the shutdown would wait out its budget every time, looking
  like it worked while doing nothing.

The drain is an `mpsc` **nobody sends on**: `recv()` returns `None` exactly when
the last sender clone is dropped, which is a counter that cannot be got wrong and
needs no polling. Whatever owns the receiver must drop its own sender first.

**Cancel-safety decides where a `select!` arm may go.** `recv_from` and `accept`
are cancel-safe, so losing a race against the stop drops nothing that was ours.
`read_exact` is not, which is why the shutdown check on a TCP connection sits
**between messages** — where the peer has committed to nothing — and not
mid-message.

Both transports are owned by a `JoinSet` rather than raced as two dropped
`JoinHandle`s: dropping a handle detaches a task, it does not cancel it, so
`main` used to return while the other transport was still reading and replies
were still queued.

---

## 6.6 `rdnsc` — the query client

```
rdnsc <server[:port]> <TYPE> <name>
```

- **Sends exactly the bytes it built.** `to_bytes` returns a length, and
  discarding it once sent a 31-byte query as 512 bytes with 481 trailing zeros —
  one EDNS option away from being rejected by this project's own validator.
- **5-second read timeout, 2 attempts** (what `dig` does). There was no timeout
  at all, so a query to a firewalled address hung forever with no way to tell that
  from a slow server.
- **TC=1 over UDP retries over TCP.** Printing what arrived would print a subset
  of the answer as if it were the answer — silently dropping records is the one
  failure a lookup tool must not have.
- **Refuses to print an answer it cannot tell was an answer to its own question.**

> **Limitation — lifted 2026-08-03.** ~~`rdnsc` sends no OPT record and cannot
> set DO, so it cannot exercise the server's DNSSEC answers.~~ `--dnssec`
> attaches an EDNS0 OPT with DO set (RFC 4035 §3.2.1), which is what a server is
> required to see before it sends RRSIG, NSEC or NSEC3. The DNSSEC recipes in
> `TODO.md` still reach for dnspython, and should: an independent implementation
> checking our signatures is worth more than our own client checking them, which
> is `CLAUDE.md` §1's point about a parser agreeing with its own serializer.
> What changed is that a first look no longer requires one.

## 6.7 `rdnsctl` — the control client

See `03-authoritative-server.md` §3.9 for the protocol and the commands.

- Default socket `/run/rdns/rdnsd.sock` — `/run` rather than `/var/run` or
  `/tmp`: tmpfs, cleared on boot so a stale socket cannot survive a crash, and a
  directory under it is what a systemd unit's `RuntimeDirectory=` creates.
- Default timeout **150 s**, longer than it sounds on purpose: `reload` re-reads,
  signs and verifies every zone before answering, and the server bounds its own
  reply at 120 s. A shorter value would time out on exactly the reload worth
  watching.
- **Unix only.** On Windows it says so and exits 2 rather than not existing, so
  `cargo build --workspace` covers it and nobody discovers the gap by finding the
  command missing.
