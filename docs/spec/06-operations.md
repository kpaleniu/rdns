# 6. Operations

Configuration, limits, observability, lifecycle, and the two client binaries.

---

## 6.1 Configuration

### Flags or a file, never both

`--config` conflicts with every flag it could set: `--config` with `--port` is an
error, not a precedence rule.

Flags that are not mutually exclusive with `--config`, because the file has no
place for them: `--check-config`, `--log-level`, `--quiet`, `--generate-keys`,
`--key-algorithm`.

### The file

TOML, `deny_unknown_fields` throughout — a mistyped key fails at startup with a
line number.

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

- Every `[zones.*]` field is an `Option`: absent means inherit from `[signing]`,
  not "the default".
- The re-signing interval follows the shortest validity of any zone.
- `[zones."x"].file` takes its origin from the table key, unlike `--zone-file`,
  which derives it from the path.
- A zone name is absolutized, so `[zones."example.com"]` and
  `[zones."example.com."]` are the same zone.
- The config builds `[alg:]name:secret[:zones]` strings and hands them to
  `TsigKey::parse` rather than constructing keys directly.
- A zone list requires the algorithm spelled out, because a fourth
  colon-separated field collides with `[alg:]name:secret` at three fields.

### Secret files

`rdns::persist::ensure_private` checks the mode and refuses a group- or
world-readable file.

> On Windows there is no equivalent and the check does not apply.

### `--check-config`

Reads the config, reads and mode-checks every secret, loads every zone, signs
every zone and verifies every signature, and exits without binding a socket.
Exit 0 means the server would start.

---

## 6.2 Limits, and how each fails

| control | default | on breach | off switch |
|---|---|---|---|
| `--query-rate` (per source, q/s) | 1000 | silent drop | `0` |
| `--query-burst` | 200 | — | floored at 1 |
| `--query-rate-exempt` | none | — | — |
| `--response-rate` (per source, bytes/s) | 8192 | every 2nd over-budget response is an empty TC=1 reply, the rest are dropped (`slip = 2`); burst = 4× the rate | `0` |
| `--udp-workers` | parallelism, clamped 2–32 | datagrams queue in the socket buffer; the kernel drops the overflow and counts it (`netstat -su`) | — |
| `MAX_TCP_CONNECTIONS` | 128 | connection waits | — |
| `MAX_INFLIGHT_PER_CONNECTION` | 16 | read loop back-pressures | — |
| `RateLimiter::max_tracked` | 10 000 | an untracked source is allowed | — |
| `ResponseLimiter::max_tracked` | 10 000 | an untracked source is truncated (TC=1), not dropped and not sent in full | — |

Rates are stated per second (`RateLimitConfig::per_second(rate, burst)`). Every
per-peer table has a `max_tracked` and a documented direction of failure: the
rate limiter allows an untracked source, the query logger decays counts. A burst
of zero is floored to one.

The effective policy — including what each TSIG key may transfer — is printed in
the startup banner, because rate-limited queries are dropped without a reply.

`--query-rate-exempt` and `--allow-transfer` are parsed by the same
`security::TransferAcl`, including the rule that a v4 prefix never matches a
v4-mapped v6 peer. `TransferAcl::parse_named` carries which list a typo is in.

---

## 6.3 Metrics — `--metrics-listen`

Off by default. `GET /metrics`, `GET /healthz`, `GET /readyz`. No TLS, no auth,
no keep-alive, no compression — bind it on loopback or a management address.
Scraped, not pushed.

### Counters (`dns_*_total`)

`queries_received`, `queries_authoritative`, `responses_sent`,
`responses_noerror`, `responses_nxdomain`, `responses_servfail`,
`responses_refused`, `rate_limited`, `validation_errors`, `queries_dropped`, and
`dns_queries_type{type=...}` for A/AAAA/MX/NS/CNAME/TXT/SOA/PTR/OTHER.

`dns_cache_hits_total`, `dns_cache_misses_total` and `dns_queries_recursive_total`
are `rdnsr`'s and stay at zero on `rdnsd`; `queries_authoritative` is the reverse.

> Gap G-3 — fixed 2026-08-03. ~~Those three counters are exported by `rdnsd` and
> nothing increments them.~~ See `07-rfc-conformance.md`.

### Histogram

`dns_answer_latency_seconds` — base units, with buckets sized for an in-memory
zone lookup (tens of microseconds).

### Per-zone gauges

`dns_zone_serial{zone=...}` and
`dns_zone_last_refresh_timestamp_seconds{zone=...}`.

- A zone with no last-transfer time — a primary, or a secondary that has never
  fetched — is omitted rather than reported as 0. `absent()` is the question to
  ask.
- A withdrawn zone stops being reported. Both paths that stop serving a zone
  (`withdraw_unvouched_zones` at startup/reload, and the runtime EXPIRE) call
  `forget_zone`.
- Gauges are written where the fact changes, not sampled at scrape time.
- Label values are escaped: RFC 1035 §5.1 allows escapes in a zone name.

### The two alerts worth having

```promql
rate(dns_responses_servfail_total[5m]) > 0
time() - dns_zone_last_refresh_timestamp_seconds > 604800   # the zone's EXPIRE
```

Timestamps are exposed as instants, not as elapsed times.

### Probes

- `/healthz` — the process is alive.
- `/readyz` — 503 until every `--secondary` zone has transferred at least once;
  200 immediately on a primary. A one-way latch (`rdns/src/readiness.rs`).

---

## 6.4 Logging

The same flag, levels and default on both daemons, through one initialiser
(`rdns::logging::init`).

| level | what appears |
|---|---|
| `error` (= `--quiet`) | failures that are ours |
| `info` (default) | the startup banner and effective policy, every zone load, transfer, NOTIFY and refusal |
| `debug` | everything per-packet |
| `trace` | more |

Nothing per-packet is above `debug`. `RUST_LOG` overrides the flag when set.

The log macros (`bad_request!`, `serving_error!`) do not evaluate their arguments
unless the level is enabled.

---

## 6.5 Lifecycle

### Startup order (`rdnsd`)

1. Logging.
2. Config or flags; refuse the combination.
3. Read secrets, mode-check them.
4. Load every zone, sign every zone with a key, verify every signature. All or
   nothing unless `--allow-partial-load`.
5. `withdraw_unvouched_zones`.
6. Print the banner: effective rate limits, worker count, what each TSIG key may
   transfer.
7. Bind UDP, TCP, and optionally the metrics and control listeners.
8. Mark ready.

### Shutdown

SIGTERM or SIGINT on Unix; Ctrl-C, Ctrl-Break, console-close and shutdown on
Windows — all four, because `tokio::signal::ctrl_c()` registers for
`CTRL_C_EVENT` alone.

Both daemons: stop accepting, let accepted work finish (5 s budget), print
`drained cleanly`, exit 0. An idle server stops in about 2 ms. An in-flight AXFR
is not cut.

`rdns::shutdown` splits two roles:

- `Stop` — watch for the signal. Accept loops hold one for the life of the
  process.
- `Busy` — hold the drain open across a unit of work, never across a sleep.

The drain is an `mpsc` nobody sends on: `recv()` returns `None` when the last
sender clone is dropped. Whatever owns the receiver must drop its own sender
first.

`recv_from` and `accept` are cancel-safe and may sit in a `select!` against the
stop. `read_exact` is not, so the shutdown check on a TCP connection sits between
messages.

Both transports are owned by a `JoinSet`, not raced as two dropped
`JoinHandle`s — dropping a handle detaches a task rather than cancelling it.

---

## 6.6 `rdnsc` — the query client

```
rdnsc [--dnssec] <server[:port]> <TYPE> <name>
```

- Sends exactly the bytes it built.
- 5-second read timeout, 2 attempts.
- TC=1 over UDP retries over TCP.
- Refuses to print an answer it cannot tell was an answer to its own question.
- `--dnssec` attaches an EDNS0 OPT with DO set (RFC 4035 §3.2.1).

The DNSSEC recipes in `TODO.md` use dnspython: an independent implementation
checking our signatures is worth more than our own client checking them.

## 6.7 `rdnsctl` — the control client

See `03-authoritative-server.md` §3.9 for the protocol and the commands.

- Default socket `/run/rdns/rdnsd.sock`, which is what a systemd unit's
  `RuntimeDirectory=` creates.
- Default timeout 150 s; the server bounds its own `reload` reply at 120 s.
- Unix only. On Windows it says so and exits 2 rather than not existing.
