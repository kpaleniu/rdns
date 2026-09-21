# 6. Operations

Configuration, limits, observability, lifecycle, and the two client binaries.

---

## 6.1 Configuration

### Flags or a file, never both

Both daemons take `--config`, and in both it conflicts with every flag it could
set: `--config` with `--port` is an error, not a precedence rule.

Flags that are not mutually exclusive with `--config`, because the file has no
place for them: `--check-config`, `--log-level`, `--quiet`, `--generate-keys`,
`--key-algorithm`. The set is checked rather than listed —
`a_setting_the_file_can_write_is_refused_beside_config` asks clap for the flags
`--config` does not replace and refuses the file a key for any of them, and
`rdnsr` has the same check from the other end.

### `rdnsd`'s file

TOML, `deny_unknown_fields` throughout — a mistyped key fails at startup with a
line number.

```toml
[server]
host = "127.0.0.1"          # default 0.0.0.0
port = 53
zone-dir = "./zones"
allow-transfer = ["192.0.2.1"]
also-notify = ["192.0.2.2:53", "192.0.2.4#partner.key."]   # #key signs the NOTIFY
response-rate = 8192        # bytes/s per client, 0 = off
query-rate = 1000           # queries/s per client, 0 = off
query-burst = 200
query-rate-exempt = ["10.0.0.0/8"]
udp-workers = 8             # default: parallelism clamped to 2..=32
metrics-listen = "127.0.0.1:9153"
tls-listen = "0.0.0.0:853"     # DoT; DoQ is quic-listen, DoH is https-listen
quic-listen = "0.0.0.0:853"    # UDP, so it does not collide with DoT
https-listen = "0.0.0.0:443"
https-path = "/dns-query"
tls-cert = "/etc/rdns/tls/fullchain.pem"
tls-key = "/etc/rdns/tls/privkey.pem"   # mode 0600, checked
transfer-tls-ca = "/etc/rdns/xot-ca.pem"  # anchors for XoT masters (RFC 9103)
transfer-tls-cert = "/etc/rdns/client.pem"  # what to present if a master asks (§7.5)
transfer-tls-key = "/etc/rdns/client.key"   # both or neither, mode-checked
transfer-tls-only = false     # true: refuse a transfer not over TLS 1.3
transfer-client-ca = "/etc/rdns/clients-ca.pem"   # anchors for a *client's* cert
allow-transfer-cert = ["partner.example.:example.com."]   # name[:zone[,zone]]
control-socket = "/run/rdns/rdnsd.sock"
allow-partial-load = false
dnstap = "tcp:127.0.0.1:6000"   # or file:/var/log/rdnsd.fstrm — see 6.4
dnstap-max-bytes = 1073741824   # a capture file's bound; 0 is no limit

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
also-notify = ["192.0.2.3"]     # added to [server].also-notify, for this zone
nsec3 = true                    # overrides [signing] for this zone only
validity-days = 7

[zones."catalog.invalid."]
masters = ["192.0.2.9#partner.key."]
catalog = true                  # its members are served too — see 03 §3.10

[zones."private.example."]      # fetched over TLS: RFC 9103, port 853 by default
masters = ["192.0.2.9#partner.key.+tls=ns1.partner.example."]

[zones."multi.example."]        # RFC 8901 Model 1: the owner signs the key set
dnskey-rrsig = "imported"       # keep the RRSIG(DNSKEY) the zone file carries
```

Rules the schema encodes:

- Every `[zones.*]` field is an `Option`: absent means inherit from `[signing]`,
  not "the default".
- `dnskey-rrsig = "imported"` is RFC 8901 §2.1.1's multi-signer Model 1, where
  "the zone owner holds the KSK set ... and is responsible for signing the DNSKEY
  RRset and distributing it to the providers". This server then has a ZSK and no
  KSK: it keeps the apex DNSKEY RRset's RRSIG from the file and makes none. A
  zone with that setting and no such RRSIG fails to sign rather than publishing
  an unsigned key set. **Model 2 (§2.1.2) needs no setting** — each provider
  signs the DNSKEY RRset with its own KSK, and importing the other providers'
  ZSKs is a zone-file edit, since the signer publishes a DNSKEY it did not put
  there and never signs with a key it has no private half of.
- The re-signing interval follows the shortest validity of any zone.
- `[zones."x"].file` takes its origin from the table key, unlike `--zone-file`,
  which derives it from the path.
- A zone name is absolutized, so `[zones."example.com"]` and
  `[zones."example.com."]` are the same zone.
- The config builds `[alg:]name:secret[:zones]` strings and hands them to
  `TsigKey::parse` rather than constructing keys directly.
- A zone list requires the algorithm spelled out, because a fourth
  colon-separated field collides with `[alg:]name:secret` at three fields.
- `catalog = true` needs masters: a catalog is consumed by replicating it, and
  one served from a local file is an ordinary zone this server produces. A
  catalog is in the catalog list and *not* also in the secondary list — startup
  adds it to the second itself, and a zone in both would be two refresh tasks
  asking one master the same question.
- A master is parsed by `MasterSpec::parse`, the same function the flag uses, so
  the file and `--secondary` cannot disagree about what `#key` or `+tls=` means.
- `+tls=` needs `server.transfer-tls-ca`, and the name after it is not optional:
  RFC 9103 §7.5 has the client authenticate the master, so there is no spelling
  of "encrypt but do not check".
- `server.transfer-tls-cert` and `server.transfer-tls-key` are both or neither,
  and need `transfer-tls-ca`: they are the identity presented when this server
  *fetches* a zone, so without anchors nothing would ever present them.
- `server.allow-transfer-cert` needs `transfer-client-ca`, which is the same rule
  from the other direction: a list of clients whose certificates nothing verifies
  is a policy the operator believes is in force and is not. The anchors in turn
  need an encrypted listener for a certificate to arrive on (03 §3.4).

### `rdnsr`'s file

The same rules, three tables, and no zones: `[server]` is the listeners and the
limits, `[resolver]` is where answers come from and what is kept, `[rpz]` is the
policy feeds.

```toml
[server]
host = "127.0.0.1"          # a resolver's default, not 0.0.0.0
port = 53
query-rate = 200            # 200 and not rdnsd's 1000: one resolver behind one
query-burst = 100           # address asks far more than one person does
max-inflight-udp = 1024     # concurrent recursions; a resolver's udp-workers
metrics-listen = "127.0.0.1:9153"

[resolver]
upstream = ["8.8.8.8:53"]   # naming any switches recursion to forwarding
cache-size = 10000
dnssec-validate = true
auto-trust-anchor = "/var/lib/rdns/anchors.xml"   # RFC 5011
serve-stale = 0             # RFC 8767 window in seconds; 0 is off
dns64 = true                # or a prefix; true is the Well-Known Prefix

[rpz]
policy = "given"            # PolicyOverride::from_str, the flag's own parser;
notify-from = ["192.0.2.1"] # the default for a feed that does not say

[[rpz.feeds]]               # an array: this order is the order they are
file = "court-order.rpz"    # consulted, and a map would reorder it

[[rpz.feeds]]
file = "new-feed.rpz"
policy = "passthru"         # measured while the one above stays enforced

[[rpz.feeds]]
file = "malware.rpz"        # transferred into that file, not written by a cron
master = "malware.rpz.example.@192.0.2.9#partner.key."   # `#name` signs it
on-expire = "enforce"       # or "lift"; enforce is the default
```

The per-feed policy is what the file was wanted for: `--rpz-policy` is one
setting for every `--rpz`, so measuring a new feed from the command line means
measuring every feed at once.

The 22 `[server]` keys both daemons have are declared once, by
`rdns::server_table!`, and expanded into each daemon's own struct. A macro
rather than a shared struct because a `#[serde(flatten)]`ed struct makes serde
buffer the table: a typo would then be reported at the table's line with no
expected-key list, for `rdnsd`'s file as much as for this one (`TODO.md` #63h).
The macro takes each field's default from the calling crate's root, which is why
`host`, `query-rate` and `query-burst` can differ between the two daemons.

It writes the *projection* onto the flags as well, for its own keys and the
daemon's. A key declared and never assigned used to parse, satisfy
`deny_unknown_fields` and then do nothing — visible as a `dead_code` warning
only while nothing else read the field, which `check` does for ten of
`rdnsd`'s (`TODO.md` #103). A key with no flag of the same name and type is now
a compile error.

`log-level` and `quiet` are not settable from either file.

### Secret files

`rdns::persist::ensure_private` checks the mode and refuses a group- or
world-readable file.

> On Windows there is no equivalent and the check does not apply.

### `--check-config`

Reads the config, reads and mode-checks every secret, resolves every TSIG key
name a `--secondary` or `--catalog` spec gives, loads every zone, signs every
zone and verifies every signature, and exits without binding a socket. Exit 0
means the server would start.

Member zones of a catalog are not among the zone count it reports: they arrive
with the catalog, so what a dry run can check is that the catalog itself is
configured and that its key resolves.

`rdnsr --check-config` is the same idea over what a resolver has: every policy
feed read and indexed, the trust anchors loaded, every ACL and the NAT64 prefix
parsed, the certificate read against its key. It reports how many feeds are not
taken at their word, because a feed at `passthru` or `disabled` blocks nothing
and looks exactly like a working server. Two differences from `rdnsd`'s: it does
not require `--config`, since everything it checks is flag-settable too; and it
does not write the `--auto-trust-anchor` file when that file does not yet exist,
because a dry run would leave it owned by whoever ran the check.

---

## 6.2 Limits, and how each fails

| control | default | on breach | off switch |
|---|---|---|---|
| `--query-rate` (per source, q/s) | 1000 | silent drop | `0` |
| `--query-burst` | 200 | — | floored at 1 |
| `--query-rate-exempt` | none | — | — |
| `--response-rate` (per source, bytes/s) | 8192 | every 2nd over-budget response is an empty TC=1 reply, the rest are dropped (`slip = 2`); burst = 4× the rate | `0` |
| `--udp-payload-size` (advertised in every reply's OPT) | 1232 | floors `--max-udp-request`; nothing else | floored at 512 |
| `--max-udp-response` | 1232 | over it, an empty TC=1 reply and the client retries over TCP, which is not capped | `65535` |
| `--udp-workers` | parallelism, clamped 2–32 | datagrams queue in the socket buffer; the kernel drops the overflow and counts it (`netstat -su`) | — |
| `MAX_TCP_CONNECTIONS` | 128 | connection waits | — |
| `MAX_INFLIGHT_PER_CONNECTION` | 16 | read loop back-pressures | — |
| `RateLimiter::max_tracked` | 10 000 | an untracked source is allowed | — |
| `ResponseLimiter::max_tracked` | 10 000 | an untracked source is truncated (TC=1), not dropped and not sent in full | — |

Rates are stated per second (`RateLimitConfig::per_second(rate, burst)`). Every
per-peer table has a `max_tracked` and a documented direction of failure: the
rate limiter allows an untracked source, the query logger decays counts. A burst
of zero is floored to one.

**Where the token is spent differs by daemon and not by transport.** `rdnsd`
charges per message, `rdnsr` per connection accepted (`TODO.md` #30e): a
resolver's clients open a connection and ask a few things, an authoritative
server's are resolvers that pipeline. All four connection-oriented transports
— TCP, DoT, DoQ and DoH — ask the same two questions of `RateLimit`, so the
number an operator sets means the same thing on each. It did not: DoH charged
a `PerConnection` client again for the first request of every connection
(#105). A `PerConnection` refusal lands before the TLS handshake and shows as
a dropped connection; a `PerMessage` one over DoH is a 429, because by then
the peer has completed two handshakes and there is nobody to reflect at.

The effective policy — including what each TSIG key may transfer — is printed in
the startup banner, because rate-limited queries are dropped without a reply.

`--query-rate-exempt` and `--allow-transfer` are parsed by the same
`security::TransferAcl`, including the rule that a v4 prefix never matches a
v4-mapped v6 peer. `TransferAcl::parse_named` carries which list a typo is in.
So is `--dns64-exclude`, which is the same question — is this address in one of
these prefixes — asked of an answer rather than of a peer.

### `rdnsr`'s policy switches

Four flags that change what an answer *is* rather than how much of it there may
be. All are off unless given, all are printed in the startup banner, and each is
specified in `05-resolver.md`.

| flag | default | what it turns on |
|---|---|---|
| `--rpz PATH` (repeatable, ordered) | none | response policy zones; `--rpz-policy` overrides every action in every zone, and `[[rpz.feeds]]` in the config file does it per feed (§5.6) |
| `--serve-stale SECONDS` | `0`, off | answering from expired cache when a refresh fails (RFC 8767, §5.5) |
| `--prefetch` | off | re-resolving a cache entry in the last tenth of its TTL (§5.5) |
| `--dns64 [PREFIX]` | off; the Well-Known Prefix when given no value | synthesizing AAAA from A (RFC 6147, §5.7). `--dns64-exclude` adds to §5.1.4's `::ffff:0:0/96` |

Off by default in every case, and for one reason each: an RPZ is a policy the
operator has to have; a stale answer is known to be out of date (RFC 8767 §6); a
prefetch turns one client query into two; and a synthesized AAAA is only
reachable through a translator this resolver does not operate.

---

## 6.3 Metrics — `--metrics-listen`

Off by default. `GET /metrics`, `GET /healthz`, `GET /readyz`. No TLS, no auth,
no keep-alive, no compression — bind it on loopback or a management address.
Scraped, not pushed.

An HTTP/1.1 request is refused 400 unless it carries exactly one valid `Host`
header, which is RFC 9112 §3.2's MUST and which hyper does not enforce for us.
Scrapers and `curl` send one; a request typed by hand does not, so the refusal
says what does — §3.2 exempts HTTP/1.0, and
`printf 'GET /metrics HTTP/1.0\r\n\r\n' | nc host 9153` is the probe that needs
no header.

### Counters (`dns_*_total`)

`queries_received`, `queries_authoritative`, `responses_sent`,
`responses_noerror`, `responses_nxdomain`, `responses_servfail`,
`responses_refused`, `rate_limited`, `validation_errors`, `queries_dropped`, and
`dns_queries_type{type=...}` for A/AAAA/MX/NS/CNAME/TXT/SOA/PTR/OTHER.

`dns_tls_handshakes_total` and `dns_tls_handshake_failures_total`, and the same
pair for QUIC: the ratio is how an expired or mismatched certificate is seen at
all, since nothing here parses `notAfter`.

`dns_dnstap_frames_total` and `dns_dnstap_dropped_total`: the query stream, and
what its bounded queue had no room for. See 6.4.

`dns_cache_hits_total`, `dns_cache_misses_total` and `dns_queries_recursive_total`
are `rdnsr`'s and stay at zero on `rdnsd`; `queries_authoritative` is the reverse.

Five more are `rdnsr`'s alone, and each counts something that is otherwise
invisible on the wire (see `05-resolver.md` §5.5-§5.7):

| counter | what it counts |
|---|---|
| `dns_policy_rewrites_total` | answers a response policy zone replaced |
| `dns_policy_drops_total` | queries an `rpz-drop` rule answered with silence — without this, one is indistinguishable from a lost packet |
| `dns_stale_answers_total` | answers served from expired cache because a refresh failed (RFC 8767) |
| `dns_prefetches_total` | names re-resolved before expiry; against `dns_cache_hits_total` it says whether `--prefetch` is paying for itself |
| `dns_synthesized_total` | AAAA records DNS64 built from an A record; it does not fall to zero on its own when a NAT64 is retired |
| `dns_slow_resolutions_total{outcome=...}` | recursions that ran past RFC 8767 §4's 1.8 s client response timer, split `completed`/`failed` — `completed` is the case a second stale timer would serve early, `failed` is one the timer already in place covers (`TODO.md` #58) |

> Gap G-3 — fixed 2026-08-03. ~~Those three counters are exported by `rdnsd` and
> nothing increments them.~~ See `07-rfc-conformance.md`.

### Histogram

`dns_answer_latency_seconds` — base units. Eleven bounds, 1 µs to 5 s,
because one histogram serves both daemons: an in-memory zone lookup is tens of
microseconds and a recursion is tens of milliseconds to seconds. `le="1.8"` is
RFC 8767 §4's client response timer, so that bound against `+Inf` counts the
resolutions a second stale timer could cut short (`TODO.md` #58).

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

### Per-catalog gauge

`dns_catalog_members{catalog=...}` — how many member zones each consumed catalog
has this server serving (see `03-authoritative-server.md` §3.10). Zero is a real
value here and is reported: RFC 9432 §6's failure is a producer emptying a
catalog, and the count falling to zero is what an alert fires on. Absent means
no catalog of that name has been read yet — one configured and never
transferred has no series, which `absent()` is the question for.

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
(`rdns_transport::logging::init`).

| level | what appears |
|---|---|
| `error` (= `--quiet`) | failures that are ours |
| `info` (default) | the startup banner and effective policy, every zone load, transfer, NOTIFY and refusal |
| `debug` | everything per-packet |
| `trace` | more |

Nothing per-packet is above `debug`. `RUST_LOG` overrides the flag when set.

The log macros (`bad_request!`, `serving_error!`) do not evaluate their arguments
unless the level is enabled.

### The query stream — `--dnstap` (dnstap)

A different output from the log, for a different reader. The log answers "is
something wrong" for a human and says nothing per packet above `debug`; dnstap is
the packet stream analytics, abuse handling and security tooling consume. The two
are not alternatives and neither substitutes for the other.

`--dnstap tcp:<addr:port>` sends to a collector; `--dnstap file:<path>` writes a
capture `dnstap -r` reads. **The scheme is required**: a bare path and a bare
address are both plausible, and guessing is how an operator gets the other one.
A target that cannot be opened — a collector not listening, a path not writable —
fails at startup rather than leaving the server up and the stream absent.

| | |
|---|---|
| payload | Protocol Buffers, `dnstap.proto`'s `Dnstap` and `Message`, written out rather than generated |
| framing | Frame Streams (`fstrm`): a 32-bit big-endian length, or a zero escape to a control frame |
| content type | `protobuf:dnstap.Dnstap`, which is what a reader matches on |
| handshake | `tcp:` speaks READY/ACCEPT/START; `file:` takes START directly, because there is nobody to accept |
| close | STOP, and FINISH on a socket. A killed process leaves a capture with neither, which `dnstap -r` reports as truncated |

**One entry per exchange, not two.** BIND emits `AUTH_QUERY` and `AUTH_RESPONSE`
separately; here the response entry carries the query verbatim in
`Message.query_message`, which is what the schema is for and halves the frames on
the answer path. A request that was answered with silence — over the response
budget — is an `AUTH_QUERY` with no response, which is the one thing a log line
at `debug` cannot tell a pipeline. An UPDATE is `UPDATE_QUERY` / `UPDATE_RESPONSE`.

**`query_time` and `response_time` are both to the nanosecond**, so a reader can
subtract them. The transport's own clock read is in whole seconds and is not used
for this: a query time rounded down to the second reports a latency of up to a
second for an answer that took microseconds, and a wrong number is worse than an
absent one. The extra `SystemTime::now` is paid only when `--dnstap` is on.

**`socket_protocol` names all five: UDP, TCP, DOT, DOH and DOQ.** The dispatcher
is told `validation::Arrival`, which says which protocol carried the message and
what it negotiated; `Privacy` — what the connection hid — is derived from it and
is still what RFC 9103 §11 turns on. Until `TODO.md` #54 the dispatcher had only
the `Privacy`, so the three encrypted transports were one value and the field
was left absent: it is `optional` in the schema, and an absent field is a reader
showing nothing where DOT for a DoH query would be a wrong one.

**The queue drops rather than blocking.** A bounded channel sits between the
answer path and the writer, and a full one costs the payload, never the query: an
analytics sink that stops reading must not become an outage.
`dns_dnstap_frames_total` and `dns_dnstap_dropped_total` are the pair, and a
ratio that leaves zero is the alert.

**A capture file is bounded and not rotated.** `--dnstap-max-bytes` (default 1
GiB, 0 for none) stops the writing when reached, warns once, and counts every
further payload as dropped. Without it an unrotated capture is a way to fill a
disk and take the server down with it. Ignored for `tcp:`, where the collector
owns the storage.

**No Unix socket**, which is dnstap's usual transport. `tokio` has no
`UnixStream` on Windows, and a cfg-gated sink is a module that stops compiling on
one platform behind a green suite — which this tree has already done once.
`rdnsd`'s control socket carries that cost because nothing else can authenticate
by file mode; a dnstap sink has TCP.

`Dnstap.identity` comes from `HOSTNAME`, then `COMPUTERNAME`, and is omitted when
neither is set. `Dnstap.version` is `rdnsd <version>`.

---

## 6.5 Lifecycle

### Startup order (`rdnsd`)

1. Logging.
2. Config or flags; refuse the combination.
3. Read secrets, mode-check them.
4. Load every zone, sign every zone with a key, verify every signature. All or
   nothing unless `--allow-partial-load`. Startup verifies everything; a later
   reload skips what it has already proved (`03-authoritative-server.md` §3.8).
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
rdnsc [--dnssec] <server[:port]> <QTYPE> <name>
```

- Sends exactly the bytes it built.
- 5-second read timeout, 2 attempts.
- TC=1 over UDP retries over TCP.
- Refuses to print an answer it cannot tell was an answer to its own question.
- Every query carries an EDNS0 OPT advertising 1232; `--dnssec` sets DO in it
  (RFC 4035 §3.2.1). The OPT is unconditional because a server may only put an
  Extended DNS Error in a reply to a query that had one (RFC 8914 §2).
- Prints any Extended DNS Error the reply carries, beside the RCODE it
  annotates — on an answer and on a refused transfer, which is the reply an
  operator is most likely to be holding.
- The type is a QTYPE: `ANY` (or `*`), `AXFR` and `TYPEnnn` as well as the
  mnemonics. An unreadable name exits 1 and says so.
- `AXFR` goes straight to TCP with RD clear (RFC 5936 §4.2, §4.1.1) and prints
  records until the closing SOA, which is the transfer's only end marker
  (§2.2). It prints rather than assembles: this client holds no zone.
- `IXFR` is refused. RFC 1995 §3 has the request carry the client's SOA, saying
  which version it holds, and this client holds none.

The DNSSEC recipes in `TODO.md` use dnspython: an independent implementation
checking our signatures is worth more than our own client checking them.

## 6.7 `rdnsctl` — the control client

See `03-authoritative-server.md` §3.9 for the protocol and the commands.

- Default socket `/run/rdns/rdnsd.sock`, which is what a systemd unit's
  `RuntimeDirectory=` creates.
- Default timeout 150 s; the server bounds its own `reload` reply at 120 s.
- Unix only. On Windows it says so and exits 2 rather than not existing.
