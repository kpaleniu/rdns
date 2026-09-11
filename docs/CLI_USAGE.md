# rdnsd CLI usage

Reference for `rdnsd`'s command-line options.

"Complete" was a claim this file made and did not keep until 2026-08-03: it had a
section for 14 of 27 flags, and the missing thirteen included all three
`--query-rate*` controls — the ones that drop traffic silently — and
`--secondary`, the whole secondary role. A reference that is quietly partial is
`CLAUDE.md` §4's failure mode in documentation form: a reader who does not find
`--query-rate` here concludes there is no such control. See `TODO.md` #19g.

- [Invocation](#invocation)
- [Flags](#flags)
- [Zone source](#zone-source)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Zone file format](#zone-file-format)

## Invocation

```bash
rdnsd [OPTIONS]
```

UDP and TCP from one process, same host and port. Both are mandatory for an
authoritative server: a reply overflowing the smaller of the client's UDP payload
size and `--max-udp-response` goes out with TC=1 and the client retries over TCP
(RFC 1035 §4.2.1), and zone transfers
are TCP-only (RFC 5936 §4.2). Whichever loop fails first takes the process down,
so it never quietly serves one and not the other.

The `rdnsd udp` / `rdnsd tcp` subcommands are gone. Writable state (a fetched
zone, a refresh timestamp) needs a single owner, and two servers over one zone
file would race to write it.

## Flags

### `--host <HOST>`

Listen address, both transports. Default `0.0.0.0`. Takes IPv4 (`127.0.0.1`,
`0.0.0.0`), IPv6 (`::1`, `::`) or a hostname (`localhost`, `dns.example.com`).

### `--port <PORT>`

Listen port, both transports. Default `53`, range 1–65535. Below 1024 needs root
or `CAP_NET_BIND_SERVICE`; use 5353 for development.

### `--zone-file <PATH>`

Load one zone file. Mutually exclusive with `--zone-dir`; one of the two is
required. The origin comes from the file name: `example.com.zone` →
`example.com.`

### `--zone-dir <DIR>`

Load every `.zone` file in one directory, origins from the file names. Mutually
exclusive with `--zone-file`.

Not recursive — a flat `read_dir`, so organising zones into subdirectories hides
them. A config file's `[zones."name"] file = "..."` names paths individually if
you need a tree.

### `--log-level <LEVEL>` and `--quiet`

`error`, `warn`, `info`, `debug`, `trace`. Default `info`. `--quiet` equals
`--log-level error`, and giving both is an error rather than a precedence rule.
Same flags, levels and default on `rdnsd` and `rdnsr`.

Nothing per-packet is above `debug`, by design. A malformed query, a parse
failure, a response arriving at a listening socket, a client that vanished
mid-write — none is worth an operator's attention one at a time, and at 50k pps
of garbage they were 50k journald lines a second with no way to turn them off.
Measured after the change: 50 malformed datagrams produce no log lines at the
default level.

| level | what it adds |
|---|---|
| `error` | the server cannot do something it must — a trust-anchor file it cannot write, a SIGHUP handler it could not install |
| `warn` | somebody should look, without turning anything up: a TSIG rejection, a refused transfer, a zone withdrawn on EXPIRE, an unacknowledged NOTIFY, an answer that failed DNSSEC validation |
| `info` | the operational record: startup banner and effective policy, zone loads, transfers, reloads, NOTIFYs. The default |
| `debug` | per-packet and per-query detail. This is the flood; ask for it deliberately |
| `trace` | everything |

`RUST_LOG` overrides the flag when set — what to reach for on a server already
misbehaving under a level chosen weeks ago in a unit file:

```bash
RUST_LOG=rdnsd=debug,rdns::xfr=trace rdnsd --config /etc/rdns/rdnsd.toml
```

Log volume is the platform's job. `rdnsd` has no log rate limiter of its own on
purpose: journald's is per-unit (`LogRateLimitIntervalSec`, `LogRateLimitBurst`,
both in the README's unit), it reports what it dropped, and two limiters would be
two things to reason about at 3am.

`--check-config` and `--generate-keys` write to stdout regardless of level,
because their output is the point of running them.

### `--response-rate <BYTES_PER_SEC>` (UDP)

Response bytes per second, per client address. Default `8192`; `0` disables.

The query limiter counts requests, which says nothing about amplification — a
query is a query whether the answer is 60 bytes or 4000. An attacker forging a
victim's source address picks the question with the largest answer, so the bytes
going *out* are what has to be metered.

- Burst allowance is four seconds' worth, so an ordinary page load (a dozen names
  at once) is never touched.
- Over budget, every second response is sent truncated (TC=1) rather than
  dropped. That reply carries no records — smaller than the query that asked for
  it — and a real client retries over TCP, where the handshake proves the source
  address and the budget does not apply.
- UDP only: a TCP query has completed a handshake, so there is nobody to reflect
  at.

Measured on a zone with a 2.5 KB TXT RRset, flooding for 5.5 s from one address:
32.7 KB/s of responses with the budget off, 13.2 KB/s with the default (the
8 KB/s rate plus the burst spread across the window), and the truncated replies
keep a legitimate client working.

```bash
rdnsd --zone-file example.com.zone                        # default 8 KiB/s
rdnsd --zone-file example.com.zone --response-rate 4096   # facing the internet
rdnsd --zone-file example.com.zone --response-rate 0      # closed network only
```

### `--query-rate <QUERIES_PER_SEC>`, `--query-burst`, `--query-rate-exempt`

Queries per second per client address, with a burst allowance and an exemption
list. Defaults 1000/s, burst 200, no exemptions. `--query-rate 0` disables it.

Over the limit a query is dropped in silence — no REFUSED, no SERVFAIL, nothing
on the wire. That is correct, because a reply to a spoofed source is exactly what
an amplifier sends. It is also why the effective policy is printed in the startup
banner and why this section exists: a control that drops traffic invisibly and is
undocumented is one an operator concludes is the network.

The unit is the one you think in. This was once "100 tokens per 10-second window
with a burst of 20", hardcoded and unreachable from the command line — which
reads like a hundred queries and is ten a second. Measured before the fix: a
60-query burst from one address got 20 answers and 40 silent drops. Put that in
front of a busy resolver and you blackhole the bulk of its traffic while `dig`
from a laptop works perfectly.

The default is 1000 because `rdnsd` is authoritative: its clients are resolvers,
not people, and one resolver behind one address legitimately asks orders of
magnitude more than one person. The limiter is a backstop against a flood, not a
quota. (`rdnsr` defaults to 200 for the mirror-image reason.)

`--query-burst` matters more than it looks: DNS clients send in bursts by nature,
one page load being dozens of names at once, so a limiter with no burst allowance
drops traffic that is not a flood. A burst of 0 is floored to 1 rather than
refused — a bucket starts full, and a full bucket of nothing has no token to
spend, so a mistyped flag would refuse every query.

`--query-rate-exempt` takes an address or CIDR prefix, repeatable, parsed by the
same code as `--allow-transfer` — including the rule that a v4 prefix never
matches a v4-mapped v6 peer. It is for the resolvers you run yourself and for a
monitoring probe whose job is to query more often than a client would. Without
it, the only way to spare a known-good source is to raise the limit for everyone.

```bash
# A busy authoritative server, with your own resolvers and a prober spared.
rdnsd --zone-dir ./zones \
  --query-rate 5000 --query-burst 1000 \
  --query-rate-exempt 192.0.2.0/24 --query-rate-exempt 198.51.100.7

rdnsd --zone-dir ./zones --query-rate 0     # off, for a lab
```

### `--secondary <ZONE@MASTER[:PORT][#KEY]>`

Replicate a zone from a master. Repeatable, and requires `--zone-dir`: the
fetched zone is written there, so a restart serves it without waiting for a
transfer.

The whole secondary role is behind this flag. It starts a refresh task per
zone-and-master pair, which:

- fetches the zone (AXFR, or IXFR when it already holds a version) and writes it
  with write-temp-then-rename, so a reader never sees a half-written file;
- honours the SOA's REFRESH and RETRY timers, and wakes early on a NOTIFY from
  one of that zone's configured masters — a NOTIFY from anywhere else is ignored;
- applies EXPIRE: a zone out of contact with every master for longer than its SOA
  says is withdrawn, not served stale. Serving a stale zone with AA set is worse
  than serving nothing;
- records the serial and last-contact time in a sidecar (`rdnsd.state`) beside
  the zones, so EXPIRE survives a restart. A restart that forgot the last-contact
  time would read "nothing known" as "fetch and serve".

`#KEY` names a TSIG key from `--tsig-key`, used to sign the transfer request.

```bash
# Two masters for one zone; either can answer, both may NOTIFY.
rdnsd --zone-dir ./zones \
  --secondary example.com@192.0.2.1 \
  --secondary example.com@192.0.2.2#transfer.key

rdnsd --zone-dir ./zones --secondary example.com@192.0.2.1:5353
```

`rdnsctl status` reports `secondary` from the configuration rather than inferring
it from an absent last-contact time, which a primary also has.

### `--metrics-listen <ADDR:PORT>`

Prometheus metrics on `/metrics`, plus `/healthz` (liveness) and `/readyz`
(readiness) on the same listener. Off by default.

The two probes answer different questions, and conflating them is the usual
mistake: `/healthz` is "this process is alive", `/readyz` is "every zone this
server answers for is loaded". A secondary that has not completed its first
transfer is alive and not ready, and routing traffic to it would mean REFUSED for
a zone it is about to hold.

Counters are RED-shaped — requests, errors, duration — plus per-zone serial and
last-transfer gauges. A zone with no last-transfer time (a primary, or a
secondary that has never fetched) is omitted rather than reported as 0, because 0
is 1970 and would fire every staleness alert there is.

A typo here stops the server rather than leaving it running without the
observability you asked for, the same as a typo in `--port`.

### `--config <FILE>` and `--check-config`

Read settings from TOML instead of flags. Mutually exclusive with the flags above
— `--config` with `--port` is an error, not a precedence rule. Every precedence
rule is one somebody has to remember at 3am to work out why the server is not
where the file says, and the failure is silent because both values are valid.

Two things the file expresses that flags cannot: a secret in a file of its own
(`secret-file`, mode-checked and refused if group- or world-readable on Unix),
and per-zone signing settings.

`--check-config` is a dry run that runs everything not binding a socket: the file
parses, secrets are read and mode-checked, every zone loads, every zone is signed
and every signature verified. A shallower check would pass for the failures that
actually break a deploy.

```bash
rdnsd --config /etc/rdns/rdnsd.toml --check-config && systemctl reload rdns
```

### Signing policy: `--signature-validity`, `--nsec3`, `--nsec3-opt-out`, `--key-algorithm`, `--require-signed`

These modify `--signing-key-dir` and are no-ops without it.

- `--signature-validity <DAYS>` (30). How long an RRSIG is good for. Re-signing
  runs at a third of it, so a failed run has two more chances before anything
  expires. Expiry is spread deterministically across a fifth of the window, so
  the zone degrades on a slope rather than expiring in one second at every
  validator at once.
- `--nsec3` / `--nsec3-opt-out`. NSEC3 instead of NSEC, and opt-out for insecure
  delegations. Empty salt, zero iterations (RFC 9276 §3.1); signing above the
  iteration cap is refused rather than quietly clamped.
- `--key-algorithm <ALG>`. For `--generate-keys`. ECDSA P-256 by default, Ed25519
  also available. RSA keys cannot be generated here.
- `--require-signed`. Refuse to start if a zone that has keys did not end up
  signed. Without it a signing failure is a warning and the zone is served
  unsigned — which, for a zone whose parent has a DS, is worse than not serving
  it: every validating client sees bogus rather than merely unvalidated.

### `--allow-partial-load`

Serve the zones that loaded when some did not. Off by default, and the default is
the point: one typo plus a deploy is otherwise a lame delegation for that zone,
39 green dashboards, and a log line that scrolled past hours ago. The flag exists
because the behaviour is defensible when the alternative is worse — a secondary
holding 40 zones would rather serve 39 than none — but it should be a decision
rather than what happens when nobody looked.

### `--udp-workers <TASKS>` (UDP)

How many UDP datagrams may be answered at once. Defaults to the machine's
parallelism, clamped to 2–32; the effective number is in the startup banner, so a
floored or clamped value is visible rather than assumed.

This is the shape of the UDP path as well as its ceiling: that many identical
tasks share the socket and answer inline, with no task spawned per datagram. TCP
had two bounds (128 connections, 16 queries in flight per connection) and UDP had
none, so a flood spawned tasks until something gave out — paying for the task, a
copy of the packet and two `Arc` clones before the rate limiter had decided
whether to keep the datagram.

- Raising it does not make a busy server faster. Answering from an in-memory zone
  is microseconds with two await points, so the useful parallelism is the
  machine's. What the number buys is memory: one 64 KB receive buffer per worker,
  because a client may send any datagram a UDP length field can express.
- Past the workers, datagrams queue in the socket receive buffer and the kernel
  drops the overflow. For UDP that is the right back-pressure, and `netstat -su`
  counts it, which a userspace drop would not.
- `0` is floored to 1 on the command line (a mistyped flag should be wrong, not
  fatal). In a config file `udp-workers = 0` is refused outright, with the line
  number, because that is where the whole policy is being edited at once.

Measured with DHAT over 1,000 UDP queries against one zone, on 16 workers:
allocation fell from 7.45 MB in 34,487 blocks to 2.88 MB in 31,574 blocks — the
1,536-byte task per datagram is gone, and 996 responses are built in 16 buffers
rather than 996. The trade is 1 MB of receive buffers held for the life of the
process instead of 64 KB.

```bash
rdnsd --zone-file example.com.zone                     # one worker per CPU, 2–32
rdnsd --zone-file example.com.zone --udp-workers 2     # small VM
```

### `--udp-payload-size <OCTETS>` and `--max-udp-response <OCTETS>` (UDP)

The two sizes a UDP answer is governed by. Both default to **1232**, both are
floored at 512, and both are in the startup banner.

`--udp-payload-size` is what every reply's OPT record says this server can
reassemble (RFC 6891 §6.2.4) — a statement about *receiving*, which is why it
also floors `--max-udp-request`: refusing a request smaller than what the OPT
advertised is a promise broken in silence.

`--max-udp-response` is the largest datagram this server will *send*. A client's
EDNS advertisement is honoured only down to it, so a stub asking for 65,535 no
longer gets 65,535. Over the cap the reply is an empty TC=1 one and the client
asks again over TCP, where the RFC 1035 §4.2.2 length prefix is the only limit
and neither number applies.

1232 is 1280 — IPv6's minimum MTU — less the IPv6 and UDP headers, and is where
BIND, Knot, NSD and Unbound all landed after DNS Flag Day 2020. Above it a reply
fragments, and a fragment is what middleboxes drop.

What this costs in TCP retries is a property of your zones, not of the number, so
measure rather than guess: `cargo test -p rdnsd response_size -- --nocapture`
weighs every shape of answer off a signed zone. For the zone it uses, one
question of eighteen exceeds 1232 and it is ANY at a signed apex; an NSEC3
NXDOMAIN proof is 760, or 1,188 during a ZSK rollover.

```bash
rdnsd --zone-file example.com.zone                              # 1232 / 1232
rdnsd --zone-file example.com.zone --max-udp-response 4096      # the pre-#41 size, bounded
rdnsd --zone-file example.com.zone --max-udp-response 65535     # whatever the client asked for
```

### `--max-udp-request <OCTETS>` and `--max-tcp-request <OCTETS>`

The largest request each transport will parse, before anything is allocated for
it. 4096 on UDP and 16 KiB on TCP; over the cap the packet is dropped in silence,
so the effective pair is in the startup banner.

The UDP one is floored at `--udp-payload-size` for the reason above. It is 4096
rather than RFC 1035's 512 because a legitimate signed UPDATE is larger than 512:
a 2048-bit DKIM rotation weighs 566 octets with its TSIG and an ACME order with
ten SANs 898, measured by
`cargo run --release -p rdns --example request_size_probe`.

### `--control-socket <PATH>` (Unix only)

Answer `rdnsctl` on this Unix domain socket. Off by default.

Of the four questions an operator asks at 3am, one could be answered before this
existed:

| question | before | now |
|---|---|---|
| Is `example.com` loaded, at what serial? | query the SOA | `rdnsctl status` |
| Is `broken.test` loaded? | REFUSED — also what a zone that was never configured answers | `rdnsctl status` |
| Is the secondary in sync? | read the state sidecar off the box by hand | `rdnsctl status`, last-contact column |
| Did that reload take effect? | grep the log and hope the level was left on | `rdnsctl reload` exits non-zero and says why |

```console
$ rdnsctl status
rdnsd 0.1.0 on 127.0.0.1:15356, up 4h 12m
zones: 2 loaded, 1 replicated

zone                            serial  records  denial  role       last contact
example.com.                        42       57  NSEC3   primary    -
replica.test.                        7       12  -       secondary  1754060591 (4m 11s ago)
```

Filesystem permissions are the authentication: the socket is created mode 0600 —
the server's user and root — and there is no TCP option. That is what Knot
(`knotc`), PowerDNS (`pdns_control`) and Unbound with `control-interface: /path`
do; the two that put a control channel on TCP put something in front of it,
BIND's `rndc` an HMAC and NSD's `nsd-control` a client certificate. Nobody ships
an unauthenticated control port, which is also why these commands are not
endpoints on `--metrics-listen`.

Three things the bind does that a plain `bind()` would not:

- A live socket is not stolen. Starting a second server on the same path is
  refused rather than leaving two daemons and one working control channel.
- A stale socket file does not block a start — the ordinary state after a crash.
- The mode is in place before the path is. The socket is bound under a temporary
  name, restricted, then renamed over the target, so there is no window in which
  it is reachable at its published path with whatever the umask gave it.

The socket is removed on a clean stop, so `rdnsctl` says "no such file" rather
than "connection refused" about a server that is not running.

`reload` is the whole zone set and takes no zone argument. That is a decision:
nothing is installed unless every zone parses, signs and verifies, because a
partial reload leaves the server serving a mixture of two versions and the half
that failed is the half that needed attention. `rdnsctl reload example.com.` is
refused and says so.

Unix only. `tokio` exposes no `UnixListener` on Windows, so `rdnsd` refuses
`--control-socket` there at startup rather than accepting it and doing nothing.

```bash
# Under systemd, with RuntimeDirectory=rdns creating /run/rdns.
rdnsd --config /etc/rdns/rdnsd.toml     # control-socket = "/run/rdns/rdnsd.sock"
rdnsctl status                          # that path is rdnsctl's default

# Development.
rdnsd --port 15353 --zone-file example.com.zone --control-socket /tmp/rdnsd.sock
rdnsctl -s /tmp/rdnsd.sock dump example.com. > served.zone
```

The protocol is one line in, one status line plus a body out, so anything that
can write to a Unix socket is a client — which matters on the day the box has
nothing else installed:

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/rdns/rdnsd.sock
```

### `--allow-transfer <ADDR|CIDR>` (TCP)

Who may request an AXFR. Repeatable, empty by default, which refuses everyone.

An AXFR answers with the entire zone: every host, every internal name, the shape
of the network. It is the one query where the answer is the whole database, so it
is allowed by list rather than refused by exception. Every attempt is logged,
permitted or not.

- A rule is a bare address (`192.0.2.10`) or a CIDR prefix (`10.0.0.0/8`,
  `2001:db8::/32`).
- Address families do not mix: a v4 rule never matches a v6 peer, including a
  v4-mapped one.
- A malformed rule stops the server rather than quietly shortening the list.
- TCP only, because AXFR is defined over TCP alone (RFC 5936 §4.2). A UDP request
  gets FORMERR.

```bash
rdnsd --zone-file example.com.zone --allow-transfer 192.0.2.10

rdnsd --zone-file example.com.zone \
  --allow-transfer 192.0.2.10 --allow-transfer 192.0.2.11 \
  --allow-transfer 10.9.0.0/24
```

### `--also-notify <ADDR[:PORT]>`

A secondary to notify when a zone changes (RFC 1996). Repeatable; port defaults
to 53.

Without it a secondary learns of a change when its refresh timer next goes off —
for a typical SOA, hours later. A NOTIFY says so at once, and the secondary
decides what to do about it.

- Sent on zone load: at startup, and again on SIGHUP where signals are supported,
  for every zone whose serial moved forward. An unchanged serial is not news, and
  one that went backwards would be ignored by the secondary anyway.
- The message carries the zone's SOA, so the secondary sees the new serial
  without asking a second question.
- Retried up to three times with a doubling wait. Any rcode counts as an
  acknowledgement — a secondary answering NOTAUTH has still received it, and
  repeating would not change its mind.
- A bare IPv6 address needs brackets to carry a port: `[::1]:5353`.

```bash
rdnsd --zone-file example.com.zone \
  --also-notify 192.0.2.10 --also-notify 192.0.2.11

rdnsd --zone-file example.com.zone --also-notify 127.0.0.1:15353
```

Not done: notifying the zone's own NS set. BIND derives that list from the NS
records; here it is only what `--also-notify` says, which is explicit and never
surprises a host that happens to be named in a zone.

Receiving a NOTIFY is answered NOTAUTH when this server is a primary: no
secondary role, no master to be told by, nothing to fetch. The attempt is logged
either way — a NOTIFY from an unexpected source is worth seeing.

### `--tsig-key <[ALG:]NAME:SECRET[:TRANSFER-ZONES[:UPDATE-ZONES]]>`

A TSIG key (RFC 8945). Repeatable.

Holding a key is an identity; arriving from an address is not. `--allow-transfer`
trusts the network to tell the truth about who is calling; TSIG replaces that
with a keyed MAC over the message.

- The secret is base64, as in a BIND `key {}` statement. The algorithm defaults
  to `hmac-sha256` (what RFC 8945 requires) and may be `hmac-sha1`,
  `hmac-sha384` or `hmac-sha512`. `hmac-md5` is deprecated by RFC 8945 and is not
  implemented.
- A signed request may transfer a zone whatever its source address — a key is a
  stronger statement than an address, so it need not also be on
  `--allow-transfer`. Both are grants; the log line says which one applied.
- Any signed query gets a signed answer, on either transport, so a client can
  tell the reply came from something holding the key rather than from whatever
  answered first.
- A signature that does not check out gets NOTAUTH and a TSIG saying which of
  BADKEY (no such key here), BADSIG (wrong secret, or the message changed) or
  BADTIME (clocks more than 300 s apart — the reply carries this server's time so
  the peer can see which side is wrong) it was.
- A malformed key spec stops the server rather than leaving a key the operator
  believes is configured silently absent.

The two zone lists are comma-separated, both take `*` for "every zone", and a
list of either kind requires the algorithm spelled out — `name:secret:zones` and
`alg:name:secret` are both three fields and cannot otherwise be told apart. Their
defaults are opposite:

- Transfer zones (fourth field): absent means every zone. Narrowing that default
  would mean upgrading the binary silently stops every transfer on a working
  deployment, which is worse than the thing it fixes. Scoping is opt-in, and the
  startup banner prints what each key may transfer, so an unscoped key is a
  visible decision.
- Update zones (fifth field): absent means no zone. A transfer hands over a copy;
  an update rewrites the original. Nothing had ever served an UPDATE before this
  existed, so there was no working deployment for deny-by-default to break — and
  reusing the transfer scope would have handed write access to every zone to every
  key already configured. Granting has to be typed.

`*` in the fourth field is how a key is left unrestricted for transfers and
scoped for updates: the fifth field is positional, so the fourth cannot be left
off, and an empty fourth field is refused because it reads as a narrowing while an
empty *list* means the opposite.

```bash
# Transfers to whoever holds the key, from anywhere. No update rights.
rdnsd --zone-file example.com.zone \
  --tsig-key hmac-sha256:transfer.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=

# A DHCP server that may rewrite one zone and transfer any.
rdnsd --zone-dir /etc/rdns/zones \
  --tsig-key hmac-sha256:dhcp.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=:*:dyn.example.com.

# Belt and braces: the key, and only from the secondary's address.
rdnsd --zone-file example.com.zone \
  --tsig-key transfer.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI= \
  --allow-transfer 192.0.2.10
```

Interoperability was checked against dnspython, whose TSIG is interop-tested
against BIND: it signs a query `rdnsd` verifies, verifies the answer `rdnsd`
signs, and validates every envelope of a multi-message zone transfer.

### `--signing-key-dir <DIR>`

Where the private signing keys live. Every zone loaded from disk whose apex
matches a key here is signed in memory as it loads: the DNSKEY RRset published,
an RRSIG over every authoritative RRset, and an NSEC chain over every name —
including delegation points and empty non-terminals, which is what makes "this
child has no DS" and "this name holds nothing" provable rather than asserted.
Zones with no key here are served exactly as before.

The zone file is never rewritten. What a client validates is what leaves the
socket, and a re-signing timer racing an editor for one file is a way to lose a
zone. A zone that arrived by transfer is not signed either: it is the master's,
signatures included, and the parent's DS points at their key rather than yours.

- Key files are `K<zone>+<algorithm>+<tag>.rdnskey` and hold PKCS#8. They are not
  BIND's `.private` format and do not pretend to be; a key from `openssl genpkey`
  imports as-is.
- Signatures last `--signature-validity` days, 30 by default, made when the zone
  loads. A server running longer than that without a reload serves expired
  signatures, which validating clients treat as bogus — SIGHUP or restart it well
  inside the window.
- `--nsec3` uses NSEC3 instead, no salt and no extra iterations (RFC 9276 §3.1:
  both only ever cost the server and the validator). `--nsec3-opt-out`
  additionally leaves insecure delegations out of the chain, worth it for a zone
  with many unsigned children, and it costs the strength of every denial covering
  an opted-out span.
- `--require-signed` refuses to start unless every zone is signed and every
  signature verifies. Off by default, because most zones are unsigned.

### `--generate-keys <ZONE>`

Makes a key-signing key and a zone-signing key for ZONE in `--signing-key-dir`,
prints the DS record to give the parent, and exits. Nothing is served in this
mode. `--key-algorithm` picks the algorithm by number or mnemonic, default
`ECDSAP256SHA256`; RSA keys cannot be generated here (`ring` implements RSA
signing, not RSA key generation) but can be imported.

Two keys rather than one because only the key-signing key is digested into the
DS: the zone-signing key can then be replaced whenever, while replacing the other
means a conversation with the registrar.

```bash
mkdir -p /etc/rdns/keys
rdnsd --signing-key-dir /etc/rdns/keys --generate-keys example.com
# -> Wrote /etc/rdns/keys/Kexample.com.+013+19047.rdnskey
# -> Wrote /etc/rdns/keys/Kexample.com.+013+04339.rdnskey
# -> Give the parent zone this DS record:
# -> example.com. IN DS 19047 13 2 F073CC97...

# Then serve, signing on the way in.
rdnsd --zone-dir /etc/rdns/zones --signing-key-dir /etc/rdns/keys

# NSEC3 instead, and a shorter validity.
rdnsd --zone-dir /etc/rdns/zones --signing-key-dir /etc/rdns/keys \
  --nsec3 --signature-validity 14

# Every zone here is meant to be signed; fail loudly if one is not.
rdnsd --zone-dir /etc/rdns/zones --signing-key-dir /etc/rdns/keys --require-signed
```

A client asking with DO set gets the signatures and the proofs that go with them;
a client that did not ask gets exactly what it always got. Checked against
dnspython, which validated every RRset served under both chains.

Until the parent publishes the DS, the zone is signed but insecure: a validator
has no path to the keys and treats the zone as unsigned rather than protected.

## Zone source

Exactly one of `--zone-file` or `--zone-dir`.

```bash
# Valid
rdnsd --zone-file example.com.zone
rdnsd --zone-dir /etc/rdns/zones
rdnsd --host 127.0.0.1 --port 5353 --zone-file test.zone

# Both: "Cannot specify both --zone-file and --zone-dir"
rdnsd --zone-file example.com.zone --zone-dir /etc/rdns/zones

# Neither: "Must specify either --zone-file or --zone-dir"
rdnsd --host 127.0.0.1 --port 5353
```

## Examples

```bash
# Development: localhost, unprivileged port, both transports in one process.
mkdir -p zones
cargo run --bin rdnsd -- --host 127.0.0.1 --port 5353 --zone-dir ./zones
dig @127.0.0.1 -p 5353 example.com          # UDP
dig @127.0.0.1 -p 5353 +tcp example.com     # TCP

# Production: all interfaces, port 53 (needs CAP_NET_BIND_SERVICE), a directory.
rdnsd --host 0.0.0.0 --port 53 --zone-dir /etc/rdns/zones

# Two independent zone sets on one host, one process each.
rdnsd --zone-dir /etc/rdns/zones/primary &
rdnsd --port 5353 --zone-dir /etc/rdns/zones/other &

# A single zone file.
rdnsd --host 127.0.0.1 --port 5353 --zone-file example.com.zone
```

## Troubleshooting

Address already in use — something else holds the port:

```bash
lsof -i :53
rdnsd --port 5353 ...        # or pick another port
```

Permission denied on port 53 — grant the capability rather than running as root
(see the README on why `sudo rdnsd` is the wrong answer):

```bash
sudo setcap cap_net_bind_service=+ep /usr/local/bin/rdnsd
rdnsd --port 5353 --zone-dir ./zones     # or just use a high port
```

No such file or directory — check the path, and prefer an absolute one:

```bash
ls -la example.com.zone
rdnsd --zone-file /full/path/to/example.com.zone
```

"No .zone files found in directory" — the extension is required and the walk is
not recursive:

```bash
ls -la ./zones
```

A query returns an empty answer section — check the startup output for "Loaded
zone from...", then that the record is actually in the file:

```bash
grep example.com zones/example.com.zone
```

`kill -HUP` does nothing — SIGHUP reload is Unix only, and the handler is
compiled in there alone. On Unix:

```bash
rdnsd --zone-dir ./zones &
SERVER_PID=$!
cp newzone.zone zones/
kill -HUP $SERVER_PID
```

## Zone file format

Standard BIND format:

```
$ORIGIN example.com.
$TTL 3600

@   IN  SOA ns1.example.com. admin.example.com. (
            2024051300  ; serial
            3600        ; refresh
            1800        ; retry
            604800      ; expire
            86400       ; minimum
        )

@   IN  NS  ns1.example.com.
@   IN  NS  ns2.example.com.

@    IN  A   192.0.2.1
www  IN  A   192.0.2.2
mail IN  A   192.0.2.3

@    IN  MX  10 mail.example.com.
```

Full syntax: `docs/spec/02-zone-model.md`.
