# rdns CLI Usage Guide

Complete reference for command-line options and examples for rdnsd (DNS server).

## Table of Contents

- [Basic Commands](#basic-commands)
- [Flags and Options](#flags-and-options)
- [Zone Source](#zone-source)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Basic Commands

```bash
rdnsd [OPTIONS]
```

Serves **UDP and TCP from one process**, on the same host and port. Both are
mandatory for an authoritative server: a reply that overflows the client's UDP
payload size goes out with TC=1 and the client retries over TCP (RFC 1035 §4.2.1),
and zone transfers are TCP-only (RFC 5936 §4.2). Whichever loop fails first takes
the process down, so it never quietly serves one and not the other.

`rdnsd` used to be one process per transport, invoked as `rdnsd udp` or
`rdnsd tcp`. Those subcommands are gone: writable state (a fetched zone, a refresh
timestamp) needs a single owner, and two servers over one zone file would race to
write it. Pass the options directly.

## Flags and Options

### `--host <HOST>`

Listen address, for both transports.

**Default:** `0.0.0.0`

**Supported formats:**
- IPv4: `127.0.0.1`, `192.168.1.1`, `0.0.0.0`
- IPv6: `::1`, `::`
- Hostnames: `localhost`, `dns.example.com`

**Examples:**
```bash
# All interfaces (production)
rdnsd --host 0.0.0.0

# Localhost only (development)
rdnsd --host 127.0.0.1

# IPv6 localhost
rdnsd --host ::1

# Specific interface
rdnsd --host 192.168.1.100
```

### `--port <PORT>`

Listen port, for both transports.

**Default:** `53` (standard DNS port)

**Valid range:** 1-65535

**Examples:**
```bash
# Standard DNS port (requires root or CAP_NET_BIND_SERVICE)
rdnsd --port 53

# Development/testing port (no root required)
rdnsd --port 5353

# High port number
rdnsd --port 8053
```

### `--zone-file <PATH>`

Load zones from a single zone file.

**Notes:**
- Mutually exclusive with `--zone-dir`
- Zone origin extracted from filename: `example.com.zone` → `example.com.`
- File must exist and be readable
- One of `--zone-file` or `--zone-dir` is required

**Examples:**
```bash
rdnsd --zone-file example.com.zone
rdnsd --zone-file /etc/rdns/zones/example.com.zone
rdnsd --zone-file ./zones/test.zone
```

### `--zone-dir <DIR>`

Load all `.zone` files from a directory.

**Notes:**
- Mutually exclusive with `--zone-file`
- Reads `*.zone` files from that one directory. **Not recursive** — a flat
  `read_dir`, so organising zones into subdirectories hides them. (A config file's
  `[zones."name"] file = "..."` names paths individually if you need a tree.)
- Zone origin extracted from filename
- Directory must exist and be readable
- One of `--zone-file` or `--zone-dir` is required

**Examples:**
```bash
# All zones in directory
rdnsd --zone-dir /etc/rdns/zones

# Development zones
rdnsd --zone-dir ./zones

# Current directory
rdnsd --zone-dir .
```

### `--log-level <LEVEL>` and `--quiet`

`error`, `warn`, `info`, `debug` or `trace`. Default `info`. `--quiet` is the
same as `--log-level error`, and giving both is an error rather than a
precedence rule. The same flags, levels and default on `rdnsd` and `rdnsr`.

**Nothing per-packet is above `debug`**, and that is the point rather than an
accident. A malformed query, a parse failure, a response arriving at a listening
socket, a client that vanished mid-write — none of those is worth an operator's
attention one at a time, and at 50k pps of garbage they were 50k journald lines a
second with no way to turn them off. Measured after the change: 50 malformed
datagrams produce no log lines at the default level.

What each level is for:

| Level | What it adds |
|-------|--------------|
| `error` | The server cannot do something it must — a trust-anchor file it cannot write, a SIGHUP handler it could not install. |
| `warn` | Somebody should look, without turning anything up: a TSIG rejection, a refused transfer, a zone withdrawn on EXPIRE, an unacknowledged NOTIFY, an answer that failed DNSSEC validation. |
| `info` | The operational record: startup banner and effective policy, zone loads, transfers, reloads, NOTIFYs. **The default.** |
| `debug` | Per-packet and per-query detail. This is the flood; ask for it deliberately. |
| `trace` | Everything. |

`RUST_LOG` overrides the flag when it is set, which is what to reach for on a
server that is already misbehaving under a level chosen weeks ago in a unit file:

```bash
RUST_LOG=rdnsd=debug,rdns::xfr=trace rdnsd --config /etc/rdns/rdnsd.toml
```

Log **volume** is the platform's job. `rdnsd` has no rate limiter of its own on
purpose — journald's is per-unit (`LogRateLimitIntervalSec`, `LogRateLimitBurst`,
both in the README's unit), it reports what it dropped, and two limiters would be
two things to reason about at 3am.

Two commands still write to **stdout** regardless of level, because their output
is the point of running them: `--check-config` and `--generate-keys`.

### `--response-rate <BYTES_PER_SEC>` (applies to UDP)

Response **bytes** per second, per client address. Default `8192`; `0` turns the
budget off.

The query limiter counts requests, which says nothing about amplification — a
query is a query whether the answer is 60 bytes or 4000. An attacker forging a
victim's source address picks the question with the largest answer, so the bytes
going *out* are what has to be metered.

- The burst allowance is four seconds' worth, so an ordinary page load (a dozen
  names at once) is never touched.
- Over budget, every second response is sent truncated (TC=1) instead of dropped.
  That reply carries no records — smaller than the query that asked for it — and a
  real client retries over TCP, where the handshake proves the source address and
  the budget does not apply.
- Applies to UDP replies only: a TCP query has completed a handshake, so there is
  nobody to reflect at.

```bash
# The default: 8 KiB/s per client.
rdnsd --zone-file example.com.zone

# Tighter, for a server facing the open internet.
rdnsd --zone-file example.com.zone --response-rate 4096

# Off — only sensible on a closed network.
rdnsd --zone-file example.com.zone --response-rate 0
```

Measured on a zone with a 2.5 KB TXT RRset, flooding for 5.5 s from one address:
**32.7 KB/s** of responses with the budget off, **13.2 KB/s** with the default
(the 8 KB/s rate plus the burst allowance spread across the window), and the
truncated replies keep a legitimate client working.

### `--udp-workers <TASKS>` (applies to UDP)

How many UDP datagrams may be answered at once. Defaults to the machine's
parallelism, clamped to 2–32; the effective number is in the startup banner, so
a floored or clamped value is visible rather than assumed.

This is the shape of the UDP path as well as its ceiling. That many identical
tasks share the socket and answer **inline**; there is no task spawned per
datagram. TCP had two bounds (128 connections, 16 queries in flight per
connection) and UDP had none at all, so a flood spawned tasks until something
gave out — and it paid for the task, a copy of the packet and two `Arc` clones
*before* the rate limiter had decided whether to keep the datagram.

- **Raising it does not make a busy server faster.** Answering from an in-memory
  zone is microseconds with two await points in it, so the useful parallelism is
  the machine's. What the number really buys is memory: one 64 KB receive buffer
  per worker, because a client may send any datagram a UDP length field can
  express.
- **Past the workers, datagrams queue in the socket receive buffer** and the
  kernel drops the overflow. For UDP that is the right back-pressure — a reply to
  a spoofed source is what an amplifier sends — and `netstat -su` counts it,
  which a userspace drop would not.
- `0` is floored to 1 on the command line (a mistyped flag should be wrong, not
  fatal). In a config file `udp-workers = 0` is refused outright, with the line
  number, because that is where the whole policy is being edited at once.

```bash
# The default: one worker per CPU, 2 to 32.
rdnsd --zone-file example.com.zone

# A small VM, or a deliberate cap on the receive buffers.
rdnsd --zone-file example.com.zone --udp-workers 2
```

Measured with DHAT over 1,000 UDP queries against one zone, on 16 workers:
allocation fell from **7.45 MB in 34,487 blocks** to **2.88 MB in 31,574
blocks** — the 1,536-byte task per datagram is gone, and 996 responses are built
in 16 buffers rather than 996. The trade is 1 MB of receive buffers held for the
life of the process instead of 64 KB, which is what "one per worker" costs.

### `--control-socket <PATH>` (Unix only)

Answer `rdnsctl` on this Unix domain socket. Off by default.

Of the four questions an operator asks at 3am, exactly one could be answered
before this existed:

| Question | Before | Now |
|---|---|---|
| Is `example.com` loaded, at what serial? | query the SOA | `rdnsctl status` |
| Is `broken.test` loaded? | REFUSED — which is also what a zone that was never configured answers | `rdnsctl status` |
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

**Filesystem permissions are the authentication.** The socket is created mode
0600 — the server's user and root — and there is no TCP option. That is what
Knot (`knotc`), PowerDNS (`pdns_control`) and Unbound with `control-interface:
/path` do; the two that put a control channel on TCP put something in front of
it, BIND's `rndc` an HMAC and NSD's `nsd-control` a client certificate. Nobody
ships an unauthenticated control port, which is also why these commands are not
endpoints on `--metrics-listen`.

Three things the bind does that a plain `bind()` would not:

- **A live socket is not stolen.** Starting a second server on the same path is
  refused rather than leaving two daemons and one working control channel.
- **A stale socket file does not block a start** — that is the ordinary state
  after a crash.
- **The mode is in place before the path is.** The socket is bound under a
  temporary name, restricted, then renamed over the target, so there is no
  window in which it is reachable at its published path with whatever the umask
  gave it.

The socket is removed on a clean stop, so `rdnsctl` says "no such file" rather
than "connection refused" about a server that is not running.

**`reload` is the whole zone set and takes no zone argument.** That is a
decision rather than a gap: nothing is installed unless every zone parses, signs
and verifies, because a partial reload leaves the server serving a mixture of
two versions and the half that failed is the half that needed attention.
`rdnsctl reload example.com.` is refused and says so.

**Unix only.** `tokio` exposes no `UnixListener` on Windows, so `rdnsd` refuses
`--control-socket` there at startup rather than accepting it and doing nothing.

```bash
# Under systemd, with RuntimeDirectory=rdns creating /run/rdns.
rdnsd --config /etc/rdns/rdnsd.toml     # control-socket = "/run/rdns/rdnsd.sock"
rdnsctl status                          # that path is rdnsctl's default

# Development.
rdnsd --port 15353 --zone-file example.com.zone --control-socket /tmp/rdnsd.sock
rdnsctl -s /tmp/rdnsd.sock dump example.com. > served.zone
```

The protocol is one line in and one status line plus a body out, so anything
that can write to a Unix socket is a client — which matters on the day the box
has nothing else installed:

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/rdns/rdnsd.sock
```

### `--allow-transfer <ADDR|CIDR>` (applies to TCP)

Who may request a zone transfer (AXFR). **Repeatable, and empty by default —
which refuses everyone.**

An AXFR answers with the entire zone: every host, every internal name, the shape
of the network. It is the one query where the answer is the whole database, so it
is allowed by list rather than refused by exception. Every attempt is logged,
permitted or not.

- A rule is a bare address (`192.0.2.10`) or a CIDR prefix (`10.0.0.0/8`,
  `2001:db8::/32`).
- Address families do not mix: a v4 rule never matches a v6 peer, including a
  v4-mapped one.
- A malformed rule stops the server rather than quietly shortening the list.
- Applies to TCP, because AXFR is defined over TCP alone (RFC 5936 §4.2). A UDP
  request for it gets FORMERR.

```bash
# One secondary.
rdnsd --zone-file example.com.zone --allow-transfer 192.0.2.10

# Two of them, and a management subnet.
rdnsd --zone-file example.com.zone \
  --allow-transfer 192.0.2.10 --allow-transfer 192.0.2.11 \
  --allow-transfer 10.9.0.0/24

# No flag: transfers refused, which is what you want unless a secondary needs one.
rdnsd --zone-file example.com.zone
```

### `--also-notify <ADDR[:PORT]>`

A secondary to notify when a zone changes (RFC 1996). **Repeatable**, port
defaults to 53, and available on both subcommands.

Without it a secondary learns of a change when its refresh timer next goes off —
for a typical SOA, hours later. A NOTIFY says so at once, and the secondary
decides what to do about it.

- Sent **on zone load**: at startup, and again on SIGHUP where signals are
  supported, for every zone whose serial moved *forward*. An unchanged serial is
  not news, and one that went backwards would be ignored by the secondary anyway.
- The message carries the zone's SOA, so the secondary sees the new serial without
  asking a second question.
- Retried up to three times with a doubling wait. Any rcode counts as an
  acknowledgement — a secondary answering NOTAUTH has still received it, and
  repeating would not change its mind.
- A bare IPv6 address needs brackets to carry a port: `[::1]:5353`.

```bash
# Two secondaries.
rdnsd --zone-file example.com.zone \
  --also-notify 192.0.2.10 --also-notify 192.0.2.11

# One on a non-standard port, for testing.
rdnsd --zone-file example.com.zone --also-notify 127.0.0.1:15353
```

Not done: notifying the zone's own NS set. BIND derives the list from the NS
records; here it is only what `--also-notify` says, which is explicit and never
surprises a host that happens to be named in a zone.

**Receiving** a NOTIFY is answered NOTAUTH: this server is a primary, with no
secondary role, no master to be told by, and nothing to fetch. The attempt is
logged either way — a NOTIFY from an unexpected source is worth seeing.

### `--tsig-key <[ALG:]NAME:SECRET[:TRANSFER-ZONES[:UPDATE-ZONES]]>`

A TSIG key (RFC 8945). **Repeatable**, and available on both subcommands.

Holding a key is an identity; arriving from an address is not. `--allow-transfer`
trusts the network to tell the truth about who is calling; TSIG replaces that with
a keyed MAC over the message.

- The secret is base64, as in a BIND `key {}` statement. The algorithm defaults to
  `hmac-sha256` (what RFC 8945 requires) and may be `hmac-sha1`, `hmac-sha384` or
  `hmac-sha512`. `hmac-md5` is deprecated by RFC 8945 and is not implemented.
- **A signed request may transfer a zone whatever its source address** — a key is
  a stronger statement than an address, so it does not also need to be on
  `--allow-transfer`. Both remain grants; the log line says which one applied.
- Any signed query gets a signed answer, on either transport, so a client can tell
  the reply came from something holding the key rather than from whatever answered
  first.
- A signature that does not check out gets NOTAUTH and a TSIG saying which of
  **BADKEY** (no such key here), **BADSIG** (wrong secret, or the message changed)
  or **BADTIME** (clocks more than 300 s apart — the reply carries this server's
  time so the peer can see which side is wrong) it was.
- A malformed key spec stops the server rather than leaving a key the operator
  believes is configured silently absent.

**The two zone lists, and why their defaults are opposite.** Both are
comma-separated, both take `*` for "every zone", and a list of either kind
requires the algorithm to be spelled out — `name:secret:zones` and
`alg:name:secret` are both three fields and cannot otherwise be told apart.

- **Transfer zones (the fourth field). Absent means every zone.** Narrowing that
  default would mean upgrading the binary silently stops every transfer on a
  working deployment, which is worse than the thing it fixes. Scoping is
  therefore opt-in, and the startup banner prints what each key may transfer so
  an unscoped key is a visible decision rather than an invisible one.
- **Update zones (the fifth field). Absent means no zone.** A transfer hands over
  a copy; an update rewrites the original. Nothing had ever served an UPDATE
  before this existed, so there was no working deployment for a deny-by-default
  to break — and reusing the transfer scope would have handed write access to
  every zone to every key already configured. Granting has to be typed.

`*` in the fourth field is how a key is left unrestricted for transfers *and*
scoped for updates: the fifth field is positional, so the fourth cannot simply be
left off, and an empty fourth field is refused because it reads as a narrowing
while an empty *list* means the opposite.

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

# Signed ordinary queries over UDP, answered signed.
rdnsd --zone-file example.com.zone \
  --tsig-key transfer.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=
```

Interoperability was checked against dnspython, whose TSIG is interop-tested
against BIND: it signs a query that `rdnsd` verifies, verifies the answer `rdnsd`
signs, and validates every envelope of a multi-message zone transfer.

### `--signing-key-dir <DIR>`

Where the private signing keys live. Every zone loaded from disk whose apex
matches a key in here is **signed in memory as it loads**: the DNSKEY RRset
published, an RRSIG over every authoritative RRset, and an NSEC chain over every
name — including delegation points and empty non-terminals, which is what makes
"this child has no DS" and "this name holds nothing" provable rather than merely
asserted. Zones with no key here are served exactly as before.

The zone file is never rewritten. What a client validates is what leaves the
socket, and a resigning timer racing an editor for one file is a way to lose a
zone. A zone that arrived by transfer is not signed either: it is the master's,
signatures included, and the parent's DS points at their key rather than yours.

- Key files are `K<zone>+<algorithm>+<tag>.rdnskey` and hold PKCS#8. They are not
  BIND's `.private` format and do not pretend to be; a key from `openssl genpkey`
  imports as-is.
- Signatures last `--signature-validity` days, 30 by default, and are made when
  the zone loads. **A server running longer than that without a reload serves
  expired signatures**, which validating clients treat as bogus — send it a
  SIGHUP, or restart it, well inside the window.
- `--nsec3` uses NSEC3 instead, with no salt and no extra iterations (RFC 9276
  §3.1: both only ever cost the server and the validator). `--nsec3-opt-out`
  additionally leaves insecure delegations out of the chain, which is worth it
  for a zone with many unsigned children and costs the strength of every denial
  covering an opted-out span.
- `--require-signed` refuses to start unless every zone is signed and every
  signature verifies. Off by default, because most zones are unsigned and serving
  them is the normal case.

### `--generate-keys <ZONE>`

Makes a key-signing key and a zone-signing key for ZONE in `--signing-key-dir`,
prints the DS record to give the parent, and exits. Nothing is served in this
mode. `--key-algorithm` picks the algorithm by number or mnemonic and defaults to
`ECDSAP256SHA256`; RSA keys cannot be generated here (`ring` implements RSA
signing and not RSA key generation) but can be imported.

Two keys rather than one because only the key-signing key is digested into the
DS: the zone-signing key can then be replaced whenever, while replacing the other
means a conversation with the registrar.

```bash
# Once, before anything else.
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

# Every zone here is meant to be signed; say so, and fail loudly if one is not.
rdnsd --zone-dir /etc/rdns/zones --signing-key-dir /etc/rdns/keys --require-signed
```

A client asking with the DO bit set gets the signatures and the proofs that go
with them; a client that did not ask gets exactly what it always got. Checked
against dnspython, which validated every RRset served under both chains.

Until the parent publishes the DS, the zone is signed but *insecure*: a validator
has no path to the keys and will treat the zone as unsigned rather than as
protected.

## Zone Source

Exactly one of `--zone-file` or `--zone-dir` must be specified.

### Valid Combinations

✅ **Valid:**
```bash
rdnsd --zone-file example.com.zone
rdnsd --zone-dir /etc/rdns/zones
rdnsd --host 127.0.0.1 --port 5353 --zone-file test.zone
```

❌ **Invalid:**
```bash
rdnsd --zone-file example.com.zone --zone-dir /etc/rdns/zones
# Error: Cannot specify both --zone-file and --zone-dir

rdnsd --host 127.0.0.1 --port 5353
# Error: Must specify either --zone-file or --zone-dir
```

## Examples

### Development Setup

**Quick local testing without root:**

```bash
# Create test zones directory
mkdir -p zones

# One process, both transports. (There is no `udp` subcommand — see above.)
cargo run --bin rdnsd -- \
  --host 127.0.0.1 \
  --port 5353 \
  --zone-dir ./zones

# In another terminal, query with dig
dig @127.0.0.1 -p 5353 example.com
```

### Production Setup

**High-availability multi-zone server:**

```bash
# Run UDP server on standard DNS port
# Requires root or CAP_NET_BIND_SERVICE capability
rdnsd \
  --host 0.0.0.0 \
  --port 53 \
  --zone-dir /etc/rdns/zones

# Run TCP server for zone transfers
rdnsd \
  --host 0.0.0.0 \
  --port 53 \
  --zone-dir /etc/rdns/zones
```

### Multiple Servers

**DNS primary and secondary on same host:**

```bash
# One server per zone set, each serving both transports.
rdnsd --zone-dir /etc/rdns/zones/primary &
rdnsd --port 5353 --zone-dir /etc/rdns/zones/other &
```

### Testing with Different Protocols

**Test UDP vs TCP:**

```bash
# One server, both transports on the same port.
rdnsd --host 127.0.0.1 --port 5353 --zone-dir ./zones

# Query it either way.
dig @127.0.0.1 -p 5353 example.com          # UDP
dig @127.0.0.1 -p 5353 +tcp example.com     # TCP
```

### Single Zone File

**For testing or dedicated zone serving:**

```bash
rdnsd \
  --host 127.0.0.1 \
  --port 5353 \
  --zone-file example.com.zone
```

## Troubleshooting

### Port Already in Use

```
Error: Address already in use
```

**Solution:**
- Use a different port: `--port 5353`
- Or find and stop the existing process:
  ```bash
  lsof -i :53              # Find process on port 53
  sudo kill -9 <PID>       # Kill the process
  ```

### Permission Denied (Port 53)

```
Error: Permission denied
```

**Solutions:**
1. Run with `sudo`:
   ```bash
   sudo rdnsd --zone-dir /etc/rdns/zones
   ```

2. Or use a high port for testing:
   ```bash
   rdnsd --port 5353 --zone-dir ./zones
   ```

3. Or set capability on binary (production):
   ```bash
   sudo setcap cap_net_bind_service=+ep /usr/local/bin/rdnsd
   ```

### Zone File Not Found

```
Error: No such file or directory
```

**Solutions:**
- Check file path:
  ```bash
  ls -la example.com.zone
  ```

- Use absolute path:
  ```bash
  rdnsd --zone-file /full/path/to/example.com.zone
  ```

### No .zone Files Found

```
Error: No .zone files found in directory: ./zones
```

**Solutions:**
- Create zone files with `.zone` extension:
  ```bash
  touch ./zones/example.com.zone
  ```

- Verify directory is readable:
  ```bash
  ls -la ./zones
  ```

### Query Returns No Results

```
$ dig @127.0.0.1 -p 5353 example.com
;; QUESTION SECTION:
; example.com.                 IN      A

;; Answer SECTION:
```

**Solutions:**
- Verify zone file is loaded: Check server startup output for "Loaded zone from..."
- Check zone file format: Verify it's valid BIND zone format
- Verify record exists in zone file:
  ```bash
  grep "example.com" zones/example.com.zone
  ```

### Cannot Reload Zones (SIGHUP)

```
kill -HUP <PID>  # No effect
```

**Notes:**
- SIGHUP reload only works on Unix/Linux (not Windows)
- Signal handler must be compiled in (Unix-only feature)
- Add new zone files to the zone directory, then signal:
  ```bash
  # Start server
  rdnsd --zone-dir ./zones &
  SERVER_PID=$!
  
  # Add new zone file
  cp newzone.zone zones/
  
  # Reload
  kill -HUP $SERVER_PID
  ```

## Zone File Format

Zone files use standard BIND format:

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

@   IN  A   192.0.2.1
www IN  A   192.0.2.2
mail IN  A  192.0.2.3

@   IN  MX  10 mail.example.com.

www IN  CNAME example.com.
```

For more details, see `ZONE_FORMAT.md`.
