# rdns

Hobby project for implementing DNS in Rust: an authoritative server, a recursive
resolver, and the library both are built on.

Note that all naming conventions try to follow RFC 1035 and others as much as possible.
This is why you get DName instead of DomainName or just Name. DName is closer to what
all the RFC nomenclature uses.

## The five crates

| crate | what it is |
|---|---|
| `rdns` | the library: wire codec, zones, cache, resolver, DNSSEC |
| `rdnsd` | authoritative server — UDP and TCP from one process |
| `rdnsr` | recursive resolver with caching; forwards on `--upstream` |
| `rdnsc` | command-line query client |
| `rdnsctl` | control client for a running `rdnsd` (Unix only) |

**Most of this README is about `rdnsd`.** `rdnsr` has its own section near the
bottom; `rdnsc` is one command.

## Where the documentation lives

| file | answers |
|---|---|
| this file | how to run it and deploy it |
| `docs/spec/` | **what it actually does** — the wire codec, zone model, both daemons, DNSSEC, operations, and an RFC conformance table with every known deviation and gap |
| `docs/CLI_USAGE.md` | the reasoning behind individual `rdnsd` flags (a subset of them — see `TODO.md` §19g) |
| `TODO.md` | what is open, how to verify, and why things are shaped as they are |
| `CLAUDE.md` | the mistakes this codebase has made, written as rules |

## Features

**Authoritative (`rdnsd`)**

- RFC 1034 §4.3.2 in full: delegations with referrals and glue, CNAME chasing,
  wildcards synthesizing to any depth, empty non-terminals, NODATA against
  NXDOMAIN
- AXFR (RFC 5936) and IXFR (RFC 1995) in **both directions**, and the secondary
  role: `--secondary zone@master`, REFRESH/RETRY timers, and EXPIRE that actually
  withdraws a zone rather than serving a stale copy with AA set
- NOTIFY (RFC 1996), sent when a serial moves and received from a zone's masters
- TSIG (RFC 8945), with per-key zone scoping so one partner's key is not a key
  to every zone, and signed error replies — a refusal a client can tell from
  tampering
- Dynamic UPDATE (RFC 2136), TSIG-only and scoped per key: prerequisites, the
  four update forms, the apex SOA and NS protections, and the §3.6 serial bump.
  Every accepted update is **written back to the zone file before the client is
  told it succeeded**, because the re-signing timer reloads from disk and an
  in-memory-only change would quietly expire. A signed zone is re-signed
  incrementally — only what moved, so the update is still an increment to a
  secondary rather than a full zone with new signatures on everything
- A per-zone journal of version steps, so a restart answers an IXFR from before
  it instead of falling back to a full transfer for every secondary
- Multi-zone support via zone enumeration, or a TOML config file with per-zone
  settings (`--config`, `--check-config`) that keeps TSIG secrets out of `argv`
- Rate limiting (`--query-rate`), a response-byte budget (`--response-rate`), and
  request validation

**DNSSEC**

- Validation: **ECDSA P-256/P-384, Ed25519, RSA/SHA-256, RSA/SHA-512**, and
  RSA/SHA-1 for the long tail of zones still signed with it (RFC 8624 §3.1 calls
  it NOT RECOMMENDED; refusing it would mark those zones bogus rather than let
  their signatures speak)
- NSEC and NSEC3 proof-of-non-existence, both read and written, including
  closest-encloser proofs and opt-out
- Signing: key generation (ECDSA, Ed25519), an RRSIG per RRset, and an NSEC or
  NSEC3 chain — signed in memory as the zone loads, re-signed on a timer before
  the signatures lapse, with expiry spread deterministically across the zone so
  it degrades on a slope rather than expiring all at once
- RFC 5011 managed trust anchors, and RFC 8198 aggressive use of validated
  denials

**Recursive (`rdnsr`)**

- Recursion from the root, or forwarding with `--upstream`
- QNAME minimisation (RFC 9156), 0x20 case randomisation, per-server RTT
  selection, and a total query budget as the NXNSAttack defence
- Answer, negative (RFC 2308) and denial caches
- Special-use names answered locally and never forwarded (RFC 6761, 6762, 6303)

**Operations**

- Signal handling: SIGHUP reloads zones, SIGTERM/SIGINT stop gracefully —
  in-flight zone transfers finish rather than being cut mid-stream
- Prometheus metrics on `--metrics-listen`: RED counters, an answer-latency
  histogram, per-zone serial and last-refresh gauges, and separate liveness
  (`/healthz`) and readiness (`/readyz`) probes
- A container image (`Dockerfile`), running unprivileged, built and exercised in
  CI rather than only written
- A control socket (`--control-socket`) and `rdnsctl`: `status`, `reload` that
  reports whether it worked, and `dump` of a zone as it is being served

## Local Development

### Quick Start

1. Ensure you have Rust 1.95.0+ installed (pinned as `rust-version` in the
   manifests and verified by CI, not just asserted here)
2. Create test zone files (`.zone` extension) in a zones directory
3. Run rdnsd on localhost without requiring root:

```bash
# One process, both transports, on localhost:5353.
cargo run --bin rdnsd -- --host 127.0.0.1 --port 5353 --zone-dir ./zones
```

There are no `udp` / `tcp` subcommands. There used to be, and both listeners now
live in one process: writable state — a fetched zone, a refresh timer, a TSIG
session, a rate-limit bucket — cannot be split across two processes without one
of them being wrong.

### Zone File Format

Zone files follow standard BIND zone file format with support for:
- A, AAAA, NS, CNAME, SOA, PTR, MX, TXT records
- DNSSEC records (DNSKEY, RRSIG, DS, NSEC, NSEC3)
- `$ORIGIN`, `$TTL` and `$INCLUDE`; comments, quoted strings and `( )`
  continuation
- Any other type in RFC 3597 `\#` generic form, or by `TYPEnnn` mnemonic

Not supported: `$GENERATE`, and any class but IN — a non-IN record is refused at
load rather than quietly stored, which is what makes the class-blind zone index
correct. `docs/spec/02-zone-model.md` is the full syntax.

Example:
```
$ORIGIN example.com.
$TTL 3600

; SOA record
@   IN  SOA ns1.example.com. admin.example.com. (
            2024051300  ; serial
            3600        ; refresh
            1800        ; retry
            604800      ; expire
            86400       ; minimum
        )

; Name servers
@   IN  NS  ns1.example.com.
@   IN  NS  ns2.example.com.

; A records
@   IN  A   192.0.2.1
www IN  A   192.0.2.2
```

### Testing Zone Queries

Use `dig` with custom port to query your local server:

```bash
# Query over UDP
dig @127.0.0.1 -p 5353 example.com

# Query over TCP
dig @127.0.0.1 -p 5353 +tcp example.com

# Query specific record type
dig @127.0.0.1 -p 5353 example.com MX
```

### Zone Reload

While the server is running, modify zone files or add new zones to the directory, then:

```bash
# Send SIGHUP to reload zones (Unix only)
kill -HUP <pid>
```

The server will reload all zones without stopping DNS service.

## Production Deployment

### systemd Service

Create `/etc/systemd/system/rdns.service`:

```ini
[Unit]
Description=rdns DNS Server
After=network.target

[Service]
Type=simple

# Not root, and never root. rdnsd has no --user/--group of its own by design:
# these two lines are stronger than a setuid drop, because the process starts
# unprivileged rather than dropping privilege after the bind, so there is no
# window in which a config parse or a key load runs as uid 0. It follows that
# whatever it starts as it stays as — so this is the user that reads the private
# signing keys and TSIG secrets, and those files should be owned by it.
# CAP_NET_BIND_SERVICE below is what lets an unprivileged user have port 53.
User=rdns
Group=rdns

# --config keeps TSIG secrets out of argv, where `ps aux` and this unit file
# would otherwise both expose them. --check-config is the dry run.
ExecStartPre=/usr/local/bin/rdnsd --config /etc/rdns/rdnsd.toml --check-config
ExecStart=/usr/local/bin/rdnsd --config /etc/rdns/rdnsd.toml

# SIGHUP reloads the zones. Signatures are re-made on their own timer, so the
# cron kill -HUP that DNSSEC deployments used to need is gone.
#
# `rdnsctl reload` does the same thing and *reports the result*, which a signal
# cannot: a zone file with a typo in it fails the reload, the previous zones
# keep answering, and only the log would have said so. Use it here and
# `systemctl reload rdns` fails when the reload did.
ExecReload=/usr/local/bin/rdnsctl reload

# The control socket lives here, created by systemd with this service's own
# ownership and cleared on stop. `rdnsctl` looks for /run/rdns/rdnsd.sock by
# default, so this name and `control-socket` in the config file have to agree.
RuntimeDirectory=rdns
RuntimeDirectoryMode=0750

# SIGTERM stops accepting and finishes what is in flight — an AXFR mid-stream
# included, since a client cannot tell a truncated transfer from a complete one.
# The drain is bounded at 5s, so the default 90s TimeoutStopSec is ample.
KillSignal=SIGTERM
Restart=on-failure
RestartSec=10

# Enable unprivileged port binding for DNS (port 53)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
SecureAmbientCapabilities=yes

# Security hardening
NoNewPrivileges=true
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
# The zone directory needs to be writable only if this server is a secondary:
# a transferred zone is written there, along with its state sidecar.
ReadWritePaths=/etc/rdns/zones

# Logging. The default level is info: the startup banner and effective policy,
# zone loads, transfers, NOTIFYs, refusals and failures. Nothing per-packet is
# above debug, so a malformed-packet flood costs no log lines at all — that used
# to be one unbuffered write(2) per bad packet with no way to turn it off.
# RUST_LOG overrides the level without editing this file; Environment= sets it
# permanently.
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rdns
#Environment=RUST_LOG=rdnsd=debug,rdns::xfr=trace

# Log volume is journald's job, not the daemon's. These are per-unit, so a flood
# here suppresses rdns's own lines and says how many it dropped, without
# starving any other service on the box. rdnsd deliberately has no *log* rate
# limiter of its own: two limiters means two things to reason about at 3am, and
# the second one hides what the first did. (It does have a *query* rate limiter,
# --query-rate, which is a different thing and is on by default at 1000/s.)
LogRateLimitIntervalSec=30s
LogRateLimitBurst=10000

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable rdns
sudo systemctl start rdns
```

### Container image

```bash
# The build arg is what `--version` reports. `.git` is deliberately not in the
# build context — an image layer is a bad place for every version of every file
# ever committed — so the description is computed here and passed in. Without it
# the image reports a bare "0.1.0", which identifies nothing.
docker build -t rdns \
  --build-arg RDNS_GIT_DESCRIBE="$(git describe --always --dirty --tags)" .
docker run -d --name rdns \
  -p 53:5353/udp -p 53:5353/tcp -p 9153:9153 \
  -v /etc/rdns/zones:/etc/rdns/zones:ro \
  rdns
```

The image runs as uid 65532 and listens on **5353**, not 53 — an unprivileged
process cannot bind 53, and both ways around that are worse than publishing a
port: running the server as root gives it root for the lifetime of the process
for the sake of one syscall, and a file capability baked into the image is
invisible to `docker inspect` and inherited by every image built `FROM` it.
Where the container genuinely needs 53 inside its own namespace — host
networking, or a Kubernetes pod with `hostNetwork` — start it with
`--sysctl net.ipv4.ip_unprivileged_port_start=53` and pass `--port 53`.

A secondary needs its zone directory **writable**: it writes each transferred
zone there along with the state sidecar that records when contact was last made,
and that sidecar is what makes a restart able to tell a current replica from an
expired one. Mount it `rw` and `chown 65532`.

`docker stop` sends SIGTERM, which stops accepting, finishes what is in flight —
an AXFR mid-stream included — and exits 0. The drain is bounded at 5s.

### Liveness and readiness

Two questions, two endpoints, on the `--metrics-listen` port:

| probe | asks | says no when |
|---|---|---|
| `GET /healthz` | is the process alive | never, while it can answer at all |
| `GET /readyz` | has it finished starting | a zone it is configured to serve is not in the zone map |

The distinction matters for exactly one deployment: a **secondary**. A primary
loads, signs and verifies every zone before it binds a socket, so it is ready as
soon as it is alive. A secondary that starts cold — or whose copy on disk is
older than the zone's EXPIRE, or that has no record of ever having transferred
it — withdraws that zone and answers REFUSED for it until the first transfer
lands. With `Restart=on-failure` and a liveness-only gate, a rolling restart
moves traffic onto exactly that server.

```console
$ curl -i localhost:9153/readyz
HTTP/1.1 503 Service Unavailable
not ready: waiting for 1 zone(s) to transfer: example.com.

$ curl -i localhost:9153/readyz          # after the transfer
HTTP/1.1 200 OK
ready
```

In Kubernetes:

```yaml
livenessProbe:
  httpGet: { path: /healthz, port: 9153 }
readinessProbe:
  httpGet: { path: /readyz, port: 9153 }
  periodSeconds: 5
```

`/readyz` is a **one-way latch**: once every zone has arrived it stays ready, and
a zone withdrawn later by EXPIRE does not take it back to not-ready. Every
replica of a zone expires at the same moment — they share the master's EXPIRE and
they all lost contact when the master did — so a readiness signal that followed
expiry would pull every server out of rotation at once, turning stale data into
no server at all. Staleness is what the `dns_zone_last_refresh_timestamp_seconds`
alert below is for.

### Monitoring

Ask the running server, which is the only thing that knows:

```bash
rdnsctl status               # zones, serials, records, denial, role, last contact
rdnsctl reload               # re-read every zone; exits non-zero if it failed
rdnsctl dump example.com.    # the zone *as served*, signatures and all
```

`rdnsctl` talks to `--control-socket` — a Unix socket, mode 0600, so the
filesystem is the authentication. There is no control port, for the reason every
other DNS server has one only behind an HMAC or a client certificate. Exit codes
are 0 for a command that worked, 1 for one the server refused, and 2 for a
server that could not be reached, so a deploy script can tell a bad zone file
from a daemon that is not running.

The distinction that makes `reload` worth having over `kill -HUP`:

```console
$ rdnsctl reload
rdnsctl: the reload failed and the zones already loaded are still being served: line 8: SOA record needs 7 fields, got 0
$ echo $?
1
```

View service logs:

```bash
journalctl -u rdns -f
```

Check service status:

```bash
systemctl status rdns
```

### Configuration

Place zone files (`.zone` extension) in the configured directory:

```bash
mkdir -p /etc/rdns/zones
chmod 755 /etc/rdns/zones
```

### Port Binding

To run on standard DNS port (53) without root:

Use the `systemd` unit above, which gives an unprivileged user
`CAP_NET_BIND_SERVICE` and nothing else. Outside systemd, grant the capability to
the binary directly — but note that a file capability applies to **everyone who
executes that binary**, not just the service, which is why the unit's
`AmbientCapabilities` is the better of the two wherever it is available:

```bash
sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/rdnsd
rdnsd --config /etc/rdns/rdnsd.toml          # as an ordinary user
```

**Running the whole server as root is worth avoiding rather than documenting.**
rdnsd has no `--user`/`--group` on purpose: privilege separation belongs to
whatever starts the process, and `User=` plus an ambient capability beats a
setuid drop, because the process is never root at all rather than dropping root
after the bind. `sudo rdnsd` used to be suggested here; a capability plus a
service-manager identity does the same job without it.

## Testing

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets   # must be clean, no exceptions
cargo fmt --all                          # before every commit
```

`--workspace` is redundant from the root — this is a virtual manifest, so plain
`cargo test` already runs every member — and it is written out anyway because
these four are the commands `CLAUDE.md` prescribes, and they have to keep working
from a subdirectory too.

Narrower runs:

```bash
cargo test -p rdns --lib dnssec              # one module
cargo test -p rdnsd                          # one binary's tests
cargo test -p rdns --test allocations -- --nocapture   # the allocation gate, read as numbers
cargo bench -p rdns                          # criterion, optimized
```

Read `rdns/benches/answer_path.rs`'s header before quoting a benchmark number:
one whole answer is ~0.5 µs and the `sendto`+`recvfrom` pair around it is ~4 µs,
so the entire suite covers about 6% of what a query costs a server.

## CLI Reference

### Authoritative server

```bash
rdnsd [OPTIONS]
```

Serves **UDP and TCP from one process**, on the same host and port. Both are
required of an authoritative server: an oversized reply goes out with TC=1 and the
client retries over TCP (RFC 1035 §4.2.1), and zone transfers are TCP-only
(RFC 5936 §4.2).

**Options:**
- `--host <HOST>` - Listen address (default: 0.0.0.0)
- `--port <PORT>` - Listen port (default: 53)
- `--zone-file <PATH>` - Load a single zone file; the origin comes from its name
- `--zone-dir <DIR>` - Load all `.zone` files from a directory
- `--allow-transfer <ADDR|CIDR>` - Who may request an AXFR. Repeatable, and empty
  by default, which refuses everyone
- `--tsig-key <[ALG:]NAME:SECRET[:TRANSFER-ZONES[:UPDATE-ZONES]]>` - A TSIG key
  (RFC 8945). Repeatable. A signed request may transfer a zone from any address,
  and gets a signed answer. The two zone lists are comma-separated, and `*` means
  every zone; a list of either kind needs the algorithm spelled out. **Their
  defaults are opposite on purpose**: an absent transfer list means every zone,
  because narrowing it would stop transfers on a working deployment, while an
  absent update list means *no* zone, because a write is not something to grant
  by default. A zone list is printed per key in the startup banner
- `--also-notify <ADDR[:PORT]>` - Tell a secondary at once when a zone's serial
  moves (RFC 1996). Repeatable
- `--response-rate <BYTES_PER_SEC>` - Cap on UDP response bytes per client
  (default 8192; 0 disables). Meters what an amplification attack is made of
- `--query-rate <QUERIES_PER_SEC>` - Queries per second per client (default 1000;
  0 disables), with `--query-burst` (200) and `--query-rate-exempt`. **Over the
  limit a query is dropped in silence** — a reply to a spoofed source is what an
  amplifier sends — so the effective policy is printed in the startup banner
- `--secondary <ZONE@MASTER[:PORT][#KEY]>` - Replicate a zone from a master.
  Repeatable; requires `--zone-dir`
- `--config <FILE>` / `--check-config` - Read settings from TOML instead of
  flags, and dry-run them. **Mutually exclusive with the flags above**, not a
  precedence rule

**That is nine of `rdnsd`'s twenty-seven flags.** `rdnsd --help` is the complete
list; `docs/CLI_USAGE.md` has the reasoning behind fourteen of them and
`docs/spec/06-operations.md` has every default and what each limit does when it
fires.

### Recursive resolver

```bash
rdnsr [OPTIONS]
```

Binds **127.0.0.1 by default**, so it is not accidentally exposed as an open
resolver. Recurses from the root unless given an `--upstream`, in which case it
forwards.

- `--upstream <ADDR:PORT>` - Forward instead of recursing. Repeatable
- `--dnssec-validate` - Walk the chain of trust, set AD only on answers that
  verify, SERVFAIL ones that do not (unless the client sets CD)
- `--trust-anchor <FILE>` / `--auto-trust-anchor <FILE>` - Anchors in DS
  presentation format. The second is *rewritten* as keys roll (RFC 5011)
- `--cache-size <N>` (10000), `--no-cache`, `--root-hints <FILE>`,
  `--max-inflight-udp <N>` (1024)

> **`rdnsr` has none of `rdnsd`'s operational shell** — no per-source rate limit,
> no response-byte budget, no metrics and no probes. That is a known gap, not a
> design decision; see `TODO.md` §18. Do not put it on a public address.

### Query client

```bash
rdnsc <server[:port]> <TYPE> <name>
rdnsc 127.0.0.1:5353 A www.example.com
```

Retries over TCP on TC=1, and refuses to print an answer it cannot match to its
own question. It does not send EDNS and cannot set DO, so it cannot exercise the
server's DNSSEC answers — use `dig +dnssec` or dnspython for that (`TODO.md`
§19h).

### Examples

```bash
# Development: localhost, unprivileged port, a directory of zones.
rdnsd --host 127.0.0.1 --port 5353 --zone-dir ./zones

# A single zone file. The origin comes from the FILE NAME, so example.com.zone
# holding `other.test.` answers NXDOMAIN for everything with nothing to say why.
# A config file's [zones."name"] states the origin instead and avoids the trap.
rdnsd --zone-file example.com.zone

# Primary: serve a directory, let one secondary transfer, and tell it at once
# when a serial moves.
rdnsd --zone-dir /etc/rdns/zones \
      --allow-transfer 192.0.2.10 \
      --also-notify 192.0.2.10

# Secondary: replicate that zone back. --zone-dir is required, because the
# transferred zone is written there under its own name.
rdnsd --zone-dir /var/lib/rdns/zones \
      --secondary example.com.@192.0.2.1

# Transfers authenticated by key rather than by address.
rdnsd --zone-file example.com.zone \
      --tsig-key hmac-sha256:transfer.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=

# Sign a zone: make the keys once and learn the DS to hand the parent...
rdnsd --signing-key-dir ./keys --generate-keys example.com.
# ...then serve, signing every zone there is a key for as it loads. The zone
# file on disk stays unsigned; the signatures live in memory only.
rdnsd --zone-dir ./zones --signing-key-dir ./keys

# Resolver: recursing from the root, validating, on localhost.
rdnsr --port 5354 --dnssec-validate

# Resolver: forwarding instead.
rdnsr --port 5354 --upstream 1.1.1.1:53

# Ask either of them something.
rdnsc 127.0.0.1:5353 A www.example.com
```

## Project Status

**757 tests passing on 2026-08-03**, plus 4 doc-tests deliberately marked
`ignore`. `cargo test --workspace` is the source of truth; the number here is a
snapshot with a date on it, because the last one said "110+ unit tests" for long
enough to be wrong by a factor of seven.

| suite | tests |
|---|---|
| `rdns` library | 658 |
| `rdns` allocation gate (`tests/allocations.rs`) | 1, holding **19 measurements**, 13 of them exact |
| `rdns` fuzz guard (`tests/no_input_panics.rs`) | 1, running **1,506 mutated messages** through the pre-authentication path |
| `rdnsd` | 94 |
| `rdnsr` | 3 |

**A test count is a poor summary of a suite, and this is where it shows.** Two of
those single tests carry more than their count suggests, and a green run has
twice not meant what it looked like here — the suite passed at 590 tests while
`rdnsd` could not serve a CNAME, a delegation or a two-label wildcard, because
the tests were written from the same understanding as the code. That is the first
rule in `CLAUDE.md`.

**What works**: everything under [Features](#features) above. **What is open**:
`TODO.md`'s "Open work" table — currently six items, of which #17 is the one
confirmed bug (a TCP length prefix that wraps on a TSIG-signed answer near 64 KB)
and #18 is the largest gap (`rdnsr` has no rate limiting or metrics).

**What is not implemented at all**: DNS over TLS/HTTPS/QUIC, DNAME, SIG(0),
SVCB/HTTPS parsing, and any class but IN. `docs/spec/07-rfc-conformance.md` is
the full matrix, with every deviation stated rather than smoothed over.

Dynamic UPDATE (RFC 2136) **was** on that list and came off it on 2026-08-03: a
TSIG-signed UPDATE is authorized against the key's own scope, checked against its
prerequisites, applied, written back to the zone file and served. A signed zone
is re-signed incrementally, so an update stays an increment on the wire rather
than turning into a whole-zone transfer, and the version steps are journalled to
disk so a restart does not drop every secondary to a full transfer.

## Licence

The manifests say `MIT OR Apache-2.0` and the repository ships only an MIT
`LICENSE`. That is a discrepancy the copyright holder has to resolve — either add
`LICENSE-APACHE` or narrow the manifests.