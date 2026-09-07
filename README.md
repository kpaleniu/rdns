# rdns

Hobby project implementing DNS in Rust: an authoritative server, a recursive
resolver, and the library both are built on.

## Crates

| crate | what it is |
|---|---|
| `rdns` | the library: wire codec, zones, cache, resolver, DNSSEC |
| `rdnsd` | authoritative server — UDP and TCP from one process |
| `rdnsr` | recursive resolver with caching; forwards on `--upstream` |
| `rdnsc` | command-line query client |
| `rdnsctl` | control client for a running `rdnsd` (Unix only) |

## Documentation

| file | contents |
|---|---|
| this file | how to run and deploy it |
| `docs/spec/` | what it does: wire codec, zone model, both daemons, DNSSEC, operations, RFC conformance |
| `docs/CLI_USAGE.md` | `rdnsd` flags in detail |
| `TODO.md` | open work, current state, verification recipes |
| `docs/CLOSED_WORK.md` | every finished item, and the reasoning that produced it |
| `CLAUDE.md` | coding rules for this repo |

## Features

Authoritative (`rdnsd`):

- RFC 1034 §4.3.2 in full: delegations with referrals and glue, CNAME chasing,
  wildcards to any depth, empty non-terminals, NODATA against NXDOMAIN
- AXFR (RFC 5936) and IXFR (RFC 1995) in both directions; secondary role with
  REFRESH/RETRY timers and EXPIRE
- NOTIFY (RFC 1996), sent and received
- TSIG (RFC 8945), per-key zone scoping, signed error replies
- Dynamic UPDATE (RFC 2136), TSIG-only, scoped per key, written back to the zone
  file before the client is answered; signed zones re-signed incrementally
- A per-zone journal of version steps, so a restart can still answer an IXFR
- Multi-zone by directory, or a TOML config file with per-zone settings
- Rate limiting, a response-byte budget, request validation

DNSSEC:

- Validation: ECDSA P-256/P-384, Ed25519, RSA/SHA-256, RSA/SHA-512, RSA/SHA-1
- NSEC and NSEC3, read and written, with closest-encloser proofs and opt-out
- Signing: key generation (ECDSA, Ed25519), an RRSIG per RRset, an NSEC or NSEC3
  chain, in memory at load, re-signed on a timer with expiry spread across the
  zone
- RFC 5011 managed trust anchors, RFC 8198 aggressive use of validated denials

Recursive (`rdnsr`):

- Recursion from the root, or forwarding with `--upstream`
- QNAME minimisation (RFC 9156), 0x20 case randomisation, per-server RTT
  selection, a total query budget
- Answer, negative (RFC 2308) and denial caches
- Special-use names answered locally (RFC 6761, 6762, 6303)
- Rate limits, response-byte budget, Prometheus metrics, `/healthz`

Operations:

- SIGHUP reloads zones; SIGTERM/SIGINT drain in-flight work, transfers included
- Prometheus metrics: RED counters, answer-latency histogram, per-zone serial and
  last-refresh gauges, `/healthz` and `/readyz`
- A container image (`Dockerfile`), unprivileged, built and exercised in CI
- A control socket and `rdnsctl`: `status`, `reload`, `dump`

## Quick start

Rust 1.95.0+. Put `.zone` files in a directory:

```bash
cargo run --bin rdnsd -- --host 127.0.0.1 --port 5353 --zone-dir ./zones

dig @127.0.0.1 -p 5353 example.com
dig @127.0.0.1 -p 5353 +tcp example.com
dig @127.0.0.1 -p 5353 example.com MX
```

`kill -HUP <pid>` reloads zones without stopping service (Unix only).

## Zone file format

Standard BIND format. Supported:

- A, AAAA, NS, CNAME, SOA, PTR, MX, TXT
- DNAME (RFC 6672) and SVCB/HTTPS (RFC 9460)
- DNSSEC records (DNSKEY, RRSIG, DS, NSEC, NSEC3)
- `$ORIGIN`, `$TTL`, `$INCLUDE`; comments, quoted strings, `( )` continuation
- Any other type in RFC 3597 `\#` generic form, or by `TYPEnnn` mnemonic

Not supported: `$GENERATE`, and any class but IN. Full syntax in
`docs/spec/02-zone-model.md`.

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
```

## Deployment

### systemd

`/etc/systemd/system/rdns.service`:

```ini
[Unit]
Description=rdns DNS Server
After=network.target

[Service]
Type=simple

# rdnsd has no --user/--group; it never runs as root. This user reads the
# private signing keys and TSIG secrets, so it should own them.
User=rdns
Group=rdns

# --config keeps TSIG secrets out of argv. --check-config is the dry run.
ExecStartPre=/usr/local/bin/rdnsd --config /etc/rdns/rdnsd.toml --check-config
ExecStart=/usr/local/bin/rdnsd --config /etc/rdns/rdnsd.toml

# Reports the result, so `systemctl reload rdns` fails when the reload did.
ExecReload=/usr/local/bin/rdnsctl reload

# rdnsctl defaults to /run/rdns/rdnsd.sock; this and `control-socket` in the
# config file have to agree.
RuntimeDirectory=rdns
RuntimeDirectoryMode=0750

# The drain is bounded at 5s, so the default 90s TimeoutStopSec is ample.
KillSignal=SIGTERM
Restart=on-failure
RestartSec=10

# Unprivileged port 53.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
SecureAmbientCapabilities=yes

NoNewPrivileges=true
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
# Writable only for a secondary: transferred zones and the state sidecar.
ReadWritePaths=/etc/rdns/zones

StandardOutput=journal
StandardError=journal
SyslogIdentifier=rdns
#Environment=RUST_LOG=rdnsd=debug,rdns::xfr=trace

# Log volume is journald's job; rdnsd has no log rate limiter of its own.
LogRateLimitIntervalSec=30s
LogRateLimitBurst=10000

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable rdns
sudo systemctl start rdns
```

### Container

```bash
# RDNS_GIT_DESCRIBE is what `--version` reports; `.git` is not in the build
# context, so it is computed here and passed in.
docker build -t rdns \
  --build-arg RDNS_GIT_DESCRIBE="$(git describe --always --dirty --tags)" .
docker run -d --name rdns \
  -p 53:5353/udp -p 53:5353/tcp -p 9153:9153 \
  -v /etc/rdns/zones:/etc/rdns/zones:ro \
  rdns
```

Runs as uid 65532 on port 5353. For port 53 inside the container's own namespace
— host networking, or a Kubernetes pod with `hostNetwork` — start it with
`--sysctl net.ipv4.ip_unprivileged_port_start=53` and pass `--port 53`.

A secondary needs its zone directory writable: mount it `rw` and `chown 65532`.

`docker stop` sends SIGTERM: stops accepting, finishes in-flight work including
an AXFR, exits 0, bounded at 5 s.

### Port 53 without systemd

```bash
sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/rdnsd
rdnsd --config /etc/rdns/rdnsd.toml          # as an ordinary user
```

A file capability applies to everyone who executes the binary; the unit's
`AmbientCapabilities` is narrower where it is available.

### Liveness and readiness

On the `--metrics-listen` port:

| probe | says no when |
|---|---|
| `GET /healthz` | never, while the process can answer at all |
| `GET /readyz` | a zone this server is configured to serve is not in the zone map |

Only a secondary is ever not-ready: a primary loads, signs and verifies every
zone before binding a socket. `/readyz` is a one-way latch — a zone withdrawn
later by EXPIRE does not take it back to not-ready; use the
`dns_zone_last_refresh_timestamp_seconds` alert for staleness.

```console
$ curl -i localhost:9153/readyz
HTTP/1.1 503 Service Unavailable
not ready: waiting for 1 zone(s) to transfer: example.com.

$ curl -i localhost:9153/readyz          # after the transfer
HTTP/1.1 200 OK
ready
```

```yaml
livenessProbe:
  httpGet: { path: /healthz, port: 9153 }
readinessProbe:
  httpGet: { path: /readyz, port: 9153 }
  periodSeconds: 5
```

### Monitoring

```bash
rdnsctl status               # zones, serials, records, denial, role, last contact
rdnsctl reload               # re-read every zone; exits non-zero if it failed
rdnsctl dump example.com.    # the zone as served, signatures and all

journalctl -u rdns -f
```

`rdnsctl` talks to `--control-socket`, a Unix socket at mode 0600. Exit codes: 0
worked, 1 the server refused, 2 the server could not be reached.

```console
$ rdnsctl reload
rdnsctl: the reload failed and the zones already loaded are still being served: line 8: SOA record needs 7 fields, got 0
$ echo $?
1
```

## Testing

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets   # must be clean, no exceptions
cargo fmt --all                          # before every commit

cargo test -p rdns --lib dnssec              # one module
cargo test -p rdnsd                          # one binary's tests
cargo test -p rdns --test allocations -- --nocapture   # the allocation gate
cargo bench -p rdns                          # criterion, optimized
```

Read `rdns/benches/answer_path.rs`'s header before quoting a benchmark number:
the suite covers about 6% of what a query costs a server.

## CLI reference

### `rdnsd` — authoritative server

UDP and TCP from one process, same host and port.

| flag | |
|---|---|
| `--host <HOST>` | listen address, default `0.0.0.0` |
| `--port <PORT>` | listen port, default 53 |
| `--zone-file <PATH>` | one zone file; the origin comes from the file name |
| `--zone-dir <DIR>` | every `.zone` file in one directory |
| `--allow-transfer <ADDR\|CIDR>` | who may AXFR. Repeatable; empty by default, which refuses everyone |
| `--tsig-key <[ALG:]NAME:SECRET[:TRANSFER-ZONES[:UPDATE-ZONES]]>` | a TSIG key (RFC 8945). Repeatable. Zone lists are comma-separated, `*` is every zone, and a list needs the algorithm spelled out. Absent transfer list = every zone; absent update list = no zone |
| `--also-notify <ADDR[:PORT]>` | notify a secondary when a serial moves. Repeatable |
| `--response-rate <BYTES_PER_SEC>` | UDP response bytes per client, default 8192, `0` disables |
| `--query-rate <QUERIES_PER_SEC>` | per client, default 1000, `0` disables. With `--query-burst` (200) and `--query-rate-exempt`. Over the limit a query is dropped silently |
| `--secondary <ZONE@MASTER[:PORT][#KEY]>` | replicate a zone. Repeatable; requires `--zone-dir` |
| `--config <FILE>`, `--check-config` | read settings from TOML, and dry-run them. Mutually exclusive with the flags above |

Nine of twenty-seven flags. `rdnsd --help` is the full list; `docs/CLI_USAGE.md`
covers them individually and `docs/spec/06-operations.md` has every default.

### `rdnsr` — recursive resolver

Binds 127.0.0.1 by default. Recurses from the root unless given `--upstream`.

| flag | |
|---|---|
| `--upstream <ADDR:PORT>` | forward instead of recursing. Repeatable |
| `--dnssec-validate` | walk the chain of trust; AD only on answers that verify, SERVFAIL on those that do not unless the client sets CD |
| `--trust-anchor <FILE>` | anchors in DS presentation format, read only |
| `--auto-trust-anchor <FILE>` | the same, rewritten as keys roll (RFC 5011) |
| `--cache-size <N>` | default 10000. Also `--no-cache` |
| `--root-hints <FILE>` | named.root format |
| `--max-inflight-udp <N>` | default 1024 |
| `--query-rate <QUERIES_PER_SEC>` | default 200, with `--query-burst` (100) and `--query-rate-exempt` |
| `--response-rate <BYTES_PER_SEC>` | default 8192, `0` disables |
| `--metrics-listen <ADDR:PORT>` | Prometheus metrics and `/healthz`. No `/readyz` |

### `rdnsc` — query client

```bash
rdnsc <server[:port]> <TYPE> <name>
rdnsc 127.0.0.1:5353 A www.example.com
rdnsc --dnssec 127.0.0.1:5353 A www.example.com
```

Retries over TCP on TC=1, and refuses to print an answer it cannot match to its
own question.

### Examples

```bash
# Development: localhost, unprivileged port, a directory of zones.
rdnsd --host 127.0.0.1 --port 5353 --zone-dir ./zones

# A single zone file. The origin comes from the FILE NAME; a config file's
# [zones."name"] states it explicitly.
rdnsd --zone-file example.com.zone

# Primary: serve a directory, let one secondary transfer, notify it on a bump.
rdnsd --zone-dir /etc/rdns/zones \
      --allow-transfer 192.0.2.10 \
      --also-notify 192.0.2.10

# Secondary: replicate that zone back.
rdnsd --zone-dir /var/lib/rdns/zones \
      --secondary example.com.@192.0.2.1

# Transfers authenticated by key rather than by address.
rdnsd --zone-file example.com.zone \
      --tsig-key hmac-sha256:transfer.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=

# Sign a zone: generate the keys and print the DS for the parent...
rdnsd --signing-key-dir ./keys --generate-keys example.com.
# ...then serve. The zone file on disk stays unsigned.
rdnsd --zone-dir ./zones --signing-key-dir ./keys

# Resolver: recursing from the root, validating, on localhost.
rdnsr --port 5354 --dnssec-validate

# Resolver: forwarding instead.
rdnsr --port 5354 --upstream 1.1.1.1:53
```

## Status

854 tests passing on Windows and 870 on Linux, measured 2026-09-05 on the same
tree; the gap is the sixteen `#[cfg(unix)]` tests. Plus 4 doc-tests marked
`ignore`. `cargo test --workspace` is the source of truth.

| suite | tests |
|---|---|
| `rdns-core` | 157 |
| `rdns` library | 574 (577 on Linux) |
| `rdns` allocation gate (`tests/allocations.rs`) | 1, holding 42 measurements, 32 exact |
| `rdns` fuzz guard (`tests/no_input_panics.rs`) | 1, running 1,506 mutated messages through the pre-authentication path |
| `rdns-transport` | 2 |
| `rdnsd` | 109 (122 on Linux) |
| `rdnsr` | 10 |

Open work is `TODO.md` — nothing numbered, and one inventory of deliberate RFC
deviations (#21). Everything numbered is closed; `docs/CLOSED_WORK.md` holds it.

Not implemented: DNS over TLS/HTTPS/QUIC, SIG(0), DNS Cookies as anything but
opaque bytes, `$GENERATE`, any class but IN.
`docs/spec/07-rfc-conformance.md` is the full matrix.

## Licence

MIT. `LICENSE` is the text.

Dependencies: 138 third-party crates, all permissive (MIT, Apache-2.0, BSD, ISC,
Unlicense, Zlib, Unicode-3.0), no copyleft. `deny.toml` holds the allow-list.
