# rdns

Hobby project implementing DNS in Rust: an authoritative server, a recursive
resolver, and the library both are built on.

## Features

Authoritative (`rdnsd`):

- RFC 1034 §4.3.2 in full: delegations with referrals and glue, CNAME chasing,
  wildcards to any depth, empty non-terminals, NODATA against NXDOMAIN
- DNAME (RFC 6672) and SVCB/HTTPS (RFC 9460), stored, served and parsed from a
  zone file
- AXFR (RFC 5936) and IXFR (RFC 1995) in both directions; secondary role with
  REFRESH/RETRY timers and EXPIRE
- Catalog zones (RFC 9432), consumer side: the zones a catalog lists are
  provisioned, removed and migrated between catalogs without an operator
- NOTIFY (RFC 1996), sent and received
- TSIG (RFC 8945), per-key zone scoping, signed error replies
- Dynamic UPDATE (RFC 2136), TSIG-only, scoped per key, written back to the zone
  file before the client is answered; signed zones re-signed incrementally
- A per-zone journal of version steps, so a restart can still answer an IXFR
- Multi-zone by directory, or a TOML config file with per-zone settings
- Rate limiting, a response-byte budget, request validation

Transports — both daemons, all from one process:

- UDP and TCP (RFC 1035, RFC 7766), many queries per connection
- DNS over TLS (RFC 7858), QUIC (RFC 9250) and HTTPS (RFC 8484) on
  `--tls-listen`, `--quic-listen`, `--https-listen`; one certificate, re-read on
  every reload
- Zone transfer over TLS (RFC 9103), both directions, with the client
  authenticated by certificate name or by TSIG

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
- Answer, negative (RFC 2308) and denial caches, with optional serve-stale
  (RFC 8767) and prefetching
- Special-use names answered locally (RFC 6761, 6762, 6303)
- Response Policy Zones, for an operator with a blocklist to enforce
- DNS64 (RFC 6147) for an IPv6-only network behind a NAT64
- Rate limits, response-byte budget, Prometheus metrics, `/healthz`

Operations:

- SIGHUP reloads zones; SIGTERM/SIGINT drain in-flight work, transfers included
- Extended DNS Errors (RFC 8914) on the refusals and on `rdnsr`'s SERVFAILs, so
  a rejection says which one it was
- dnstap (`--dnstap`) to a socket or a file, for every answered request
- Prometheus metrics: RED counters, answer-latency histogram, per-zone serial and
  last-refresh gauges, `/healthz` and `/readyz`
- A container image (`Dockerfile`), unprivileged, built and exercised in CI
- A control socket and `rdnsctl`: `status`, `reload`, `dump`, `catalog`

## Crates

Nine, split so a client links neither a server nor a crypto library
(`TODO.md` #31, #66c, #67).

| crate | what it is |
|---|---|
| `rdns-core` | the wire format: codes, records, EDNS0, the message. No `tokio`, no crypto |
| `rdns-present` | presentation format — the text a zone file is written in, both directions |
| `rdns-tsig` | TSIG (RFC 8945) on its own, so a query client can sign without linking a server |
| `rdns-transport` | the socket layer both daemons run: UDP, TCP, TLS, QUIC, HTTPS, metrics |
| `rdns` | above the wire: zones, cache, resolver, DNSSEC, transfers |
| `rdnsd` | authoritative server — every transport from one process |
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
rdnsctl status               # zones, serials, records, denial, role, catalog, last contact
rdnsctl reload               # re-read every zone; exits non-zero if it failed
rdnsctl dump example.com.    # the zone as served, signatures and all
rdnsctl catalog              # what each catalog provisioned, and what it refused

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
cargo test -p rdnsr allocation -- --nocapture          # the resolver's
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
| `--also-notify <ADDR[:PORT][#KEY]>` | notify a secondary when a serial moves. Repeatable; `#KEY` signs it |
| `--tls-listen <ADDR:PORT>` | also answer DNS over TLS here (RFC 7858). Needs `--tls-cert` and `--tls-key` |
| `--quic-listen <ADDR:PORT>` | also answer DNS over QUIC here (RFC 9250). Same certificate, same 853 — DoT is TCP, this is UDP |
| `--https-listen <ADDR:PORT>`, `--https-path` | also answer DNS over HTTPS here (RFC 8484), on 443. Path defaults to `/dns-query` |
| `--tls-cert <PATH>`, `--tls-key <PATH>` | the PEM chain and key both present; re-read on every reload |
| `--response-rate <BYTES_PER_SEC>` | UDP response bytes per client, default 8192, `0` disables |
| `--query-rate <QUERIES_PER_SEC>` | per client, default 1000, `0` disables. With `--query-burst` (200) and `--query-rate-exempt`. Over the limit a query is dropped silently |
| `--secondary <ZONE@MASTER[:PORT][#KEY]>` | replicate a zone. Repeatable; requires `--zone-dir` |
| `--catalog <ZONE@MASTER[:PORT][#KEY]>` | consume a catalog zone (RFC 9432): replicate it, and serve the zones it lists from the same master. Repeatable; requires `--zone-dir` |
| `--config <FILE>`, `--check-config` | read settings from TOML, and dry-run them. Mutually exclusive with the flags above |

Nineteen of `rdnsd`'s fifty-one flags, counted from `--help` rather than
remembered — the denominator here has been stale twice, at twenty-seven and at
forty-three. `rdnsd --help` is the full list;
`docs/CLI_USAGE.md` covers them individually and `docs/spec/06-operations.md`
has every default.

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
| `--config <FILE>`, `--check-config` | read settings from TOML, and dry-run them. Mutually exclusive with the flags above. `[[rpz.feeds]]` is what only the file can say: a policy per feed, so a new one is measured in `passthru` while the rest stay enforced |
| `--rpz <FILE>` | a response policy zone, repeatable and consulted in order; `--rpz-policy` overrides what its rules say, for every feed at once. How blocking is delivered |
| `--serve-stale <SECONDS>` | answer from expired cache when the authoritative servers cannot be reached (RFC 8767). `0`, off, by default |
| `--prefetch` | re-resolve a cached name in the last tenth of its TTL, after the reply that found it |
| `--dns64 [PREFIX]` | synthesize AAAA from A for an IPv6-only client behind a NAT64 (RFC 6147). The Well-Known Prefix if given no value; `--dns64-exclude` adds to RFC 6147 §5.1.4's default |

The last four are off unless given, and each is specified in
`docs/spec/05-resolver.md` §5.4-§5.7.

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

# Resolver for an IPv6-only network, blocking what a feed says to block and
# riding out an upstream outage on what it last knew.
rdnsr --port 5354 --dns64 --rpz /var/lib/rdns/blocklist.rpz --serve-stale 86400
```

## Status

1,252 tests passing on Windows and 1,273 on Linux, measured 2026-09-20 on the
same tree, none failing. Plus 3 doc-tests marked `ignore`. `cargo test
--workspace` is the source of truth, and the numbers below are what it printed
rather than a summary kept beside it.

| suite | tests (Windows / Linux) |
|---|---|
| `rdns-core` | 188 / 190 |
| `rdns-present` | 19 |
| `rdns-tsig` | 27 |
| `rdns-transport` | 38 / 39 |
| `rdns` library | 704 / 705 |
| `rdns` allocation gate (`tests/allocations.rs`) | 1, printing its measurements — `cargo test -p rdns --test allocations -- --nocapture` shows them, and most are asserted to an exact count |
| `rdns` fuzz guard (`tests/no_input_panics.rs`) | 1, running mutated messages through the pre-authentication path |
| `rdnsd` | 193 / 209 |
| `rdnsr` | 75, two of them allocation counts for one cached answer |
| `rdnsc` | 5 / 6 |

The gap between the columns is the `#[cfg(unix)]` tests, which a Windows build
never compiles — which is why a green suite on one platform is not a green
suite (`CLAUDE.md` §1).

Open work is `TODO.md`: #58, #68, #78-#84, #87-#90, and one inventory of
deliberate RFC deviations (#21). Everything else numbered is closed, and
`docs/CLOSED_WORK.md` holds it.

Not implemented: SIG(0), multi-signer DNSSEC (RFC 8901), EDNS Client Subnet
(declined on purpose, RFC 7871 §11), DNS Cookies as anything but opaque bytes,
RSA key *generation*, automated key rollover, `$GENERATE`, any class but IN.
`docs/spec/07-rfc-conformance.md` is the full matrix.

## Licence

MIT. `LICENSE` is the text.

Dependencies: `Cargo.lock` holds 214 packages, nine of them this workspace, so
205 third-party. `cargo deny --all-features list` checks 138 of the 214; the
other 76 are the dev-dependency trees under `criterion` and `rcgen`, which only
`cargo bench` and the test suite compile. Across those 138, every licence is
permissive and none is copyleft — eight of them: Apache-2.0, MIT, ISC,
BSD-3-Clause, Unicode-3.0, Zlib, 0BSD and Unlicense. `deny.toml` holds the
allow-list, the duplicate-version exceptions, and the reason for each;
`cargo deny --all-features check` reports all four sections ok — with
`--all-features`, because that is what the CI job passes and a plain run checks
a narrower graph (#97).
