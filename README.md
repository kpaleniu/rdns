# rdns

Hobby project for implementing DNS client and server.

Note that all naming conventions try to follow RFC 1035 and others as much as possible.
This is why you get DName instead of DomainName or just Name. DName is closer to what
all the RFC nomenclature uses.

## Features

- Full DNSSEC validation (RSA/ECDSA, SHA-256/SHA-512 signatures)
- NSEC/NSEC3 proof-of-non-existence validation
- DNSSEC signing: key generation, an RRSIG per RRset, and an NSEC or NSEC3 chain,
  signed in memory as the zone loads, re-signed on a timer before the signatures
  lapse, with expiry spread across the zone so it degrades on a slope rather than
  expiring all at once
- Multi-zone support via zone enumeration, or a TOML config file with per-zone
  settings (`--config`, `--check-config`) that keeps TSIG secrets out of `argv`
- Signal handling: SIGHUP reloads zones, SIGTERM/SIGINT stop gracefully —
  in-flight zone transfers finish rather than being cut mid-stream
- Prometheus metrics on `--metrics-listen`: RED counters, an answer-latency
  histogram, per-zone serial and last-refresh gauges, and a liveness probe
- Rate limiting (`--query-rate`) and request validation
- TSIG (RFC 8945), with per-key zone scoping so one partner's key is not a key
  to every zone

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
- A, AAAA, MX, CNAME, NS, SOA records
- DNSSEC records (DNSKEY, RRSIG, DS, NSEC, NSEC3)
- Comments and standard DNS label notation

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

# Not root. rdnsd has no --user/--group of its own, so it never drops privilege
# after binding — which means whatever it starts as, it stays as, and it reads
# private signing keys and TSIG secrets as that user for the life of the process.
# systemd is what makes it unprivileged, and CAP_NET_BIND_SERVICE is what lets an
# unprivileged user have port 53 anyway.
User=rdns
Group=rdns

# --config keeps TSIG secrets out of argv, where `ps aux` and this unit file
# would otherwise both expose them. --check-config is the dry run.
ExecStartPre=/usr/local/bin/rdnsd --config /etc/rdns/rdnsd.toml --check-config
ExecStart=/usr/local/bin/rdnsd --config /etc/rdns/rdnsd.toml

# SIGHUP reloads the zones. Signatures are re-made on their own timer, so the
# cron kill -HUP that DNSSEC deployments used to need is gone.
ExecReload=/bin/kill -HUP $MAINPID

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

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rdns

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable rdns
sudo systemctl start rdns
```

### Monitoring

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
the binary directly:

```bash
sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/local/bin/rdnsd
rdnsd --config /etc/rdns/rdnsd.toml          # as an ordinary user
```

**Running the whole server as root is worth avoiding rather than documenting.**
rdnsd has no `--user`/`--group`, so it does not drop privilege after binding —
whatever it starts as, it stays as, and it reads private signing keys and TSIG
secrets as that user for the life of the process. `sudo rdnsd` used to be
suggested here; a capability on the binary or a `User=` in the unit does the same
job without it.

## Testing

Run the full test suite:

```bash
cargo test
```

Run specific test module:

```bash
cargo test --lib dnssec
cargo test --bin rdnsd
```

Run with output:

```bash
cargo test -- --nocapture
```

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
- `--tsig-key <[ALG:]NAME:SECRET>` - A TSIG key (RFC 8945). Repeatable. A signed
  request may transfer a zone from any address, and gets a signed answer
- `--also-notify <ADDR[:PORT]>` - Tell a secondary at once when a zone's serial
  moves (RFC 1996). Repeatable
- `--response-rate <BYTES_PER_SEC>` - Cap on UDP response bytes per client
  (default 8192; 0 disables). Meters what an amplification attack is made of

See `docs/CLI_USAGE.md` for the reasoning behind each.

### Examples

```bash
# Production: all interfaces, port 53, zones from a directory, one secondary.
rdnsd --zone-dir /etc/rdns/zones   --allow-transfer 192.0.2.10 --also-notify 192.0.2.10

# Development: localhost, custom port.
rdnsd --host 127.0.0.1 --port 5353 --zone-dir ./zones

# Single zone file.
rdnsd --zone-file example.com.zone

# Transfers authenticated by key rather than by address.
rdnsd --host 127.0.0.1 --port 5353 --zone-file example.com.zone   --tsig-key hmac-sha256:transfer.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=
```

## Project Status

**Phase 7**: Complete DNSSEC validation, CLI improvements, and operational features.

- ✅ DNSSEC signature verification (RSA/ECDSA, SHA-256/SHA-512)
- ✅ DNSKEY chain validation with DS chain verification
- ✅ NSEC/NSEC3 proof-of-non-existence validation
- ✅ Multi-zone support with automatic enumeration
- ✅ Signal handling: SIGHUP reload, SIGTERM/SIGINT graceful shutdown
- ✅ CLI with configurable host/port defaults
- ✅ Prometheus metrics endpoint (`--metrics-listen`)
- ✅ 110+ unit tests with 100% pass rate

Test Results: 110 tests passing
- 95 library tests (rdns)
- 15 CLI integration tests (rdnsd)