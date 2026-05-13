# rdns

Hobby project for implementing DNS client and server.

Note that all naming conventions try to follow RFC 1035 and others as much as possible.
This is why you get DName instead of DomainName or just Name. DName is closer to what
all the RFC nomenclature uses.

## Features

- Full DNSSEC validation (RSA/ECDSA, SHA-256/SHA-512 signatures)
- NSEC/NSEC3 proof-of-non-existence validation
- Multi-zone support via zone enumeration
- Signal handling (SIGHUP) for zone reload without restart
- OpenTelemetry integration for tracing and metrics
- Rate limiting and request validation
- Structured logging

## Local Development

### Quick Start

1. Ensure you have Rust 1.95.0+ installed
2. Create test zone files (`.zone` extension) in a zones directory
3. Run rdnsd on localhost without requiring root:

```bash
# UDP server on localhost:5353
cargo run --bin rdnsd -- udp --host 127.0.0.1 --port 5353 --zone-dir ./zones

# TCP server on localhost:5353
cargo run --bin rdnsd -- tcp --host 127.0.0.1 --port 5353 --zone-dir ./zones
```

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
ExecStart=/usr/local/bin/rdnsd udp --host 0.0.0.0 --port 53 --zone-dir /etc/rdns/zones
ExecReload=/bin/kill -HUP $MAINPID
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

1. Use the `systemd` service file above with `AmbientCapabilities=CAP_NET_BIND_SERVICE`
2. Or use `sudo` to run with elevated privileges:

```bash
sudo rdnsd udp --host 0.0.0.0 --port 53 --zone-dir /etc/rdns/zones
```

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

### UDP Server

```bash
rdnsd udp [OPTIONS]
```

**Options:**
- `--host <HOST>` - Listen address (default: 0.0.0.0)
- `--port <PORT>` - Listen port (default: 53)
- `--zone-file <PATH>` - Load single zone file
- `--zone-dir <DIR>` - Load all .zone files from directory

### TCP Server

```bash
rdnsd tcp [OPTIONS]
```

**Options:** Same as UDP server

### Examples

```bash
# Production setup (UDP, all interfaces, port 53, load zones from directory)
rdnsd udp --zone-dir /etc/rdns/zones

# Development setup (UDP, localhost, custom port)
rdnsd udp --host 127.0.0.1 --port 5353 --zone-dir ./zones

# Single zone file
rdnsd udp --zone-file example.com.zone

# TCP server for zone transfer testing
rdnsd tcp --host 127.0.0.1 --port 5354 --zone-dir ./zones
```

## Project Status

**Phase 7**: Complete DNSSEC validation, CLI improvements, and operational features.

- ✅ DNSSEC signature verification (RSA/ECDSA, SHA-256/SHA-512)
- ✅ DNSKEY chain validation with DS chain verification
- ✅ NSEC/NSEC3 proof-of-non-existence validation
- ✅ Multi-zone support with automatic enumeration
- ✅ Signal handling (SIGHUP) for zone reload
- ✅ CLI with configurable host/port defaults
- ✅ OpenTelemetry integration for observability
- ✅ 110+ unit tests with 100% pass rate

Test Results: 110 tests passing
- 95 library tests (rdns)
- 15 CLI integration tests (rdnsd)