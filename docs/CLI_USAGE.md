# rdns CLI Usage Guide

Complete reference for command-line options and examples for rdnsd (DNS server).

## Table of Contents

- [Basic Commands](#basic-commands)
- [Flags and Options](#flags-and-options)
- [Zone Source](#zone-source)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Basic Commands

### UDP Server

```bash
rdnsd udp [OPTIONS]
```

Starts a UDP DNS server on the specified host and port.

### TCP Server

```bash
rdnsd tcp [OPTIONS]
```

Starts a TCP DNS server on the specified host and port. Useful for:
- Zone transfers (AXFR)
- Large DNS queries
- Testing and debugging

## Flags and Options

### `--host <HOST>`

Listen address for the DNS server.

**Default:** `0.0.0.0`

**Supported formats:**
- IPv4: `127.0.0.1`, `192.168.1.1`, `0.0.0.0`
- IPv6: `::1`, `::`
- Hostnames: `localhost`, `dns.example.com`

**Examples:**
```bash
# All interfaces (production)
rdnsd udp --host 0.0.0.0

# Localhost only (development)
rdnsd udp --host 127.0.0.1

# IPv6 localhost
rdnsd udp --host ::1

# Specific interface
rdnsd udp --host 192.168.1.100
```

### `--port <PORT>`

Listen port for the DNS server.

**Default:** `53` (standard DNS port)

**Valid range:** 1-65535

**Examples:**
```bash
# Standard DNS port (requires root or CAP_NET_BIND_SERVICE)
rdnsd udp --port 53

# Development/testing port (no root required)
rdnsd udp --port 5353

# High port number
rdnsd udp --port 8053
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
rdnsd udp --zone-file example.com.zone
rdnsd udp --zone-file /etc/rdns/zones/example.com.zone
rdnsd tcp --zone-file ./zones/test.zone
```

### `--zone-dir <DIR>`

Load all `.zone` files from a directory.

**Notes:**
- Mutually exclusive with `--zone-file`
- Recursively searches directory for `*.zone` files
- Zone origin extracted from filename
- Directory must exist and be readable
- One of `--zone-file` or `--zone-dir` is required

**Examples:**
```bash
# All zones in directory
rdnsd udp --zone-dir /etc/rdns/zones

# Development zones
rdnsd udp --zone-dir ./zones

# Current directory
rdnsd udp --zone-dir .
```

## Zone Source

Exactly one of `--zone-file` or `--zone-dir` must be specified.

### Valid Combinations

✅ **Valid:**
```bash
rdnsd udp --zone-file example.com.zone
rdnsd udp --zone-dir /etc/rdns/zones
rdnsd tcp --host 127.0.0.1 --port 5353 --zone-file test.zone
```

❌ **Invalid:**
```bash
rdnsd udp --zone-file example.com.zone --zone-dir /etc/rdns/zones
# Error: Cannot specify both --zone-file and --zone-dir

rdnsd udp --host 127.0.0.1 --port 5353
# Error: Must specify either --zone-file or --zone-dir
```

## Examples

### Development Setup

**Quick local testing without root:**

```bash
# Create test zones directory
mkdir -p zones

# Run UDP server on localhost
cargo run --bin rdnsd -- udp \
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
rdnsd udp \
  --host 0.0.0.0 \
  --port 53 \
  --zone-dir /etc/rdns/zones

# Run TCP server for zone transfers
rdnsd tcp \
  --host 0.0.0.0 \
  --port 53 \
  --zone-dir /etc/rdns/zones
```

### Multiple Servers

**DNS primary and secondary on same host:**

```bash
# Primary server (UDP + TCP on standard port)
rdnsd udp --zone-dir /etc/rdns/zones/primary &
rdnsd tcp --zone-dir /etc/rdns/zones/primary &

# Secondary server (UDP + TCP on alternate port for testing)
rdnsd udp --port 5353 --zone-dir /etc/rdns/zones/secondary &
rdnsd tcp --port 5354 --zone-dir /etc/rdns/zones/secondary &
```

### Testing with Different Protocols

**Test UDP vs TCP:**

```bash
# Terminal 1: UDP server
rdnsd udp --host 127.0.0.1 --port 5353 --zone-dir ./zones

# Terminal 2: TCP server (different port)
rdnsd tcp --host 127.0.0.1 --port 5354 --zone-dir ./zones

# Terminal 3: Query both
dig @127.0.0.1 -p 5353 example.com          # UDP
dig @127.0.0.1 -p 5354 +tcp example.com    # TCP
```

### Single Zone File

**For testing or dedicated zone serving:**

```bash
rdnsd udp \
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
   sudo rdnsd udp --zone-dir /etc/rdns/zones
   ```

2. Or use a high port for testing:
   ```bash
   rdnsd udp --port 5353 --zone-dir ./zones
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
  rdnsd udp --zone-file /full/path/to/example.com.zone
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
  rdnsd udp --zone-dir ./zones &
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
