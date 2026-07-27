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
- Recursively searches directory for `*.zone` files
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

### `--tsig-key <[ALG:]NAME:SECRET>`

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

```bash
# Transfers to whoever holds the key, from anywhere.
rdnsd --zone-file example.com.zone \
  --tsig-key hmac-sha256:transfer.key:MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=

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
