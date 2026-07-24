# rdns — TODO / Next Steps

Working notes for picking this up cold. "Open work" is what is left; the
"Architecture" sections describe what exists and why it is shaped that way.
Completed work is one line each under "Done so far" — the reasoning, RFC
citations and verification for each piece are in its commit message, which is
where to look rather than here.

---

## Current state (last updated 2026-07-24)

**Workspace** — four members, all on branch `master`:

| crate   | what it is                                                        |
|---------|-------------------------------------------------------------------|
| `rdns`  | the library: wire codec, zones, cache, resolver, DNSSEC           |
| `rdnsc` | command-line query client                                         |
| `rdnsd` | authoritative server — serves zone files, one process per transport |
| `rdnsr` | recursive resolver with a caching layer; forwards on `--upstream` |

**Green as of the last commit:** `cargo build --workspace` clean,
`cargo test --workspace` = **210 lib + 15 integration** tests passing,
`cargo clippy --workspace --all-targets` clean **except one deliberate warning**
(`if_same_then_else` on `dnssec_validation_mode.rs::validate_response` — the
`validate_unsigned` no-op; leave it until open item #2 defines the semantics).

**Next task: #1 (recursor follow-ups — async conversion first)**, then #2.

### How to run

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets

# Authoritative server. The zone origin comes from the FILENAME:
# example.com.zone serves example.com — a mismatch silently yields NXDOMAIN for
# everything. Serves UDP and TCP; run one process per transport.
cargo run -p rdnsd -- udp --host 127.0.0.1 --port 15353 --zone-file example.com.zone
cargo run -p rdnsd -- tcp --host 127.0.0.1 --port 15353 --zone-file example.com.zone

# Resolver, recursing from the root hints. Serves UDP and TCP on one port, and
# binds 127.0.0.1 by default on purpose — not an open resolver.
cargo run -p rdnsr -- --port 15354

# Same resolver, forwarding instead of recursing.
cargo run -p rdnsr -- --port 15354 --upstream 127.0.0.1:15353
```

### Verifying, and one trap that invalidates it

**Check first whether the network hijacks port 53.** Send any DNS query to
`192.0.2.1` — TEST-NET-1, reserved for documentation, which cannot host a
server. If something answers, every outbound port-53 query on this machine is
being intercepted and answered by a middlebox:

```sh
python -c "import socket;s=socket.socket(2,2);s.settimeout(3);s.sendto(bytes.fromhex('424201000001000000000000') + b'\x07example\x03com\x00\x00\x01\x00\x01',('192.0.2.1',53));print('INTERCEPTED:',len(s.recv(512)),'bytes')"
```

That is the case on the machine this was developed on, and it has two
consequences worth knowing before trusting any measurement in this repo:

- **Recursion cannot be verified here.** Iterative (RD=0) queries to the real
  root addresses get SERVFAIL from the interceptor, so `rdnsr`'s default mode
  fails while forwarding works — the interceptor answers RD=1 happily.
- **`--upstream 8.8.8.8` means "whatever answers port 53"**, not Google. Every
  figure recorded here that involved a public resolver was really measured
  against the interceptor.

For local verification, `nslookup` is unreliable against a non-53 port on
Windows — it reports "No response from server" even when the server replied.
Probe with a raw `System.Net.Sockets.UdpClient` in PowerShell and read the
bytes; that is how the "verified live" claims here were checked.

For an *independent* decode check — our parser agreeing with our serializer
proves little — Node's resolver is c-ares and takes a port in the server string:

```js
const r = new (require('dns').Resolver)();
r.setServers(['127.0.0.1:15353']);
r.resolve4('www.example.com', console.log);
```

Four environment traps that have each cost an hour:

- **PowerShell 5.1 `-shl` keeps the left operand's `[byte]` type and truncates**,
  so `$b[0] -shl 8` is **0**. Cast to `[int]` first, or every 2-byte field you
  decode by hand is silently wrong.
- **Never round-trip a source file through `Get-Content`/`Set-Content` in PS
  5.1.** It reads UTF-8 as cp1252 and writes it back as UTF-8, double-encoding
  every non-ASCII character, and adds a BOM. Use the editor, not the shell.
- **`Copy-Item` preserves the source file's timestamp**, so a restored file can
  look older than the build artifacts; cargo then skips recompiling and the test
  run reports the *previous* build's results. Touch the file or
  `cargo clean -p rdns` before trusting numbers after a copy.
- **Windows hands out ephemeral ports sequentially** from a rotating cursor, and
  TCP and UDP have exclusion blocks at *different* ranges
  (`netsh int ipv4 show excludedportrange tcp|udp`). "Bind port 0 on one
  protocol, then match that port on the other" can fail for every attempt in a
  row; `resolver.rs`'s test helpers scan fixed ports at 20000+ instead.

---

## Open work

### 1. Recursor follow-ups
The recursor works and is covered by 21 tests in `resolver.rs` (see
"Architecture: the resolver"). What is left, in priority order:

- [ ] **Convert the resolver to async.** It is synchronous `std::net` and `rdnsr`
      drives it through `spawn_blocking`, so a cold resolution holds a blocking
      thread for the sum of its round trips. Less pressing since the delegation
      cache landed — warm resolutions are now one round trip — but it is the
      right shape for a resolver.
- [ ] **QNAME minimization (RFC 9156)** — send only the label being delegated
      rather than the full name to every server up the chain. A privacy fix: the
      root currently learns every name we resolve.
- [ ] Aggressive NSEC caching (RFC 8198), 0x20 randomization, and RTT-based
      server selection instead of always trying servers in order.
- [ ] IPv6 root hints and AAAA glue. AAAA glue is parsed and used already, but
      the built-in hint list is v4-only.
- [ ] A `--root-hints` flag. The list is overridable in `ResolverConfig` but not
      from the CLI, and the built-in addresses do drift (b.root-servers.net moved
      in 2023).

### 2. Put DNSSEC validation on the resolve path
**The pieces all exist; nothing calls them.** `grep` for `DnssecValidator` or
`dnssec_validation_mode` across `rdnsd`/`rdnsr`/`rdnsc` returns nothing, and the
DO bit round-trips through the EDNS codec without being acted on. This is a
wiring job plus two policy decisions, not a from-scratch implementation.

The chain this has to walk (RFC 4034 / 6605):

```
root DNSKEY (trust anchor)
  → verify RRSIG over the zone's DNSKEY RRset with it
  → DS in the parent == hash of the child DNSKEY
  → verify RRSIG over the answer RRset with the child DNSKEY
  → answer is validated (set AD)
```

Already in `dnssec.rs`, with tests:

- `validate_signature`, `calculate_key_tag`, `extract_dnssec_records`
- `validate_ds_chain` (child DNSKEY hashes to the parent DS)
- `validate_dnskey_chain` (the walk above; 4 tests incl. bad signature, DS
  mismatch, expired)
- `validate_wildcard` (RFC 4034 §3.1.3 — label count vs signer name)
- `validate_nsec`, `validate_nsec3` (negative proof — but see #3: the NSEC3 hash
  is not RFC 5155 §5, so negative proof cannot be trusted until that is fixed)
- `serialization::serialize_rrset_canonical` is generic over every record type,
  so the old "only A/AAAA can be verified" limitation is gone
- `dnssec_validation_mode.rs` already composes several of these into a
  `validate_response`

Outstanding:

- [ ] Call it. In `rdnsr`, between "answer obtained" and "cache-store": validate
      when the client set DO, and set AD on the reply only when validation
      succeeded. Never cache an answer as validated that was not.
- [ ] **Trust anchor: where does the root key come from?** Hardcoding the ICANN
      root KSK means a rebuild at every rollover; a file means a config path and
      a parse step. A file with the current key compiled in as fallback is the
      usual compromise.
- [ ] **Strictness policy.** On validation failure: SERVFAIL (fail closed, the
      correct default) versus serving the unsigned answer. Same decision as the
      `validate_unsigned` flag in `dnssec_validation_mode.rs::validate_response`,
      whose two branches both return `(true, false)` today — that is the one
      deliberate clippy warning. The `false` path is correct; `true` ("require
      signing") is unspecified and should be defined here.
- [ ] Distinguish an unsigned *zone* from a *failed* signature. Unsigned is
      normal — most zones are — while failed is an attack or a misconfiguration.
      They must not share a code path.

### 3. NSEC3 validation ignores salt and iterations
`dnssec.rs::validate_nsec3` destructures only `hash_algorithm` and
`next_hashed_owner`, then hashes the query name with a single bare SHA-1 pass.
RFC 5155 §5 requires the *salted, iterated* construction, so any NSEC3 record
with a non-empty salt or a non-zero iteration count validates against the wrong
hash. The code comment admits this ("simplified"). `hash_algorithm` is checked
(must be 1); iterations and salt are parsed and stored but never read.

- [ ] Implement the RFC 5155 §5 iterated hash.
- [ ] Cap `iterations` when doing so. It is a `u16` off the wire and each
      iteration hashes the whole name, so 65535 is a CPU amplification vector.
      RFC 9276 says treat anything above 0 as suspect; a few hundred is a
      generous ceiling. No cap is needed *today* only because the loop does not
      exist yet.

### 4. Zone lookup is a linear scan
`Zone::query` filters the whole record vector per query, and `matches_query`
normalizes and lowercases both names into fresh `String`s for every record it
touches. Fine at current zone sizes; the wrong shape as zones grow.

- [ ] Index by (name, type) — a `HashMap`/`BTreeMap` built at load time — and
      drop the per-comparison allocation.

### 5. Smaller open items
- [ ] **AXFR is not implemented at all** (no handler, no type 252). When adding
      it, gate it on an ACL that defaults to deny and log every attempt — an open
      AXFR is a whole-zone disclosure.
- [ ] **Amplification:** `rdnsd` binds `0.0.0.0` by default and the rate limiter
      is a flat 100 queries / 10 s / IP with no regard for *response size*. A
      large-RRset query is cheap to send and expensive to answer.
      (Note: the resolver's outbound source port is already randomized via
      `UdpSocket::bind("0.0.0.0:0")`. Do **not** "fix" the servers to reply from
      a random port — a reply must come from the port the query was sent to.)
- [ ] `rdnsr` caches answer sections only, not authority/additional. Now that it
      recurses, caching negative answers (RFC 2308) matters more than it did.
- [ ] Zone parser: no `$INCLUDE`, and no parenthesized multi-line records — a
      parenthesized SOA fails the load.
- [ ] TXT is stored as one blob, not split into `<character-string>`s (RFC 1035).
- [ ] Canonical DNSSEC serialization does not lowercase embedded names (not
      strict RFC 4034 §6.2).

---

## Architecture: the resolver

One `Resolver` type with `ResolverMode::{Recurse, Forward}`, chosen by config —
not two programs. That is how BIND, Unbound, Knot Resolver and PowerDNS Recursor
all model it, and for the same reasons: the client-facing half is identical, only
the means of obtaining an answer differs, and mixed deployments (forward one
zone, recurse the rest) need both in one process. `rdnsr` recurses by default;
any `--upstream` selects forwarding.

**Recursion** walks root hints → TLD → authoritative, following referrals. Three
controls are load-bearing:

- **Bailiwick on referrals.** A referral must be below the zone we asked and at
  or above the name being chased, or `com.` could hand us the servers for
  somebody else's zone.
- **Bailiwick on glue**, judged against the *responding server's own* zone rather
  than the zone being delegated to. This distinction is the whole ballgame at the
  root: the referral to `com.` carries glue for `a.gtld-servers.net.`, which is
  not under `com.` at all, and rejecting it breaks bootstrapping outright —
  resolving `gtld-servers.net.` needs `net.`, whose glue is also
  `gtld-servers.net.`. Against the root's own zone it is properly in bailiwick.
  A `com.` server gets no such latitude.
- **A total query budget**, not merely a depth limit. This is the NXNSAttack
  (2020) defence: a hostile zone can name dozens of glueless nameservers, each
  costing a full resolution, so bounding the total is what stops one client query
  from becoming hundreds of upstream ones.

Also: answers are filtered to the chain actually asked about (the name in hand
plus CNAME targets already accepted), because `rdnsr` caches what comes back and
records volunteered for unrelated names are a cache-poisoning attempt. A response
with no answer, no AA and no usable referral is an error, not a pass-through — an
empty NOERROR reads as a definitive "no such record", which a lame delegation is
not.

**The delegation cache** (`DelegationCache`) keeps the servers learned per zone,
keyed by zone name with the referral's shortest TTL, capped at a day. A
resolution starts at the deepest cached ancestor of the name rather than at the
root: knowing `example.com.` beats knowing `com.` because it skips a round trip.
A cached delegation that fails is dropped and the walk restarts from the root, so
stale bookkeeping degrades to slow rather than broken. `delegation_cache_size`
(10k default, 0 disables). Verified: three queries into one zone consult the root
exactly once.

**Forwarding** sends RD=1 to each configured upstream in turn and returns the
first answer. Recursion sends RD=0 — an authoritative server has no business
recursing for us, and asking it to is how open resolvers get abused.

Tests (21 in `resolver.rs`) stand up a fake root/TLD/authoritative hierarchy
in-process. They share one port across distinct loopback addresses, because glue
carries an address and no port — which is also why `server_port` exists in the
config.

## Architecture: DNS over TCP (both daemons)

Both daemons frame TCP messages with the RFC 1035 §4.2.2 2-byte big-endian
length prefix and keep a connection open for **multiple queries** (RFC 7766
§6.2.1). Shared shape: an accept loop bounded by a 128-permit semaphore (an
unbounded accept-and-spawn loop is a file-descriptor exhaustion vector), a 10 s
idle timeout between messages, and a 5 s timeout to finish a message whose length
prefix has already arrived — a peer mid-message has committed to those bytes, an
idle peer has not. A zero-length frame closes the connection. Neither applies the
EDNS UDP payload size to a TCP reply: the length prefix is the only limit there
(RFC 6891 §6.2.2), and truncating would strand a client that came to TCP
*because* it was truncated.

Both answer a connection's queries **concurrently** (RFC 7766 §6.2.1.1). The
connection splits into read and write halves:

- the read loop parses frames and spawns a task per query;
- each task funnels its framed reply through an `mpsc` channel;
- a single writer task owns the write half, so replies can complete out of order
  (legal — clients match on transaction id) but two framed messages can never
  interleave on the wire.

Both the channel depth and a per-connection semaphore are
`MAX_INFLIGHT_PER_CONNECTION` (16), so a client that pipelines faster than it
reads pushes back on the read loop rather than growing an unbounded task queue.
Dropping the reader's channel sender at loop exit lets the writer drain replies
still in flight and then exit by itself.

**Lock discipline:** the zone-map read guard is scoped to building and
serializing the response and is never held across a socket write — otherwise a
SIGHUP zone reload (a writer) would queue behind a slow client for the life of
its connection.

Concurrency is nearly free on `rdnsd` (an in-memory zone lookup) but is the whole
point on `rdnsr`, where a cache miss costs an upstream round trip. Measured with
`--no-cache`, 8 distinct names on one connection: **172 ms lock-step vs 50 ms
pipelined**.

## Architecture: why `rdnsr` is separate from `rdnsd`

Split following the NSD/Unbound and Knot/Knot-Resolver precedent: opposite trust
models (serving the public versus serving your clients), different data (zones
versus a cache), independent lifecycle, and no risk of an accidental open
resolver. Forwarding versus recursion divides none of those, which is why *that*
is a mode rather than a fifth crate.

`rdnsr` (`rdnsr/src/main.rs`): query → EDNS sanity check (FORMERR / BADVERS) →
`DnsCache` lookup → miss resolves via `Resolver` on a blocking thread →
cache-store by (name,type)+TTL → reply, echoing the client's txn id with RA set
and OPT mirrored only if the client used EDNS. Cache hits return in 0 ms against
~7 ms for a miss.

It serves UDP *and* TCP on one host:port — both loops are spawned and whichever
fails first takes the process down, so it never silently serves one transport.
TCP is not optional for a resolver: when an answer overflows the client's
advertised UDP payload we reply TC=1, and RFC 1035 §4.2.1 has the client retry
over TCP. The transport reaches `handle_query` as a `Transport` enum whose only
job is picking the response size limit.

Two things `rdnsr` does *not* share with `rdnsd`: it doesn't run the
`RequestValidator`, and it has no zone storage. `--no-cache` is a zero-capacity
`DnsCache` (`put` is a no-op at 0) rather than an `Option`. `--dnssec-validate`
parses but only warns — it does nothing until open item #2.

---

## Done so far

Newest first. The reasoning, RFC citations and verification for each are in the
commit message.

- **Delegation cache** — resolution starts at the deepest known zone instead of
  the root every time; stale entries fall back to the root rather than failing.
- **Real recursion, with forwarding as a mode** — root hints, referral walking,
  both bailiwick rules, glueless delegations, CNAME chasing, query budget.
  `RecursiveResolver` (which only ever forwarded) became `Resolver`.
- **`rdnsr` logs why a resolution failed** instead of turning everything into an
  undiagnosable SERVFAIL.
- **Consolidated the wire-writing primitives into `dname`** — one bounds-checked
  write, one label encoder, one statement of the pointer constants, instead of a
  copy on each side of the dname/compression split.
- **Fixed a parser panic on truncated names** — `Label::try_from_bytes` indexed
  unchecked, so a hostile packet panicked the task rather than erroring.
- **Concurrent multi-query TCP in both daemons**, plus `rdnsr`'s TCP listener (it
  had none, so the TC=1 → TCP retry every client makes was refused) and the
  RFC 1035 §4.2.2 framing `rdnsd`'s TCP listener never implemented.
- **Name compression on output (RFC 1035 §4.1.4)** — 170-record A RRset went
  5314 → 2764 bytes (−48%). Owner names always; RDATA names only for
  NS/CNAME/PTR/SOA/MX (RFC 3597 §4 forbids it for newer types); canonical DNSSEC
  output stays uncompressed. Verified against c-ares.
- **TCP fallback on truncation** — a TC=1 UDP answer is re-issued over TCP on the
  same upstream.
- **EDNS0 / OPT (RFC 6891)** — codec, options, the 12-bit extended RCODE,
  BADVERS, payload-size negotiation. Fixed `validate_header` rejecting every
  request with an additional section, which had made `rdnsd`'s EDNS support dead
  on arrival.
- **`DnsMessage::to_bytes` serializes records at all** — responses used to claim
  N answers with an empty body.
- **`rdnsd` answered NXDOMAIN for its own zone** — three independent causes in
  zone matching and zone-file parsing.
- **The `RecordData` raw-storage refactor** — a 24-byte
  `{ rtype: u16, rdata: Box<[u8]> }` holding uncompressed wire bytes, down from a
  ~96-byte three-level enum; the typed view is a flat `ParsedRecord` produced on
  demand, as NSD/Knot/Unbound do it. An earlier plan to *split* the enum was
  abandoned: a Rust enum is sized to its largest variant, so it gave zero
  happy-path benefit.

---

## Quick reference: the RecordData API

```rust
// stored form (compact, wire-format, uncompressed names)
pub struct RecordData { pub rtype: u16, pub rdata: Box<[u8]> }

RecordData::from_wire(rtype, rdata, &unpacker)? // ingest from the wire
record.parse()?                                 // -> ParsedRecord, on demand
RecordData::from_parsed(&ParsedRecord::A(addr))? // build a record
record.rtype                                    // type code, direct field read
```

## Quick reference: names on the wire

`dname` owns the primitives — the bounds-checked write, the label encoder, and
the pointer constants. `compression` holds only the per-message offset table and
the policy for which RR types may have compressed names in their RDATA.

```rust
dname_to_bytes("www.example.com.")?     // full, uncompressed — RDATA and DNSSEC

// One compressor per message being serialized; offsets are meaningless across
// messages. DnsMessage::to_bytes drives this for you — you only touch it
// directly if you write a new serializer.
let mut c = NameCompressor::new();
pos = c.write_name("www.example.com.", buf, pos)?;   // literal, or a pointer
pos = c.write_rdata(rtype, &rdata, buf, pos)?;       // NS/CNAME/PTR/SOA/MX only
```

Canonical DNSSEC output must stay uncompressed — use
`serialization::serialize_resource_record_canonical`, not the compressor.

## Quick reference: the EDNS0 API

```rust
// OPT is stored as an ordinary ResourceRecord in `additionals`; `Edns` is an
// interpretation layer over it, NOT a field on DnsMessage.
pub struct Edns { udp_payload_size: u16, version: u8, do_bit: bool,
                  options: Vec<EdnsOption> }
pub struct EdnsOption { code: u16, data: Vec<u8> }

msg.edns()?                       // Option<Edns>; Err = malformed options -> FORMERR
msg.has_edns()                    // infallible; use this to decide OPT mirroring
msg.udp_payload_size()            // OPT CLASS, floored at 512; 512 if no OPT
msg.set_edns(Edns::with_payload_size(4096))?
edns.option(EDNS_OPTION_COOKIE)   // Option<&[u8]>
msg.to_bytes_within(max)?         // truncates + sets TC=1, keeps question + OPT

// msg.rcode holds the FULL 12-bit RCODE. to_bytes splits it across the header's
// low 4 bits and the OPT TTL's top byte; try_from_bytes reassembles it. An RCODE
// above 15 without an OPT record in `additionals` is a to_bytes error.
```
