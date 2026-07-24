# rdns — TODO / Next Steps

Working notes for continuing in Claude Code. Completed work is summarized in one
line each under "Done so far"; the reasoning behind each piece is in its commit
message, which is where to look rather than here.

---

## Current state (last updated 2026-07-24)

**Workspace** — four members: `rdns` (library), `rdnsc` (client), `rdnsd`
(authoritative server), `rdnsr` (forwarding resolver). Branch `master`.

**Green as of the last commit:** `cargo build --workspace` clean,
`cargo test --workspace` = **197 lib + 15 integration** tests passing,
`cargo clippy --workspace --all-targets` clean **except one deliberate warning**
(`if_same_then_else` on `dnssec_validation_mode.rs::validate_response` — the
`validate_unsigned` no-op; leave it until #2 below wires the module up).

**Next task: #1 (forwarder vs. real recursion — decide intent)**, then #2.

### How to run and verify

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets

# authoritative server (zone origin is taken from the FILENAME: example.com.zone
# serves example.com — a mismatch here silently yields NXDOMAIN for everything).
# Serves UDP and TCP; run one process per transport.
cargo run -p rdnsd -- udp --host 127.0.0.1 --port 15353 --zone-file example.com.zone

# forwarding resolver — serves UDP and TCP on the same port (binds 127.0.0.1 by
# default, on purpose — not an open resolver)
cargo run -p rdnsr -- --port 15354
```

`nslookup` is unreliable against a non-53 port on Windows — it reports "No
response from server" even when the server replies correctly. Probe with a raw
`System.Net.Sockets.UdpClient` in PowerShell instead and read the bytes; that is
how every "verified live" claim was checked.

For an *independent* decode check (our parser agreeing with our serializer proves
little), Node's resolver is c-ares and accepts a port in the server string:

```js
const r = new (require('dns').Resolver)();
r.setServers(['127.0.0.1:15353']);
r.resolve4('www.example.com', console.log);
```

Three gotchas that have each cost an hour:
- In PowerShell 5.1 `-shl` keeps the left operand's `[byte]` type and truncates,
  so `$b[0] -shl 8` is **0**. Cast to `[int]` first or every 2-byte field you
  decode by hand will be silently wrong.
- Windows hands out ephemeral ports sequentially from a rotating cursor, and TCP
  and UDP have exclusion blocks at *different* ranges
  (`netsh int ipv4 show excludedportrange tcp|udp`). "Bind port 0 on one
  protocol, then match that port on the other" can fail for every attempt in a
  row; `resolver.rs`'s test helper scans fixed ports at 20000+ instead.
- `Copy-Item` preserves the *source* file's timestamp, so restoring a file that
  way can look older than the build artifacts and cargo will skip recompiling —
  a test run then silently reports the previous build's results. Touch the file
  or `cargo clean -p rdns` before trusting numbers after a copy.

---

## Open work

### 1. "Recursive resolver" is actually a forwarder — decide intent — **NEXT**
`resolver.rs::resolve_internal` never recurses; it forwards to 8.8.8.8 / 1.1.1.1
and returns the first answer.
- [ ] If a forwarder is the goal: rename it (`ForwardingResolver`) and drop the
      unused `depth`/recursion machinery.
- [ ] If true recursion is the goal (separate design pass): root hints,
      NS-delegation chasing (root → TLD → authoritative), CNAME-chain following,
      glue-record handling.

### 2. Put DNSSEC validation on the resolve path
**The pieces all exist; nothing calls them.** `grep` for `DnssecValidator` or
`dnssec_validation_mode` across `rdnsd`/`rdnsr`/`rdnsc` returns nothing, and the
DO bit round-trips through the EDNS codec without being acted on. This is a
wiring job plus two policy decisions — not a from-scratch implementation.
Depends on #1 (a real resolve path to validate).

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
- `validate_nsec`, `validate_nsec3` (negative proof — but see #3, the NSEC3
  hash is not RFC 5155 §5)
- `serialization::serialize_rrset_canonical` is generic over every record type,
  so the old "only A/AAAA can be verified" limitation is gone
- `dnssec_validation_mode.rs` already composes several of these into a
  `validate_response`

Outstanding:
- [ ] Call it. In `rdnsr`, between "answer obtained from upstream" and
      "cache-store": validate when the client set DO, and set AD on the reply
      only when validation succeeded. Do not cache an answer as validated that
      was not.
- [ ] **Trust anchor: where does the root key come from?** Hardcoding the ICANN
      root KSK means a rebuild at every rollover; a file means a config path and
      a parse step. A file with the current key compiled in as fallback is the
      usual compromise.
- [ ] **Strictness policy.** On validation failure: SERVFAIL (fail closed, the
      correct default) versus serving the unsigned answer. This is the same
      decision as the `validate_unsigned` flag in
      `dnssec_validation_mode.rs::validate_response`, whose two branches
      currently both return `(true, false)` — the one deliberate clippy warning.
      The `false` path is correct today; `true` ("require signing") is
      unspecified and should be defined here.
- [ ] Decide what an unsigned *zone* means as distinct from a *failed*
      signature: unsigned is normal (most zones are), failed is an attack or a
      misconfiguration, and they must not share a code path.

### 3. NSEC3 validation ignores salt and iterations
`dnssec.rs::validate_nsec3` destructures only `hash_algorithm` and
`next_hashed_owner`, then hashes the query name with a single bare SHA-1 pass.
RFC 5155 §5 requires the *salted, iterated* construction, so any NSEC3 record
with a non-empty salt or a non-zero iteration count validates against the wrong
hash. The code comment admits this ("simplified"). `hash_algorithm` is checked
(must be 1); iterations and salt are parsed and stored but never read.
- [ ] Implement the RFC 5155 §5 iterated hash.
- [ ] Cap `iterations` when doing so. It is a `u16` off the wire, and each
      iteration is a hash of the whole name — at 65535 that is a CPU
      amplification vector. RFC 9276 says treat >0 as suspect; a few hundred is a
      generous ceiling. No cap is needed *today* only because the loop does not
      exist yet.

### 4. Zone lookup is a linear scan
`Zone::query` filters the whole record vector per query, and `matches_query`
normalizes and lowercases both names into fresh `String`s for every record it
touches. Fine at current zone sizes, quadratic-ish in the wrong direction as
zones grow.
- [ ] Index by (name, type) — a `HashMap`/`BTreeMap` built at load time — and
      avoid the per-comparison allocation.

### 5. Smaller open items
- [ ] **AXFR is not implemented at all** (no handler, no type 252). When adding
      it, gate it on an ACL that defaults to deny and log every attempt — an open
      AXFR is a whole-zone disclosure.
- [ ] **Amplification:** `rdnsd` binds `0.0.0.0` by default and the rate limiter
      is a flat 100 queries / 10 s / IP, which does not account for *response
      size*. A large-RRset query is cheap to send and expensive to answer.
      Response-size-aware limiting would close that gap.
      (Note: the resolver's outbound source port is already randomized —
      `UdpSocket::bind("0.0.0.0:0")`. Do **not** "fix" the servers to reply from
      a random port; a reply must come from the port the query was sent to.)
- [ ] `rdnsr` caches `answers` only, not authority/additional sections. Fine for
      a forwarder; revisit if it ever becomes a recursor.
- [ ] Zone parser: no `$INCLUDE`, no parenthesized multi-line records (a
      parenthesized SOA fails the load), TXT not split into `<character-string>`s.
- [ ] Canonical DNSSEC serialization does **not** lowercase embedded names (not
      strict RFC 4034 §6.2).
- [ ] TXT stored as one blob, not split into `<character-string>`s (RFC 1035).

---

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
point on `rdnsr`, where every cache miss costs an upstream round trip. Measured
on `rdnsr` with `--no-cache` against real upstreams, 8 distinct names on one
connection: **172 ms lock-step vs 50 ms pipelined**.

## Architecture: `rdnsr` forwarding resolver

Split out of `rdnsd` following the NSD/Unbound and Knot/Knot-Resolver precedent:
opposite trust models, avoids an accidental open resolver, independent lifecycle.

`rdnsr` (`rdnsr/src/main.rs`) is a caching forwarder:
query → EDNS sanity check (FORMERR / BADVERS) → `DnsCache` lookup → miss forwards
via `RecursiveResolver` (on a blocking thread) → cache-store by (name,type)+TTL →
reply (echoing the client's txn id, RA set, OPT mirrored only if the client used
EDNS). Binds `127.0.0.1` by default so it is not an open resolver. Cache hits
return in 0 ms vs. ~7 ms on a miss.

It serves UDP *and* TCP on the same host:port — both loops are spawned and
whichever fails first takes the process down, so we never silently serve one
transport. TCP is not optional for a resolver: when an answer overflows the
client's advertised UDP payload we reply TC=1, and RFC 1035 §4.2.1 has the client
retry over TCP. The transport reaches `handle_query` as a `Transport` enum whose
only job is picking the response size limit.

Two things `rdnsr` does *not* share with `rdnsd`: it doesn't run the
`RequestValidator`, and it has no zone storage. `--no-cache` is a zero-capacity
`DnsCache` (`put` is a no-op at 0) rather than an `Option`. `--dnssec-validate`
parses but only warns — it does nothing until open item #2.

---

## Done so far

Newest first. Each links to a commit message with the reasoning, the RFC
citations, and what was verified.

- **Consolidated the wire-writing primitives into `dname`** — one bounds-checked
  write, one label encoder, one statement of the pointer constants, instead of a
  copy on each side of the dname/compression split.
- **Fixed a parser panic on truncated names** — `Label::try_from_bytes` indexed
  unchecked, so a hostile packet panicked the task rather than erroring.
- **Concurrent multi-query TCP in both daemons**, plus `rdnsr`'s TCP listener
  (it had none, so the TC=1 → TCP retry every client makes was refused) and the
  RFC 1035 §4.2.2 framing `rdnsd`'s TCP listener never implemented.
- **Name compression on output (RFC 1035 §4.1.4)** — 170-record A RRset went
  5314 → 2764 bytes (−48%). Applied to owner names always, to RDATA names only
  for NS/CNAME/PTR/SOA/MX (RFC 3597 §4 forbids it for newer types); canonical
  DNSSEC output stays uncompressed. Verified against c-ares.
- **TCP fallback on truncation** in `resolver.rs` — a TC=1 UDP answer is
  re-issued over TCP on the same upstream.
- **EDNS0 / OPT (RFC 6891)** — codec, options, the 12-bit extended RCODE,
  BADVERS, payload-size negotiation. Fixed `validate_header` rejecting every
  request with an additional section, which had made `rdnsd`'s EDNS support dead
  on arrival.
- **`DnsMessage::to_bytes` serializes records at all** — responses used to claim
  N answers with an empty body.
- **`rdnsd` answered NXDOMAIN for its own zone** — three independent causes in
  zone matching and zone-file parsing.
- **The `RecordData` raw-storage refactor** — `RecordData` is a 24-byte
  `{ rtype: u16, rdata: Box<[u8]> }` holding uncompressed wire bytes, down from a
  ~96-byte three-level enum; the typed view is a flat `ParsedRecord` produced on
  demand. This is how NSD/Knot/Unbound store rdata. An earlier plan to *split*
  the enum was abandoned: a Rust enum is sized to its largest variant, so the
  split gave zero happy-path benefit.

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
