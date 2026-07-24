# rdns — TODO / Next Steps

Working notes for continuing in Claude Code. **Part A (the `RecordData`
raw-storage refactor) is complete and archived below for context** — start from
"Current state" and Part B.

---

## Current state (last updated 2026-07-24)

**Workspace** — four members: `rdns` (library), `rdnsc` (client), `rdnsd`
(authoritative server), `rdnsr` (forwarding resolver). Branch `master`.

**Green as of the last commit:** `cargo build --workspace` clean,
`cargo test --workspace` = **193 lib + 15 integration** tests passing,
`cargo clippy --workspace --all-targets` clean **except one deliberate warning**
(`if_same_then_else` on `dnssec_validation_mode.rs::validate_response` — the
`validate_unsigned` no-op, see Open decisions #2; leave it until #6 wires the
module up).

**Next task: Part B #3 (forwarder vs. real recursion — decide intent)**, then #6.
Everything else in Part B is done.

### How to run and verify

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets

# authoritative server (zone origin is taken from the FILENAME: example.com.zone
# serves example.com — a mismatch here silently yields NXDOMAIN for everything)
cargo run -p rdnsd -- udp --host 127.0.0.1 --port 15353 --zone-file example.com.zone

# forwarding resolver — serves UDP and TCP on the same port (binds 127.0.0.1 by
# default, on purpose — not an open resolver)
cargo run -p rdnsr -- --port 15354
```

`nslookup` is unreliable against a non-53 port on Windows — it reports "No
response from server" even when the server replies correctly. Probe with a raw
`System.Net.Sockets.UdpClient` in PowerShell instead and read the bytes; that is
how every "verified live" claim in this file was checked.

For an *independent* decode check (our parser agreeing with our serializer proves
little), Node's resolver is c-ares and accepts a port in the server string:

```js
const r = new (require('dns').Resolver)();
r.setServers(['127.0.0.1:15353']);
r.resolve4('www.example.com', console.log);
```

Two Windows gotchas that have each cost an hour:
- In PowerShell 5.1 `-shl` keeps the left operand's `[byte]` type and truncates,
  so `$b[0] -shl 8` is **0**. Cast to `[int]` first or every 2-byte field you
  decode by hand will be silently wrong.
- Ephemeral ports are handed out sequentially from a rotating cursor, and both
  TCP and UDP have exclusion blocks (hundreds of ports wide, at *different*
  ranges per protocol — `netsh int ipv4 show excludedportrange tcp|udp`). So
  "bind port 0 on one protocol, then match that port on the other" can fail for
  every attempt in a row. `resolver.rs`'s test helper scans fixed ports at
  20000+ instead.

### Known gaps, in one place

- `RecursiveResolver` forwards; it does not recurse (#3).
- DNSSEC validation exists but nothing calls it; the DO bit round-trips but is
  not acted on (#6).
- `rdnsr` caches answers only, not authority/additional sections (#4).
- Zone parser: no `$INCLUDE`, no parenthesized multi-line records (a
  parenthesized SOA fails the load), TXT not split into `<character-string>`s.
- The 7 untracked `*.md` / `*.txt` planning docs in the repo root are
  deliberately uncommitted; two of them are stale (see "Docs" below).

---

## A. The RecordData raw-storage refactor — **COMPLETE (archive)**

Kept for context on why the storage layer looks the way it does. Nothing here is
outstanding except the two items under "Deliberately preserved pre-existing
behavior" and the "Docs" cleanup.

**What changed:** `RecordData` is now a 24-byte struct
`{ rtype: u16, rdata: Box<[u8]> }` holding **uncompressed wire-format bytes**
(down from the ~96-byte three-level enum). The typed view is a new flat
`ParsedRecord` enum, produced on demand via `RecordData::parse()` and consumed
when building records via `RecordData::from_parsed()`. On ingest,
`RecordData::from_wire()` decodes once (following compression pointers) then
re-encodes without compression so stored bytes are self-contained. This matches
how NSD / Knot / Unbound store rdata.

Core codec was validated with 18 standalone `rustc` unit tests (round-trips for
every type incl. NSEC3, byte-stable storage, `size_of == 24`, compression-pointer
rejection). The full crate was **not** compiled here (sandbox blocks
`static.crates.io`, so ring/tokio/opentelemetry can't download).

**Files touched:** `rdns/src/lib.rs`, `dname.rs`, `serialization.rs`, `zone.rs`,
`utils.rs`, `dnssec.rs`, `dnssec_validation_mode.rs`, `cache.rs`, `bench.rs`,
`rdnsd/src/main.rs`.

### Checklist — DONE (verified in Claude Code, 2026-07-23)
- [x] `cargo build` — green. Only breakage was in `rdnsd/src/main.rs` (see below).
- [x] `cargo test` — 152 lib + 15 integration tests passed at the time (175 + 15
      now, after the Part B work). One stale test
      (`dnssec::tests::test_dname_wire_format_root`) asserted the *old* buggy
      3-byte root encoding; updated to expect the correct single `[0]` octet.
- [x] `cargo clippy` — clean except one deliberately-left `if_same_then_else`
      (see "Open decisions" below). Applied all machine-applicable fixes and
      converted module `///` docs to `//!` in the new files.

**What was blocking the build (all in `rdnsd/src/main.rs`, refactor tail):**
- `DnsMessage` gained `ad`/`cd` DNSSEC-flag fields; the response builder didn't
  set them → now `ad: false, cd: msg.cd` (mirror the query's CD bit, RFC 4035).
- `Commands::Tcp`/`Udp` gained `cache_size`/`no_cache`/`dnssec_validate` CLI
  flags the match arms didn't destructure. Since resolved by removing them from
  `rdnsd` entirely — they moved to `rdnsr` (Open decisions #1).
- Removed an unused `DnsCache` import.

### Risk spots — CONFIRMED OK by the full build/test run
- [x] `bench.rs` `std::hint::black_box` — compiles.
- [x] `parse()` deref coercion / `DNameUnpacker` lifetimes — type-check, tests pass.
- [x] `zone.rs` silently skipped zone lines with invalid domain labels
      (`from_parsed(&…).ok()`). Resolved: it now fails fast — Open decisions #3.

### Open decisions
1. ~~CLI flags `--cache-size` / `--no-cache` / `--dnssec-validate` on `rdnsd`~~
   — **RESOLVED.** These were resolver concerns bolted onto the authoritative
   daemon. Moved to the new **`rdnsr`** forwarding-resolver binary (see
   "Architecture" below), where they actually do something. `rdnsd` is
   authoritative-only again. Note: a parse-level cache was explicitly ruled out —
   lazy-parse is cheap and the hot path never parses.
2. **`dnssec_validation_mode.rs::validate_response`: the `validate_unsigned`
   flag is a no-op** (both `if` branches return `(true, false)` — the clippy
   warning). Deliberately left until the module is wired into the server; the
   `true` = "require signing" semantics get defined then. Default `false` path
   is correct.
3. ~~`zone.rs` silent-skip of invalid zone lines~~ — **DONE.** `parse_zone_file`
   now fails fast with a `line N: …` message naming the specific field (bad IP,
   bad MX preference, unknown type, malformed `$TTL`, etc.). Tests added.

### Deliberately preserved pre-existing behavior (fix later if desired)
- [ ] Canonical DNSSEC serialization does **not** lowercase embedded names
      (not strict RFC 4034 §6.2).
- [ ] TXT stored as one blob, not split into `<character-string>`s (RFC 1035).

### Bugs already fixed in this refactor (no action, just FYI)
- `dname_to_bytes` used to append a spurious extra `0` byte for names ending in
  `.`, corrupting SOA/MX/RRSIG and the query section. Now handles trailing dot +
  root and validates label length.
- Unknown record types now preserve their rdata bytes verbatim (RFC 3597); the
  old typed enum dropped them.

### Docs
- [ ] `ARCHITECTURE_REVIEW_RecordData_Refactoring.md` and
      `REFACTORING_TRADEOFF_ANALYSIS.md` are now stale (they conclude "split
      enum"; the split gave **zero** happy-path memory benefit because a Rust
      enum is sized to its largest variant). Update or delete.

---

## Architecture: DNS over TCP (both servers)

Both daemons frame TCP messages with the RFC 1035 §4.2.2 2-byte big-endian
length prefix and keep a connection open for **multiple queries** (RFC 7766
§6.2.1) instead of answering once and hanging up. Shared shape: an accept loop
bounded by a 128-permit semaphore (an unbounded accept-and-spawn loop is a
file-descriptor exhaustion vector), a 10 s idle timeout between messages, and a
5 s timeout to finish a message whose length prefix has already arrived — a peer
mid-message has committed to those bytes, an idle peer has not. A zero-length
frame closes the connection. Neither applies the EDNS UDP payload size to a TCP
reply: the length prefix is the only limit there (RFC 6891 §6.2.2), and
truncating would strand a client that came to TCP *because* it was truncated.

Both answer a connection's queries **concurrently** (RFC 7766 §6.2.1.1). The
connection splits into read and write halves:

- the read loop parses frames and spawns a task per query;
- each task funnels its framed reply through an `mpsc` channel;
- a single writer task owns the write half, so replies can complete out of order
  (legal — clients match on transaction id) but two framed messages can never
  interleave on the wire.

Both the channel depth and a per-connection semaphore are `MAX_INFLIGHT_PER_
CONNECTION` (16), so a client that pipelines faster than it reads pushes back on
our read loop rather than growing an unbounded task queue. Dropping the reader's
channel sender at loop exit lets the writer drain replies still in flight and
then exit by itself.

**Lock discipline:** the zone-map read guard is scoped to building and
serializing the response and is never held across a socket write — otherwise a
SIGHUP zone reload (a writer) would queue behind a slow client for the life of
its connection. The UDP path had the same guard-across-`send_to` and was scoped
the same way.

Concurrency is nearly free on `rdnsd` (an in-memory zone lookup) but is the whole
point on `rdnsr`, where every cache miss costs an upstream round trip: in
lock-step, each query on a connection waits out the slowest one ahead of it.

Verified live on `rdnsd`: four sequential queries on one connection; **8 pipelined
queries** written before reading any reply, all answered with correct ids and
complete 170-record RRsets, observably out of order (B001, B003, B002, …); two
interleaved connections; a zero-length frame closing the connection; an idle
connection closed at 10 s; UDP unchanged.

Verified live on `rdnsr` (`--no-cache`, real upstreams, so all 8 queries are
misses): 8 distinct names lock-step = **172 ms**, the same 8 pipelined = **50 ms**,
replies out of order (1001, 1006, 1007, 1000, …) and all 8 carrying real answers
(rcode 0, ancount >= 1). Also re-checked after the restructure: full 170-record
RRset over TCP with a 512-byte advert, connection reuse, non-EDNS gets no OPT
back, BADVERS = RCODE 16, zero-length frame closes, 10 s idle close, UDP still
truncates with TC=1.

c-ares resolves A/SOA/NS through both daemons.

## Architecture: `rdnsr` forwarding resolver (new binary)

Decided to split the resolver out of `rdnsd` following the NSD/Unbound and
Knot/Knot-Resolver precedent (opposite trust models; avoid an accidental open
resolver; independent lifecycle). Workspace now has four members: `rdns` (lib),
`rdnsc` (client), `rdnsd` (authoritative server), **`rdnsr` (forwarding
resolver)**.

`rdnsr` (`rdnsr/src/main.rs`) is a working caching UDP forwarder:
query → EDNS sanity check (FORMERR / BADVERS, see #1) → `DnsCache` lookup → miss
forwards via `RecursiveResolver` (on a blocking thread) → cache-store by
(name,type)+TTL → `to_bytes_within(client_max)` → reply (echoing the client's txn
id, RA set, OPT mirrored only if the client used EDNS). Binds `127.0.0.1` by
default so it is not an open resolver. Verified end-to-end: correct answers, and
cache hits return in 0 ms vs. ~7 ms on a miss.

Two things `rdnsr` does *not* share with `rdnsd`: it doesn't run the
`RequestValidator`, and it has no zone storage. `--no-cache` is implemented as a
zero-capacity `DnsCache` (`put` is a no-op at 0) rather than an `Option`.
`--dnssec-validate` parses but only warns — it does nothing until #6.

**`rdnsr` serves UDP *and* TCP** on the same host:port (both loops are spawned;
whichever fails first takes the process down, so we never silently serve one
transport). TCP is not optional for a resolver: when an answer overflows the
client's advertised UDP payload we reply TC=1, and RFC 1035 §4.2.1 has the client
retry over TCP — without a listener that retry is refused and the query just
fails. This was a real, observed failure (c-ares advertises a small payload, so
it hit it on the first large RRset it asked for).

The transport reaches `handle_query` as a `Transport` enum, whose only job is to
pick the response size limit: the EDNS payload size over UDP, the 65535-byte
frame limit over TCP. Framing, timeouts, the connection cap and concurrent
pipelining all follow the shared shape described under "Architecture: DNS over
TCP" above.

Verified live against `rdnsd` as upstream: 170-record RRset over TCP arrives
complete (2764 bytes, TC=0) even when the client advertises only 512; three more
queries answered on that same connection; non-EDNS query gets no OPT back
(arcount=0); BADVERS over TCP returns full RCODE 16; a zero-length frame closes
the connection; an idle connection is closed at 10 s; UDP still truncates with
TC=1 as before. c-ares resolves A/SOA/NS through `rdnsr` — the case that
previously returned ETIMEOUT.

Still forwarder-only (not a true recursor) — the `RecursiveResolver` naming/depth
question from Part B #3 is unchanged, just now housed behind `rdnsr`.

## B. Resolver / EDNS0 gaps (prioritized)

Suggested order: **3 → 6** (0, 1, 2, 4, 5 done).

### 0. `rdnsd` NXDOMAINed records that were in its zone — **DONE**
Found while probing EDNS against `rdnsd`. The authoritative server could not
answer *anything* from a zone file. Three independent causes, all fixed:
- `find_zone_for_query` compared a wire-format (absolute) qname against a
  dot-stripped origin, so `"www.example.com."` never matched `"example.com"` and
  no zone was ever selected. Now trims both sides, and requires the match to land
  on a **label boundary** so a zone for `example.com` can't capture
  `notexample.com`. The root zone is handled explicitly.
- `make_response`'s NXDOMAIN check compared the **raw** stored record name
  against the query name instead of going through `Zone::matches_query`, which is
  what expands `@` and relative names against the origin. Now uses it, which also
  gives a correct NODATA (NOERROR, no answers) when the name exists but the type
  doesn't. Answers now echo the queried name rather than the stored `@`/relative
  form — required anyway for wildcards (RFC 1034 §4.3.3).
- `zone.rs` couldn't parse a fully-qualified owner name: the owner-vs-TTL
  lookahead treated any token ending in `.` (or containing a digit) as "not a
  name", so `www.example.com. IN A …` was read as a record type. Replaced by the
  RFC 1035 §5.1 rule — **position** decides: a line beginning with whitespace
  inherits the previous owner, anything else starts with one. This also fixes
  `www2` (digits) and `ns IN A …` (a host whose name collides with a type
  mnemonic), and makes indented continuation lines work at all: the old code
  trimmed the line *before* testing for leading whitespace, so that branch was
  dead.

`Zone::matches_query` now also compares case-insensitively (RFC 4343).
Verified live: apex, relative, FQDN, indented-continuation, uppercase, NODATA,
NXDOMAIN, and out-of-zone queries all behave correctly.

### 1. EDNS0 / OPT pseudo-record (RFC 6891) — **DONE**
`Edns` codec on `DnsMessage` (`edns()`/`set_edns()`/`udp_payload_size()`),
interpreted over the additional-section OPT record; `to_bytes_within(max)`
truncates with TC=1. Payload-size negotiation wired through `resolver.rs`
(advertises EDNS upstream + payload-sized recv buffer), `rdnsr`, and `rdnsd`
(both honor the client's advertised size and mirror OPT only when the client
used EDNS). Verified end-to-end: EDNS query → OPT echoed (arcount=1); plain
query → no OPT (arcount=0). The DO bit round-trips through the codec but is not
yet acted on — that lands with #6 (DNSSEC on the resolve path).
- [x] **EDNS options (RDATA)** — `EdnsOption { code, data }` list on `Edns`,
      encoded/decoded from OPT RDATA, stored verbatim (we interpret no option's
      contents). Named constants for NSID / CLIENT_SUBNET / COOKIE / PADDING;
      `Edns::option(code)` for lookup. A malformed option list is an error, not a
      partial read, so `DnsMessage::edns()` now returns
      `Result<Option<Edns>, _>` and both servers answer **FORMERR** for it. Use
      `has_edns()` (infallible) to decide OPT mirroring.
- [x] **12-bit extended RCODE** — `DnsMessage::rcode` is now the whole 12-bit
      value: `try_from_bytes` reassembles it from the header's low 4 bits and the
      OPT TTL's top byte, and `to_bytes` splits it back out, stamping the OPT
      TTL from the message RCODE. `Edns::ext_rcode` was **removed** — the
      extended RCODE is a property of the message, not of the OPT record, and two
      sources of truth invite drift. Serializing an RCODE > 15 without an OPT
      record is an error (RFC 6891 §6.1.3 makes it unrepresentable).
- [x] **BADVERS** (RFC 6891 §6.1.3 says MUST) — both `rdnsd` and `rdnsr` reject
      an EDNS version above `EDNS_VERSION` with RCODE 16 before doing any lookup
      or forwarding. This is the first real producer of an extended RCODE.

**Bug found and fixed while verifying this:** `validation.rs::validate_header`
rejected *any* request with a non-empty additional section, which is exactly
where a request's OPT record lives — so `rdnsd` silently dropped every EDNS
query and its EDNS support was dead on arrival. Requests may now carry
additionals (capped at `MAX_REQUEST_ADDITIONALS = 4`, room for OPT + TSIG);
answers and authority records in a request are still rejected. `rdnsr` was
unaffected (it doesn't run the validator).

### 2. TCP fallback on truncation — **DONE**
`resolver.rs::query_upstream` now checks `truncation` on the parsed UDP response
and, if set, re-issues the same query bytes over TCP via the new
`query_upstream_tcp` (`std::net::TcpStream`, matching the resolver's synchronous
style; `connect_timeout` + read/write timeouts all take the same `timeout_ms / 2`
budget as the UDP half). Framing is the RFC 1035 §4.2.2 2-byte big-endian length
prefix, written together with the message in one `write_all`.

Decisions made:
- **Retry stays on the same upstream.** TC=1 means "this answer doesn't fit in a
  datagram", not "this server is sick" — the next upstream would just return the
  same TC. If the TCP attempt errors, that error propagates and
  `resolve_internal` moves to the next upstream with a fresh UDP query.
- **A still-truncated TCP response is passed through, not an error.** TCP is the
  last resort, so TC=1 there means the upstream genuinely can't express the
  RRset; the partial answer plus the flag beats a hard failure.
- A zero-length TCP frame *is* an error (it can't hold a header).

**Bug found and fixed while doing this:** `rdnsd`'s TCP listener did **not**
implement the length prefix at all (the note here previously claimed it did). It
`read()` a raw chunk and fed the whole thing — length prefix included, for any
spec-compliant client — straight to the validator/parser, and wrote its response
back unframed. Now it `read_exact`s the 2-byte prefix, then exactly that many
bytes (a single `read` can return a short or coalesced chunk), and length-prefixes
its reply. `rdnsd tcp` was effectively unusable by any real DNS client before this.

Four unit tests in `resolver.rs` drive a fake upstream bound to the *same* port on
both UDP and TCP: fallback happens on TC=1 and the TCP answer wins; no TCP
connection is made when the UDP answer fits; a still-truncated TCP answer is
returned; a zero-length frame fails the resolve.

Verified live (zone with a 170-record A RRset, ~5.3 KB, `rdnsd udp` + `rdnsd tcp`
on 15353, `rdnsr --upstream 127.0.0.1:15353` on 15354):
- `rdnsd` UDP, client advertising 4096 → TC=1, ancount=0.
- `rdnsd` TCP → length prefix `14 C2` = 5314, body 5314 bytes, ancount=170, TC=0.
- `rdnsr` (client advertising 8192) → 5314 bytes, **ancount=170**, TC=0 — i.e. the
  forwarder's own UDP query was truncated and the TCP retry supplied the answer.

Probe gotcha for future live checks: in PowerShell 5.1 `-shl` keeps the left
operand's `[byte]` type and truncates, so `$b[0] -shl 8` is 0. Cast to `[int]`
first or every 2-byte field you decode will be silently wrong.

### 3. "Recursive resolver" is actually a forwarder — decide intent — **NEXT**
`resolver.rs::resolve_internal` never recurses; it forwards to 8.8.8.8 / 1.1.1.1
and returns the first answer.
- [ ] If a forwarder is the goal: rename it (`ForwardingResolver`) and drop the
      unused `depth`/recursion machinery.
- [ ] If true recursion is the goal (separate design pass): root hints,
      NS-delegation chasing (root → TLD → authoritative), CNAME-chain following,
      glue-record handling.

### 4. Wire cache + resolver into a request path — **DONE (in `rdnsr`)**
Done as the `rdnsr` binary rather than inside `rdnsd` (see Architecture above):
query → `DnsCache` lookup → forward → cache-store with TTL. `rdnsd` stays
authoritative-only by design.
- [ ] (Future) answer-only cache: `rdnsr` caches `answers` but not
      authority/additional sections. Fine for a forwarder; revisit if needed.

### 5. Finish response record serialization — **DONE**
`DnsMessage::to_bytes` serializes answer/authority/additional records (a straight
copy of the stored wire bytes). Round-trip test added
(`test_response_roundtrip_with_answer`). This also fixed a latent `rdnsd` bug
where responses claimed N answers with an empty body.
- [x] **Name compression on output (RFC 1035 §4.1.4)** — new `compression.rs`
      module. `NameCompressor` keeps a per-message map of lowercased name suffix
      -> offset (case-insensitive per RFC 4343) and writes the longest reachable
      suffix as a 2-byte pointer. Suffixes *within* a name are registered too, so
      a later `com.` can point into an earlier `www.example.com.`. Offsets past
      the 14-bit pointer range are written but never become targets.

      **Where compression is applied:** owner names (question + all three RR
      sections) always. Names inside RDATA only for NS / CNAME / PTR / SOA / MX —
      a receiver that doesn't know a type can't locate the names in it, which is
      why RFC 3597 §4 forbids it for newer types and RFC 4034 §3.1.7/§4.1.1
      requires RRSIG/NSEC names to stay uncompressed. SRV and DNAME are likewise
      copied verbatim.

      DNSSEC canonical serialization is a separate path (`serialization.rs`) and
      is deliberately untouched — canonical form must stay uncompressed.

      `to_bytes` was rewritten off `Cursor` onto an explicit position with bounds
      checks, because RDLEN can only be filled in after the RDATA is written
      (compression changes its length). **Side fix:** `Cursor`-based writes
      silently dropped the tail when the buffer was too small — a too-small
      buffer is now an error. Relevant to `rdnsd`'s TCP path, which serializes
      into a fixed 16 KB array.

      Measured on a 170-record A RRset: **5314 -> 2764 bytes (-48%)**, which also
      takes it back under the 4096 EDNS advertisement so it no longer truncates
      at all. SOA and NS answers verified to compress their RDATA names.

      Verified against **c-ares** (Node's resolver — an independent decoder, so
      this is not just our parser agreeing with our serializer): A (170
      addresses), SOA, NS and a plain A all decode correctly from `rdnsd` and
      `rdnsr`.

### 6. Put DNSSEC validation on the resolve path
`dnssec.rs` has validation but nothing calls it during resolution. Depends on
item 1 (DO bit) and items 3/4 (a real resolve path to validate).
- [ ] Invoke `DnssecValidator` during resolution when DO is set.

---

## Quick reference: the new RecordData API

```rust
// stored form (compact, wire-format, uncompressed names)
pub struct RecordData { pub rtype: u16, pub rdata: Box<[u8]> }

RecordData::from_wire(rtype, rdata, &unpacker)? // ingest from the wire
record.parse()?                                 // -> ParsedRecord, on demand
RecordData::from_parsed(&ParsedRecord::A(addr))? // build a record
record.rtype                                    // type code, direct field read
```

## Quick reference: name compression

```rust
// One per message being serialized; offsets are meaningless across messages.
// DnsMessage::to_bytes drives this for you — you only touch it directly if you
// write a new serializer.
let mut c = NameCompressor::new();
pos = c.write_name("www.example.com.", buf, pos)?;   // literal, or a pointer
pos = c.write_rdata(rtype, &rdata, buf, pos)?;       // compresses NS/CNAME/PTR/SOA/MX only
```

Canonical DNSSEC output must stay uncompressed — use
`serialization::serialize_resource_record_canonical`, not these.

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
