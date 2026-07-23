# rdns — TODO / Next Steps

Working notes for continuing in Claude Code. Two parts: (A) finish verifying the
just-completed `RecordData` refactor, then (B) the resolver / EDNS0 gaps.

---

## A. Verify the RecordData raw-storage refactor

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
- [x] `cargo test` — 152 lib + 15 integration tests pass. One stale test
      (`dnssec::tests::test_dname_wire_format_root`) asserted the *old* buggy
      3-byte root encoding; updated to expect the correct single `[0]` octet.
- [x] `cargo clippy` — clean except one deliberately-left `if_same_then_else`
      (see "Open decisions" below). Applied all machine-applicable fixes and
      converted module `///` docs to `//!` in the new files.

**What was blocking the build (all in `rdnsd/src/main.rs`, refactor tail):**
- `DnsMessage` gained `ad`/`cd` DNSSEC-flag fields; the response builder didn't
  set them → now `ad: false, cd: msg.cd` (mirror the query's CD bit, RFC 4035).
- `Commands::Tcp`/`Udp` gained `cache_size`/`no_cache`/`dnssec_validate` CLI
  flags the match arms didn't destructure → ignored with `..` for now (unwired,
  see Open decisions).
- Removed an unused `DnsCache` import.

### Risk spots — CONFIRMED OK by the full build/test run
- [x] `bench.rs` `std::hint::black_box` — compiles.
- [x] `parse()` deref coercion / `DNameUnpacker` lifetimes — type-check, tests pass.
- [x] `zone.rs` silently skips zone lines with invalid domain labels
      (`from_parsed(&…).ok()`). Behavior change is in effect; still needs a
      product call on whether silent-skip vs. error is acceptable (Open decisions).

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

## Architecture: `rdnsr` forwarding resolver (new binary)

Decided to split the resolver out of `rdnsd` following the NSD/Unbound and
Knot/Knot-Resolver precedent (opposite trust models; avoid an accidental open
resolver; independent lifecycle). Workspace now has four members: `rdns` (lib),
`rdnsc` (client), `rdnsd` (authoritative server), **`rdnsr` (forwarding
resolver)**.

`rdnsr` (`rdnsr/src/main.rs`) is a working caching UDP forwarder:
query → `DnsCache` lookup → miss forwards via `RecursiveResolver` (on a blocking
thread) → cache-store by (name,type)+TTL → serialize via `to_bytes` → reply
(echoing the client's txn id, RA set). Binds `127.0.0.1` by default so it is not
an open resolver. Verified end-to-end: correct answers, and cache hits return in
0 ms vs. ~7 ms on a miss.

Still forwarder-only (not a true recursor) — the `RecursiveResolver` naming/depth
question from Part B #3 is unchanged, just now housed behind `rdnsr`.

## B. Resolver / EDNS0 gaps (prioritized)

Suggested order: **1 → 2 → 3 → 6** (4 and 5 now done via `rdnsr`).

### 1. EDNS0 / OPT pseudo-record (RFC 6891) — do first
No type-41 handling anywhere; UDP buffers hard-coded to 512 bytes. Blocks DNSSEC
over UDP (no DO bit), larger payloads, and extended RCODEs.
- [ ] Parse/build an `OPT` record in the additional section.
- [ ] Negotiate UDP payload size; stop hard-coding 512 (`resolver.rs`,
      `rdnsd/src/main.rs`).
- [ ] Plumb the DO bit and extended RCODE through `DnsMessage`.

### 2. TCP fallback on truncation
`resolver.rs::query_upstream` reads a single 512-byte UDP datagram and never
retries. A TC=1 response must be re-queried over TCP.
- [ ] If response has TC set, re-issue the query over TCP.
- [ ] Reuse the TCP listener plumbing that already exists in `rdnsd`.

### 3. "Recursive resolver" is actually a forwarder — decide intent
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

### 5. Finish response record serialization — **DONE** (compression still TODO)
`DnsMessage::to_bytes` now serializes answer/authority/additional records (a
straight copy of the stored wire bytes). Round-trip test added
(`test_response_roundtrip_with_answer`). This also fixed a latent `rdnsd` bug
where responses claimed N answers with an empty body.
- [ ] Add name compression on output later as an optimization (responses are
      currently uncompressed, wasting UDP space).

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
