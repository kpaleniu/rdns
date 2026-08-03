# Architectural review — 2026-08-03

Read at commit `6882b1e`, clean tree, `cargo clippy --workspace --all-targets`
clean, `cargo test --workspace` **757 passed / 0 failed / 4 ignored** on Windows.

The findings below are new. Where something looked like a finding and turns out
to be already recorded in `TODO.md` — `listener_failure`'s deliberate
duplication (§16c), the `Result<_, String>` helpers in `zone.rs`,
`parse_root_hints` returning a `Vec`, the unaudited `.lock().unwrap()` count —
it is not repeated here. §7.4 of `docs/spec/07-rfc-conformance.md` carries the
protocol-level gaps; this file carries the structural ones.

**Suggested `TODO.md` numbering: #17 onwards.** The three sections below are in
descending order of what they would cost if left.

---

## Status, 2026-08-03 (revised at `e2ebaef`)

Filed as `TODO.md` #17, #18 and #19, and **all of it is closed except B2**,
which was never filed at all — see the note under it. The findings are left as
they were written rather than rewritten in the past tense: what a defect *was*,
and the reasoning that found it, is the half worth keeping (`CLAUDE.md` §11).

| finding | outcome |
|---|---|
| **A1** TCP length prefix | fixed, `c9cc5c9` — `TODO.md` #17 |
| **A2** two live `str::to_lowercase` | fixed, `85c864c` — #19a |
| **A3** `zone_signer` shadows `is_at_or_under` | fixed, `85c864c` — #19b |
| **A4** broken string literal | fixed, `85c864c` — #19h |
| **B1** the operational shell | fixed, `b523861` — #18 |
| **B2** `main.rs` is eleven subsystems | fixed, `0748111`+`e51659b`+`e756a6a` — #20. Two corrections to the plan on the way |
| **B3** six copies of `fn absolute` | fixed, `85c864c` — #19c |
| **B4** three metrics nothing increments | fixed, `b523861` — #19d, by moving them to `rdnsr` |
| **B5** `RequestValidator` duplicates the parser | fixed, `85c864c` — #19e, and renamed `AdmissionCheck` |
| **B6** two `serve_connection`s | **declined**, #19f, with the reason recorded |
| **B7** `CLI_USAGE.md` covers half the flags | fixed, `e2ebaef` — #19g |
| **C** the eight small ones | seven fixed in `85c864c`; `rand_id` left, as D-3 |

**One finding of this review turned up a defect in the review itself**, which is
worth stating because it is the same shape as the things it was looking for. B5
listed four ways the admission check's name walk disagreed with `dname.rs`.
Re-pointing its test at the parser found a fifth that neither the review nor the
test had noticed: the packet in `test_oversized_label` carries `0x41`, described
in its own comment as "Label length: 65", and that octet is not a length at
all — the top two bits are a *type*, and `01` is RFC 2673's binary label. A label
over 63 octets cannot be spelled on the wire. The deleted check was rejecting an
impossible case for the wrong reason, and the test agreed with it because both
were written from the same misreading.

---

## Verdict first

This is an unusually well-built codebase for its size, and the reason is legible:
the hard parts were reviewed adversarially and the reasoning was kept in prose
next to the code. DNSSEC, TSIG, the denial proofs, serial arithmetic, the type
work of `TODO.md` #13 — all of that reads as finished. `CLAUDE.md` §17's claim
holds up under inspection: the invariants that were moved into types have not
recurred, and every one that was fixed at a call site has left at least one
straggler behind.

Three of the four findings in **A** below are stragglers of exactly that kind:
consolidations that caught most copies and missed one. That is not a criticism of
the consolidations, it is evidence for the rule.

The single structural thing worth changing is **B1**: the operational shell was
built for `rdnsd`, put in the shared library so both daemons could use it, and
then wired into one daemon. The resolver — the more amplifying of the two — has
none of it.

---

## A. Correctness and safety

### A1. The TCP length prefix is an unchecked `as u16`, in five places

| site | what it frames |
|---|---|
| `rdnsd/src/main.rs:1833` (`frame`) | every TCP reply, every transfer envelope |
| `rdnsr/src/main.rs:776` | every TCP reply |
| `rdns/src/resolver.rs:1432` | an outgoing upstream TCP query |
| `rdns/src/xfr.rs:693` | an outgoing transfer request |
| `rdnsc/src/main.rs:160` | the client's TCP retry |

Every one is `(bytes.len() as u16).to_be_bytes()` with no check. `CLAUDE.md` §2
is about `as` on values coming *off* the wire; this is the same cast going the
other way, and `DnsMessage::to_bytes` — twenty lines of which do exactly this
correctly, with `try_into().map_err(|_| WireError::TooLong { .. })` for RDLENGTH,
ARCOUNT and OPT RDLENGTH — is the sibling that shows what the shape should be.

**The reachable path, provoked rather than argued.** `to_bytes_within(u16::MAX as
usize)` yields at most 65 535 octets — the scratch buffer is exactly that size,
so anything larger comes back as a 33-byte TC=1 reply instead. `tsig::append_tsig`
(`tsig.rs:844`) then appends a TSIG record to the *finished* bytes with **no
total-length check**; it checks only that ARCOUNT does not overflow.

A throwaway integration test (`rdns/tests/`, run and deleted) swept a TXT RRset's
size one octet at a time through the boundary, signing each result with a real
`TsigSession`:

```
pad= 15 serialized=65452 signed=65534 prefix=65534 ok
pad= 16 serialized=65453 signed=65535 prefix=65535 ok
WRAPPED at pad=17: serialized 65454 + TSIG 82 = 65536 bytes,
                   but the frame prefix says 0
```

**The failure is worse than a wrong length.** 65536 mod 65536 is **0**, and a
zero-length prefix is exactly what both daemons' read loops treat as a broken
peer — `rdnsd/src/main.rs:1390` logs "zero-length TCP message" and closes the
connection, `rdnsr/src/main.rs:751` breaks. So the client's connection is dropped
with no answer at all, and nothing on either side reports why.

The window is **82 octets wide** — one hmac-sha256 TSIG record with a ten-octet
key name — out of the 65 536 possible sizes: serialized lengths 65 454..=65 535
all wrap. A longer key name widens it. Larger overshoots produce a small non-zero
prefix instead, which desynchronises the stream rather than closing it.

AXFR is **not** the exposure (envelopes target 16 KiB, `AXFR_TARGET_MESSAGE_SIZE`);
a TSIG-signed ordinary answer over TCP is. That needs a ~64 KB RRset at one name,
which is unusual but entirely constructible in a zone file.

**Fix**, in two parts:

1. A length check in `append_tsig` — it is the only thing that can push a message
   past the limit it was serialized to, and it already returns
   `ConfigResult<Vec<u8>>`, so there is a channel for the error.
2. One `rdns::` helper for the framing. This returns
   `Result<Vec<u8>, WireError>` and no error type crosses the library boundary,
   so §16c's argument against moving `listener_failure` does not apply:

   ```rust
   /// A message with its RFC 1035 §4.2.2 length prefix, in one buffer.
   pub fn framed(bytes: &[u8]) -> Result<Vec<u8>, WireError>
   ```

**The regression test writes itself** from the sweep above, and it fails against
today's code — I watched it.

### A2. Two live `str::to_lowercase` calls on wire-supplied names

`rdnsd/src/main.rs:1915` — the NOTIFY zone-name lookup key — and the matching
insert at `:3064`. `CLAUDE.md` §8 and RFC 4343: the fold is ASCII-only, and
`to_lowercase` folds U+212A KELVIN SIGN onto `k`.

The two agree with each other, so the `Secondaries` table is self-consistent and
the master-address check still gates the refresh — the impact is bounded to "a
NOTIFY naming a Kelvin-sign variant of a replicated zone folds onto that zone".
It is on the list because it is precisely the rule this codebase wrote down, on a
name a stranger chooses, and because `utils::absolute_lowered` is one call away
and returns a `Cow` that borrows in the common case.

Every other `to_lowercase()` in the tree is on `base32hex_encode` output (ASCII
by construction — still worth `make_ascii_lowercase`) or in tests.

### A3. `zone_signer` shadows `utils::is_at_or_under` with a worse copy

`zone_signer.rs:652`:

```rust
fn is_at_or_under(name: &str, origin: &str) -> bool {
    if origin == "." { return true; }
    name.eq_ignore_ascii_case(origin)
        || name.to_ascii_lowercase()
               .ends_with(&format!(".{}", origin.to_ascii_lowercase()))
}
```

This is a **private function shadowing a public one of the same name in the same
crate**, which is why the `TODO.md` #13b sweep that folded four copies together
did not see it — nothing greps as a second definition when the call sites read
identically.

Two things about the copy:

- **Three allocations per call**, two `String`s and a `format!`. That is
  word-for-word what `utils::is_at_or_under`'s doc comment says it was written to
  remove from `resolver::is_subdomain`. Its one caller is `Layout::chain_names`
  (`zone_signer.rs:613`), which calls it once per ancestor per included name, so
  the cost scales as (names × labels) per signing run — and signing runs at every
  load and every re-sign. **I have not measured it**, and the order-of-magnitude
  arithmetic in an earlier draft of this file was exactly the "a count nobody
  counted" that `CLAUDE.md` §17 warns about, so it is struck. The correctness
  half below stands on its own and does not need the number.

  While reading that loop: `ancestors_of` (`zone_signer.rs:635`) allocates a
  `Vec<String>` of **every** ancestor including the ones above the origin —
  `com.`, `.` — which `is_under` then rejects one at a time. If A3 is fixed, that
  is the function to look at next; it is the same walk `zone::parent_name` does
  by borrowing.
- **It disagrees with the shared version.** `utils::is_at_or_under` makes the
  trailing dot optional on either side; this one does not, so
  `is_at_or_under("www.example.com", "example.com.")` is `true` there and `false`
  here. Not currently reachable — every caller passes `canonical_name` output —
  but that is a property of the callers, not of the function, and it is the
  drift §7 is about.

**Fix.** Delete it and `is_under`, import `utils::is_at_or_under`, keep a local
`is_under` as `name != origin && utils::is_at_or_under(..)` if it earns its name.

### A4. A broken string literal in an operator-facing error

`lib.rs:1787`:

```
"extended RCODE {rcode} needs an EDNS0 OPT record to carry its high                      bits (RFC 6891 §6.1.3)"
```

Twenty-two literal spaces where a `\` line continuation was intended. This is
exactly the failure `CLAUDE.md` §12 predicts — rustfmt does not touch string
literals, so a careless search-and-replace wrecks a continuation and nothing
notices. Cosmetic, one-line fix, listed because §12 says to watch for it.

---

## B. Structure

### B1. The operational shell is in the library and wired into one daemon

| facility | `rdnsd` | `rdnsr` |
|---|---|---|
| `security::RateLimiter` (per-source q/s) | yes | **no** |
| `security::ResponseLimiter` (per-source bytes/s) | yes | **no** |
| `logging::QueryLogger` | yes | **no** |
| `metrics::DnsMetrics` | yes | **no** |
| `metrics_server` (`/metrics`, `/healthz`, `/readyz`) | yes | **no** |
| `validation::RequestValidator` | yes | **no** (recorded in `TODO.md`, no reason given) |
| `readiness::Readiness` | yes | **no** |
| `shutdown::{Stop, Busy}` | yes | yes |
| `validation::Request` (the QR door) | yes | yes |

`rdnsr`'s only mitigations are a 127.0.0.1 default bind and `--max-inflight-udp`.

The asymmetry runs the wrong way round. A recursive resolver is the more
amplifying of the two — a 30-byte query can produce a 4 KB validated answer, and
`--dnssec-validate` makes that the normal case — and it is the one with no byte
budget and no per-source rate limit. It is also completely unobservable: no
counters, no probes, so "is it up and answering" has no answer that does not
involve sending it a query.

`TODO.md`'s "Architecture: why `rdnsr` is separate from `rdnsd`" argues the split
convincingly on trust model, data and lifecycle. None of those arguments implies
"and therefore no rate limit". The most likely history is simply that #9's
operational review was scoped to `rdnsd`.

**This is the one finding worth being a numbered item on its own.** Staged, it is
small: the library types already exist and are tested; `rdnsr`'s UDP loop already
has the admission point (it checks the semaphore before copying the datagram), so
the rate limiter goes on the same line, and `metrics_server::serve` is a
constructor call and a flag. What needs a decision rather than code is which
counters a *resolver* should have — `rdnsd`'s set is authoritative-shaped, and
cache hit rate, which is meaningless on `rdnsd` (see B4), is the headline number
here.

### B2. `rdnsd/src/main.rs` is 4 316 lines of code and eleven subsystems

> **Done 2026-08-03** — see `TODO.md` #20 for the two plan corrections it needed.
> The note below is as filed.
>
> **The one finding here that was still open, and was never filed.** #17, #18
> and #19 took the rest; this fell between them because it is not a defect and
> has no natural sub-item. Filed as `TODO.md` #20 on 2026-08-03. The number in
> the heading is also now low: the file is **8 340 lines** after dynamic UPDATE
> landed, roughly half of it tests, which makes the argument below stronger
> rather than weaker.

`mod config` and `mod control` are split out; everything else is in one file:
the answer path (`make_response`, `resolve_in_zone`, and six builders), the UDP
worker pool, the TCP accept and connection loops, the transfer server, NOTIFY in
both directions, the whole secondary role (refresh, expire, withdraw, state), the
reload machinery, zone loading and signing, key generation, CLI parsing, signal
handling and `main`.

Nothing here is *wrong* — the seams are visible in the code and the doc comments
are excellent — but the file is now the thing that makes a change to any one of
them expensive to review. Three seams are already drawn and would lift cleanly:

| module | contents | why it is a seam |
|---|---|---|
| `answer.rs` | `make_response`, `Outcome`, `resolve_in_zone`, `add_*`, `refer_to_child`, `find_zone_for_query`, `negative_ttl` | synchronous functions of `(&DnsMessage, &HashMap<String, Zone>, &DnsMetrics)` — no sockets, no lock guards, nothing `async`. `notify_reply` stays behind: it needs `&Secondaries` and the peer address |
| `secondary.rs` | `spawn_secondaries`, `secondary_loop`, `refresh_once`, `record_state`, `expire_if_out_of_contact`, `withdraw_unvouched_zones` | one owner, one lifetime, already talks to the rest through `Replication` and `Served` |
| `zones.rs` | `Zones`, `Served`, `Reloading`, `plan_reload`, `install_*`, `note_serials`, `load_zones_from_source`, `enumerate_zone_files`, `ZoneSigning` | the zone-map lifecycle, which `Reloading`'s doc comment already treats as a unit |

That leaves `main.rs` as the server struct, the two transport loops and startup —
about 1 200 lines. **Do this as its own commit with no behaviour change**, and
the ~3 000 lines of tests move with the code they cover, which is most of the
diff and most of the value.

### B3. Six copies of `fn absolute` — four of them byte-identical

`rfc5011.rs:797`, `secondary.rs:180`, `xfr.rs:531` and `zone.rs:557` are
byte-identical (same md5 over the function). `rdnsd/config.rs:234` differs only in
its parameter name (`zone` rather than `name`) and `rdnsd/main.rs:1949` only in
the function name (`absolute_name`). All six are:

```rust
if name.ends_with('.') { name.to_string() } else { format!("{name}.") }
```

`utils` has `absolute_lowered` (absolutize **and** fold, returning a `Cow`) but no
plain "add the trailing dot". Six copies is what happens when the shared module is
one accessor short.

`utils::absolute(name) -> Cow<'_, str>` — borrowing when the name already ends in
a dot, which is most of them. `answer_transfer` computes `absolute_name(&qname)`
twice, sixteen lines apart (`main.rs:1631` and `:1665`), which the `Cow` version
makes free.

### B4. Three exported metrics that nothing increments

`dns_cache_hits_total`, `dns_cache_misses_total`, `dns_queries_recursive_total`.
`DnsMetrics` is used only by `rdnsd`, which has no cache and never recurses. The
change that removed the misnamed *call sites* (`CLAUDE.md` §14 — "a counter's
name is a claim about what it counts") left the fields, the `# HELP`/`# TYPE`
lines and the `MetricsSnapshot` fields behind.

A dashboard computing `hits / (hits + misses)` gets 0/0. Delete all three, or —
if B1 lands — move the two cache counters to wherever `rdnsr`'s metrics live,
where they would mean something.

### B5. `RequestValidator` is a second, weaker copy of the parser's checks

`validation.rs:159`. Two of the things it does are real and cheap, and one is
neither:

- **Real:** packet-size caps (512 UDP / 16 KiB TCP) and the per-section count
  caps. Neither has an equivalent in `DnsMessage::try_from_bytes`, and both are
  header arithmetic that runs before anything is allocated. This is the part that
  earns its place on the pre-admission path.
- **Redundant:** `validate_domain_names` walks the first question's name a second
  time, with its own label-length check, its own 255-octet check and its own
  pointer handling — all of which `dname.rs` does immediately afterwards, and
  does better. The copies already disagree: `MAX_DEPTH` is 10 here and 50 there;
  this one does not require pointers to point backwards; it validates only the
  **first** question, ignoring the rest; and its `total_size` omits the
  terminating root octet, so it is off by one against `MAX_NAME_LEN`.

The disagreements are all in the safe direction today. They are still two
implementations of one rule (§7), and the weaker one runs first.

Also in this file: `validate_header` hand-rolls `(data[2] >> 3) & 0x0f` for the
opcode and `data[2] & 0x80` for QR, where `OpCode::from_u8(hi >> 3)` exists; and
two doc comments are wrong — `max_udp_size` cites "RFC 512", and `max_labels: 127`
is attributed to RFC 1035, which states no such limit (127 is derived from
255 octets / 2 per label).

**Suggested shape:** keep the size and count caps, delete the name walk, and
rename the type to say what it is — an admission check, not a validator. That is
about 100 lines out and one fewer place for the name rules to live.

### B6. Two near-identical TCP `serve_connection` implementations

`rdnsd/src/main.rs:1345` and `rdnsr/src/main.rs:712`, ~80 lines each. Same
split-writer task, same `Semaphore`, same read loop, same framing, same
drop-the-sender drain. The differences are: `rdnsd` logs, `rdnsd` returns a
`Vec<Vec<u8>>` (a transfer is several messages) where `rdnsr` returns one, and
`rdnsd` names the zero-length case in the log.

This is worth recording as a **candidate, not a plan**, because the honest
version is a generic over the answer function plus a logging trait, and that may
well cost more than the eight lines it deletes — the same trade §16c recorded for
`listener_failure`. What is *not* debatable is the framing inside it, which is A1.

---

### B7. `docs/CLI_USAGE.md` says "Complete reference" and covers half the flags

`rdnsd` has **27** flags. `CLI_USAGE.md` has a `### --flag` section for **14** of
them. The other thirteen appear in passing, in an example, or not at all:

```
--allow-partial-load  --check-config  --config       --key-algorithm
--metrics-listen      --nsec3         --nsec3-opt-out
--query-burst         --query-rate    --query-rate-exempt
--require-signed      --secondary     --signature-validity
```

Two of those gaps matter more than the rest:

- **The three `--query-rate*` flags.** That limiter drops traffic **silently** —
  no REFUSED, no SERVFAIL, nothing on the wire. `CLAUDE.md` §14 exists because
  the hardcoded 10 q/s version of it blackholed traffic and an operator had no way
  to learn the limit existed. The startup banner was the fix for "no way to learn
  the number"; the CLI guide is where you look for "what is this and how do I
  change it", and it is not there. Meanwhile `--response-rate`, the one control
  that at least answers TC=1, has a 35-line section.
- **`--secondary`.** The entire secondary role — replication, REFRESH/RETRY,
  EXPIRE and zone withdrawal — has no section. It is mentioned in one table row
  and in the `--also-notify` prose, both of which assume you already know what it
  does.

**Not a request to write thirteen sections.** Either document them or change the
first line, which currently makes a promise the file does not keep — and a
reference that is silently partial is the documentation version of §4's "degrading
quietly is worse than failing": a reader who does not find `--query-rate` there
concludes there is no such control.

## C. Smaller items

| item | where | note |
|---|---|---|
| `pub mod bench` is empty in a non-test build | `lib.rs:15`, `bench.rs` | the file is entirely `#[cfg(test)] mod benches`, so the library exports an empty public module. Should be `#[cfg(test)] mod bench;` — the filename is kept on purpose (§10 cites it), the `pub` is not |
| `impl EdnsHeader {}` | `lib.rs:1352` | an empty impl block |
| `// TODO: TryToBytes and others` | `dname.rs:118` | the only bare `TODO` left in the tree, and `dname.rs:237` records that the *other* one was deleted rather than done, with the reasoning. This one deserves the same treatment either way |
| `rdnsd::in_zone` is a private `is_at_or_under` | `main.rs:765` | allocates `zone.origin().to_ascii_lowercase()` **per call**, and both call sites additionally allocate `.to_ascii_lowercase()` on the name to feed it. On the CNAME-chase and referral-glue paths. `utils::is_at_or_under` needs neither allocation. Same family as A3 |
| `xfr::rand_id` and `rdnsd::rand_id` — **left, as D-3** | `xfr.rs:770`, `main.rs:3476` | same name, different entropy — one is `rand::thread_rng()`, the other is folded nanoseconds. See D-3 in the conformance doc |
| ~~`rdnsc` cannot set DO or send an OPT~~ **fixed** | `rdnsc/src/main.rs` | the shipped client cannot exercise the server's most complex feature, which is why every DNSSEC verification recipe in `TODO.md` reaches for dnspython. A `--dnssec` flag and an `Edns` on the builder is a small change with a disproportionate payoff for the workflow |
| ~~`metrics_server::serve` has no connection ceiling~~ **fixed** | `metrics_server.rs:44` | the only accept loop in the workspace without one. A management port with a 5 s read timeout, so low severity — but the pattern is established three times elsewhere |
| ~~`update.rs` is 1 070 unreachable lines~~ **fixed — served end to end** | — | already `TODO.md` #10; noted here only because a shipped library carrying a feature nothing can reach is worth stating in the conformance doc, which it now is (G-4) |
| `TODO.md` #13e carries a claim the head commit falsified | `TODO.md:1466` | "**≤255 octets** … and *not* checked by `dname_to_bytes`, which validates label length and total length never". Commit `6882b1e` closed that door: both now go through one `check_name_len` (`dname.rs:466`), and §15 records the fix at `TODO.md:2033`. The stale sentence is in §13e's **live body**, not in a preserved "as filed" block, so `CLAUDE.md` §11 applies — correct it in place with a pointer to §15, keeping the reasoning |

---

## What I checked and found nothing wrong with

Recorded so the next reviewer does not re-derive it (`TODO.md` §16's second list
is the precedent, and it is the more useful half of that section).

- **`Qtype`/`Rtype`/`Class`/`QueryClass`.** The four newtypes and their one-way
  conversions are consistent; `Qtype::matches` is the only type comparison
  against stored data, and `zone::of_type`, `dnssec_answer::answer_signatures`
  and the two former `resolver.rs` sites all go through it now.
- **`Serial`.** No `Ord`, no `PartialOrd`, `is_newer_than` is RFC 1982 §3.2
  verbatim, and the one raw comparison left carries a comment saying why the
  claim is arithmetical rather than about versions.
- **`Ttl`.** One clamp, at `from_wire`, and OPT's TTL field correctly bypasses it
  in `Additional::try_from_bytes`.
- **The wire parser's length checks.** `read_be!`, `Label::try_from_bytes`,
  `walk_options` and `read_record_parts` all check before slicing. The RDLENGTH
  fix is in place with its reasoning.
- **`dnssec_answer`.** All four answer shapes owe what RFC 4035 says they owe,
  and the tests judge the output with `verify_rrset` / `proves_nxdomain` /
  `proves_nodata` rather than by inspection.
- **`answer_transfer`'s authorization.** Checked against the apex, before the
  zone lookup, off the `TsigSession` rather than by a second key lookup, with
  every error path signed. The two-ways-to-be-allowed structure is correct and
  the log says which one fired.
- **`security::RateLimiter` / `ResponseLimiter`.** Both bounded by `max_tracked`,
  both with a written-down direction of failure and a shortfall counter.
- **`shutdown`.** The `Stop`/`Busy` split, the sender-drop drain, and the
  cancel-safety reasoning about where each `select!` arm may sit all hold up. The
  Windows four-signal handler is correct.
- **`Zone`'s index, chains and non-terminals.** Derived state is private,
  `reindex` rebuilds all three, and `matches_query` asks `name_kind_of_key`
  rather than re-deriving the wildcard rule.
- **The `#[cfg(unix)]` boundary.** `rdnsctl` and `rdnsd --control-socket` both
  refuse on Windows with a message rather than compiling away silently.
