# Architectural reviews — 2026-08-03 (structure), 2026-08-04 (algorithmic shape)

Two reviews, in the order they were done. The second is appended below the
first's "Checked and found nothing wrong with"; neither is rewritten to account
for the other, except where one falsifies a claim in the other, which is marked
in place (`CLAUDE.md` §11).

## Review 1 — 2026-08-03: structure

Read at commit `6882b1e`, clean tree, `cargo clippy --workspace --all-targets`
clean, `cargo test --workspace` 757 passed / 0 failed / 4 ignored on Windows.

Findings below are new. Things that looked like findings but are already in
`TODO.md` — `listener_failure`'s deliberate duplication (§16c), the
`Result<_, String>` helpers in `zone.rs`, `parse_root_hints` returning a `Vec`,
the unaudited `.lock().unwrap()` count — are not repeated. Protocol-level gaps
are in `docs/spec/07-rfc-conformance.md` §7.4; this file carries structural ones.

Sections are in descending order of what they would cost if left.

**A second review is appended below, 2026-08-04**, read at `bb4b812` and aimed at
algorithmic shape rather than structure: what costs more than it should, what
grows with a number nobody is watching, and what the compiler is being stopped
from doing. It is filed as `TODO.md` #23-#26, and it falsifies one line of the
status table immediately below — A4 was recorded as fixed and is not.

---

## Status, 2026-08-03 (revised at `e2ebaef`)

Filed as `TODO.md` #17, #18 and #19. All closed except B2, which was never filed
— see the note under it. Findings are left as written rather than rewritten in
the past tense: what a defect *was*, and the reasoning that found it, is the half
worth keeping (`CLAUDE.md` §11).

| finding | outcome |
|---|---|
| A1 TCP length prefix | fixed, `c9cc5c9` — `TODO.md` #17 |
| A2 two live `str::to_lowercase` | fixed, `85c864c` — #19a |
| A3 `zone_signer` shadows `is_at_or_under` | fixed, `85c864c` — #19b |
| A4 broken string literal | ~~fixed, `85c864c` — #19h~~ **that was wrong** — `85c864c` moved the spaces one word to the left and left the literal broken. Really fixed 2026-08-04, with the test that would have caught it (`TODO.md` #26j) — see the note below |
| B1 the operational shell | fixed, `b523861` — #18 |
| B2 `main.rs` is eleven subsystems | fixed, `0748111`+`e51659b`+`e756a6a` — #20, with two plan corrections on the way |
| B3 six copies of `fn absolute` | fixed, `85c864c` — #19c |
| B4 three metrics nothing increments | fixed, `b523861` — #19d, by moving them to `rdnsr` |
| B5 `RequestValidator` duplicates the parser | fixed, `85c864c` — #19e, renamed `AdmissionCheck` |
| B6 two `serve_connection`s | declined, #19f, with the reason recorded |
| B7 `CLI_USAGE.md` covers half the flags | fixed, `e2ebaef` — #19g |
| C the eight small ones | seven fixed in `85c864c`; `rand_id` left, as D-3 |

One finding turned up a defect in the review itself, worth stating because it is
the same shape as the things it was looking for. B5 listed four ways the
admission check's name walk disagreed with `dname.rs`. Re-pointing its test at
the parser found a fifth that neither the review nor the test had noticed: the
packet in `test_oversized_label` carries `0x41`, described in its own comment as
"Label length: 65". That octet is not a length — the top two bits are a *type*,
and `01` is RFC 2673's binary label. A label over 63 octets cannot be spelled on
the wire. The deleted check was rejecting an impossible case for the wrong
reason, and the test agreed because both came from the same misreading.

**A second defect in this review, found the day after by re-reading the code
instead of the table.** A4's row said *fixed*, and so did `85c864c`'s commit
message. The commit moved the twenty-two spaces from one side of a word to the
other:

```
85c864c^:  ...to carry its high                      bits (RFC 6891 §6.1.3)
85c864c :  ...to carry                      its high bits (RFC 6891 §6.1.3)
bb4b812 :  ...to carry                      its high bits (RFC 6891 §6.1.3)
```

The defect is cosmetic and the mistake is not: three documents — the commit
message, `TODO.md` #19h and this table — asserted a fix nobody had opened the
result of, each copying the one before (`CLAUDE.md` §4). The row is struck rather
than deleted, for the same reason the findings are left in the present tense.

Fixed 2026-08-04. The half worth keeping is why the suite never said anything:
`test_extended_rcode_without_opt_is_an_error` asserted that the message
*contains* `"OPT record"`, which is true of the broken string and the fixed one
alike (§1). It now asserts the rendered message holds no double space — a guard
for the whole class rather than for this literal — and was watched failing
against the old one.

---

## Verdict

Unusually well built for its size, and the reason is legible: the hard parts were
reviewed adversarially and the reasoning kept in prose next to the code. DNSSEC,
TSIG, the denial proofs, serial arithmetic, the type work of `TODO.md` #13 all
read as finished. `CLAUDE.md` §17's claim holds under inspection: invariants moved
into types have not recurred, and every one fixed at a call site left at least one
straggler.

Three of the four findings in A are stragglers of exactly that kind —
consolidations that caught most copies and missed one. That is evidence for the
rule, not a criticism of the consolidations.

The one structural thing worth changing is B1: the operational shell was built
for `rdnsd`, put in the shared library so both daemons could use it, then wired
into one daemon. The resolver — the more amplifying of the two — has none of it.

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

Every one is `(bytes.len() as u16).to_be_bytes()`, unchecked. `CLAUDE.md` §2 is
about `as` on values coming *off* the wire; this is the same cast going the other
way. `DnsMessage::to_bytes` is the sibling that shows the shape — twenty lines of
it do exactly this correctly, with `try_into().map_err(|_| WireError::TooLong { .. })`
for RDLENGTH, ARCOUNT and OPT RDLENGTH.

The reachable path, provoked rather than argued: `to_bytes_within(u16::MAX as usize)`
yields at most 65 535 octets, since the scratch buffer is exactly that size, so
anything larger comes back as a 33-byte TC=1 reply. `tsig::append_tsig`
(`tsig.rs:844`) then appends a TSIG record to the *finished* bytes with no
total-length check — it checks only that ARCOUNT does not overflow.

A throwaway integration test (`rdns/tests/`, run and deleted) swept a TXT RRset's
size one octet at a time through the boundary, signing each result with a real
`TsigSession`:

```
pad= 15 serialized=65452 signed=65534 prefix=65534 ok
pad= 16 serialized=65453 signed=65535 prefix=65535 ok
WRAPPED at pad=17: serialized 65454 + TSIG 82 = 65536 bytes,
                   but the frame prefix says 0
```

The failure is worse than a wrong length. 65536 mod 65536 is 0, and a zero-length
prefix is what both daemons' read loops treat as a broken peer —
`rdnsd/src/main.rs:1390` logs "zero-length TCP message" and closes the connection,
`rdnsr/src/main.rs:751` breaks. The client's connection is dropped with no answer,
and nothing on either side reports why.

The window is 82 octets wide — one hmac-sha256 TSIG record with a ten-octet key
name — out of 65 536 possible sizes: serialized lengths 65 454..=65 535 all wrap.
A longer key name widens it. Larger overshoots produce a small non-zero prefix,
which desynchronises the stream rather than closing it.

AXFR is not the exposure (envelopes target 16 KiB, `AXFR_TARGET_MESSAGE_SIZE`); a
TSIG-signed ordinary answer over TCP is. That needs a ~64 KB RRset at one name,
which is unusual but entirely constructible in a zone file.

Fix, in two parts:

1. A length check in `append_tsig` — it is the only thing that can push a message
   past the limit it was serialized to, and it already returns
   `ConfigResult<Vec<u8>>`, so there is a channel for the error.
2. One `rdns::` helper for the framing. It returns `Result<Vec<u8>, WireError>`
   and no error type crosses the library boundary, so §16c's argument against
   moving `listener_failure` does not apply:

   ```rust
   /// A message with its RFC 1035 §4.2.2 length prefix, in one buffer.
   pub fn framed(bytes: &[u8]) -> Result<Vec<u8>, WireError>
   ```

The regression test writes itself from the sweep above, and it fails against
today's code — watched.

### A2. Two live `str::to_lowercase` calls on wire-supplied names

`rdnsd/src/main.rs:1915`, the NOTIFY zone-name lookup key, and the matching insert
at `:3064`. `CLAUDE.md` §8 and RFC 4343: the fold is ASCII-only, and
`to_lowercase` folds U+212A KELVIN SIGN onto `k`.

The two agree with each other, so the `Secondaries` table is self-consistent and
the master-address check still gates the refresh. Impact is bounded to "a NOTIFY
naming a Kelvin-sign variant of a replicated zone folds onto that zone". It is on
the list because it is precisely the rule this codebase wrote down, on a name a
stranger chooses, and `utils::absolute_lowered` is one call away and returns a
`Cow` that borrows in the common case.

Every other `to_lowercase()` in the tree is on `base32hex_encode` output (ASCII by
construction — still worth `make_ascii_lowercase`) or in tests.

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

A private function shadowing a public one of the same name in the same crate,
which is why the `TODO.md` #13b sweep that folded four copies together missed it:
nothing greps as a second definition when the call sites read identically.

- Three allocations per call, two `String`s and a `format!` — word for word what
  `utils::is_at_or_under`'s doc comment says it was written to remove from
  `resolver::is_subdomain`. Its one caller is `Layout::chain_names`
  (`zone_signer.rs:613`), called once per ancestor per included name, so cost
  scales as (names × labels) per signing run, at every load and every re-sign.
  Not measured — the order-of-magnitude arithmetic in an earlier draft was exactly
  the "count nobody counted" `CLAUDE.md` §17 warns about, so it is struck. The
  correctness half stands on its own.

  Also in that loop: `ancestors_of` (`zone_signer.rs:635`) allocates a
  `Vec<String>` of every ancestor including those above the origin — `com.`, `.` —
  which `is_under` rejects one at a time. If A3 is fixed, that is the next
  function to look at; it is the walk `zone::parent_name` does by borrowing.
- It disagrees with the shared version. `utils::is_at_or_under` makes the trailing
  dot optional on either side; this one does not, so
  `is_at_or_under("www.example.com", "example.com.")` is `true` there and `false`
  here. Not currently reachable — every caller passes `canonical_name` output —
  but that is a property of the callers, not the function, and it is the drift §7
  is about.

Fix: delete it and `is_under`, import `utils::is_at_or_under`, keep a local
`is_under` as `name != origin && utils::is_at_or_under(..)` if it earns its name.

### A4. A broken string literal in an operator-facing error

`lib.rs:1787`:

```
"extended RCODE {rcode} needs an EDNS0 OPT record to carry its high                      bits (RFC 6891 §6.1.3)"
```

Twenty-two literal spaces where a `\` line continuation was intended — exactly the
failure `CLAUDE.md` §12 predicts, since rustfmt does not touch string literals.
Cosmetic, one-line fix, listed because §12 says to watch for it.

---

## B. Structure

### B1. The operational shell is in the library and wired into one daemon

| facility | `rdnsd` | `rdnsr` |
|---|---|---|
| `security::RateLimiter` (per-source q/s) | yes | no |
| `security::ResponseLimiter` (per-source bytes/s) | yes | no |
| `logging::QueryLogger` | yes | no |
| `metrics::DnsMetrics` | yes | no |
| `metrics_server` (`/metrics`, `/healthz`, `/readyz`) | yes | no |
| `validation::RequestValidator` | yes | no (recorded in `TODO.md`, no reason given) |
| `readiness::Readiness` | yes | no |
| `shutdown::{Stop, Busy}` | yes | yes |
| `validation::Request` (the QR door) | yes | yes |

`rdnsr`'s only mitigations are a 127.0.0.1 default bind and `--max-inflight-udp`.

The asymmetry runs the wrong way round. A recursive resolver is the more
amplifying of the two — a 30-byte query can produce a 4 KB validated answer, and
`--dnssec-validate` makes that the normal case — and it is the one with no byte
budget and no per-source rate limit. It is also unobservable: no counters, no
probes, so "is it up and answering" has no answer that does not involve sending it
a query.

`TODO.md`'s "Architecture: why `rdnsr` is separate from `rdnsd`" argues the split
convincingly on trust model, data and lifecycle. None of those arguments implies
"and therefore no rate limit". The likely history is that #9's operational review
was scoped to `rdnsd`.

Staged, it is small: the library types exist and are tested; `rdnsr`'s UDP loop
already has the admission point (it checks the semaphore before copying the
datagram), so the rate limiter goes on the same line, and `metrics_server::serve`
is a constructor call and a flag. What needs a decision rather than code is which
counters a *resolver* should have — `rdnsd`'s set is authoritative-shaped, and
cache hit rate, meaningless on `rdnsd` (B4), is the headline number here.

### B2. `rdnsd/src/main.rs` is 4 316 lines of code and eleven subsystems

> Done 2026-08-03 — see `TODO.md` #20 for the two plan corrections it needed. The
> note below is as filed.
>
> The one finding here still open, and never filed: #17, #18 and #19 took the
> rest; this fell between them because it is not a defect and has no natural
> sub-item. Filed as `TODO.md` #20 on 2026-08-03. The number in the heading is
> also now low — the file is 8 340 lines after dynamic UPDATE landed, roughly half
> tests, which makes the argument stronger rather than weaker.

`mod config` and `mod control` are split out; everything else is in one file: the
answer path (`make_response`, `resolve_in_zone`, six builders), the UDP worker
pool, the TCP accept and connection loops, the transfer server, NOTIFY in both
directions, the whole secondary role (refresh, expire, withdraw, state), the
reload machinery, zone loading and signing, key generation, CLI parsing, signal
handling and `main`.

Nothing here is wrong — the seams are visible and the doc comments are excellent —
but the file is what makes a change to any one of them expensive to review. Three
seams are already drawn and would lift cleanly:

| module | contents | why it is a seam |
|---|---|---|
| `answer.rs` | `make_response`, `Outcome`, `resolve_in_zone`, `add_*`, `refer_to_child`, `find_zone_for_query`, `negative_ttl` | synchronous functions of `(&DnsMessage, &HashMap<String, Zone>, &DnsMetrics)` — no sockets, no lock guards, nothing `async`. `notify_reply` stays behind: it needs `&Secondaries` and the peer address |
| `secondary.rs` | `spawn_secondaries`, `secondary_loop`, `refresh_once`, `record_state`, `expire_if_out_of_contact`, `withdraw_unvouched_zones` | one owner, one lifetime, already talks to the rest through `Replication` and `Served` |
| `zones.rs` | `Zones`, `Served`, `Reloading`, `plan_reload`, `install_*`, `note_serials`, `load_zones_from_source`, `enumerate_zone_files`, `ZoneSigning` | the zone-map lifecycle, which `Reloading`'s doc comment already treats as a unit |

That leaves `main.rs` as the server struct, the two transport loops and startup —
about 1 200 lines. Do it as its own commit with no behaviour change; the ~3 000
lines of tests move with the code they cover, which is most of the diff and most
of the value.

### B3. Six copies of `fn absolute` — four byte-identical

`rfc5011.rs:797`, `secondary.rs:180`, `xfr.rs:531` and `zone.rs:557` are
byte-identical (same md5 over the function). `rdnsd/config.rs:234` differs only in
its parameter name (`zone` rather than `name`) and `rdnsd/main.rs:1949` only in
the function name (`absolute_name`). All six are:

```rust
if name.ends_with('.') { name.to_string() } else { format!("{name}.") }
```

`utils` has `absolute_lowered` (absolutize and fold, returning a `Cow`) but no
plain "add the trailing dot". Six copies is what happens when the shared module is
one accessor short.

`utils::absolute(name) -> Cow<'_, str>`, borrowing when the name already ends in a
dot, which is most of them. `answer_transfer` computes `absolute_name(&qname)`
twice, sixteen lines apart (`main.rs:1631` and `:1665`), which the `Cow` version
makes free.

### B4. Three exported metrics that nothing increments

`dns_cache_hits_total`, `dns_cache_misses_total`, `dns_queries_recursive_total`.
`DnsMetrics` is used only by `rdnsd`, which has no cache and never recurses. The
change that removed the misnamed *call sites* (`CLAUDE.md` §14 — "a counter's name
is a claim about what it counts") left the fields, the `# HELP`/`# TYPE` lines and
the `MetricsSnapshot` fields.

A dashboard computing `hits / (hits + misses)` gets 0/0. Delete all three, or — if
B1 lands — move the two cache counters to wherever `rdnsr`'s metrics live.

### B5. `RequestValidator` is a second, weaker copy of the parser's checks

`validation.rs:159`. Two things it does are real and cheap, one is neither:

- Real: packet-size caps (512 UDP / 16 KiB TCP) and the per-section count caps.
  Neither has an equivalent in `DnsMessage::try_from_bytes`, and both are header
  arithmetic that runs before anything is allocated. This part earns its place on
  the pre-admission path.
- Redundant: `validate_domain_names` walks the first question's name a second
  time, with its own label-length check, its own 255-octet check and its own
  pointer handling — all of which `dname.rs` does immediately afterwards, and
  better. The copies already disagree: `MAX_DEPTH` is 10 here and 50 there; this
  one does not require pointers to point backwards; it validates only the first
  question, ignoring the rest; and its `total_size` omits the terminating root
  octet, so it is off by one against `MAX_NAME_LEN`.

The disagreements are all in the safe direction today. They are still two
implementations of one rule (§7), and the weaker one runs first.

Also in this file: `validate_header` hand-rolls `(data[2] >> 3) & 0x0f` for the
opcode and `data[2] & 0x80` for QR, where `OpCode::from_u8(hi >> 3)` exists. Two
doc comments are wrong — `max_udp_size` cites "RFC 512", and `max_labels: 127` is
attributed to RFC 1035, which states no such limit (127 is derived from 255
octets / 2 per label).

Suggested shape: keep the size and count caps, delete the name walk, rename the
type to say what it is — an admission check, not a validator. About 100 lines out
and one fewer place for the name rules to live.

### B6. Two near-identical TCP `serve_connection` implementations

`rdnsd/src/main.rs:1345` and `rdnsr/src/main.rs:712`, ~80 lines each. Same
split-writer task, same `Semaphore`, same read loop, same framing, same
drop-the-sender drain. Differences: `rdnsd` logs, `rdnsd` returns a `Vec<Vec<u8>>`
(a transfer is several messages) where `rdnsr` returns one, and `rdnsd` names the
zero-length case in the log.

Recorded as a candidate, not a plan: the honest version is a generic over the
answer function plus a logging trait, which may cost more than the eight lines it
deletes — the same trade §16c recorded for `listener_failure`. What is not
debatable is the framing inside it, which is A1.

### B7. `docs/CLI_USAGE.md` says "Complete reference" and covers half the flags

`rdnsd` has 27 flags. `CLI_USAGE.md` has a `### --flag` section for 14. The other
thirteen appear in passing, in an example, or not at all:

```
--allow-partial-load  --check-config  --config       --key-algorithm
--metrics-listen      --nsec3         --nsec3-opt-out
--query-burst         --query-rate    --query-rate-exempt
--require-signed      --secondary     --signature-validity
```

Two gaps matter more than the rest:

- The three `--query-rate*` flags. That limiter drops traffic silently — no
  REFUSED, no SERVFAIL, nothing on the wire. `CLAUDE.md` §14 exists because the
  hardcoded 10 q/s version blackholed traffic and an operator had no way to learn
  the limit existed. The startup banner fixed "no way to learn the number"; the
  CLI guide is where you look for "what is this and how do I change it", and it is
  not there. Meanwhile `--response-rate`, the one control that at least answers
  TC=1, has a 35-line section.
- `--secondary`. The entire secondary role — replication, REFRESH/RETRY, EXPIRE,
  zone withdrawal — has no section. It appears in one table row and in the
  `--also-notify` prose, both of which assume you already know what it does.

Not a request to write thirteen sections. Either document them or change the first
line, which currently makes a promise the file does not keep — a reference that is
silently partial is the documentation version of §4's "degrading quietly is worse
than failing": a reader who does not find `--query-rate` there concludes there is
no such control.

## C. Smaller items

| item | where | note |
|---|---|---|
| `pub mod bench` is empty in a non-test build | `lib.rs:15`, `bench.rs` | the file is entirely `#[cfg(test)] mod benches`, so the library exports an empty public module. Should be `#[cfg(test)] mod bench;` — the filename is kept on purpose (§10 cites it), the `pub` is not |
| `impl EdnsHeader {}` | `lib.rs:1352` | an empty impl block |
| `// TODO: TryToBytes and others` | `dname.rs:118` | the only bare `TODO` left in the tree; `dname.rs:237` records that the *other* one was deleted rather than done, with reasoning. This one deserves the same treatment either way |
| `rdnsd::in_zone` is a private `is_at_or_under` | `main.rs:765` | allocates `zone.origin().to_ascii_lowercase()` per call, and both call sites additionally allocate `.to_ascii_lowercase()` on the name to feed it. On the CNAME-chase and referral-glue paths. `utils::is_at_or_under` needs neither. Same family as A3 |
| `xfr::rand_id` and `rdnsd::rand_id` — left, as D-3 | `xfr.rs:770`, `main.rs:3476` | same name, different entropy — one is `rand::thread_rng()`, the other folded nanoseconds. See D-3 in the conformance doc |
| ~~`rdnsc` cannot set DO or send an OPT~~ fixed | `rdnsc/src/main.rs` | the shipped client could not exercise the server's most complex feature, which is why every DNSSEC recipe in `TODO.md` reaches for dnspython. A `--dnssec` flag and an `Edns` on the builder, small change, disproportionate payoff |
| ~~`metrics_server::serve` has no connection ceiling~~ fixed | `metrics_server.rs:44` | the only accept loop in the workspace without one. A management port with a 5 s read timeout, so low severity — but the pattern is established three times elsewhere |
| ~~`update.rs` is 1 070 unreachable lines~~ fixed — served end to end | — | already `TODO.md` #10; noted here only because a shipped library carrying a feature nothing can reach belongs in the conformance doc, which it now is (G-4) |
| `TODO.md` #13e carries a claim the head commit falsified | `TODO.md:1466` | "≤255 octets … and *not* checked by `dname_to_bytes`, which validates label length and total length never". Commit `6882b1e` closed that: both now go through one `check_name_len` (`dname.rs:466`), and §15 records the fix at `TODO.md:2033`. The stale sentence is in §13e's live body, not a preserved "as filed" block, so `CLAUDE.md` §11 applies — correct in place with a pointer to §15, keeping the reasoning |

---

## Checked and found nothing wrong with

Recorded so the next reviewer does not re-derive it (`TODO.md` §16's second list
is the precedent, and the more useful half of that section).

- `Qtype`/`Rtype`/`Class`/`QueryClass`. The four newtypes and their one-way
  conversions are consistent; `Qtype::matches` is the only type comparison against
  stored data, and `zone::of_type`, `dnssec_answer::answer_signatures` and the two
  former `resolver.rs` sites all go through it.
- `Serial`. No `Ord`, no `PartialOrd`, `is_newer_than` is RFC 1982 §3.2 verbatim,
  and the one raw comparison left carries a comment saying why the claim is
  arithmetical rather than about versions.
- `Ttl`. One clamp, at `from_wire`, and OPT's TTL field correctly bypasses it in
  `Additional::try_from_bytes`.
- The wire parser's length checks. `read_be!`, `Label::try_from_bytes`,
  `walk_options` and `read_record_parts` all check before slicing. The RDLENGTH fix
  is in place with its reasoning.
- `dnssec_answer`. All four answer shapes owe what RFC 4035 says they owe, and the
  tests judge output with `verify_rrset` / `proves_nxdomain` / `proves_nodata`
  rather than by inspection.
- `answer_transfer`'s authorization. Checked against the apex, before the zone
  lookup, off the `TsigSession` rather than a second key lookup, with every error
  path signed. The two-ways-to-be-allowed structure is correct and the log says
  which one fired.
- `security::RateLimiter` / `ResponseLimiter`. Both bounded by `max_tracked`, both
  with a written-down direction of failure and a shortfall counter.
- `shutdown`. The `Stop`/`Busy` split, the sender-drop drain, and the
  cancel-safety reasoning about where each `select!` arm may sit all hold up. The
  Windows four-signal handler is correct.
- `Zone`'s index, chains and non-terminals. Derived state is private, `reindex`
  rebuilds all three, and `matches_query` asks `name_kind_of_key` rather than
  re-deriving the wildcard rule.
- The `#[cfg(unix)]` boundary. `rdnsctl` and `rdnsd --control-socket` both refuse
  on Windows with a message rather than compiling away silently.

---
---

# Second review — 2026-08-04: algorithmic shape

Read at `bb4b812`, clean tree. The first review asked whether the code is
*arranged* well; this one asks what it *costs* — where the work is superlinear in
something an operator or a client chooses, where a standard-library spelling
exists for a hand-roll, and where the compiler is being stopped from vectorizing
a loop that has the shape for it.

Filed as `TODO.md` #23-#26. As above, findings are left as written rather than
rewritten once fixed.

| finding | filed as |
|---|---|
| #23 `NsecCache::synthesize` re-hashes per cached NSEC3 record, under one mutex | `TODO.md` #23 — **the one with teeth** |
| #24a zone selection is a linear scan of the zone map, per query | #24a |
| #24b name compression is quadratic in the records of one message | #24b |
| #24c an AXFR materializes the zone three times over | #24c |
| #25a-h per-answer waste on paths #9e already measured | #25 |
| #26a-i helpers written twice, hand-rolls with a standard spelling | #26 |
| #26j A4 had never been fixed | #26j — **fixed 2026-08-04**, and the struck row above |

## Verdict

The first review's verdict stands and this one does not soften it: the hard parts
are still the parts that are right. What this pass found is a different failure
mode from the first — not code that is arranged badly, but code whose cost was
never the question anyone asked of it. Every finding here was written by someone
who had thought carefully about correctness and stopped there, which is why they
survived a five-way review and two architecture passes: **a scan that is
obviously correct does not look like a defect.**

Three of them share one cause worth naming. `find_zone_for_query` (#24a),
`cache::get_validated` (#25e) and the NSEC3 half of `nsec_cache` (#23) all have
the right data structure sitting beside them, unasked — a hash map that cannot be
hashed against because its key was never normalized, and a `BTreeMap` keyed by the
exact value the scan is recomputing. `CLAUDE.md` §17 says the invariant has to
live in the type; these say the same thing about the *index*, and that the type
existing (`NameKeyBuf`) is not the same as the map using it.

The one that must not wait is #23. The rest are performance; that one is a
stranger holding a core for a second at a time.

## Method, and what the numbers are worth

Measurements come from a throwaway crate outside the tree (`rdns` as a path
dependency, release profile, Windows 11, five binaries); disassembly from the
same code built on the Linux side with `objdump -d`, same LLVM, same baseline
`x86-64` target with no `target-cpu`.

**Absolute nanoseconds on this machine are not reproducible between runs** — the
same `to_bytes` call read 106 ns in one run and 227-255 ns in four later ones, on
an idle machine. Every claim below is therefore a **delta or a ratio**, both
measured in the same run, and anything re-measured later should be too. This is
`CLAUDE.md` §10's rule arrived at the hard way: the first draft of #25b quoted the
106 ns as the denominator and would have overstated the finding by 2×.

## The one with teeth: #23

`nsec_cache.rs`. The NSEC half is right — `matching_nsec` (`:600`) is a
`BTreeMap` lookup by canonical sort key and `covering_nsec` is a range query. The
NSEC3 half, in the same file and by the same hand, scans **every cached record**:
`synthesize_nodata` (`:645`) and `synthesize_nxdomain_nsec3` (`:732`) call
`Nsec3::matches` and then `covers`, each of which recomputes the salted, iterated
SHA-1 of the name (`dnssec_denial.rs:420-426`).

The hash is a function of (name, salt, iterations). Every record in one zone's
chain carries the same salt and iteration count, and `nsec3s` is **already keyed
by owner hash** — so the entire scan is one hash, one `get` and one `range`.

The multiplier is the QNAME's label count, which the client picks:
`synthesize_nxdomain_nsec3` builds two candidate names per label between the zone
apex and the queried name, then walks all 256 records (`MAX_PROOFS_PER_ZONE`) for
each, hashing twice per pair on the common path where `matches` fails.

Provoked rather than argued — fill an `NsecCache` the way a validated denial
fills it, then time one `synthesize`. 256 records, every call returning `None`,
which is both the worst case and what a random-name flood produces:

| iterations | QNAME | one `synthesize` |
|---|---|---|
| 0 (RFC 9276's recommendation) | 249 octets, 118 labels | **105 ms** |
| 10 | 249 octets | **176 ms** |
| 150 (`MAX_NSEC3_ITERATIONS`) | 33 octets, 10 labels | **102 ms** |
| 150 | 249 octets | **1 156 ms** |

`rdnsr --dnssec-validate` calls `synthesize` on every query, *before* the answer
cache (`rdnsr/src/main.rs:1227`), holding `self.zones` — one `Mutex` for the whole
cache — across the call. So the second cost is the first one's shadow: every other
thread's cache lookup queues behind it. Cost is linear in what is cached, so a
full table is the worst case rather than a precondition, and filling it costs an
attacker roughly ninety denials from a zone they signed themselves.

Two things make this a review finding rather than a bug report. The correct data
structure is already there and already used correctly ten lines away, which is
`CLAUDE.md` §7 in its least visible form — not two copies of a rule, but one
right implementation and one that never asked the index a question. And the
per-record `hash()` is *right* for its other caller, `dnssec_denial`, where the
loop is bounded by one message's records; what is wrong is reusing a
message-shaped helper against a cache-shaped collection.

## Costs that grow with something nobody is watching: #24

### #24a. Zone selection is a linear scan, per query

`rdnsd/src/answer.rs:548`. `Zones::matching_key` (`zones.rs:407`),
`Zones::matching` (`:415`) and `answer_transfer`'s apex lookup (`main.rs:1222`)
are three more copies of the same scan.

| zones | `find_zone_for_query` | a suffix walk over the same map |
|---|---|---|
| 1 | 15.7 ns | 20.0 ns |
| 100 | 540 ns | 23.1 ns |
| 1 000 | 7.3 µs | 22.9 ns |
| 10 000 | 53.7 µs | 20.4 ns |

At a thousand zones, choosing which zone to answer from costs more than the whole
rest of the query including both syscalls (#9e: 522 ns of library work inside a
~4 µs `sendto`+`recvfrom` pair).

The comment on that function records that the allocations were taken out of it,
which is true and is the smaller half. What was left is the scan, and the reason
it cannot be a lookup is a *type*: the map is keyed by `zone.origin().to_string()`
in whatever case the zone file was written (`zones.rs:378`), so nothing can hash a
QNAME against it. `utils::NameKeyBuf` exists for precisely this — one constructor,
which folds — and the zone map does not use it. `CLAUDE.md` §17's own prediction,
unclaimed: the fix that lives in a type still has to be reached for.

### #24b. Name compression is quadratic in the records of one message

`compression.rs:153`. `lookup` is a linear scan of `seen`, which grows by one
entry per label per distinct name, so a message costs O(names² × labels).

| distinct names | ns/message | ns/record |
|---|---|---|
| 25 | 2 359 | 94 |
| 100 | 14 522 | 145 |
| 400 | 148 464 | 371 |
| 800 | 572 332 | **715** |

The type's doc comment justifies the scan — *"one message holds a handful of
distinct names, so the table is a handful of entries long"* — and that is true of
a query response and false of every other caller of `to_bytes`. An AXFR envelope
targets 16 KiB (`transfer.rs:29`), which is 300-500 records, and the cost worsens
in exactly the direction anyone tuning envelope size would push.

Worth noting what this is *not*: the arena rewrite that replaced
`HashMap<String, u16>` was right, and the measurement that motivated it (339 ns
per name, the majority of serialization) was real. Hashing was not the cost; the
per-suffix `String` was. Putting a hash back over ranges into the arena keeps both
wins.

### #24c. An AXFR materializes the zone three times over

`transfer::axfr_messages` clones every record into a `Vec<ResourceRecord>`,
`pack_transfer_messages` moves those into a `Vec<DnsMessage>`, and `rdnsd` builds
**all** frames before writing any (`main.rs:1262-1300`), each frame a `Vec` with
64 KiB of capacity (#25b). For a million-record zone that is the zone, the zone
again as messages, and ~2 500 × 64 KiB of frame capacity, per concurrent transfer.

ACL-gated, so not pre-authentication — but the whole-zone read under a read lock
is also a reload blocked for its duration, and a secondary reconnecting in a loop
multiplies the memory. The shape wanted is an envelope iterator the writer pulls
from; the framing and signing loop already has it.

## Per-answer waste: #25

Eight items, each small, on a path #9e measured at 455 ns (Windows) for the
library's share of one answer. Full detail and boxes are in `TODO.md` #25; the
evidence in brief:

| | finding | measured |
|---|---|---|
| 25a | the answer path walks the zone three times to answer once — `delegation_for`, `name_kind`, `query().is_empty()` (which recomputes `name_kind_of_key` and allocates a `Vec` for a boolean), then `query()` again for the records | `Zone::query` alone 61-69 ns; what `resolve_in_zone` + `add_answer` do 190-215 ns |
| 25b | every TCP reply allocates and zeroes 64 KiB — `to_bytes_within(u16::MAX)` at `main.rs:1119`, `:1267`, `:1625`, and `to_bytes_within_buf` memsets the ceiling each call | 591/632/618 ns against 227/252/255 ns for the same work into a live `[u8]`, three runs |
| 25c | the latency histogram increments every cumulative bucket at or above the sample — eight atomic RMWs for a healthy answer, on shared lines | 46.7 ns against 12.5 ns for bucket-once-and-cumulate-at-scrape, which is what every Prometheus client library does for identical output |
| 25d | canonical ordering allocates a `String` per label per comparison (`reversed_labels`) | `canonical_name_cmp` 302-324 ns, `canonical_sort_key` 176-185 ns, against 52-56 ns allocation-free. `Nsec::covers` calls the first three times |
| 25e | a cache lookup allocates its key: `HashMap<(String, Qtype), _>` has no `Borrow` for a tuple, so `get_validated` folds into a fresh `String` every time | — |
| 25f | the rate limiter takes two global mutexes per datagram; the first only compares a timestamp | — |
| 25g | the "is there anything to fold?" scan — see below | 3.25 → 2.14 ns at 16 octets, **61.1 → 7.9 ns at 200** |
| 25h | `zone::nsec3_covering` allocates a `Vec` to build a range bound | — |

25b is worth one more line, because it is `CLAUDE.md` §13's own finding one caller
short. §13 fixed the 64 KB-capacity `Vec` handed to `send_to`, gave the hot path
`to_bytes_within_buf`, and wired it into the UDP workers (`main.rs:2070`). The TCP
path still calls the allocating form with `u16::MAX`, so it pays the allocation
*and* the memset — and the memset buys nothing, since the caller reads only `..n`.

## The SIMD question, answered with the disassembly

The interesting answer is mostly negative, and the negatives are worth recording
so they are not re-derived.

**Already wide, correctly:**

- `<[u8]>::eq_ignore_ascii_case_chunks::<16>` — 16 bytes per iteration,
  `pcmpeqb`/`por`. So `is_at_or_under`, `names_equal` and the compressor's suffix
  comparison are vectorized already, through `std`.
- `make_ascii_lowercase` inside `ascii_lowered` / `absolute_lowered` —
  `movdqu`/`paddb`/`pminub`/`pcmpeqb`, 32 bytes per iteration.
- `label_starts(...).count()` in `write_name` — vectorized as a `pcmpeqb`+`paddq`
  reduction.
- SHA-1 and SHA-256 reach SHA-NI at run time through `cpufeatures` (`sha1 0.10`'s
  `x86.rs` backend). Nothing to enable, nothing to add.

**The one loop whose shape the code prevents.** `utils::ascii_lowered_cow` and
`absolute_lowered` decide whether they have to copy with
`name.bytes().any(|b| b.is_ascii_uppercase())`. LLVM will not vectorize a loop
whose exit is data-dependent, so the *test* runs one byte per iteration while the
fold it exists to avoid runs thirty-two:

```
72a0:  cmp    %rax,%rbx              ; the scan: one byte per iteration
72a5:  movzbl (%rsi,%rax,1),%ecx
72a9:  add    $0xbf,%cl
72af:  cmp    $0x1a,%cl
72b2:  jae    72a0
...
7360:  movdqu (%r14,%rdx,1),%xmm3     ; the fold it was deciding about: 32/iter
7366:  movdqu 0x10(%r14,%rdx,1),%xmm4
7371:  paddb  %xmm0,%xmm5
7381:  pminub %xmm1,%xmm7
7385:  pcmpeqb %xmm5,%xmm7
```

`write_name` shows the same contrast twice in one function: its `.` scan
vectorizes where it is written as `.count()` and stays scalar where it is written
as a search. Written as a branchless OR-reduction the predicate is 3.25 → 2.14 ns
at 16 octets and 61.1 → 7.9 ns at 200 — and the QNAME's length is the client's
choice, which is the half worth caring about. Three lines, no `unsafe`, no
intrinsics.

**Looks like a SIMD candidate, is not:** base32hex encode and decode (twenty-byte
payloads), the NSEC3 type bitmap (tens of bytes, and `bitmap_has_type` already
skips whole windows), and the wire parser (branch-dense per-record state, no
loop to widen).

**`lto = "fat"` + `codegen-units = 1`: measured, no verdict.** Zone lookup
195 → 190 ns; serialization worse in the same run; run-to-run variance larger than
either. Recorded because the next person will think of it, not because it is
recommended against.

## Helpers written twice, and hand-rolls with a standard spelling: #26

The §7 family again, and the reason none of them turned up in #13b's sweep is
that finding these needs reading rather than grepping for a name.

| | what | note |
|---|---|---|
| 26a | two `fn hex`, byte-identical | `rfc5011.rs:778`, `zone_writer.rs:324` — and both are `format!("{b:02X}")` **per byte**, one heap allocation per output byte. `rdnsctl dump` of a signed zone runs it over every DS digest |
| 26b | two base32hex decoders that disagree | `zone::parse_base32_hex` (`:619`) does `to_uppercase()` — the Unicode fold §8 forbids — and a linear `position()` over the alphabet per character; `dnssec_denial::base32hex_decode` (`:226`) is a range match. They also disagree about `=` padding |
| 26c | two `parse_hex` | `rfc5011.rs:764`, `zone.rs:604`; the second collects a `Vec<char>` to index pairs |
| 26d | two `fn base64` | `rfc5011.rs:781`, `zone_writer.rs:320`, identical wrappers |
| 26e | `ancestors_of` / `ancestors` allocate a `String` per ancestor | `zone_signer.rs:785`, `resolver.rs:482`. Ancestors are suffix slices. **This is the function A3 above named as "the next one to look at" once A3 was fixed** — A3 was fixed, this was not |
| 26f | `resolver::normalize` allocates unconditionally | `utils::absolute_lowered` borrows the common case. A straggler of #13b |
| 26g | `canonical_name_cmp` hand-rolls `Iterator::cmp` | `for i in 0.. { match (a.get(i), b.get(i)) … }`, closed with `unreachable!()` |
| 26h | `utils::record_type_name` returns `String` for a constant | thirteen mnemonics, each `"A".to_string()` |
| 26i | a bitmap byte walked bit by bit | `dnssec_denial.rs:189`; `trailing_zeros` is the idiom |
| 26j | A4 had never been fixed — **done 2026-08-04** | the struck row at the top of this file, and the test that now holds the whole message |

## Checked and found nothing wrong with

- **`cache::evict_oldest`.** The `select_nth_unstable` rewrite is right, and the
  tie handling is the part that matters: expiries are whole seconds, so a strict
  `retain` would empty the cache instead of halving it. The comment says so.
- **`Zone`'s index and `has_wildcards`.** The #11/#22 work holds up — a miss is
  three hash lookups and no allocation, and the wildcard skip does what its
  measurement claimed.
- **`Serial`, `Ttl`, `Qtype`/`Rtype`/`Class`.** Re-checked from the algorithmic
  side; nothing to add to the first review's list.
- **`security::ResponseLimiter` and `TransferAcl`.** Bounded, with the direction
  of failure written down.
- **The wire parser's bounds**, from the other direction: nothing in the hot paths
  contradicts what `no_input_panics` covers.

## What this pass did not audit

So it is not read as broader than it is: the crypto primitives, the `#[cfg(unix)]`
half (`control.rs`, the mode checks), `update.rs` and the journal beyond their
data structures, and the 22 `.lock().unwrap()` / 42 `let _ =` sites §16 counted
and nobody has read. No test was run for this review — it is a reading and a set
of measurements against an unmodified tree.
