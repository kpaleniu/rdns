# Working on rdns

Orientation lives in `TODO.md`: what each crate is, what is open (each item is
`docs/issues/NNN.md`), how to run the binaries, how to verify against
dnspython, and four environment traps. Read it before planning.

These are rules. Each section links to its lesson in `docs/LESSONS.md`: the
defect behind the rule, with dates and counts. Suspicion belongs where
confidence is highest: what broke here broke where the problem looked simple —
the plain answer path, error handling, integer widening, the operational shell.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets   # must be clean, no exceptions
cargo doc --workspace --no-deps          # must be clean
cargo fmt --all                          # before every commit (§12)
```

- `cargo doc`: a doc link to an item that does not exist is a false claim (§4)
  the compiler checks for free. `--no-deps`: dependency warnings bury ours.

Prefer using LSP tools (rust-analyzer) over grep/file search for code navigation,
finding definitions, and symbol queries in Rust files.

---

## Writing comments

Before writing a comment, in order:

1. The code is clear without it: write nothing.
2. It is a reason (a constraint, the RFC section, the rejected alternative and
   why it fails): write that. Present tense. `//`: at most two lines. Doc
   comment: a summary line and at most one short paragraph of contract.
3. Anything else: the commit message.

Never in a comment: "used to", "was", "now", "no longer", "previously",
"until #N", "since #N", "watched failing", a strike-through, a list of past
bugs, a measurement. Tests say what they check: "Fails if the zone is
installed without writing the file."

Cite RFC sections and these rules freely. Cite a closed item only where its
file holds what the claim rests on: a measurement, a rejected design, a
comparison with another implementation. A pointer to where a fix landed is
history; `git log` finds it.

Bad:

```rust
// Four ways to answer and one tail, because three of them used to `return`
// past it: `record_dnstap` was reachable only through `finish`, so a capture
// held no UPDATE and no transfer while `--dnstap` says "every answered
// request" ...
```

Good:

```rust
// Every branch yields the bytes sent, so `answer` records dnstap once for all.
```

---

## 1. A test that agrees with the code is not evidence

[Lesson](docs/LESSONS.md#1)
- Cite the RFC section that says it, not one nearby that sounds relevant, and
  quote enough to show it was read.
- Prefer the RFC's own worked example as the test case.
- Show a new regression test failing against the old behaviour: revert the
  fix, run it, watch it fail, restore.
- A test that has to change when behaviour is fixed encoded the bug. Say so in
  the commit.
- Judge output with the reader: `verify_rrset` / `proves_nxdomain` /
  `proves_nodata`, and dnspython for anything cryptographic. Our parser
  agreeing with our serializer proves nothing.
- A green suite on one platform is not a green suite. Windows does not compile
  `#[cfg(unix)]`: before committing a change to a cfg-gated file, run the suite
  and clippy on Linux too. A test count that differs by platform is the tell.
- Say which platform a verification ran on.

## 2. Wire input: check every length, and never widen a signed field

[Lesson](docs/LESSONS.md#2)
- Every length off the wire is attacker-chosen. Check it before slicing.
- `as` on a wire value is a bug until proven otherwise. Clamp a signed field at
  the parse boundary (`.max(0)` before widening), ceiling the result, and
  `saturating_add` onto timestamps.
- Bounds and clamps belong at the boundary, once. Make the invariant
  unrepresentable rather than re-asserting it per site.
- A catch-all variant carries the value it caught: `Other(u16)`, with
  hand-rolled `from_u16`/`to_u16`, total and mutually inverse.
- `unwrap_or` on a wire field is the smell: ask what the fallback means on the
  wire. No `FromPrimitive`; its `Option` invites the `unwrap_or`.

## 3. Error types: typed in the library, `anyhow` in the binaries

[Lesson](docs/LESSONS.md#3)
- `rdns` returns typed errors from `rdns::error`. The failure kind is the
  answer: FORMERR, NOTIMP, SERVFAIL, insecure.
- `rdnsd` and `rdnsr` use `anyhow::Result` with `.context()`.
- Never `Box<dyn Error>` (no context, not `Send + Sync`, `Debug` mangles the
  message). Never `Result<_, String>` (not an `Error`; `?` will not lift it).
- Add a variant when a caller would branch on it, not when a message differs.
  Check with a `grep` for a match on the variant. Example:
  `ResolveError::BudgetExhausted`, an operational signal.
- A `String` inside a variant is fine when the category is the typed part.
- Assert on the variant, not the message:
  `matches!(err, WireError::TooLong { what: "a label", .. })`.

## 4. Errors: degrading quietly is worse than failing

[Lesson](docs/LESSONS.md#4)
- Serving a wrong answer is worse than serving none.
- Never turn an error into an empty value. Justify each `unwrap_or_default`,
  `unwrap_or_else(|_| ...)` and `let _ =` on anything fallible, or delete it.
- All-or-nothing means all: one zone file that fails to parse fails the set.
- A doc comment claiming an invariant is a claim to verify.
- Never state what a function does without opening it, ours or a third
  party's. Reading the docs is not reading the code.
- Check what BIND, Knot, PowerDNS and NSD do, and quote them.
- Prove an operational fix by provoking the failure. A change about what
  happens to a process needs a test that involves a process.
- When one function answers several questions, separate them before fixing one.
- "Missing state degrades, never crashes" is right for a cache and wrong for
  anything with teeth.
- In a receive loop, ask what a remote party can provoke; it must not end the
  loop. See `rdns_transport::recv_error_is_transient`.

## 5. State keyed on something an attacker chooses must be bounded

[Lesson](docs/LESSONS.md#5)
- Every per-peer table has a `max_tracked` and a policy for the bound. Follow
  `security::ResponseLimiter`.
- Decide which way the bound fails and write down why.
- A bound plus a visible shortfall counter (`untracked_sources`) beats per-key
  counters over an unbounded key space.
- CPU is chosen too. Count every multiplier the client controls and time the
  worst case rather than reading the loop.

## 6. Wall-clock time is not monotonic

[Lesson](docs/LESSONS.md#6)
- Every subtraction of two timestamps is `saturating_sub`. No exceptions.
- Never panic while holding a lock. On a query path, prefer
  `let Ok(guard) = m.lock() else` with a commented failure decision.
- An interval is measured with `Instant`.

## 7. Duplicated logic drifts; the second copy is where the bug lives

[Lesson](docs/LESSONS.md#7)
- Move shared reasoning into `rdns`, make every caller use it, and put the
  reason in the doc comment: the reason stops the next copy.
- An early `return` past a shared epilogue is a missing copy. Adding a `return`
  to a function with a tail means asking what the tail did.
- Two functions building the same kind of message are one function with a
  parameter.
- Reuse the parser you already have for the same syntax: address lists go
  through `security::TransferAcl`.

## 8. DNS rules this codebase has already got wrong

[Lesson](docs/LESSONS.md#8)
- Try RFC 1034 §4.3.2's four cases in order: referral, data, alias, no data.
  See `rdns::zone_answer`'s `resolve_in_zone`.
- AA is clear on a referral (RFC 1035 §4.1.1; RFC 8020).
- A name with descendants exists: NODATA, not NXDOMAIN (RFC 4592 §2.2.2).
- Wildcard synthesis reaches any depth and stops at the closest encloser
  (RFC 4592 §3.3.1, §3.3.2). An existing name, empty non-terminals included,
  ends the search (§4.4). None at or below a delegation (§2.2.1).
- A negative answer's SOA TTL, and its RRSIG's, is `min(MINIMUM, the record's
  own TTL)` (RFC 2308 §3).
- Case folding is ASCII-only (RFC 4343): `text_names::ascii_lowered`.
- REFUSED, not NXDOMAIN, for a zone we do not serve.
- A response is not a question: test QR at the socket on both daemons.
  `validation::Request` is the only door for anything a stranger can send.
- Echo the client's opcode; NOTIMP for anything unimplemented (RFC 1035 §4.1.1).
- A negative answer's proof is about the end of the CNAME chain (RFC 4035 §5.4).
  A chain ending without the queried type is negative with answers present.
- Each negative answer owes its own proof: NODATA, wildcard NODATA, NXDOMAIN
  and a referral differ. See `dnssec_answer`.
- A delegation's NS RRset carries no signature; its NSEC lists `NS RRSIG NSEC`.
- A denial record's bitmap lists every type present at its name (RFC 5155 §7.1,
  RFC 4034 §4.1.2). Snapshot-then-mutate is the bug pattern.
- Re-signing is a new version of the zone: the served serial moves.
- Spread RRSIG expiry over a fraction of the window, deterministically per
  (owner, type), never past the requested validity.
- Re-sign at a third of the validity remaining.
- A QTYPE is not an RTYPE and a QCLASS is not a CLASS (RFC 1035 §3.2.3,
  §3.2.5). QTYPE=ANY gets one of RFC 8482 §4's shapes.
- A class we do not serve is REFUSED (RFC 1034 §4.3.2 step 1).
- DNSSEC records are not answer data unless DO asked (RFC 4035 §3.1.1), ANY
  included.
- QNAME minimisation: a ceiling of 10, probes ask for A (RFC 9156 §2.3).

## 9. Async, locks, and the work done under them

[Lesson](docs/LESSONS.md#9)
- An `async fn` with no `.await` is blocking. Use `spawn_blocking` and say why.
- Compute under the read lock, apply under the write lock.
- Do not hold a `std::sync::Mutex` across an fsync, or anything else that
  yields in spirit but not in type.
- Check admission before spawning, not inside the spawned future.
- Dropping a `JoinHandle` detaches the task. Use `JoinSet`; `join_next` is
  cancel-safe in a `select!`.
- Separate watching for the stop from holding the thing open: `Stop` and `Busy`
  in `rdns::shutdown`. Hold `Busy` across work, never across a sleep.
- The drain is an `mpsc` nobody sends on. Its receiver's owner drops its own
  sender first.
- Cancel-safety decides where a `select!` arm may go: `recv_from` and `accept`
  are cancel-safe, `read_exact` is not, so TCP checks shutdown between messages.

## 10. Benchmarks and measurement

[Lesson](docs/LESSONS.md#10)
- A wall-clock floor gets a factor of ten of headroom.
- Never lower a floor without first proving why it moved. Restore it when the
  cause is fixed, with what it measures written beside it.
- Prefer a deterministic assertion: an allocation count, a capacity, a pointer
  identity, a table length, a count of queries a mock server received.
- "Cost must not grow with N" is a ratio: time a batch cold, do N units of
  work, time it again, assert the ratio.
- A ceiling with a factor of a hundred of headroom is a tripwire for a
  complexity class.
- Say what a test is a regression for, and what it is not.
- Profile before optimising, and record the negative results.
- An exact count is exact: tally per thread (`Counting`), hold the mutex for
  the whole test, call the function once before measuring, check stability.
- A `#[global_allocator]` test goes in its own `tests/` file.

## 11. Commits and `TODO.md`

[Lesson](docs/LESSONS.md#11)
- Commit messages: imperative subject line, then reasoning, RFC citations, and
  how it was verified. Terse bullets. No diff narration, no machine (§20).
- No new READMEs, design documents or doc-comment essays unless asked for by
  name.
- `TODO.md` carries one line per finished item, pointing at the commit.
- A wrong claim in `TODO.md` or an issue file is struck through and corrected in
  place with a pointer, its reasoning kept. A status line is overwritten.
- Issue numbers are stable: `docs/issues/NNN.md` open, `docs/closed/NNN.md`
  closed. Move the file, never renumber. Cite as `TODO.md #N`.
- Strike-throughs are for `TODO.md` and issue files. Never in code.

## 12. Formatting: `cargo fmt --all`, every time

[Lesson](docs/LESSONS.md#12)
- `cargo fmt --all` before every commit; `--check` asks without touching. Stock
  rustfmt, no `rustfmt.toml`.
- rustfmt touches neither comments nor string literals. Wrap prose by hand at
  ~80 columns; keep `\` continuations intact.
- A reformat is its own commit, listed in `.git-blame-ignore-revs`. Once per
  clone: `git config blame.ignoreRevsFile .git-blame-ignore-revs`.
- After an edit made by a script, this prints nothing (double-encoded UTF-8):

```sh
git ls-files -z | LC_ALL=C xargs -0 grep -na $'\xc3[\xa2-\xaf]\xc2[\x80-\xbf]\xc2[\x80-\xbf]'
```

## 13. Size a buffer for what you will send, not for what the protocol allows

[Lesson](docs/LESSONS.md#13)
- `Vec::truncate` does not release capacity. A UDP caller sizes for its EDNS
  payload; only TCP and transfers want `u16::MAX`.
- Give the hot path its own buffer: `to_bytes_within_buf` is the primitive,
  `to_bytes_within` the allocating wrapper.
- When the buffer is the limit, "does not fit" is `WireError::Truncated` from
  the writer: catch that one, propagate the rest. Test exactly `max_len` bytes.
- Do not store one owned copy per derived key: one arena, ranges into it.
- Before writing a loop over a map, ask what the map is keyed by.
- Evict with `select_nth_unstable`, not `min_by_key` in a loop, and check ties.

## 14. A limit with no flag is a limit nobody has reviewed

[Lesson](docs/LESSONS.md#14)
- State a rate in the operator's unit:
  `RateLimitConfig::per_second(rate, burst)`.
- Silence can be the right answer and still has to be visible: print the
  effective policy at startup, count what is dropped.
- Every knob has an escape hatch and an off switch.
- Floor a knob that can turn the server off.
- Group policy parameters into a struct past a few.
- A dependency only ever configured is a liability. Count what it does at run
  time.
- Prefer the shape the operator already runs: a Prometheus scrape, no second
  HTTP stack.
- A counter's name is a claim about what it counts. Count what an operator
  pages on.
- Histograms in base units (seconds), with buckets where the system falls.
- Expose an instant, not an elapsed time.
- A gauge with no answer is omitted, never zero.
- A withdrawn thing stops being reported: every path that stops serving
  something forgets it.
- Update a gauge where the fact changes, not where it is read.
- Escape label values.

## 15. Configuration

[Lesson](docs/LESSONS.md#15)
- `deny_unknown_fields`, always.
- Two sources for one setting is an error, not a precedence rule.
- `Option` per field for an override: absent means inherit.
- A derived global follows the extreme, not the default.
- Refuse a secret file others can read, and say where the check does not apply
  (Windows).
- Reuse the parser the flags use (`TsigKey::parse`).
- A dry run exits before the first thing that binds, spawns or writes, after
  everything that can fail a deploy: parse, secrets, load, sign, verify.
- Every flag is parsed above that exit, never in an argument expression below
  it.
- Pay for a parser; do not pay for a stub.

## 16. Authentication is not authorization

[Lesson](docs/LESSONS.md#16)
- "Who are you" and "what may you do" are two questions. A verified MAC answers
  the first.
- Authorize against the most specific thing the request names: a transfer
  against the apex.
- Check before doing the work, not before sending it.
- Ask the object that already knows: the `TsigSession`, not a key name.
- An authenticated refusal is signed (RFC 8945 §5.3).
- Do not silently narrow a default that would break a working deployment; make
  the wide case visible.
- Where a new field is ambiguous, require the disambiguating one.

## 17. Fix it in the type, or fix it again next month

[Lesson](docs/LESSONS.md#17)
When a fix is about to be a check, ask what would make the check unnecessary.
Usually a newtype, usually free. The smells:

- A primitive that means two things depending on a sibling field.
- Two `u16`s that name different spaces and compare with `==`.
- A number whose ordering is not the ordering of the numbers: no `PartialOrd`
  (`Serial::is_newer_than`).
- `unwrap_or` on the parse of a wire field (§2).
- The same normalization written per module (§7).
- An invariant asserted in a doc comment: make it unrepresentable, or say why
  it cannot be.
- A `pub` field beside a checking constructor. Seal it in a module small enough
  to be the boundary.

Limits:

- Measure "zero-cost": `cargo test -p rdns --test allocations -- --nocapture`
  and `cargo bench -p rdns --baseline`. A count that rises carries its reason.
- Not everything wants a type: would a caller branch on the distinction?
- A type does not settle a question it inherits. Settle the meaning first.

Review a plan the way the code gets reviewed: a plan is a claim about the code.

## 18. Finish the sweep, or give the remainder a number

[Lesson](docs/LESSONS.md#18)
- Count the instances before fixing one. Fix all of them, or name in the same
  sentence which are left and under which number.
- A sentence naming remaining work is a `TODO.md` item, or it is deleted.
- Dead code is a finding: file it, then delete it.
- Never write a number you did not just read.
- File what you saw; name a remedy only if you checked it.
- "Done" is the whole request. Finish what does not depend on the big part;
  file that part with the measurement that lets somebody else start.
- Before committing, read the request back sentence by sentence and answer
  each with a diff or a number. Report in that shape.

## 19. Take the measurement that could refute the finding

[Lesson](docs/LESSONS.md#19)
- A measurement that agrees with your finding is not evidence. Take the one
  that could make it wrong before filing.
- A claim about a type is a claim about its call sites.
- When the code carries a stated reason, the finding answers it. No stated
  reason is itself the finding.
- "Missed" and "chosen" are different findings; say which one you verified.
- When a design choice has two or three shapes, build them. Keep the patches;
  put the numbers in the row.

## 20. Write about the project, not about the box it was built on

[Lesson](docs/LESSONS.md#20)
- Test: a fresh clone, a year on, somebody else's machine. If the sentence
  would not be true and about the code there, it goes in `CLAUDE.local.md`.
- A measurement keeps its platform (§1); it does not keep its host.
- "X is installed" is never a project fact. Name the tool and the command.
- Do not cite `CLAUDE.local.md` as the source of a claim.
- Correcting a stale setup fact: state the rule; the detail goes untracked.
- This applies to every tracked file and commit, `TODO.md` hardest.

---

## Agent skills

### Issue tracker

Issues are numbered files, open in `docs/issues/NNN.md` and closed in
`docs/closed/NNN.md`; `TODO.md` lists which are open. See
`docs/agents/issue-tracker.md`.

### Triage labels

The five canonical roles under their own names, as markers rather than labels.
See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root, both created
lazily by `/domain-modeling`. See `docs/agents/domain.md`.

@CLAUDE.local.md

The machine: paths, the Linux image and its invocation, what is installed, why
nothing may be pushed, port 53 here. Untracked; no tracked file depends on it.
