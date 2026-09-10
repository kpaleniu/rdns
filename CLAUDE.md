# Working on rdns

Orientation lives in `TODO.md`: what each crate is, what is open, how to run the
binaries, how to verify against dnspython, and four environment traps. Read it
before planning.

@CLAUDE.local.md

That import is the *machine*: paths, the Linux image and its exact invocation,
what is installed, the git remote and why nothing may be pushed, and why port 53
does not behave here. It is untracked, so a clone without it loses nothing but
convenience — every tracked file states its own conclusions and none depends on
it being present.

This file is the list of mistakes this codebase has made, written as rules. A
five-way review in July 2026 found 48 defects; they were a dozen patterns,
repeated.

The hard work is right — DNSSEC verification, TSIG, NSEC3 iteration caps,
RFC 5011, serial arithmetic all reviewed clean. Everything that broke, broke
where the problem looked too simple to get wrong: the plain answer path, error
handling, integer widening, the operational shell. Suspicion belongs where
confidence is highest.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets   # must be clean, no exceptions
cargo doc --workspace --no-deps          # clean since 2026-09-09; keep it that way
cargo fmt --all                          # before every commit — see §12
```

`cargo doc` is here because a doc comment naming a function that does not exist
is §4's "a claim to verify", and this is the one such claim a compiler checks
for free. Unrun, it had accumulated sixteen: seven links that resolved to
nothing — two near-misses for a real name (`DnsMetrics::render` for
`to_prometheus_format`), one function #37b had moved, two items in another
module, one *parameter* name, and one RFC quotation whose `return[s]` was read
as a link — and nine from a public page to a private item, which is the shape
§37 makes more of. `--no-deps`, because the dependencies' warnings are not ours
to fix and would bury ours.

---

## 1. A test that agrees with the code is not evidence

The suite was green at 590 tests while `rdnsd` could not serve a CNAME, a
delegation, or a two-label wildcard: same author, same understanding, same
sitting. Two tests asserted the wrong behaviour and cited an RFC section that
says nothing about the subject.

- Cite the section that says it, not the one nearby that sounds relevant. The
  wildcard bug lived for months behind "a wildcard covers one label and only one
  (RFC 4592 §2.1.1)". §2.1.1 is about `*` in zone-file *syntax*; §3.3.2 has a
  worked example synthesizing two labels down. Quote enough of the section in
  the comment to show it was read.
- Prefer the RFC's own worked example as the test case. It is the one input the
  spec has already committed to an answer for.
- Show a new regression test failing against the old behaviour: revert the fix,
  run it, watch it fail, restore. Two probe tests for the RDLENGTH panic were
  written and discarded during review; the panic survived.
- Expect to change tests when fixing behaviour, and say so in the commit. A test
  that has to change is a test that encoded the bug.
- Judge output with the reader, not by inspection. Signed answers go through
  `verify_rrset` / `proves_nxdomain` / `proves_nodata`, and anything
  cryptographic through dnspython as well. Our parser agreeing with our
  serializer proves nothing.
- **A green suite on one platform is not a green suite.** This repo is developed
  on Windows, where `#[cfg(unix)]` code is never compiled: `rdnsd/src/control.rs`
  had an unimported `Serial` and two `Served` initializers missing a field, and
  `cargo test --workspace` reported 793 passing for several commits over a module
  that did not build. CI is Linux and had been red the whole time. The gap is
  visible in the number — 793 here against 809 there — so a test count that
  differs by platform is the tell. **Before committing anything that touches a
  cfg-gated file, run the suite and clippy on the other side** — the exact
  invocation for this machine is in `CLAUDE.local.md`, which is untracked because
  it is a fact about one box rather than about the code.

  And when reporting a verification, say which platform it ran on. "Clippy clean"
  that means "clean on the half of the tree this OS compiles" is the same claim
  as a comment asserting an invariant nothing checks (§4).

## 2. Wire input: check every length, and never widen a signed field

- Every length off the wire is attacker-chosen. RDLENGTH was sliced as
  `&rest[..rdatalen as usize]` unchecked, in a parser where `read_be!`,
  `Label::try_from_bytes` and `parse_options` all check theirs. Pre-auth remote
  panic on both transports, in `rdnsr` with no validator in front of it, and in
  a secondary's replication task — which is not restarted, so the zone silently
  stopped refreshing until EXPIRE.
- `as` on a wire value is a bug until proven otherwise. `ttl` is `i32` off the
  wire; `-1 as u64` is `u64::MAX`, which `min` picked as the smallest TTL and
  pinned a cache entry for the life of the process. Clamp at the parse boundary
  (`.max(0)` *before* the widening), ceiling the result, `saturating_add` onto
  timestamps.
- Bounds and clamps belong at the boundary, once. Three modules clamped TTLs and
  one did not; the two call sites feeding that one clamped on the way in, so a
  check that existed four times over was still missing where it mattered. Make
  the invariant unrepresentable rather than re-asserting it per site.
- A catch-all variant must carry the value it caught. `QueryClass` had none, so
  the parse was `from_u16(qclass).unwrap_or(QueryClass::None)` — and `None` is
  not a sentinel, it is 254, RFC 2136's real NONE class. QCLASS 99 went back out
  as 254, so the echoed question was not the question asked. `ResponseCode` had
  the mirror image: an `Unknown = 65535` sentinel that `to_bytes` wrote as 0, an
  unrecognized *failure* relayed as NOERROR. Write `Other(u16)` with hand-rolled
  `from_u16`/`to_u16`, total and mutually inverse. `unwrap_or` on a wire field
  is the smell; look at what the fallback means on the wire.
- A signed catch-all is worse than a `String`. Both of the above came from
  `num_derive`'s `FromPrimitive`, which hands you an `Option` and invites that
  `unwrap_or`. A data-carrying variant costs twenty lines of match and buys a
  conversion with no failure case to paper over.

## 3. Error types: typed in the library, `anyhow` in the binaries

- `rdns` returns typed errors: `WireError`, `RequestError`, `ZoneError`,
  `DnssecError`, `TransferError`, `ResolveError`, `ConfigError`, all in
  `rdns::error`. The failure kind *is* the answer — truncated packet is FORMERR,
  unsupported label is NOTIMP, a signature that does not verify is SERVFAIL, an
  algorithm we cannot read is insecure. A string cannot tell them apart.
- `rdnsd` and `rdnsr` use `anyhow::Result` with `.context()`. Their only consumer
  is a human reading a log line.
- Never `Box<dyn Error>`, never `Result<_, String>`. `Box<dyn Error>` is `anyhow`
  without context chaining or `Send + Sync`, and its `Debug` renders a multi-line
  message as an escaped Rust literal — `main` prints `Err` with `Debug`, so the
  operator gets it unreadable. `Result<_, String>` does not implement `Error`, so
  `?` will not lift it into either.
- Add a variant when a caller would branch on it, not when a message differs.
  `TransferError::Timeout` exists because a secondary retries a timeout and gives
  up on a malformed transfer; `ResolveError::BudgetExhausted` because the
  NXNSAttack defence firing is an operational signal, not a lookup failure. A
  variant nobody matches on is a `String` with extra syntax.
- A `String` inside a variant is fine when the *category* is the typed part. The
  structural ways a message can be malformed are open-ended, and dropping the
  text makes a bad packet undiagnosable.
- Assert on the variant, not the message:
  `matches!(err, WireError::TooLong { what: "a label", .. })`, not
  `err.to_string().contains("label length")`. A dozen tests here were the second
  kind.

## 4. Errors: degrading quietly is worse than failing

Serving a wrong answer is worse than serving none. Every finding in this class
left the process healthy with nothing alerting.

- Never turn an error into an empty value.
  `enumerate_zone_files(dir).unwrap_or_default()` made an unreadable directory
  look like an empty one: server up, listening, zero zones, REFUSED for every
  name it was authoritative for. Grep `unwrap_or_default`,
  `unwrap_or_else(|_| ...)` and `let _ =` on anything fallible; justify each in a
  comment or delete it.
- All-or-nothing means all. A zone file that fails to parse must not be dropped
  while the rest load — collect the errors and fail the set. Otherwise one typo
  plus a deploy SIGHUP is a lame delegation with 39 green dashboards.
- A doc comment claiming an invariant is a claim to verify. `Reloading::load`
  said "nothing is installed unless the whole set comes through". It did not
  hold.
- Never state what a function does without opening it. The fix for the
  unreadable-directory bug was landed claiming `enumerate_zone_files` returned
  `Ok(empty)` for an empty directory. It returned `Err`. The claim went into the
  commit message, the doc comment and `TODO.md` unread, and a secondary pointed
  at an empty directory refused to start — no test covered it, so a green suite
  stood in for evidence (§1 from the other direction).

  It happened again with graceful shutdown, and about a *third party's*
  function: `tokio::signal::ctrl_c()` was used as the whole Windows stop handler
  under a comment asserting it also covers a console close. It registers for
  `CTRL_C_EVENT` alone; `ctrl_break`, `ctrl_close` and `ctrl_shutdown` are
  separate listeners. A real `CTRL_BREAK_EVENT` mid-AXFR hit the default handler
  and killed the process with `0xC000013A` — the exact failure the change existed
  to fix. Reading the docs is not reading the code, and neither is sending the
  signal.
- Check what the other implementations do, and quote them. The SOA-serial
  question (`TODO.md` #8) sat for weeks and was settled in twenty minutes by
  reading BIND, Knot, PowerDNS and NSD, which converge — on something better than
  either option written down. It also caught a design error pre-ship:
  `max(file, now)` looks right and silently does nothing for a date-style serial,
  which PowerDNS's docs say in five words ("requiring epoch-based backend
  serials").
- Prove an operational fix by provoking the failure, not by reading the diff. The
  three shutdown unit tests passed against the broken signal handler because they
  call `Shutdown::begin()` directly. When a change is about what happens to a
  *process*, the test has to involve a process.
- When one function answers several questions, separate them before fixing one.
  That loader conflated "could the directory be read", "did every file parse" and
  "is it empty" — three questions, three different right answers, one of them
  depending on whether the caller is a secondary. Every fix moved the bug until
  they were pulled apart.
- "Missing state degrades, never crashes" is right for a cache and wrong for
  anything with teeth. Forgetting a secondary's last-contact time is the
  difference between a withdrawn zone and a stale zone served with AA set.
- In a receive loop, ask what a remote party can provoke. `recv_from` returning
  `Err` ended the loop and the process, making a stray ICMP report a remote kill
  switch — and then, because the fix was a list of `ErrorKind`s, an oversized
  datagram was a second one: WSAEMSGSIZE arrives as `Uncategorized` and matches
  no kind. See `rdns_transport::recv_error_is_transient`.

## 5. State keyed on something an attacker chooses must be bounded

Four of five reviewers found the same shape. `QueryStats::queries_by_ip`,
`rate_limited_ips` and `RateLimiter::buckets` grew one entry per source address,
created *before* any validation — one spoofed 12-byte datagram per entry — with
no trimming in two of them.

- Every per-peer table needs a `max_tracked` and a policy for the bound. Follow
  `security::ResponseLimiter`, which had this from the start: the table is
  otherwise the next amplification vector.
- Decide which way the bound fails, and write down why. The rate limiter *allows*
  an untracked source, because failing closed lets one flood deny service to
  everybody. The logger *decays* counts, because heavy hitters are the signal.
- Per-key counters are the wrong shape for an unbounded key space anyway. A bound
  plus a visible shortfall counter (`untracked_sources`) beats a map that is
  quietly a lie.
- Memory is not the only thing they choose. `NsecCache::synthesize` hashed a name
  once per cached record, for two candidate names per label of the QNAME: both
  multipliers were the client's, and one query cost 1 124 ms of CPU with the
  cache's one mutex held for all of it. A bound did exist —
  `MAX_NSEC3_ITERATIONS`, on the *third* multiplier — which is exactly what made
  the other two look like they had one. Count the multipliers, and time the worst
  case rather than reading the loop.

## 6. Wall-clock time is not monotonic

`utils::current_unix_timestamp` is `SystemTime`. An NTP step backwards made
`now - last_refill` underflow: a debug panic with a mutex held, which poisons it,
after which every later call panics and the server stops answering — a clock
correction taking the process off the air permanently. In release it wrapped to
~1.8e19 and silently refilled every bucket.

- Every subtraction of two timestamps is `saturating_sub`. No exceptions.
- Never panic while holding a lock. Prefer `let Ok(guard) = m.lock() else` with a
  commented failure decision over `.lock().unwrap()` on any path a query reaches.
- Anything measuring an interval rather than naming an instant wants `Instant`.

## 7. Duplicated logic drifts; the second copy is where the bug lives

The ICMP predicate existed twice, once per binary, and the oversized-datagram
case was found in one copy. The ASCII-lowercasing helper existed correctly in
`zone` with a comment explaining why, and incorrectly in `cache` without one.

Move shared reasoning into `rdns` and make both call it — and put the *reason* in
the doc comment, because the reason is what stops the next copy being written.

Two shapes that are drift wearing different clothes:

- An early `return` that jumps over a shared epilogue. `make_response` ends by
  mirroring the client's OPT record (RFC 6891 §6.1.1); the NOTIMP branch fifty
  lines above returned first, so the one reply that dropped the client's EDNS was
  the one for an opcode we do not implement. Here the copy is the *absence* of
  one. Adding a `return` to a function with a tail means asking what the tail did.
- A sibling written separately that got it right. `truncated_reply` set AA on a
  reply carrying no data and hardcoded 512 instead of reading
  `udp_payload_size()`; `error_bytes`, twenty lines up, had both correct. Two
  functions building the same kind of message are one function with a parameter.

Reuse the parser you already have for the same syntax. The query-rate exemption
list is addresses and CIDR prefixes, which `security::TransferAcl` already
parses — including the rule that a v4 prefix never matches a v4-mapped v6 peer,
which a second implementation would not have. It grew a `parse_named` so the
error says which list has the typo, and that is the whole cost.

## 8. DNS rules this codebase has already got wrong

Cheap to re-check, expensive to rediscover.

- RFC 1034 §4.3.2 is four cases, tried in order: authority ends here (referral),
  the name has the data, the name is an alias (follow, restart), the name has no
  such data. Getting the first one last is how a parent answers NXDOMAIN for a
  child's names. See `rdnsd`'s `resolve_in_zone`.
- AA is clear on a referral (RFC 1035 §4.1.1). With AA set, per RFC 8020 every
  resolver caches "the whole subtree does not exist".
- A name with descendants exists (RFC 4592 §2.2.2) — NODATA, not NXDOMAIN. An
  RFC 8020 resolver extends NXDOMAIN downwards, taking the zone's own data
  offline.
- Wildcard synthesis reaches any depth and stops at the closest encloser
  (RFC 4592 §3.3.1, §3.3.2). An existing name, empty non-terminals included, ends
  the search (§4.4). No synthesis at or below a delegation (§2.2.1).
- A negative answer's SOA TTL is `min(MINIMUM, the record's own TTL)`
  (RFC 2308 §3), and so is the RRSIG's beside it.
- Case folding is ASCII-only (RFC 4343). `str::to_lowercase` folds U+212A KELVIN
  SIGN into `k`, merging two names that differ on the wire. Use
  `utils::ascii_lowered`.
- REFUSED, not NXDOMAIN, for a zone we do not serve. NXDOMAIN is an assertion we
  have no standing to make, and resolvers cache it.
- A response is not a question. Test QR at the socket on both daemons.
  `RequestValidator` accepts QR=1 on purpose — it is used on both directions of
  the wire — so the check belongs at the socket; otherwise two servers pointed at
  each other, or one spoofed datagram, is a packet loop neither end can see. The
  rule was written down and then omitted from one of `rdnsd`'s two answering
  paths anyway, which is why it is now a type: `validation::Request` is the only
  door and checks on the way through. Reach for it, not
  `DnsMessage::try_from_bytes`, at anything a stranger can send to.
- The opcode is the client's. Echo it (RFC 1035 §4.1.1) and answer NOTIMP to
  anything unimplemented. Hardcoding `OpCode::Query` in a response builder hid
  the missing check.
- A negative answer's proof is about the end of the CNAME chain, not the name
  asked about (RFC 4035 §5.4) — and "is this negative?" is not
  `answers.is_empty()`: a chain ending without the queried type is a negative
  answer with a non-empty answer section.
- Every negative answer owes a specific proof, and they differ. NODATA owes a
  record *at* the name; NODATA through a wildcard owes that record at the
  wildcard plus a denial of the name asked for; NXDOMAIN owes a denial of the
  name and of the wildcard that could have answered it; a referral owes the DS or
  a signed denial that there is one. See `dnssec_answer`.
- A delegation's NS RRset carries no signature — it is the child's data. Its NSEC
  lists `NS RRSIG NSEC`, not `DS`.
- A denial record's bitmap must list every type present at the name it describes
  (RFC 5155 §7.1, RFC 4034 §4.1.2). This makes snapshot-then-mutate a bug
  pattern: `Layout::of` was taken before NSEC3PARAM was added, so the apex NSEC3
  denied a type that was there, and an aggressive-NSEC resolver would synthesize
  that false NODATA for other clients out of its cache.
- Re-signing is a new version of the zone, so the serial has to move. A secondary
  decides whether to transfer by comparing serials; without a bump the replica
  keeps signatures that then expire underneath it. Everyone who signs and *stores*
  signatures does this, and the served serial and the file's serial are different
  numbers, so they cannot collide: BIND's inline-signing serves a number that
  visibly drifts from the file's, Knot takes the field away from the operator.
- Do not give every RRSIG in a zone the same expiration, or "signatures lapsed"
  becomes "the entire zone SERVFAILs at every validator at once". Spread expiry
  across a fraction of the window, deterministically per (owner, type) — random
  jitter reshuffles the slope on every reload and no two servers holding the zone
  agree. Never spread *past* the requested validity: 30 days means at most 30.
- Re-sign with slack. A third of the validity (BIND uses a quarter) leaves room
  for a run to fail, or the server to be down over one, without anything expiring.
- A QTYPE is not an RTYPE and a QCLASS is not a CLASS. The question carries values
  no stored record can hold — ANY is QTYPE 255 and QCLASS 255 — so
  `record_type_code(&r.rdata) == qtype` matched nothing and QTYPE=ANY came back as
  an empty NOERROR plus the SOA: a NODATA for a name with data, and none of the
  shapes RFC 8482 §4 permits. Every comparison of a question field against stored
  data has to ask first whether the field is a *query* value with its own meaning
  (RFC 1035 §3.2.3, §3.2.5).
- A class we do not serve is REFUSED, not answered from the class we do. The class
  was parsed, stored on every record, and never compared, so a CH question was
  answered out of the IN zone — `CLASS=CH` in the echoed question next to
  `CLASS=IN` answers, which is malformed. RFC 1034 §4.3.2 step 1 searches the
  zones *of the question's class*. The zone parser now refuses a non-IN record
  outright, which makes the class-blind index correct rather than untested (§2).
- DNSSEC records are not answer-section data unless DO asked for them
  (RFC 4035 §3.1.1). This is the trap inside "ANY means every type": RRSIG, NSEC
  and NSEC3 are types at the name, so a literal reading hands them to a client
  that cannot read them, duplicates what `answer_signatures` attaches, and makes
  an empty non-terminal in an NSEC-signed zone look like a name *with* data.
- QNAME minimisation needs a ceiling (RFC 9156 §2.3, MAX_MINIMISE_COUNT,
  recommended 10), and the probes ask for A, not NS — §2.3 replaced RFC 7816's NS
  advice with "the QTYPE least likely to raise issues in DNS software and
  middleboxes". Without the ceiling a 34-label reverse-IPv6 PTR spent ~30 round
  trips and exhausted the query budget, failing outright where it should have
  degraded to a full-QNAME query.

## 9. Async, locks, and the work done under them

- An `async fn` with no `.await` is blocking and its signature says otherwise.
  `load_zones_from_source` did `read_dir`, a `read_to_string` per zone, a full
  parse and a full ECDSA signing run on a worker that was also serving queries.
  Use `spawn_blocking` and say why.
- Do not compute under a write lock. Compute under the read lock, apply under the
  write lock. A full zone diff per zone inside one write guard blocks every query
  for the sum of the diffs.
- Do not hold a `std::sync::Mutex` across an fsync, or anything else that yields
  in spirit but not in type.
- Check admission before spawning, not inside the spawned future. Paying a
  `to_vec()`, two `Arc` clones and a task before deciding to drop the packet is
  backwards.
- Dropping a `JoinHandle` detaches the task; it does not cancel it. Both daemons
  had a `tokio::select!` over two handles that dropped the loser, so `main`
  returned while the other transport was still reading and replies were queued in
  per-connection channels. `JoinSet` gives the same first-one-wins shape with both
  tasks owned and joinable, and `join_next` is cancel-safe so it can sit in the
  `select!`.
- Separate "watch for the stop" from "hold the thing open" — `Stop` and `Busy` in
  `rdns::shutdown`. The accept loops hold the signal for the life of the process,
  so one type carrying both would keep the drain open forever and wait out the
  budget every time, looking like it worked while doing nothing. Hold the claim
  across *work*, never across a sleep: a refresh timer is hours long.
- The drain is an `mpsc` nobody sends on. `recv()` returns `None` exactly when the
  last sender clone drops — a counter that cannot be got wrong and needs no
  polling. Whatever owns the receiver must drop its own sender first.
- Cancel-safety decides where a `select!` arm may go. `recv_from` and `accept` are
  cancel-safe. `read_exact` is not, which is why the shutdown check on a TCP
  connection sits between messages, where the peer has committed to nothing.

## 10. Benchmarks and measurement

- A wall-clock assertion with no headroom is a coin toss. Give a floor a factor of
  ten, as `bench_zone_lookup` does.
- Never lower a floor to make a bench pass without first proving why it moved.
  `bench_logger_throughput` went from 45k to 10k, attributed to competing load. It
  was a quadratic in `log_query`, and lowering the floor ratified the regression
  the benchmark had caught. Put it back when you fix the cause, with what it
  measures now written beside it.
- Prefer a deterministic assertion where one exists: an allocation count
  (`dhat::assert_eq!` on `total_blocks`), a `Vec::capacity`, a pointer identity
  (did the reused buffer reallocate?), a table length, a count of the queries a
  mock server was asked. None of them care what else is running.
- "Cost must not grow with N" is a ratio, not a floor. Time a batch cold, do N
  units of work, time it again, assert the ratio — machine-independent, which is
  exactly the weakness that let the `log_query` quadratic be argued away. Old
  code 22.5×, fixed ~1×. See
  `logging::tests::logging_a_query_costs_the_same_however_many_came_before`.
- A ceiling with a factor of a hundred of headroom is a fine test. Filling a
  20k-entry cache twice over takes 0.05 s now and took 6.8 s with the O(n²)
  eviction; "under five seconds" is a tripwire for a complexity class, not a
  performance target, and never fires on a busy machine.
- Say what a test is a regression for, and what it is not. The tie-handling test
  for cache eviction fails against the *naive rewrite*, not the old quadratic,
  which got ties right slowly. Conflating them is how a suite gets credit it has
  not earned (§1).
- Profile before optimising, and record the negative results. The DHAT pass found
  the biggest cost on the query path — `tokio::spawn` at 1,536 bytes per datagram,
  46% of everything a query allocates — which was on nobody's list, and cleared
  one that was: `verify_rrset` against two candidate signatures costs 22
  allocations, so that item is a time problem, not a count problem.
- An exact count that is not exact is worse than a timing, because it looks
  trustworthy. `rdns/tests/allocations.rs` got two numbers wrong first: the DHAT
  profiler is *global*, so guarding only the measurement let other test threads'
  allocations land in the total (4 read as 12, 208 as 1015, varying with
  `--test-threads`) — every test now holds the mutex for its whole body. That was
  not enough, because the threads that allocate are libtest's and no mutex here
  can hold them: CI read 10 for a parse that reads 6 on four machines and passed
  on a re-run of the same commit, so the count is now tallied per thread in front
  of dhat (`Counting`), and dhat supplies only the peak-bytes figures. And the
  first profiled block in a process picks up a one-off, which for a target of zero
  flips on scheduling order; call the function once before measuring. Check counts
  are stable across runs.
- A `#[global_allocator]` applies to the whole binary, so allocation-count tests
  belong in their own `tests/` file.

## 11. Comments, commits, and `TODO.md`

Terse. Facts, not essays. Say why, in as few words as it takes, then stop.

- A comment records why, or why not: the rejected alternative, the bug hit, the
  RFC that forbids the obvious thing. One or two lines. Never restate the code.
- No comment where the code is plain. Deleting a redundant comment is a fix.
- Commit messages: imperative subject line, then reasoning, RFC citations, and
  how it was verified. Terse bullets. Do not narrate the diff.
- No new READMEs, design documents or doc-comment essays unless asked for by
  name.
- `TODO.md` carries one line per finished item, pointing at the commit.
- Do not quietly edit a claim in `TODO.md` that turned out to be wrong. Correct it
  in place with a pointer and leave the reasoning that produced it — that
  reasoning is why the bug happened.
- The numbered sections in `TODO.md` are stable identifiers referenced from the
  code and from each other. Move them, never renumber them.

## 12. Formatting: `cargo fmt --all`, every time

Run it before every commit. Stock rustfmt, no `rustfmt.toml` — the defaults are
the convention. `cargo fmt --all --check` asks whether the tree is clean without
touching it.

This was not done for the first year, and the cost was not ugliness: hand
formatting became load-bearing. A mechanical rewrite of a hundred error call
sites needed a hand-written re-wrapping pass afterwards, because the tree was 558
diffs away from `cargo fmt` and running it would have buried the change under a
workspace-wide reformat.

Two things it does not do:

- It does not touch comments. `wrap_comments` is off and nightly-only, so prose
  is wrapped by hand. rustfmt only re-indents a comment to follow its code. Keep
  prose at 80-ish columns; rustfmt's 100 applies to code.
- It does not touch string literals. `format_strings` is off, so a `\`
  continuation stays where you put it, including the continuation line's
  indentation — which a careless search-and-replace will wreck.

A reformat is its own commit and goes in `.git-blame-ignore-revs`. Mixing one
into a behaviour change makes the diff unreviewable and the blame useless.
Configure git once per clone:

```sh
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

---

## 13. Size a buffer for what you will send, not for what the protocol allows

- `Vec::truncate` does not release capacity. `to_bytes_within` built every
  response in `vec![0u8; u16::MAX as usize]` — 64 KB, zeroed — and truncated it,
  so a 60-byte response was handed to `send_to` holding capacity 65535. Only the
  TCP and transfer paths want `u16::MAX`; a UDP caller knows its EDNS payload
  size. Verified by asserting on `capacity()`, which is exact.
- Give the hot path a way to bring its own buffer. `to_bytes_within_buf` is the
  primitive and `to_bytes_within` the allocating wrapper, so a send loop keeping
  one scratch buffer allocates nothing per response. A third of serialization was
  allocator traffic, and it is not optimizer-erasable: the allocation escapes into
  the socket call.
- When the maximum *is* the limit, the "too long" check moves. Sizing the scratch
  to `max_len` turns "does not fit" from a comparison into a
  `WireError::Truncated` from the writer, which has to be caught rather than
  propagated — and every *other* `WireError` is still a real failure. Test the
  message that is exactly `max_len` bytes.
- Do not store one owned copy per derived key. The name compressor kept a
  `HashMap<String, u16>` filled by `labels[i..].join(".").to_ascii_lowercase()`:
  two allocations per suffix and a byte count quadratic in the label count,
  because every suffix carried its own copy of the shared tail. One lowercased
  copy in an arena plus ranges into it is smaller and faster, and a linear scan
  beats the hash when a message holds a handful of distinct names.
- A scan beside the index that would have answered it. The denial cache kept its
  NSEC3 records in a `BTreeMap` keyed by owner hash and looked them up by walking
  every entry and *re-deriving that key* — a salted, iterated SHA-1 per record,
  and again per candidate name. `matches` was a `get` and `covers` a `range` the
  whole time. Before writing a loop over a map, ask what the map is keyed by.
- Halving a map with `select_nth_unstable` beats `min_by_key` in a loop. Cache
  eviction re-scanned the whole map for *one* victim and cloned its `String` key
  to remove it: O(n²) plus an allocation per removal, under the global lock, ~37
  million iterations per stall at the default size. And check the ties — expiries
  are whole seconds, so a cache filled in one burst has every entry on one value
  and `retain(|e| e.expires_at > cutoff)` empties it instead of halving it.

## 14. A limit with no flag is a limit nobody has reviewed

- State a rate in the unit the operator thinks in. The query limiter was "100
  tokens per 10-second window, burst 20", which reads as a hundred queries and is
  ten a second — below what one busy resolver sends. Hardcoded, no flag, and it
  dropped over the limit silently: no REFUSED, no SERVFAIL, nothing on the wire,
  so the operator blames the network. Measured before the fix: a 60-query burst
  got 20 answers and 40 drops. `RateLimitConfig::per_second(rate, burst)` makes
  the number in the config the number in the head.
- Silence can be the right answer and still needs to be visible somewhere.
  Replying to a rate-limited source is what an amplifier does, so dropping is
  correct — which is why the effective policy is printed at startup and why the
  metrics item (`TODO.md` #9d) finishes this.
- Every knob wants an escape hatch and an off switch. `--query-rate 0` disables
  the limiter; `--query-rate-exempt` takes your own resolvers and the monitoring
  probe. Without it the only way to spare a known-good source is to raise the
  limit for everyone.
- Floor a knob that can turn the server off. A burst of zero refuses every query,
  because a bucket starts full and a full bucket of nothing has no token to spend.
  `per_second` floors it at one: a mistyped flag should be wrong, not fatal.
- Group policy parameters into a struct past a few. `serve` reached eight
  arguments — two `u32`s and two address-shaped things among them — one edit away
  from swapping the response budget for the query rate with nothing to catch it.
  Clippy says so at 7.
- A dependency that is only ever *configured* is a liability, not a feature.
  `init_telemetry` built two OTLP exporters into `let _trace_exporter` /
  `let _metrics_exporter` and dropped them; nothing called it. For that the
  workspace carried `opentelemetry`, `-otlp`, `_sdk`, `tracing-opentelemetry`,
  `tracing` and `tracing-subscriber`, and through them `tonic`, `prost`, `hyper`
  and `h2` — a gRPC *server*. Deleting the module took `Cargo.lock` from 187
  packages to 104. Meanwhile the module with the counters worth paging on was
  referenced only by a benchmark. Count what a dependency does at run time.
- Prefer the shape the operator already runs. DNS shops scrape; an OTLP push
  exporter was the wrong default before it was a broken one. The replacement is
  ninety lines of HTTP over `tokio`'s `TcpListener` — pulling a second HTTP stack
  back in to answer one method on one path would be the same mistake with better
  manners.
- A counter's name is a claim about what it counts. `make_response` called
  `increment_cache_hits` / `increment_cache_misses` on an *authoritative* server,
  which has no cache; they stood in for "found something" and "did not", so the
  dashboard reported a hit rate for a thing with no cache. Count what an operator
  pages on: REFUSED climbing means a zone went missing, SERVFAIL climbing means
  one went wrong, NXDOMAIN is ordinary.
- Histograms in base units, with the buckets the system actually falls in.
  Prometheus convention is seconds. An in-memory zone lookup is tens of
  microseconds, so a histogram starting at 5 ms reports every healthy server as
  identical.
- Expose an instant, not an elapsed time. `time() - x` is the query language's
  job; a "seconds since" computed at scrape time is stale on arrival and goes on
  ageing in the dashboard's cache.
- A gauge must be able to say "no answer". Zero is a value, and for a timestamp it
  is 1970, which fires every staleness alert there is. A zone we are primary for
  has no last-transfer time, and neither has a secondary that has never fetched,
  so those series are omitted. `absent()` is a question the query language can
  ask; a wrong number is not.
- A withdrawn thing must stop being reported, not freeze. A serial gauge left at
  its last value shows a zone nobody serves as perfectly healthy — the exact
  condition the staleness alert exists to catch. Every path that stops serving
  something has to forget it; `rdnsd` has two (startup check, runtime EXPIRE) and
  the second was missed until an unused binding warned about it.
- Update a gauge where the fact changes, not where it is read. Sampling live state
  at scrape time puts the scrape behind whatever lock the state is under — a
  scrape behind a reload and a reload behind a scrape — and the value is still
  only as fresh as the last scrape.
- Escape label values. A stray `"` makes the *rest of the scrape* unparseable.
  Zone names come from a file an operator wrote and RFC 1035 §5.1 allows escapes,
  so "should not contain a quote" is not "cannot".

## 15. Configuration

- `deny_unknown_fields`, always. A mistyped key that is silently ignored is a
  setting the operator believes is in force and is not. `require-signd = true` has
  to fail at startup with a line number, not serve unsigned zones quietly.
- Two sources for one setting is an error, not a precedence rule. `--config` and
  `--port` together is refused. Every precedence rule is one somebody has to
  remember at 3am, and the failure is silent because both values are valid.
  Refusing costs one restart.
- `Option` per field for an override, not a whole struct. In `[zones.*]` absent
  means *inherit*, not "the default": setting `nsec3` for one zone must not
  silently reset that zone's validity to thirty days.
- A derived global follows the extreme, not the default. The re-signing interval
  follows the *shortest* validity of any zone — a seven-day zone among thirty-day
  ones is the one that expires if the timer runs on the global number.
- A secret in a file is only better than a secret in `argv` if the file is
  private, so check the mode and refuse a readable one. A key directory restored
  from backup as 0644, or `chmod -R`'d by a deploy script, is the ordinary way a
  private key stops being private. Say out loud where the check does not apply:
  Windows has no equivalent, and "the permissions were checked" must not be a
  claim that is true on one platform only.
- Reuse the parser the flags use. The config builds `[alg:]name:secret[:zones]`
  strings and hands them to `TsigKey::parse` rather than constructing keys, so the
  two paths cannot disagree (§7).
- A dry run has to run everything that does not bind a socket. `--check-config`
  returns after the config parsed, secrets were read and mode-checked, every zone
  loaded, every zone signed and every signature verified. Parse-and-stop passes
  for the failures that actually break a deploy.
- Pay for a parser; do not pay for a stub. Nine crates for `toml` + `serde` is
  proportionate three commits after deleting eighty-three for an exporter that
  never ran. The rule is not "no dependencies", it is "no dependencies that do not
  do anything" — and a hand-rolled TOML subset that misreads a config is the worst
  outcome available.

## 16. Authentication is not authorization

`answer_transfer` asked whether a TSIG *session existed* and called that
permission, so holding any key in the keyring transferred any zone and bypassed
`--allow-transfer` entirely. Hand a per-customer key to one partner and you have
handed them every zone on the server.

- "Who are you" and "what may you do" are two questions. A verified MAC answers
  the first and says nothing about the second.
- Authorize against the most specific thing the request names. A transfer hands
  over a whole zone, so the check is against the *apex*; a rule matching anything
  less specific authorizes more than it names, which is why a child of a listed
  zone is refused.
- Check before doing the work, not before sending it. The point is that the zone
  is never looked up and the messages are never built.
- Ask the object that already knows. The check hangs off the `TsigSession` rather
  than looking the key up by name: the session *is* the answer to "which key was
  this", and a key name is attacker-supplied until the MAC verifies.
- An authenticated refusal is still signed (RFC 8945 §5.3). Not doing so was a
  second, older bug on every error path of the transfer, with the usual symptom —
  the client cannot tell a refusal from a tampered reply. dnspython reported the
  unsigned REFUSED as "the TSIG record is malformed", sending the reader after a
  key mismatch that does not exist.
- Do not silently narrow a default that would break a working deployment, but make
  the wide case visible. An unscoped key still transfers everything, because
  changing that means a version bump stops every transfer with no warning; the
  startup banner prints what each key may transfer. Narrowing belongs with the
  config file, where the operator edits the whole policy at once.
- Where a new field is ambiguous, require the disambiguating one. A zone list as a
  fourth colon-separated field collides with `[alg:]name:secret` at three fields,
  so a zone list requires the algorithm spelled out. Failing at startup beats
  guessing whether the first field looks like an algorithm name, and beats reading
  a zone list as a base64 secret.

---

## 17. Fix it in the type, or fix it again next month

§2's "make it unrepresentable", promoted to a rule because this repo ran the
controlled experiment by accident. Two defects fixed by changing a *type* —
`QueryClass::Other(u16)` and `ResponseCode::Other(u16)`, each replacing a sentinel
that could not carry what it stood for — have not recurred. Every defect in the
same class fixed at a *call site* has: the TTL clamp is written out by hand
fourteen times, the QTYPE-vs-RTYPE comparison is right in `zone::of_type` and
wrong twice in `resolver.rs`, and the ASCII case fold exists in nine places
including one in the public API doing the Unicode fold §8 forbids. Same authors,
same care, same review. The difference is where the invariant lives.

When a fix is about to be a check, ask what would have to be true for the check to
be unnecessary. Usually the answer is a newtype, and usually it is free.

The smells, all currently in this tree (`TODO.md` §13 plans the staged removal,
with the measurements each stage has to hold):

- A primitive that means two things depending on a sibling field. OPT's CLASS is a
  UDP payload size and its TTL is a flags word, which is why the TTL cannot be
  clamped at the parse boundary and the clamp goes elsewhere fourteen times
  instead. The fix is to stop storing the pseudo-record in the resource-record
  list, not to special-case rtype 41.
- Two `u16`s that name different spaces and compare with `==`. A QTYPE is not an
  RTYPE (ANY is 255 and no record *is* that type); a QCLASS is not a CLASS.
  Newtype them and the wrong comparison stops compiling everywhere at once,
  including the copies nobody knew about.
- A number whose ordering is not the ordering of the numbers. An SOA serial is
  RFC 1982 sequence space: it wraps, so `a > b` is not "a is later", and a
  secondary reading a wrapped increment as a rollback declines the transfer
  forever with nothing in a failed state to alert on. The type must omit
  `PartialOrd` and offer `is_newer_than`. §3.2 also leaves the result undefined
  for two serials half the space apart, which an `Ord` would have to invent an
  answer for. See `Serial`, and the one place that still compares raw numbers —
  with a comment saying why the claim is arithmetical rather than about versions.
- `unwrap_or` on the parse of a wire field, and its cause: `num_derive`'s
  `FromPrimitive`. A data-carrying `Other(T)` with hand-rolled, total, mutually
  inverse conversions costs twenty lines and buys a lossless round trip.
- The same normalization written per module. If two modules fold a name, compare a
  name, or clamp a value their own way, one is already wrong or will be. Move it,
  and put the reason in the doc comment (§7).
- An invariant asserted in a doc comment. That is a claim to verify, not
  documentation to trust (§4). If it is worth writing down it is worth making
  unrepresentable; if it cannot be, say in the comment why not.
- A `pub` field beside a checking constructor. `RecordData` had `pub rtype` and
  `pub rdata` plus three checking constructors, so
  `RecordData { rtype: A, rdata: <seventeen bytes> }` was a value nothing objected
  to until something read it — which is why `parse` returns a `Result`. Two things
  generalize. Private in the crate root is not private: it means visible to the
  root and every descendant, so a type whose fields must be sealed against its own
  crate has to live in a module small enough to be the boundary — a file with one
  struct in it, on purpose. And going to seal something is the cheapest way to
  find out it is not true: writing down "the RDATA is well formed for its TYPE"
  turned up RFC 2136's RDLENGTH=0 records, and the fact that a legal UPDATE could
  not be parsed at all.

Three limits, so this does not become its own kind of damage:

- Measure it, do not assume it. Most of these are `#[repr(transparent)]` newtypes
  that compile to the same code — but "zero-cost" is a claim about a compiler, not
  a fact about a diff. `cargo test -p rdns --test allocations -- --nocapture`
  holds twenty-two counts, fourteen exact, and reads the same on Windows and
  Linux; `cargo bench -p rdns --baseline` is the backstop. Identical counts or
  lower; a
  count that moves up is accepted only with the reason written next to the
  assertion (§10's rule about never lowering a floor).
- Not everything wants a type. A typestate marker to catch one bug that now has a
  test makes every function in the module generic. `String` inside an error variant
  is right when the *category* is the typed part (§3). The question is whether a
  caller would branch on the distinction.
- A type does not settle a question it inherits. A `Name` newtype over a `String`
  that might be in presentation form with escapes, or might not, has renamed the
  ambiguity rather than removed it. Settle what the type *means* first; a newtype
  wrapping an unanswered question is worse than the `String`, because it looks
  like an answer.

Review the plan the way the code gets reviewed. The first draft of `TODO.md` §13
had five claims that did not survive being checked against the code and IANA: a
citation from memory, a count nobody counted, a hedge standing in for a one-line
grep, a key type that could not be a map key, and a missed prerequisite that could
invalidate a whole stage. Every one reasoned about what the code *should* look
like instead of opening it. §4's rule applies to a plan too, because a plan is a
claim about the code.

---

## 18. Finish the sweep, or give the remainder a number

Every unfinished change here ended the same way, and not the way it looks.
Nobody stopped halfway and said so. What was left over was *named in prose* — a
closing note, a doc comment, a plan's own "not worth doing on its own account" —
and prose is not a queue. The review that became #20 put it exactly: **a review
finding with no number is a review finding nobody schedules.** It sat unfiled
because it was "not a defect and had no natural sub-item". #37a's closing
sentence named the next step — "the type answer is to hold these names as
`Name`, which is what the `dnssec` structs still do not do" — and that step
waited for somebody to ask a general question about the codebase before it was
taken, as #38.

- **Count the instances before fixing one.** A change is almost always one case
  of a shape. `grep` for the shape first, put the count in the commit message,
  and fix all of them or say in the same sentence which are left and under which
  number. A fix that silently leaves N-1 reads as complete to the next person
  and to the next `grep`. #38's DO bit was three sites; its `pub` sweep was 87
  items measured before a single one was edited.
- **A sentence naming remaining work is a `TODO.md` item, or it is deleted.**
  Not a doc comment, not a `// for now`, not "when this code is next opened".
  Three got away: `journal::journalled_zones`, a doc comment describing a
  cleanup nothing performed; and `should_set_ad_bit` and `resign_at`, two
  policies written and never wired up, each with a second copy of its rule live
  somewhere else.
- **Dead code is a finding, not litter.** Deleting it is right and deleting it
  silently is not: what it documented was somebody's intent, and the intent
  outlives the function. File it (#38b), then delete.
- **Never write a number you did not just read.** Test counts, allocation
  counts, package counts, "clippy is clean". #38's first commit message said
  "913 on Linux" from a run taken before the change it was describing; the
  correct number was 911 and the only way to know was to check out the commit
  and run it. §1 and §4 say this about the code; it is just as true of the
  message.
- **"Done" is the whole request, not its interesting half.** When part of a task
  turns out to be bigger than the rest, finish everything that does not depend
  on it, then file the part that does with the measurement that would let
  somebody else start. Scaling the work down is the owner's call, and the owner
  cannot make it if the smaller shape is presented as the finished one.

The check that catches all of this before a commit: read the request back as a
list of sentences and answer each one with either a diff or a number. That is
also the shape a session should report in — what was done, what was measured,
what was filed and under which number.
