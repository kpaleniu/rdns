# Working on rdns

Orientation lives in `TODO.md`: what each crate is, what is open, how to run the
binaries, how to verify against dnspython, and four environment traps that have
each cost an hour. Read it before planning. This file is different — it is the
list of mistakes this codebase has actually made, written as rules, because a
five-way review in July 2026 found 48 defects and they were not 48 unrelated
things. They were a dozen patterns, repeated.

**The pattern behind the pattern:** the hard cryptographic and protocol-state
work here is right. DNSSEC verification, TSIG, NSEC3 iteration caps, RFC 5011,
serial arithmetic — all reviewed clean. Everything that broke, broke where the
problem looked too simple to get wrong: the plain answer path, error handling,
integer widening, the operational shell. Suspicion belongs where confidence is
highest.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets   # must be clean, no exceptions
cargo fmt --all                          # before every commit — see §12
```

---

## 1. A test that agrees with the code is not evidence

This is the rule the other rules depend on. The suite was green at 590 tests
while `rdnsd` could not serve a CNAME, a delegation, or a two-label wildcard —
because the tests were written from the same understanding as the code, by the
same author, in the same sitting. Two of them asserted the wrong behaviour and
cited an RFC section that says nothing about the subject.

- **Assert what the RFC says, and cite the section that says it.** Not the
  section that is nearby and sounds relevant. The wildcard bug lived for months
  behind the citation "a wildcard covers one label and only one (RFC 4592
  §2.1.1)" — §2.1.1 is about `*` being special only as the leftmost label in
  zone-file *syntax*. §3.3.2 has a worked example synthesizing two labels down.
  Read the section before citing it, and quote enough of it in the comment that
  the next reader can tell you did.
- **Prefer the RFC's own worked example as the test case.** It is the one input
  the specification has already committed to an answer for.
- **A new regression test must be shown to fail against the old behaviour.**
  Revert the fix, run the test, watch it fail, put the fix back. If it passes
  both ways it is testing something else. Two probe tests for the RDLENGTH panic
  were written and thrown away during the review without ever being landed; the
  panic survived that.
- **When fixing behaviour, expect to change tests, and say so in the commit.** A
  test that has to change is a test that encoded the bug. Fixing it silently
  hides the most interesting fact about the change.
- **Judge output with the reader, not by inspection.** A signed answer is checked
  by putting it through `verify_rrset` / `proves_nxdomain` / `proves_nodata` — the
  same code that judges a real zone off the internet — and, for anything
  cryptographic, against dnspython as well. Our parser agreeing with our
  serializer proves nothing.

## 2. Wire input: check every length, and never widen a signed field

Both halves of this were violated in code where every *other* length was checked.

- **Every length that came off the wire is attacker-chosen.** RDLENGTH was
  sliced as `&rest[..rdatalen as usize]` with no bounds check, in a parser where
  `read_be!`, `Label::try_from_bytes` and `parse_options` all check theirs. It
  was a pre-authentication remote panic on both transports, in `rdnsr` with no
  validator in front of it, and in a secondary's replication task — which is not
  restarted, so the zone silently stopped refreshing until EXPIRE.
- **`as` on a value from the wire is a bug until proven otherwise.** `ttl` is an
  `i32` straight off the wire; `-1 as u64` is `u64::MAX`, which `min` then picked
  as the smallest TTL and pinned a cache entry for the life of the process. Clamp
  at the parse boundary (`.max(0)` *before* the widening), give the result a
  ceiling, and use `saturating_add` for anything added to a timestamp.
- **Bounds and clamps belong at the boundary, once.** Three modules clamped TTLs
  and one did not, and the two call sites writing into that one clamped on the
  way in — so a check that existed four times over was still missing where it
  mattered. If a value has an invariant, make it unrepresentable without it
  rather than re-asserting it per site.
- **A catch-all variant must carry the value it caught.** `QueryClass` had no
  variant for an unrecognized class, so the parse was
  `from_u16(qclass).unwrap_or(QueryClass::None)` — and `None` is not a sentinel,
  it is **254**, RFC 2136's real NONE class. QCLASS 99 arrived as `None` and went
  back out as 254, so the question echoed in the response was not the question
  asked. `ResponseCode` had the mirror image: an `Unknown = 65535` sentinel that
  could not hold the code it stood for, which `to_bytes` therefore wrote as
  **0** — an unrecognized *failure* relayed to the client as NOERROR. Write
  `Other(u16)`, hand-roll `from_u16`/`to_u16` so both are total and each other's
  inverse, and the round trip cannot lose anything. `unwrap_or` on the parse of a
  wire field is the smell; look at what the fallback actually means on the wire.
- **A signed catch-all is worse than a `String`.** Both of the above were
  `num_derive`'s `FromPrimitive`, which hands you an `Option` and invites exactly
  that `unwrap_or`. A data-carrying variant costs the derive and twenty lines of
  match; it buys a conversion with no failure case for the compiler to let you
  paper over.

## 3. Error types: typed in the library, `anyhow` in the binaries

One rule, and it runs the opposite way in the two places:

- **`rdns` returns typed errors** (`WireError`, `ZoneError`, `DnssecError`,
  `TransferError`, `ResolveError`, `ConfigError` — all in `rdns::error`). A
  library that returns `anyhow::Error` erases the failure kind from its own API,
  and here that kind *is* the answer: a truncated packet is FORMERR, an
  unsupported label is NOTIMP, a signature that does not verify is SERVFAIL and
  an algorithm we cannot read is insecure. With a string in hand the caller
  cannot tell them apart.
- **`rdnsd` and `rdnsr` use `anyhow::Result`** with `.context()`. Their only
  consumer is a human reading a log line or an exit message, which is exactly
  what `anyhow` is for.
- **Never `Box<dyn Error>`, never `Result<_, String>`.** Both were in use here
  and both are strictly worse than the option beside them. `Box<dyn Error>` is
  `anyhow` without context chaining, without `Send + Sync`, and with a `Debug`
  impl that renders a multi-line message as a quoted Rust literal with the
  newlines escaped — `main` prints its `Err` with `Debug`, so an error an
  operator has to read comes out unreadable. `Result<_, String>` does not even
  implement `Error`, so `?` will not lift it into either of the above.

Two habits that keep the types honest:

- **Add a variant when a caller would branch on it, not when a message differs.**
  `TransferError::Timeout` exists because a secondary retries a timeout and gives
  up on a malformed transfer; `ResolveError::BudgetExhausted` exists because the
  NXNSAttack defence firing is an operational signal, not a lookup failure. A
  variant nobody matches on is a `String` with extra syntax.
- **A `String` inside a variant is fine when the *category* is the typed part.**
  The structural ways a DNS message can be malformed are open-ended; enumerating
  them would produce a hundred variants nobody reads, and dropping the text would
  make a bad packet undiagnosable.

**Assert on the variant, not the message.** `matches!(err, WireError::TooLong { what: "a label", .. })`
says what the test means and survives a reworded message; `err.to_string().contains("label length")`
does neither. Roughly a dozen tests here were the second kind.

## 4. Errors: degrading quietly is worse than failing

Serving a wrong DNS answer is worse than serving none, and every finding in this
class left the process healthy with nothing alerting.

- **Never turn an error into an empty value.** `enumerate_zone_files(dir).unwrap_or_default()`
  made an unreadable directory look like an empty one: the server came up,
  listening, holding zero zones, answering REFUSED for every name it was
  authoritative for. Grep for `unwrap_or_default`, `unwrap_or_else(|_| ...)` and
  `let _ =` on anything that can fail, and justify each in a comment or delete it.
- **All-or-nothing means all.** A zone file that fails to parse must not be
  dropped while the rest load; collect the errors and fail the set. Anything else
  makes one typo plus a deploy SIGHUP into a lame delegation with 39 green
  dashboards.
- **A doc comment claiming an invariant must be checked against the code that
  upholds it.** `Reloading::load`'s comment says "nothing is installed unless the
  whole set comes through". It did not hold. A comment asserting a property is a
  claim to verify, not documentation to trust.
- **Never state what a function you are calling does without opening it.** The
  fix for "an unreadable zone directory reads as empty" was landed with the
  claim that `enumerate_zone_files` already returned `Ok(empty)` for an empty
  directory, so deleting the `unwrap_or_default()` could not affect a secondary's
  first start. It returned `Err`. The claim went into the commit message, the doc
  comment and `TODO.md` without anyone reading the twenty lines that would have
  settled it, and a secondary pointed at an empty directory then refused to
  start. Nothing caught it, because the case had no test — a green suite standing
  in for evidence it never had, which is §1 again from the other direction.

  **It happened again**, in the commit that added graceful shutdown, and the
  second time is the more instructive one because the claim was about a *third
  party's* function. `tokio::signal::ctrl_c()` was used as the whole Windows stop
  handler, with a doc comment asserting it also covers a console close. It does
  not: it registers for `CTRL_C_EVENT` alone, and `ctrl_break`, `ctrl_close` and
  `ctrl_shutdown` are separate listeners. A real `CTRL_BREAK_EVENT` sent
  mid-AXFR went to the *default* handler and killed the process with exit code
  `0xC000013A` — the exact failure the change existed to fix, shipped alongside
  a comment saying it could not happen. Reading the docs is not the same as
  reading the code, and neither is the same as sending the signal.
- **Check what the other implementations do, and quote them.** The SOA-serial
  question under `TODO.md` #8 sat undecided for weeks and was settled in twenty
  minutes by reading BIND's, Knot's, PowerDNS's and NSD's answers — which
  *converge*, and converge on something better than either option that had been
  written down. It also caught a design error before it shipped: `max(file, now)`
  looks obviously right and silently does nothing for a date-style serial, and
  PowerDNS's docs say so in five words ("requiring epoch-based backend serials")
  that are easy to read past. A protocol this old has had every decision made
  several times already.
- **Prove an operational fix by provoking the failure, not by reading the diff.**
  The three unit tests for shutdown passed against the broken signal handler,
  because they call `Shutdown::begin()` directly and never involve the operating
  system. Only sending a real console control event to a real process mid-transfer
  showed it. When a change is about what happens to a *process*, the test that
  settles it has to involve a process.
- **When one function answers several questions, separate them before fixing
  one.** That same loader conflated "could the directory be read", "did every
  file parse", and "is it empty" — three questions with three different right
  answers, one of which depends on whether the caller is a secondary. Every fix
  that touched it moved the bug rather than removing it, until they were pulled
  apart.
- **"Missing state degrades, never crashes" is right for a cache and wrong for
  anything with teeth.** Forgetting a secondary's last-contact time *is* the
  difference between a withdrawn zone and a stale zone served with AA set.
- **In a receive loop, ask what a remote party can provoke.** `recv_from`
  returning `Err` ends the loop and the process. That made a stray ICMP report a
  remote kill switch, and then — because the fix was written as a list of
  `ErrorKind`s — an oversized datagram was a second one, since WSAEMSGSIZE
  arrives as `Uncategorized` and matches no kind at all. See
  `utils::recv_error_is_transient`.

## 5. State keyed on something an attacker chooses must be bounded

Four of five reviewers found the same shape. `QueryStats::queries_by_ip`,
`rate_limited_ips` and `RateLimiter::buckets` grew one entry per source address,
created *before* any validation — one spoofed 12-byte datagram per entry — with
no trimming at all in two of them.

- Every per-peer table needs a `max_tracked` and a policy for the bound. Follow
  `security::ResponseLimiter`, which had this from the start and says in a comment
  why: the table would otherwise be the next amplification vector.
- **Decide which way the bound fails, and write down why.** The rate limiter
  *allows* an untracked source, because failing closed would let one flood deny
  service to everybody. The logger *decays* counts, because keeping heavy hitters
  is the whole signal.
- Per-key counters are the wrong shape for an unbounded key space in the first
  place. A bound plus a visible shortfall counter (`untracked_sources`) beats a
  map that is quietly a lie.

## 6. Wall-clock time is not monotonic

`utils::current_unix_timestamp` is `SystemTime`. An NTP step backwards made
`now - last_refill` underflow: a debug panic **with a mutex held**, which poisons
it, after which every later call panics and the server stops answering entirely
— a clock correction taking the process off the air permanently. In release it
wrapped to ~1.8e19 and silently refilled every bucket.

- **Every subtraction of two timestamps is `saturating_sub`.** No exceptions.
- **Never panic while holding a lock.** Prefer `let Ok(guard) = m.lock() else`
  with an explicit, commented failure decision over `.lock().unwrap()` on any
  path a query can reach.
- Anything measuring an interval rather than naming an instant wants `Instant`.

## 7. Duplicated logic drifts; the second copy is where the bug lives

The ICMP predicate existed twice, once per binary. The oversized-datagram case
was found in one copy. The ASCII-lowercasing helper existed correctly in `zone`
with a comment explaining why, and incorrectly in `cache` without one.

When you find the same reasoning in two places, move it into `rdns` and make both
call it — and put the *reason* in the doc comment, because the reason is what
stops the next copy being written.

Two shapes that are the same drift wearing different clothes:

- **An early `return` that jumps over a shared epilogue.** `make_response` ends
  by mirroring the client's OPT record (RFC 6891 §6.1.1), and the NOTIMP branch
  fifty lines above it returned before reaching that — so the one reply that
  dropped the client's EDNS was the one for an opcode we do not implement. There
  is no second copy to grep for here; the copy is the *absence* of one. When you
  add a `return` to a function with a tail that matters, ask what the tail was
  doing.
- **A sibling that was written separately and got it right.** `truncated_reply`
  set AA on a reply carrying no data and hardcoded 512 instead of reading
  `udp_payload_size()`; `error_bytes`, twenty lines up and doing the same job,
  had both correct. Two functions that build the same kind of message are one
  function with a parameter, and until they are, fixing one means reading the
  other.

**Reuse the parser you already have for the same syntax.** The query-rate
exemption list is addresses and CIDR prefixes, which `security::TransferAcl`
already parses — including the rule that a v4 prefix never matches a v4-mapped v6
peer, which a second implementation would not have. It grew a `parse_named` so
the error text can say which list has the typo, and that is the whole of what
"another list of the same thing" should cost.

## 8. DNS rules this codebase has already got wrong

Cheap to re-check, expensive to rediscover.

- **RFC 1034 §4.3.2 is four cases, tried in order:** the zone's authority ends
  here (referral), the name has the data, the name is an alias (follow it,
  restart), the name has no such data. Getting the first one last is how a parent
  answers NXDOMAIN for a child's names. See `rdnsd`'s `resolve_in_zone`.
- **AA is clear on a referral** (RFC 1035 §4.1.1). With AA set, per RFC 8020
  every resolver caches "the whole subtree does not exist".
- **A name with descendants exists** (RFC 4592 §2.2.2) — NODATA, not NXDOMAIN.
  An RFC 8020 resolver extends an NXDOMAIN downwards, so the zone takes its own
  data offline.
- **Wildcard synthesis reaches any depth, and stops at the closest encloser**
  (RFC 4592 §3.3.1, §3.3.2). An existing name — an empty non-terminal included —
  ends the search (§4.4). No synthesis at or below a delegation (§2.2.1).
- **A negative answer's SOA TTL is `min(MINIMUM, the record's own TTL)`**
  (RFC 2308 §3), and so is the RRSIG's beside it.
- **Case folding is ASCII-only** (RFC 4343). `str::to_lowercase` folds U+212A
  KELVIN SIGN into `k`, merging two names that differ on the wire. Use
  `utils::ascii_lowered`.
- **REFUSED, not NXDOMAIN, for a zone we do not serve.** NXDOMAIN is an assertion
  about the DNS that we have no standing to make, and resolvers cache it.
- **A response is not a question.** Test QR before doing anything with a packet
  that arrived at a listening socket, on both daemons. `RequestValidator` accepts
  QR=1 on purpose — it is used on both directions of the wire — so the check
  belongs at the socket. Two servers pointed at each other, or one spoofed
  datagram, is otherwise a packet loop neither end can see.
- **The opcode is the client's.** Echo it (RFC 1035 §4.1.1) and answer NOTIMP to
  anything unimplemented. Hardcoding `OpCode::Query` in a response builder is what
  hid the missing check.
- **A negative answer's proof is about the end of the CNAME chain**, not the name
  asked about (RFC 4035 §5.4) — and "is this negative?" is not
  `answers.is_empty()`, because a chain that ends without the queried type is a
  negative answer with a non-empty answer section.
- **Every negative answer owes a specific proof, and they differ.** NODATA owes a
  record *at* the name; NODATA through a wildcard owes that record at the wildcard
  *plus* a denial of the name asked for; NXDOMAIN owes a denial of the name *and*
  of the wildcard that could have answered it; a referral owes the DS or a signed
  denial that there is one. See `dnssec_answer`.
- **A delegation's NS RRset carries no signature** — it is the child's data. Its
  NSEC lists `NS RRSIG NSEC` and not `DS`.
- **A denial record's bitmap must list every type present at the name it
  describes** (RFC 5155 §7.1, RFC 4034 §4.1.2). Which makes **snapshot-then-mutate
  a bug pattern**: `Layout::of` was taken before NSEC3PARAM was added, so the apex
  NSEC3 denied a type that was there — and an aggressive-NSEC resolver would then
  synthesize that false NODATA for other clients out of its cache.
- **Re-signing is a new version of the zone, so the serial has to move.** A
  secondary decides whether to transfer by comparing serials; without a bump the
  replica keeps the signatures it already has and they expire underneath it —
  the same outage as never re-signing, one hop downstream. Everyone who signs and
  *stores* signatures does this, and they all dissolve the "but the operator owns
  that number" objection the same way: the served serial and the file's serial are
  **different numbers**, so they cannot collide. BIND's inline-signing serves a
  number that visibly drifts from the file's; Knot takes the field away from the
  operator entirely.
- **Do not give every RRSIG in a zone the same expiration.** They then all expire
  in the same second, which turns "signatures lapsed" into "the entire zone
  SERVFAILs at every validator at once". Spread expiry across a fraction of the
  window — and make the spread **deterministic** per (owner, type), because random
  jitter reshuffles the slope on every reload and no two servers holding the zone
  agree about it. Never spread *past* the requested validity: 30 days means at
  most 30 days.
- **Re-sign with slack, not just before expiry.** A third of the validity (BIND
  uses a quarter) leaves room for a run to fail, or for the server to be down
  over one, without anything expiring. A missed re-sign has to be survivable.
- **A QTYPE is not an RTYPE and a QCLASS is not a CLASS.** The question carries
  values no stored record can ever hold — ANY is QTYPE 255 and QCLASS 255,
  neither of which any RR *is* — so `record_type_code(&r.rdata) == qtype` matched
  nothing and QTYPE=ANY came back as an empty NOERROR plus the SOA. That is a
  NODATA for a name with data, and none of the shapes RFC 8482 §4 permits. Every
  comparison of a question field against stored data has to ask first whether the
  question field is a *query* value with its own meaning (RFC 1035 §3.2.3,
  §3.2.5).
- **A class we do not serve is REFUSED, not answered from the class we do.** The
  class was parsed, stored on every record, and then never compared, so a CH
  question was answered out of the IN zone — `CLASS=CH` in the echoed question
  next to `CLASS=IN` records in the answer, which is malformed. RFC 1034 §4.3.2
  step 1 searches the zones *of the question's class*. The zone parser now refuses
  a non-IN record outright, which is what makes the class-blind index correct
  rather than merely untested (§2's "make it unrepresentable").
- **DNSSEC records are not answer-section data unless DO asked for them**
  (RFC 4035 §3.1.1). This is the trap hiding inside "ANY means every type": RRSIG,
  NSEC and NSEC3 are types at the name, so a literal reading hands them to a
  client that cannot read them, duplicates the ones `answer_signatures` attaches,
  and — the one that is a correctness bug rather than noise — makes an empty
  non-terminal in an NSEC-signed zone look like a name *with* data, because the
  chain puts an NSEC at it.
- **QNAME minimisation needs a ceiling** (RFC 9156 §2.3, MAX_MINIMISE_COUNT,
  recommended 10), and the probes ask for **A**, not NS — §2.3 replaced RFC 7816's
  NS advice with "the QTYPE least likely to raise issues in DNS software and
  middleboxes". Without the ceiling a 34-label reverse-IPv6 PTR spent ~30 round
  trips and exhausted the query budget, so a deep name failed outright where it
  should have degraded to a full-QNAME query that still resolves.

## 9. Async, locks, and the work done under them

- **An `async fn` with no `.await` in it is blocking, and its signature says
  otherwise.** `load_zones_from_source` did `read_dir`, `read_to_string` per zone,
  a full parse and a full ECDSA signing run on a worker that was also serving
  queries. Use `spawn_blocking` and say why.
- **Do not compute under a write lock.** Compute under the read lock, apply under
  the write lock. A full zone diff per zone inside one write guard blocks every
  query for the sum of the diffs.
- **Do not hold a `std::sync::Mutex` across an fsync**, or across anything else
  that yields in spirit but not in type.
- **Check admission before spawning, not inside the spawned future.** Paying a
  `to_vec()`, two `Arc` clones and a task before deciding to drop the packet is
  backwards.
- **Dropping a `JoinHandle` detaches the task; it does not cancel it.** Both
  daemons had a `tokio::select!` over two handles that dropped the loser, so
  `main` returned while the other transport was still reading and replies were
  still queued in per-connection channels. A `JoinSet` gives the same
  first-one-wins shape with both tasks still owned and joinable, and
  `join_next` is cancel-safe so it can sit in the `select!` directly.
- **Separate "watch for the stop" from "hold the thing open".** In
  `rdns::shutdown` those are `Stop` and `Busy`, and the split is the whole
  design: the accept loops hold the signal for the life of the process, so one
  type carrying both would keep the drain open forever and the shutdown would
  wait out its budget every time — looking like it worked while doing nothing.
  Hold the claim across *work*, never across a sleep: a refresh timer is hours
  long.
- **The drain is an `mpsc` nobody sends on.** `recv()` returns `None` exactly
  when the last sender clone is dropped, which is a counter that cannot be got
  wrong and needs no polling. Whatever owns the receiver must drop its own
  sender first, or it waits forever.
- **Cancel-safety decides where a `select!` arm may go.** `recv_from` and
  `accept` are cancel-safe, so losing a race against the stop drops nothing that
  was ours. `read_exact` is not, which is why the shutdown check on a TCP
  connection sits between messages — where the peer has committed to nothing —
  and not mid-message.

## 10. Benchmarks and measurement

- **A wall-clock assertion with no headroom is a coin toss, not a test.** Give a
  floor a factor of ten of headroom, as `bench_zone_lookup` does.
- **Never lower a floor to make a bench pass without first proving why it moved.**
  `bench_logger_throughput`'s floor went from 45k to 10k, attributed to competing
  load. It was a quadratic in `log_query`, and lowering the floor ratified the
  regression the benchmark had caught. **And put it back when you fix the cause**,
  with what it measures now written next to it — a floor left at the regressed
  value is a benchmark that has agreed to stop noticing.
- **Prefer a deterministic assertion where one exists.** An allocation count
  (`dhat::assert_eq!` on `total_blocks`) does not care what else is running.
  Neither does a `Vec::capacity` (the 64 KB response scratch), a pointer identity
  (did the reused buffer reallocate?), a table length (six suffixes, one copy of
  the name between them), or a count of the queries a mock server was asked.
  Reach for one of those before reaching for a stopwatch.
- **"Cost must not grow with N" is a ratio, not a floor.** Time a batch cold,
  do N units of work, time the same batch again, assert the ratio. It does not
  care how fast the machine is or what else is running — which is exactly the
  weakness that let the `log_query` quadratic be argued away. Measured against
  the old code: 22.5×. Against the fix: ~1×. See
  `logging::tests::logging_a_query_costs_the_same_however_many_came_before`.
- **A ceiling with a factor of a hundred of headroom is a fine test.** Filling a
  20k-entry cache twice over takes 0.05 s now and took 6.8 s with the O(n²)
  eviction; asserting "under five seconds" is not a performance target, it is a
  tripwire for a complexity class, and it never fires on a busy machine.
- **Say what a test is a regression for, and what it is not.** The tie-handling
  test for cache eviction fails against the *naive rewrite*, not against the old
  quadratic — which got ties right, slowly. Both are worth having; conflating
  them is how a suite gets credit it has not earned (§1).
- **Profile before optimising, and record the negative results.** The DHAT pass
  turned up the biggest cost on the query path — `tokio::spawn` at 1,536 bytes
  per datagram, 46% of everything a query allocates — which was on nobody's
  hand-written list, and cleared one that was: `verify_rrset` against two
  candidate signatures costs 22 allocations, so that item is a time problem and
  not a count problem. A measurement that redirects effort away from something
  is worth as much as one that finds a bug.
- **An exact count that is not actually exact is worse than a timing**, because
  it looks trustworthy. `rdns/tests/allocations.rs` got two numbers wrong before
  it got any right: the DHAT profiler is *global*, so guarding only the
  measurement let other test threads' allocations land in the total (4 read as
  12, 208 as 1015, changing with `--test-threads`) — every test holds the mutex
  for its whole body now. And the first profiled block in a process picks up a
  one-off, which for a target of exactly zero flips on which test the scheduler
  started first; call the function once before measuring it. Check a count is
  stable across several runs before trusting it.
- **A `#[global_allocator]` applies to the whole binary**, so allocation-count
  tests belong in their own `tests/` file rather than beside the unit tests they
  would otherwise slow down.

## 11. Comments, commits, and `TODO.md`

This repo keeps its reasoning in prose, and that is deliberate — match it.

- Comments say **why**, and especially why *not*: the alternative that was
  rejected, the bug that was hit, the RFC that forbids the obvious thing. A
  comment restating the code is noise; a comment recording a wrong turn saves the
  next reader an hour.
- The commit message carries the reasoning, the RFC citations and the
  verification for a change. `TODO.md` carries one line per finished item and
  points at the commit.
- **Do not quietly edit a claim in `TODO.md` that turned out to be wrong.**
  Correct it in place with a pointer, and leave the reasoning that produced it —
  that reasoning is why the bug happened, and it is the most useful thing on the
  page.
- The numbered sections in `TODO.md` are stable identifiers referenced from the
  code and from each other. Move them, never renumber them.

## 12. Formatting: `cargo fmt --all`, every time

**Run it before every commit.** Stock rustfmt, no `rustfmt.toml` — the defaults
are the convention, and a config file is a thing to argue about rather than a
thing that helps. `cargo fmt --all --check` is the way to ask whether the tree is
clean without touching it.

This was not done for the first year of the repo, and the cost was not
ugliness — it was that **hand-formatting became load-bearing**. A mechanical
rewrite of a hundred error call sites had to be followed by a hand-written
re-wrapping pass, because `cargo fmt` was unavailable: the tree was 558 diffs
away from it, so running it would have buried the change under a reformat of
every file in the workspace. A formatter you cannot run is a formatter that makes
every large edit more expensive than it should be.

Two things it does *not* do, so do not expect them:

- **It does not touch comments.** `wrap_comments` is off (and nightly-only), so
  the prose in this codebase — which is most of its value, per §11 — is wrapped
  by hand and stays that way. rustfmt will re-indent a comment to follow the code
  it is attached to, and nothing else. Keep prose at 80-ish columns; rustfmt's
  100 applies to code.
- **It does not touch string literals.** `format_strings` is off, so a `\`
  continuation inside a message stays where you put it, including the indentation
  of the continuation line — which rustfmt will not fix and a careless
  search-and-replace will wreck.

**A reformat is its own commit, and goes in `.git-blame-ignore-revs`.** Mixing
one into a behaviour change makes the diff unreviewable and the blame useless.
Configure git to honour the file once per clone:

```sh
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

---

## 13. Size a buffer for what you will send, not for what the protocol allows

Every one of these was a scratch buffer sized by the format's maximum rather than
by the caller's actual limit, and each cost more than it looks.

- **`Vec::truncate` does not release capacity.** `to_bytes_within` built every
  response in `vec![0u8; u16::MAX as usize]` — 64 KB, zeroed — and truncated it,
  so the `Vec` handed to `send_to` and held for the duration of the send was 64 KB
  whatever the answer was. A 60-byte response retained capacity 65535. Only the
  TCP and transfer paths ever want `u16::MAX`; a UDP caller knows its EDNS payload
  size and should be charged that. Verified by asserting on `capacity()`, which is
  exact.
- **Give the hot path a way to bring its own buffer.** `to_bytes_within_buf` is
  the primitive and `to_bytes_within` is the allocating wrapper, so a send loop
  that keeps one scratch buffer allocates nothing per response — a third of
  serialization was allocator traffic, and it is not optimizer-erasable because
  the allocation escapes into the socket call.
- **When the maximum *is* the limit, the "too long" check moves.** Sizing the
  scratch to `max_len` turns "the message does not fit" from a comparison into a
  `WireError::Truncated` from the writer, which then has to be caught rather than
  propagated — and every *other* `WireError` is still a real failure. Test the
  message that is exactly `max_len` bytes: that is where an off-by-one puts a
  message that fits onto the truncation path.
- **Do not store one owned copy per derived key.** The name compressor kept a
  `HashMap<String, u16>` filled by `labels[i..].join(".").to_ascii_lowercase()` —
  two allocations per suffix (join, then lowercase, since `to_ascii_lowercase` on
  a `str` returns a new `String`) and a total byte count quadratic in the label
  count, because every suffix carried its own copy of the tail it shares with the
  others. One lowercased copy in an arena plus ranges into it is smaller, faster,
  and a linear scan beats the hash outright when a message holds a handful of
  distinct names.
- **Halving a map with `select_nth_unstable` beats `min_by_key` in a loop.** Cache
  eviction re-scanned the whole map to find *one* victim and cloned its `String`
  key to remove it: O(n²) plus an allocation per removal, under the global lock,
  ~37 million iterations per stall at the default size. And **check the ties**:
  expiries are whole seconds, so a cache filled in one burst has every entry on
  one value, and `retain(|e| e.expires_at > cutoff)` empties the whole cache
  instead of halving it.

## 14. A limit with no flag is a limit nobody has reviewed

- **State a rate in the unit the operator thinks in.** The query limiter was
  configured as "100 tokens per 10-second window, burst 20", which reads as a
  hundred queries and *is* **ten a second** — below what one busy resolver sends.
  It was hardcoded, had no flag, and dropped over it **silently**: no REFUSED, no
  SERVFAIL, nothing on the wire, so the operator concludes it is the network.
  Measured before the fix: a 60-query burst got 20 answers and 40 drops.
  `RateLimitConfig::per_second(rate, burst)` exists so the number in the config
  is the number in the head.
- **Silence can be the right answer and still needs to be visible somewhere.**
  Replying to a rate-limited source is what an amplifier does, so dropping is
  correct — which is exactly why the effective policy is printed at startup and
  why the metrics item (`TODO.md` #9d) is what finishes this. A control nobody can
  observe is a control nobody can debug.
- **Every knob wants an escape hatch and an off switch.** `--query-rate 0`
  disables the limiter outright, and `--query-rate-exempt` takes the resolvers you
  run yourself and the monitoring probe whose job is to query more often than a
  client would. Without the exemption the only way to spare a known-good source is
  to raise the limit for everyone.
- **Floor a knob that can turn the server off.** A burst of zero refuses every
  query, because a bucket starts full and a full bucket of nothing has no token to
  spend. `per_second` floors it at one: a mistyped flag should be wrong, not
  fatal.
- **Group policy parameters into a struct once there are more than a few.**
  `serve` reached eight arguments — two `u32`s and two address-shaped things among
  them — which is one edit away from swapping the response budget for the query
  rate with nothing to catch it. Clippy says so at 7; it is right for a reason.
- **A dependency that is only ever *configured* is not a feature, it is a
  liability.** `init_telemetry` built two OTLP exporters into
  `let _trace_exporter` / `let _metrics_exporter` and dropped them. Nothing
  called it. For that, the workspace carried `opentelemetry`, `-otlp`, `_sdk`,
  `tracing-opentelemetry`, `tracing` and `tracing-subscriber` — and through them
  `tonic`, `prost`, `hyper` and `h2`, a gRPC *server*. Deleting the module took
  `Cargo.lock` from **187 packages to 104**. Meanwhile the module that had the
  counters worth paging on was referenced only by a benchmark. Count what a
  dependency does *at run time*, not what it is for.
- **Prefer the shape the operator already runs.** DNS shops scrape; an OTLP push
  exporter was the wrong default before it was a broken one. The replacement is
  ninety lines of HTTP over `tokio`'s `TcpListener`, because pulling a second
  HTTP stack back in to answer one method on one path would be the same mistake
  with better manners.
- **A counter's name is a claim about what it counts.** `make_response` called
  `increment_cache_hits` and `increment_cache_misses` on an *authoritative*
  server, which has no cache — they were standing in for "found something" and
  "did not". A dashboard built on that reports a cache hit rate for a thing with
  no cache. Count what an operator pages on: REFUSED climbing means a zone went
  missing, SERVFAIL climbing means one went wrong, NXDOMAIN is ordinary.
- **Histograms in base units, with the buckets the system actually falls in.**
  Prometheus convention is seconds, and a dashboard that has to know you chose
  milliseconds is a dashboard that will get it wrong. An in-memory zone lookup is
  tens of microseconds, so a histogram whose first bucket is 5 ms reports every
  healthy server as identical.
- **Expose an instant, not an elapsed time.** `time() - x` is the query
  language's job. A "seconds since" computed at scrape time is already stale when
  it arrives and goes on ageing in the dashboard's cache.
- **A gauge must be able to say "no answer".** Zero is a value, and for a
  timestamp it is 1970 — which fires every staleness alert there is. A zone we
  are primary for has no last-transfer time and a secondary that has never
  fetched has none either, so those series are *omitted*. `absent()` is a
  question the query language can ask; a wrong number is not.
- **A withdrawn thing must stop being reported, not freeze.** A serial gauge left
  at its last value shows a zone nobody serves any more as perfectly healthy —
  the exact condition a staleness alert exists to catch, hidden by the metric
  meant to reveal it. Every path that stops serving something has to forget it;
  in `rdnsd` there are two (the startup check and the runtime EXPIRE) and the
  second was missed until an unused binding warned about it.
- **Update a gauge where the fact changes, not where it is read.** Sampling live
  state at scrape time puts the scrape behind whatever lock the state is under —
  here a scrape behind a reload and a reload behind a scrape — and the value is
  still only as fresh as the last scrape. Write it at the moment you already hold
  the answer.
- **Escape label values.** A stray `"` does not corrupt one line, it makes the
  *rest of the scrape* unparseable. Zone names come from a file an operator
  wrote, and RFC 1035 §5.1 allows escapes in one, so "should not contain a quote"
  is not "cannot".

## 15. Configuration

- **`deny_unknown_fields`, always.** A mistyped key that is silently ignored is a
  setting the operator believes is in force and is not. `require-signd = true`
  has to fail at startup with a line number, not serve unsigned zones quietly.
  This one attribute is most of the difference between a config file and a config
  file worth having.
- **Two sources for one setting means an error, not a precedence rule.**
  `--config` and `--port` together is refused. Every precedence rule is one
  somebody has to remember at 3am to work out why the server is not where the
  file says — and the failure is silent, because both values are valid. Refusing
  costs one restart.
- **`Option` per field for an override, not a whole struct.** In `[zones.*]`,
  absent means *inherit* and not "the default": an operator who sets `nsec3` for
  one zone must not silently reset that zone's validity to thirty days.
- **A derived global has to follow the extreme, not the default.** The re-signing
  interval follows the *shortest* validity of any zone, because a seven-day zone
  among thirty-day ones is the one that expires if the timer runs on the global
  number.
- **A secret in a file is only better than a secret in `argv` if the file is
  private** — so check the mode and refuse a readable one. A key directory
  restored from backup as 0644, or `chmod -R`'d by a deploy script, is the
  ordinary way a private key stops being private. And say out loud where the
  check does not apply: on Windows there is no equivalent, and "the permissions
  were checked" must not be a claim that is only true on one platform.
- **Reuse the parser the flags use.** The config builds `[alg:]name:secret[:zones]`
  strings and hands them to `TsigKey::parse`, rather than constructing keys
  directly, so the two paths cannot disagree about what a key means and every rule
  the parser enforces applies to both (§7).
- **A dry run has to run everything that does not bind a socket.** `--check-config`
  returns after the config parsed, the secrets were read and mode-checked, every
  zone loaded, every zone was signed and every signature verified. A shallower
  check — parse the file and stop — passes for the failures that actually break a
  deploy: a typo in a zone, a chmodded key, signatures that do not verify.
- **Pay for a parser; do not pay for a stub.** Nine crates for `toml` + `serde`
  is proportionate three commits after deleting eighty-three for an exporter that
  never ran. The rule is not "no dependencies", it is "no dependencies that do
  not do anything" — and a hand-rolled TOML subset that misreads a config is the
  worst outcome available.

## 16. Authentication is not authorization

`answer_transfer` asked whether a TSIG *session existed* and called that
permission, so holding any key in the keyring transferred any zone and bypassed
`--allow-transfer` entirely. Hand a per-customer key to one partner and you have
handed them every zone on the server.

- **"Who are you" and "what may you do" are two questions.** A verified MAC
  answers the first. It says nothing about the second, and code that treats it as
  though it did grants everything to anyone who holds anything.
- **Authorize against the most specific thing the request names.** A transfer
  hands over a whole zone, so the check is against the *apex* — a rule matching
  anything less specific authorizes more than it names, which is why a child of a
  listed zone is refused.
- **Check before doing the work, not before sending it.** The point of an
  authorization check is that the zone is never looked up and the messages are
  never built.
- **Ask the object that already knows.** The check hangs off the `TsigSession`
  rather than looking the key up again by name: the session *is* the answer to
  "which key was this", and a key name is attacker-supplied until the MAC
  verifies. A second lookup is a second chance to get it wrong.
- **An authenticated refusal is still signed** (RFC 8945 §5.3). Not doing so was
  a second, older bug on every error path of the transfer — and the symptom was
  this codebase's usual one: the client cannot tell a refusal from a tampered
  reply. dnspython reported the unsigned REFUSED as "the TSIG record is
  malformed", which sends the reader after a key mismatch that does not exist.
- **Do not silently narrow a default that would break a working deployment**, but
  do make the wide case *visible*. An unscoped key still transfers everything,
  because changing that would mean a version bump stops every transfer with no
  warning; the startup banner now prints what each key may transfer, so the
  decision is reviewable instead of invisible. Narrowing belongs with the config
  file, where the operator is editing the whole policy at once.
- **Where a new field is ambiguous, require the disambiguating one.** A zone list
  as a fourth colon-separated field collides with `[alg:]name:secret` at three
  fields, so a zone list requires the algorithm to be spelled out. Failing at
  startup with a message beats guessing whether the first field looks like an
  algorithm name — and beats reading a zone list as a base64 secret.
