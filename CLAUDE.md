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

## 3. Errors: degrading quietly is worse than failing

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

## 4. State keyed on something an attacker chooses must be bounded

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

## 5. Wall-clock time is not monotonic

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

## 6. Duplicated logic drifts; the second copy is where the bug lives

The ICMP predicate existed twice, once per binary. The oversized-datagram case
was found in one copy. The ASCII-lowercasing helper existed correctly in `zone`
with a comment explaining why, and incorrectly in `cache` without one.

When you find the same reasoning in two places, move it into `rdns` and make both
call it — and put the *reason* in the doc comment, because the reason is what
stops the next copy being written.

## 7. DNS rules this codebase has already got wrong

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

## 8. Async, locks, and the work done under them

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

## 9. Benchmarks and measurement

- **A wall-clock assertion with no headroom is a coin toss, not a test.** Give a
  floor a factor of ten of headroom, as `bench_zone_lookup` does.
- **Never lower a floor to make a bench pass without first proving why it moved.**
  `bench_logger_throughput`'s floor went from 45k to 10k, attributed to competing
  load. It was a quadratic in `log_query`, and lowering the floor ratified the
  regression the benchmark had caught.
- **Prefer a deterministic assertion where one exists.** An allocation count
  (`dhat::assert_eq!` on `total_blocks`) does not care what else is running.

## 10. Comments, commits, and `TODO.md`

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
